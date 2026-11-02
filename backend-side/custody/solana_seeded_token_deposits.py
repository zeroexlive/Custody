"""Instruction attribution for published, seeded classic SPL customer accounts.

Incoming authorities may be delegates, multisigs or runtime PDAs. The finalized
Token Program execution authenticates those authorities; custody source account
and source owner exclusions remain separate from transaction fee payment.
"""

from decimal import Decimal

import base58
from solders.pubkey import Pubkey

from .chain_registry import get_chain_spec
from .indexer.base import DepositEvent
from .solana_wire import uint
from .token_metadata import CLASSIC_TOKEN_PROGRAM


def normalized_token_balances(meta, keys):
    """Require complete typed ownership metadata; normalize away UI/RPC extras."""
    result = {}
    for name in ("preTokenBalances", "postTokenBalances"):
        entries = meta.get(name)
        if not isinstance(entries, list):
            raise ValueError("complete finalized SPL balance metadata required")
        normalized, seen = [], set()
        for entry in entries:
            index = entry["accountIndex"]
            if type(index) is not int or not 0 <= index < len(keys) or index in seen:
                raise ValueError("duplicate or unresolved SPL balance account")
            seen.add(index)
            value = {key: entry[key] for key in ("mint", "owner", "programId")}
            for address in value.values():
                if not isinstance(address, str) or str(Pubkey.from_string(address)) != address:
                    raise ValueError("canonical SPL balance identities required")
            amount = entry["uiTokenAmount"]
            decimals = amount["decimals"]
            if type(decimals) is not int or not 0 <= decimals <= 255:
                raise ValueError("invalid SPL balance decimals")
            normalized.append(
                dict(
                    accountIndex=index,
                    **value,
                    amount=str(uint(amount["amount"])),
                    decimals=decimals,
                )
            )
        result[name] = sorted(normalized, key=lambda item: item["accountIndex"])
    return result


def transfer_events(tx, meta, slot, signature, wallet, claim, *, internal_addresses):
    if meta["err"] is not None:
        return []
    keys = [str(key) for key in tx.message.account_keys]
    balances = normalized_token_balances(meta, keys)
    asset = claim.asset

    def selected(name):
        return {
            entry["accountIndex"]: entry
            for entry in balances[name]
            if entry["mint"] == asset.contract_address
            and entry["programId"] == CLASSIC_TOKEN_PROGRAM
            and entry["decimals"] == asset.decimals
        }

    before, after = selected("preTokenBalances"), selected("postTokenBalances")
    target = wallet.asset_account_address
    if target not in keys:
        return []
    target_index = keys.index(target)
    outer_groups = [
        (f"ix:{i}", ix.program_id_index, list(ix.accounts), bytes(ix.data))
        for i, ix in enumerate(tx.message.instructions)
    ]
    seen = set()
    inner_groups = {}
    for group in meta.get("innerInstructions") or []:
        outer = group["index"]
        if type(outer) is not int or not 0 <= outer < len(tx.message.instructions) or outer in seen:
            raise ValueError("invalid finalized inner SPL instruction group")
        seen.add(outer)
        for i, ix in enumerate(group["instructions"]):
            data = base58.b58decode(ix["data"])
            if base58.b58encode(data).decode() != ix["data"]:
                raise ValueError("noncanonical inner SPL instruction encoding")
            inner_groups.setdefault(outer, []).append(
                (f"inner:{outer}:{i}", ix["programIdIndex"], ix["accounts"], data)
            )
    groups = []
    for index, instruction in enumerate(outer_groups):
        groups.append(instruction)
        groups.extend(inner_groups.get(index, []))
    events, total = [], 0
    owners = {entry["accountIndex"]: entry["owner"] for entry in balances["preTokenBalances"]}
    mints = {entry["accountIndex"]: entry["mint"] for entry in balances["preTokenBalances"]}
    known_owners = {index: {owner} for index, owner in owners.items()}
    used_sources = set()
    for identity, program, accounts, data in groups:
        if (
            type(program) is not int
            or not 0 <= program < len(keys)
            or not isinstance(accounts, (list, tuple))
            or any(type(index) is not int or not 0 <= index < len(keys) for index in accounts)
        ):
            raise ValueError("unresolved finalized SPL instruction accounts")
        if keys[program] != CLASSIC_TOKEN_PROGRAM or not data:
            continue
        # Standard, successful Token Program instructions authenticate owners
        # even for a new account forwarded and closed within the same tx.
        if data[0] in {1, 16, 18}:
            expected_length = 1 if data[0] == 1 else 33
            minimum_accounts = 4 if data[0] == 1 else (3 if data[0] == 16 else 2)
            if len(data) != expected_length or len(accounts) < minimum_accounts:
                raise ValueError("malformed executed SPL account initialization")
            index, mint = accounts[:2]
            owner = keys[accounts[2]] if data[0] == 1 else str(Pubkey.from_bytes(data[1:]))
            owners[index], mints[index] = owner, keys[mint]
            known_owners.setdefault(index, set()).add(owner)
            continue
        if data[0] == 6 and len(data) >= 2 and data[1] == 2:
            if len(data) != 35 or len(accounts) < 2 or data[2] != 1:
                raise ValueError("malformed executed SPL owner change")
            index = accounts[0]
            if index in owners:
                owner = str(Pubkey.from_bytes(data[3:]))
                owners[index] = owner
                known_owners[index].add(owner)
            continue
        if data[0] == 9:
            if len(data) != 1 or len(accounts) < 3:
                raise ValueError("malformed executed SPL close")
            owners.pop(accounts[0], None)
            mints.pop(accounts[0], None)
            continue
        if data[0] == 12 and len(data) == 10 and len(accounts) >= 4:
            source, mint, destination = accounts[:3]
            if keys[mint] != asset.contract_address or data[9] != asset.decimals:
                continue
        elif data[0] == 3 and len(data) == 9 and len(accounts) >= 3:
            source, destination = accounts[:2]
        else:
            continue
        units = int.from_bytes(data[1:9], "little")
        if destination != target_index or source == destination or units == 0:
            continue
        if (
            source not in owners
            or mints.get(source) != asset.contract_address
            or destination not in before
            or destination not in after
        ):
            raise ValueError("selected SPL transfer ownership/effect metadata incomplete")
        owner = owners[source]
        if (
            before[destination]["owner"] != claim.root.base_address
            or after[destination]["owner"] != claim.root.base_address
        ):
            raise ValueError("seeded SPL destination authority changed")
        # Net source balance is not an instruction precondition: an external
        # route may replenish/forward the same account in this transaction.
        used_sources.add(source)
        total += units
        event = DepositEvent(
            signature,
            Decimal(units) / Decimal(10**asset.decimals),
            slot,
            get_chain_spec("SOL").confirmations,
            asset_key=asset.asset_key,
            event_index=identity,
            contract_address=asset.contract_address,
        )
        event.source_address, event.source_owner_address = keys[source], owner
        events.append((source, event))
    if total and uint(after[target_index]["amount"]) - uint(before[target_index]["amount"]) < total:
        raise ValueError("aggregate seeded SPL deposit effect mismatch")
    for source in used_sources:
        if source in after and owners.get(source) != after[source]["owner"]:
            raise ValueError("finalized SPL owner metadata conflicts with executed history")
    for source, event in events:
        event.source_owner_history = sorted(known_owners[source])
    return [
        event
        for source, event in events
        if keys[source] not in internal_addresses
        and not known_owners[source].intersection(internal_addresses)
    ]
