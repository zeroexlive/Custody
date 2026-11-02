"""Exact classic seeded-token effects; no activation or ledger authority.

The caller must authenticate permanent ownership of the original MPC
signature/message and finalized RPC status before consuming this pure validator.
"""

import base64

from .solana_seeded import (
    account_address,
    build_token_creation,
    validate_token_creation,
    validate_token_seeded_transfer,
    validate_token_transfer,
)
from .solana_settlement import token_balances
from .solana_wire import uint
from .spl import derive_ata


def validate_token_intent_message(intent, encoded):
    claim, action = intent["claim"], intent["action"]
    asset, base, block = claim["asset"], intent["fee_payer"], intent["recent_blockhash"]
    if asset["kind"] != "ClassicToken":
        raise ValueError("original classic token Claim required")
    common = (encoded, base, claim["index"], asset["mint"])
    if action["kind"] == "CreateClassicToken" and set(action) == {"kind", "rent_lamports"}:
        return validate_token_creation(*common, action["rent_lamports"], block)
    if action["kind"] == "ClassicSeededTransfer" and set(action) == {
        "kind",
        "destination_base",
        "destination_index",
        "amount",
    }:
        return validate_token_seeded_transfer(
            *common,
            action["destination_base"],
            action["destination_index"],
            action["amount"],
            asset["decimals"],
            block,
        )
    if action["kind"] == "ClassicTransfer" and set(action) == {
        "kind",
        "destination_owner",
        "amount",
        "create_ata",
    }:
        return validate_token_transfer(
            *common,
            action["destination_owner"],
            action["amount"],
            asset["decimals"],
            block,
            create_ata=action["create_ata"],
        )
    raise ValueError("exact supported token operation and wire required")


def creation_effect(intent, tx, meta):
    claim = intent["claim"]
    asset = claim["asset"]
    if asset["kind"] != "ClassicToken" or intent["action"]["kind"] != "CreateClassicToken":
        raise ValueError("original classic-token initialization intent required")
    base = intent["fee_payer"]
    source = account_address(base, claim["index"], token=True)
    fee = uint(intent["expected_fee_lamports"], positive=True)
    rent = uint(intent["expected_rent_lamports"], positive=True)
    expected = build_token_creation(
        base, claim["index"], asset["mint"], rent, intent["recent_blockhash"]
    )
    if (
        intent["operation_type"] != "PROVISION"
        or intent["financial_source"] != source
        or intent["rent_payer"] != base
        or intent["action"]["rent_lamports"] != rent
        or bytes(tx.message) != expected
        or len(tx.signatures) != 1
        or meta["fee"] != fee
        or meta.get("innerInstructions") not in (None, [])
    ):
        raise ValueError("original token initialization wire/fee/rent identity mismatch")
    keys = [str(key) for key in tx.message.account_keys]
    account = keys.index(source)
    if keys[0] != base or account == 0:
        raise ValueError("separate original base and initialized token account required")
    before, after = meta["preBalances"], meta["postBalances"]
    pre = token_balances(meta, "preTokenBalances", keys, asset["mint"], asset["decimals"])
    post = token_balances(meta, "postTokenBalances", keys, asset["mint"], asset["decimals"])
    if meta["err"] is not None and not isinstance(meta["err"], (str, dict)):
        raise ValueError("invalid finalized token initialization execution result")
    if meta["err"] is None:
        changes = {0: -fee - rent, account: rent}
        if before[account] != 0 or pre or post != {account: (0, base)}:
            raise ValueError("initialization must create one fresh zero-token account")
    else:
        changes = {0: -fee}
        if pre != post:
            raise ValueError("failed token initialization changed token state")
    if any(after[i] - before[i] != changes.get(i, 0) for i in range(len(keys))):
        raise ValueError("token initialization fee/rent or rollback effects differ")
    return {
        "effect": "classic_seeded_initialization" if meta["err"] is None else "failed_rollback",
        "fee_lamports": str(fee),
        "rent_lamports": str(rent if meta["err"] is None else 0),
        "account": source,
        "message": base64.b64encode(expected).decode(),
    }


def token_effect(row, tx, meta, slot):
    """Original owned wire plus exact token principal and separate Root costs."""
    from .solana_financial_finality import signed_identity

    payload, signature = signed_identity(row)
    intent, operation = row.intent, row.operation
    if bytes(tx).hex() != payload or str(tx.signatures[0]) != signature:
        raise ValueError("finalized token wire differs from original captured MPC signature")
    common = {
        "signature": signature,
        "slot": slot,
        "finalized": True,
        "err": meta["err"],
        "message_fingerprint": intent["message_fingerprint"],
        "financial_source": intent["financial_source"],
        "base_fee_authority": intent["fee_payer"],
        "destination": operation.destination_address,
    }
    if operation.provision_id:
        effect = creation_effect(intent, tx, meta)
        return {
            **common,
            **{k: effect[k] for k in ("effect", "fee_lamports", "rent_lamports")},
            "amount": "0",
        }
    asset = intent["claim"]["asset"]
    action = intent["action"]
    if operation.sweep_id:
        target = account_address(
            action["destination_base"], action["destination_index"], token=True
        )
        target_owner = action["destination_base"]
    else:
        target_owner = action["destination_owner"]
        target = derive_ata(target_owner, asset["mint"])
    keys = [str(k) for k in tx.message.account_keys]
    source, destination = keys.index(intent["financial_source"]), keys.index(target)
    if keys[0] != intent["fee_payer"] or len({0, source, destination}) != 3:
        raise ValueError("separate original Root/source/destination required")
    before = token_balances(meta, "preTokenBalances", keys, asset["mint"], asset["decimals"])
    after = token_balances(meta, "postTokenBalances", keys, asset["mint"], asset["decimals"])
    if before.get(source, (None, None))[1] != intent["fee_payer"]:
        raise ValueError("original token source owner missing")
    if meta["err"] is not None and not isinstance(meta["err"], (str, dict)):
        raise ValueError("invalid finalized token execution error")
    fee = uint(meta["fee"], positive=True)
    if fee != intent["expected_fee_lamports"] or fee > operation.fee_budget_lamports:
        raise ValueError("original token network fee differs from exact authorization")
    pre_lamps, post_lamps = meta["preBalances"], meta["postBalances"]
    rent = 0
    if meta["err"] is not None:
        if before != after:
            raise ValueError("failed token transaction lacks exact principal rollback")
    else:
        original_destination = before.get(destination)
        if original_destination is None:
            if not operation.withdrawal_id or pre_lamps[destination] != 0:
                raise ValueError("only explicit ATA creation may introduce destination")
            original_destination = (0, target_owner)
        if (
            original_destination[1] != target_owner
            or after.get(source, (None, None))[1] != intent["fee_payer"]
            or after.get(destination, (None, None))[1] != target_owner
            or set(before) - {source, destination}
            or set(after) != {source, destination}
            or before[source][0] - after[source][0] != int(operation.base_unit_amount)
            or after[destination][0] - original_destination[0] != int(operation.base_unit_amount)
        ):
            raise ValueError("original token source/recipient/amount effects differ")
        rent = post_lamps[destination] - pre_lamps[destination]
        if not 0 <= rent <= min(intent["expected_rent_lamports"], operation.rent_budget_lamports):
            raise ValueError("actual token rent exceeds original creation maximum")
        if operation.sweep_id and rent != 0:
            raise ValueError("seeded treasury sweep cannot pay destination rent")
    expected = {0: -fee - rent, destination: rent} if meta["err"] is None else {0: -fee}
    if any(post_lamps[i] - pre_lamps[i] != expected.get(i, 0) for i in range(len(keys))):
        raise ValueError("original token transaction changed unexpected native funds")
    return {
        **common,
        "fee_lamports": str(fee),
        "rent_lamports": str(rent),
        "effect": "classic_seeded_transfer_checked" if meta["err"] is None else "failed_rollback",
        "amount": str(int(operation.base_unit_amount)) if meta["err"] is None else "0",
        "destination_token_account": target,
    }
