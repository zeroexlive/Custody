"""Canonical incoming v0 wire and resolved account keys using the Solana SDK.

Outgoing protected messages remain legacy-only. This helper adds no cryptographic
algorithm and trusts loaded-address/finality metadata at the existing pinned RPC
boundary, as it trusts executed inner instructions and balances.
"""

import base64
from dataclasses import dataclass

from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from .solana_settlement import finalized_transaction
from .solana_wire import uint


@dataclass(frozen=True)
class ResolvedMessage:
    account_keys: tuple
    header: object
    instructions: tuple


@dataclass(frozen=True)
class ResolvedIncomingTransaction:
    transaction: object
    message: ResolvedMessage

    @property
    def signatures(self):
        return self.transaction.signatures

    def __bytes__(self):
        return bytes(self.transaction)

    def verify_with_results(self):
        return self.transaction.verify_with_results()


def finalized_incoming_transaction(response, signature, status):
    if response.get("version", "legacy") == "legacy":
        return finalized_transaction(response, signature, status)
    if type(response.get("version")) is not int or response["version"] != 0:
        raise ValueError("unsupported incoming transaction version")
    if not status or status.get("confirmationStatus") != "finalized":
        raise ValueError("finalized incoming transaction status required")
    wire = response["transaction"]
    if not isinstance(wire, list) or len(wire) != 2 or wire[1] != "base64":
        raise ValueError("canonical versioned transaction encoding required")
    raw = base64.b64decode(wire[0], validate=True)
    tx = VersionedTransaction.from_bytes(raw)
    tx.sanitize()
    if (
        bytes(tx) != raw
        or not isinstance(tx.message, MessageV0)
        or not tx.signatures
        or tx.signatures[0] != Signature.from_string(signature)
        or not all(tx.verify_with_results())
    ):
        raise ValueError("original versioned transaction signature/wire mismatch")
    slot = uint(response["slot"], positive=True)
    meta = response.get("meta")
    if (
        not isinstance(meta, dict)
        or "err" not in meta
        or status.get("slot") != slot
        or status.get("err") != meta["err"]
    ):
        raise ValueError("versioned finalized slot/result conflict")
    lookups = tx.message.address_table_lookups
    counts = {
        "writable": sum(len(lookup.writable_indexes) for lookup in lookups),
        "readonly": sum(len(lookup.readonly_indexes) for lookup in lookups),
    }
    loaded = meta.get("loadedAddresses")
    if loaded is None and sum(counts.values()) == 0:
        loaded = {"writable": [], "readonly": []}
    if not isinstance(loaded, dict):
        raise ValueError("versioned resolved account metadata unavailable")
    resolved = []
    for kind in ("writable", "readonly"):
        addresses = loaded.get(kind)
        if not isinstance(addresses, list) or len(addresses) != counts[kind]:
            raise ValueError("versioned loaded-address cardinality mismatch")
        for address in addresses:
            key = Pubkey.from_string(address)
            if str(key) != address:
                raise ValueError("noncanonical loaded address")
            resolved.append(key)
    keys = list(tx.message.account_keys) + resolved
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate resolved incoming accounts")
    for instruction in tx.message.instructions:
        if not 0 <= instruction.program_id_index < len(keys) or any(
            index >= len(keys) for index in instruction.accounts
        ):
            raise ValueError("unresolved compiled incoming account index")
    for name in ("preBalances", "postBalances"):
        values = meta.get(name)
        if not isinstance(values, list) or len(values) != len(keys):
            raise ValueError("incomplete versioned finalized balances")
        for value in values:
            uint(value)
    uint(meta["fee"])
    return (
        ResolvedIncomingTransaction(
            tx, ResolvedMessage(tuple(keys), tx.message.header, tuple(tx.message.instructions))
        ),
        meta,
        slot,
    )
