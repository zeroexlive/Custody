"""Finalized original transaction observations for the dedicated deposit boundary.

No credits, cursor changes or wallet activation occur here. Evidence comes only
from the independently pinned trusted RPC boundary; it is not a light-client
proof and a caller-supplied event/evidence dictionary is never accepted as truth.
"""

import copy
import hashlib
import json

from solders.hash import Hash, ParseHashError
from solders.signature import Signature

from .chain_registry import rpc_urls
from .mpc_binding import MpcBindingError
from .mpc_solana_network import guarded_solana_rpc, network_identity
from .native_tx import RequestsTransport
from .solana_incoming_wire import finalized_incoming_transaction
from .solana_wire import uint


def _block_identity(block, signature, slot):
    if not isinstance(block, dict):
        raise MpcBindingError("finalized deposit block evidence unavailable")
    block_hash = block["blockhash"]
    try:
        canonical_hash = str(Hash.from_string(block_hash))
    except (ParseHashError, TypeError) as exc:
        raise MpcBindingError("malformed finalized deposit block hash") from exc
    if canonical_hash != block_hash:
        raise MpcBindingError("noncanonical finalized deposit block hash")
    if uint(block["parentSlot"]) >= slot:
        raise MpcBindingError("finalized deposit block parent is inconsistent")
    signatures = block["signatures"]
    if (
        not isinstance(signatures, list)
        or not 1 <= len(signatures) <= 100_000
        or any(not isinstance(value, str) for value in signatures)
        or len(set(signatures)) != len(signatures)
        or signatures.count(signature) != 1
    ):
        raise MpcBindingError("original deposit signature absent from finalized block")
    return block_hash


def observe_deposit_transaction(signature, *, transport=None, classic_asset=None):
    """Fetch and authenticate canonical wire/status and explicit block membership.

    Missing/pruned data can use another trusted endpoint. Conflicting evidence
    cannot be overridden by a different endpoint. This function posts no ledger
    entries; successful transfers still require ownership/internal-source checks.
    """
    transport = transport or RequestsTransport()
    if not isinstance(signature, str) or not 64 <= len(signature) <= 88:
        raise MpcBindingError("canonical original deposit signature required")
    try:
        if str(Signature.from_string(signature)) != signature:
            raise ValueError
    except ValueError:
        raise MpcBindingError("canonical original deposit signature required") from None
    network = network_identity("SOL")
    errors = []
    for endpoint in rpc_urls("SOL"):
        try:

            def rpc(method, params):
                return guarded_solana_rpc("SOL", endpoint, transport, method, params)

            status = rpc("getSignatureStatuses", [[signature], {"searchTransactionHistory": True}])[
                "value"
            ][0]
            if status is None or status.get("confirmationStatus") != "finalized":
                errors.append("FINALIZED_STATUS_UNAVAILABLE")
                continue
            response = rpc(
                "getTransaction",
                [
                    signature,
                    {
                        "encoding": "base64",
                        "commitment": "finalized",
                        "maxSupportedTransactionVersion": 0,
                    },
                ],
            )
            if response is None:
                errors.append("FINALIZED_TRANSACTION_UNAVAILABLE")
                continue
            tx, meta, slot = finalized_incoming_transaction(response, signature, status)
            if meta["err"] is not None and not isinstance(meta["err"], (str, dict)):
                raise MpcBindingError("invalid finalized deposit execution result")
            block = rpc(
                "getBlock",
                [
                    slot,
                    {
                        "commitment": "finalized",
                        "transactionDetails": "signatures",
                        "rewards": False,
                        "maxSupportedTransactionVersion": 0,
                    },
                ],
            )
            if block is None:
                errors.append("FINALIZED_BLOCK_UNAVAILABLE")
                continue
            block_hash = _block_identity(block, signature, slot)
            evidence = copy.deepcopy(
                {
                    "version": 1,
                    "network": network,
                    "signature": signature,
                    "slot": slot,
                    "block_hash": block_hash,
                    "status": status,
                    "transaction": response,
                    "block": block,
                }
            )
            # Retain raw evidence, but optional RPC envelope fields cannot change
            # permanent attribution of the same canonical transaction/effects.
            material = {
                "version": 1,
                "kind": "SOLANA_NATIVE_DEPOSIT_V1",
                "network": network,
                "signature": signature,
                "slot": slot,
                "block_hash": block_hash,
                "parent_slot": block["parentSlot"],
                "wire": bytes(tx).hex(),
                "meta": {
                    name: meta[name] for name in ["err", "fee", "preBalances", "postBalances"]
                },
                "inner": [
                    {
                        "index": group["index"],
                        "instructions": [
                            {key: ix[key] for key in ["programIdIndex", "accounts", "data"]}
                            for ix in group["instructions"]
                        ],
                    }
                    for group in meta.get("innerInstructions") or []
                ],
                "loaded_addresses": meta.get("loadedAddresses") or {"writable": [], "readonly": []},
            }
            if classic_asset is not None:
                from .solana_seeded_token_deposits import normalized_token_balances

                material["kind"] = "SOLANA_CLASSIC_TOKEN_DEPOSIT_V1"
                material["asset"] = {
                    "asset_key": classic_asset.asset_key,
                    "mint": classic_asset.contract_address,
                    "decimals": classic_asset.decimals,
                }
                material["meta"].update(normalized_token_balances(meta, tx.message.account_keys))
                evidence["classic_asset"] = material["asset"].copy()
            digest = hashlib.sha256(
                json.dumps(
                    material, sort_keys=True, separators=(",", ":"), allow_nan=False
                ).encode()
            ).hexdigest()
            return tx, copy.deepcopy(meta), evidence, digest
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            raise MpcBindingError("conflicting/malformed finalized deposit evidence") from exc
        except Exception as exc:
            errors.append(type(exc).__name__)
    raise MpcBindingError(
        "finalized deposit history unavailable; credit and cursor unchanged: " + ",".join(errors)
    )
