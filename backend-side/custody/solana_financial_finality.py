"""Finalized seeded-native effects, with Claim principal separate from base fees.

These validators do not broadcast or post a ledger entry. RPC is the existing
independently genesis-pinned trusted boundary, not a light client.
"""

from .chain_registry import rpc_urls
from .models import MpcSolanaMessageOwner, MpcSolanaSignatureOwner
from .mpc_binding import MpcBindingError
from .mpc_solana_network import guarded_solana_rpc
from .native_tx import ReconciliationResult, ReconciliationState
from .solana_seeded import validate_native_transfer
from .solana_settlement import finalized_transaction
from .solana_wire import assemble_signature, uint


def signed_identity(row):
    if row.status != "COMPLETED" or not row.signature_hex:
        raise MpcBindingError("original completed protected signature required")
    owner = MpcSolanaMessageOwner.objects.get(
        genesis_hash=row.intent["claim"]["root"]["genesis_hash"],
        message_fingerprint=row.intent["message_fingerprint"],
        operation=row.operation,
    )
    signature = MpcSolanaSignatureOwner.objects.get(session=row, message=owner)
    payload, txid = assemble_signature(
        row.attempt.prepared_metadata["message"],
        row.intent["claim"]["root"]["group_public_key"],
        row.signature_hex,
    )
    if (payload, txid) != (
        row.attempt.signed_payload,
        row.attempt.network_tx_id,
    ) or signature.signature != txid:
        raise MpcBindingError("permanent signature ownership/original signed bytes mismatch")
    if row.intent["claim"]["asset"]["kind"] == "Native":
        validate_native_transfer(
            row.attempt.prepared_metadata["message"],
            row.intent["fee_payer"],
            row.intent["claim"]["index"],
            row.operation.destination_address,
            int(row.operation.base_unit_amount),
            row.intent["recent_blockhash"],
        )
    else:
        from .solana_seeded_token_effects import validate_token_intent_message

        validate_token_intent_message(row.intent, row.attempt.prepared_metadata["message"])
    return payload, txid


def native_effect(row, tx, meta, slot):
    payload, txid = signed_identity(row)
    if bytes(tx).hex() != payload or len(tx.signatures) != 1 or str(tx.signatures[0]) != txid:
        raise MpcBindingError("finalized transaction differs from captured original signature")
    keys = [str(key) for key in tx.message.account_keys]
    base = keys.index(row.intent["fee_payer"])
    source = keys.index(row.intent["financial_source"])
    destination = keys.index(row.operation.destination_address)
    if base != 0 or len({base, source, destination}) != 3:
        raise MpcBindingError("separate original base/source/destination accounts required")
    if meta.get("innerInstructions") not in (None, []) or any(
        meta.get(name) not in (None, []) for name in ["preTokenBalances", "postTokenBalances"]
    ):
        raise MpcBindingError("unexpected effects in original native transfer")
    if meta["err"] is not None and not isinstance(meta["err"], (str, dict)):
        raise MpcBindingError("invalid finalized execution error")
    fee = uint(meta["fee"])
    if fee != row.intent["expected_fee_lamports"] or fee > row.operation.fee_budget_lamports:
        raise MpcBindingError("actual base fee differs from original exact quote/budget")
    before, after = meta["preBalances"], meta["postBalances"]
    units = int(row.operation.base_unit_amount)
    expected = {base: -fee}
    if meta["err"] is None:
        expected.update({source: -units, destination: units})
    if any(after[i] - before[i] != expected.get(i, 0) for i in range(len(keys))):
        raise MpcBindingError("finalized Claim principal/base fee effects or rollback inconsistent")
    return {
        "signature": txid,
        "slot": slot,
        "finalized": True,
        "err": meta["err"],
        "fee_lamports": str(fee),
        "rent_lamports": "0",
        "effect": "seeded_system_transfer" if meta["err"] is None else "failed_rollback",
        "amount": str(units) if meta["err"] is None else "0",
        "message_fingerprint": row.intent["message_fingerprint"],
        "financial_source": row.intent["financial_source"],
        "base_fee_authority": row.intent["fee_payer"],
        "destination": row.operation.destination_address,
    }


def observe_finality(row, transport):
    _, signature = signed_identity(row)
    errors = []
    for endpoint in rpc_urls("SOL"):
        try:

            def rpc(method, params):
                return guarded_solana_rpc("SOL", endpoint, transport, method, params)

            status = rpc("getSignatureStatuses", [[signature], {"searchTransactionHistory": True}])[
                "value"
            ][0]
            if not status or status.get("confirmationStatus") != "finalized":
                errors.append("FINALIZED_STATUS_UNAVAILABLE")
                continue
            response = rpc(
                "getTransaction", [signature, {"encoding": "base64", "commitment": "finalized"}]
            )
            if response is None:
                errors.append("FINALIZED_TRANSACTION_UNAVAILABLE")
                continue
            tx, meta, slot = finalized_transaction(response, signature, status)
            if slot < row.attempt.prepared_metadata["blockhashContextSlot"]:
                raise MpcBindingError("finalized transaction predates original blockhash context")
            if row.intent["claim"]["asset"]["kind"] == "Native":
                effect = native_effect(row, tx, meta, slot)
            else:
                from .solana_seeded_token_effects import token_effect

                effect = token_effect(row, tx, meta, slot)
            return ReconciliationResult(
                ReconciliationState.CONFIRMED
                if meta["err"] is None
                else ReconciliationState.FAILED,
                effect,
            )
        except (ValueError, KeyError, TypeError, IndexError):
            return ReconciliationResult(
                ReconciliationState.RECONCILIATION_REQUIRED,
                {
                    "error": "SEEDED_FINALIZED_EVIDENCE_INVALID",
                    "manual_reconciliation_required": True,
                },
            )
        except Exception as exc:
            errors.append(type(exc).__name__)
    return ReconciliationResult(
        ReconciliationState.RECONCILIATION_REQUIRED,
        {
            "error": "SEEDED_FINALIZED_EVIDENCE_UNAVAILABLE",
            "observations": errors,
            "manual_reconciliation_required": True,
            "non_inclusion_proven": False,
        },
    )
