"""Protected native broadcast/finality using the existing authoritative ledger.

No timeout, missing signature status or blockhash expiry releases a reserve.
Settlement requires the original owned signed wire and finalized exact effects.
"""

import base64
from datetime import datetime
from datetime import timezone as datetime_timezone

from django.db import transaction
from django.utils import timezone

from .chain_registry import get_chain_spec, rpc_urls
from .identity_registry import _standalone, _text, _uuid
from .ledger import (
    _require_withdrawal_reservation,
    clearing_account,
    financial_precision,
    lock_user_accounts,
    post_transaction,
)
from .models import MpcSolanaFinancialEffect, MpcSolanaFinancialQuery, MpcSolanaSignatureOwner
from .mpc_binding import MpcBindingError
from .mpc_solana_network import require_fresh, verify_solana_endpoint
from .native_tx import ReconciliationState, RequestsTransport
from .solana_costs import post_execution_costs
from .solana_financial_finality import observe_finality, signed_identity
from .solana_financial_preparation import _business, _liquidity, _locked, _quote, _snapshot
from .solana_financial_sessions import _external_destination, request_query
from .solana_financial_signing import _binding_id
from .solana_issuance import _pin
from .solana_provisioning import _audit, _runtime
from .solana_witness_client import _verify, query_witness


def _ledger_terminal(parent, *, confirmed):
    """Same original journal identities/postings as ordinary withdrawals."""
    accounts = lock_user_accounts(parent.user_id, parent.asset_key)
    _require_withdrawal_reservation(parent, accounts)
    suffix = "settle" if confirmed else "release"
    return post_transaction(
        event_key=f"withdrawal:{parent.pk}:{suffix}",
        event_type="WITHDRAWAL_SETTLE" if confirmed else "WITHDRAWAL_RELEASE",
        asset_key=parent.asset_key,
        ref_type="WithdrawalRequest",
        ref_id=parent.pk,
        postings=[
            (accounts["RESERVED"], -parent.amount),
            (
                clearing_account(parent.asset_key) if confirmed else accounts["AVAILABLE"],
                parent.amount,
            ),
        ],
    )


def _parent(parent, row, status):
    parent.status = status
    parent.tx_hash = row.attempt.network_tx_id
    fields = ["status", "tx_hash"]
    if (row.operation.sweep_id or row.operation.provision_id) and status in {"CONFIRMED", "FAILED"}:
        parent.completed_at = timezone.now()
        fields.append("completed_at")
    parent.save(update_fields=fields)


def _uncertain(row, tenant_id, operator_ref, error):
    with transaction.atomic():
        current, parent = _locked(row, tenant_id)
        attempt = current.attempt
        if attempt.status not in {"CONFIRMED", "FAILED"}:
            attempt.status, attempt.error_code = "RECONCILIATION_REQUIRED", error
            attempt.save(update_fields=["status", "error_code", "updated_at"])
            _parent(parent, current, "RECONCILIATION_REQUIRED")
            _audit("SOL_FIN_CHAIN_UNKNOWN", attempt, operator_ref)
        return attempt


@financial_precision()
def broadcast_session(*, session_id, tenant_id, operator_ref, transport=None):
    _standalone()
    _runtime()
    session_id, tenant_id = _uuid(session_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    transport = transport or RequestsTransport()
    snapshot = _snapshot(session_id, tenant_id)
    payload, signature = signed_identity(snapshot)
    if snapshot.attempt.status != "SIGNED":
        return snapshot.attempt
    quote = _quote(snapshot, transport, fixed=True)
    request = request_query(
        session_id=session_id, tenant_id=tenant_id, purpose="RECOVERY", operator_ref=operator_ref
    )
    proof = query_witness(request["query"])
    with transaction.atomic():
        row, parent = _locked(snapshot, tenant_id)
        attempt = row.attempt
        if attempt.status != "SIGNED":
            return attempt
        _business(row.operation, parent)
        if int(timezone.now().timestamp()) >= row.intent["expires_at"]:
            raise MpcBindingError("original broadcast intent expired; retain reserve and reconcile")
        if quote.fee_metadata["policy"] != get_chain_spec("SOL").gas_settings:
            raise MpcBindingError("current broadcast fee/reserve policy changed")
        if int(quote.fee_metadata["fee_lamports"]) != row.intent["expected_fee_lamports"]:
            raise MpcBindingError("broadcast fee differs from original exact authorization")
        _liquidity(row.operation, quote)
        payload, signature = signed_identity(row)
        lease = MpcSolanaFinancialQuery.objects.select_for_update().get(
            pk=request["query"]["challenge"], session=row, purpose="RECOVERY", status="PENDING"
        )
        value = _verify("WITNESS_QUERY_REPLY_V1", proof)
        anchor, key, _ = _pin()
        if (
            (anchor, key) != (lease.witness_anchor_id, lease.witness_key_id)
            or value["query"] != lease.query
            or value["root"]["original"] != row.intent["claim"]["root"]
            or value["root"]["phase"] != "Active"
            or value.get("abandoned") is not False
            or value.get("execution", {}).get("status") != "SignedPending"
            or value["execution"]["signature"] != row.signature_hex
            or value["execution"]["binding_fingerprint"] != _binding_id(row)
            or timezone.now() >= lease.expires_at
        ):
            raise MpcBindingError(
                "fresh Active original signature witness required before broadcast"
            )
        lease.status, lease.evidence = "VERIFIED", proof
        lease.save(update_fields=["status", "evidence"])
        attempt.status = "BROADCASTING"
        attempt.broadcast_started_at = timezone.now()
        attempt.confirmation_metadata = {"broadcast_query": lease.pk}
        attempt.save(
            update_fields=["status", "broadcast_started_at", "confirmation_metadata", "updated_at"]
        )
        _parent(
            parent,
            row,
            "PROCESSING"
            if (row.operation.withdrawal_id or row.operation.provision_id)
            else "SWEEP_PROCESSING",
        )
        _audit("SOL_FIN_BROADCAST_BEGIN", attempt, operator_ref)
        deadline = min(
            lease.expires_at,
            datetime.fromtimestamp(row.intent["expires_at"], datetime_timezone.utc),
        )
    try:
        endpoint = rpc_urls("SOL")[0]
        require_fresh(
            "SOL", row.attempt.last_valid_block, transport, blockhash=row.intent["recent_blockhash"]
        )
        verify_solana_endpoint("SOL", endpoint, transport)
        if timezone.now() >= deadline:
            raise MpcBindingError("broadcast dispatch expired after commit/genesis verification")
        result = transport.rpc(
            endpoint,
            "sendTransaction",
            [
                base64.b64encode(bytes.fromhex(payload)).decode(),
                {
                    "encoding": "base64",
                    "skipPreflight": False,
                    "preflightCommitment": "finalized",
                    "maxRetries": 0,
                },
            ],
        )
        if result != signature:
            raise MpcBindingError("network returned another transaction identity")
        with transaction.atomic():
            current, parent = _locked(row, tenant_id)
            attempt = current.attempt
            if attempt.status == "BROADCASTING":
                attempt.status, attempt.broadcast_at = "BROADCASTED", timezone.now()
                attempt.save(update_fields=["status", "broadcast_at", "updated_at"])
                _parent(
                    parent,
                    current,
                    "BROADCASTED"
                    if (current.operation.withdrawal_id or current.operation.provision_id)
                    else "SWEEP_BROADCASTED",
                )
                _audit("SOL_FIN_BROADCAST_ACK", attempt, operator_ref)
            return attempt
    except Exception:
        _uncertain(row, tenant_id, operator_ref, "SEEDED_BROADCAST_UNCERTAIN")
        raise


@financial_precision()
def reconcile_finality(*, session_id, tenant_id, operator_ref, transport=None):
    _standalone()
    _runtime()
    session_id, tenant_id = _uuid(session_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    snapshot = _snapshot(session_id, tenant_id)
    if snapshot.attempt.status in {"CONFIRMED", "FAILED"}:
        return snapshot.attempt
    signed_identity(snapshot)
    result = observe_finality(snapshot, transport or RequestsTransport())
    if result.state not in {ReconciliationState.CONFIRMED, ReconciliationState.FAILED}:
        return _uncertain(snapshot, tenant_id, operator_ref, result.evidence["error"])
    with transaction.atomic():
        row, parent = _locked(snapshot, tenant_id)
        attempt = row.attempt
        if attempt.status in {"CONFIRMED", "FAILED"}:
            return attempt
        signed_identity(row)
        owner = MpcSolanaSignatureOwner.objects.get(session=row)
        effect, created = MpcSolanaFinancialEffect.objects.get_or_create(
            attempt=attempt,
            defaults={
                "signature_owner": owner,
                "slot": result.evidence["slot"],
                "outcome": result.state.value,
                "evidence": result.evidence,
            },
        )
        if effect.evidence != result.evidence:
            raise MpcBindingError("conflicting original finalized effect")
        post_execution_costs(attempt, effect.evidence)
        attempt.confirmation_metadata = effect.evidence
        confirmed = result.state is ReconciliationState.CONFIRMED
        if confirmed and row.operation.withdrawal_id:
            try:
                _external_destination(row.operation.destination_address)
            except MpcBindingError:
                attempt.status, attempt.error_code = (
                    "RECONCILIATION_REQUIRED",
                    "DESTINATION_BECAME_CUSTODY",
                )
                attempt.save(
                    update_fields=["status", "confirmation_metadata", "error_code", "updated_at"]
                )
                _parent(parent, row, "RECONCILIATION_REQUIRED")
                _audit("SOL_FIN_DESTINATION_HOLD", attempt, operator_ref)
                return attempt
        attempt.status = "CONFIRMED" if confirmed else "FAILED"
        attempt.error_code = ""
        attempt.save(update_fields=["status", "confirmation_metadata", "error_code", "updated_at"])
        row.operation.status = "SETTLED" if confirmed else "RELEASED"
        row.operation.save(update_fields=["status"])
        _parent(parent, row, "CONFIRMED" if confirmed else "FAILED")
        if row.operation.withdrawal_id:
            _ledger_terminal(parent, confirmed=confirmed)
        _audit("SOL_FIN_FINALIZED_SETTLE", attempt, operator_ref)
        return attempt
