"""Financial-customer routing prevents pre-allocation legacy signing fallback.

Membership history is permanent, including pending publication and retired keys.
This does not reclassify every p1 principal or block original public recovery.
"""

import copy
from uuid import UUID

from django.db import connection
from django.db.models import F

from .models import (
    Asset,
    LedgerTransaction,
    MpcSigningSession,
    MpcSolanaFinancialWallet,
    OnchainTransactionAttempt,
    SweepJob,
    WithdrawalRequest,
)
from .mpc_binding import MpcBindingError


def financial_customer(user_id, chain_id, asset_key):
    if chain_id != "SOL" or not isinstance(user_id, str) or not user_id.startswith("p1:"):
        return False
    try:
        principal_id = UUID(user_id[3:])
    except ValueError:
        return False
    if user_id != f"p1:{principal_id}":
        return False
    return MpcSolanaFinancialWallet.objects.filter(
        role="CUSTOMER_DEPOSIT",
        claim__principal_id=principal_id,
        claim__asset__asset_key=asset_key,
        claim__root__tenant_id=F("claim__principal__tenant_id"),
    ).exists()


def requires_typed_private(operation_type, operation_id):
    if operation_type == "WITHDRAWAL":
        parent = WithdrawalRequest.objects.filter(pk=operation_id).first()
        if parent is None:
            return False
        if parent.chain_id == "SOL" and connection.vendor == "postgresql":
            with connection.cursor() as cursor:
                cursor.execute("SHOW transaction_isolation")
                if cursor.fetchone()[0] != "read committed":
                    raise MpcBindingError("Solana private routing requires READ COMMITTED")
        return financial_customer(parent.user_id, parent.chain_id, parent.asset_key)
    if operation_type == "SWEEP":
        return SweepJob.objects.filter(
            pk=operation_id, user_wallet__solana_claim__isnull=False
        ).exists()
    return False


def reject_generic_private(operation_type, operation_id):
    if requires_typed_private(operation_type, operation_id):
        raise MpcBindingError(
            "financial customer requires explicit tenant treasury and typed private authorization"
        )


def guard_unallocated_ledger_mutation(req, *, release):
    """No generic mutation of a financial hold from timeout/raw FAILED/absence.

    A never-started pending denial is safe under its parent lock. Historical
    legacy payouts may use their original finalized wire outcome, never a new
    private execution. Typed operations retain their separate stricter fence.
    """
    snapshot = WithdrawalRequest.objects.filter(pk=req.pk).first()
    if snapshot is None or not financial_customer(
        snapshot.user_id, snapshot.chain_id, snapshot.asset_key
    ):
        return
    parent = WithdrawalRequest.objects.select_for_update(nowait=True).get(pk=req.pk)
    if (req.user_id, req.chain_id, req.asset_key, req.amount) != (
        parent.user_id,
        parent.chain_id,
        parent.asset_key,
        parent.amount,
    ):
        raise MpcBindingError("original stored financial withdrawal identity required")
    attempt = (
        OnchainTransactionAttempt.objects.filter(
            operation_type="WITHDRAWAL", operation_id=parent.pk
        )
        .order_by("-attempt_number")
        .first()
    )
    opposite = "settle" if release else "release"
    if LedgerTransaction.objects.filter(event_key=f"withdrawal:{parent.pk}:{opposite}").exists():
        raise MpcBindingError("prior financial terminal decision requires explicit reconciliation")
    if release and parent.status == "DENIED" and attempt is None:
        return
    expected = "FAILED" if release else "CONFIRMED"
    if (
        attempt is None
        or attempt.status != expected
        or not attempt.signed_payload
        or not attempt.network_tx_id
        or attempt.confirmation_metadata.get("finalized") is not True
        or (attempt.confirmation_metadata.get("err") is None) == release
    ):
        raise MpcBindingError(
            "unallocated financial hold needs safe denial or original finalized payout"
        )
    from .native_tx import to_base_units

    decimals = Asset.objects.get(asset_key=parent.asset_key, chain_id=parent.chain_id).decimals
    if (
        attempt.chain_id,
        attempt.asset_key,
        attempt.to_address,
        attempt.amount,
        int(attempt.base_unit_amount),
    ) != (
        parent.chain_id,
        parent.asset_key,
        parent.to_address,
        parent.amount,
        to_base_units(parent.amount, decimals),
    ) or attempt.confirmation_metadata.get("signature") != attempt.network_tx_id:
        raise MpcBindingError("original legacy payout does not match financial withdrawal")
    from .solana_wire import uint

    uint(attempt.confirmation_metadata.get("slot"), positive=True)
    same_kind = "release" if release else "settle"
    if LedgerTransaction.objects.filter(event_key=f"withdrawal:{parent.pk}:{same_kind}").exists():
        return  # post_transaction still verifies the immutable original posting set.
    session = MpcSigningSession.objects.filter(attempt=attempt).first()
    from .mpc_signing import _default_consumer

    if session is None or session.status != "COMPLETED" or not session.signature_consumed_at:
        raise MpcBindingError("original captured legacy MPC completion required")
    view = copy.copy(attempt)
    view.status = "RECONCILIATION_REQUIRED"  # Public historical verification, no private dispatch.
    if _default_consumer(view, session) != (attempt.signed_payload, attempt.network_tx_id):
        raise MpcBindingError("original legacy MPC signature/wire identity mismatch")
