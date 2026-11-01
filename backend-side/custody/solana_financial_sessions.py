"""Durable business/session allocation and authenticated no-signature recovery.

No private signing, broadcast, settlement or seeded credit is enabled here.
HELD reuses an existing withdrawal reserve; sweeps only acquire exclusivity.
Query/command export follows a committed UUID allocation. Lifecycle commands
are signed and submitted independently; this module owns no Lifecycle key.
"""

import secrets
from datetime import timedelta

from django.db import connection, transaction
from django.db.models import Q
from django.utils import timezone
from solders.pubkey import Pubkey

from .chain_registry import get_chain_spec
from .identity_registry import _standalone, _text, _uuid
from .ledger import _require_withdrawal_reservation, lock_user_accounts
from .models import (
    CustodyPrincipal,
    CustodyPrincipalRole,
    HotWallet,
    LedgerTransaction,
    MpcSolanaClaim,
    MpcSolanaFinancialOperation,
    MpcSolanaFinancialQuery,
    MpcSolanaFinancialSession,
    MpcSolanaFinancialWallet,
    MpcSolanaRoot,
    OnchainTransactionAttempt,
    SweepJob,
    UserWallet,
    WithdrawalRequest,
)
from .mpc_binding import MpcBindingError
from .native_tx import _cap, to_base_units
from .solana_financial_wallet import validate_financial_wallet
from .solana_issuance import _fingerprint, _locked_claim, _pin
from .solana_provisioning import _audit, _runtime
from .solana_witness_client import _verify

PAIRS = (["signer-a", "signer-b"], ["signer-a", "signer-c"], ["signer-b", "signer-c"])


def reject_generic_business(operation_type, operation_id):
    parent = {"WITHDRAWAL": WithdrawalRequest, "SWEEP": SweepJob}.get(operation_type)
    if parent and connection.vendor == "postgresql":
        source = "chain_id" if operation_type == "WITHDRAWAL" else "user_wallet__chain_id"
        if parent.objects.filter(pk=operation_id, **{source: "SOL"}).exists():
            with connection.cursor() as cursor:
                cursor.execute("SHOW transaction_isolation")
                if cursor.fetchone()[0] != "read committed":
                    raise MpcBindingError("Solana financial mutation requires READ COMMITTED")
    field = {"WITHDRAWAL": "withdrawal_id", "SWEEP": "sweep_id"}.get(operation_type)
    if field and MpcSolanaFinancialOperation.objects.filter(**{field: operation_id}).exists():
        raise MpcBindingError("protected financial operation requires typed proof handling")


def reject_generic_attempt(attempt):
    reject_generic_business(attempt.operation_type, attempt.operation_id)
    if MpcSolanaFinancialSession.objects.filter(attempt=attempt).exists():
        raise MpcBindingError("protected financial session requires typed proof handling")


def _budget(value):
    cap = _cap(get_chain_spec("SOL").gas_settings, "max_fee_lamports")
    if type(value) is not int or not 0 < value <= min(cap, 2**63 - 1):
        raise MpcBindingError("explicit native fee budget within installed policy required")
    return value


def _wallet(claim_id, tenant_id, role):
    claim = _locked_claim(claim_id, tenant_id)
    row = validate_financial_wallet(MpcSolanaFinancialWallet.objects.get(pk=claim.pk))
    if row.role != role or claim.root.statement["wallet_class"] != "HOT":
        raise MpcBindingError("exact explicitly published HOT financial source role required")
    # Historical ownership validation alone is not new-spend admission.
    if claim.root.keyset.status != "ACTIVE":
        raise MpcBindingError("new financial allocation requires active source keyset")
    return row


def _external_destination(address):
    try:
        if not isinstance(address, str) or str(Pubkey.from_string(address)) != address:
            raise ValueError
    except ValueError:
        raise MpcBindingError("canonical external Solana destination required") from None
    if (
        MpcSolanaRoot.objects.filter(base_address=address).exists()
        or MpcSolanaClaim.objects.filter(address=address).exists()
        or UserWallet.objects.filter(chain_id="SOL")
        .filter(Q(deposit_address=address) | Q(asset_account_address=address))
        .exists()
        or HotWallet.objects.filter(chain_id="SOL", address=address).exists()
    ):
        raise MpcBindingError(
            "known custody destination requires separate internal-transfer handling"
        )


def _existing(row, source_id, budget, destination_id=None):
    if (row.source_id, row.fee_budget_lamports, row.treasury_destination_id) != (
        source_id,
        budget,
        destination_id,
    ) or row.status != "HELD":
        raise MpcBindingError("original business reservation/source/budget cannot change")
    return row


def allocate_withdrawal(*, withdrawal_id, source_id, tenant_id, fee_budget_lamports, operator_ref):
    """Reuse the original USER reserve; allocate no second balance/hold journal."""
    _standalone()
    _runtime()
    tenant_id, source_id = _uuid(tenant_id), _uuid(source_id)
    operator_ref, budget = (
        _text(operator_ref, "operator audit reference"),
        _budget(fee_budget_lamports),
    )
    with transaction.atomic():
        source = _wallet(source_id, tenant_id, "TENANT_TREASURY")
        req = WithdrawalRequest.objects.select_for_update().get(pk=withdrawal_id)
        existing = (
            MpcSolanaFinancialOperation.objects.select_for_update().filter(withdrawal=req).first()
        )
        if existing:
            return _existing(existing, source_id, budget)
        principal = CustodyPrincipal.objects.get(tenant_id=tenant_id, ledger_owner_id=req.user_id)
        if not CustodyPrincipalRole.objects.filter(principal=principal, role="CUSTOMER").exists():
            raise MpcBindingError("explicit customer reservation owner required")
        if (req.chain_id, req.asset_key, req.status) != (
            "SOL",
            source.claim.asset.asset_key,
            "APPROVED",
        ):
            raise MpcBindingError("exact approved native withdrawal required")
        _external_destination(req.to_address)
        accounts = lock_user_accounts(req.user_id, req.asset_key)
        _require_withdrawal_reservation(req, accounts)
        if LedgerTransaction.objects.filter(
            event_key__in=[f"withdrawal:{req.pk}:settle", f"withdrawal:{req.pk}:release"]
        ).exists():
            raise MpcBindingError("terminal withdrawal reserve cannot be adopted")
        row = MpcSolanaFinancialOperation.objects.create(
            withdrawal=req,
            principal=principal,
            source=source,
            amount=req.amount,
            base_unit_amount=to_base_units(
                req.amount, source.claim.asset.decimals, maximum=2**64 - 1
            ),
            destination_address=req.to_address,
            fee_budget_lamports=budget,
        )
        _audit("SOL_FIN_WITHDRAWAL_RESERVE", row, operator_ref)
        return row


def allocate_sweep(*, sweep_id, destination_id, tenant_id, fee_budget_lamports, operator_ref):
    """Bind an existing sweep snapshot to an explicit tenant treasury, no liability change."""
    _standalone()
    _runtime()
    tenant_id, destination_id = _uuid(tenant_id), _uuid(destination_id)
    operator_ref, budget = (
        _text(operator_ref, "operator audit reference"),
        _budget(fee_budget_lamports),
    )
    ref = SweepJob.objects.select_related("user_wallet").get(pk=sweep_id)
    source_id = ref.user_wallet.solana_claim_id
    if source_id is None:
        raise MpcBindingError("original seeded customer source required")
    with transaction.atomic():
        # Lock all involved Roots in stable order before locking either Claim.
        from .models import MpcKeyset

        root_ids = sorted(
            set(
                MpcSolanaClaim.objects.filter(pk__in=[source_id, destination_id]).values_list(
                    "root_id", flat=True
                )
            )
        )
        for root_id in root_ids:
            MpcKeyset.objects.select_for_update().get(pk=root_id)
            MpcSolanaRoot.objects.select_for_update().get(pk=root_id)
        source = _wallet(source_id, tenant_id, "CUSTOMER_DEPOSIT")
        destination = _wallet(destination_id, tenant_id, "TENANT_TREASURY")
        sweep = SweepJob.objects.select_for_update().get(pk=sweep_id)
        existing = (
            MpcSolanaFinancialOperation.objects.select_for_update().filter(sweep=sweep).first()
        )
        if existing:
            return _existing(existing, source_id, budget, destination_id)
        if (
            sweep.user_wallet_id != source.user_wallet_id
            or sweep.status != "CREATED"
            or sweep.asset_key != source.claim.asset.asset_key
            or destination.claim.asset_id != source.claim.asset_id
            or sweep.gas_topup_intent_id is not None
        ):
            raise MpcBindingError("exact original customer sweep and same-asset treasury required")
        row = MpcSolanaFinancialOperation.objects.create(
            sweep=sweep,
            source=source,
            principal=source.claim.principal,
            treasury_destination=destination,
            destination_address=destination.claim.address,
            amount=sweep.balance_snapshot,
            base_unit_amount=to_base_units(
                sweep.balance_snapshot, source.claim.asset.decimals, maximum=2**64 - 1
            ),
            fee_budget_lamports=budget,
        )
        _audit("SOL_FIN_SWEEP_RESERVE", row, operator_ref)
        return row


def _locked_operation(reservation_id, tenant_id):
    return (
        MpcSolanaFinancialOperation.objects.select_for_update(of=("self",))
        .select_related(
            "source__claim__root__keyset",
            "source__claim__principal",
            "source__claim__asset",
            "principal",
        )
        .get(pk=reservation_id, principal__tenant_id=tenant_id)
    )


def allocate_session(*, reservation_id, tenant_id, selected_signers, operator_ref):
    """Commit both MPC UUIDs and an OnchainAttempt before exporting any proof/RPC."""
    _standalone()
    _runtime()
    reservation_id, tenant_id = _uuid(reservation_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    if selected_signers not in PAIRS:
        raise MpcBindingError("explicit canonical original threshold pair required")
    with transaction.atomic():
        operation = _locked_operation(reservation_id, tenant_id)
        if operation.status != "HELD":
            raise MpcBindingError("original held business reservation required")
        existing = (
            MpcSolanaFinancialSession.objects.filter(operation=operation)
            .exclude(status="NO_SIGNATURE")
            .first()
        )
        if existing:
            if existing.selected_signers != selected_signers:
                raise MpcBindingError("original unresolved session pair cannot change")
            return existing
        claim = operation.source.claim
        if claim.root.keyset.status != "ACTIVE":
            raise MpcBindingError("new session requires active original source")
        validate_financial_wallet(operation.source)
        operation_type = "WITHDRAWAL" if operation.withdrawal_id else "SWEEP"
        attempt = OnchainTransactionAttempt.objects.create(
            operation_type=operation_type,
            operation_id=operation.withdrawal_id or operation.sweep_id,
            attempt_number=MpcSolanaFinancialSession.objects.filter(operation=operation).count()
            + 1,
            chain_id="SOL",
            asset_key=claim.asset.asset_key,
            from_address=claim.address,
            to_address=operation.destination_address,
            amount=operation.amount,
            base_unit_amount=operation.base_unit_amount,
        )
        row = MpcSolanaFinancialSession.objects.create(
            operation=operation, attempt=attempt, selected_signers=selected_signers
        )
        _audit("SOL_FIN_SESSION_ALLOCATE", row, operator_ref)
        return row


def request_query(*, session_id, tenant_id, purpose, operator_ref):
    """Append a new 15s challenge; never extend/reuse an old query lease."""
    _standalone()
    _runtime()
    session_id, tenant_id = _uuid(session_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    if purpose not in {"ADMISSION", "RECOVERY", "TERMINAL"}:
        raise MpcBindingError("explicit financial query purpose required")
    anchor, key_id, _ = _pin()
    with transaction.atomic():
        row = (
            MpcSolanaFinancialSession.objects.select_for_update(of=("self",))
            .select_related("operation__source__claim__root")
            .get(pk=session_id, operation__principal__tenant_id=tenant_id)
        )
        claim = row.operation.source.claim
        challenge = secrets.token_hex(32)
        query = {
            "anchor_id": str(anchor),
            "root_identity": _fingerprint("SOLANA_SEEDED_ROOT_V1", claim.root.statement),
            "challenge": challenge,
            "execution_id": str(row.crypto_execution_id),
            "claim_reservation_id": str(claim.pk),
        }
        lease = MpcSolanaFinancialQuery.objects.create(
            challenge=challenge,
            session=row,
            purpose=purpose,
            witness_anchor_id=anchor,
            witness_key_id=key_id,
            query=query,
            expires_at=timezone.now() + timedelta(seconds=15),
        )
        _audit("SOL_FIN_QUERY_ALLOCATE", lease, operator_ref)
        return {
            "query": query,
            "expires_at": lease.expires_at.isoformat(),
            "lifecycle_action": {
                "kind": "CloseNoSignature",
                "execution_id": str(row.crypto_execution_id),
            }
            if purpose == "TERMINAL"
            else None,
        }


def complete_no_signature(*, session_id, tenant_id, challenge, evidence, operator_ref):
    """Only an original pinned W terminal reply permits a fresh attempt.

    Current implementation handles unprepared allocations only. Once an exact
    intent exists, original-binding recovery requires the typed signer path.
    It never releases a business hold or posts a ledger event.
    """
    _standalone()
    _runtime()
    session_id, tenant_id = _uuid(session_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    with transaction.atomic():
        ref = MpcSolanaFinancialSession.objects.only("operation_id").get(pk=session_id)
        operation = _locked_operation(ref.operation_id, tenant_id)
        row = MpcSolanaFinancialSession.objects.select_for_update().get(
            pk=session_id, operation=operation
        )
        if row.status == "NO_SIGNATURE":
            return row
        lease = MpcSolanaFinancialQuery.objects.select_for_update().get(
            pk=challenge, session=row, purpose="TERMINAL"
        )
        value = _verify("WITNESS_QUERY_REPLY_V1", evidence)
        anchor, key_id, _ = _pin()
        claim = operation.source.claim
        if (
            row.status != "ALLOCATED"
            or row.intent
            or row.signature_hex
            or value.get("query") != lease.query
            or evidence["key_id"] != lease.witness_key_id
            or (anchor, key_id) != (lease.witness_anchor_id, lease.witness_key_id)
            or value.get("root", {}).get("original") != claim.root.statement
            or value.get("claim") != claim.evidence
            or value.get("abandoned") is not True
            or value.get("execution") is not None
            or type(value.get("sequence")) is not int
            or value["sequence"] <= 0
        ):
            raise MpcBindingError("original unprepared execution abandonment proof required")
        if timezone.now() >= lease.expires_at:
            raise MpcBindingError(
                "terminal query expired; retain original session and business hold"
            )
        lease.status, lease.evidence = "VERIFIED", evidence
        lease.save(update_fields=["status", "evidence"])
        row.status, row.no_signature_evidence = "NO_SIGNATURE", evidence
        row.save(update_fields=["status", "no_signature_evidence", "updated_at"])
        _audit("SOL_FIN_NO_SIGNATURE", row, operator_ref)
        return row
