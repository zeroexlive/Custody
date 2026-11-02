"""Original financial-wallet membership with independent issuance grants.

ACTIVE here is an immutable publication/ownership record. It posts no balances,
does not authorize private signing or deposit credit by itself. Dedicated typed
financial services enforce their own admission. Treasury never creates a UserWallet.
"""

import secrets
from datetime import timedelta

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .identity_registry import _standalone, _text, _uuid
from .models import (
    CustodyPrincipalRole,
    HotWallet,
    MpcSolanaFinancialRoot,
    MpcSolanaFinancialWallet,
    MpcSolanaIssuance,
    UserWallet,
)
from .mpc_binding import MpcBindingError
from .mpc_solana_network import verify_solana_rpc_endpoints
from .native_tx import RequestsTransport
from .solana_financial_root import verify_financial_mode
from .solana_issuance import _claim, _locked_claim, _pin, _query, _witness
from .solana_provisioning import VERSION, _audit, _runtime

ROLES = {"CUSTOMER": "CUSTOMER_DEPOSIT", "TREASURY": "TENANT_TREASURY"}


def _membership(claim, *, historical=False):
    _claim(claim, claim.root.tenant_id, historical=historical)
    try:
        mode = MpcSolanaFinancialRoot.objects.select_related("root").get(
            root_id=claim.root_id, status="VERIFIED"
        )
        classification = CustodyPrincipalRole.objects.get(principal_id=claim.principal_id)
    except (MpcSolanaFinancialRoot.DoesNotExist, CustodyPrincipalRole.DoesNotExist):
        raise MpcBindingError("verified financial Root and explicit owner role required") from None
    verify_financial_mode(mode)
    return mode, ROLES[classification.role]


def _grant(mode, issuance, signed):
    _witness(issuance, signed)
    expected = {
        "version": 1,
        "activation_id": str(mode.activation_id),
        "command_id": str(mode.command_id),
    }
    if signed["value"]["root"].get("financial_mode") != expected or (
        issuance.witness_anchor_id,
        issuance.witness_key_id,
    ) != (mode.witness_anchor_id, mode.witness_key_id):
        raise MpcBindingError(
            "original irreversible financial mode and issuance authority required"
        )


def _view(row):
    view = {
        "financial_wallet_id": str(row.claim_id),
        "status": row.status,
        "role": row.role,
        "issuance_id": str(row.issuance_id),
        "witness_action": {
            "kind": "IssueNativeClaim",
            "reservation_id": str(row.claim_id),
            "issuance_id": str(row.issuance_id),
        },
        "query": _query(row.issuance),
    }
    if not row.claim.asset.is_native:
        from .solana_token_provisioning import publication_action

        view["witness_action"] = publication_action(row)
        view["initialization_required"] = view["witness_action"] is None
    return view


def financial_wallet_request(*, reservation_id, tenant_id, operator_ref):
    """Commit both original intents before exporting a grant action or query."""
    _standalone()
    _runtime()
    reservation_id, tenant_id = _uuid(reservation_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    anchor, key_id, _ = _pin()
    with transaction.atomic():
        claim = _locked_claim(reservation_id, tenant_id)
        if not claim.asset.is_native:
            from .solana_token_provisioning import require_spl_enabled

            require_spl_enabled()
        mode, role = _membership(claim)
        row = MpcSolanaFinancialWallet.objects.select_for_update().filter(claim=claim).first()
        if row is None:
            if (
                MpcSolanaIssuance.objects.filter(claim=claim).exists()
                or UserWallet.objects.filter(
                    Q(solana_claim=claim)
                    | Q(chain_id="SOL", deposit_address=claim.address)
                    | Q(chain_id="SOL", asset_account_address=claim.address)
                ).exists()
                or HotWallet.objects.filter(chain_id="SOL", address=claim.address).exists()
            ):
                raise MpcBindingError("existing wallet/address/issuance cannot be adopted")
            issuance = MpcSolanaIssuance.objects.create(
                claim=claim,
                witness_anchor_id=anchor,
                witness_key_id=key_id,
                query_challenge=secrets.token_hex(32),
                query_expires_at=timezone.now() + timedelta(seconds=15),
            )
            row = MpcSolanaFinancialWallet.objects.create(
                claim=claim, mode=mode, issuance=issuance, role=role
            )
            _audit("SOL_FIN_WALLET_RESERVE", row, operator_ref)
        else:
            issuance = MpcSolanaIssuance.objects.select_for_update().get(pk=row.issuance_id)
            if row.role != role or row.mode_id != mode.pk or issuance.claim_id != claim.pk:
                raise MpcBindingError("original financial wallet identity cannot change")
            if row.status == "ACTIVE":
                validate_financial_wallet(row)
                return _view(row)
            if (issuance.witness_anchor_id, issuance.witness_key_id) != (anchor, key_id):
                raise MpcBindingError("original financial publication authority cannot change")
            if issuance.status != "PENDING":
                raise MpcBindingError("incomplete financial publication history")
            if timezone.now() >= issuance.query_expires_at:
                issuance.query_challenge = secrets.token_hex(32)
                issuance.query_expires_at = timezone.now() + timedelta(seconds=15)
                issuance.save(update_fields=["query_challenge", "query_expires_at"])
                _audit("SOL_FIN_WALLET_QUERY_REFRESH", row, operator_ref)
        row.issuance, row.claim = issuance, claim
        return _view(row)


def validate_financial_wallet(row):
    """Verify stored original ownership; no fresh Active/spending or ledger grant.

    Always reload the authoritative row and linked public proofs. New spend
    admission separately locks its own operation/reserve and consumes a fresh W query. Historical
    registration does not disappear when the source keyset is retired.
    """
    row = MpcSolanaFinancialWallet.objects.select_related(
        "claim__root__keyset",
        "claim__principal",
        "claim__asset",
        "mode__root",
        "issuance__claim__root",
    ).get(pk=row.pk)
    mode, role = _membership(row.claim, historical=True)
    issuance = row.issuance
    if (
        row.status != "ACTIVE"
        or row.mode_id != mode.pk
        or row.role != role
        or issuance.claim_id != row.claim_id
        or issuance.status != "WITNESSED"
        or row.evidence != issuance.evidence
    ):
        raise MpcBindingError("original active financial wallet membership required")
    _grant(mode, issuance, row.evidence)
    if not row.claim.asset.is_native:
        from .models import MpcSolanaTokenPublication
        from .solana_token_provisioning import accepted_initialization

        _, effect = accepted_initialization(row.claim_id)
        if not MpcSolanaTokenPublication.objects.filter(claim=row.claim, effect=effect).exists():
            raise MpcBindingError("original finalized classic token publication proof required")
    if role == "TENANT_TREASURY":
        if (
            row.user_wallet_id is not None
            or UserWallet.objects.filter(solana_claim_id=row.claim_id).exists()
        ):
            raise MpcBindingError("treasury cannot become a customer deposit wallet")
    else:
        try:
            wallet = UserWallet.objects.get(pk=row.user_wallet_id)
        except UserWallet.DoesNotExist:
            raise MpcBindingError("original customer wallet link missing") from None
        claim = row.claim
        if (
            wallet.solana_claim_id != row.claim_id
            or wallet.user_id != claim.principal.ledger_owner_id
            or wallet.chain_id != "SOL"
            or wallet.asset_key != claim.asset.asset_key
            or wallet.deposit_address != claim.address
            or wallet.mpc_keyset_id != claim.root_id
            or wallet.derivation_version != VERSION
            or wallet.derivation_path != f"solana:{claim.root.keyset.keyset_id}:{claim.index}"
            or wallet.address_index != claim.index
            or wallet.custody_account_id is not None
            or wallet.asset_account_address != (None if claim.asset.is_native else claim.address)
            or wallet.memo is not None
        ):
            raise MpcBindingError("original customer financial wallet identity mismatch")
    return row


def complete_financial_wallet(*, reservation_id, tenant_id, evidence, operator_ref, transport=None):
    _standalone()
    _runtime()
    reservation_id, tenant_id = _uuid(reservation_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    transport = transport or RequestsTransport()
    verify_solana_rpc_endpoints("SOL", transport)
    snapshot = MpcSolanaFinancialWallet.objects.select_related("claim__root", "claim__asset").get(
        claim_id=reservation_id, claim__root__tenant_id=tenant_id
    )
    initialized = None
    if not snapshot.claim.asset.is_native and snapshot.status != "ACTIVE":
        from .solana_token_provisioning import observe_publication_account

        initialized = observe_publication_account(snapshot.claim, transport)
    with transaction.atomic():
        claim = _locked_claim(reservation_id, tenant_id)
        row = MpcSolanaFinancialWallet.objects.select_for_update().get(claim=claim)
        row.claim = claim
        issuance = MpcSolanaIssuance.objects.select_for_update().get(pk=row.issuance_id)
        if issuance.claim_id != claim.pk:
            raise MpcBindingError("original financial issuance belongs to another Claim")
        issuance.claim = claim
        row.issuance = issuance
        if row.status == "ACTIVE":
            return validate_financial_wallet(row)
        mode, role = _membership(claim)
        if row.mode_id != mode.pk or row.role != role or issuance.status != "PENDING":
            raise MpcBindingError("original pending financial wallet intent required")
        _grant(mode, issuance, evidence)
        if timezone.now() >= issuance.query_expires_at:
            raise MpcBindingError("financial publication query expired; retain original IDs")
        issuance.status, issuance.evidence = "WITNESSED", evidence
        issuance.save(update_fields=["status", "evidence"])
        if not claim.asset.is_native:
            from .models import MpcSolanaTokenPublication
            from .solana_financial_preparation import _effect_slot
            from .solana_token_provisioning import accepted_initialization

            session, effect = accepted_initialization(claim.pk)
            if (
                initialized is None
                or (session.pk, effect.pk) != (initialized[0].pk, initialized[1].pk)
                or initialized[2]["context_slot"] < _effect_slot(claim.root_id)
            ):
                raise MpcBindingError("original current classic initialization proof required")
            MpcSolanaTokenPublication.objects.create(
                claim=claim,
                effect=effect,
                account_context_slot=initialized[2]["context_slot"],
                account_evidence=initialized[2],
            )
        if role == "CUSTOMER_DEPOSIT":
            row.user_wallet = UserWallet.objects.create(
                solana_claim=claim,
                user_id=claim.principal.ledger_owner_id,
                chain_id="SOL",
                asset_key=claim.asset.asset_key,
                deposit_address=claim.address,
                asset_account_address=None if claim.asset.is_native else claim.address,
                derivation_path=f"solana:{claim.root.keyset.keyset_id}:{claim.index}",
                address_index=claim.index,
                mpc_keyset=claim.root.keyset,
                derivation_version=VERSION,
            )
        row.status, row.evidence = "ACTIVE", evidence
        row.save(update_fields=["status", "evidence", "user_wallet"])
        _audit("SOL_FIN_WALLET_ACTIVATE", row, operator_ref)
        return validate_financial_wallet(row)
