"""Default-off public Claim registration and archival effective Evidence.

No Life/Policy key, private permit, signing/broadcast or ledger mutation. Every
query precedes external transport; immutable original Claims/attempts survive
unknown public outcomes and audit rollback.
"""

import copy
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .identity_registry import _standalone, _text, _uuid
from .models import (
    AdminActionLog,
    HotWallet,
    MpcSigningSession,
    MpcSolanaClaimApproval,
    MpcSolanaClaimQuery,
    MpcSolanaClaimRegistration,
    MpcSolanaFinancialEffect,
    MpcSolanaFinancialOperation,
    MpcSolanaFinancialQuery,
    MpcSolanaFinancialSession,
    MpcSolanaFinancialWallet,
    MpcSolanaIssuance,
    MpcSolanaMessageOwner,
    MpcSolanaSignatureOwner,
    UserWallet,
)
from .mpc_binding import MpcBindingError
from .mpc_request_auth import _authorize_message
from .mpc_solana_network import network_identity
from .solana_claim_authority import _authority, verify_current_claim
from .solana_coordinator import solana_adapter
from .solana_issuance import _canonical, _fingerprint, _locked_claim, _pin
from .solana_provisioning import _asset_statement, _runtime, _validate_root, _verify
from .solana_seeded import account_address
from .solana_witness_client import _verify as verify_witness


def _enabled():
    _runtime()
    if not settings.MPC_SOLANA_CURRENT_CLAIMS_ENABLED:
        raise MpcBindingError("current Claim registration is explicitly disabled")


def _audit(action, claim, operator_ref, **metadata):
    AdminActionLog.objects.create(
        actor_id=operator_ref,
        action_type=action,
        entity_type="solana_current_claim",
        entity_id=str(claim.pk),
        metadata={"authority": "privileged_operator", **metadata},
    )


def _reserved(claim, tenant_id):
    root = claim.root
    _validate_root(root)
    _verify("root", root.statement, root.evidence)
    asset, namespace = _asset_statement(claim.asset)
    if (
        root.status != "APPROVED"
        or root.tenant_id != tenant_id
        or claim.principal.tenant_id != tenant_id
        or root.network_identity != network_identity("SOL")
        or claim.asset_namespace != namespace
        or claim.statement
        != dict(
            root=root.statement,
            reservation_id=str(claim.pk),
            owner_ref=claim.principal.ledger_owner_id,
            idempotency_key=claim.idempotency_key,
            index=claim.index,
            asset=asset,
        )
        or claim.address
        != account_address(root.base_address, claim.index, token=not claim.asset.is_native)
        or claim.status not in {"PENDING", "APPROVED"}
    ):
        raise MpcBindingError("original reserved Claim/tenant/network/asset identity required")
    if claim.status == "APPROVED":
        _verify_evidence(claim, claim.evidence)


def _query(row):
    return dict(
        anchor_id=str(row.witness_anchor_id),
        root_identity=_fingerprint("SOLANA_SEEDED_ROOT_V1", row.claim.root.statement),
        challenge=row.challenge,
        execution_id=None,
        claim_reservation_id=str(row.claim_id),
        candidate_claim=row.claim.statement,
    )


def _proof(row, signed, *, fresh):
    anchor, key, _ = _pin()
    if (anchor, key) != (row.witness_anchor_id, row.witness_key_id):
        raise MpcBindingError("original independently installed witness authority required")
    if len(_canonical(signed)) > 1024 * 1024:
        raise MpcBindingError("bounded public witness response required")
    value = verify_witness("WITNESS_QUERY_REPLY_V1", signed)
    try:
        if (
            value["query"] != _query(row)
            or value["root"]["original"] != row.claim.root.statement
            or value["execution"] is not None
            or value["abandoned"] is not False
            or type(value["sequence"]) is not int
            or value["sequence"] <= 0
            or type(value["root"]["revision"]) is not int
            or value["root"]["revision"] <= 0
            or value["root"]["phase"] not in {"Active", "Frozen", "Prepared"}
        ):
            raise ValueError
        if fresh and not timezone.now() < row.expires_at:
            raise MpcBindingError("Claim query expired; retain original Claim/attempt/command IDs")
    except (KeyError, TypeError, ValueError):
        raise MpcBindingError("exact independently durable Claim query result required") from None
    return value


def _verify_evidence(claim, evidence):
    if isinstance(evidence, dict) and "authority" in evidence:
        verify_current_claim(
            claim.statement,
            evidence,
            lifecycle_certificate=settings.MPC_SOLANA_LIFECYCLE_CERTIFICATE,
            witness_anchor_id=settings.MPC_SOLANA_WITNESS_ANCHOR_ID,
        )
    else:
        _verify("claim", claim.statement, evidence)


def effective_claim_evidence(claim):
    """Read and re-verify authoritative archival data; never mutate Claim.evidence."""
    row = MpcSolanaClaimRegistration.objects.select_related("query").filter(claim=claim).first()
    if row is None:
        _verify("claim", claim.statement, claim.evidence)
        return copy.deepcopy(claim.evidence)
    query = row.query
    query.claim = claim
    if query.status != "VERIFIED" or claim.status != "APPROVED":
        raise MpcBindingError("original completed Claim registration required")
    value = _proof(query, query.evidence, fresh=False)
    if value.get("claim") != row.evidence:
        raise MpcBindingError("original exact permanently registered Claim Evidence required")
    _verify_evidence(claim, row.evidence)
    if claim.evidence != row.evidence:
        _verify("claim", claim.statement, claim.evidence)
    return copy.deepcopy(row.evidence)


def _allow_effective_change(claim, value):
    if claim.status == "APPROVED" and value["claim"] == claim.evidence:
        return
    # Pending public intents have consumed no grant/private authority. Keep their
    # original IDs/roles/mode, while refusing every uncertain/consumed history.
    if (
        value.get("claim_issuance") is not None
        or MpcSolanaIssuance.objects.filter(claim=claim)
        .exclude(status="PENDING", evidence={})
        .exists()
        or MpcSolanaFinancialWallet.objects.filter(claim=claim)
        .exclude(status="PENDING", evidence={}, user_wallet__isnull=True)
        .exists()
        or not _unprepared_provisioning(claim)
        or UserWallet.objects.filter(solana_claim=claim).exists()
        or UserWallet.objects.filter(chain_id="SOL", deposit_address=claim.address).exists()
        or UserWallet.objects.filter(chain_id="SOL", asset_account_address=claim.address).exists()
        or HotWallet.objects.filter(chain_id="SOL", address=claim.address).exists()
    ):
        raise MpcBindingError(
            "consumed or uncertain Claim history cannot change effective Evidence"
        )


def _unprepared_provisioning(claim):
    """Retain existing HELD/empty-ALLOCATED IDs; accept no frozen/private history."""
    operations = MpcSolanaFinancialOperation.objects.select_related("provision").filter(
        source_id=claim.pk
    )
    if operations.exclude(
        status="HELD",
        provision__status="CREATED",
        provision__tx_hash__isnull=True,
        provision__completed_at__isnull=True,
    ).exists():
        return False
    if MpcSolanaMessageOwner.objects.filter(operation__in=operations).exists():
        return False
    sessions = MpcSolanaFinancialSession.objects.select_related("attempt").filter(
        operation__in=operations
    )
    if sessions.exclude(
        status="ALLOCATED",
        intent={},
        payload=b"",
        custody_authorization={},
        policy_authorization={},
        admission_evidence={},
        no_signature_evidence={},
        signature_hex="",
        coordinator_evidence={},
        attempt__status="PREPARING",
        attempt__network_tx_id__isnull=True,
        attempt__sequence__isnull=True,
        attempt__prepared_metadata={},
        attempt__fee_metadata={},
        attempt__signed_payload="",
        attempt__expires_at__isnull=True,
        attempt__last_valid_block__isnull=True,
        attempt__broadcast_started_at__isnull=True,
        attempt__broadcast_at__isnull=True,
        attempt__confirmation_metadata={},
    ).exists():
        return False
    return not (
        MpcSolanaFinancialQuery.objects.filter(session__in=sessions)
        .exclude(status="PENDING", evidence={})
        .exists()
        or MpcSolanaSignatureOwner.objects.filter(session__in=sessions).exists()
        or MpcSolanaFinancialEffect.objects.filter(
            attempt_id__in=sessions.values("attempt_id")
        ).exists()
        or MpcSigningSession.objects.filter(attempt_id__in=sessions.values("attempt_id")).exists()
    )


def claim_query_request(*, reservation_id, tenant_id, operator_ref, attempt_id=None):
    _standalone()
    _enabled()
    reservation_id, tenant_id = _uuid(reservation_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    anchor, key, _ = _pin()
    with transaction.atomic():
        claim = _locked_claim(reservation_id, tenant_id)
        _reserved(claim, tenant_id)
        attempt = None
        if attempt_id is not None:
            attempt = MpcSolanaClaimApproval.objects.select_for_update().get(
                pk=_uuid(attempt_id), claim=claim, status="REPORTED"
            )
            _verify_evidence(claim, attempt.evidence)
        row = MpcSolanaClaimQuery.objects.create(
            claim=claim,
            witness_anchor_id=anchor,
            witness_key_id=key,
            challenge=secrets.token_hex(32),
            expires_at=timezone.now() + timedelta(seconds=15),
            purpose="REGISTRATION" if attempt else "DISCOVERY",
            attempt=attempt,
        )
        _audit("SOL_CURRENT_CLAIM_QUERY", claim, operator_ref, challenge=row.pk)
        result = dict(query=_query(row), challenge=row.pk, purpose=row.purpose)
        if attempt:
            result.update(
                command_id=str(attempt.command_id),
                witness_action=dict(kind="RegisterClaim", evidence=copy.deepcopy(attempt.evidence)),
            )
        return result


def begin_current_claim_approval(
    *, challenge, tenant_id, evidence, node_certificates_der_hex, operator_ref
):
    from pathlib import Path

    from cryptography import x509
    from cryptography.exceptions import InvalidSignature

    _standalone()
    _enabled()
    tenant_id = _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    ref = MpcSolanaClaimQuery.objects.get(pk=challenge, claim__root__tenant_id=tenant_id)
    with transaction.atomic():
        claim = _locked_claim(ref.claim_id, tenant_id)
        _reserved(claim, tenant_id)
        query = MpcSolanaClaimQuery.objects.select_for_update().get(pk=challenge)
        query.claim = claim
        previous = MpcSolanaClaimApproval.objects.filter(discovery=query).first()
        if previous:
            if query.evidence != evidence:
                raise MpcBindingError("original discovery proof cannot change")
            return previous
        if (
            query.purpose != "DISCOVERY"
            or query.status != "PENDING"
            or claim.root.keyset.status != "ACTIVE"
            or MpcSolanaClaimRegistration.objects.filter(claim=claim).exists()
        ):
            raise MpcBindingError("new original unregistered Claim discovery required")
        value = _proof(query, evidence, fresh=True)
        _allow_effective_change(claim, {**value, "claim": {}})
        availability = value.get("claim_availability")
        if (
            value.get("claim") is not None
            or value.get("claim_issuance") is not None
            or value["root"]["phase"] != "Active"
            or value["root"].get("prepared") is not None
            or value.get("refresh") is not None
            or value.get("replacement") is not None
            or value["root"]["next_claim_index"] != claim.index
            or availability
            != dict(reservation_id=str(claim.pk), index=None, owner=None, retry=None)
        ):
            raise MpcBindingError(
                "current Active unregistered frontier and unused aliases required"
            )
        authority = dict(
            version=1,
            prepare=value.get("generation_authority"),
            node_certificates_der_hex=copy.deepcopy(node_certificates_der_hex),
        )
        try:
            life = x509.load_pem_x509_certificate(
                Path(settings.MPC_SOLANA_LIFECYCLE_CERTIFICATE).read_bytes()
            )
            _authority(claim.root.statement, authority, life, query.witness_anchor_id)
            ready = authority["prepare"]["value"]["action"]
            if (
                value["root"]["generation"] != ready["ready"][0]["value"]["generation"]
                or value["root"]["public_key_package"]
                != ready["ready"][0]["value"]["public_key_package"]
                or value["root"]["node_keys"] != ready["node_keys"]
                or value.get("lifecycle_key_id") != authority["prepare"]["key_id"]
            ):
                raise ValueError
        except (
            OSError,
            TypeError,
            KeyError,
            ValueError,
            InvalidSignature,
            x509.ExtensionNotFound,
        ) as exc:
            raise MpcBindingError(
                "exact installed Lifecycle/current prepared roster required"
            ) from exc
        now = int(timezone.now().timestamp())
        body = dict(
            statement=claim.statement, authority=authority, issued_at=now, expires_at=now + 120
        )
        body["custody_authorization"] = _authorize_message(
            b"Wallet-MPC/CUSTODY_SOLANA_CURRENT_CLAIM_V1\0" + _canonical(body),
            settings.MPC_CLIENT_CERT,
            settings.MPC_CLIENT_KEY,
        )
        query.status, query.evidence = "VERIFIED", copy.deepcopy(evidence)
        query.save(update_fields=["status", "evidence"])
        attempt = MpcSolanaClaimApproval.objects.create(
            claim=claim,
            discovery=query,
            authority_identity=_fingerprint("SOLANA_CURRENT_CLAIM_AUTHORITY_V1", authority),
            approval=body,
        )
        _audit(
            "SOL_CURRENT_CLAIM_APPROVAL",
            claim,
            operator_ref,
            attempt_id=str(attempt.pk),
            command_id=str(attempt.command_id),
            challenge=query.pk,
        )
        return attempt


def record_current_claim_evidence(*, attempt_id, tenant_id, evidence, operator_ref):
    _standalone()
    _enabled()
    tenant_id = _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    ref = MpcSolanaClaimApproval.objects.get(pk=_uuid(attempt_id), claim__root__tenant_id=tenant_id)
    with transaction.atomic():
        claim = _locked_claim(ref.claim_id, tenant_id)
        _reserved(claim, tenant_id)
        attempt = MpcSolanaClaimApproval.objects.select_for_update().get(pk=ref.pk)
        if (
            not isinstance(evidence, dict)
            or evidence.get("authority") != attempt.approval["authority"]
        ):
            raise MpcBindingError("original durable approval context cannot change")
        _verify_evidence(claim, evidence)
        if attempt.status == "REPORTED":
            if attempt.evidence != evidence:
                raise MpcBindingError("original all-three current receipts cannot change")
            return attempt
        attempt.status, attempt.evidence = "REPORTED", copy.deepcopy(evidence)
        attempt.save(update_fields=["status", "evidence"])
        _audit("SOL_CURRENT_CLAIM_REPORTS", claim, operator_ref, attempt_id=str(attempt.pk))
        return attempt


def collect_current_claim_evidence(*, attempt_id, tenant_id, operator_ref, client=None):
    _standalone()
    _enabled()
    operator_ref = _text(operator_ref, "operator audit reference")
    attempt = MpcSolanaClaimApproval.objects.select_related("claim__root__keyset").get(
        pk=_uuid(attempt_id), claim__root__tenant_id=_uuid(tenant_id)
    )
    response = (
        client or solana_adapter(attempt.claim.root.keyset.keyset_id)
    ).approve_current_solana_claim(
        str(attempt.claim.root.keyset.keyset_id), copy.deepcopy(attempt.approval)
    )
    return record_current_claim_evidence(
        attempt_id=attempt.pk, tenant_id=tenant_id, evidence=response, operator_ref=operator_ref
    )


def complete_claim_registration(*, challenge, tenant_id, evidence, operator_ref):
    _standalone()
    _enabled()
    tenant_id = _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    ref = MpcSolanaClaimQuery.objects.get(pk=challenge, claim__root__tenant_id=tenant_id)
    with transaction.atomic():
        claim = _locked_claim(ref.claim_id, tenant_id)
        _reserved(claim, tenant_id)
        query = MpcSolanaClaimQuery.objects.select_for_update().get(pk=challenge)
        query.claim = claim
        existing = MpcSolanaClaimRegistration.objects.filter(claim=claim).first()
        if query.status == "VERIFIED":
            if (
                query.evidence != evidence
                or not existing
                or existing.evidence != evidence.get("value", {}).get("claim")
            ):
                raise MpcBindingError("original completed registration proof required")
            effective_claim_evidence(claim)
            return existing
        value = _proof(query, evidence, fresh=True)
        registered = value.get("claim")
        _verify_evidence(claim, registered)
        if query.attempt_id:
            attempt = MpcSolanaClaimApproval.objects.get(
                pk=query.attempt_id, claim=claim, status="REPORTED"
            )
            if registered != attempt.evidence:
                raise MpcBindingError(
                    "exact original reported attempt must be permanently registered"
                )
        if existing:
            if existing.evidence != registered:
                raise MpcBindingError("original permanent Claim registration cannot change")
        else:
            _allow_effective_change(claim, value)
        query.status, query.evidence = "VERIFIED", copy.deepcopy(evidence)
        query.save(update_fields=["status", "evidence"])
        if existing is None:
            existing = MpcSolanaClaimRegistration.objects.create(
                claim=claim, query=query, evidence=copy.deepcopy(registered)
            )
            if claim.status == "PENDING":
                claim.status, claim.evidence = "APPROVED", copy.deepcopy(registered)
                claim.save(update_fields=["status", "evidence"])
        _audit("SOL_CURRENT_CLAIM_REGISTER", claim, operator_ref, challenge=query.pk)
        return existing
