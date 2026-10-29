"""Operator-only native publication, with independent permanent witness grants.

The backend never owns the lifecycle key. Export the durable public query/action
to that authority and relay its signed witness response. No SPL publication is
available here until initialization and finality have their own acceptance.
"""

import hashlib
import json
import re
import secrets
from datetime import timedelta
from pathlib import Path
from uuid import UUID

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .identity_registry import _standalone, _text, _uuid
from .models import Asset, MpcKeyset, MpcSolanaClaim, MpcSolanaIssuance, MpcSolanaRoot, UserWallet
from .mpc_binding import MpcBindingError
from .mpc_solana_network import network_identity, verify_solana_rpc_endpoints
from .native_tx import RequestsTransport
from .solana_provisioning import (
    VERSION,
    _asset_statement,
    _audit,
    _runtime,
    _validate_root,
    _verify,
)
from .solana_seeded import account_address


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _fingerprint(domain, value):
    return hashlib.sha256(domain.encode() + b"\0" + _canonical(value)).hexdigest()


def _pin():
    try:
        anchor = UUID(settings.MPC_SOLANA_WITNESS_ANCHOR_ID)
        cert = x509.load_pem_x509_certificate(
            Path(settings.MPC_SOLANA_WITNESS_CERTIFICATE).read_bytes()
        )
        key = cert.public_key()
        uris = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
        if (
            anchor.int == 0
            or uris != ["spiffe://wallet-mpc/witness"]
            or cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            or not isinstance(key, ec.EllipticCurvePublicKey)
            or not isinstance(key.curve, ec.SECP256R1)
        ):
            raise ValueError
        ident = hashlib.sha256(
            key.public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
            )
        ).hexdigest()
        return anchor, ident, key
    except (OSError, TypeError, ValueError, x509.ExtensionNotFound):
        raise MpcBindingError(
            "independently installed current witness authority required"
        ) from None


def _query(row):
    return {
        "anchor_id": str(row.witness_anchor_id),
        "root_identity": _fingerprint("SOLANA_SEEDED_ROOT_V1", row.claim.root.statement),
        "challenge": row.query_challenge,
        "execution_id": None,
        "claim_reservation_id": str(row.claim_id),
    }


def _claim(claim, tenant_id):
    root = claim.root
    _validate_root(root)
    _verify("root", root.statement, root.evidence)
    _verify("claim", claim.statement, claim.evidence)
    asset, namespace = _asset_statement(claim.asset)
    expected = {
        "root": root.statement,
        "reservation_id": str(claim.pk),
        "owner_ref": claim.principal.ledger_owner_id,
        "idempotency_key": claim.idempotency_key,
        "index": claim.index,
        "asset": asset,
    }
    if (
        root.tenant_id != tenant_id
        or claim.principal.tenant_id != tenant_id
        or root.network_identity != network_identity("SOL")
        or root.status != "APPROVED"
        or claim.status != "APPROVED"
        or root.keyset.status != "ACTIVE"
        or asset != {"kind": "Native"}
        or namespace != claim.asset_namespace
        or expected != claim.statement
        or claim.address != account_address(root.base_address, claim.index)
    ):
        raise MpcBindingError("exact approved native owner/root/network/asset/address required")


def _locked_claim(reservation_id, tenant_id):
    # Consistent keyset -> root -> claim order. No transaction spans remote I/O.
    ref = MpcSolanaClaim.objects.only("root_id").get(pk=reservation_id, root__tenant_id=tenant_id)
    MpcKeyset.objects.select_for_update().get(pk=ref.root_id)
    MpcSolanaRoot.objects.select_for_update().get(pk=ref.root_id)
    claim = (
        MpcSolanaClaim.objects.select_for_update(of=("self",))
        .select_related("root__keyset", "principal", "asset")
        .get(pk=reservation_id)
    )
    claim.asset = Asset.objects.select_for_update().get(pk=claim.asset_id)
    return claim


def publication_request(*, reservation_id, tenant_id, operator_ref):
    """Persist/recover one immutable issuance UUID and a bounded public query.

    Only a PENDING query's challenge may be refreshed. Delayed replies cannot
    answer a newer challenge. The original issuance/grant ID never changes.
    """
    _standalone()
    _runtime()
    reservation_id, tenant_id = _uuid(reservation_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    anchor, key_id, _ = _pin()
    with transaction.atomic():
        claim = _locked_claim(reservation_id, tenant_id)
        _claim(claim, tenant_id)
        row = MpcSolanaIssuance.objects.select_for_update().filter(claim=claim).first()
        if row is None:
            row = MpcSolanaIssuance.objects.create(
                claim=claim,
                witness_anchor_id=anchor,
                witness_key_id=key_id,
                query_challenge=secrets.token_hex(32),
                query_expires_at=timezone.now() + timedelta(seconds=15),
            )
            _audit("SOLANA_ISSUANCE_RESERVE", row, operator_ref)
        elif row.witness_anchor_id != anchor or row.witness_key_id != key_id:
            raise MpcBindingError("original publication authority cannot be replaced")
        elif row.status == "PENDING" and timezone.now() >= row.query_expires_at:
            row.query_challenge = secrets.token_hex(32)
            row.query_expires_at = timezone.now() + timedelta(seconds=15)
            row.save(update_fields=["query_challenge", "query_expires_at"])
            _audit("SOLANA_ISSUANCE_QUERY_REFRESH", row, operator_ref)
        return {
            "issuance_id": str(row.pk),
            "status": row.status,
            "witness_action": {
                "kind": "IssueNativeClaim",
                "reservation_id": str(claim.pk),
                "issuance_id": str(row.pk),
            },
            "query": _query(row),
        }


def _witness(row, signed):
    """Verify fresh/current authority separately from archival claim receipts."""
    try:
        anchor, key_id, key = _pin()
        if (
            anchor != row.witness_anchor_id
            or key_id != row.witness_key_id
            or set(signed) != {"key_id", "value", "signature"}
            or signed["key_id"] != key_id
            or not re.fullmatch(r"[0-9a-f]{16,160}", signed["signature"])
        ):
            raise ValueError
        content = {"key_id": key_id, "value": signed["value"]}
        message = b"Wallet-MPC/WITNESS_QUERY_REPLY_V1\0" + _canonical(content)
        if len(message) > 1024 * 1024:
            raise ValueError
        key.verify(bytes.fromhex(signed["signature"]), message, ec.ECDSA(hashes.SHA256()))
        value = signed["value"]
        grant = value["claim_issuance"]
        root = value["root"]
        if (
            value["query"] != _query(row)
            or value["claim"] != row.claim.evidence
            or root["original"] != row.claim.root.statement
            or value["execution"] is not None
            or value["abandoned"] is not False
            or type(value["sequence"]) is not int
            or value["sequence"] <= 0
            or type(root["revision"]) is not int
            or root["revision"] <= 0
            or root["phase"] not in {"Active", "Frozen", "Prepared"}
            or set(grant) != {"reservation_id", "issuance_id", "command_id"}
            or grant["reservation_id"] != str(row.claim_id)
            or grant["issuance_id"] != str(row.pk)
            or str(UUID(grant["command_id"])) != grant["command_id"]
            or UUID(grant["command_id"]).int == 0
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, InvalidSignature):
        raise MpcBindingError("original independent witness publication grant required") from None


def complete_publication(*, issuance_id, tenant_id, evidence, operator_ref, transport=None):
    _standalone()
    _runtime()
    issuance_id, tenant_id = _uuid(issuance_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    ref = MpcSolanaIssuance.objects.get(pk=issuance_id, claim__root__tenant_id=tenant_id)
    verify_solana_rpc_endpoints("SOL", transport or RequestsTransport())
    with transaction.atomic():
        claim = _locked_claim(ref.claim_id, tenant_id)
        _claim(claim, tenant_id)
        row = (
            MpcSolanaIssuance.objects.select_for_update(of=("self",))
            .select_related("claim__root")
            .get(pk=issuance_id)
        )
        if row.status == "WITNESSED":
            _witness(row, row.evidence)
            return UserWallet.objects.get(solana_claim=claim)
        _witness(row, evidence)
        if timezone.now() >= row.query_expires_at:
            raise MpcBindingError("publication query expired; recover the original issuance ID")
        row.status, row.evidence = "WITNESSED", evidence
        row.save(update_fields=["status", "evidence"])
        wallet = UserWallet.objects.create(
            solana_claim=claim,
            user_id=claim.principal.ledger_owner_id,
            chain_id="SOL",
            asset_key=claim.asset.asset_key,
            deposit_address=claim.address,
            derivation_path=f"solana:{claim.root.keyset.keyset_id}:{claim.index}",
            address_index=claim.index,
            mpc_keyset=claim.root.keyset,
            derivation_version=VERSION,
        )
        _audit("SOLANA_NATIVE_WALLET_PUBLISH", row, operator_ref)
        return wallet
