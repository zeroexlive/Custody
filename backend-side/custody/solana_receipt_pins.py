"""Original receipt identities; installed operator config is the only bootstrap.

Snapshots contain public DER, never private keys or coordinator-supplied trust.
No-row legacy validation retains its original global pins. An existing malformed
snapshot fails closed; changes to installed files cannot replace archived trust.
"""

import re
from pathlib import Path
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.db import connection, transaction

from .identity_registry import _standalone, _text, _uuid
from .models import AdminActionLog, MpcKeyset, MpcSolanaClaim, MpcSolanaReceiptPins, MpcSolanaRoot
from .mpc_binding import PARTICIPANTS, MpcBindingError
from .mpc_receipts import verify_receipts


def configured_cohorts():
    cohorts = settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES
    try:
        if not isinstance(cohorts, dict):
            raise ValueError
        for keyset_id, pins in cohorts.items():
            if (
                not isinstance(keyset_id, str)
                or str(UUID(keyset_id)) != keyset_id
                or not UUID(keyset_id).int
                or not isinstance(pins, dict)
                or set(pins) != set(PARTICIPANTS)
                or any(not isinstance(path, str) or not path for path in pins.values())
            ):
                raise ValueError
        return cohorts
    except (ValueError, TypeError, AttributeError):
        raise MpcBindingError("invalid independently installed Solana receipt cohort map") from None


def _decode(value):
    from .solana_witness_client import _require_role

    try:
        if not isinstance(value, dict) or set(value) != set(PARTICIPANTS):
            raise ValueError
        result, identities = {}, set()
        for party in PARTICIPANTS:
            encoded = value[party]
            if (
                not isinstance(encoded, str)
                or not 256 <= len(encoded) <= 32768
                or len(encoded) % 2
                or not re.fullmatch("[0-9a-f]+", encoded)
            ):
                raise ValueError
            der = bytes.fromhex(encoded)
            cert = x509.load_der_x509_certificate(der)
            if cert.public_bytes(serialization.Encoding.DER) != der:
                raise ValueError
            _require_role(cert, party)
            key = cert.public_key()
            if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
                key.curve, ec.SECP256R1
            ):
                raise ValueError
            identities.add(
                key.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
            result[party] = der
        if len(identities) != 3:
            raise ValueError
        return result
    except (KeyError, TypeError, ValueError, x509.ExtensionNotFound):
        raise MpcBindingError("invalid immutable Solana receipt pins; quarantine Root") from None


def installed_certificates(keyset_id):
    pins = configured_cohorts().get(str(keyset_id), settings.MPC_HD_SIGNER_CERTIFICATES)
    try:
        if not isinstance(pins, dict) or set(pins) != set(PARTICIPANTS):
            raise ValueError
        value = {}
        for party in PARTICIPANTS:
            raw = Path(pins[party]).read_bytes()
            if len(raw) > 32768:
                raise ValueError
            value[party] = (
                x509.load_pem_x509_certificate(raw).public_bytes(serialization.Encoding.DER).hex()
            )
        _decode(value)
        return value
    except (OSError, ValueError, TypeError):
        raise MpcBindingError(
            "three independently installed Solana receipt leaves required"
        ) from None


def certificates_for_statement(kind, statement):
    """Exact Root binding, never inferred from an uploaded pin or a claim owner."""
    try:
        root_statement = statement if kind == "root" else statement["root"]
        keyset_id = UUID(root_statement["dkg"]["keyset_id"])
        root = MpcSolanaRoot.objects.get(keyset__keyset_id=keyset_id)
        if root.statement != root_statement:
            raise ValueError
        row = MpcSolanaReceiptPins.objects.filter(root=root).first()
        if row is None and root.receipt_pins_reserved:
            raise MpcBindingError("required original Root receipt pins are missing")
        return None if row is None else _decode(row.certificates_der_hex)
    except (KeyError, TypeError, ValueError, MpcSolanaRoot.DoesNotExist):
        raise MpcBindingError("original Root receipt pin binding mismatch") from None


def _verify_original(kind, statement, evidence, certificates):
    if (
        not isinstance(evidence, dict)
        or set(evidence) != {"statement", "participant_agreement"}
        or evidence["statement"] != statement
    ):
        raise MpcBindingError("immutable original receipt evidence required")
    verify_receipts(
        "solana_" + kind, statement, evidence["participant_agreement"], certificates=certificates
    )


def capture_new_root(root):
    """Called only inside the original Root reservation transaction, before RPC."""
    if not root.receipt_pins_reserved:
        return None
    if str(root.keyset.keyset_id) not in configured_cohorts():
        raise MpcBindingError("reserved receipt cohort configuration is missing")
    if connection.vendor != "postgresql":
        raise MpcBindingError("immutable Solana receipt cohorts require PostgreSQL")
    return MpcSolanaReceiptPins.objects.create(
        root=root,
        source="RESERVATION",
        certificates_der_hex=installed_certificates(root.keyset.keyset_id),
    )


def import_root_receipt_pins(*, keyset_id, tenant_id, operator_ref):
    """Explicit archival import; never adopt unknown old PENDING enrollment work."""
    _standalone()
    if connection.vendor != "postgresql":
        raise MpcBindingError("immutable Solana receipt cohorts require PostgreSQL")
    from .solana_provisioning import _runtime, _validate_root

    _runtime()
    keyset_id, tenant_id = _uuid(keyset_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    with transaction.atomic():
        keyset = MpcKeyset.objects.select_for_update().get(keyset_id=keyset_id)
        root = MpcSolanaRoot.objects.select_for_update().select_related("keyset").get(keyset=keyset)
        if root.tenant_id != tenant_id or root.status != "APPROVED":
            raise MpcBindingError("original approved Root and tenant required for archival import")
        _validate_root(root)
        existing = MpcSolanaReceiptPins.objects.filter(root=root).first()
        value = existing.certificates_der_hex if existing else installed_certificates(keyset_id)
        certificates = _decode(value)
        _verify_original("root", root.statement, root.evidence, certificates)
        # Lock all old Claims before inspecting approvals. Original reservations
        # serialize on Root; late approval cannot change the validated archive.
        for claim in MpcSolanaClaim.objects.select_for_update().filter(root=root).order_by("index"):
            if claim.status == "APPROVED" and "authority" not in claim.evidence:
                _verify_original("claim", claim.statement, claim.evidence, certificates)
        if existing:
            return existing
        row = MpcSolanaReceiptPins.objects.create(
            root=root, source="ARCHIVAL_IMPORT", certificates_der_hex=value
        )
        AdminActionLog.objects.create(
            actor_id=operator_ref,
            action_type="SOLANA_ROOT_RECEIPT_PINS_IMPORT",
            entity_type="solana_provisioning",
            entity_id=str(root.pk),
            metadata={"authority": "privileged_operator", "source": row.source},
        )
        return row
