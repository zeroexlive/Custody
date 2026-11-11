"""Own-nonce public control proofs for sealed, still unpublished sources.

These archives do not publish a Claim, create membership, authorize a private
round, or establish current liveness when read later. A movement consumer must
obtain its own fresh permission and preserve the original beneficial owner.
"""

import copy
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import connection, transaction
from django.utils import timezone

from .identity_registry import _standalone, _text, _uuid
from .models import AdminActionLog, MpcSolanaRotationInventoryEntry, MpcSolanaRotationSourceQuery
from .mpc_binding import MpcBindingError
from .solana_claim_authority import _exact, _hex, _uint
from .solana_claim_registration import _verify_evidence
from .solana_issuance import _canonical, _fingerprint, _pin
from .solana_provisioning import _runtime
from .solana_receipt_pins import _decode, certificates_for_statement, installed_certificates
from .solana_rotation_inventory import _current_role, _historical_claim, _locked, export_slice
from .solana_witness_client import _point_id
from .solana_witness_client import _verify as verify_witness


def _audit(action, row, operator_ref):
    AdminActionLog.objects.create(
        actor_id=operator_ref,
        action_type=action,
        entity_type="solana_rotation_source",
        entity_id=row.pk,
        metadata={"authority": "privileged_operator"},
    )


def _entry(snapshot_id, tenant_id, ordinal):
    if type(ordinal) is not int or ordinal < 0:
        raise MpcBindingError("original source ordinal required")
    # Reverify the historical header, seal, entry and original publication proofs.
    exported = export_slice(snapshot_id=snapshot_id, tenant_id=tenant_id, start_index=ordinal)
    entry = MpcSolanaRotationInventoryEntry.objects.select_related(
        "snapshot__pause__root__keyset",
        "snapshot__header_query",
        "snapshot__seal_query",
        "claim__root__keyset",
        "claim__asset",
        "claim__principal",
    ).get(snapshot_id=snapshot_id, ordinal=ordinal)
    if not exported["entries"] or exported["entries"][0] != entry.source:
        raise MpcBindingError("exact original sealed source required")
    _historical_claim(entry.claim)
    _current_role(entry)
    return entry


def _query(row):
    entry, snapshot = row.entry, row.entry.snapshot
    return dict(
        anchor_id=str(snapshot.witness_anchor_id),
        root_identity=snapshot.root_identity,
        challenge=row.challenge,
        execution_id=None,
        claim_reservation_id=str(entry.claim_id),
        candidate_claim=copy.deepcopy(entry.original_record["claim"]),
        rotation_id=str(row.rotation_id),
    )


def request_source_query(*, snapshot_id, tenant_id, ordinal, rotation_id, operator_ref):
    _standalone()
    _runtime()
    if not settings.MPC_SOLANA_ROTATION_INVENTORY_ENABLED:
        raise MpcBindingError("new rotation source queries are disabled")
    if connection.vendor != "postgresql":
        raise MpcBindingError("durable rotation source queries require PostgreSQL")
    snapshot_id, tenant_id, rotation_id = map(_uuid, (snapshot_id, tenant_id, rotation_id))
    operator_ref = _text(operator_ref, "operator audit reference")
    with transaction.atomic():
        _locked(snapshot_id, tenant_id)
        entry = _entry(snapshot_id, tenant_id, ordinal)
        row = MpcSolanaRotationSourceQuery.objects.create(
            entry=entry,
            rotation_id=rotation_id,
            challenge=secrets.token_hex(32),
            expires_at=timezone.now() + timedelta(seconds=15),
        )
        _audit("SOLANA_ROTATION_SOURCE_QUERY", row, operator_ref)
        return dict(query=_query(row), expires_at=row.expires_at.isoformat())


def _original_roster(entry):
    from cryptography import x509

    certificates = certificates_for_statement("claim", entry.claim.statement)
    if certificates is None:
        certificates = _decode(installed_certificates(entry.claim.root.keyset.keyset_id))
    return {
        party: _point_id(x509.load_der_x509_certificate(der).public_key())
        for party, der in certificates.items()
    }


def _proof(row, signed, *, fresh):
    entry, snapshot = row.entry, row.entry.snapshot
    if _pin()[:2] != (snapshot.witness_anchor_id, snapshot.witness_key_id):
        raise MpcBindingError("original independently installed rotation witness required")
    if len(_canonical(signed)) > 1024 * 1024:
        raise MpcBindingError("bounded source control reply required")
    value = verify_witness("WITNESS_QUERY_REPLY_V1", signed)
    try:
        root, source = value["root"], entry.source
        rotation, evidence = root["rotation"], value["claim"]
        captured = snapshot.seal_query.evidence["value"]
        _uint(value["sequence"], positive=True)
        _uint(root["revision"], positive=True)
        _uint(root["next_claim_index"])
        _exact(
            rotation,
            "rotation_id source_identity target_identity business_fingerprint status "
            "next_index allocated_high_water inventory_fingerprint",
        )
        for field in ("target_identity", "business_fingerprint"):
            if not any(_hex(rotation[field])):
                raise ValueError("nonzero canonical rotation identity required")
        if rotation["target_identity"] == snapshot.root_identity:
            raise ValueError("distinct target Root required")
        if (
            value["query"] != _query(row)
            or value["execution"] is not None
            or value["abandoned"] is not False
            or root["original"] != entry.claim.root.statement
            or root["phase"] != "Frozen"
            or root["prepared"] is not None
            or (root.get("financial_mode") or {}) != snapshot.local_mode
            or value.get("refresh") is not None
            or value.get("replacement") is not None
            or value["sequence"] < captured["sequence"]
            or root["revision"] < captured["root"]["revision"]
            or not entry.ordinal < root["next_claim_index"] <= snapshot.pause.frontier
            or any(
                root[k] != captured["root"][k]
                for k in ("generation", "public_key_package", "node_keys")
            )
            or rotation["rotation_id"] != str(row.rotation_id)
            or rotation["source_identity"] != snapshot.root_identity
            or rotation["status"] != "Sealed"
            or type(rotation["allocated_high_water"]) is not int
            or rotation["allocated_high_water"] != snapshot.pause.frontier
            or type(rotation["next_index"]) is not int
            or rotation["next_index"] != snapshot.pause.frontier
            or rotation["inventory_fingerprint"] != snapshot.inventory_fingerprint
            or value.get("claim_issuance") != source["membership"].get("issuance")
            or value["claim_availability"]
            != dict(
                reservation_id=str(entry.claim_id),
                index=str(entry.claim_id),
                owner=str(entry.claim_id),
                retry=str(entry.claim_id),
            )
        ):
            raise ValueError
        _verify_evidence(entry.claim, evidence)
        evidence_fp = _fingerprint("SOLANA_ROTATION_CLAIM_EVIDENCE_V1", evidence)
        original_fp = source.get("witness_evidence_fingerprint")
        provenance = value.get("rotation_claim_registration")
        if original_fp is not None:
            if original_fp != evidence_fp or provenance is not None:
                raise ValueError("preserve originally registered source evidence")
        else:
            # New readonly registration supplies actual current source receipts.
            # Already registered Evidence stays archival across later refreshes;
            # never demand that an immutable old receipt become a new receipt.
            authority = evidence.get("authority")
            if authority is None:
                if (
                    root["generation"]["epoch"] != 0
                    or root["node_keys"] != _original_roster(entry)
                    or value.get("generation_authority") is not None
                ):
                    raise ValueError("exact original source cohort required")
            elif (
                authority["prepare"] != value.get("generation_authority")
                or authority["prepare"]["value"]["action"]["node_keys"] != root["node_keys"]
                or any(
                    report["value"]["generation"] != root["generation"]
                    or report["value"]["public_key_package"] != root["public_key_package"]
                    for report in authority["prepare"]["value"]["action"]["ready"]
                )
            ):
                raise ValueError("exact accepted current source authority required")
            _exact(
                provenance,
                "rotation_id command_id reservation_id source_fingerprint evidence_fingerprint",
            )
            command_id = _uuid(provenance["command_id"])
            if (
                provenance
                != dict(
                    rotation_id=str(row.rotation_id),
                    command_id=str(command_id),
                    reservation_id=str(entry.claim_id),
                    source_fingerprint=_fingerprint("SOLANA_ROTATION_SOURCE_V1", source),
                    evidence_fingerprint=evidence_fp,
                )
                or command_id in {row.rotation_id, entry.claim_id, snapshot.witness_anchor_id}
                or source["membership"]
                not in (
                    {"kind": "Unpublished"},
                    {"kind": "LegacyControl"},
                )
            ):
                raise ValueError("exact original rotation registration provenance required")
        if fresh and timezone.now() >= row.expires_at:
            raise MpcBindingError("source query expired; retain all original IDs and proofs")
    except MpcBindingError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError):
        raise MpcBindingError(
            "exact sealed source control and own witness query required"
        ) from None
    return value


def accept_source_query(*, challenge, tenant_id, evidence, operator_ref):
    _standalone()
    _runtime()
    tenant_id = _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    evidence = copy.deepcopy(evidence)
    ref = MpcSolanaRotationSourceQuery.objects.select_related("entry").get(
        pk=challenge, entry__snapshot__pause__root__tenant_id=tenant_id
    )
    with transaction.atomic():
        _locked(ref.entry.snapshot_id, tenant_id)
        entry = _entry(ref.entry.snapshot_id, tenant_id, ref.entry.ordinal)
        row = MpcSolanaRotationSourceQuery.objects.select_for_update().get(pk=challenge)
        row.entry = entry
        if row.status == "VERIFIED":
            if row.evidence != evidence:
                raise MpcBindingError("original accepted source reply cannot change")
            _proof(row, evidence, fresh=False)
            return row
        _proof(row, evidence, fresh=True)
        row.status, row.evidence = "VERIFIED", evidence
        row.save(update_fields=["status", "evidence"])
        _audit("SOLANA_ROTATION_SOURCE_ACCEPT", row, operator_ref)
        return row


def source_control_archive(*, challenge, tenant_id):
    """Reverify historical public proof; this read is NEVER a fresh private grant."""
    tenant_id = _uuid(tenant_id)
    row = MpcSolanaRotationSourceQuery.objects.select_related("entry").get(
        pk=challenge, status="VERIFIED", entry__snapshot__pause__root__tenant_id=tenant_id
    )
    row.entry = _entry(row.entry.snapshot_id, tenant_id, row.entry.ordinal)
    value = _proof(row, row.evidence, fresh=False)
    return dict(
        challenge=row.pk,
        rotation_id=str(row.rotation_id),
        original_source=copy.deepcopy(row.entry.source),
        registered_evidence=copy.deepcopy(value["claim"]),
        registration=copy.deepcopy(value.get("rotation_claim_registration")),
    )
