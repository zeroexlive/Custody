"""Actual PG and public P256 contracts; synthetic receipts are not MPC evidence."""

import copy
import json
from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest.mock import patch
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.core.management import call_command
from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor

from custody.models import AdminActionLog, MpcSolanaReceiptPins
from custody.mpc_binding import PARTICIPANTS, MpcBindingError
from custody.mpc_receipts import receipt_message
from custody.solana_provisioning import _verify
from custody.solana_receipt_pins import (
    import_root_receipt_pins,
    installed_certificates,
)
from custody.tests.solana_fixture import root as fixture_root
from custody.tests.test_phase6gb_issuance import (
    _RECEIPT_KEYS,
    signer_receipt_trust,  # noqa: F401
)
from custody.tests.test_solana_provisioning import (
    PublicClient,
    approve,
    enroll,
    reserve,
)
from custody.tests.test_solana_provisioning import (
    context as context_fixture,
)

pytestmark = pytest.mark.django_db(transaction=True)
context = context_fixture


def certificates(tmp_path, keys=None, *, ca=False, wrong_role=False, expired=False):
    keys = keys or _RECEIPT_KEYS
    pins = {}
    for party, key in keys.items():
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, party)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=3))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=-1 if expired else 1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.UniformResourceIdentifier(
                            "spiffe://wallet-mpc/" + ("wrong" if wrong_role else party)
                        )
                    ]
                ),
                critical=False,
            )
            .sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
        )
        path = tmp_path / (str(uuid4()) + ".crt")
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        pins[party] = str(path)
    return pins


class CohortClient(PublicClient):
    def __init__(self, metadata, keys):
        super().__init__(metadata)
        self.keys = keys

    def _approve(self, kind, statement):
        assert not connection.in_atomic_block
        from custody.models import MpcSolanaRoot

        root_statement = statement if kind == "root" else statement["root"]
        assert MpcSolanaReceiptPins.objects.filter(root__statement=root_statement).exists()
        assert MpcSolanaRoot.objects.filter(statement=root_statement).exists()
        reports = []
        for party, key in self.keys.items():
            value = {"statement": statement, "party_id": party, "durable": True}
            reports.append(
                value
                | {
                    "signer_signature": key.sign(
                        receipt_message("solana_" + kind, value), ec.ECDSA(hashes.SHA256())
                    ).hex()
                }
            )
        self.calls.append((kind, json.dumps(statement, sort_keys=True)))
        return {"statement": statement, "participant_agreement": reports}


def archive(c):
    return import_root_receipt_pins(
        keyset_id=c["keyset"].keyset_id, tenant_id=c["tenant"].pk, operator_ref="pins-operator"
    )


def test_new_cohort_commits_pins_before_rpc_and_ignores_later_configuration(
    context, settings, tmp_path
):
    c = context
    new_keys = {p: ec.generate_private_key(ec.SECP256R1()) for p in PARTICIPANTS}
    settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES = {
        str(c["keyset"].keyset_id): certificates(tmp_path, new_keys)
    }
    c["client"] = CohortClient(c["keyset"].dkg_public_evidence, new_keys)
    root = enroll(c)
    pins = MpcSolanaReceiptPins.objects.get(root=root)
    assert pins.source == "RESERVATION"
    original = copy.deepcopy(root.evidence)
    settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES = {}
    settings.MPC_HD_SIGNER_CERTIFICATES = {}
    assert enroll(c).evidence == original
    claim = approve(c, reserve(c))
    _verify("claim", claim.statement, claim.evidence)
    assert archive(c).pk == pins.pk  # existing immutable snapshot needs no installed paths
    assert root.evidence == original


def test_two_cohorts_and_old_claims_have_independent_archival_pins(context, settings, tmp_path):
    c = context
    settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES = {
        str(c["keyset"].keyset_id): certificates(tmp_path)
    }
    old_root = enroll(c)
    old_claim = approve(c, reserve(c))
    _, fresh_keyset = fixture_root(88)
    fresh_keys = {p: ec.generate_private_key(ec.SECP256R1()) for p in PARTICIPANTS}
    settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES = {
        str(fresh_keyset.keyset_id): certificates(tmp_path, fresh_keys)
    }
    fresh = c | {
        "keyset": fresh_keyset,
        "client": CohortClient(fresh_keyset.dkg_public_evidence, fresh_keys),
    }
    new_root = enroll(fresh)
    new_claim = approve(fresh, reserve(fresh))
    assert old_root.base_address != new_root.base_address
    settings.MPC_HD_SIGNER_CERTIFICATES = {}
    settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES = {}
    for kind, obj in [
        ("root", old_root),
        ("claim", old_claim),
        ("root", new_root),
        ("claim", new_claim),
    ]:
        _verify(kind, obj.statement, obj.evidence)
    with pytest.raises(MpcBindingError):
        _verify("root", old_root.statement, new_root.evidence)
    with pytest.raises(MpcBindingError):
        _verify("claim", old_claim.statement, new_claim.evidence)


def test_explicit_legacy_import_verifies_original_root_and_claims(context, settings, tmp_path):
    c = context
    root = enroll(c)
    claim = approve(c, reserve(c))
    assert not MpcSolanaReceiptPins.objects.exists()
    original = copy.deepcopy((root.evidence, claim.evidence))
    settings.MPC_HD_SIGNER_CERTIFICATES = certificates(tmp_path)
    row = archive(c)
    assert row.source == "ARCHIVAL_IMPORT"
    settings.MPC_HD_SIGNER_CERTIFICATES = {}
    _verify("root", root.statement, root.evidence)
    _verify("claim", claim.statement, claim.evidence)
    assert archive(c).pk == row.pk
    root.refresh_from_db()
    claim.refresh_from_db()
    assert (root.evidence, claim.evidence) == original
    assert AdminActionLog.objects.filter(action_type="SOLANA_ROOT_RECEIPT_PINS_IMPORT").count() == 1


def test_legacy_import_wrong_installed_cohort_rolls_back(context, settings, tmp_path):
    c = context
    enroll(c)
    keys = {p: ec.generate_private_key(ec.SECP256R1()) for p in PARTICIPANTS}
    settings.MPC_HD_SIGNER_CERTIFICATES = certificates(tmp_path, keys)
    with pytest.raises(MpcBindingError):
        archive(c)
    assert not MpcSolanaReceiptPins.objects.exists()


def test_legacy_import_invalid_claim_and_audit_failures_roll_back(context, settings, tmp_path):
    c = context
    enroll(c)
    claim = reserve(c)
    bad = copy.deepcopy(c["client"]._approve("claim", claim.statement))
    bad["participant_agreement"][0]["signer_signature"] = "aa" * 64
    claim.status, claim.evidence = "APPROVED", bad
    claim.save(
        update_fields=["status", "evidence"]
    )  # SQL only checks shape; app must reject crypto
    settings.MPC_HD_SIGNER_CERTIFICATES = certificates(tmp_path)
    with pytest.raises(MpcBindingError):
        archive(c)
    assert not MpcSolanaReceiptPins.objects.exists()


def test_archival_audit_failure_is_atomic(context, settings, tmp_path):
    c = context
    enroll(c)
    settings.MPC_HD_SIGNER_CERTIFICATES = certificates(tmp_path)
    with patch(
        "custody.solana_receipt_pins.AdminActionLog.objects.create",
        side_effect=RuntimeError("audit"),
    ):
        with pytest.raises(RuntimeError):
            archive(c)
    assert not MpcSolanaReceiptPins.objects.exists()


@pytest.mark.parametrize("action", ["import", "cohort-retry", "raw-reservation", "raw-import"])
def test_unknown_legacy_pending_root_cannot_adopt_new_pins(context, settings, tmp_path, action):
    c = context
    with patch.object(c["client"], "enroll_solana_root", side_effect=TimeoutError):
        with pytest.raises(TimeoutError):
            enroll(c)
    value = certificates(tmp_path)
    settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES = {str(c["keyset"].keyset_id): value}
    if action == "import":
        with pytest.raises(MpcBindingError):
            archive(c)
    elif action == "cohort-retry":
        with pytest.raises(MpcBindingError):
            enroll(c)
    else:
        with pytest.raises(DatabaseError), transaction.atomic():
            MpcSolanaReceiptPins.objects.create(
                root_id=c["keyset"].pk,
                source="RESERVATION" if action == "raw-reservation" else "ARCHIVAL_IMPORT",
                certificates_der_hex=installed_certificates(c["keyset"].keyset_id),
            )
    assert not MpcSolanaReceiptPins.objects.exists()


@pytest.mark.parametrize("operation", ["update", "delete", "raw-update", "raw-delete", "downgrade"])
def test_pins_are_immutable_and_populated_downgrade_refused(context, settings, tmp_path, operation):
    enroll(context)
    settings.MPC_HD_SIGNER_CERTIFICATES = certificates(tmp_path)
    row = archive(context)
    final = MigrationExecutor(connection).loader.graph.leaf_nodes()
    try:
        with pytest.raises(DatabaseError), transaction.atomic():
            if operation == "update":
                MpcSolanaReceiptPins.objects.filter(pk=row.pk).update(certificates_der_hex={})
            elif operation == "delete":
                row.delete()
            elif operation.startswith("raw-"):
                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE custody_mpcsolanareceiptpins SET source=source"
                        if operation == "raw-update"
                        else "DELETE FROM custody_mpcsolanareceiptpins"
                    )
            else:
                MigrationExecutor(connection).migrate(
                    [("custody", "0046_solana_current_claim_registration")]
                )
    finally:
        MigrationExecutor(connection).migrate(final)
    assert (
        MpcSolanaReceiptPins.objects.get(pk=row.pk).certificates_der_hex == row.certificates_der_hex
    )


@pytest.mark.parametrize(
    "damage", ["empty", "missing", "unknown", "trailing", "same-key", "wrong-role", "ca"]
)
def test_malformed_snapshot_never_falls_back(context, settings, tmp_path, damage):
    root = enroll(context)
    pins = certificates(tmp_path)
    settings.MPC_HD_SIGNER_CERTIFICATES = pins
    row = archive(context)
    value = copy.deepcopy(row.certificates_der_hex)
    if damage == "empty":
        value = {}
    elif damage == "missing":
        value.pop("signer-a")
    elif damage == "unknown":
        value["other"] = value["signer-a"]
    elif damage == "trailing":
        value["signer-a"] += "00"
    else:
        keys = (
            {p: _RECEIPT_KEYS["signer-a"] for p in PARTICIPANTS} if damage == "same-key" else None
        )
        settings.MPC_HD_SIGNER_CERTIFICATES = certificates(
            tmp_path, keys, wrong_role=damage == "wrong-role", ca=damage == "ca"
        )
        value = {
            p: x509.load_pem_x509_certificate(open(path, "rb").read())
            .public_bytes(serialization.Encoding.DER)
            .hex()
            for p, path in settings.MPC_HD_SIGNER_CERTIFICATES.items()
        }
    # Simulate corrupt loaded storage without disabling DB immutability triggers.
    row.certificates_der_hex = value
    settings.MPC_HD_SIGNER_CERTIFICATES = pins
    with patch("custody.solana_receipt_pins.MpcSolanaReceiptPins.objects.filter") as query:
        query.return_value.first.return_value = row
        with pytest.raises(MpcBindingError):
            _verify("root", root.statement, root.evidence)


@pytest.mark.parametrize("damage", ["ca", "wrong-role", "same-key", "missing", "bad-map"])
def test_invalid_installed_trust_cannot_create_a_root_reservation(
    context, settings, tmp_path, damage
):
    keys = {p: _RECEIPT_KEYS["signer-a"] for p in PARTICIPANTS} if damage == "same-key" else None
    pins = certificates(tmp_path, keys, ca=damage == "ca", wrong_role=damage == "wrong-role")
    if damage == "missing":
        pins.pop("signer-c")
    settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES = (
        {str(context["keyset"].keyset_id): pins} if damage != "bad-map" else {"not-a-uuid": pins}
    )
    with pytest.raises(MpcBindingError):
        enroll(context)
    from custody.models import MpcSolanaRoot

    assert not MpcSolanaRoot.objects.exists()
    assert not context["client"].calls


def test_archival_transport_expiry_does_not_expire_receipts(context, settings, tmp_path):
    root = enroll(context)
    settings.MPC_HD_SIGNER_CERTIFICATES = certificates(tmp_path, expired=True)
    archive(context)
    settings.MPC_HD_SIGNER_CERTIFICATES = {}
    _verify("root", root.statement, root.evidence)


def test_operator_archive_command_preserves_original_root(context, settings, tmp_path):
    root = enroll(context)
    settings.MPC_HD_SIGNER_CERTIFICATES = certificates(tmp_path)
    output = StringIO()
    call_command(
        "solana_provisioning",
        "archive-pins",
        tenant_id=str(context["tenant"].pk),
        keyset_id=str(context["keyset"].keyset_id),
        operator_ref="pins-operator",
        stdout=output,
    )
    result = json.loads(output.getvalue())
    assert result == {"id": str(root.pk), "source": "ARCHIVAL_IMPORT", "issued": False}


@pytest.mark.parametrize("operation", ["noop-then-reserve", "enable-flag"])
def test_old_pending_root_noop_update_cannot_become_new_reservation(
    context, settings, tmp_path, operation
):
    with patch.object(context["client"], "enroll_solana_root", side_effect=TimeoutError):
        with pytest.raises(TimeoutError):
            enroll(context)
    settings.MPC_HD_SIGNER_CERTIFICATES = certificates(tmp_path)
    value = installed_certificates(context["keyset"].keyset_id)
    with pytest.raises(DatabaseError), transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE custody_mpcsolanaroot SET next_index=next_index"
                if operation == "noop-then-reserve"
                else "UPDATE custody_mpcsolanaroot SET receipt_pins_reserved=true"
            )
        MpcSolanaReceiptPins.objects.create(
            root_id=context["keyset"].pk, source="RESERVATION", certificates_der_hex=value
        )
    assert not MpcSolanaReceiptPins.objects.exists()


def test_new_reserved_root_cannot_commit_without_pins(context, settings, tmp_path):
    from custody.models import MpcSolanaRoot

    settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES = {
        str(context["keyset"].keyset_id): certificates(tmp_path)
    }
    with patch("custody.solana_provisioning.capture_new_root"):
        with pytest.raises(DatabaseError):
            enroll(context)
    assert not MpcSolanaRoot.objects.exists()
    assert not context["client"].calls


def test_reserved_root_missing_snapshot_fails_closed(context, settings, tmp_path):
    settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES = {
        str(context["keyset"].keyset_id): certificates(tmp_path)
    }
    root = enroll(context)
    with patch("custody.solana_receipt_pins.MpcSolanaReceiptPins.objects.filter") as query:
        query.return_value.first.return_value = None
        with pytest.raises(MpcBindingError):
            _verify("root", root.statement, root.evidence)


def test_concurrent_explicit_import_keeps_one_snapshot_and_one_audit(context, settings, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from django.db import close_old_connections

    enroll(context)
    settings.MPC_HD_SIGNER_CERTIFICATES = certificates(tmp_path)
    barrier = Barrier(2)

    def worker():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            row = archive(context)
            return row.pk, row.certificates_der_hex
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker) for _ in range(2)]
        results = [f.result(timeout=20) for f in futures]
    assert results[0] == results[1]
    assert MpcSolanaReceiptPins.objects.count() == 1
    assert AdminActionLog.objects.filter(action_type="SOLANA_ROOT_RECEIPT_PINS_IMPORT").count() == 1


def test_wrong_tenant_cannot_archive_pins(context, settings, tmp_path):
    enroll(context)
    settings.MPC_HD_SIGNER_CERTIFICATES = certificates(tmp_path)
    with pytest.raises(MpcBindingError):
        import_root_receipt_pins(
            keyset_id=context["keyset"].keyset_id, tenant_id=uuid4(), operator_ref="other"
        )
    assert not MpcSolanaReceiptPins.objects.exists()


def test_new_root_and_pins_can_be_captured_in_a_nested_savepoint(context, settings, tmp_path):
    from custody.models import MpcSolanaRoot
    from custody.solana_receipt_pins import capture_new_root

    settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES = {
        str(context["keyset"].keyset_id): certificates(tmp_path)
    }

    # Preserve the service's no-RPC-in-transaction rule: build an ordinary
    # reservation payload from a deliberately rolled-back successful enrollment.
    class Rollback(Exception):
        pass

    fields = None

    def preserve_reservation_and_rollback(original):
        nonlocal fields
        fields = {f.attname: getattr(original, f.attname) for f in original._meta.concrete_fields}
        raise Rollback()

    with patch(
        "custody.solana_provisioning.capture_new_root",
        side_effect=preserve_reservation_and_rollback,
    ):
        with pytest.raises(Rollback):
            enroll(context)
    with transaction.atomic():
        # Network binding was rolled back along with Root; restore only the
        # authentic original immutable identity used in that reservation.
        keyset = context["keyset"]
        keyset.refresh_from_db()
        keyset.network_bindings = {
            "SOL": {
                "scope": keyset.scope,
                "algorithm": keyset.algorithm,
                "public_key": keyset.public_key,
                "dkg_execution_id": str(keyset.dkg_execution_id),
                "dkg_fingerprint": keyset.dkg_result_fingerprint,
                "network": fields["network_identity"],
            }
        }
        keyset.save(update_fields=["network_bindings"])
        with transaction.atomic():
            root = MpcSolanaRoot.objects.create(**fields)
            capture_new_root(root)
    assert MpcSolanaReceiptPins.objects.filter(root=root, source="RESERVATION").exists()


@pytest.mark.parametrize("first", ["import", "approval"])
def test_archival_import_and_claim_approval_recheck_both_lock_orders(
    context, settings, tmp_path, first
):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from django.db import close_old_connections

    from custody.models import MpcSolanaClaim
    from custody.solana_receipt_pins import _verify_original as original_archive_verify

    c = context
    enroll(c)
    claim = reserve(c)
    pins_a = certificates(tmp_path)
    keys_b = {p: ec.generate_private_key(ec.SECP256R1()) for p in PARTICIPANTS}
    pins_b = certificates(tmp_path, keys_b)
    reached, release, import_checked = Event(), Event(), Event()

    def returned_by_wrong_cohort(*_):
        # Root check happened under A. A separately changed global map could
        # verify a wrong-cohort response before the final approval lock.
        settings.MPC_HD_SIGNER_CERTIFICATES = pins_b
        reports = []
        for party, key in keys_b.items():
            value = {"statement": claim.statement, "party_id": party, "durable": True}
            reports.append(
                value
                | {
                    "signer_signature": key.sign(
                        receipt_message("solana_claim", value), ec.ECDSA(hashes.SHA256())
                    ).hex()
                }
            )
        return {"statement": claim.statement, "participant_agreement": reports}

    def verify_with_barrier(kind, statement, proof):
        _verify(kind, statement, proof)
        if kind == "claim" and connection.in_atomic_block == (first == "approval"):
            reached.set()
            assert release.wait(timeout=20)

    def verify_archive(kind, *args):
        original_archive_verify(kind, *args)
        if kind == "root":
            import_checked.set()

    def approve_worker():
        close_old_connections()
        try:
            try:
                approve(c, claim)
                return "approved"
            except MpcBindingError:
                return "rejected"
        finally:
            close_old_connections()

    def import_worker():
        close_old_connections()
        try:
            try:
                archive(c)
                return "imported"
            except MpcBindingError:
                return "rejected"
        finally:
            close_old_connections()

    with (
        patch.object(c["client"], "approve_solana_claim", side_effect=returned_by_wrong_cohort),
        patch("custody.solana_provisioning._verify", side_effect=verify_with_barrier),
        patch("custody.solana_receipt_pins._verify_original", side_effect=verify_archive),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        approved = pool.submit(approve_worker)
        assert reached.wait(timeout=15)
        settings.MPC_HD_SIGNER_CERTIFICATES = pins_a
        try:
            if first == "import":
                assert pool.submit(import_worker).result(timeout=15) == "imported"
                settings.MPC_HD_SIGNER_CERTIFICATES = pins_b
            else:
                imported = pool.submit(import_worker)
                assert import_checked.wait(timeout=15)
                assert not imported.done()  # waiting on approval's Claim lock
        finally:
            release.set()
        result = approved.result(timeout=15)
        if first == "approval":
            assert result == "approved"
            assert imported.result(timeout=15) == "rejected"
            assert not MpcSolanaReceiptPins.objects.exists()
        else:
            assert result == "rejected"
            assert MpcSolanaReceiptPins.objects.count() == 1
            assert MpcSolanaClaim.objects.get(pk=claim.pk).status == "PENDING"


@pytest.mark.parametrize("damage", ["missing", "malformed"])
def test_pending_reserved_root_corrupt_pins_deny_rpc_after_config_removed(
    context, settings, tmp_path, damage
):
    settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES = {
        str(context["keyset"].keyset_id): certificates(tmp_path)
    }
    with patch.object(context["client"], "enroll_solana_root", side_effect=TimeoutError):
        with pytest.raises(TimeoutError):
            enroll(context)
    settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES = {}
    row = MpcSolanaReceiptPins.objects.get(root_id=context["keyset"].pk)
    row.certificates_der_hex = {}
    with (
        patch("custody.solana_receipt_pins.MpcSolanaReceiptPins.objects.filter") as query,
        patch.object(context["client"], "enroll_solana_root") as remote,
    ):
        query.return_value.first.return_value = None if damage == "missing" else row
        with pytest.raises(MpcBindingError):
            enroll(context)
        remote.assert_not_called()
