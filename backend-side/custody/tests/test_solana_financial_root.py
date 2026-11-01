"""PG structure and genuine P256 proofs over synthetic Root-mode fixtures.

These cases do not constitute genuine MPC, wallet activation or ledger acceptance.
"""

import copy
import hashlib
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.db import DatabaseError, close_old_connections, connection, transaction
from django.db.migrations.executor import MigrationExecutor

from custody.models import AdminActionLog, LedgerTransaction, MpcSolanaFinancialRoot
from custody.mpc_binding import MpcBindingError
from custody.solana_financial_root import (
    complete_financial_mode,
    financial_mode_request,
    verify_financial_mode,
)
from custody.solana_issuance import _canonical
from custody.tests.test_solana_provisioning import context as registry_context_fixture
from custody.tests.test_solana_provisioning import enroll, reserve
from custody.tests.test_solana_provisioning import signer_receipt_trust as receipt_trust_fixture

pytestmark = pytest.mark.django_db(transaction=True)
context = registry_context_fixture
signer_receipt_trust = receipt_trust_fixture


@pytest.fixture
def clean_mode(context, signer_receipt_trust, settings, tmp_path):
    c = context
    c["root"] = enroll(c)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated mode fixture")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier("spiffe://wallet-mpc/witness")]
            ),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "witness-public.crt"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    settings.MPC_SOLANA_WITNESS_ANCHOR_ID = str(uuid4())
    settings.MPC_SOLANA_WITNESS_CERTIFICATE = str(path)
    c["witness_key"] = key
    with patch("custody.solana_financial_root._runtime"):
        yield c


def begin(c):
    return financial_mode_request(
        keyset_id=c["keyset"].keyset_id, tenant_id=c["tenant"].pk, operator_ref="operator"
    )


def signed(c, request, value=None):
    row = MpcSolanaFinancialRoot.objects.get(root=c["root"])
    package = c["root"].statement["public_key_package"]
    if value is None:
        value = {
            "query": request["query"],
            "sequence": 4,
            "root": {
                "original": c["root"].statement,
                "revision": 4,
                "phase": "Active",
                "next_claim_index": 0,
                "financial_mode": request["expected_mode"],
                "public_key_package": package,
                "generation": {
                    "epoch": 0,
                    "ceremony_id": str(c["keyset"].dkg_execution_id),
                    "public_key_package_sha256": hashlib.sha256(bytes(package)).hexdigest(),
                },
                "node_keys": {f"signer-{p}": b * 64 for p, b in zip("abc", "123")},
                "prepared": None,
            },
            "claim": None,
            "execution": None,
            "abandoned": False,
        }
    message = b"Wallet-MPC/WITNESS_QUERY_REPLY_V1\0" + _canonical(
        {"key_id": row.witness_key_id, "value": value}
    )
    return {
        "key_id": row.witness_key_id,
        "value": value,
        "signature": c["witness_key"].sign(message, ec.ECDSA(hashes.SHA256())).hex(),
    }


def complete(c, proof):
    return complete_financial_mode(
        keyset_id=c["keyset"].keyset_id,
        tenant_id=c["tenant"].pk,
        operator_ref="operator",
        evidence=proof,
        transport=c["rpc"],
    )


def test_durable_mode_ids_query_and_verified_history_survive_claim_allocation(clean_mode):
    c = clean_mode
    before = LedgerTransaction.objects.count()
    request = begin(c)
    assert begin(c) == request
    assert request["expected_mode"]["activation_id"] != request["expected_mode"]["command_id"]
    with pytest.raises(MpcBindingError, match="before any Claim"):
        reserve(c)
    row = complete(c, signed(c, request))
    assert row.status == "VERIFIED"
    assert complete(c, None).evidence == row.evidence
    original = copy.deepcopy(row.evidence)
    claim = reserve(c)
    assert claim.index == 0
    assert verify_financial_mode(row) == row.activation_id
    assert begin(c)["status"] == "VERIFIED"
    assert row.evidence == original
    assert LedgerTransaction.objects.count() == before


@pytest.mark.parametrize(
    "field",
    ("challenge", "root", "phase", "mode", "activation", "command", "claim", "package", "key"),
)
def test_signed_but_wrong_mode_context_cannot_finish(clean_mode, field):
    c = clean_mode
    request = begin(c)
    value = copy.deepcopy(signed(c, request)["value"])
    if field == "challenge":
        value["query"]["challenge"] = "fe" * 32
    elif field == "root":
        value["root"]["original"]["ownership_scope"] = str(uuid4())
    elif field == "phase":
        value["root"]["phase"] = "Frozen"
    elif field == "mode":
        value["root"].pop("financial_mode")
    elif field in ("activation", "command"):
        value["root"]["financial_mode"][field + "_id"] = str(uuid4())
    elif field == "claim":
        value["root"]["next_claim_index"] = 1
    elif field == "package":
        value["root"]["generation"]["public_key_package_sha256"] = "00" * 32
    proof = signed(c, request, value)
    if field == "key":
        proof["key_id"] = "00" * 32
    with pytest.raises(MpcBindingError):
        complete(c, proof)
    row = MpcSolanaFinancialRoot.objects.get(root=c["root"])
    assert row.status == "PENDING" and not row.evidence


def test_populated_root_cannot_enter_mode_import(clean_mode):
    c = clean_mode
    reserve(c)
    with pytest.raises(MpcBindingError, match="populated"):
        begin(c)
    assert not MpcSolanaFinancialRoot.objects.exists()


def test_expired_query_renewal_keeps_mode_ids_and_rejects_delayed_proof(clean_mode):
    c = clean_mode
    original = begin(c)
    delayed = signed(c, original)
    deadline = MpcSolanaFinancialRoot.objects.get(root=c["root"]).query_expires_at
    time.sleep(max(0, (deadline - datetime.now(timezone.utc)).total_seconds()) + 0.05)
    with pytest.raises(MpcBindingError, match="expired"):
        complete(c, delayed)
    renewed = begin(c)
    assert renewed["expected_mode"] == original["expected_mode"]
    assert renewed["query"]["challenge"] != original["query"]["challenge"]
    with pytest.raises(MpcBindingError):
        complete(c, delayed)
    assert complete(c, signed(c, renewed)).status == "VERIFIED"


def test_audit_failure_rolls_back_both_reservation_and_verification(clean_mode):
    c = clean_mode
    with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit")):
        with pytest.raises(RuntimeError, match="audit"):
            begin(c)
    assert not MpcSolanaFinancialRoot.objects.exists()
    request = begin(c)
    proof = signed(c, request)
    with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit")):
        with pytest.raises(RuntimeError, match="audit"):
            complete(c, proof)
    assert MpcSolanaFinancialRoot.objects.get(root=c["root"]).status == "PENDING"
    assert complete(c, proof).status == "VERIFIED"


@pytest.mark.parametrize("verified", [False, True])
def test_sql_guards_preserve_ids_history_and_pending_claim_fence(clean_mode, verified):
    c = clean_mode
    request = begin(c)
    if verified:
        complete(c, signed(c, request))
    row = MpcSolanaFinancialRoot.objects.get(root=c["root"])
    for update in (
        {"activation_id": uuid4()},
        {"command_id": uuid4()},
        {"witness_key_id": "00" * 32},
    ):
        with pytest.raises(DatabaseError), transaction.atomic():
            MpcSolanaFinancialRoot.objects.filter(pk=row.pk).update(**update)
    with pytest.raises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
        cursor.execute("DELETE FROM custody_mpcsolanafinancialroot WHERE root_id=%s", [row.pk])
    if not verified:
        from custody.models import Asset, MpcSolanaClaim

        # Even bypassing the service's check cannot allocate through the SQL fence.
        from custody.solana_provisioning import _asset_statement
        from custody.solana_seeded import account_address

        asset = Asset.objects.get(asset_key="SOL")
        statement_asset, namespace = _asset_statement(asset)
        reservation_id = uuid4()
        statement = {
            "root": c["root"].statement,
            "reservation_id": str(reservation_id),
            "owner_ref": c["principal"].ledger_owner_id,
            "idempotency_key": "raw",
            "index": 0,
            "asset": statement_asset,
        }
        with (
            pytest.raises(DatabaseError, match="financial Root mode import must finish"),
            transaction.atomic(),
        ):
            MpcSolanaClaim.objects.create(
                reservation_id=reservation_id,
                root=c["root"],
                principal=c["principal"],
                asset=asset,
                asset_namespace=namespace,
                idempotency_key="raw",
                index=0,
                statement=statement,
                address=account_address(c["root"].base_address, 0),
            )


def test_concurrent_request_reuses_one_committed_mode_query(clean_mode):
    c = clean_mode

    def worker(_):
        close_old_connections()
        try:
            return begin(c)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(worker, range(2)))
    assert result[0] == result[1]
    assert MpcSolanaFinancialRoot.objects.count() == 1
    assert AdminActionLog.objects.filter(action_type="SOLANA_FINANCIAL_ROOT_RESERVE").count() == 1


def wait_for_database_lock(application):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_stat_clear_snapshot()")
            cursor.execute(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity "
                "WHERE application_name=%s AND wait_event_type='Lock')",
                [application],
            )
            if cursor.fetchone()[0]:
                return
        time.sleep(0.02)
    raise AssertionError("competing writer never waited on the real PostgreSQL lock")


@pytest.mark.parametrize("first", ["mode", "claim"])
def test_claim_and_mode_birth_races_serialize_on_original_keyset(clean_mode, first):
    from custody import solana_financial_root
    from custody.models import MpcSolanaClaim

    c = clean_mode
    entered, release = threading.Event(), threading.Event()
    original = (
        solana_financial_root._locked_root if first == "mode" else MpcSolanaClaim.objects.create
    )

    def gate(*args, **kwargs):
        if first == "mode":
            result = original(*args, **kwargs)
            entered.set()
            assert release.wait(10)
            return result
        entered.set()
        assert release.wait(10)
        return original(*args, **kwargs)

    application = "mode-race-" + str(uuid4())

    def worker(kind, waiting=False):
        close_old_connections()
        try:
            if waiting:
                with connection.cursor() as cursor:
                    cursor.execute("SET application_name=%s", [application])
            try:
                return begin(c) if kind == "mode" else reserve(c)
            except MpcBindingError as exc:
                return str(exc)
        finally:
            close_old_connections()

    target = (
        patch("custody.solana_financial_root._locked_root", side_effect=gate)
        if first == "mode"
        else patch.object(MpcSolanaClaim.objects, "create", side_effect=gate)
    )
    with target, ThreadPoolExecutor(max_workers=2) as pool:
        winner = pool.submit(worker, first)
        try:
            assert entered.wait(5)
            loser = pool.submit(worker, "claim" if first == "mode" else "mode", True)
            wait_for_database_lock(application)
        finally:
            release.set()
        winner.result(timeout=10)
        denied = loser.result(timeout=10)
    assert ("before any Claim" if first == "mode" else "populated") in denied
    assert MpcSolanaFinancialRoot.objects.exists() == (first == "mode")
    assert MpcSolanaClaim.objects.exists() == (first == "claim")


def test_completion_rechecks_query_expiry_after_database_lock_wait(clean_mode):
    from custody.models import MpcKeyset

    c = clean_mode
    request = begin(c)
    proof = signed(c, request)
    expires = MpcSolanaFinancialRoot.objects.get(root=c["root"]).query_expires_at
    application = "mode-expiry-" + str(uuid4())

    def worker():
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET application_name=%s", [application])
            with pytest.raises(MpcBindingError, match="expired"):
                complete(c, proof)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with transaction.atomic():
            MpcKeyset.objects.select_for_update().get(pk=c["keyset"].pk)
            pending = pool.submit(worker)
            wait_for_database_lock(application)
            time.sleep(max(0, (expires - datetime.now(timezone.utc)).total_seconds()) + 0.05)
        pending.result(timeout=10)
    assert MpcSolanaFinancialRoot.objects.get(root=c["root"]).status == "PENDING"


@pytest.mark.parametrize("verified", [False, True])
def test_populated_import_refuses_downgrade_and_preserves_leaf_schema(clean_mode, verified):
    c = clean_mode
    request = begin(c)
    if verified:
        complete(c, signed(c, request))
    executor = MigrationExecutor(connection)
    leaf = executor.loader.graph.leaf_nodes()
    try:
        with pytest.raises(DatabaseError, match="populated financial Root mode"):
            executor.migrate([("custody", "0035_solana_native_wallet_issuance")])
        assert MpcSolanaFinancialRoot.objects.get(root=c["root"]).status == (
            "VERIFIED" if verified else "PENDING"
        )
    finally:
        MigrationExecutor(connection).migrate(leaf)
