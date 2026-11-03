"""Actual PG admission guards and TLS identity checks; no MPC claims from fixtures."""

import copy
import json
from io import StringIO
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.core.management import call_command
from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor

from custody.models import AdminActionLog, MpcKeyset, MpcSolanaCoordinatorBinding
from custody.mpc_binding import MpcBindingError
from custody.solana_coordinator import bind_coordinator, resolve_route, solana_adapter
from custody.tests.test_solana_financial_root import clean_mode as clean_mode_fixture
from custody.tests.test_solana_financial_sessions import financial as financial_fixture
from custody.tests.test_solana_financial_sessions import operation, session
from custody.tests.test_solana_provisioning import context as context_fixture
from custody.tests.test_solana_provisioning import enroll
from custody.tests.test_solana_provisioning import signer_receipt_trust as trust_fixture
from custody.tests.test_solana_receipt_pins import archive, certificates
from custody.tests.test_solana_witness_client import identity

pytestmark = pytest.mark.django_db(transaction=True)
context = context_fixture
signer_receipt_trust = trust_fixture
clean_mode = clean_mode_fixture
financial = financial_fixture


def installed(tmp_path, *, port=9443):
    issuer = identity(tmp_path / "ca", "ca")
    identity(tmp_path / "coordinator", "coordinator", issuer)
    identity(tmp_path / "custody", "custody", issuer)
    return dict(
        url=f"https://localhost:{port}",
        coordinator_certificate=str(tmp_path / "coordinator/tls.crt"),
        ca_certificate=str(tmp_path / "ca/tls.crt"),
        client_certificate=str(tmp_path / "custody/tls.crt"),
        client_key=str(tmp_path / "custody/tls.key"),
    )


def creating():
    return MpcKeyset.objects.create(
        keyset_id=uuid4(),
        algorithm="FROST_ED25519",
        curve="ed25519",
        scope="SOLANA",
        derivation_version="frost_keyset_v1",
    )


def configured(settings, tmp_path, keyset):
    value = installed(tmp_path)
    settings.MPC_SOLANA_COORDINATOR_ROUTES = {str(keyset.keyset_id): value}
    return value


def bind(keyset, c=None):
    return bind_coordinator(
        keyset_id=keyset.keyset_id,
        operator_ref="route-operator",
        tenant_id=None if c is None else c["tenant"].pk,
    )


def old_archive(c, settings, tmp_path):
    if "root" not in c:
        c["root"] = enroll(c)
    settings.MPC_HD_SIGNER_CERTIFICATES = certificates(tmp_path)
    return archive(c)


def test_new_binding_is_durable_before_network_and_idempotent(context, settings, tmp_path):
    keyset = creating()
    value = configured(settings, tmp_path, keyset)
    with patch("custody.mpc_transport.http.client.HTTPSConnection") as network:
        row = bind(keyset)
        assert bind(keyset).pk == row.pk
        network.assert_not_called()
    keyset.refresh_from_db()
    assert keyset.solana_coordinator_required
    assert resolve_route(keyset.keyset_id).url == value["url"]
    assert AdminActionLog.objects.filter(action_type="SOLANA_COORDINATOR_BIND").count() == 1


def test_map_entry_requires_explicit_binding_before_rpc(context, settings, tmp_path):
    keyset = creating()
    configured(settings, tmp_path, keyset)
    with patch("custody.mpc_transport.http.client.HTTPSConnection") as network:
        with pytest.raises(MpcBindingError):
            solana_adapter(keyset.keyset_id)
        network.assert_not_called()
    assert not MpcSolanaCoordinatorBinding.objects.exists()


@pytest.mark.parametrize("damage", ["remove-map", "change-url", "change-key", "missing-row"])
def test_bound_keyset_never_returns_to_global_transport(context, settings, tmp_path, damage):
    keyset = creating()
    config = configured(settings, tmp_path, keyset)
    bind(keyset)
    if damage == "remove-map":
        settings.MPC_SOLANA_COORDINATOR_ROUTES = {}
    elif damage == "change-url":
        settings.MPC_SOLANA_COORDINATOR_ROUTES[str(keyset.keyset_id)]["url"] = (
            "https://localhost:9444"
        )
    elif damage == "change-key":
        replacement = installed(tmp_path / "other")
        settings.MPC_SOLANA_COORDINATOR_ROUTES[str(keyset.keyset_id)]["coordinator_certificate"] = (
            replacement["coordinator_certificate"]
        )
    else:
        settings.MPC_SOLANA_COORDINATOR_ROUTES = {}
    with patch("custody.mpc_transport.http.client.HTTPSConnection") as network:
        if damage == "missing-row":
            with patch(
                "custody.solana_coordinator.MpcSolanaCoordinatorBinding.objects.filter"
            ) as query:
                query.return_value.first.return_value = None
                with pytest.raises(MpcBindingError):
                    resolve_route(keyset.keyset_id)
        else:
            with pytest.raises(MpcBindingError):
                resolve_route(keyset.keyset_id)
        network.assert_not_called()
    assert config["url"].startswith("https://")


@pytest.mark.parametrize(
    "change", ["flag", "url", "key", "delete", "keyset-id", "scope", "downgrade"]
)
def test_bound_admission_and_identity_are_permanent(context, settings, tmp_path, change):
    keyset = creating()
    configured(settings, tmp_path, keyset)
    row = bind(keyset)
    final = MigrationExecutor(connection).loader.graph.leaf_nodes()
    try:
        with pytest.raises(DatabaseError), transaction.atomic():
            if change == "flag":
                MpcKeyset.objects.filter(pk=keyset.pk).update(solana_coordinator_required=False)
            elif change == "keyset-id":
                MpcKeyset.objects.filter(pk=keyset.pk).update(keyset_id=uuid4())
            elif change == "scope":
                MpcKeyset.objects.filter(pk=keyset.pk).update(scope="TON")
            elif change == "url":
                MpcSolanaCoordinatorBinding.objects.filter(pk=row.pk).update(url="https://other")
            elif change == "key":
                MpcSolanaCoordinatorBinding.objects.filter(pk=row.pk).update(
                    coordinator_key_id="11" * 32
                )
            elif change == "delete":
                row.delete()
            else:
                MigrationExecutor(connection).migrate(
                    [("custody", "0047_solana_root_receipt_pins")]
                )
    finally:
        MigrationExecutor(connection).migrate(final)
    assert resolve_route(keyset.keyset_id).coordinator_key_id == row.coordinator_key_id


@pytest.mark.parametrize("half", ["flag-only", "row-only"])
def test_binding_and_forward_admission_commit_together(context, settings, tmp_path, half):
    keyset = creating()
    configured(settings, tmp_path, keyset)
    with pytest.raises(DatabaseError), transaction.atomic():
        if half == "flag-only":
            MpcKeyset.objects.filter(pk=keyset.pk).update(solana_coordinator_required=True)
        else:
            MpcSolanaCoordinatorBinding.objects.create(
                keyset=keyset, url="https://localhost:9443", coordinator_key_id="11" * 32
            )
    assert not MpcSolanaCoordinatorBinding.objects.exists()
    keyset.refresh_from_db()
    assert not keyset.solana_coordinator_required


def test_legacy_root_binding_requires_archived_receipts_and_original_tenant(
    context, settings, tmp_path
):
    c = context
    c["root"] = enroll(c)
    configured(settings, tmp_path / "transport", c["keyset"])
    with pytest.raises(MpcBindingError):
        bind(c["keyset"], c)
    old_archive(c, settings, tmp_path)
    with pytest.raises(MpcBindingError):
        bind(c["keyset"])
    original = copy.deepcopy(c["root"].evidence)
    row = bind(c["keyset"], c)
    assert bind(c["keyset"], c).pk == row.pk
    c["root"].refresh_from_db()
    assert c["root"].evidence == original


def test_pending_root_cannot_receive_a_new_route(context, settings, tmp_path):
    with patch.object(context["client"], "enroll_solana_root", side_effect=TimeoutError):
        with pytest.raises(TimeoutError):
            enroll(context)
    configured(settings, tmp_path, context["keyset"])
    with pytest.raises(MpcBindingError):
        bind(context["keyset"], context)
    assert not MpcSolanaCoordinatorBinding.objects.exists()


def test_imported_keyset_without_original_root_cannot_adopt_route(context, settings, tmp_path):
    configured(settings, tmp_path, context["keyset"])
    with pytest.raises(MpcBindingError):
        bind(context["keyset"])
    assert not MpcSolanaCoordinatorBinding.objects.exists()


@pytest.mark.parametrize("work", ["held", "allocated"])
def test_legacy_tracked_private_work_blocks_binding_without_releasing_hold(
    financial, settings, tmp_path, work
):
    c = financial
    old_archive(c, settings, tmp_path)
    configured(settings, tmp_path / "transport", c["keyset"])
    op = operation(c)
    row = session(c, op) if work == "allocated" else None
    with pytest.raises(MpcBindingError):
        bind(c["keyset"], c)
    assert not MpcSolanaCoordinatorBinding.objects.exists()
    op.refresh_from_db()
    assert op.status == "HELD"
    if row is not None:
        row.refresh_from_db()
        assert row.status == "ALLOCATED"


def test_binding_audit_failure_rolls_back_row_and_marker(context, settings, tmp_path):
    keyset = creating()
    configured(settings, tmp_path, keyset)
    with patch(
        "custody.solana_coordinator.AdminActionLog.objects.create", side_effect=RuntimeError
    ):
        with pytest.raises(RuntimeError):
            bind(keyset)
    keyset.refresh_from_db()
    assert not keyset.solana_coordinator_required
    assert not MpcSolanaCoordinatorBinding.objects.exists()


def test_scoped_adapter_rejects_other_keysets_and_generic_private_paths(
    context, settings, tmp_path
):
    keyset = creating()
    configured(settings, tmp_path, keyset)
    bind(keyset)
    adapter = solana_adapter(keyset.keyset_id)
    with patch("custody.mpc_transport.http.client.HTTPSConnection") as network:
        with pytest.raises(MpcBindingError):
            adapter.get_keyset(str(uuid4()))
        with pytest.raises(MpcBindingError):
            adapter.execute_signing_session(str(uuid4()))
        network.assert_not_called()


def test_binding_command_outputs_only_public_identity(context, settings, tmp_path):
    keyset = creating()
    configured(settings, tmp_path, keyset)
    output = StringIO()
    call_command(
        "solana_coordinator",
        "bind",
        keyset_id=str(keyset.keyset_id),
        operator_ref="route-operator",
        stdout=output,
    )
    result = json.loads(output.getvalue())
    assert result["keyset_id"] == str(keyset.keyset_id)
    assert len(result["coordinator_key_id"]) == 64
    assert result["private_work_performed"] is False


@pytest.mark.parametrize(
    "fault",
    [
        "correct",
        "wrong-key",
        "wrong-role",
        "wrong-ca",
        "expired",
        "deadline",
        "redirect",
        "oversize",
    ],
)
def test_bound_tls_authenticates_before_any_http_and_rejects_redirects(tmp_path, settings, fault):
    import hashlib
    import ssl
    import threading
    from datetime import datetime, timedelta, timezone
    from socketserver import BaseRequestHandler, ThreadingTCPServer

    import requests
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    from custody.mpc_transport import CoordinatorRoute, coordinator_request

    issuer = identity(tmp_path / "issuer", "ca")
    expected_key, expected = identity(tmp_path / "expected", "coordinator", issuer)
    identity(tmp_path / "client", "custody", issuer)
    other_issuer = identity(tmp_path / "other-ca", "ca") if fault == "wrong-ca" else issuer
    server_key, server_cert = identity(
        tmp_path / "server",
        "custody" if fault == "wrong-role" else "coordinator",
        other_issuer,
        key=None if fault == "wrong-key" else expected_key,
    )
    if fault == "expired":
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(server_cert.subject)
            .issuer_name(issuer[1].subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(now - timedelta(days=1))
        )
        for extension in server_cert.extensions:
            builder = builder.add_extension(extension.value, extension.critical)
        (tmp_path / "server/tls.crt").write_bytes(
            builder.sign(issuer[0], hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
        )
    seen = bytearray()

    class Handler(BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            try:
                while True:
                    data = self.request.recv(4096)
                    if not data:
                        return
                    seen.extend(data)
                    if b"\r\n\r\n" in seen:
                        header, body = seen.split(b"\r\n\r\n", 1)
                        length = next(
                            int(line.split(b":", 1)[1])
                            for line in header.split(b"\r\n")
                            if line.lower().startswith(b"content-length:")
                        )
                        if len(body) >= length:
                            break
                body = b"x" * (1024 * 1024 + 1) if fault == "oversize" else b'{"ok":true}'
                status = b"302 Redirect" if fault == "redirect" else b"200 OK"
                self.request.sendall(
                    b"HTTP/1.1 "
                    + status
                    + b"\r\nLocation: https://localhost:1\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\n\r\n"
                    + body
                )
            except (OSError, StopIteration):
                return

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = tls.maximum_version = ssl.TLSVersion.TLSv1_3
    tls.load_cert_chain(tmp_path / "server/tls.crt", tmp_path / "server/tls.key")
    tls.load_verify_locations(tmp_path / "issuer/tls.crt")
    tls.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    key_id = hashlib.sha256(
        expected.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()
    route = CoordinatorRoute(
        url=f"https://localhost:{server.server_address[1]}",
        ca_certificate=str(tmp_path / "issuer/tls.crt"),
        client_certificate=str(tmp_path / "client/tls.crt"),
        client_key=str(tmp_path / "client/tls.key"),
        coordinator_key_id=key_id,
    )
    settings.MPC_REQUEST_TIMEOUT_SECONDS = 3
    try:
        args = dict(route=route, json_payload={"canary": "public-routing-payload"})
        if fault == "correct":
            assert coordinator_request("POST", "/routing-canary", **args) == {"ok": True}
        else:
            if fault == "deadline":
                args["dispatch_deadline"] = datetime.now(timezone.utc) - timedelta(seconds=1)
            error = (
                requests.HTTPError
                if fault == "redirect"
                else ValueError
                if fault in {"oversize", "deadline"}
                else ssl.SSLCertVerificationError
            )
            with pytest.raises(error):
                coordinator_request("POST", "/routing-canary", **args)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    if fault in {"wrong-key", "wrong-role", "wrong-ca", "expired", "deadline"}:
        assert len(seen) == 0
    else:
        assert b"POST /routing-canary" in seen and b"public-routing-payload" in seen


def import_metadata(c, keyset):
    value = copy.deepcopy(c["keyset"].dkg_public_evidence)
    changes = dict(
        keyset_id=str(keyset.keyset_id), execution_id=str(uuid4()), session_id=str(uuid4())
    )
    value.update(changes)
    for report in value["participant_agreement"]:
        report["request"].update(changes)
    return value


@pytest.mark.parametrize("first", ["binding", "metadata"])
def test_binding_and_legacy_metadata_import_serialize_both_lock_orders(
    context, settings, tmp_path, first
):
    import time
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from django.core.management.base import CommandError
    from django.db import close_old_connections

    from custody.management.commands.mpc_keyset import Command

    keyset = creating()
    metadata = import_metadata(context, keyset)
    config = installed(tmp_path)
    reached, release, bind_started = Event(), Event(), Event()
    original = Command._handle_atomic
    binder_pid = []

    def legacy_boundary(command, *args, **options):
        if first == "binding":
            reached.set()
            assert release.wait(timeout=20)
        return original(command, *args, **options)

    def global_metadata(*_):
        assert connection.in_atomic_block
        if first == "metadata":
            reached.set()
            assert release.wait(timeout=20)
        return metadata

    def importing():
        close_old_connections()
        try:
            try:
                call_command("mpc_keyset", "import-dkg", keyset_id=str(keyset.keyset_id))
                return "imported"
            except CommandError:
                return "rejected"
        finally:
            close_old_connections()

    def binding():
        close_old_connections()
        try:
            connection.ensure_connection()
            binder_pid.append(connection.connection.info.backend_pid)
            bind_started.set()
            try:
                bind(keyset)
                return "bound"
            except MpcBindingError:
                return "rejected"
        finally:
            close_old_connections()

    with (
        patch.object(Command, "_handle_atomic", new=legacy_boundary),
        patch(
            "custody.signer_adapter.SelfHostedMpcAdapter.get_keyset", side_effect=global_metadata
        ) as global_rpc,
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        pending = pool.submit(importing)
        assert reached.wait(timeout=15)
        settings.MPC_SOLANA_COORDINATOR_ROUTES = {str(keyset.keyset_id): config}
        try:
            future = pool.submit(binding)
            if first == "binding":
                assert future.result(timeout=15) == "bound"
            else:
                assert bind_started.wait(timeout=10)
                deadline = time.monotonic() + 10
                while True:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT cardinality(pg_blocking_pids(%s))", [binder_pid[0]])
                        blocked = cursor.fetchone()[0]
                    if blocked:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(0.01)
                assert not future.done()
        finally:
            release.set()
        if first == "binding":
            assert pending.result(timeout=15) == "rejected"
            global_rpc.assert_not_called()
            keyset.refresh_from_db()
            assert keyset.public_key == "" and keyset.solana_coordinator_required
        else:
            assert pending.result(timeout=15) == "imported"
            assert future.result(timeout=15) == "rejected"
            assert not MpcSolanaCoordinatorBinding.objects.exists()
            keyset.refresh_from_db()
            assert keyset.dkg_public_evidence == metadata and not keyset.solana_coordinator_required


@pytest.mark.parametrize("first", ["binding", "allocation"])
def test_legacy_binding_and_financial_allocation_share_root_lock_order(
    financial, settings, tmp_path, first
):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from django.db import close_old_connections

    from custody.ledger import user_balances
    from custody.tests.test_solana_financial_root import wait_for_database_lock

    c = financial
    old_archive(c, settings, tmp_path)
    configured(settings, tmp_path / "transport", c["keyset"])
    before = user_balances(c["withdrawal"].user_id, "SOL")
    entered, release = Event(), Event()
    original_audit = AdminActionLog.objects.create
    expected_action = (
        "SOLANA_COORDINATOR_BIND" if first == "binding" else "SOL_FIN_WITHDRAWAL_RESERVE"
    )

    def audit(**kwargs):
        result = original_audit(**kwargs)
        if kwargs["action_type"] == expected_action:
            entered.set()
            assert release.wait(timeout=20)
        return result

    def worker(kind):
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT set_config('application_name',%s,false)", ["routing-op-race-" + kind]
                )
            return bind(c["keyset"], c) if kind == "binding" else operation(c)
        finally:
            close_old_connections()

    second = "allocation" if first == "binding" else "binding"
    with (
        patch.object(AdminActionLog.objects, "create", side_effect=audit),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        leading = pool.submit(worker, first)
        try:
            assert entered.wait(timeout=15)
            trailing = pool.submit(worker, second)
            wait_for_database_lock("routing-op-race-" + second)
            assert not trailing.done()
        finally:
            release.set()
        leading.result(timeout=15)
        if first == "allocation":
            with pytest.raises(MpcBindingError):
                trailing.result(timeout=15)
        else:
            assert trailing.result(timeout=15).status == "HELD"
    assert MpcSolanaCoordinatorBinding.objects.exists() == (first == "binding")
    assert user_balances(c["withdrawal"].user_id, "SOL") == before


def test_scoped_runtime_defers_only_transport_validation_and_keeps_generic_guards(
    context, settings
):
    from custody.signer_adapter import assert_mpc_backend_runtime_safe

    settings.CUSTODY_DEMO_MODE = False
    settings.CUSTODY_TX_MODE = "live"
    settings.CUSTODY_INDEXER_MODE = "live"
    with patch(
        "custody.mpc_transport.coordinator_tls_context",
        side_effect=AssertionError("global transport"),
    ) as tls:
        assert_mpc_backend_runtime_safe("SOL", validate_coordinator_transport=False)
        tls.assert_not_called()
        with pytest.raises(AssertionError):
            assert_mpc_backend_runtime_safe("SOL")
        with pytest.raises(RuntimeError):
            assert_mpc_backend_runtime_safe("ETH", validate_coordinator_transport=False)


@pytest.mark.parametrize("kind", ["root", "claim", "current"])
def test_wrong_statement_scope_rejected_before_authority_key_or_payload(
    context, settings, tmp_path, kind
):
    keyset = creating()
    configured(settings, tmp_path, keyset)
    bind(keyset)
    adapter = solana_adapter(keyset.keyset_id)
    root = {"dkg": {"keyset_id": str(uuid4())}}
    statement = root if kind == "root" else {"root": root}
    with (
        patch("custody.mpc_request_auth.authorize_solana_provisioning") as authority,
        patch("custody.solana_coordinator.coordinator_request") as network,
    ):
        with pytest.raises(MpcBindingError):
            if kind == "current":
                adapter.approve_current_solana_claim(
                    str(keyset.keyset_id), {"statement": statement}
                )
            elif kind == "claim":
                adapter.approve_solana_claim(str(keyset.keyset_id), statement)
            else:
                adapter.enroll_solana_root(str(keyset.keyset_id), statement)
        authority.assert_not_called()
        network.assert_not_called()
