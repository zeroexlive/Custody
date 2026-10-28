"""Real PostgreSQL guards; synthetic public receipts are not MPC acceptance."""

import copy
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from unittest.mock import patch
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.core.management import call_command
from django.db import DatabaseError, close_old_connections, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone
from ops.models import Chain, NodeEndpoint
from solders.pubkey import Pubkey

from custody.identity_registry import RegistryError, register_principal, register_tenant
from custody.models import (
    AdminActionLog,
    Asset,
    HotWallet,
    LedgerAccount,
    MpcKeyset,
    MpcSolanaClaim,
    MpcSolanaRoot,
    UserWallet,
)
from custody.mpc_binding import MpcBindingError
from custody.mpc_receipts import receipt_message
from custody.solana_provisioning import approve_claim, register_root, reserve_claim
from custody.tests.solana_fixture import SolRpc
from custody.tests.solana_fixture import root as fixture_root
from custody.tests.test_phase6gb_issuance import _RECEIPT_KEYS
from custody.tests.test_phase6gb_issuance import signer_receipt_trust as receipt_trust_fixture
from custody.token_metadata import metadata_fingerprint

pytestmark = pytest.mark.django_db(transaction=True)
signer_receipt_trust = receipt_trust_fixture


def evidence(kind, value):
    reports = []
    for party, key in _RECEIPT_KEYS.items():
        s = {"statement": copy.deepcopy(value), "party_id": party, "durable": True}
        reports.append(
            s
            | {
                "signer_signature": key.sign(
                    receipt_message(f"solana_{kind}", s), ec.ECDSA(hashes.SHA256())
                ).hex()
            }
        )
    return {"statement": copy.deepcopy(value), "participant_agreement": reports}


class PublicClient:
    def __init__(self, metadata):
        self.metadata, self.calls, self.results = metadata, [], {}

    def get_keyset(self, keyset_id):
        return copy.deepcopy(self.metadata)

    def _approve(self, kind, statement):
        # Assert the required commit happened before this fake remote side effect.
        assert not connection.in_atomic_block and connection.get_autocommit()
        if kind == "root":
            assert MpcSolanaRoot.objects.filter(statement=statement).exists()
        else:
            assert MpcSolanaClaim.objects.filter(statement=statement).exists()
        slot = kind, json.dumps(statement, sort_keys=True)
        self.calls.append(slot)
        return copy.deepcopy(self.results.setdefault(slot, evidence(kind, statement)))

    def enroll_solana_root(self, keyset_id, statement):
        return self._approve("root", statement)

    def approve_solana_claim(self, keyset_id, statement):
        return self._approve("claim", statement)


@pytest.fixture
def context(settings):
    _, keyset = fixture_root(87)
    Chain.objects.filter(chain_id="SOL").update(
        kind="solana",
        is_testnet=True,
        enabled=True,
        evm_chain_id=None,
    )
    NodeEndpoint.objects.filter(chain_id="SOL", kind="rpc").update(enabled=False)
    NodeEndpoint.objects.create(
        chain_id="SOL", kind="rpc", name="provision", url="http://127.0.0.1:8899", enabled=True
    )
    settings.MPC_SOLANA_INTEGRATION_ENABLED = True
    settings.MPC_INTEGRATION_ENVIRONMENT = "development"
    settings.MPC_SIGNER_BACKEND = "self_hosted_mpc"
    settings.MPC_SOLANA_NETWORK = {
        "network": "isolated-v1",
        "genesis_hash": str(Pubkey.from_bytes(bytes([91]) * 32)),
        "genesis_source": "validator-genesis-artifact",
        "genesis_artifact_sha256": "ab" * 32,
        "trusted_endpoints": ["http://127.0.0.1:8899"],
    }
    tenant = register_tenant(reference="tenant-A", operator_ref="operator")
    principal = register_principal(
        tenant_id=tenant.pk, customer_ref="customer", operator_ref="operator"
    )
    client = PublicClient(keyset.dkg_public_evidence)
    rpc = SolRpc("unused", "unused", settings.MPC_SOLANA_NETWORK["genesis_hash"])
    with patch("custody.solana_provisioning._runtime"):
        yield {
            "keyset": keyset,
            "tenant": tenant,
            "principal": principal,
            "client": client,
            "rpc": rpc,
        }


def enroll(c):
    return register_root(
        keyset_id=c["keyset"].keyset_id,
        tenant_id=c["tenant"].pk,
        operator_ref="operator",
        client=c["client"],
        transport=c["rpc"],
    )


def reserve(c, retry="retry", principal=None, asset="SOL"):
    return reserve_claim(
        keyset_id=c["keyset"].keyset_id,
        tenant_id=c["tenant"].pk,
        principal_id=(principal or c["principal"]).pk,
        asset_key=asset,
        idempotency_key=retry,
        operator_ref="operator",
    )


def approve(c, row):
    return approve_claim(
        reservation_id=row.pk,
        tenant_id=c["tenant"].pk,
        operator_ref="operator",
        client=c["client"],
        transport=c["rpc"],
    )


def token(name, mint=None):
    row = Asset.objects.create(
        asset_key=name,
        chain_id="SOL",
        symbol=name,
        decimals=6,
        is_native=False,
        token_standard="SPL",
        contract_address=mint or str(Pubkey.new_unique()),
    )
    row.metadata_verified_at = timezone.now()
    row.metadata_fingerprint = metadata_fingerprint(row)
    row.save()
    return row


def test_original_approvals_do_not_issue_wallets_or_financial_accounts(context):
    c = context
    root = enroll(c)
    first = reserve(c)
    assert root.status == "APPROVED" and first.status == "PENDING" and first.index == 0
    assert root.statement["ownership_scope"] == str(c["tenant"].pk)
    assert first.statement["owner_ref"] == c["principal"].ledger_owner_id
    signed = approve(c, first)
    calls = len(c["client"].calls)
    assert signed.status == "APPROVED" and approve(c, first).evidence == signed.evidence
    assert enroll(c).evidence == root.evidence and reserve(c).pk == first.pk
    assert len(c["client"].calls) == calls
    assert not UserWallet.objects.exists() and not LedgerAccount.objects.exists()
    root.refresh_from_db()
    assert root.next_index == 1


@pytest.mark.parametrize("kind", ["root", "claim"])
def test_lost_remote_response_keeps_original_pending_identity(context, kind):
    c = context
    if kind == "root":
        method = "enroll_solana_root"

        def run():
            return enroll(c)
    else:
        enroll(c)
        row = reserve(c)
        method = "approve_solana_claim"

        def run():
            return approve(c, row)

    original = getattr(c["client"], method)

    def lost(*args):
        original(*args)
        raise TimeoutError("response lost after commit")

    with patch.object(c["client"], method, side_effect=lost), pytest.raises(TimeoutError):
        run()
    model = MpcSolanaRoot if kind == "root" else MpcSolanaClaim
    pending = model.objects.get()
    statement = copy.deepcopy(pending.statement)
    assert pending.status == "PENDING" and not pending.evidence
    connection.close()
    result = run()
    assert result.statement == statement and result.status == "APPROVED"
    assert model.objects.count() == 1


@pytest.mark.parametrize("kind", ["root", "claim"])
@pytest.mark.parametrize("fault", ["forged", "partial", "duplicate", "domain", "statement"])
def test_unverifiable_remote_receipts_never_approve(context, kind, fault):
    c = context
    if kind == "root":
        method = "enroll_solana_root"

        def run():
            return enroll(c)
    else:
        enroll(c)
        row = reserve(c)
        method = "approve_solana_claim"

        def run():
            return approve(c, row)

    original = getattr(c["client"], method)

    def bad(*args):
        result = original(*args)
        reports = result["participant_agreement"]
        if fault == "forged":
            reports[0]["signer_signature"] = "00" * 70
        if fault == "partial":
            reports.pop()
        if fault == "duplicate":
            reports[1] = reports[0]
        if fault == "statement":
            result["statement"]["unknown"] = True
        if fault == "domain":
            result = evidence("claim" if kind == "root" else "root", result["statement"])
        return result

    with patch.object(c["client"], method, side_effect=bad), pytest.raises(MpcBindingError):
        run()
    model = MpcSolanaRoot if kind == "root" else MpcSolanaClaim
    assert model.objects.get().status == "PENDING"
    assert run().status == "APPROVED"


@pytest.mark.parametrize("kind", ["root", "claim"])
def test_mandatory_audit_failure_does_not_start_remote_side_effect(context, kind):
    c = context
    if kind == "claim":
        enroll(c)
    calls = len(c["client"].calls)
    with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit down")):
        with pytest.raises(RuntimeError):
            enroll(c) if kind == "root" else reserve(c)
    assert len(c["client"].calls) == calls
    assert not (MpcSolanaRoot if kind == "root" else MpcSolanaClaim).objects.exists()


def test_cross_tenant_and_conflicting_retries_keep_original_owner(context):
    c = context
    enroll(c)
    first = reserve(c)
    second = register_principal(
        tenant_id=c["tenant"].pk, customer_ref="other", operator_ref="operator"
    )
    with pytest.raises(MpcBindingError, match="retry conflicts"):
        reserve(c, principal=second)
    with pytest.raises(MpcBindingError, match="original reservation"):
        reserve(c, retry="different")
    other = register_tenant(reference="other-tenant", operator_ref="operator")
    with pytest.raises(RegistryError):
        reserve_claim(
            keyset_id=c["keyset"].keyset_id,
            tenant_id=other.pk,
            principal_id=c["principal"].pk,
            asset_key="SOL",
            idempotency_key="new",
            operator_ref="operator",
        )
    with pytest.raises(MpcBindingError, match="tenant/network"):
        register_root(
            keyset_id=c["keyset"].keyset_id,
            tenant_id=other.pk,
            operator_ref="operator",
            client=c["client"],
        )
    assert MpcSolanaClaim.objects.get().pk == first.pk


def test_two_mints_and_native_share_one_monotonic_counter(context):
    c = context
    enroll(c)
    assets = ["SOL", token("mint-A").asset_key, token("mint-B").asset_key]
    rows = [reserve(c, retry=f"asset:{a}", asset=a) for a in assets]
    assert [r.index for r in rows] == [0, 1, 2] and len({r.address for r in rows}) == 3
    with pytest.raises(MpcBindingError, match="earlier pending"):
        approve(c, rows[1])
    for row in rows:
        assert approve(c, row).status == "APPROVED"
    with pytest.raises(DatabaseError, match="asset identity"), transaction.atomic():
        Asset.objects.filter(asset_key="mint-A").update(decimals=7)


def test_parallel_duplicate_and_distinct_owner_reservations(context):
    c = context
    enroll(c)
    people = [
        register_principal(
            tenant_id=c["tenant"].pk, customer_ref=f"owner:{i}", operator_ref="operator"
        )
        for i in range(8)
    ]

    def worker(i):
        close_old_connections()
        try:
            with patch("custody.solana_provisioning._runtime"):
                row = reserve(c, retry=f"retry:{i % 8}", principal=people[i % 8])
                return row.pk, row.index
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(32)))
    assert len(set(results)) == 8 and sorted({r[1] for r in results}) == list(range(8))
    assert AdminActionLog.objects.filter(action_type="SOLANA_CLAIM_RESERVE").count() == 8


@pytest.mark.parametrize(
    "table,field,value",
    [
        ("root", "statement", {}),
        ("root", "next_index", 2),
        ("root", "network_identity", {}),
        ("claim", "index", 4),
        ("claim", "address", "1" * 32),
        ("claim", "idempotency_key", "replacement"),
        ("keyset", "dkg_public_evidence", {}),
        ("keyset", "network_bindings", {}),
    ],
)
def test_raw_sql_cannot_replace_original_identity(context, table, field, value):
    c = context
    root = enroll(c)
    claim = reserve(c)
    model = {"root": MpcSolanaRoot, "claim": MpcSolanaClaim, "keyset": MpcKeyset}[table]
    pk = {"root": root.pk, "claim": claim.pk, "keyset": c["keyset"].pk}[table]
    dbfield = model._meta.get_field(field)
    encoded = json.dumps(value) if isinstance(value, dict) else value
    with pytest.raises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(
            f'UPDATE "{model._meta.db_table}" SET "{dbfield.column}"=%s '
            f'WHERE "{model._meta.pk.column}"=%s',
            [encoded, pk],
        )


@pytest.mark.parametrize("kind", ["root", "claim"])
def test_deletion_and_approved_evidence_mutation_are_rejected(context, kind):
    c = context
    row = enroll(c)
    if kind == "claim":
        row = approve(c, reserve(c))
    model = type(row)
    with pytest.raises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(
            f'DELETE FROM "{model._meta.db_table}" WHERE "{model._meta.pk.column}"=%s', [row.pk]
        )
    with pytest.raises(DatabaseError), transaction.atomic():
        model.objects.filter(pk=row.pk).update(evidence={})


@pytest.mark.parametrize("bound", [True, False])
def test_historical_base_wallet_blocks_dedication_without_remote_action(context, bound):
    c = context
    HotWallet.objects.update_or_create(
        chain_id="SOL",
        defaults={
            "address": str(Pubkey.from_bytes(bytes.fromhex(c["keyset"].public_key))),
            "mpc_keyset": c["keyset"] if bound else None,
            "signing_key_ref": "historical",
        },
    )
    with pytest.raises(DatabaseError, match="historical"):
        enroll(c)
    assert not MpcSolanaRoot.objects.exists() and not c["client"].calls


def test_dedicated_pending_root_cannot_enter_legacy_wallets(context):
    c = context
    with (
        patch.object(c["client"], "enroll_solana_root", side_effect=TimeoutError),
        pytest.raises(TimeoutError),
    ):
        enroll(c)
    root = MpcSolanaRoot.objects.get()
    for binding in (None, c["keyset"]):
        with pytest.raises(DatabaseError, match="legacy"), transaction.atomic():
            HotWallet.objects.create(chain_id="SOL", address=root.base_address, mpc_keyset=binding)
        with pytest.raises(DatabaseError, match="legacy"), transaction.atomic():
            UserWallet.objects.create(
                user_id="old",
                chain_id="SOL",
                asset_key="SOL",
                derivation_path="old",
                deposit_address=root.base_address,
                mpc_keyset=binding,
            )


def test_pending_lower_claim_cannot_be_skipped_after_restart(context):
    c = context
    enroll(c)
    first = reserve(c)
    p = register_principal(tenant_id=c["tenant"].pk, customer_ref="later", operator_ref="operator")
    later = reserve(c, retry="later", principal=p)
    connection.close()
    with pytest.raises(MpcBindingError, match="earlier"):
        approve(c, later)
    assert approve(c, first).pk == first.pk and approve(c, later).pk == later.pk


def test_claim_reservation_and_counter_rollback_together_on_audit_failure(context):
    c = context
    root = enroll(c)
    with (
        patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError),
        pytest.raises(RuntimeError),
    ):
        reserve(c)
    root.refresh_from_db()
    assert root.next_index == 0 and not MpcSolanaClaim.objects.exists()
    assert reserve(c).index == 0


def test_populated_migration_cannot_be_downgraded(context):
    enroll(context)
    executor = MigrationExecutor(connection)
    with pytest.raises(RuntimeError, match="cannot downgrade"):
        executor.migrate([("custody", "0033_tenant_principal_registry")])
    assert MpcSolanaRoot.objects.count() == 1


def test_operator_command_reports_approval_separately_from_issuance(context):
    c = context
    enroll(c)
    out = StringIO()
    call_command(
        "solana_provisioning",
        "reserve",
        tenant_id=str(c["tenant"].pk),
        keyset_id=str(c["keyset"].keyset_id),
        principal_id=str(c["principal"].pk),
        asset_key="SOL",
        idempotency_key="command",
        operator_ref="operator",
        stdout=out,
    )
    result = json.loads(out.getvalue())
    assert result["status"] == "PENDING" and result["issued"] is False


def test_legacy_writer_before_dedication_causes_nowait_retry(context):
    c = context
    entered, release = threading.Event(), threading.Event()

    def writer():
        close_old_connections()
        try:
            with transaction.atomic():
                HotWallet.objects.filter(chain_id="SOL").update(
                    address=str(Pubkey.from_bytes(bytes.fromhex(c["keyset"].public_key)))
                )
                entered.set()
                assert release.wait(10)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(writer)
        try:
            assert entered.wait(5)
            with pytest.raises(DatabaseError) as exc:
                enroll(c)
            assert exc.value.__cause__.pgcode == "55P03"
            assert not c["client"].calls and not MpcSolanaRoot.objects.exists()
        finally:
            release.set()
        future.result(timeout=5)
    with pytest.raises(DatabaseError, match="historical"):
        enroll(c)


def test_dedication_before_legacy_writer_blocks_then_rejects_write(context):
    c = context
    entered, release = threading.Event(), threading.Event()
    writer_started = threading.Event()
    pids = []
    from custody.solana_provisioning import _audit

    def hold(action, row, operator_ref):
        _audit(action, row, operator_ref)
        if action == "SOLANA_ROOT_RESERVE":
            entered.set()
            assert release.wait(10)

    def root_worker():
        close_old_connections()
        try:
            return enroll(c).status
        finally:
            close_old_connections()

    def legacy_worker():
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            writer_started.set()
            with pytest.raises(DatabaseError, match="legacy"):
                HotWallet.objects.filter(chain_id="SOL").update(mpc_keyset=c["keyset"])
        finally:
            close_old_connections()

    with patch("custody.solana_provisioning._audit", side_effect=hold):
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(root_worker)
            try:
                assert entered.wait(5)
                second = pool.submit(legacy_worker)
                assert writer_started.wait(5)
                blocked = False
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT cardinality(pg_blocking_pids(%s)) > 0", [pids[0]])
                        blocked = cursor.fetchone()[0]
                    if blocked:
                        break
                    time.sleep(0.01)
                assert blocked, "writer must actually wait on dedication's table lock"
            finally:
                release.set()
            assert first.result(timeout=5) == "APPROVED"
            second.result(timeout=5)
    assert HotWallet.objects.get(chain_id="SOL").mpc_keyset_id is None


def test_last_signed_bigint_index_has_an_exact_exhausted_sentinel(context):
    c = context
    root = enroll(c)
    # Privileged fixture only, simulating a populated namespace at its capacity.
    # Production code cannot advance a counter except from the INSERT trigger.
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(
            "ALTER TABLE custody_mpcsolanaroot DISABLE TRIGGER custody_sol_root_identity"
        )
        cursor.execute("UPDATE custody_mpcsolanaroot SET next_index = %s", [(1 << 63) - 1])
        cursor.execute("ALTER TABLE custody_mpcsolanaroot ENABLE TRIGGER custody_sol_root_identity")
    row = reserve(c)
    assert row.index == (1 << 63) - 1
    root.refresh_from_db()
    assert root.next_index == 1 << 63
    assert reserve(c).pk == row.pk
    another = register_principal(
        tenant_id=c["tenant"].pk, customer_ref="last", operator_ref="operator"
    )
    with pytest.raises(MpcBindingError, match="exhausted"):
        reserve(c, retry="overflow", principal=another)


def test_remote_commit_then_audit_failure_recovers_original_approval(context):
    c = context
    enroll(c)
    row = reserve(c)
    with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit down")):
        with pytest.raises(RuntimeError):
            approve(c, row)
    row.refresh_from_db()
    assert row.status == "PENDING" and len(c["client"].results) == 2
    assert approve(c, row).status == "APPROVED"
    assert AdminActionLog.objects.filter(action_type="SOLANA_CLAIM_APPROVE").count() == 1


@pytest.mark.parametrize("isolation", ["repeatable read", "serializable"])
@pytest.mark.parametrize("chain", ["SOL", "ETH"])
def test_stale_snapshot_cannot_insert_a_legacy_sol_reference(context, isolation, chain):
    c = context
    enroll(c)
    with pytest.raises(DatabaseError, match="READ COMMITTED"), transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation}")
        HotWallet.objects.filter(chain_id=chain).update(mpc_keyset=c["keyset"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("index", 1),
        ("principal_id", uuid4()),
        ("asset_namespace", "wrong"),
        ("idempotency_key", " leading"),
        ("status", "APPROVED"),
    ],
)
def test_sql_insertion_cannot_allocate_a_substituted_claim(context, field, value):
    c = context
    enroll(c)
    original = reserve(c)
    kwargs = {
        f.attname: getattr(original, f.attname)
        for f in MpcSolanaClaim._meta.fields
        if f.name != "created_at"
    }
    kwargs.update(reservation_id=uuid4(), **{field: value})
    with pytest.raises(DatabaseError), transaction.atomic():
        MpcSolanaClaim.objects.create(**kwargs)
    root = MpcSolanaRoot.objects.get()
    assert root.next_index == 1 and MpcSolanaClaim.objects.count() == 1
