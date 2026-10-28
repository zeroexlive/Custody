"""Actual PostgreSQL identity/transaction guards, not MPC or user-login acceptance."""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from io import StringIO
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.contrib import admin
from django.core.management import call_command
from django.db import DatabaseError, close_old_connections, connection, transaction
from django.db.migrations.executor import MigrationExecutor

from custody.identity_registry import (
    RegistryError,
    register_principal,
    register_tenant,
    resolve_principal,
)
from custody.ledger import ensure_accounts, post_transaction, user_balances
from custody.models import (
    AdminActionLog,
    Asset,
    CustodyPrincipal,
    CustodyTenant,
    LedgerAccount,
    LedgerPosting,
    LedgerTransaction,
    MpcCustodyAccount,
    UserWallet,
    WithdrawalRequest,
)
from custody.mpc_provisioning import reserve_derivation_path
from custody.tests.test_phase6g_provisioning import root as provisioning_root_fixture

pytestmark = pytest.mark.django_db(transaction=True)
root = provisioning_root_fixture


def tenant(ref="operator-tenant"):
    return register_tenant(reference=ref, operator_ref="operator:test")


def principal(row, ref="opaque-customer"):
    return register_principal(tenant_id=row.pk, customer_ref=ref, operator_ref="operator:test")


def wallet(owner):
    return UserWallet.objects.create(
        user_id=owner,
        chain_id="SOL",
        asset_key="SOL",
        derivation_path="legacy",
        deposit_address=f"legacy-address-{uuid4()}",
    )


def raw_principal(row, ident, owner=None, ref="raw-customer"):
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO custody_custodyprincipal"
            "(principal_id, tenant_id, customer_ref, ledger_owner_id, created_at)"
            " VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)",
            [ident, row.pk, ref, owner or f"p1:{ident}"],
        )


def test_exact_scoped_identity_is_idempotent_without_financial_side_effects():
    a, b = tenant("A"), tenant("a")
    assert a.pk != b.pk and tenant("A").pk == a.pk
    first, other = principal(a), principal(b)
    assert first.pk != other.pk and first.ledger_owner_id == f"p1:{first.pk}"
    assert principal(a).pk == first.pk
    assert resolve_principal(tenant_id=a.pk, principal_id=first.pk).pk == first.pk
    with pytest.raises(RegistryError, match="unavailable"):
        resolve_principal(tenant_id=b.pk, principal_id=first.pk)
    refs = ["Case", "case", "é", "e\u0301", "مشتری"]
    assert len({principal(a, ref).pk for ref in refs}) == len(refs)
    assert not LedgerAccount.objects.exists() and not UserWallet.objects.exists()
    assert AdminActionLog.objects.filter(action_type="TENANT_REGISTER").count() == 2
    assert AdminActionLog.objects.filter(action_type="PRINCIPAL_REGISTER").count() == 7


@pytest.mark.parametrize("bad", [None, "", " leading", "trailing\n", "x" * 65, "nul\0ref"])
def test_invalid_reference_cannot_create_identity_or_audit(bad):
    row = tenant()
    with pytest.raises(RegistryError):
        register_tenant(reference=bad, operator_ref="operator")
    with pytest.raises(RegistryError):
        principal(row, bad)
    assert CustodyTenant.objects.count() == 1 and not CustodyPrincipal.objects.exists()
    assert AdminActionLog.objects.count() == 1


@pytest.mark.parametrize("kind", ["tenant", "principal"])
def test_audit_failure_rolls_back_creation_and_retry_has_one_birth(kind):
    row = tenant() if kind == "principal" else None
    before = AdminActionLog.objects.count()
    with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit down")):
        with pytest.raises(RuntimeError, match="audit down"):
            principal(row) if row else tenant()
    assert not CustodyPrincipal.objects.exists()
    assert CustodyTenant.objects.count() == (1 if row else 0)
    assert AdminActionLog.objects.count() == before
    created = principal(row) if row else tenant()
    assert created.pk == (principal(row) if row else tenant()).pk
    assert AdminActionLog.objects.count() == before + 1


@pytest.mark.parametrize("kind", ["tenant", "principal"])
@pytest.mark.parametrize(
    "action", ["orm-save", "orm-update", "orm-delete", "sql-update", "sql-delete"]
)
def test_identity_cannot_be_reassigned_or_deleted_even_unused(kind, action):
    row = tenant()
    obj = row if kind == "tenant" else principal(row)
    model = type(obj)
    table, key = model._meta.db_table, model._meta.pk.column
    before = model.objects.values().get(pk=obj.pk)
    if action.startswith("orm"):
        with pytest.raises(ValueError, match="registry identity"):
            if action == "orm-save":
                obj.save()
            elif action == "orm-update":
                model.objects.filter(pk=obj.pk).update(created_at=obj.created_at)
            else:
                obj.delete()
    else:
        with pytest.raises(DatabaseError, match="registry identity"):
            with transaction.atomic(), connection.cursor() as cursor:
                if action == "sql-delete":
                    cursor.execute(f'DELETE FROM "{table}" WHERE "{key}" = %s', [obj.pk])
                else:
                    cursor.execute(
                        f"UPDATE \"{table}\" SET created_at = created_at + interval '1 second'"
                        f' WHERE "{key}" = %s',
                        [obj.pk],
                    )
    assert model.objects.values().get(pk=obj.pk) == before


@pytest.mark.parametrize(
    "wrong", ["plain-owner", "p1:00000000-0000-0000-0000-000000000000", "P1:bad"]
)
def test_sql_requires_generated_canonical_owner_id(wrong):
    row = tenant()
    with pytest.raises(DatabaseError, match="generated principal"):
        raw_principal(row, uuid4(), owner=wrong)
    assert not CustodyPrincipal.objects.exists()


@pytest.mark.parametrize("bad", ["", " leading", "trailing\t"])
def test_sql_validates_opaque_references_before_registration(bad):
    row = tenant()
    with pytest.raises(DatabaseError, match="invalid generated principal"):
        raw_principal(row, uuid4(), ref=bad)
    with pytest.raises(DatabaseError, match="invalid tenant identity"):
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO custody_custodytenant(tenant_id,reference,created_at)"
                " VALUES (%s,%s,CURRENT_TIMESTAMP)",
                [uuid4(), bad],
            )


def test_sql_validates_nil_ids_and_original_tenant_fk():
    from types import SimpleNamespace
    from uuid import UUID

    row = tenant()
    with pytest.raises(DatabaseError, match="generated principal"):
        raw_principal(row, UUID(int=0))
    with pytest.raises(DatabaseError, match="invalid tenant identity"):
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO custody_custodytenant(tenant_id,reference,created_at)"
                " VALUES (%s,'nil-tenant',CURRENT_TIMESTAMP)",
                [UUID(int=0)],
            )
    with pytest.raises(DatabaseError, match="foreign key constraint"):
        raw_principal(SimpleNamespace(pk=uuid4()), uuid4())


@pytest.mark.parametrize("field", ["tenant_id", "principal_id", "ledger_owner_id", "customer_ref"])
def test_sql_cannot_reassign_principal_tenant_or_financial_identity(field):
    row, other = tenant("first"), tenant("other")
    item = principal(row)
    values = {
        "tenant_id": other.pk,
        "principal_id": uuid4(),
        "ledger_owner_id": "p1:" + str(uuid4()),
        "customer_ref": "different",
    }
    with pytest.raises(DatabaseError, match="immutable"):
        with connection.cursor() as cursor:
            cursor.execute(
                f'UPDATE custody_custodyprincipal SET "{field}" = %s WHERE principal_id = %s',
                [values[field], item.pk],
            )
    assert (
        resolve_principal(tenant_id=row.pk, principal_id=item.pk).ledger_owner_id
        == item.ledger_owner_id
    )


def test_postgresql_catalog_has_exact_reference_collations():
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT a.attname,c.collname FROM pg_attribute a"
            " JOIN pg_collation c ON c.oid=a.attcollation"
            " WHERE (a.attrelid='custody_custodytenant'::regclass AND a.attname='reference')"
            " OR (a.attrelid='custody_custodyprincipal'::regclass AND a.attname='customer_ref')"
        )
        assert set(cursor.fetchall()) == {("reference", "C"), ("customer_ref", "C")}


@pytest.mark.parametrize("kind", ["ledger", "wallet", "withdrawal", "reservation", "account"])
def test_legacy_ownership_is_never_adopted(kind, root):
    row = tenant()
    ident = uuid4()
    owner = f"p1:{ident}"
    if kind == "ledger":
        assert Asset.objects.get(asset_key="SOL").is_native
        old = LedgerAccount.objects.create(
            owner_type="USER", owner_id=owner, asset_key="SOL", bucket="AVAILABLE"
        )
    elif kind == "wallet":
        old = wallet(owner)
    elif kind == "withdrawal":
        old = WithdrawalRequest.objects.create(
            user_id=owner, chain_id="SOL", asset_key="SOL", to_address="legacy", amount="1"
        )
    else:
        old = reserve_derivation_path(
            keyset_id=root.keyset.keyset_id,
            ownership_scope=root.ownership_scope,
            customer_ref=owner,
            idempotency_key="legacy-reservation",
        )
        if kind == "account":
            old = MpcCustodyAccount.objects.create(
                reservation=old,
                ownership_scope=root.ownership_scope,
                customer_ref=owner,
                chain_id=root.chain_id,
            )
    model, old_id = type(old), old.pk
    original = model.objects.values().get(pk=old_id)
    with patch("custody.identity_registry.uuid4", return_value=ident):
        with pytest.raises(DatabaseError, match="legacy ownership"):
            principal(row)
    assert model.objects.values().get(pk=old_id) == original
    assert not CustodyPrincipal.objects.exists()
    assert AdminActionLog.objects.filter(action_type="PRINCIPAL_REGISTER").count() == 0


def test_concurrent_retries_have_one_identity_and_audit():
    row = tenant()

    def work(i):
        close_old_connections()
        try:
            item = principal(row, f"customer-{i % 8}")
            return item.pk, item.ledger_owner_id
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(work, range(32)))
    assert len(set(results)) == 8
    assert AdminActionLog.objects.filter(action_type="PRINCIPAL_REGISTER").count() == 8


def test_concurrent_tenant_registration_has_one_identity_and_audit():
    def work(_):
        close_old_connections()
        try:
            return tenant().pk
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(work, range(12)))
    assert len(set(results)) == 1
    assert AdminActionLog.objects.filter(action_type="TENANT_REGISTER").count() == 1


def test_busy_legacy_writer_prevents_birth_then_committed_collision_is_rejected():
    row = tenant()
    ident = uuid4()
    owner = f"p1:{ident}"
    ready, release = threading.Event(), threading.Event()

    def old_writer():
        close_old_connections()
        try:
            with transaction.atomic():
                item = wallet(owner)
                ready.set()
                assert release.wait(10)
            return item.pk
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=1) as pool:
        old = pool.submit(old_writer)
        try:
            assert ready.wait(10)
            with patch("custody.identity_registry.uuid4", return_value=ident):
                with pytest.raises(DatabaseError) as caught:
                    principal(row)
            assert caught.value.__cause__.pgcode == "55P03"
            assert not CustodyPrincipal.objects.exists()
        finally:
            release.set()
        old_id = old.result(timeout=10)
    with patch("custody.identity_registry.uuid4", return_value=ident):
        with pytest.raises(DatabaseError, match="legacy ownership"):
            principal(row)
    assert UserWallet.objects.get(pk=old_id).user_id == owner


def test_birth_locks_legacy_writer_until_the_identity_transaction_finishes():
    row = tenant()
    ident = uuid4()
    held, writer_started, release = threading.Event(), threading.Event(), threading.Event()
    pids = {}
    real_audit = AdminActionLog.objects.create

    def audited(**kwargs):
        if kwargs["action_type"] == "PRINCIPAL_REGISTER":
            pids["registry"] = connection.connection.get_backend_pid()
            held.set()
            assert release.wait(10)
        return real_audit(**kwargs)

    def birth():
        close_old_connections()
        try:
            return principal(row)
        finally:
            close_old_connections()

    def later_writer():
        close_old_connections()
        try:
            connection.ensure_connection()
            pids["writer"] = connection.connection.get_backend_pid()
            writer_started.set()
            return wallet(f"p1:{ident}")
        finally:
            close_old_connections()

    with (
        patch("custody.identity_registry.uuid4", return_value=ident),
        patch.object(AdminActionLog.objects, "create", side_effect=audited),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        registered = pool.submit(birth)
        try:
            assert held.wait(10)
            writer = pool.submit(later_writer)
            assert writer_started.wait(10)
            deadline = time.monotonic() + 5
            blocked = False
            while time.monotonic() < deadline:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_blocking_pids(%s)", [pids["writer"]])
                    blocked = pids["registry"] in cursor.fetchone()[0]
                if blocked:
                    break
                time.sleep(0.01)
            assert blocked, "legacy INSERT must wait on the real registry table lock"
        finally:
            release.set()
        item, old = registered.result(timeout=10), writer.result(timeout=10)
    assert old.user_id == item.ledger_owner_id
    # Future privileged writes remain trusted; this proves serialization at
    # birth, not authorization of the later legacy writer.


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
def test_raw_sql_cannot_use_a_stale_transaction_snapshot(isolation):
    row = tenant()
    with pytest.raises(DatabaseError, match="READ COMMITTED"):
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation}")
            raw_principal(row, uuid4())


def test_service_rejects_atomic_and_manual_outer_transactions():
    with transaction.atomic(), pytest.raises(RegistryError, match="standalone"):
        tenant()
    connection.set_autocommit(False)
    try:
        with pytest.raises(RegistryError, match="standalone"):
            tenant()
    finally:
        connection.rollback()
        connection.set_autocommit(True)


def test_operator_command_returns_only_the_original_scoped_identity():
    out = StringIO()
    call_command(
        "custody_identity", "tenant", tenant_reference="command", operator_ref="op", stdout=out
    )
    row = json.loads(out.getvalue())
    out = StringIO()
    call_command(
        "custody_identity",
        "principal",
        tenant_id=row["tenant_id"],
        customer_ref="id",
        operator_ref="op",
        stdout=out,
    )
    original = json.loads(out.getvalue())
    out = StringIO()
    call_command(
        "custody_identity",
        "resolve",
        tenant_id=row["tenant_id"],
        principal_id=original["principal_id"],
        stdout=out,
    )
    assert json.loads(out.getvalue()) == original


@pytest.mark.parametrize("model", [CustodyTenant, CustodyPrincipal])
def test_admin_is_view_only_even_for_superuser(model, admin_client, admin_user):
    row = tenant()
    obj = row if model is CustodyTenant else principal(row)
    handler = admin.site._registry[model]
    request = type("Request", (), {"user": admin_user})()
    assert not handler.has_add_permission(request)
    assert not handler.has_change_permission(request, obj)
    assert not handler.has_delete_permission(request, obj)
    name = model._meta.model_name
    assert admin_client.get(f"/admin/custody/{name}/{obj.pk}/change/").status_code == 200
    assert admin_client.post(f"/admin/custody/{name}/{obj.pk}/change/", {}).status_code == 403
    assert admin_client.post(f"/admin/custody/{name}/add/", {}).status_code == 403
    assert admin_client.post(f"/admin/custody/{name}/{obj.pk}/delete/", {}).status_code == 403
    assert (
        admin_client.post(
            f"/admin/custody/{name}/",
            {"action": "delete_selected", "_selected_action": [str(obj.pk)]},
        ).status_code
        == 200
    )
    assert model.objects.filter(pk=obj.pk).exists()


def test_migration_does_not_rewrite_history_and_refuses_populated_downgrade():
    executor = MigrationExecutor(connection)
    final = executor.loader.graph.leaf_nodes()
    old = wallet("legacy-owner")
    original = UserWallet.objects.values().get(pk=old.pk)
    Asset.objects.get_or_create(
        asset_key="SOL",
        defaults={"chain_id": "SOL", "symbol": "SOL", "decimals": 9, "is_native": True},
    )
    with transaction.atomic():
        ensure_accounts("legacy-owner", "SOL")
        available = LedgerAccount.objects.get(
            owner_type="USER", owner_id="legacy-owner", asset_key="SOL", bucket="AVAILABLE"
        )
        clearing = LedgerAccount.objects.get(
            owner_type="SYSTEM", owner_id="custody", asset_key="SOL", bucket="CUSTODY_CLEARING"
        )
        post_transaction(
            event_key="registry-migration-history",
            event_type="DEPOSIT",
            asset_key="SOL",
            ref_type="isolated-test",
            ref_id="original",
            postings=[(available, Decimal("7.25")), (clearing, Decimal("-7.25"))],
        )
    financial = {
        model: list(model.objects.order_by("pk").values())
        for model in (LedgerAccount, LedgerTransaction, LedgerPosting)
    }
    try:
        executor.migrate([("custody", "0032_signer_origin_receipts")])
        MigrationExecutor(connection).migrate(final)
        assert UserWallet.objects.values().get(pk=old.pk) == original
        assert user_balances("legacy-owner", "SOL")["total"] == Decimal("7.25")
        row = tenant()
        registered = principal(row)
        with pytest.raises(RuntimeError, match="cannot downgrade registered identities"):
            MigrationExecutor(connection).migrate([("custody", "0032_signer_origin_receipts")])
        assert resolve_principal(tenant_id=row.pk, principal_id=registered.pk).pk == registered.pk
        assert UserWallet.objects.values().get(pk=old.pk) == original
        for model, rows in financial.items():
            assert list(model.objects.order_by("pk").values()) == rows
    finally:
        MigrationExecutor(connection).migrate(final)
