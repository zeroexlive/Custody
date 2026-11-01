"""Real PG role/ownership guards; no wallet signing or financial activation."""

import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.db import DatabaseError, close_old_connections, connection, transaction

from custody.financial_identity import register_financial_principal
from custody.identity_registry import RegistryError, register_principal, register_tenant
from custody.ledger import ensure_accounts, post_transaction, user_balances
from custody.models import (
    AdminActionLog,
    CustodyPrincipal,
    CustodyPrincipalRole,
    LedgerAccount,
    LedgerTransaction,
    UserWallet,
    WithdrawalRequest,
)
from custody.tests.test_solana_financial_root import wait_for_database_lock

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def tenant():
    return register_tenant(reference="financial-role-tenant", operator_ref="operator")


def declare(tenant, role="CUSTOMER", reference="principal"):
    return register_financial_principal(
        tenant_id=tenant.pk, reference=reference, role=role, operator_ref="operator"
    )


def wallet(owner, chain="ETH"):
    return UserWallet.objects.create(
        user_id=owner,
        chain_id=chain,
        asset_key=chain,
        derivation_path="legacy-test",
        deposit_address="0x" + "12" * 20 if chain == "ETH" else "legacy-native-address",
    )


def withdrawal(owner, chain="ETH"):
    return WithdrawalRequest.objects.create(
        user_id=owner,
        chain_id=chain,
        asset_key=chain,
        to_address="0x" + "34" * 20,
        amount=Decimal("1"),
        idempotency_key=str(uuid4()),
    )


def test_customer_declaration_preserves_existing_multichain_owner_and_ledger(tenant):
    original = register_principal(
        tenant_id=tenant.pk, customer_ref="existing", operator_ref="operator"
    )
    original_wallet = wallet(original.ledger_owner_id)
    ensure_accounts(original.ledger_owner_id, "ETH")
    available = LedgerAccount.objects.get(
        owner_type="USER", owner_id=original.ledger_owner_id, asset_key="ETH", bucket="AVAILABLE"
    )
    clearing = LedgerAccount.objects.get(
        owner_type="SYSTEM", owner_id="custody", asset_key="ETH", bucket="CUSTODY_CLEARING"
    )
    with transaction.atomic():
        post_transaction(
            event_key="historical-credit",
            event_type="fixture",
            asset_key="ETH",
            ref_type="fixture",
            ref_id="existing",
            postings=[(available, Decimal("5")), (clearing, Decimal("-5"))],
        )
    balances = user_balances(original.ledger_owner_id, "ETH")
    journals = LedgerTransaction.objects.count()
    declared = declare(tenant, reference="existing")
    assert declared.pk == original.pk and declared.ledger_owner_id == original.ledger_owner_id
    assert UserWallet.objects.get(pk=original_wallet.pk).user_id == original.ledger_owner_id
    assert user_balances(original.ledger_owner_id, "ETH") == balances
    assert LedgerTransaction.objects.count() == journals
    assert CustodyPrincipalRole.objects.get(principal=declared).role == "CUSTOMER"


@pytest.mark.parametrize("role", ["CUSTOMER", "TREASURY"])
def test_explicit_role_is_idempotent_permanent_and_not_inferred_from_reference(tenant, role):
    principal = declare(tenant, role, reference="opaque-customer-treasury")
    assert declare(tenant, role, reference=principal.customer_ref).pk == principal.pk
    assert CustodyPrincipalRole.objects.get(principal=principal).role == role
    assert AdminActionLog.objects.filter(action_type="PRINCIPAL_FINANCIAL_ROLE").count() == 1
    other = "TREASURY" if role == "CUSTOMER" else "CUSTOMER"
    with pytest.raises(RegistryError, match="cannot change"):
        declare(tenant, other, reference=principal.customer_ref)
    assert not LedgerTransaction.objects.exists()
    assert not UserWallet.objects.exists()


def test_treasury_service_never_adopts_even_empty_existing_reference(tenant):
    original = register_principal(
        tenant_id=tenant.pk, customer_ref="existing-empty", operator_ref="operator"
    )
    with pytest.raises(RegistryError, match="fresh"):
        declare(tenant, "TREASURY", reference=original.customer_ref)
    assert not CustodyPrincipalRole.objects.filter(principal=original).exists()


@pytest.mark.parametrize("history", ["wallet", "account", "withdrawal"])
def test_raw_sql_cannot_relabel_existing_customer_history_as_treasury(tenant, history):
    original = register_principal(
        tenant_id=tenant.pk, customer_ref="historical", operator_ref="operator"
    )
    if history == "wallet":
        wallet(original.ledger_owner_id)
    elif history == "withdrawal":
        withdrawal(original.ledger_owner_id)
    else:
        ensure_accounts(original.ledger_owner_id, "SOL")
    with pytest.raises(DatabaseError, match="history cannot become treasury"), transaction.atomic():
        CustodyPrincipalRole.objects.create(principal=original, role="TREASURY")
    assert declare(tenant, "CUSTOMER", reference=original.customer_ref).pk == original.pk


@pytest.mark.parametrize("chain", ["ETH", "SOL"])
@pytest.mark.parametrize(
    "writer", ["wallet", "account", "withdrawal", "hd_account", "hd_reservation"]
)
def test_treasury_owner_cannot_enter_future_customer_paths(tenant, chain, writer):
    treasury = declare(tenant, "TREASURY")
    with (
        pytest.raises(DatabaseError, match="treasury principal cannot own customer"),
        transaction.atomic(),
    ):
        if writer == "wallet":
            wallet(treasury.ledger_owner_id, chain)
        elif writer == "withdrawal":
            withdrawal(treasury.ledger_owner_id, chain)
        elif writer == "account":
            LedgerAccount.objects.create(
                owner_type="USER",
                owner_id=treasury.ledger_owner_id,
                asset_key=chain,
                bucket="AVAILABLE",
            )
        else:
            table = {
                "hd_account": "custody_mpccustodyaccount",
                "hd_reservation": "custody_mpcderivationreservation",
            }[writer]
            # The role guard precedes other row validation, even for a direct
            # privileged insertion lacking all other required public evidence.
            with connection.cursor() as cursor:
                cursor.execute(
                    f"INSERT INTO {table} (customer_ref) VALUES (%s)",
                    [treasury.ledger_owner_id],
                )


def test_legacy_wallet_cannot_be_reassigned_to_treasury(tenant):
    treasury = declare(tenant, "TREASURY")
    ordinary = wallet("legacy-owner")
    with pytest.raises(DatabaseError, match="treasury principal"), transaction.atomic():
        UserWallet.objects.filter(pk=ordinary.pk).update(user_id=treasury.ledger_owner_id)
    assert UserWallet.objects.get(pk=ordinary.pk).user_id == "legacy-owner"


def test_roles_are_immutable_through_model_and_raw_sql(tenant):
    principal = declare(tenant, "TREASURY")
    with pytest.raises(ValueError, match="immutable"):
        CustodyPrincipalRole.objects.filter(principal=principal).update(role="CUSTOMER")
    with connection.cursor() as cursor:
        for command in (
            "UPDATE custody_custodyprincipalrole SET role='CUSTOMER' WHERE principal_id=%s",
            "DELETE FROM custody_custodyprincipalrole WHERE principal_id=%s",
        ):
            with pytest.raises(DatabaseError), transaction.atomic():
                cursor.execute(command, [principal.pk])


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
def test_customer_writer_checks_isolation_before_role_absence_lookup(tenant, isolation):
    unclassified = register_principal(
        tenant_id=tenant.pk, customer_ref="not-classified", operator_ref="operator"
    )
    with pytest.raises(DatabaseError, match="READ COMMITTED"), transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION ISOLATION LEVEL " + isolation)
        wallet(unclassified.ledger_owner_id)


def test_role_registration_audit_failure_rolls_back_fresh_identity_and_role(tenant):
    with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit")):
        with pytest.raises(RuntimeError, match="audit"):
            declare(tenant, "TREASURY", reference="failed")
    assert not CustodyPrincipal.objects.filter(tenant=tenant, customer_ref="failed").exists()
    assert not CustodyPrincipalRole.objects.exists()


@pytest.mark.parametrize("first", ["role", "customer"])
@pytest.mark.parametrize("writer", ["wallet", "account"])
def test_role_birth_and_future_customer_writer_races_are_serialized(tenant, first, writer):
    principal = register_principal(
        tenant_id=tenant.pk, customer_ref="race-empty", operator_ref="operator"
    )
    entered, release = threading.Event(), threading.Event()
    application = "principal-role-race-" + str(uuid4())

    def worker(kind, waiting=False):
        close_old_connections()
        try:
            if waiting:
                with connection.cursor() as cursor:
                    cursor.execute("SET application_name=%s", [application])
            try:
                with transaction.atomic():
                    if kind == "role":
                        CustodyPrincipalRole.objects.create(principal=principal, role="TREASURY")
                    elif writer == "wallet":
                        wallet(principal.ledger_owner_id)
                    else:
                        LedgerAccount.objects.create(
                            owner_type="USER",
                            owner_id=principal.ledger_owner_id,
                            asset_key="ETH",
                            bucket="AVAILABLE",
                        )
                    if not waiting:
                        entered.set()
                        assert release.wait(10)
                return "created"
            except DatabaseError as exc:
                return str(exc)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        winner = pool.submit(worker, first)
        try:
            assert entered.wait(5)
            loser = pool.submit(worker, "customer" if first == "role" else "role", True)
            wait_for_database_lock(application)
        finally:
            release.set()
        assert winner.result(timeout=10) == "created"
        denied = loser.result(timeout=10)
    assert (
        "treasury principal cannot own customer"
        if first == "role"
        else "history cannot become treasury"
    ) in denied
    assert CustodyPrincipalRole.objects.filter(principal=principal).exists() == (first == "role")
    assert (
        UserWallet.objects.filter(user_id=principal.ledger_owner_id).exists()
        if writer == "wallet"
        else LedgerAccount.objects.filter(
            owner_type="USER", owner_id=principal.ledger_owner_id
        ).exists()
    ) == (first == "customer")


def test_concurrent_opposite_service_declarations_cannot_relabel_one_owner(tenant):
    def worker(role):
        close_old_connections()
        try:
            try:
                return declare(tenant, role, reference="same-ref").pk
            except RegistryError as exc:
                return str(exc)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(worker, ["CUSTOMER", "TREASURY"]))
    assert sum(not isinstance(value, str) for value in outcomes) == 1
    principal = CustodyPrincipal.objects.get(tenant=tenant, customer_ref="same-ref")
    assert CustodyPrincipalRole.objects.filter(principal=principal).count() == 1
    assert AdminActionLog.objects.filter(action_type="PRINCIPAL_FINANCIAL_ROLE").count() == 1
