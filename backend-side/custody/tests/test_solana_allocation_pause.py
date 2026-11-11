"""Actual PG fences and races; synthetic public receipts are not MPC evidence."""

import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
from django.core.management import call_command
from django.db import DatabaseError, close_old_connections, connection, transaction
from django.db.migrations.executor import MigrationExecutor

from custody.identity_registry import register_principal
from custody.ledger import reserve_withdrawal
from custody.models import (
    AdminActionLog,
    Asset,
    LedgerTransaction,
    MpcSolanaAllocationPause,
    MpcSolanaClaim,
    MpcSolanaFinancialOperation,
    MpcSolanaFinancialSession,
    MpcSolanaRoot,
    WithdrawalRequest,
)
from custody.mpc_binding import MpcBindingError
from custody.solana_allocation_pause import pause_allocation
from custody.solana_seeded import account_address
from custody.tests.solana_fixture import root as fixture_root
from custody.tests.test_solana_financial_preparation import preparation as preparation_fixture
from custody.tests.test_solana_financial_root import clean_mode as clean_mode_fixture
from custody.tests.test_solana_financial_root import wait_for_database_lock
from custody.tests.test_solana_financial_sessions import financial as financial_fixture
from custody.tests.test_solana_financial_sessions import operation, session
from custody.tests.test_solana_provisioning import PublicClient, approve, enroll, reserve
from custody.tests.test_solana_provisioning import context as context_fixture
from custody.tests.test_solana_provisioning import signer_receipt_trust as trust_fixture
from custody.tests.test_solana_token_provisioning import allocate as allocate_token
from custody.tests.test_solana_token_provisioning import pending as pending_fixture

pytestmark = pytest.mark.django_db(transaction=True)
context = context_fixture
signer_receipt_trust = trust_fixture
clean_mode = clean_mode_fixture
financial = financial_fixture
preparation = preparation_fixture
pending = pending_fixture


@pytest.fixture(autouse=True)
def enabled(settings):
    settings.MPC_SOLANA_ALLOCATION_PAUSE_ENABLED = True


def pause(c, pause_id=None, **overrides):
    return pause_allocation(
        **{
            "keyset_id": c["keyset"].keyset_id,
            "tenant_id": c["tenant"].pk,
            "pause_id": pause_id or uuid4(),
            "operator_ref": "pause-operator",
            **overrides,
        }
    )


def raw_pause(c):
    r = MpcSolanaRoot.objects.get(pk=c["keyset"].pk)
    return MpcSolanaAllocationPause.objects.create(root=r, frontier=r.next_index)


def claim_data(c, principal):
    root = MpcSolanaRoot.objects.get(pk=c["keyset"].pk)
    idx, reservation, retry = int(root.next_index), uuid4(), str(uuid4())
    return dict(
        reservation_id=reservation,
        root=root,
        principal=principal,
        asset_id=Asset.objects.get(asset_key="SOL").pk,
        asset_namespace="SOL",
        idempotency_key=retry,
        index=idx,
        statement={
            "root": copy.deepcopy(root.statement),
            "reservation_id": str(reservation),
            "owner_ref": principal.ledger_owner_id,
            "idempotency_key": retry,
            "index": idx,
            "asset": {"kind": "Native"},
        },
        address=account_address(root.base_address, idx),
    )


def raw_operation(c):
    source, req = c["TREASURY"], c["withdrawal"]
    return MpcSolanaFinancialOperation.objects.create(
        withdrawal=req,
        principal=c["CUSTOMER"].claim.principal,
        source=source,
        amount=req.amount,
        base_unit_amount=1_000_000_000,
        destination_address=req.to_address,
        fee_budget_lamports=20_000,
    )


def other_root(c):
    _, keyset = fixture_root(88)
    other = dict(c, keyset=keyset, client=PublicClient(keyset.dkg_public_evidence))
    other["root"] = enroll(other)
    return other


def test_pause_commits_exact_frontier_without_remote_or_ledger_work(context, signer_receipt_trust):
    c = context
    root = enroll(c)
    claim = reserve(c)
    original = copy.deepcopy(root.statement), copy.deepcopy(root.evidence)
    with patch("custody.mpc_transport.http.client.HTTPSConnection") as network:
        row = pause(c)
        network.assert_not_called()
    root.refresh_from_db()
    assert row.frontier == root.next_index == 1
    assert (root.statement, root.evidence) == original and root.status == "APPROVED"
    assert reserve(c).pk == claim.pk
    assert MpcSolanaFinancialOperation.objects.count() == LedgerTransaction.objects.count() == 0
    assert AdminActionLog.objects.filter(action_type="SOLANA_ALLOCATION_PAUSE").count() == 1


def test_exact_retry_and_fences_survive_entry_flag_off(context, signer_receipt_trust, settings):
    c = context
    enroll(c)
    claim = reserve(c)
    row = pause(c)
    settings.MPC_SOLANA_ALLOCATION_PAUSE_ENABLED = False
    assert pause(c, row.pk).pk == row.pk and reserve(c).pk == claim.pk
    with pytest.raises(MpcBindingError, match="original allocation pause"):
        pause(c)
    new_owner = register_principal(
        tenant_id=c["tenant"].pk, customer_ref="another", operator_ref="operator"
    )
    with pytest.raises(MpcBindingError, match="locally paused"):
        reserve(c, retry="another", principal=new_owner)
    with pytest.raises(DatabaseError, match="locally paused"), transaction.atomic():
        MpcSolanaClaim.objects.create(**claim_data(c, new_owner))
    assert MpcSolanaRoot.objects.get().next_index == 1


def test_new_pause_is_default_disabled(context, signer_receipt_trust, settings):
    enroll(context)
    settings.MPC_SOLANA_ALLOCATION_PAUSE_ENABLED = False
    with pytest.raises(MpcBindingError, match="disabled"):
        pause(context)
    assert not MpcSolanaAllocationPause.objects.exists()


def test_existing_public_claim_can_finish_after_pause(context, signer_receipt_trust):
    c = context
    enroll(c)
    claim = reserve(c)
    pause(c)
    approved = approve(c, claim)
    assert approved.pk == claim.pk and approved.status == "APPROVED"
    assert MpcSolanaRoot.objects.get().next_index == 1
    assert not LedgerTransaction.objects.exists()


@pytest.mark.parametrize("mutation", ["frontier", "identity", "delete", "counter"])
def test_pause_and_frontier_are_immutable(context, signer_receipt_trust, mutation):
    enroll(context)
    row = pause(context)
    with pytest.raises(DatabaseError), transaction.atomic():
        if mutation == "frontier":
            MpcSolanaAllocationPause.objects.filter(pk=row.pk).update(frontier=1)
        elif mutation == "identity":
            MpcSolanaAllocationPause.objects.filter(pk=row.pk).update(pause_id=uuid4())
        elif mutation == "delete":
            MpcSolanaAllocationPause.objects.filter(pk=row.pk).delete()
        else:
            MpcSolanaRoot.objects.filter(pk=row.root_id).update(next_index=1)
    assert MpcSolanaAllocationPause.objects.get().frontier == 0


@pytest.mark.parametrize("damage", ["frontier", "zero-id", "unapproved", "retired"])
def test_raw_pause_requires_exact_approved_original_source(context, signer_receipt_trust, damage):
    if damage == "unapproved":
        with patch.object(context["client"], "enroll_solana_root", side_effect=RuntimeError):
            with pytest.raises(RuntimeError):
                enroll(context)
    else:
        enroll(context)
    if damage == "retired":
        context["keyset"].status = "RETIRED"
        context["keyset"].save(update_fields=["status"])
    data = dict(root_id=context["keyset"].pk, frontier=int(damage == "frontier"))
    if damage == "zero-id":
        data["pause_id"] = UUID(int=0)
    with pytest.raises(DatabaseError, match="exact original"), transaction.atomic():
        MpcSolanaAllocationPause.objects.create(**data)
    assert not MpcSolanaAllocationPause.objects.exists()


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
def test_raw_pause_rejects_stale_isolation(context, signer_receipt_trust, isolation):
    enroll(context)
    with pytest.raises(DatabaseError, match="READ COMMITTED"), transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation}")
        raw_pause(context)


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
def test_invisible_pause_cannot_be_bypassed_by_old_claim_snapshot(
    context, signer_receipt_trust, isolation
):
    c = context
    enroll(c)
    data = claim_data(c, c["principal"])

    def worker():
        close_old_connections()
        try:
            return pause(c).pk
        finally:
            close_old_connections()

    with pytest.raises(DatabaseError, match="READ COMMITTED"), transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation}")
        assert MpcSolanaAllocationPause.objects.count() == 0
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(worker).result(timeout=10)
        assert MpcSolanaAllocationPause.objects.count() == 0  # Truly invisible to old snapshot.
        MpcSolanaClaim.objects.create(**data)
    assert MpcSolanaAllocationPause.objects.count() == 1
    assert MpcSolanaRoot.objects.get().next_index == 0


def test_pause_audit_failure_rolls_back_fence(context, signer_receipt_trust):
    enroll(context)
    with patch(
        "custody.solana_allocation_pause.AdminActionLog.objects.create", side_effect=RuntimeError
    ):
        with pytest.raises(RuntimeError):
            pause(context)
    assert not MpcSolanaAllocationPause.objects.exists()
    assert reserve(context).index == 0


def test_pause_refuses_existing_held_business(financial):
    c = financial
    op = operation(c)
    with pytest.raises(DatabaseError, match="recover all tracked"):
        pause(c)
    op.refresh_from_db()
    assert op.status == "HELD" and not MpcSolanaAllocationPause.objects.exists()


def test_no_signature_does_not_make_held_business_quiescent(financial):
    from custody.solana_financial_sessions import complete_no_signature
    from custody.tests.test_solana_financial_sessions import query, terminal

    c = financial
    row = session(c)
    request = query(c, row)
    complete_no_signature(
        session_id=row.pk,
        tenant_id=c["tenant"].pk,
        challenge=request["query"]["challenge"],
        evidence=terminal(c, row, request),
        operator_ref="operator",
    )
    with pytest.raises(DatabaseError, match="recover all tracked"):
        pause(c)
    row.refresh_from_db()
    assert row.status == "NO_SIGNATURE" and row.operation.status == "HELD"


def test_pause_fences_application_and_raw_financial_business(financial):
    c = financial
    pause(c)
    before = LedgerTransaction.objects.count()
    with pytest.raises(MpcBindingError, match="locally paused"):
        operation(c)
    with pytest.raises(DatabaseError, match="locally paused"), transaction.atomic():
        raw_operation(c)
    assert not MpcSolanaFinancialOperation.objects.exists()
    assert LedgerTransaction.objects.count() == before


def test_zero_principal_initializer_is_still_held_work(pending):
    c = pending
    op = allocate_token(c)
    assert op.base_unit_amount == 0 and op.rent_budget_lamports > 0
    with pytest.raises(DatabaseError, match="recover all tracked"):
        pause(c)
    assert not MpcSolanaAllocationPause.objects.exists()


def test_pause_prevents_new_initializer_without_rewriting_pending_membership(pending):
    c = pending
    row = pause(c)
    with pytest.raises(MpcBindingError, match="locally paused"):
        allocate_token(c)
    c["token_wallet"].refresh_from_db()
    assert c["token_wallet"].status == "PENDING"
    assert not MpcSolanaFinancialOperation.objects.exists()
    assert MpcSolanaAllocationPause.objects.get().frontier == row.frontier


@pytest.mark.parametrize("address_kind", ["base", "claim"])
@pytest.mark.parametrize("first", ["pause", "incoming"])
def test_known_incoming_address_and_pause_are_mutually_exclusive(financial, address_kind, first):
    c = financial
    other = other_root(c)
    other["principal"] = c["CUSTOMER"].claim.principal
    destination = other["root"].base_address
    if address_kind == "claim":
        destination = reserve(other).address
    # Exercise the SQL classifier directly. Ordinary app withdrawals already
    # reject known custody destinations; this is not internal-transfer authority.
    original = c["withdrawal"]
    with transaction.atomic():
        req = WithdrawalRequest.objects.create(
            user_id=original.user_id,
            chain_id="SOL",
            asset_key="SOL",
            to_address=destination,
            amount=original.amount,
            status="APPROVED",
        )
        reserve_withdrawal(req)
    c = dict(c, withdrawal=req)
    if first == "pause":
        pause(other)
        with pytest.raises(DatabaseError, match="locally paused"), transaction.atomic():
            raw_operation(c)
    else:
        raw_operation(c)
        with pytest.raises(DatabaseError, match="recover all tracked"):
            pause(other)


@pytest.mark.parametrize("first", ["pause", "claim"])
def test_pause_and_claim_birth_serialize_at_original_root(context, signer_receipt_trust, first):
    c = context
    enroll(c)
    data = claim_data(c, c["principal"])
    entered, release = threading.Event(), threading.Event()

    def leading():
        close_old_connections()
        try:
            with transaction.atomic():
                (raw_pause(c) if first == "pause" else MpcSolanaClaim.objects.create(**data))
                entered.set()
                assert release.wait(15)
        finally:
            close_old_connections()

    def trailing():
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET application_name='pause-claim-race'")
            if first == "pause":
                with pytest.raises(DatabaseError, match="locally paused"), transaction.atomic():
                    MpcSolanaClaim.objects.create(**data)
            else:
                assert pause(c).frontier == 1
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        head = pool.submit(leading)
        try:
            assert entered.wait(10)
            tail = pool.submit(trailing)
            wait_for_database_lock("pause-claim-race")
        finally:
            release.set()
        head.result(timeout=10)
        tail.result(timeout=10)
    assert MpcSolanaAllocationPause.objects.get().frontier == int(first == "claim")


@pytest.mark.parametrize("first", ["pause", "operation"])
def test_pause_and_held_operation_birth_serialize(financial, first):
    c = financial
    entered, release = threading.Event(), threading.Event()

    def leading():
        close_old_connections()
        try:
            with transaction.atomic():
                (raw_pause(c) if first == "pause" else raw_operation(c))
                entered.set()
                assert release.wait(15)
        finally:
            close_old_connections()

    def trailing():
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET application_name='pause-op-race'")
            if first == "pause":
                with pytest.raises(DatabaseError, match="locally paused"), transaction.atomic():
                    raw_operation(c)
            else:
                with pytest.raises(DatabaseError, match="recover all tracked"):
                    pause(c)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        head = pool.submit(leading)
        try:
            assert entered.wait(10)
            tail = pool.submit(trailing)
            wait_for_database_lock("pause-op-race")
        finally:
            release.set()
        head.result(timeout=10)
        tail.result(timeout=10)
    assert MpcSolanaAllocationPause.objects.exists() == (first == "pause")
    assert MpcSolanaFinancialOperation.objects.exists() == (first == "operation")


def test_pause_cannot_miss_incoming_operation_while_destination_becomes_known(financial):
    c = financial
    other = other_root(c)
    data = claim_data(other, c["CUSTOMER"].claim.principal)
    with transaction.atomic():
        req = WithdrawalRequest.objects.create(
            user_id=c["withdrawal"].user_id,
            chain_id="SOL",
            asset_key="SOL",
            to_address=data["address"],
            amount=c["withdrawal"].amount,
            status="APPROVED",
        )
        reserve_withdrawal(req)
    incoming = dict(c, withdrawal=req)
    entered, release = threading.Event(), threading.Event()

    def writer():
        close_old_connections()
        try:
            with transaction.atomic():
                # No Claim exists for the future destination yet. The operation
                # correctly cannot discover or lock that destination Root here.
                raw_operation(incoming)
                entered.set()
                assert release.wait(15)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(writer)
        try:
            assert entered.wait(10)
            MpcSolanaClaim.objects.create(**data)
            with pytest.raises(DatabaseError) as exc:
                pause(other)
            assert exc.value.__cause__.pgcode == "55P03"
            assert not MpcSolanaAllocationPause.objects.exists()
        finally:
            release.set()
        future.result(timeout=10)
    with pytest.raises(DatabaseError, match="recover all tracked"):
        pause(other)
    assert MpcSolanaFinancialOperation.objects.count() == 1


def test_pause_cannot_be_downgraded_when_populated(context, signer_receipt_trust):
    enroll(context)
    pause(context)
    executor = MigrationExecutor(connection)
    try:
        with pytest.raises(DatabaseError, match="cannot lose its fences"):
            executor.migrate([("custody", "0048_solana_coordinator_binding")])
    finally:
        MigrationExecutor(connection).migrate([("custody", "0049_solana_allocation_pause")])
    assert MpcSolanaAllocationPause.objects.count() == 1


def test_operator_command_returns_only_local_pause_facts(context, signer_receipt_trust):
    c = context
    enroll(c)
    out = StringIO()
    call_command(
        "solana_allocation_pause",
        keyset_id=str(c["keyset"].keyset_id),
        tenant_id=str(c["tenant"].pk),
        pause_id=str(uuid4()),
        operator_ref="operator",
        stdout=out,
    )
    value = json.loads(out.getvalue())
    assert value["frontier"] == "0"
    assert value["private_work_performed"] is value["witness_freeze_performed"] is False
    assert not MpcSolanaFinancialSession.objects.exists()
