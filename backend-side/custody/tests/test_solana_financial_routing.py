"""PG financial routing/denial tests with synthetic histories; no MPC claim."""

from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.db import DatabaseError, transaction

from custody.financial_identity import register_financial_principal
from custody.ledger import (
    clearing_account,
    ensure_accounts,
    lock_user_accounts,
    post_transaction,
    release_withdrawal,
    reserve_withdrawal,
    settle_withdrawal,
    user_balances,
)
from custody.models import (
    AdminActionLog,
    LedgerTransaction,
    MpcSigningSession,
    MpcSolanaFinancialOperation,
    OnchainTransactionAttempt,
    WithdrawalRequest,
)
from custody.mpc_binding import MpcBindingError
from custody.outbound import _execute_attempt, create_attempt
from custody.solana_financial_routing import financial_customer
from custody.solana_financial_wallet import financial_wallet_request
from custody.tests import test_phase6_signing as legacy_fixtures
from custody.tests import test_solana_financial_sessions as fixtures
from custody.tests.test_solana_provisioning import approve as approve_claim
from custody.tests.test_solana_provisioning import reserve as reserve_claim
from custody.withdrawals import approve, deny, process_withdrawal

pytestmark = pytest.mark.django_db(transaction=True)
clean_mode = fixtures.clean_mode
context = fixtures.context
financial = fixtures.financial
signer_receipt_trust = fixtures.signer_receipt_trust
integration_settings = legacy_fixtures.integration_settings
legacy_context = legacy_fixtures.context


def attempt_values(c, req=None, **changes):
    req = req or c["withdrawal"]
    return dict(
        operation_type="WITHDRAWAL",
        operation_id=req.pk,
        chain_id="SOL",
        asset_key="SOL",
        from_address=c["root"].base_address,
        to_address=req.to_address,
        amount=req.amount,
        base_unit_amount=10**9,
        **changes,
    )


def test_unallocated_financial_request_cannot_reach_shared_hot_or_create_legacy_attempt(financial):
    c = financial
    assert not MpcSolanaFinancialOperation.objects.exists()
    with patch("custody.withdrawals.ensure_hot_wallet") as hot:
        with pytest.raises(MpcBindingError, match="explicit tenant treasury"):
            process_withdrawal("operator", c["withdrawal"].pk)
        hot.assert_not_called()
    with pytest.raises(MpcBindingError, match="typed private"):
        create_attempt(
            operation_type="WITHDRAWAL",
            operation_id=c["withdrawal"].pk,
            chain_id="SOL",
            asset_key="SOL",
            source=c["root"].base_address,
            destination=c["withdrawal"].to_address,
            amount=Decimal(1),
        )
    with pytest.raises(DatabaseError, match="legacy private attempt"), transaction.atomic():
        OnchainTransactionAttempt.objects.create(**attempt_values(c))
    assert not OnchainTransactionAttempt.objects.exists()
    c["withdrawal"].refresh_from_db()
    assert c["withdrawal"].status == "APPROVED"


def test_financial_membership_history_still_fences_after_retirement(financial):
    c = financial
    c["root"].keyset.status = "RETIRED"
    c["root"].keyset.save(update_fields=["status"])
    assert financial_customer(c["withdrawal"].user_id, "SOL", "SOL")
    assert not financial_customer(c["withdrawal"].user_id, "ETH", "ETH")
    with pytest.raises(MpcBindingError):
        process_withdrawal("operator", c["withdrawal"].pk)


@pytest.mark.parametrize("action", ["release", "settle"])
def test_unallocated_approved_financial_hold_is_not_released_or_settled_from_absence(
    financial, action
):
    c = financial
    with pytest.raises(MpcBindingError), transaction.atomic():
        (release_withdrawal if action == "release" else settle_withdrawal)(c["withdrawal"])
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1


def test_never_started_pending_denial_releases_original_reserve_once(financial):
    c = financial
    WithdrawalRequest.objects.filter(pk=c["withdrawal"].pk).update(status="PENDING_APPROVAL")
    result = deny(
        "independent-admin", c["withdrawal"].pk, notes="customer cancelled before signing"
    )
    assert result.status == "DENIED" and deny("independent-admin", result.pk).status == "DENIED"
    assert user_balances(result.user_id, "SOL") == {"available": 5, "reserved": 0, "total": 5}
    assert (
        LedgerTransaction.objects.filter(event_key=f"withdrawal:{result.pk}:release").count() == 1
    )
    assert (
        AdminActionLog.objects.filter(
            action_type="WITHDRAWAL_DENY", entity_id=str(result.pk)
        ).count()
        == 1
    )


@pytest.mark.parametrize("action", ["approve", "deny"])
def test_financial_manual_decision_audit_failure_rolls_back_state_and_reserve(financial, action):
    c = financial
    WithdrawalRequest.objects.filter(pk=c["withdrawal"].pk).update(status="PENDING_APPROVAL")
    before = LedgerTransaction.objects.count()
    with patch.object(
        AdminActionLog.objects, "create", side_effect=RuntimeError("mandatory audit")
    ):
        with pytest.raises(RuntimeError, match="mandatory audit"):
            (approve if action == "approve" else deny)("independent-admin", c["withdrawal"].pk)
    c["withdrawal"].refresh_from_db()
    assert c["withdrawal"].status == "PENDING_APPROVAL"
    assert LedgerTransaction.objects.count() == before
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1


def candidate(c):
    principal = register_financial_principal(
        tenant_id=c["tenant"].pk,
        reference="legacy-candidate",
        role="CUSTOMER",
        operator_ref="operator",
    )
    claim = approve_claim(c, reserve_claim(c, retry="candidate", principal=principal))
    owner = principal.ledger_owner_id
    ensure_accounts(owner, "SOL")
    with transaction.atomic():
        accounts = lock_user_accounts(owner, "SOL")
        post_transaction(
            event_key="synthetic-candidate-funding",
            event_type="FIXTURE",
            asset_key="SOL",
            ref_type="Fixture",
            ref_id="not-chain-evidence",
            postings=[(accounts["AVAILABLE"], Decimal(5)), (clearing_account("SOL"), Decimal(-5))],
        )
        req = WithdrawalRequest.objects.create(
            user_id=owner,
            chain_id="SOL",
            asset_key="SOL",
            to_address=c["withdrawal"].to_address,
            amount=Decimal(1),
            status="APPROVED",
        )
        reserve_withdrawal(req)
    return claim, req


def begin_candidate(c, claim):
    return financial_wallet_request(
        reservation_id=claim.pk, tenant_id=c["tenant"].pk, operator_ref="operator"
    )


def test_ordinary_customer_without_financial_membership_keeps_legacy_admission(financial):
    c = financial
    _, req = candidate(c)
    assert not financial_customer(req.user_id, "SOL", "SOL")
    result = create_attempt(
        operation_type="WITHDRAWAL",
        operation_id=req.pk,
        chain_id="SOL",
        asset_key="SOL",
        source=c["root"].base_address,
        destination=req.to_address,
        amount=req.amount,
    )
    assert result.status == "PREPARING"


@pytest.mark.parametrize("history", ["preparing", "unknown", "unproved_terminal"])
def test_enrollment_refuses_unresolved_or_unproved_legacy_private_history(financial, history):
    c = financial
    claim, req = candidate(c)
    values = attempt_values(c, req)
    values["status"] = {
        "preparing": "PREPARING",
        "unknown": "RECONCILIATION_REQUIRED",
        "unproved_terminal": "CONFIRMED",
    }[history]
    OnchainTransactionAttempt.objects.create(**values)
    with pytest.raises(DatabaseError, match="resolve original legacy"):
        begin_candidate(c, claim)


def test_original_terminal_history_enrolls_but_cannot_start_new_legacy_private_work(financial):
    c = financial
    claim, req = candidate(c)
    values = attempt_values(c, req)
    # Explicit structural unit history, not accepted cryptographic/chain evidence.
    values.update(
        status="CONFIRMED",
        signed_payload="unit-history",
        network_tx_id="unit-history",
        confirmation_metadata={
            "finalized": True,
            "err": None,
            "signature": "unit-history",
            "slot": 20,
        },
    )
    attempt = OnchainTransactionAttempt.objects.create(**values)
    assert begin_candidate(c, claim)["status"] == "PENDING"
    with pytest.raises(DatabaseError, match="generic MPC"), transaction.atomic():
        MpcSigningSession.objects.create(
            attempt=attempt,
            session_id=uuid4(),
            keyset=c["root"].keyset,
            algorithm="FROST_ED25519",
            payload_type="SOLANA_MESSAGE",
            signing_payload=b"unit",
            message_fingerprint="ab" * 32,
        )
    with pytest.raises(DatabaseError, match="legacy private"), transaction.atomic():
        OnchainTransactionAttempt.objects.filter(pk=attempt.pk).update(status="SIGNING")
    OnchainTransactionAttempt.objects.filter(pk=attempt.pk).update(status="RECONCILIATION_REQUIRED")
    with patch("custody.outbound._executor") as private:
        with pytest.raises(MpcBindingError, match="typed private"):
            _execute_attempt(attempt.pk, "operator")
        private.assert_not_called()


@pytest.mark.parametrize("winner", ["membership", "legacy_attempt"])
def test_financial_enrollment_and_legacy_attempt_birth_serialize_on_asset(financial, winner):
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    from django.db import close_old_connections, connection

    from custody.models import MpcSolanaFinancialWallet
    from custody.solana_financial_wallet import _audit as actual_audit

    c = financial
    claim, req = candidate(c)
    held, proceed = threading.Event(), threading.Event()
    waiting_tag = "financial-routing-waiter-" + winner

    def named():
        close_old_connections()
        with connection.cursor() as cursor:
            cursor.execute("SET application_name=%s", [waiting_tag])

    def wait_for_database_lock():
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT wait_event_type FROM pg_stat_activity WHERE application_name=%s",
                    [waiting_tag],
                )
                if any(row[0] == "Lock" for row in cursor.fetchall()):
                    return
            time.sleep(0.02)
        raise AssertionError("second transaction never waited on the actual admission lock")

    def member_first():
        close_old_connections()

        def holding_audit(action, row, operator):
            actual_audit(action, row, operator)
            if action == "SOL_FIN_WALLET_RESERVE" and row.claim_id == claim.pk:
                held.set()
                assert proceed.wait(10)

        try:
            with patch("custody.solana_financial_wallet._audit", side_effect=holding_audit):
                return begin_candidate(c, claim)
        finally:
            close_old_connections()

    original_create = OnchainTransactionAttempt.objects.create

    def legacy_first():
        close_old_connections()

        def holding_create(**kwargs):
            result = original_create(**kwargs)
            held.set()
            assert proceed.wait(10)
            return result

        try:
            with patch.object(
                OnchainTransactionAttempt.objects, "create", side_effect=holding_create
            ):
                return create_attempt(
                    operation_type="WITHDRAWAL",
                    operation_id=req.pk,
                    chain_id="SOL",
                    asset_key="SOL",
                    source=c["root"].base_address,
                    destination=req.to_address,
                    amount=req.amount,
                )
        finally:
            close_old_connections()

    def member_waiter():
        named()
        try:
            with pytest.raises(DatabaseError, match="resolve original legacy"):
                begin_candidate(c, claim)
        finally:
            close_old_connections()

    def legacy_waiter():
        named()
        try:
            with pytest.raises(DatabaseError, match="legacy private"):
                create_attempt(
                    operation_type="WITHDRAWAL",
                    operation_id=req.pk,
                    chain_id="SOL",
                    asset_key="SOL",
                    source=c["root"].base_address,
                    destination=req.to_address,
                    amount=req.amount,
                )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(member_first if winner == "membership" else legacy_first)
        assert held.wait(10)
        second = pool.submit(legacy_waiter if winner == "membership" else member_waiter)
        try:
            wait_for_database_lock()
        finally:
            proceed.set()
        first.result(timeout=10)
        second.result(timeout=10)
    assert MpcSolanaFinancialWallet.objects.filter(claim=claim).exists() == (winner == "membership")
    assert OnchainTransactionAttempt.objects.filter(operation_id=req.pk).exists() == (
        winner == "legacy_attempt"
    )


def test_unallocated_financial_reserve_cannot_be_erased_by_extra_balanced_lines(financial):
    from custody.models import LedgerPosting

    c = financial
    journal = LedgerTransaction.objects.get(event_key=f"withdrawal:{c['withdrawal'].pk}:reserve")
    postings = list(journal.postings.all())
    with pytest.raises(DatabaseError, match="reserve posting"), transaction.atomic():
        LedgerPosting.objects.bulk_create(
            [
                LedgerPosting(transaction=journal, account_id=p.account_id, amount=-p.amount)
                for p in postings
            ]
        )
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1


@pytest.mark.parametrize("remote", ["missing", "created", "completed"])
def test_enrolled_legacy_recovery_reads_original_execution_without_create_or_execute(
    legacy_context, remote
):
    from custody.mpc_signing import advance_mpc_signing, coordinator_request

    c = legacy_context
    client = legacy_fixtures.CoordinatorClient(c)
    if remote != "missing":
        with transaction.atomic():
            client.request = coordinator_request(c.attempt, c.session)
    if remote == "completed":
        client.selected = ["signer-b", "signer-c"]
        client.complete()
    with patch("custody.solana_financial_routing.requires_typed_private", return_value=True):
        result = advance_mpc_signing(c.attempt.pk, client)
    assert client.gets == [str(c.session.session_id)]
    assert not client.creates and not client.executes
    assert result.status == (
        "SIGNED"
        if remote == "completed"
        else "RECONCILIATION_REQUIRED"
        if remote == "missing"
        else "SIGNING"
    )


@pytest.mark.parametrize(
    "change,value",
    [
        ("chain_id", "ETH"),
        ("asset_key", "OTHER"),
        ("amount", Decimal(2)),
        ("base_unit_amount", 2 * 10**9),
        ("to_address", "different-destination"),
    ],
)
def test_cutover_does_not_bless_wrong_family_or_mismatched_linked_history(financial, change, value):
    c = financial
    claim, req = candidate(c)
    values = attempt_values(c, req)
    values.update(
        status="CONFIRMED",
        signed_payload="unit-history",
        network_tx_id="unit-history",
        confirmation_metadata={
            "finalized": True,
            "err": None,
            "signature": "unit-history",
            "slot": 20,
        },
    )
    values[change] = value
    OnchainTransactionAttempt.objects.create(**values)
    with pytest.raises(DatabaseError, match="resolve original legacy"):
        begin_candidate(c, claim)


@pytest.mark.parametrize("release", [False, True])
def test_terminal_strings_without_original_mpc_completion_cannot_mutate_hold(financial, release):
    c = financial
    claim, req = candidate(c)
    values = attempt_values(c, req)
    values.update(
        status="FAILED" if release else "CONFIRMED",
        signed_payload="not-a-signed-wire",
        network_tx_id="not-a-signature",
        confirmation_metadata={
            "finalized": True,
            "err": {"InstructionError": [0, "Custom"]} if release else None,
            "signature": "not-a-signature",
            "slot": 20,
        },
    )
    OnchainTransactionAttempt.objects.create(**values)
    begin_candidate(c, claim)  # SQL history checks are structural, not cryptographic.
    before = LedgerTransaction.objects.count()
    with pytest.raises(MpcBindingError, match="captured legacy MPC"), transaction.atomic():
        (release_withdrawal if release else settle_withdrawal)(req)
    assert LedgerTransaction.objects.count() == before
    assert user_balances(req.user_id, "SOL")["reserved"] == 1
