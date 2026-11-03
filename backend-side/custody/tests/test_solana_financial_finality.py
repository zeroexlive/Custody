"""Real PG and canonical unit-fixture signed wire, never genuine MPC acceptance."""

import base64
import copy
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

import pytest
from django.db import DatabaseError, close_old_connections, connection, transaction
from django.utils import timezone
from solders.transaction import Transaction

from custody.ledger import user_balances
from custody.models import (
    AdminActionLog,
    LedgerPosting,
    LedgerTransaction,
    MpcSolanaFinancialEffect,
    MpcSolanaSignatureOwner,
)
from custody.mpc_binding import MpcBindingError
from custody.native_tx import ReconciliationState
from custody.solana_financial_finality import observe_finality
from custody.solana_financial_outbound import broadcast_session, reconcile_finality
from custody.solana_financial_preparation import _effect_slot
from custody.tests import test_solana_financial_signing as fixtures
from custody.tests.test_solana_financial_sessions import no_signature, operation, query, session
from custody.tests.test_solana_financial_signing import completed
from custody.tests.test_solana_issuance import signed

pytestmark = pytest.mark.django_db(transaction=True)
clean_mode = fixtures.clean_mode
context = fixtures.context
financial = fixtures.financial
preparation = fixtures.preparation
signer_receipt_trust = fixtures.signer_receipt_trust
signing = fixtures.signing


def finalized(row, *, failed=False):
    tx = Transaction.from_bytes(bytes.fromhex(row.attempt.signed_payload))
    keys = [str(k) for k in tx.message.account_keys]
    before = [10_000_000_000] * len(keys)
    after = before.copy()
    after[0] -= row.intent["expected_fee_lamports"]
    if not failed:
        after[keys.index(row.intent["financial_source"])] -= int(row.operation.base_unit_amount)
        after[keys.index(row.operation.destination_address)] += int(row.operation.base_unit_amount)
    error = {"InstructionError": [0, "Custom"]} if failed else None
    meta = {
        "preBalances": before,
        "postBalances": after,
        "fee": row.intent["expected_fee_lamports"],
        "err": error,
    }
    response = {
        "transaction": [base64.b64encode(bytes(tx)).decode(), "base64"],
        "slot": 20,
        "meta": meta,
        "version": "legacy",
    }
    status = {"confirmationStatus": "finalized", "slot": 20, "err": error}
    return tx, meta, response, status


def rpc_finality(c, response, status):
    original = c["rpc"].rpc

    def rpc(url, method, params):
        if method == "getSignatureStatuses":
            return {"value": [status]}
        if method == "getTransaction":
            return response
        return original(url, method, params)

    c["rpc"].rpc = rpc


@pytest.mark.parametrize("failed", [False, True])
def test_original_finalized_effect_posts_fee_and_settles_or_releases_once(signing, failed):
    c = signing
    row = completed(c)
    _, _, response, status = finalized(row, failed=failed)
    rpc_finality(c, response, status)
    before = LedgerTransaction.objects.count()
    with patch("custody.solana_financial_outbound._runtime"):
        args = dict(
            session_id=row.pk, tenant_id=c["tenant"].pk, operator_ref="operator", transport=c["rpc"]
        )
        result = reconcile_finality(**args)
        assert reconcile_finality(**args).status == result.status
    row.operation.refresh_from_db()
    c["withdrawal"].refresh_from_db()
    assert result.status == ("FAILED" if failed else "CONFIRMED")
    assert row.operation.status == ("RELEASED" if failed else "SETTLED")
    assert c["withdrawal"].status == result.status
    balances = user_balances(c["withdrawal"].user_id, "SOL")
    assert balances["reserved"] == 0 and balances["available"] == (5 if failed else 4)
    assert LedgerTransaction.objects.count() == before + 2
    fee = LedgerTransaction.objects.get(event_key=f"solana:{result.pk}:network_fee")
    assert sorted(fee.postings.values_list("amount", flat=True)) == [
        Decimal("-0.000005"),
        Decimal("0.000005"),
    ]
    assert MpcSolanaFinancialEffect.objects.get(attempt=result).slot == 20
    assert _effect_slot(row.operation.source.claim.root_id) == 20
    with pytest.raises(DatabaseError, match="terminal attempt"), transaction.atomic():
        type(result).objects.filter(pk=result.pk).update(status="SIGNED")
    posting = fee.postings.first()
    with pytest.raises(DatabaseError, match="append-only"), transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE custody_ledgerposting SET amount=amount*2 WHERE id=%s", [posting.pk]
            )
    with pytest.raises(DatabaseError, match="posting set"), transaction.atomic():
        LedgerPosting.objects.create(transaction=fee, account_id=posting.account_id, amount=1)


@pytest.mark.parametrize(
    "fault",
    ["principal", "fee_source", "fee", "rollback", "inner", "token", "slot", "wire", "error"],
)
def test_conflicting_finalized_rpc_never_releases_original_reserve(signing, fault):
    c = signing
    row = completed(c)
    _, meta, response, status = finalized(row, failed=fault == "rollback")
    keys = [
        str(k)
        for k in Transaction.from_bytes(
            bytes.fromhex(row.attempt.signed_payload)
        ).message.account_keys
    ]
    if fault in {"principal", "rollback"}:
        meta["postBalances"][keys.index(row.intent["financial_source"])] -= 1
    elif fault == "fee_source":
        meta["postBalances"][0] += meta["fee"]
        meta["postBalances"][keys.index(row.intent["financial_source"])] -= meta["fee"]
    elif fault == "fee":
        meta["fee"] += 1
    elif fault == "inner":
        meta["innerInstructions"] = [{"index": 0, "instructions": []}]
    elif fault == "token":
        meta["postTokenBalances"] = [{"accountIndex": 1}]
    elif fault == "slot":
        response["slot"] += 1
    elif fault == "wire":
        response["transaction"][0] = base64.b64encode(b"wrong wire").decode()
    else:
        meta["err"] = status["err"] = True
    rpc_finality(c, response, status)
    before = LedgerTransaction.objects.count()
    with patch("custody.solana_financial_outbound._runtime"):
        result = reconcile_finality(
            session_id=row.pk, tenant_id=c["tenant"].pk, operator_ref="operator", transport=c["rpc"]
        )
    assert result.status == "RECONCILIATION_REQUIRED"
    assert (
        LedgerTransaction.objects.count() == before
        and not MpcSolanaFinancialEffect.objects.exists()
    )
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1


def test_finality_audit_failure_rolls_back_effect_costs_settlement_and_original_hold(signing):
    c = signing
    row = completed(c)
    _, _, response, status = finalized(row)
    rpc_finality(c, response, status)
    before = LedgerTransaction.objects.count()
    with (
        patch("custody.solana_financial_outbound._runtime"),
        patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit")),
    ):
        with pytest.raises(RuntimeError, match="audit"):
            reconcile_finality(
                session_id=row.pk,
                tenant_id=c["tenant"].pk,
                operator_ref="operator",
                transport=c["rpc"],
            )
    row.operation.refresh_from_db()
    assert row.operation.status == "HELD" and not MpcSolanaFinancialEffect.objects.exists()
    assert LedgerTransaction.objects.count() == before
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1


def test_missing_transaction_after_finalized_status_is_unknown_not_failure(signing):
    c = signing
    row = completed(c)
    _, _, _, status = finalized(row)
    rpc_finality(c, None, status)
    result = observe_finality(row, c["rpc"])
    assert result.state is ReconciliationState.RECONCILIATION_REQUIRED
    assert result.evidence["non_inclusion_proven"] is False


def test_direct_terminal_attempt_without_effect_is_rejected_at_commit(signing):
    row = completed(signing)
    with pytest.raises(DatabaseError, match="requires finalized effect"), transaction.atomic():
        type(row.attempt).objects.filter(pk=row.attempt_id).update(status="CONFIRMED")


def test_local_no_signature_allows_retry_but_cannot_release_business_hold(financial):
    c = financial
    row = session(c)
    assert no_signature(c, row, query(c, row)).status == "NO_SIGNATURE"
    with pytest.raises(DatabaseError), transaction.atomic():
        type(row.operation).objects.filter(pk=row.operation_id).update(status="RELEASED")
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1


def test_extra_balanced_postings_cannot_erase_original_protected_reserve(financial):
    c = financial
    operation(c)
    journal = LedgerTransaction.objects.get(event_key=f"withdrawal:{c['withdrawal'].pk}:reserve")
    postings = list(journal.postings.all())
    with pytest.raises(DatabaseError, match="posting set"), transaction.atomic():
        LedgerPosting.objects.bulk_create(
            [
                LedgerPosting(transaction=journal, account_id=p.account_id, amount=-p.amount)
                for p in postings
            ]
        )
    assert journal.postings.count() == 2
    balances = user_balances(c["withdrawal"].user_id, "SOL")
    assert balances["available"] == 4 and balances["reserved"] == 1


def completion_reply(c, row, query):
    original = MpcSolanaSignatureOwner.objects.get(session=row).evidence
    value = copy.deepcopy(original["value"])
    value["query"] = query
    return signed(c, original["key_id"], value)


@pytest.mark.parametrize("fault", ["none", "lost_ack", "changed_fee", "audit", "delayed_genesis"])
def test_first_broadcast_commits_original_bytes_before_io_and_never_resends_ambiguity(
    signing, fault
):
    c = signing
    row = completed(c)
    original = c["rpc"].rpc
    sent = []
    clock_expired = False
    actual_now = timezone.now

    def rpc(url, method, params):
        nonlocal clock_expired
        if method == "getGenesisHash" and fault == "delayed_genesis":
            row.attempt.refresh_from_db()
            if row.attempt.status == "BROADCASTING":
                clock_expired = True
        if method == "getFeeForMessage" and fault == "changed_fee":
            return {"value": 5001}
        if method == "sendTransaction":
            row.attempt.refresh_from_db()
            assert row.attempt.status == "BROADCASTING"
            assert base64.b64decode(params[0]).hex() == row.attempt.signed_payload
            sent.append(params)
            if fault == "lost_ack":
                raise TimeoutError("lost ack")
            return row.attempt.network_tx_id
        return original(url, method, params)

    c["rpc"].rpc = rpc
    audit = AdminActionLog.objects.create

    def audit_guard(**kwargs):
        if fault == "audit" and kwargs["action_type"] == "SOL_FIN_BROADCAST_BEGIN":
            raise RuntimeError("broadcast audit")
        return audit(**kwargs)

    args = dict(
        session_id=row.pk, tenant_id=c["tenant"].pk, operator_ref="operator", transport=c["rpc"]
    )
    before = LedgerTransaction.objects.count()
    with (
        patch("custody.solana_financial_outbound._runtime"),
        patch(
            "custody.solana_financial_outbound.query_witness",
            side_effect=lambda q: completion_reply(c, row, q),
        ),
        patch.object(AdminActionLog.objects, "create", side_effect=audit_guard),
        patch(
            "custody.solana_financial_outbound.timezone.now",
            side_effect=lambda: (
                actual_now() + (timedelta(minutes=10) if clock_expired else timedelta(0))
            ),
        ),
    ):
        if fault == "changed_fee":
            with pytest.raises(MpcBindingError, match="fee differs"):
                broadcast_session(**args)
        elif fault == "audit":
            with pytest.raises(RuntimeError, match="broadcast audit"):
                broadcast_session(**args)
        elif fault == "lost_ack":
            with pytest.raises(TimeoutError):
                broadcast_session(**args)
            assert broadcast_session(**args).status == "RECONCILIATION_REQUIRED"
        elif fault == "delayed_genesis":
            with pytest.raises(MpcBindingError, match="expired after commit/genesis"):
                broadcast_session(**args)
            assert broadcast_session(**args).status == "RECONCILIATION_REQUIRED"
        else:
            assert broadcast_session(**args).status == "BROADCASTED"
            assert broadcast_session(**args).status == "BROADCASTED"
    assert len(sent) == (1 if fault in {"none", "lost_ack"} else 0)
    assert LedgerTransaction.objects.count() == before
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
@pytest.mark.parametrize("mutation", ["header", "posting", "append"])
def test_old_snapshot_cannot_hide_new_protection_from_journal_mutation(
    financial, isolation, mutation
):
    c = financial
    journal = LedgerTransaction.objects.get(event_key=f"withdrawal:{c['withdrawal'].pk}:reserve")
    posting = journal.postings.first()
    observed, proceed = threading.Event(), threading.Event()

    def stale():
        close_old_connections()
        try:
            with pytest.raises(DatabaseError, match="READ COMMITTED"), transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute("SET TRANSACTION ISOLATION LEVEL " + isolation)
                    cursor.execute(
                        "SELECT id FROM custody_ledgertransaction WHERE id=%s", [journal.pk]
                    )
                    assert cursor.fetchone() == (journal.pk,)
                    observed.set()
                    assert proceed.wait(10)
                    if mutation == "header":
                        cursor.execute(
                            "UPDATE custody_ledgertransaction SET metadata='{}'::jsonb WHERE id=%s",
                            [journal.pk],
                        )
                    elif mutation == "posting":
                        cursor.execute(
                            "UPDATE custody_ledgerposting SET amount=amount*2 WHERE id=%s",
                            [posting.pk],
                        )
                    else:
                        LedgerPosting.objects.create(
                            transaction=journal, account_id=posting.account_id, amount=1
                        )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(stale)
        assert observed.wait(10)
        try:
            operation(c)
        finally:
            proceed.set()
        future.result(timeout=10)
    assert journal.postings.count() == 2
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1


@pytest.mark.parametrize("fault", ["postings", "fee", "parent_hash"])
def test_settlement_rejects_wrong_postings_and_preserves_original_hold(signing, fault):
    c = signing
    row = completed(c)
    _, _, response, status = finalized(row)
    rpc_finality(c, response, status)
    from custody.solana_financial_outbound import post_transaction as actual_post

    def wrong(**kwargs):
        kwargs["postings"] = [(account, amount * 2) for account, amount in kwargs["postings"]]
        return actual_post(**kwargs)

    def wrong_parent(parent, row, status):
        parent.status, parent.tx_hash = status, "wrong original hash"
        parent.save(update_fields=["status", "tx_hash"])

    target = (
        "custody.solana_financial_outbound.post_transaction"
        if fault == "postings"
        else "custody.solana_costs.post_transaction"
        if fault == "fee"
        else "custody.solana_financial_outbound._parent"
    )

    with (
        patch("custody.solana_financial_outbound._runtime"),
        patch(target, side_effect=wrong_parent if fault == "parent_hash" else wrong),
    ):
        with pytest.raises(DatabaseError):
            reconcile_finality(
                session_id=row.pk,
                tenant_id=c["tenant"].pk,
                operator_ref="operator",
                transport=c["rpc"],
            )
    assert not MpcSolanaFinancialEffect.objects.exists()
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1


@pytest.mark.parametrize("journal_kind", ["settlement", "fee"])
@pytest.mark.parametrize("side", [0, 1])
def test_two_identical_debits_or_credits_do_not_satisfy_exact_pair(signing, journal_kind, side):
    c = signing
    row = completed(c)
    _, _, response, status = finalized(row)
    rpc_finality(c, response, status)

    def duplicate(**kwargs):
        postings = kwargs.pop("postings")
        account, amount = postings[side]
        journal = LedgerTransaction.objects.create(**kwargs)
        LedgerPosting.objects.bulk_create(
            [
                LedgerPosting(transaction=journal, account=account, amount=amount),
                LedgerPosting(transaction=journal, account=account, amount=amount),
            ]
        )
        return journal, True

    target = (
        "custody.solana_costs.post_transaction"
        if journal_kind == "fee"
        else "custody.solana_financial_outbound.post_transaction"
    )
    with patch("custody.solana_financial_outbound._runtime"), patch(target, side_effect=duplicate):
        with pytest.raises(DatabaseError):
            reconcile_finality(
                session_id=row.pk,
                tenant_id=c["tenant"].pk,
                operator_ref="operator",
                transport=c["rpc"],
            )
    assert not MpcSolanaFinancialEffect.objects.exists()
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1


def test_finalized_outgoing_to_newly_known_custody_address_keeps_business_held(signing):
    c = signing
    row = completed(c)
    _, _, response, status = finalized(row)
    rpc_finality(c, response, status)
    with (
        patch("custody.solana_financial_outbound._runtime"),
        patch(
            "custody.solana_financial_outbound._external_destination",
            side_effect=MpcBindingError("custody address"),
        ),
    ):
        result = reconcile_finality(
            session_id=row.pk, tenant_id=c["tenant"].pk, operator_ref="operator", transport=c["rpc"]
        )
    assert (
        result.status == "RECONCILIATION_REQUIRED"
        and result.error_code == "DESTINATION_BECAME_CUSTODY"
    )
    row.operation.refresh_from_db()
    assert row.operation.status == "HELD"
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1
    assert (
        MpcSolanaFinancialEffect.objects.get(attempt=result).slot
        == _effect_slot(row.operation.source.claim.root_id)
        == 20
    )
    assert not LedgerTransaction.objects.filter(
        event_key=f"withdrawal:{c['withdrawal'].pk}:settle"
    ).exists()
