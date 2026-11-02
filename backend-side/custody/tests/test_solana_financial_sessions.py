"""Real PG transactions, synthetic public receipts/ledger funding; not MPC acceptance."""

import base64
import copy
import hashlib
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from decimal import Decimal
from importlib import import_module
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.db import DatabaseError, close_old_connections, connection, transaction
from django.utils import timezone
from ops.models import Chain
from solders.pubkey import Pubkey

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
    MpcKeyset,
    MpcSigningSession,
    MpcSolanaFinancialOperation,
    MpcSolanaFinancialQuery,
    MpcSolanaFinancialSession,
    MpcSolanaMessageOwner,
    OnchainTransactionAttempt,
    SweepJob,
    WithdrawalRequest,
)
from custody.mpc_binding import MpcBindingError
from custody.outbound import _execute_attempt, create_attempt
from custody.reconciliation import _reconcile_attempt
from custody.solana_financial_sessions import (
    allocate_session,
    allocate_sweep,
    allocate_withdrawal,
    complete_no_signature,
    request_query,
)
from custody.tests.test_solana_financial_root import (
    begin as begin_mode,
)
from custody.tests.test_solana_financial_root import (
    clean_mode as clean_mode_fixture,
)
from custody.tests.test_solana_financial_root import (
    complete as complete_mode,
)
from custody.tests.test_solana_financial_root import (
    context as context_fixture,
)
from custody.tests.test_solana_financial_root import (
    signed as signed_mode,
)
from custody.tests.test_solana_financial_root import (
    signer_receipt_trust as signer_receipt_trust_fixture,
)
from custody.tests.test_solana_financial_wallet import begin, complete, reply
from custody.tests.test_solana_issuance import signed
from custody.tests.test_solana_provisioning import approve, reserve

pytestmark = pytest.mark.django_db(transaction=True)
context = context_fixture
clean_mode = clean_mode_fixture
signer_receipt_trust = signer_receipt_trust_fixture


@pytest.fixture
def financial(clean_mode):
    c = clean_mode
    Chain.objects.filter(chain_id="SOL").update(gas_settings={"max_fee_lamports": "20000"})
    c["mode"] = complete_mode(c, signed_mode(c, begin_mode(c)))
    with (
        patch("custody.solana_financial_wallet._runtime"),
        patch("custody.solana_issuance._runtime"),
        patch("custody.solana_financial_sessions._runtime"),
    ):
        for role in ["CUSTOMER", "TREASURY"]:
            c["principal"] = register_financial_principal(
                tenant_id=c["tenant"].pk,
                reference="session-" + role,
                role=role,
                operator_ref="operator",
            )
            c["claim"] = approve(c, reserve(c, retry=role, principal=c["principal"]))
            request = begin(c)
            proof = reply(c, request)
            proof["value"]["root"]["next_claim_index"] = c["claim"].index + 1
            row = complete(c, signed(c, proof["key_id"], proof["value"]))
            c[role] = row
        customer = c["CUSTOMER"].claim.principal
        ensure_accounts(customer.ledger_owner_id, "SOL")
        with transaction.atomic():
            accounts = lock_user_accounts(customer.ledger_owner_id, "SOL")
            post_transaction(
                event_key="synthetic-unit-funding",
                event_type="FIXTURE",
                asset_key="SOL",
                ref_type="Fixture",
                ref_id="not-a-real-deposit",
                postings=[
                    (accounts["AVAILABLE"], Decimal(5)),
                    (clearing_account("SOL"), Decimal(-5)),
                ],
            )
            withdrawal = WithdrawalRequest.objects.create(
                user_id=customer.ledger_owner_id,
                chain_id="SOL",
                asset_key="SOL",
                to_address=str(Pubkey.from_bytes(bytes([59]) * 32)),
                amount=Decimal(1),
                status="APPROVED",
            )
            reserve_withdrawal(withdrawal)
        c["withdrawal"] = withdrawal
        yield c


def operation(c, **kwargs):
    return allocate_withdrawal(
        **{
            "withdrawal_id": c["withdrawal"].pk,
            "source_id": c["TREASURY"].pk,
            "tenant_id": c["tenant"].pk,
            "fee_budget_lamports": 20_000,
            "operator_ref": "operator",
            **kwargs,
        }
    )


def session(c, op=None, **kwargs):
    op = op or operation(c)
    return allocate_session(
        **{
            "reservation_id": op.pk,
            "tenant_id": c["tenant"].pk,
            "selected_signers": ["signer-a", "signer-b"],
            "operator_ref": "operator",
            **kwargs,
        }
    )


def query(c, row, purpose="TERMINAL"):
    return request_query(
        session_id=row.pk, tenant_id=c["tenant"].pk, purpose=purpose, operator_ref="operator"
    )


def terminal(c, row, request, **overrides):
    value = copy.deepcopy(c["TREASURY"].evidence["value"])
    value.update(
        query=copy.deepcopy(request["query"]),
        execution=None,
        abandoned=True,
        sequence=12,
        claim=c["TREASURY"].claim.evidence,
        **overrides,
    )
    return signed(c, c["TREASURY"].issuance.witness_key_id, value)


def no_signature(c, row, request, evidence=None):
    return complete_no_signature(
        session_id=row.pk,
        tenant_id=c["tenant"].pk,
        challenge=request["query"]["challenge"],
        evidence=evidence or terminal(c, row, request),
        operator_ref="operator",
    )


def legacy_request(c):
    """Ordinary declared customer with no seeded financial membership/history."""
    principal = register_financial_principal(
        tenant_id=c["tenant"].pk,
        reference="ordinary-legacy-customer",
        role="CUSTOMER",
        operator_ref="operator",
    )
    owner = principal.ledger_owner_id
    ensure_accounts(owner, "SOL")
    with transaction.atomic():
        accounts = lock_user_accounts(owner, "SOL")
        post_transaction(
            event_key="synthetic-legacy-funding",
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
    return req


def test_allocation_commits_ids_and_reuses_one_original_ledger_hold(financial):
    c = financial
    before = LedgerTransaction.objects.count()
    op = operation(c)
    assert operation(c).pk == op.pk
    row = session(c, op)
    assert session(c, op).pk == row.pk
    assert row.pk != row.crypto_execution_id and row.attempt.status == "PREPARING"
    assert row.operation.approval_id == op.approval_id
    assert LedgerTransaction.objects.count() == before
    assert user_balances(op.principal.ledger_owner_id, "SOL")["reserved"] == 1
    assert not row.intent and bytes(row.payload) == b""


def test_no_signature_only_permits_new_crypto_attempt_not_business_release(financial):
    c = financial
    op = operation(c)
    first = session(c, op)
    request = query(c, first)
    assert request["lifecycle_action"] == {
        "kind": "CloseNoSignature",
        "execution_id": str(first.crypto_execution_id),
    }
    assert no_signature(c, first, request).status == "NO_SIGNATURE"
    assert no_signature(c, first, request).pk == first.pk
    second = session(c, op, selected_signers=["signer-a", "signer-c"])
    assert second.pk != first.pk and second.crypto_execution_id != first.crypto_execution_id
    assert second.attempt.attempt_number == 2 and second.operation_id == first.operation_id
    assert second.operation.approval_id == op.approval_id
    assert (
        LedgerTransaction.objects.filter(
            event_key=f"withdrawal:{c['withdrawal'].pk}:reserve"
        ).count()
        == 1
    )
    assert user_balances(op.principal.ledger_owner_id, "SOL")["reserved"] == 1


@pytest.mark.parametrize(
    "change",
    ["signature", "challenge", "root", "claim", "open", "signed", "absent", "key", "sequence"],
)
def test_invalid_or_nonterminal_reply_preserves_session_and_reserve(financial, change):
    c = financial
    row = session(c)
    request = query(c, row)
    proof = terminal(c, row, request)
    value = proof["value"]
    if change == "challenge":
        value["query"]["challenge"] = "fa" * 32
    elif change == "root":
        value["root"]["original"]["ownership_scope"] = str(uuid4())
    elif change == "claim":
        value["claim"]["statement"]["owner_ref"] = "p1:" + str(uuid4())
    elif change == "open":
        value.update(abandoned=False, execution={"status": "Open", "signature": None})
    elif change == "signed":
        value.update(abandoned=False, execution={"status": "SignedPending", "signature": "ab" * 64})
    elif change == "absent":
        value.update(abandoned=False, execution=None)
    elif change == "sequence":
        value["sequence"] = True
    proof = signed(c, proof["key_id"], value)
    if change == "signature":
        proof["signature"] = "00" * 64
    if change == "key":
        proof["key_id"] = "aa" * 32
    with pytest.raises(MpcBindingError):
        no_signature(c, row, request, proof)
    row.refresh_from_db()
    assert row.status == "ALLOCATED" and not row.no_signature_evidence
    assert MpcSolanaFinancialQuery.objects.get(pk=request["query"]["challenge"]).status == "PENDING"
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1


@pytest.mark.parametrize(
    "target,values",
    [
        ("operation", {"destination_address": str(Pubkey.from_bytes(bytes([60]) * 32))}),
        ("operation", {"fee_budget_lamports": 100}),
        ("operation", {"status": "RELEASED"}),
        ("parent", {"amount": Decimal(2)}),
        ("parent", {"to_address": str(Pubkey.from_bytes(bytes([60]) * 32))}),
        ("parent", {"status": "FAILED"}),
        ("session", {"crypto_execution_id": uuid4()}),
        ("session", {"selected_signers": ["signer-a", "signer-c"]}),
        ("session", {"status": "NO_SIGNATURE"}),
        ("attempt", {"from_address": str(Pubkey.from_bytes(bytes([60]) * 32))}),
        ("attempt", {"amount": Decimal(2)}),
    ],
)
def test_bulk_sql_cannot_replace_identity_or_infer_terminal_authority(financial, target, values):
    c = financial
    row = session(c)
    models = {
        "operation": row.operation,
        "parent": c["withdrawal"],
        "session": row,
        "attempt": row.attempt,
    }
    obj = models[target]
    with pytest.raises(DatabaseError), transaction.atomic():
        type(obj).objects.filter(pk=obj.pk).update(**values)


@pytest.mark.parametrize("action", ["create", "execute", "reconcile", "release", "settle"])
def test_generic_paths_cannot_consume_protected_finances(financial, action):
    c = financial
    row = session(c)
    before = LedgerTransaction.objects.count()
    with pytest.raises(MpcBindingError, match="typed proof"):
        if action == "create":
            create_attempt(
                operation_type="WITHDRAWAL",
                operation_id=c["withdrawal"].pk,
                chain_id="SOL",
                asset_key="SOL",
                source=row.attempt.from_address,
                destination=row.attempt.to_address,
                amount=Decimal(1),
            )
        elif action == "execute":
            _execute_attempt(row.attempt_id, "operator")
        elif action == "reconcile":
            _reconcile_attempt(row.attempt_id)
        elif action == "release":
            release_withdrawal(c["withdrawal"])
        else:
            settle_withdrawal(c["withdrawal"])
    assert LedgerTransaction.objects.count() == before


def test_raw_failed_attempt_does_not_allow_retry(financial):
    c = financial
    first = session(c)
    with pytest.raises(DatabaseError, match="requires finalized effect"), transaction.atomic():
        OnchainTransactionAttempt.objects.filter(pk=first.attempt_id).update(status="FAILED")
    assert session(c).pk == first.pk
    with pytest.raises(MpcBindingError, match="pair"):
        session(c, selected_signers=["signer-a", "signer-c"])
    assert OnchainTransactionAttempt.objects.count() == 1


def test_append_only_query_nonce_and_deadline_and_wrong_purpose(financial):
    c = financial
    row = session(c)
    first, second = query(c, row), query(c, row)
    assert first["query"]["challenge"] != second["query"]["challenge"]
    lease = MpcSolanaFinancialQuery.objects.get(pk=first["query"]["challenge"])
    with pytest.raises(DatabaseError), transaction.atomic():
        MpcSolanaFinancialQuery.objects.filter(pk=lease.pk).update(
            expires_at=timezone.now() + timedelta(seconds=15)
        )
    wrong = query(c, row, "RECOVERY")
    with pytest.raises(MpcSolanaFinancialQuery.DoesNotExist):
        no_signature(c, row, wrong)


def test_terminal_audit_failure_rolls_back_proof_and_session(financial):
    c = financial
    row = session(c)
    request = query(c, row)
    with patch.object(
        AdminActionLog.objects, "create", side_effect=RuntimeError("audit unavailable")
    ):
        with pytest.raises(RuntimeError, match="audit unavailable"):
            no_signature(c, row, request)
    row.refresh_from_db()
    assert row.status == "ALLOCATED"
    assert MpcSolanaFinancialQuery.objects.get(pk=request["query"]["challenge"]).status == "PENDING"
    assert no_signature(c, row, request).status == "NO_SIGNATURE"


def test_concurrent_allocation_has_one_attempt_and_session(financial):
    c = financial
    op = operation(c)

    def allocate():
        close_old_connections()
        try:
            return session(c, op).pk
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: allocate(), range(2)))
    assert results[0] == results[1]
    assert MpcSolanaFinancialSession.objects.count() == 1
    assert OnchainTransactionAttempt.objects.count() == 1


def test_sweep_has_explicit_treasury_and_never_creates_customer_reserve(financial):
    c = financial
    sweep = SweepJob.objects.create(
        user_wallet=c["CUSTOMER"].user_wallet,
        asset_key="SOL",
        balance_snapshot=Decimal(1),
        idempotency_key="synthetic-sweep",
    )
    before = LedgerTransaction.objects.count()
    kwargs = {
        "sweep_id": sweep.pk,
        "destination_id": c["TREASURY"].pk,
        "tenant_id": c["tenant"].pk,
        "fee_budget_lamports": 20_000,
        "operator_ref": "operator",
    }
    op = allocate_sweep(**kwargs)
    assert allocate_sweep(**kwargs).pk == op.pk
    assert session(c, op).attempt.operation_type == "SWEEP"
    assert LedgerTransaction.objects.count() == before
    with pytest.raises(DatabaseError), transaction.atomic():
        SweepJob.objects.filter(pk=sweep.pk).update(balance_snapshot=Decimal(2))


def frozen(c, row, payload=b"synthetic-structural-wire"):
    intent = {
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 120,
        "version": "solana_seeded_intent_v1",
        "session_id": str(row.pk),
        "crypto_execution_id": str(row.crypto_execution_id),
        "attempt_id": row.attempt_id,
        "operation_id": row.attempt.operation_id,
        "operation_type": "WITHDRAWAL",
        "claim": c["TREASURY"].claim.statement,
        "financial_source": row.attempt.from_address,
        "fee_payer": c["root"].base_address,
        "financial": {
            "version": 1,
            "reservation_id": str(row.operation_id),
            "approval_id": str(row.operation.approval_id),
            "tenant_id": str(c["tenant"].pk),
            "reservation_owner_ref": row.operation.principal.ledger_owner_id,
            "source_owner_ref": c["TREASURY"].claim.principal.ledger_owner_id,
            "source_role": "TENANT_TREASURY",
            "operation_type": "WITHDRAWAL",
            "operation_id": row.attempt.operation_id,
            "asset_key": "SOL",
        },
        "asset_key": "SOL",
        "action": {
            "kind": "NativeTransfer",
            "destination": row.attempt.to_address,
            "amount": 10**9,
        },
        "rent_payer": None,
        "expected_rent_lamports": 0,
        "expected_fee_lamports": 5000,
        "message_fingerprint": hashlib.sha256(payload).hexdigest(),
    }
    OnchainTransactionAttempt.objects.filter(pk=row.attempt_id).update(
        prepared_metadata={"message": base64.b64encode(payload).decode()}
    )
    MpcSolanaFinancialSession.objects.filter(pk=row.pk).update(
        status="WAITING_POLICY",
        intent=intent,
        payload=payload,
        custody_authorization={"synthetic": "not-cryptographic-acceptance"},
    )
    return intent


def test_message_owner_must_commit_before_private_work_and_is_permanent(financial):
    c = financial
    row = session(c)
    with pytest.raises(DatabaseError, match="message ownership"), transaction.atomic():
        frozen(c, row)
    with transaction.atomic():
        intent = frozen(c, row)
        owner = MpcSolanaMessageOwner.objects.create(
            operation=row.operation,
            first_session=row,
            genesis_hash=c["root"].statement["genesis_hash"],
            message_fingerprint=intent["message_fingerprint"],
        )
    with pytest.raises(DatabaseError, match="permanent"), transaction.atomic():
        MpcSolanaMessageOwner.objects.filter(pk=owner.pk).delete()
    with pytest.raises(DatabaseError), transaction.atomic():
        OnchainTransactionAttempt.objects.filter(pk=row.attempt_id).update(
            prepared_metadata={"message": "different"}
        )


def test_populated_schema_cannot_downgrade(financial):
    operation(financial)
    migration = import_module("custody.migrations.0039_solana_financial_sessions")
    with pytest.raises(DatabaseError, match="cannot be downgraded"), transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(migration.REVERSE, params=None)


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
def test_old_snapshot_cannot_hide_new_financial_parent_protection(financial, isolation):
    c = financial
    observed, proceed = threading.Event(), threading.Event()

    def stale_writer():
        close_old_connections()
        try:
            with pytest.raises(DatabaseError, match="READ COMMITTED"), transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute("SET TRANSACTION ISOLATION LEVEL " + isolation)
                assert WithdrawalRequest.objects.get(pk=c["withdrawal"].pk).amount == 1
                observed.set()
                assert proceed.wait(10)
                WithdrawalRequest.objects.filter(pk=c["withdrawal"].pk).update(amount=Decimal(2))
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(stale_writer)
        assert observed.wait(10)
        try:
            op = operation(c)
        finally:
            proceed.set()
        future.result(timeout=10)
    c["withdrawal"].refresh_from_db()
    assert c["withdrawal"].amount == op.amount == 1


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
def test_non_read_committed_legacy_solana_attempt_and_session_fail_closed(financial, isolation):
    c = financial
    # An enrolled customer now correctly cannot start ANY generic attempt.
    # Keep this separate isolation regression on an ordinary legacy customer.
    req = legacy_request(c)
    attempt = OnchainTransactionAttempt.objects.create(
        operation_type="WITHDRAWAL",
        operation_id=req.pk,
        chain_id="SOL",
        asset_key="SOL",
        from_address=c["TREASURY"].claim.address,
        to_address=req.to_address,
        amount=req.amount,
        base_unit_amount=10**9,
    )
    for action in ["attempt", "session", "ledger"]:
        with (
            pytest.raises((DatabaseError, MpcBindingError), match="READ COMMITTED"),
            transaction.atomic(),
        ):
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL " + isolation)
            if action == "attempt":
                OnchainTransactionAttempt.objects.filter(pk=attempt.pk).update(amount=Decimal(2))
            elif action == "session":
                MpcSigningSession.objects.create(
                    attempt=attempt,
                    session_id=uuid4(),
                    keyset=c["keyset"],
                    algorithm="FROST_ED25519",
                    message_fingerprint="aa" * 32,
                    payload_type="SOLANA",
                    signing_payload=b"x",
                )
            else:
                release_withdrawal(req)


@pytest.mark.parametrize("action", ["release", "settle"])
def test_legacy_worker_that_passed_initial_absence_cannot_post_after_allocation(financial, action):
    c = financial
    checked, proceed = threading.Event(), threading.Event()
    original = lock_user_accounts

    def delayed_accounts(*args):
        checked.set()
        assert proceed.wait(10)
        return original(*args)

    def legacy_worker():
        close_old_connections()
        try:
            with patch("custody.ledger.lock_user_accounts", side_effect=delayed_accounts):
                with pytest.raises(MpcBindingError, match="typed proof"), transaction.atomic():
                    (release_withdrawal if action == "release" else settle_withdrawal)(
                        c["withdrawal"]
                    )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(legacy_worker)
        assert checked.wait(10)
        try:
            op = operation(c)
        finally:
            proceed.set()
        future.result(timeout=10)
    assert user_balances(op.principal.ledger_owner_id, "SOL")["reserved"] == 1
    assert not LedgerTransaction.objects.filter(
        event_type__in=["WITHDRAWAL_RELEASE", "WITHDRAWAL_SETTLE"]
    ).exists()


@pytest.mark.parametrize("action", ["release", "settle"])
def test_prior_terminal_journal_cannot_be_adopted_as_held_operation(financial, action):
    c = dict(financial, withdrawal=legacy_request(financial))
    with transaction.atomic():
        (release_withdrawal if action == "release" else settle_withdrawal)(c["withdrawal"])
    with pytest.raises(MpcBindingError, match="terminal"):
        operation(c)
    assert not MpcSolanaFinancialOperation.objects.exists()


def test_expired_terminal_query_cannot_be_consumed_or_extended(financial):
    c = financial
    row = session(c)
    request = query(c, row)
    source = MpcSolanaFinancialQuery.objects.get(pk=request["query"]["challenge"])
    # New short lease tests the same real wall clock boundary without changing
    # an existing immutable nonce/deadline or mocking the database clock.
    nonce = "de" * 32
    value = copy.deepcopy(source.query) | {"challenge": nonce}
    MpcSolanaFinancialQuery.objects.create(
        challenge=nonce,
        session=row,
        purpose="TERMINAL",
        witness_anchor_id=source.witness_anchor_id,
        witness_key_id=source.witness_key_id,
        query=value,
        expires_at=timezone.now() + timedelta(milliseconds=100),
    )
    request = {"query": value}
    proof = terminal(c, row, request)
    time.sleep(0.15)
    with pytest.raises(MpcBindingError, match="expired"):
        no_signature(c, row, request, proof)
    row.refresh_from_db()
    assert row.status == "ALLOCATED"


def test_raw_journal_cannot_bypass_protected_hold(financial):
    c = financial
    op = operation(c)
    with pytest.raises(DatabaseError, match="typed terminal evidence"), transaction.atomic():
        accounts = lock_user_accounts(op.principal.ledger_owner_id, "SOL")
        post_transaction(
            event_key=f"withdrawal:{c['withdrawal'].pk}:release",
            event_type="WITHDRAWAL_RELEASE",
            asset_key="SOL",
            ref_type="WithdrawalRequest",
            ref_id=c["withdrawal"].pk,
            postings=[(accounts["RESERVED"], Decimal(-1)), (accounts["AVAILABLE"], Decimal(1))],
        )


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
def test_wrong_family_generic_session_cannot_hide_new_protected_attempt(financial, isolation):
    c = financial
    op = operation(c)
    keyset = MpcKeyset.objects.create(
        keyset_id=uuid4(),
        algorithm="CGGMP24_ECDSA",
        curve="secp256k1",
        scope="EVM",
        derivation_version="cggmp_hd_v1",
    )
    observed, proceed = threading.Event(), threading.Event()
    attempts = []

    def wrong_family_writer():
        close_old_connections()
        try:
            with (
                pytest.raises(DatabaseError, match="query returned no rows|READ COMMITTED"),
                transaction.atomic(),
            ):
                with connection.cursor() as cursor:
                    cursor.execute("SET TRANSACTION ISOLATION LEVEL " + isolation)
                MpcKeyset.objects.get(pk=keyset.pk)
                observed.set()
                assert proceed.wait(10)
                MpcSigningSession.objects.create(
                    attempt_id=attempts[0],
                    session_id=uuid4(),
                    keyset=keyset,
                    algorithm="CGGMP24_ECDSA",
                    message_fingerprint="aa" * 32,
                    payload_type="SOLANA",
                    signing_payload=b"x",
                )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(wrong_family_writer)
        assert observed.wait(10)
        try:
            attempts.append(session(c, op).attempt_id)
        finally:
            proceed.set()
        future.result(timeout=10)
    assert not MpcSigningSession.objects.exists()


@pytest.mark.parametrize("budget", [True, 1.5, 0, -1, 20_001])
def test_native_budget_must_be_explicit_integer_within_installed_cap(financial, budget):
    with pytest.raises(MpcBindingError, match="budget"):
        operation(financial, fee_budget_lamports=budget)
    assert not MpcSolanaFinancialOperation.objects.exists()


def test_customer_claim_cannot_silently_replace_withdrawal_treasury(financial):
    c = financial
    with pytest.raises(MpcBindingError, match="source role"):
        operation(c, source_id=c["CUSTOMER"].pk)
    assert not MpcSolanaFinancialOperation.objects.exists()


def test_operation_audit_failure_preserves_original_ledger_reserve(financial):
    c = financial
    before = LedgerTransaction.objects.count()
    with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit")):
        with pytest.raises(RuntimeError, match="audit"):
            operation(c)
    assert not MpcSolanaFinancialOperation.objects.exists()
    assert LedgerTransaction.objects.count() == before
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1


def test_expiry_during_audit_rolls_back_terminal_proof_at_commit(financial):
    c = financial
    row = session(c)
    request = query(c, row)
    source = MpcSolanaFinancialQuery.objects.get(pk=request["query"]["challenge"])
    nonce = "ef" * 32
    value = copy.deepcopy(source.query) | {"challenge": nonce}
    MpcSolanaFinancialQuery.objects.create(
        challenge=nonce,
        session=row,
        purpose="TERMINAL",
        witness_anchor_id=source.witness_anchor_id,
        witness_key_id=source.witness_key_id,
        query=value,
        expires_at=timezone.now() + timedelta(milliseconds=400),
    )
    request = {"query": value}
    proof = terminal(c, row, request)
    original = AdminActionLog.objects.create

    def delayed_audit(**kwargs):
        result = original(**kwargs)
        time.sleep(0.5)
        return result

    with patch.object(AdminActionLog.objects, "create", side_effect=delayed_audit):
        with pytest.raises(DatabaseError, match="expired before commit"):
            no_signature(c, row, request, proof)
    row.refresh_from_db()
    assert row.status == "ALLOCATED"
    assert MpcSolanaFinancialQuery.objects.get(pk=nonce).status == "PENDING"


@pytest.mark.parametrize(
    "scope,chain", [("EVM", "ETH"), ("TRON", "TRX"), ("SOLANA", "SOL"), ("TON", "TON")]
)
def test_unprotected_legacy_session_birth_remains_available_in_read_committed(
    financial, scope, chain
):
    """SQL structural compatibility only; no actual legacy signing authorization."""
    c = financial
    req = legacy_request(c)
    ecdsa = scope in {"EVM", "TRON"}
    keyset = MpcKeyset.objects.create(
        keyset_id=uuid4(),
        scope=scope,
        algorithm="CGGMP24_ECDSA" if ecdsa else "FROST_ED25519",
        curve="secp256k1" if ecdsa else "ed25519",
        derivation_version="cggmp_hd_v1" if ecdsa else "frost_keyset_v1",
    )
    attempt = OnchainTransactionAttempt.objects.create(
        operation_type="WITHDRAWAL",
        operation_id=req.pk,
        chain_id=chain,
        asset_key="SOL",
        from_address="legacy-structural-source",
        to_address="legacy-structural-destination",
        amount=Decimal(1),
        base_unit_amount=10**9,
    )
    row = MpcSigningSession.objects.create(
        attempt=attempt,
        session_id=uuid4(),
        keyset=keyset,
        algorithm=keyset.algorithm,
        message_fingerprint=hashlib.sha256(b"legacy-structural-wire").hexdigest(),
        payload_type="LEGACY_STRUCTURAL",
        signing_payload=b"legacy-structural-wire",
    )
    assert MpcSigningSession.objects.get(pk=row.pk).attempt_id == attempt.pk
    assert not MpcSolanaFinancialOperation.objects.exists()


def test_legacy_sqlite_demo_keeps_ledger_flows_and_refuses_protected_allocation(tmp_path):
    script = Path(__file__).with_name("sqlite_financial_compatibility.py")
    result = subprocess.run(
        [sys.executable, str(script), str(tmp_path / "disposable-demo.sqlite3")],
        env=os.environ | {"PYTHONPATH": str(script.parents[2])},
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert "PostgreSQL-only allocation: PASS" in result.stdout
