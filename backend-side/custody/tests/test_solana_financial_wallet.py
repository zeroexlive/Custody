"""Real PG transactional publication with signed synthetic fixtures, not MPC."""

import copy
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from importlib import import_module
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.db import DatabaseError, close_old_connections, connection, transaction

from custody.financial_identity import register_financial_principal
from custody.models import (
    AdminActionLog,
    HotWallet,
    LedgerTransaction,
    MpcKeyset,
    MpcSolanaFinancialWallet,
    MpcSolanaIssuance,
    UserWallet,
)
from custody.mpc_binding import MpcBindingError
from custody.solana_financial_wallet import (
    complete_financial_wallet,
    financial_wallet_request,
    validate_financial_wallet,
)
from custody.solana_issuance import complete_publication, publication_request
from custody.tests.test_solana_financial_root import (
    begin as begin_mode,
)
from custody.tests.test_solana_financial_root import (
    clean_mode as mode_fixture,
)
from custody.tests.test_solana_financial_root import (
    complete as complete_mode,
)
from custody.tests.test_solana_financial_root import (
    context as registry_context_fixture,
)
from custody.tests.test_solana_financial_root import (
    signed as mode_signed,
)
from custody.tests.test_solana_financial_root import (
    signer_receipt_trust as receipt_trust_fixture,
)
from custody.tests.test_solana_financial_root import (
    wait_for_database_lock,
)
from custody.tests.test_solana_issuance import signed
from custody.tests.test_solana_provisioning import approve, reserve

pytestmark = pytest.mark.django_db(transaction=True)
context = registry_context_fixture
signer_receipt_trust = receipt_trust_fixture
clean_mode = mode_fixture


@pytest.fixture(params=["CUSTOMER", "TREASURY"])
def financial_claim(clean_mode, request):
    c = clean_mode
    query = begin_mode(c)
    c["mode"] = complete_mode(c, mode_signed(c, query))
    principal = register_financial_principal(
        tenant_id=c["tenant"].pk,
        reference="financial-" + request.param,
        role=request.param,
        operator_ref="operator",
    )
    c["principal"] = principal
    c["claim"] = approve(c, reserve(c, principal=principal))
    with (
        patch("custody.solana_financial_wallet._runtime"),
        patch("custody.solana_issuance._runtime"),
    ):
        yield c


def begin(c):
    return financial_wallet_request(
        reservation_id=c["claim"].pk, tenant_id=c["tenant"].pk, operator_ref="operator"
    )


def reply(c, request, *, phase="Active"):
    issuance = MpcSolanaIssuance.objects.get(pk=request["issuance_id"])
    value = copy.deepcopy(c["mode"].evidence["value"])
    value.update(
        query=request["query"],
        sequence=8,
        claim=c["claim"].evidence,
        claim_issuance={
            "reservation_id": str(c["claim"].pk),
            "issuance_id": str(issuance.pk),
            "command_id": str(uuid4()),
        },
    )
    value["root"].update(phase=phase, revision=8, next_claim_index=1)
    return signed(c, issuance.witness_key_id, value)


def complete(c, evidence):
    return complete_financial_wallet(
        reservation_id=c["claim"].pk,
        tenant_id=c["tenant"].pk,
        evidence=evidence,
        operator_ref="operator",
        transport=c["rpc"],
    )


def test_financial_publication_is_atomic_idempotent_and_never_creates_treasury_customer_wallet(
    financial_claim,
):
    c = financial_claim
    journals = LedgerTransaction.objects.count()
    request = begin(c)
    assert begin(c) == request and request["status"] == "PENDING"
    assert not UserWallet.objects.filter(solana_claim=c["claim"]).exists()
    row = complete(c, reply(c, request))
    assert row.status == "ACTIVE" and validate_financial_wallet(row).pk == c["claim"].pk
    assert complete(c, None).evidence == row.evidence
    assert begin(c)["status"] == "ACTIVE"
    if request["role"] == "CUSTOMER_DEPOSIT":
        assert row.user_wallet_id is not None
        wallet = UserWallet.objects.get(pk=row.user_wallet_id)
        assert wallet.user_id == c["principal"].ledger_owner_id
        assert wallet.deposit_address == c["claim"].address
    else:
        assert row.user_wallet_id is None
        assert not UserWallet.objects.filter(user_id=c["principal"].ledger_owner_id).exists()
    assert LedgerTransaction.objects.count() == journals


def test_legacy_customer_api_rejects_financial_root_before_any_issuance_intent(financial_claim):
    c = financial_claim
    with pytest.raises(MpcBindingError, match="dedicated"):
        publication_request(
            reservation_id=c["claim"].pk, tenant_id=c["tenant"].pk, operator_ref="operator"
        )
    assert not MpcSolanaIssuance.objects.filter(claim=c["claim"]).exists()
    request = begin(c)
    with pytest.raises(MpcBindingError, match="dedicated"):
        complete_publication(
            issuance_id=request["issuance_id"],
            tenant_id=c["tenant"].pk,
            evidence=reply(c, request),
            operator_ref="operator",
            transport=c["rpc"],
        )
    assert MpcSolanaIssuance.objects.get(pk=request["issuance_id"]).status == "PENDING"


@pytest.mark.parametrize("phase", ["Frozen", "Prepared"])
def test_original_permanent_grant_can_finish_publication_after_maintenance(financial_claim, phase):
    c = financial_claim
    request = begin(c)
    row = complete(c, reply(c, request, phase=phase))
    assert validate_financial_wallet(row).status == "ACTIVE"


@pytest.mark.parametrize("field", ["mode", "challenge", "grant", "claim", "signature"])
def test_invalid_or_wrong_original_financial_proof_cannot_activate(financial_claim, field):
    c = financial_claim
    request = begin(c)
    proof = reply(c, request)
    if field == "mode":
        proof["value"]["root"]["financial_mode"]["activation_id"] = str(uuid4())
    elif field == "challenge":
        proof["value"]["query"]["challenge"] = "fe" * 32
    elif field == "grant":
        proof["value"]["claim_issuance"]["issuance_id"] = str(uuid4())
    elif field == "claim":
        proof["value"]["claim"]["statement"]["owner_ref"] = "p1:" + str(uuid4())
    if field != "signature":
        proof = signed(c, proof["key_id"], proof["value"])
    else:
        proof["signature"] = "00" * 64
    with pytest.raises(MpcBindingError):
        complete(c, proof)
    assert MpcSolanaFinancialWallet.objects.get(claim=c["claim"]).status == "PENDING"
    assert not UserWallet.objects.filter(solana_claim=c["claim"]).exists()


def test_activation_audit_failure_rolls_back_issuer_customer_wallet_and_membership(financial_claim):
    c = financial_claim
    request = begin(c)
    proof = reply(c, request)
    with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit")):
        with pytest.raises(RuntimeError, match="audit"):
            complete(c, proof)
    assert MpcSolanaIssuance.objects.get(pk=request["issuance_id"]).status == "PENDING"
    assert MpcSolanaFinancialWallet.objects.get(claim=c["claim"]).status == "PENDING"
    assert not UserWallet.objects.filter(solana_claim=c["claim"]).exists()
    assert complete(c, proof).status == "ACTIVE"


def test_begin_audit_failure_leaves_no_orphan_issuance_or_financial_intent(financial_claim):
    c = financial_claim
    with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit")):
        with pytest.raises(RuntimeError, match="audit"):
            begin(c)
    assert not MpcSolanaIssuance.objects.filter(claim=c["claim"]).exists()
    assert not MpcSolanaFinancialWallet.objects.filter(claim=c["claim"]).exists()


def test_deferred_constraints_reject_witnessed_issuer_without_atomic_activation(financial_claim):
    c = financial_claim
    request = begin(c)
    proof = reply(c, request)
    with pytest.raises(DatabaseError, match="partial financial publication"), transaction.atomic():
        issuance = MpcSolanaIssuance.objects.get(pk=request["issuance_id"])
        issuance.status, issuance.evidence = "WITNESSED", proof
        issuance.save(update_fields=["status", "evidence"])
    assert MpcSolanaIssuance.objects.get(pk=request["issuance_id"]).status == "PENDING"


def test_expired_query_renewal_preserves_original_issuer_and_rejects_delayed_reply(financial_claim):
    c = financial_claim
    original = begin(c)
    proof = reply(c, original)
    expires = MpcSolanaIssuance.objects.get(pk=original["issuance_id"]).query_expires_at
    time.sleep(max(0, (expires - datetime.now(timezone.utc)).total_seconds()) + 0.05)
    with pytest.raises(MpcBindingError, match="expired"):
        complete(c, proof)
    renewed = begin(c)
    assert renewed["issuance_id"] == original["issuance_id"]
    assert renewed["query"]["challenge"] != original["query"]["challenge"]
    with pytest.raises(MpcBindingError):
        complete(c, proof)
    assert complete(c, reply(c, renewed)).status == "ACTIVE"


def test_public_validation_reloads_state_instead_of_trusting_supplied_object(financial_claim):
    c = financial_claim
    request = begin(c)
    fake = MpcSolanaFinancialWallet.objects.get(claim=c["claim"])
    fake.status, fake.evidence = "ACTIVE", reply(c, request)
    fake.issuance.status, fake.issuance.evidence = "WITNESSED", fake.evidence
    with pytest.raises(MpcBindingError, match="active financial wallet"):
        validate_financial_wallet(fake)


def test_committed_active_membership_cannot_mutate_or_disappear(financial_claim):
    c = financial_claim
    request = begin(c)
    row = complete(c, reply(c, request))
    for update in (
        {"status": "PENDING", "evidence": {}},
        {"role": "CUSTOMER_DEPOSIT" if row.role == "TENANT_TREASURY" else "TENANT_TREASURY"},
    ):
        with pytest.raises(DatabaseError), transaction.atomic():
            MpcSolanaFinancialWallet.objects.filter(pk=row.pk).update(**update)
    with pytest.raises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
        cursor.execute("DELETE FROM custody_mpcsolanafinancialwallet WHERE claim_id=%s", [row.pk])


def test_concurrent_requests_and_completions_keep_one_original_publication(financial_claim):
    c = financial_claim

    def worker(proof=None):
        close_old_connections()
        try:
            return begin(c) if proof is None else complete(c, proof).pk
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        requests = list(pool.map(lambda _: worker(), range(2)))
    assert requests[0] == requests[1]
    proof = reply(c, requests[0])
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(worker, [proof, proof]))
    assert outcomes[0] == outcomes[1]
    assert MpcSolanaFinancialWallet.objects.filter(claim=c["claim"]).count() == 1
    assert UserWallet.objects.filter(solana_claim=c["claim"]).count() == (
        1 if requests[0]["role"] == "CUSTOMER_DEPOSIT" else 0
    )


@pytest.mark.parametrize("financial_claim", ["CUSTOMER"], indirect=True)
def test_deferred_customer_wallet_without_active_membership_cannot_commit(financial_claim):
    c = financial_claim
    request = begin(c)
    proof = reply(c, request)
    claim = c["claim"]
    with pytest.raises(DatabaseError, match="partial financial publication"), transaction.atomic():
        issuance = MpcSolanaIssuance.objects.get(pk=request["issuance_id"])
        issuance.status, issuance.evidence = "WITNESSED", proof
        issuance.save(update_fields=["status", "evidence"])
        UserWallet.objects.create(
            solana_claim=claim,
            user_id=claim.principal.ledger_owner_id,
            chain_id="SOL",
            asset_key=claim.asset.asset_key,
            deposit_address=claim.address,
            derivation_path=f"solana:{claim.root.keyset.keyset_id}:{claim.index}",
            address_index=claim.index,
            mpc_keyset=claim.root.keyset,
            derivation_version="solana_seeded_v1",
        )
    assert not UserWallet.objects.filter(solana_claim=claim).exists()
    assert MpcSolanaIssuance.objects.get(pk=request["issuance_id"]).status == "PENDING"


@pytest.mark.parametrize("financial_claim", ["CUSTOMER"], indirect=True)
def test_forward_preflight_refuses_unlinked_old_issuance_without_adoption(financial_claim):
    from datetime import timedelta

    from django.utils import timezone as django_timezone

    from custody.solana_issuance import _pin

    c = financial_claim
    anchor, key_id, _ = _pin()
    migration = import_module("custody.migrations.0038_solana_financial_wallets")
    # Pending orphan exists only inside this rollback transaction. Execute the
    # actual forward migration's preflight before deferred endtxn constraints.
    preflight = migration.FORWARD.split("CREATE FUNCTION", 1)[0]
    with pytest.raises(DatabaseError, match="publication cannot be adopted"), transaction.atomic():
        MpcSolanaIssuance.objects.create(
            claim=c["claim"],
            witness_anchor_id=anchor,
            witness_key_id=key_id,
            query_challenge="ab" * 32,
            query_expires_at=django_timezone.now() + timedelta(seconds=15),
        )
        with connection.cursor() as cursor:
            cursor.execute(preflight)
    assert not MpcSolanaIssuance.objects.filter(claim=c["claim"]).exists()
    assert not MpcSolanaFinancialWallet.objects.filter(claim=c["claim"]).exists()


def test_populated_reverse_guard_keeps_original_financial_history(financial_claim):
    c = financial_claim
    request = begin(c)
    row = complete(c, reply(c, request))
    migration = import_module("custody.migrations.0038_solana_financial_wallets")
    guard = migration.REVERSE.split("DROP TRIGGER", 1)[0]
    with pytest.raises(DatabaseError, match="cannot be downgraded"), transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(guard)
    assert validate_financial_wallet(row).status == "ACTIVE"


@pytest.mark.parametrize("financial_claim", ["CUSTOMER"], indirect=True)
def test_financial_completion_rechecks_expiry_after_actual_database_lock_wait(financial_claim):
    c = financial_claim
    request = begin(c)
    proof = reply(c, request)
    expires = MpcSolanaIssuance.objects.get(pk=request["issuance_id"]).query_expires_at
    application = "financial-pub-expiry-" + str(uuid4())

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
    assert MpcSolanaFinancialWallet.objects.get(claim=c["claim"]).status == "PENDING"


@pytest.mark.parametrize("financial_claim", ["CUSTOMER"], indirect=True)
@pytest.mark.parametrize("first", ["financial", "hot"])
def test_hot_reference_and_financial_intent_cannot_adopt_each_other(financial_claim, first):
    from custody import solana_financial_wallet

    c = financial_claim
    entered, release = threading.Event(), threading.Event()
    application = "financial-hot-race-" + str(uuid4())
    original_audit = solana_financial_wallet._audit

    def hold_audit(*args):
        original_audit(*args)
        entered.set()
        assert release.wait(10)

    def hot_worker():
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET application_name=%s", [application])
            try:
                with transaction.atomic():
                    HotWallet.objects.update_or_create(
                        chain_id="SOL",
                        defaults={
                            "address": c["claim"].address,
                            "mpc_keyset": None,
                            "signing_key_ref": None,
                        },
                    )
                    if first == "hot":
                        entered.set()
                        assert release.wait(10)
                return "created"
            except DatabaseError as exc:
                return str(exc)
        finally:
            close_old_connections()

    def finance_worker():
        close_old_connections()
        try:
            try:
                begin(c)
                return "created"
            except DatabaseError as exc:
                return str(exc)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        if first == "financial":
            with patch("custody.solana_financial_wallet._audit", side_effect=hold_audit):
                winner = pool.submit(finance_worker)
                try:
                    assert entered.wait(5)
                    loser = pool.submit(hot_worker)
                    wait_for_database_lock(application)
                finally:
                    release.set()
                assert winner.result(timeout=10) == "created"
                assert "financial Claim cannot become a legacy HotWallet" in loser.result(
                    timeout=10
                )
        else:
            winner = pool.submit(hot_worker)
            try:
                assert entered.wait(5)
                loser = pool.submit(finance_worker)
                assert "could not obtain lock" in loser.result(timeout=5)
            finally:
                release.set()
            assert winner.result(timeout=10) == "created"
            assert not MpcSolanaIssuance.objects.filter(claim=c["claim"]).exists()
            with pytest.raises(MpcBindingError, match="cannot be adopted"):
                begin(c)
