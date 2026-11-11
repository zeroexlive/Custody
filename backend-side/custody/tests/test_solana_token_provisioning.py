"""Real PG, SDK wire and known-key synthetic authorities; not MPC acceptance."""

import base64
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.db import DatabaseError, connection, connections, transaction
from django.utils import timezone
from ops.models import Chain
from solders.hash import Hash
from solders.pubkey import Pubkey
from solders.transaction import Transaction

from custody.ledger import user_balances
from custody.models import (
    AdminActionLog,
    LedgerAccount,
    LedgerTransaction,
    MpcSolanaFinancialOperation,
    MpcSolanaFinancialWallet,
    MpcSolanaTokenProvision,
    MpcSolanaTokenPublication,
    UserWallet,
)
from custody.mpc_binding import MpcBindingError
from custody.solana_financial_outbound import reconcile_finality
from custody.solana_financial_preparation import approve_session, prepare_session
from custody.solana_financial_sessions import allocate_session, request_query
from custody.solana_financial_wallet import complete_financial_wallet, financial_wallet_request
from custody.solana_token_provisioning import allocate_provision
from custody.solana_witness_client import _point_id
from custody.tests import test_solana_financial_preparation as fixtures
from custody.tests import test_solana_financial_signing as signature_fixtures
from custody.tests.test_solana_issuance import signed
from custody.tests.test_solana_provisioning import approve, reserve, token
from custody.tests.test_solana_witness_client import identity
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM

pytestmark = pytest.mark.django_db(transaction=True)
clean_mode = fixtures.clean_mode
context = fixtures.context
financial = fixtures.financial
preparation = fixtures.preparation
signer_receipt_trust = fixtures.signer_receipt_trust


def account(owner, data, lamports):
    return {
        "owner": owner,
        "executable": False,
        "data": [base64.b64encode(data).decode(), "base64"],
        "lamports": lamports,
    }


def token_account(c, units=0):
    raw = bytearray(165)
    raw[:32] = bytes(Pubkey.from_string(c["token_asset"].contract_address))
    raw[32:64] = bytes(Pubkey.from_string(c["root"].base_address))
    raw[64:72] = units.to_bytes(8, "little")
    raw[108] = 1
    return account(CLASSIC_TOKEN_PROGRAM, raw, 2_039_280)


@pytest.fixture(params=["CUSTOMER", "TREASURY"])
def pending(preparation, settings, tmp_path, request):
    c = preparation
    settings.MPC_SOLANA_SEEDED_SPL_ENABLED = True
    chain = Chain.objects.get(chain_id="SOL")
    chain.gas_settings |= {"max_ata_rent_lamports": "3000000"}
    chain.save(update_fields=["gas_settings"])
    c["token_asset"] = token("UNIT-SPL")
    c["token_claim"] = approve(
        c,
        reserve(
            c,
            retry="classic-initializer",
            principal=c[request.param].claim.principal,
            asset=c["token_asset"].asset_key,
        ),
    )
    c["token_slot"], c["token_accounts"] = 10, {}
    c["node_signers"] = {}
    keys = {}
    ca = identity(tmp_path / "token-node-ca", "ca")
    for party in ("signer-a", "signer-b", "signer-c"):
        key, cert = identity(tmp_path / "token-nodes" / party, party, ca)
        c["node_signers"][party] = key

        keys[party] = _point_id(cert.public_key())
    settings.MPC_SOLANA_FINANCIAL_SIGNER_CERTIFICATES = {
        p: [str(tmp_path / "token-nodes" / p / "tls.crt")] for p in keys
    }
    original = c["rpc"].rpc

    def rpc(url, method, params):
        assert not connection.in_atomic_block
        if method == "getSlot":
            return c["token_slot"]
        if method == "getAccountInfo":
            address = params[0]
            if address in c["token_accounts"]:
                result = c["token_accounts"][address]
            elif address == c["token_claim"].address:
                result = None
            elif address == c["token_asset"].contract_address:
                mint = bytearray(82)
                mint[44], mint[45] = 6, 1
                result = account(CLASSIC_TOKEN_PROGRAM, mint, 1_461_600)
            else:
                result = account("11111111111111111111111111111111", b"", 20_000_000_000)
            return {"context": {"slot": c["token_slot"]}, "value": copy.deepcopy(result)}
        return original(url, method, params)

    c["rpc"].rpc = rpc

    def proof(c, row, purpose="ADMISSION"):
        lease = request_query(
            session_id=row.pk, tenant_id=c["tenant"].pk, purpose=purpose, operator_ref="operator"
        )
        value = copy.deepcopy(c["mode"].evidence["value"])
        value.update(
            query=lease["query"],
            claim=row.operation.source.claim.evidence,
            claim_issuance=None,
            execution=None,
            abandoned=False,
            sequence=10,
        )
        value["root"]["node_keys"] = keys
        return lease, signed(c, c["mode"].witness_key_id, value)

    c["proof"] = proof
    with (
        patch("custody.solana_token_provisioning._runtime"),
        patch("custody.solana_financial_signing._runtime"),
        patch("custody.solana_financial_outbound._runtime"),
    ):
        c["token_request"] = financial_wallet_request(
            reservation_id=c["token_claim"].pk, tenant_id=c["tenant"].pk, operator_ref="operator"
        )
        c["token_wallet"] = MpcSolanaFinancialWallet.objects.get(pk=c["token_claim"].pk)
        yield c


def allocate(c, **changes):
    return allocate_provision(
        **{
            "reservation_id": c["token_claim"].pk,
            "tenant_id": c["tenant"].pk,
            "idempotency_key": "initialize-1",
            "fee_budget_lamports": 20_000,
            "rent_budget_lamports": 3_000_000,
            "operator_ref": "operator",
            **changes,
        }
    )


def prepared(c, **allocation):
    op = allocate(c, **allocation)
    row = allocate_session(
        reservation_id=op.pk,
        tenant_id=c["tenant"].pk,
        selected_signers=["signer-a", "signer-b"],
        operator_ref="operator",
    )
    lease, proof = c["proof"](c, row)
    return prepare_session(
        session_id=row.pk,
        tenant_id=c["tenant"].pk,
        challenge=lease["query"]["challenge"],
        evidence=proof,
        operator_ref="operator",
        transport=c["rpc"],
    )


def completed(c, **allocation):
    row = prepared(c, **allocation)
    lease, proof = c["proof"](c, row)
    c["ready"] = approve_session(
        session_id=row.pk,
        tenant_id=c["tenant"].pk,
        challenge=lease["query"]["challenge"],
        evidence=proof,
        policy_authorization=fixtures.policy(c, row),
        operator_ref="operator",
    )
    return signature_fixtures.completed(c)


def finalized(c, *, failed=False, **allocation):
    row = completed(c, **allocation)
    tx = Transaction.from_bytes(bytes.fromhex(row.attempt.signed_payload))
    keys = [str(key) for key in tx.message.account_keys]
    source = keys.index(c["token_claim"].address)
    before = [10_000_000_000] * len(keys)
    before[source] = 0
    after = before.copy()
    after[0] -= 5000
    error = {"InstructionError": [0, "Custom"]} if failed else None
    if not failed:
        after[0] -= 2_039_280
        after[source] += 2_039_280
    meta = dict(
        err=error,
        fee=5000,
        preBalances=before,
        postBalances=after,
        preTokenBalances=[],
        postTokenBalances=[]
        if failed
        else [
            {
                "accountIndex": source,
                "mint": c["token_asset"].contract_address,
                "programId": CLASSIC_TOKEN_PROGRAM,
                "owner": c["root"].base_address,
                "uiTokenAmount": {"amount": "0", "decimals": 6},
            }
        ],
    )
    c["rpc"].responses.update(
        getSignatureStatuses={
            "value": [{"confirmationStatus": "finalized", "slot": 20, "err": error}]
        },
        getTransaction={
            "slot": 20,
            "version": "legacy",
            "meta": meta,
            "transaction": [base64.b64encode(bytes(tx)).decode(), "base64"],
        },
    )
    result = reconcile_finality(
        session_id=row.pk, tenant_id=c["tenant"].pk, operator_ref="operator", transport=c["rpc"]
    )
    row.refresh_from_db()
    row.operation.refresh_from_db()
    return row, result


def test_pending_init_reserves_only_root_budgets_and_exports_no_premature_grant(pending):
    c = pending
    before = LedgerTransaction.objects.count()
    assert c["token_request"]["initialization_required"] is True
    assert c["token_request"]["witness_action"] is None
    op = allocate(c)
    assert allocate(c).pk == op.pk and op.provision_id
    assert op.amount == op.base_unit_amount == 0
    assert op.rent_budget_lamports == 3_000_000
    assert not UserWallet.objects.filter(solana_claim=c["token_claim"]).exists()
    assert LedgerTransaction.objects.count() == before
    assert not LedgerAccount.objects.filter(owner_type="USER", asset_key="UNIT-SPL").exists()


def test_initializer_captures_original_exact_wire_and_provision_identity(pending):
    row = prepared(pending)
    assert row.intent["operation_type"] == "PROVISION"
    assert row.intent["action"] == {"kind": "CreateClassicToken", "rent_lamports": 2_039_280}
    assert row.intent["rent_payer"] == pending["root"].base_address
    assert row.operation.amount == row.operation.base_unit_amount == 0
    assert row.intent["financial"]["source_owner_ref"] == row.operation.principal.ledger_owner_id


@pytest.mark.parametrize("failed", [False, True])
def test_original_finalized_initializer_accounts_actual_fee_and_owned_rent_only(pending, failed):
    c = pending
    before = LedgerTransaction.objects.count()
    row, result = finalized(c, failed=failed)
    parent = MpcSolanaTokenProvision.objects.get(pk=row.operation.provision_id)
    assert result.status == parent.status == ("FAILED" if failed else "CONFIRMED")
    assert row.operation.status == ("RELEASED" if failed else "SETTLED")
    assert LedgerTransaction.objects.count() == before + (1 if failed else 2)
    assert not LedgerAccount.objects.filter(owner_type="USER", asset_key="UNIT-SPL").exists()
    assert not UserWallet.objects.filter(solana_claim=c["token_claim"]).exists()
    if failed:
        assert allocate(c, idempotency_key="explicit-initialize-2").pk != row.operation_id
    else:
        request = financial_wallet_request(
            reservation_id=c["token_claim"].pk, tenant_id=c["tenant"].pk, operator_ref="operator"
        )
        assert request["witness_action"]["initialization_execution_id"] == str(
            row.crypto_execution_id
        )


@pytest.mark.parametrize("fault", ["existing_address", "budget", "missing_finality"])
def test_initialization_or_publication_never_adopts_unproved_account_or_budget(pending, fault):
    c = pending
    if fault == "existing_address":
        c["token_accounts"][c["token_claim"].address] = account(
            "11111111111111111111111111111111", b"", 1_000_000
        )
        with pytest.raises(MpcBindingError, match="adoption"):
            prepared(c)
    elif fault == "budget":
        with pytest.raises(MpcBindingError, match="rent budget"):
            allocate(c, rent_budget_lamports=0)
    else:
        c["token_accounts"][c["token_claim"].address] = token_account(c)
        with pytest.raises(MpcBindingError, match="initialization"):
            complete_financial_wallet(
                reservation_id=c["token_claim"].pk,
                tenant_id=c["tenant"].pk,
                evidence={},
                operator_ref="operator",
                transport=c["rpc"],
            )
    assert not MpcSolanaTokenPublication.objects.exists()
    assert not UserWallet.objects.filter(solana_claim=c["token_claim"]).exists()


def publication(c, **allocation):
    row, _ = finalized(c, **allocation)
    c["token_accounts"][c["token_claim"].address] = token_account(c, units=123)
    c["token_slot"] = 30
    request = financial_wallet_request(
        reservation_id=c["token_claim"].pk, tenant_id=c["tenant"].pk, operator_ref="operator"
    )
    value = copy.deepcopy(c["mode"].evidence["value"])
    value.update(
        query=request["query"],
        claim=c["token_claim"].evidence,
        sequence=20,
        claim_issuance={
            key: value for key, value in request["witness_action"].items() if key != "kind"
        }
        | {"command_id": str(uuid4())},
    )
    return row, signed(c, c["mode"].witness_key_id, value)


def publish(c, evidence):
    return complete_financial_wallet(
        reservation_id=c["token_claim"].pk,
        tenant_id=c["tenant"].pk,
        evidence=evidence,
        operator_ref="operator",
        transport=c["rpc"],
    )


def test_classic_publication_requires_both_owned_initialization_and_actual_account(pending):
    c = pending
    before = user_balances(c["CUSTOMER"].claim.principal.ledger_owner_id, "SOL")
    row, proof = publication(c)
    wallet = publish(c, proof)
    assert wallet.status == "ACTIVE" and publish(c, None).pk == wallet.pk
    record = MpcSolanaTokenPublication.objects.get(pk=c["token_claim"].pk)
    assert record.effect.attempt_id == row.attempt_id and record.account_context_slot == 30
    if wallet.role == "TENANT_TREASURY":
        assert wallet.user_wallet_id is None
    else:
        assert wallet.user_wallet.deposit_address == wallet.user_wallet.asset_account_address
        assert wallet.user_wallet.deposit_address == c["token_claim"].address
    assert not LedgerAccount.objects.filter(owner_type="USER", asset_key="UNIT-SPL").exists()
    assert user_balances(c["CUSTOMER"].claim.principal.ledger_owner_id, "SOL") == before


@pytest.mark.parametrize(
    "fault", ["program", "mint", "owner", "state", "delegate", "native", "close", "rent", "slot"]
)
def test_publication_rejects_wrong_or_mutable_account_without_any_activation(pending, fault):
    c = pending
    _, proof = publication(c)
    current = c["token_accounts"][c["token_claim"].address]
    if fault == "program":
        current["owner"] = "11111111111111111111111111111111"
    elif fault == "rent":
        current["lamports"] = 1
    elif fault == "slot":
        c["token_slot"] = 19
    else:
        raw = bytearray(base64.b64decode(current["data"][0]))
        offset = {
            "mint": 0,
            "owner": 32,
            "state": 108,
            "delegate": 72,
            "native": 109,
            "close": 129,
        }[fault]
        raw[offset] = 2 if fault == "state" else raw[offset] ^ 1
        current["data"][0] = base64.b64encode(raw).decode()
    with pytest.raises(MpcBindingError):
        publish(c, proof)
    assert not MpcSolanaTokenPublication.objects.exists()
    assert not UserWallet.objects.filter(solana_claim=c["token_claim"]).exists()
    c["token_wallet"].refresh_from_db()
    assert c["token_wallet"].status == "PENDING"


def test_publication_audit_failure_rolls_back_all_local_activation_with_original_ids(pending):
    c = pending
    _, proof = publication(c)
    before = LedgerTransaction.objects.count()
    with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit")):
        with pytest.raises(RuntimeError, match="audit"):
            publish(c, proof)
    c["token_wallet"].refresh_from_db()
    assert c["token_wallet"].status == "PENDING"
    assert not MpcSolanaTokenPublication.objects.exists()
    assert LedgerTransaction.objects.count() == before
    assert publish(c, proof).status == "ACTIVE"


def test_new_initializer_identity_never_replaces_unresolved_business_or_rent(pending):
    c = pending
    original = allocate(c)
    with pytest.raises(MpcBindingError, match="unresolved"):
        allocate(c, idempotency_key="different-initializer")
    with pytest.raises(MpcBindingError, match="immutable"):
        allocate(c, rent_budget_lamports=2_500_000)
    assert MpcSolanaTokenProvision.objects.count() == 1
    assert MpcSolanaFinancialOperation.objects.get(pk=original.pk).status == "HELD"


def test_original_actual_fee_cannot_be_posted_again_under_an_alias(pending):
    c = pending
    row, result = finalized(c)
    fee = LedgerTransaction.objects.get(event_key=f"solana:{result.pk}:network_fee")
    with pytest.raises(DatabaseError, match="cost journal identity"), transaction.atomic():
        LedgerTransaction.objects.create(
            event_key="aliased-double-charge",
            event_type="NETWORK_FEE",
            ref_type="OnchainTransactionAttempt",
            ref_id=str(result.pk),
            asset_key="SOL",
            metadata=fee.metadata,
        )
    assert row.operation.status == "SETTLED"


def test_concurrent_initializer_allocation_retains_one_original_parent_and_hold(pending):
    c = pending
    barrier = Barrier(2)

    def allocate_once():
        connections.close_all()
        try:
            barrier.wait(timeout=15)
            return allocate(c).pk
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: allocate_once(), range(2)))
    assert results[0] == results[1]
    assert MpcSolanaTokenProvision.objects.count() == 1
    assert MpcSolanaFinancialOperation.objects.filter(provision__isnull=False).count() == 1


def test_concurrent_publication_commits_one_proof_and_customer_wallet(pending):
    from custody.solana_token_provisioning import observe_publication_account

    c = pending
    _, proof = publication(c)
    barrier = Barrier(2)

    def observed(*args, **kwargs):
        result = observe_publication_account(*args, **kwargs)
        barrier.wait(timeout=15)
        return result

    def publish_once():
        connections.close_all()
        try:
            return publish(c, proof).pk
        finally:
            connections.close_all()

    with patch(
        "custody.solana_token_provisioning.observe_publication_account", side_effect=observed
    ):
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: publish_once(), range(2)))
    assert results[0] == results[1]
    assert MpcSolanaTokenPublication.objects.count() == 1
    assert UserWallet.objects.filter(solana_claim=c["token_claim"]).count() == (
        1 if c["token_wallet"].role == "CUSTOMER_DEPOSIT" else 0
    )


@pytest.mark.parametrize("mutation", ["header", "amount", "delete", "append"])
def test_original_initializer_rent_journal_is_exact_and_immutable(pending, mutation):
    from custody.models import LedgerPosting

    c = pending
    _, attempt = finalized(c)
    journal = LedgerTransaction.objects.get(event_key=f"solana:{attempt.pk}:token_account_rent")
    postings = journal.postings.all()
    original = list(postings.values_list("account_id", "amount"))
    with pytest.raises(DatabaseError), transaction.atomic():
        if mutation == "header":
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE custody_ledgertransaction SET metadata='{}' WHERE id=%s", [journal.pk]
                )
        elif mutation == "amount":
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE custody_ledgerposting SET amount=0 WHERE id=%s", [postings.first().pk]
                )
        elif mutation == "delete":
            with connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM custody_ledgerposting WHERE transaction_id=%s", [journal.pk]
                )
        else:
            LedgerPosting.objects.create(transaction=journal, account_id=original[0][0], amount=1)
    assert list(journal.postings.values_list("account_id", "amount")) == original


def test_populated_classic_financial_history_refuses_migration_downgrade(pending):
    from importlib import import_module

    migration = import_module("custody.migrations.0045_solana_classic_token_financial_workflows")
    allocate(pending)
    with pytest.raises(DatabaseError, match="cannot be downgraded"), transaction.atomic():
        with connection.schema_editor() as editor:
            migration.uninstall(None, editor)


def test_failed_initializer_needs_new_business_and_new_wire_before_successful_publication(pending):
    c = pending
    failed, _ = finalized(c, failed=True)
    c["token_slot"] = 20
    c["rpc"].blockhash = str(Hash.from_bytes(bytes([9]) * 32))
    c["rpc"].responses["getLatestBlockhash"] = {
        "context": {"slot": 20},
        "value": {"blockhash": c["rpc"].blockhash, "lastValidBlockHeight": 200},
    }
    successful, proof = publication(c, idempotency_key="explicit-new-initializer")
    assert successful.operation_id != failed.operation_id
    assert publish(c, proof).status == "ACTIVE"
    assert MpcSolanaTokenProvision.objects.filter(status="FAILED").count() == 1
    assert MpcSolanaTokenProvision.objects.filter(status="CONFIRMED").count() == 1
    assert MpcSolanaTokenPublication.objects.get().effect.attempt_id == successful.attempt_id


def test_publication_query_expiring_while_waiting_for_claim_lock_cannot_activate(pending):
    from custody.solana_issuance import _locked_claim

    c = pending
    _, proof = publication(c)
    now = timezone.now()
    after_lock = False

    def locked(*args):
        nonlocal after_lock
        result = _locked_claim(*args)
        after_lock = True
        return result

    with (
        patch("custody.solana_financial_wallet._locked_claim", side_effect=locked),
        patch(
            "custody.solana_financial_wallet.timezone.now",
            side_effect=lambda: now + timedelta(seconds=30) if after_lock else now,
        ),
    ):
        with pytest.raises(MpcBindingError, match="query expired"):
            publish(c, proof)
    c["token_wallet"].refresh_from_db()
    assert c["token_wallet"].status == "PENDING"
    assert not MpcSolanaTokenPublication.objects.exists()


@pytest.mark.parametrize("fault", ["raw_mint", "missing_lamports", "missing_minimum_rent"])
def test_sql_publication_proof_checks_raw_mint_and_required_rent_fields(pending, fault):
    from custody.solana_token_provisioning import observe_publication_account

    c = pending
    _, proof = publication(c)

    def observed(*args, **kwargs):
        session, effect, account = observe_publication_account(*args, **kwargs)
        if fault == "raw_mint":
            raw = bytearray(base64.b64decode(account["account"]["data"][0]))
            raw[0] ^= 1
            account["account"]["data"][0] = base64.b64encode(raw).decode()
        elif fault == "missing_lamports":
            del account["account"]["lamports"]
        else:
            del account["minimum_rent_lamports"]
        return session, effect, account

    with patch(
        "custody.solana_token_provisioning.observe_publication_account", side_effect=observed
    ):
        with pytest.raises(DatabaseError, match="exact classic account proof"):
            publish(c, proof)
    c["token_wallet"].refresh_from_db()
    assert c["token_wallet"].status == "PENDING"
    assert not MpcSolanaTokenPublication.objects.exists()
