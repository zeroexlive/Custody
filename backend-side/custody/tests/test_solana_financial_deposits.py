"""PG provenance with synthetic RPC/funds; genuine customer flow is separate."""

import base64
import copy
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.db import DatabaseError, connection, transaction
from solders.hash import Hash
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction

from custody.deposits import reverse_confirmed
from custody.indexer.base import DepositEvent, IndexerUnavailable
from custody.ledger import user_balances
from custody.models import (
    AdminActionLog,
    Deposit,
    LedgerTransaction,
    MpcSolanaFinancialWallet,
    UserWallet,
)
from custody.mpc_binding import MpcBindingError
from custody.solana_financial_deposits import (
    _internal_sources,
    ingest_financial_event,
    register_operator_funding_source,
    scan_financial_wallet,
)
from custody.tests import test_solana_financial_sessions as fixtures

pytestmark = pytest.mark.django_db(transaction=True)
clean_mode = fixtures.clean_mode
context = fixtures.context
financial = fixtures.financial
signer_receipt_trust = fixtures.signer_receipt_trust


def wire(c, *, sender=None):
    # Known external fixture sender, never a reconstructed MPC custody key.
    sender = sender or Keypair.from_seed(bytes([91]) * 32)
    address = c["CUSTOMER"].claim.address
    tx = Transaction.new_signed_with_payer(
        [
            transfer(
                TransferParams(
                    from_pubkey=sender.pubkey(),
                    to_pubkey=Pubkey.from_string(address),
                    lamports=2_000_000,
                )
            ),
        ],
        sender.pubkey(),
        [sender],
        Hash.from_bytes(bytes([7]) * 32),
    )
    keys = [str(k) for k in tx.message.account_keys]
    before = [10_000_000] * len(keys)
    after = before.copy()
    after[0] -= 2_005_000
    after[keys.index(address)] += 2_000_000
    signature = str(tx.signatures[0])
    status = dict(confirmationStatus="finalized", slot=20, err=None)
    response = {
        "slot": 20,
        "transaction": [base64.b64encode(bytes(tx)).decode(), "base64"],
        "meta": dict(err=None, fee=5000, preBalances=before, postBalances=after),
        "version": "legacy",
    }
    block = dict(
        blockhash=str(Hash.from_bytes(bytes([8]) * 32)), parentSlot=19, signatures=[signature]
    )
    c["rpc"].responses.update(
        getFirstAvailableBlock=0,
        getSlot=20,
        getSignaturesForAddress=[
            dict(signature=signature, slot=20, err=None, confirmationStatus="finalized")
        ],
        getSignatureStatuses={"value": [status]},
        getTransaction=response,
        getBlock=block,
    )
    return DepositEvent(
        signature,
        Decimal("0.002"),
        20,
        100,
        asset_key="SOL",
        event_index="ix:0",
        block_hash=block["blockhash"],
    )


@pytest.fixture
def deposits(financial, settings, monkeypatch):
    c = financial
    settings.MPC_SOLANA_SEEDED_DEPOSITS_ENABLED = True
    settings.CUSTODY_INDEXER_MODE = "live"
    monkeypatch.setenv("CUSTODY_INDEXER_MODE", "live")
    c["operator_key"] = Keypair.from_seed(bytes([93]) * 32)
    with patch("custody.solana_financial_deposits._runtime"):
        c["funding"] = register_operator_funding_source(
            address=str(c["operator_key"].pubkey()),
            reference="unit-operator",
            operator_ref="operator",
        )
        c["event"] = wire(c)
        yield c


def scan(c, **kwargs):
    return scan_financial_wallet(
        **(
            dict(
                user_wallet_id=c["CUSTOMER"].user_wallet_id,
                tenant_id=c["tenant"].pk,
                operator_ref="operator",
                transport=c["rpc"],
            )
            | kwargs
        )
    )


def ingest(c, event=None):
    return ingest_financial_event(
        user_wallet_id=c["CUSTOMER"].user_wallet_id,
        tenant_id=c["tenant"].pk,
        event=event or c["event"],
        operator_ref="operator",
        transport=c["rpc"],
    )


def test_finalized_instruction_credits_original_customer_once_with_cursor(deposits):
    c = deposits
    before = LedgerTransaction.objects.count()
    assert scan(c).scan_complete and scan(c).scan_complete
    deposit = Deposit.objects.get(user_wallet_id=c["CUSTOMER"].user_wallet_id)
    assert deposit.status == "CONFIRMED" and deposit.amount == Decimal("0.002")
    assert deposit.event_index == "ix:0" and deposit.block == 20
    assert LedgerTransaction.objects.count() == before + 1
    assert user_balances(c["withdrawal"].user_id, "SOL") == {
        "available": Decimal("4.002"),
        "reserved": Decimal(1),
        "total": Decimal("5.002"),
    }
    wallet = UserWallet.objects.get(pk=c["CUSTOMER"].user_wallet_id)
    assert wallet.last_scanned_block == 20 and wallet.solana_scan_cursor == {}


def test_high_account_balance_alone_creates_no_customer_credit(deposits):
    c = deposits
    c["rpc"].responses["getSignaturesForAddress"] = []
    before = LedgerTransaction.objects.count()
    assert scan(c).confirmed_balance == Decimal(20)
    assert not Deposit.objects.exists() and LedgerTransaction.objects.count() == before


def test_registered_operator_transfer_is_not_a_customer_deposit(deposits):
    c = deposits
    c["event"] = wire(c, sender=c["operator_key"])
    before = LedgerTransaction.objects.count()
    assert scan(c).scan_complete
    assert not Deposit.objects.exists() and LedgerTransaction.objects.count() == before
    with pytest.raises(MpcBindingError, match="attributable external"):
        ingest(c)


@pytest.mark.parametrize(
    "field,value",
    [
        ("amount", Decimal(1)),
        ("event_index", "ix:1"),
        ("block", 21),
        ("block_hash", str(Hash.from_bytes(bytes([9]) * 32))),
        ("asset_key", "OTHER"),
    ],
)
def test_event_hint_cannot_change_actual_amount_identity_or_slot(deposits, field, value):
    c = deposits
    event = copy.deepcopy(c["event"])
    setattr(event, field, value)
    with pytest.raises(MpcBindingError):
        ingest(c, event)
    assert not Deposit.objects.exists()


@pytest.mark.parametrize("fault", ["pruned", "missing", "slot", "block_membership"])
def test_missing_or_conflicting_history_never_credits_or_advances_cursor(deposits, fault):
    c = deposits
    responses = c["rpc"].responses
    if fault == "pruned":
        responses["getFirstAvailableBlock"] = 10
    elif fault == "missing":
        responses["getTransaction"] = None
    elif fault == "slot":
        responses["getSignaturesForAddress"][0]["slot"] = 19
    else:
        responses["getBlock"]["signatures"] = []
    with pytest.raises(IndexerUnavailable):
        scan(c)
    wallet = UserWallet.objects.get(pk=c["CUSTOMER"].user_wallet_id)
    assert wallet.last_scanned_block is None and wallet.solana_scan_cursor == {}
    assert not Deposit.objects.exists()


def test_scan_audit_failure_rolls_back_credit_provenance_and_cursor(deposits):
    c = deposits
    before = LedgerTransaction.objects.count()
    audit = AdminActionLog.objects.create

    def failed(**kwargs):
        if kwargs["action_type"] == "SOL_FIN_DEPOSIT_SCAN":
            raise RuntimeError("scan audit")
        return audit(**kwargs)

    with patch.object(AdminActionLog.objects, "create", side_effect=failed):
        with pytest.raises(RuntimeError, match="scan audit"):
            scan(c)
    assert not Deposit.objects.exists() and LedgerTransaction.objects.count() == before
    assert UserWallet.objects.get(pk=c["CUSTOMER"].user_wallet_id).last_scanned_block is None


def test_retired_root_late_attribution_and_reversal_preserve_original_history(deposits):
    c = deposits
    c["root"].keyset.status = "RETIRED"
    c["root"].keyset.save(update_fields=["status"])
    deposit, created = ingest(c)
    assert created and deposit.status == "CONFIRMED"
    assert reverse_confirmed(deposit.pk).status == "REVERTED"
    assert ingest(c)[0].status == "REVERTED"
    assert user_balances(c["withdrawal"].user_id, "SOL")["available"] == 4
    assert LedgerTransaction.objects.filter(event_key=f"deposit:{deposit.pk}:credit").count() == 1
    assert LedgerTransaction.objects.filter(event_key=f"deposit:{deposit.pk}:reversal").count() == 1


def test_funding_registration_cannot_reclassify_accepted_external_history(deposits):
    c = deposits
    ingest(c)
    with pytest.raises(MpcBindingError, match="explicit reconciliation"):
        register_operator_funding_source(
            address=str(Keypair.from_seed(bytes([91]) * 32).pubkey()),
            reference="late-operator",
            operator_ref="operator",
        )


def test_source_pool_retains_original_base_all_claims_and_operator(deposits):
    c = deposits
    pool = _internal_sources()
    assert c["root"].base_address in pool
    assert c["CUSTOMER"].claim.address in pool and c["TREASURY"].claim.address in pool
    assert str(c["operator_key"].pubkey()) in pool


def test_tenant_mismatch_and_disabled_activation_stop_before_rpc(deposits, settings):
    c = deposits
    before = len(c["rpc"].calls)
    with pytest.raises(MpcSolanaFinancialWallet.DoesNotExist):
        scan(c, tenant_id=uuid4())
    assert len(c["rpc"].calls) == before
    settings.MPC_SOLANA_SEEDED_DEPOSITS_ENABLED = False
    with pytest.raises(MpcBindingError, match="disabled"):
        scan(c)
    assert len(c["rpc"].calls) == before


def test_original_provenance_is_immutable(deposits):
    from custody.models import MpcSolanaDepositProvenance

    c = deposits
    deposit, _ = ingest(c)
    proof = MpcSolanaDepositProvenance.objects.get(deposit=deposit)
    with pytest.raises(DatabaseError), transaction.atomic():
        MpcSolanaDepositProvenance.objects.filter(pk=proof.pk).update(
            source_address=str(c["operator_key"].pubkey())
        )


def test_rpc_display_fields_do_not_rewrite_or_duplicate_accepted_provenance(deposits):
    from custody.models import MpcSolanaDepositProvenance

    c = deposits
    deposit, _ = ingest(c)
    original = copy.deepcopy(MpcSolanaDepositProvenance.objects.get(deposit=deposit).evidence)
    c["rpc"].responses["getTransaction"]["meta"]["computeUnitsConsumed"] = 900
    c["rpc"].responses["getSignatureStatuses"]["value"][0]["confirmations"] = None
    assert ingest(c) == (deposit, False)
    assert MpcSolanaDepositProvenance.objects.get(deposit=deposit).evidence == original


def test_direct_journal_and_status_cannot_credit_unproven_seeded_deposit(deposits):
    from custody.ledger import clearing_account, lock_user_accounts, post_transaction

    c = deposits
    event = c["event"]
    pending = Deposit.objects.create(
        user_wallet_id=c["CUSTOMER"].user_wallet_id,
        asset_key="SOL",
        tx_hash=event.tx_hash,
        event_index=event.event_index,
        amount=event.amount,
    )
    with pytest.raises(DatabaseError), transaction.atomic():
        Deposit.objects.filter(pk=pending.pk).update(status="CONFIRMED")
    with pytest.raises(DatabaseError, match="provenance"), transaction.atomic():
        accounts = lock_user_accounts(c["withdrawal"].user_id, "SOL")
        post_transaction(
            event_key=f"deposit:{pending.pk}:credit",
            event_type="DEPOSIT_CREDIT",
            asset_key="SOL",
            ref_type="Deposit",
            ref_id=pending.pk,
            postings=[
                (accounts["AVAILABLE"], pending.amount),
                (clearing_account("SOL"), -pending.amount),
            ],
        )
    with pytest.raises(MpcBindingError, match="cannot be adopted"):
        ingest(c)


def test_credit_postings_and_account_identity_cannot_be_reinterpreted(deposits):
    from custody.models import LedgerPosting

    c = deposits
    deposit, _ = ingest(c)
    journal = LedgerTransaction.objects.get(event_key=f"deposit:{deposit.pk}:credit")
    postings = list(journal.postings.all())
    with pytest.raises(DatabaseError), transaction.atomic():
        LedgerPosting.objects.bulk_create(
            [
                LedgerPosting(transaction=journal, account_id=p.account_id, amount=-p.amount)
                for p in postings
            ]
        )
    with pytest.raises(DatabaseError, match="account identity"), transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE custody_ledgeraccount SET owner_id='another-owner' WHERE id=%s",
                [postings[0].account_id],
            )
    assert user_balances(c["withdrawal"].user_id, "SOL")["available"] == Decimal("4.002")


def test_stub_mode_blocks_direct_and_scanned_credit_entrypoints(deposits, monkeypatch):
    c = deposits
    monkeypatch.setenv("CUSTODY_INDEXER_MODE", "stub")
    with pytest.raises(IndexerUnavailable, match="live finalized"):
        ingest(c)
    with pytest.raises(IndexerUnavailable, match="live finalized"):
        scan(c)
    assert not Deposit.objects.exists()


def test_funding_identity_is_permanent_and_generic_sweep_does_not_start_private_work(deposits):
    from custody.models import MpcSolanaOperatorFundingSource, SweepJob
    from custody.sweeper import trigger_sweep

    c = deposits
    with pytest.raises(DatabaseError), transaction.atomic():
        MpcSolanaOperatorFundingSource.objects.filter(pk=c["funding"].pk).update(reference="new")
    triggered, job, reason = trigger_sweep(c["CUSTOMER"].user_wallet, "operator")
    assert triggered is False and job is None and "explicit treasury" in reason
    assert not SweepJob.objects.exists()


def cpi_wire(c):
    import base58
    from solders.instruction import AccountMeta, Instruction

    sender = Keypair.from_seed(bytes([91]) * 32)
    program = Pubkey.from_bytes(bytes([24]) * 32)
    source, _ = Pubkey.find_program_address([b"unit-cpi-source"], program)
    destination = Pubkey.from_string(c["CUSTOMER"].claim.address)
    ix = Instruction(
        program,
        b"unit-runtime-call",
        [
            AccountMeta(source, False, True),
            AccountMeta(destination, False, True),
            AccountMeta(Pubkey.default(), False, False),
        ],
    )
    tx = Transaction.new_signed_with_payer(
        [ix], sender.pubkey(), [sender], Hash.from_bytes(bytes([7]) * 32)
    )
    keys = list(tx.message.account_keys)
    before = [10_000_000] * len(keys)
    after = before.copy()
    after[0] -= 5000
    after[keys.index(source)] -= 2_000_000
    after[keys.index(destination)] += 2_000_000
    meta = dict(
        err=None,
        fee=5000,
        preBalances=before,
        postBalances=after,
        innerInstructions=[
            {
                "index": 0,
                "instructions": [
                    {
                        "programIdIndex": keys.index(Pubkey.default()),
                        "accounts": [keys.index(source), keys.index(destination)],
                        "data": base58.b58encode(
                            bytes([2, 0, 0, 0]) + (2_000_000).to_bytes(8, "little")
                        ).decode(),
                        "stackHeight": 2,
                    }
                ],
            }
        ],
    )
    signature = str(tx.signatures[0])
    responses = c["rpc"].responses
    responses["getTransaction"] = dict(
        slot=20,
        version="legacy",
        transaction=[base64.b64encode(bytes(tx)).decode(), "base64"],
        meta=meta,
    )
    responses["getBlock"]["signatures"] = [signature]
    responses["getSignaturesForAddress"] = [dict(signature=signature, slot=20, err=None)]
    event = DepositEvent(
        signature,
        Decimal("0.002"),
        20,
        100,
        asset_key="SOL",
        event_index="inner:0:0",
        block_hash=responses["getBlock"]["blockhash"],
    )
    return event, source


def test_runtime_authorized_cpi_source_need_not_be_an_ed25519_signer(deposits):
    c = deposits
    event, _ = cpi_wire(c)
    deposit, created = ingest(c, event)
    assert created and deposit.event_index == "inner:0:0" and deposit.amount == Decimal("0.002")


@pytest.mark.parametrize("fault", ["index", "program", "amount", "duplicate", "internal_pda"])
def test_invalid_or_internal_cpi_provenance_never_creates_customer_credit(deposits, fault):
    import base58

    c = deposits
    event, source = cpi_wire(c)
    meta = c["rpc"].responses["getTransaction"]["meta"]
    inner = meta["innerInstructions"][0]["instructions"][0]
    if fault == "index":
        inner["accounts"][0] = 255
    elif fault == "program":
        inner["programIdIndex"] = 0
    elif fault == "amount":
        inner["data"] = base58.b58encode(
            bytes([2, 0, 0, 0]) + (3_000_000).to_bytes(8, "little")
        ).decode()
    elif fault == "duplicate":
        meta["innerInstructions"] *= 2
    else:
        register_operator_funding_source(
            address=str(source), reference="operator-pda", operator_ref="operator"
        )
    with pytest.raises((MpcBindingError, ValueError)):
        ingest(c, event)
    assert not Deposit.objects.exists()
