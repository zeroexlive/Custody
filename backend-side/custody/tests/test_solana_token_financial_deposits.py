"""Real PG journal/provenance with synthetic chain evidence; no MPC assertion."""

import base64
import copy
from decimal import Decimal
from unittest.mock import patch

import pytest
from django.db import DatabaseError, transaction
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import Transaction

from custody.deposits import reverse_confirmed
from custody.indexer.base import IndexerUnavailable
from custody.ledger import user_balances
from custody.models import Deposit, LedgerTransaction, MpcSolanaDepositProvenance
from custody.mpc_binding import MpcBindingError
from custody.solana_financial_deposits import (
    register_operator_funding_source,
    scan_financial_wallet,
)
from custody.tests import test_solana_token_provisioning as fixtures
from custody.tests.test_solana_seeded_token_deposits import incoming
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.parametrize("pending", ["CUSTOMER"], indirect=True),
]
clean_mode = fixtures.clean_mode
context = fixtures.context
financial = fixtures.financial
preparation = fixtures.preparation
signer_receipt_trust = fixtures.signer_receipt_trust
pending = fixtures.pending


@pytest.fixture
def deposits(pending, settings, monkeypatch):
    c = pending
    _, proof = fixtures.publication(c)
    c["published"] = fixtures.publish(c, proof)
    settings.MPC_SOLANA_SEEDED_DEPOSITS_ENABLED = True
    settings.CUSTODY_INDEXER_MODE = "live"
    monkeypatch.setenv("CUSTODY_INDEXER_MODE", "live")
    tx, meta = incoming(c["token_claim"])
    c["incoming_tx"], c["incoming_meta"] = tx, meta
    signature = str(tx.signatures[0])
    c["token_slot"] = 40
    c["token_accounts"][c["token_claim"].address] = fixtures.token_account(c, 2_000_123)
    c["rpc"].responses.update(
        getFirstAvailableBlock=0,
        getSignaturesForAddress=[dict(signature=signature, slot=40, err=None)],
        getSignatureStatuses={"value": [dict(confirmationStatus="finalized", slot=40, err=None)]},
        getTransaction=dict(
            slot=40,
            version="legacy",
            meta=meta,
            transaction=[base64.b64encode(bytes(tx)).decode(), "base64"],
        ),
        getBlock=dict(
            blockhash=str(Hash.from_bytes(bytes([8]) * 32)), parentSlot=39, signatures=[signature]
        ),
    )
    with patch("custody.solana_financial_deposits._runtime"):
        # Registering the fee payer must not classify another owner's token
        # inventory as operator funding. This also exercises delegate execution.
        register_operator_funding_source(
            address=str(tx.message.account_keys[0]),
            reference="external-fee-sponsor",
            operator_ref="operator",
        )
        yield c


def scan(c):
    return scan_financial_wallet(
        user_wallet_id=c["published"].user_wallet_id,
        tenant_id=c["tenant"].pk,
        operator_ref="operator",
        transport=c["rpc"],
    )


def test_finalized_classic_instruction_credits_once_with_exact_asset_and_owner(deposits):
    c = deposits
    before = LedgerTransaction.objects.count()
    assert scan(c).confirmed_balance == Decimal("2.000123")
    assert scan(c).scan_complete
    deposit = Deposit.objects.get(asset_key="UNIT-SPL")
    provenance = MpcSolanaDepositProvenance.objects.get(deposit=deposit)
    assert deposit.amount == 2 and deposit.status == "CONFIRMED"
    assert provenance.source_owner_address == c["incoming_meta"]["preTokenBalances"][0]["owner"]
    assert provenance.source_address != provenance.source_owner_address
    assert LedgerTransaction.objects.count() == before + 1
    assert user_balances(c["published"].claim.principal.ledger_owner_id, "UNIT-SPL")["total"] == 2


@pytest.mark.parametrize("kind", ["owner", "account"])
def test_operator_classification_excludes_token_owner_or_account_before_credit(deposits, kind):
    c = deposits
    entry = c["incoming_meta"]["preTokenBalances"][0]
    address = (
        entry["owner"]
        if kind == "owner"
        else str(c["incoming_tx"].message.account_keys[entry["accountIndex"]])
    )
    register_operator_funding_source(
        address=address, reference="operator-inventory", operator_ref="operator"
    )
    assert scan(c).scan_complete
    assert not Deposit.objects.filter(asset_key="UNIT-SPL").exists()


def test_token_balance_without_instruction_never_creates_credit(deposits):
    c = deposits
    c["rpc"].responses["getSignaturesForAddress"] = []
    assert scan(c).confirmed_balance == Decimal("2.000123")
    assert not Deposit.objects.filter(asset_key="UNIT-SPL").exists()


def test_credited_token_owner_cannot_be_reclassified_as_operator_even_by_sql(deposits):
    c = deposits
    scan(c)
    owner = MpcSolanaDepositProvenance.objects.get().source_owner_address
    with pytest.raises(MpcBindingError, match="reconciliation"):
        register_operator_funding_source(address=owner, reference="late", operator_ref="operator")
    from custody.models import MpcSolanaOperatorFundingSource

    with pytest.raises(DatabaseError, match="external attribution"), transaction.atomic():
        MpcSolanaOperatorFundingSource.objects.create(
            genesis_hash=c["root"].network_identity["genesis_hash"],
            address=owner,
            reference="late-sql",
        )


def test_conflicting_token_metadata_cannot_rewrite_original_attribution(deposits):
    c = deposits
    scan(c)
    c["incoming_meta"]["postTokenBalances"][1]["uiTokenAmount"]["amount"] = "2000124"
    with pytest.raises((IndexerUnavailable, MpcBindingError)):
        scan(c)
    assert Deposit.objects.get(asset_key="UNIT-SPL").amount == 2


def test_optional_rpc_token_ui_fields_do_not_change_permanent_digest(deposits):
    c = deposits
    scan(c)
    before = MpcSolanaDepositProvenance.objects.get().observation_sha256
    for name in ("preTokenBalances", "postTokenBalances"):
        for entry in c["incoming_meta"][name]:
            entry["uiTokenAmount"]["uiAmountString"] = "different-display"
            entry["uiTokenAmount"].pop("uiAmount", None)
        c["incoming_meta"][name].reverse()
    assert scan(c).scan_complete
    assert MpcSolanaDepositProvenance.objects.get().observation_sha256 == before


def test_token_reversal_preserves_original_journals_and_replay_never_recredits(deposits):
    c = deposits
    scan(c)
    deposit = Deposit.objects.get(asset_key="UNIT-SPL")
    reverse_confirmed(deposit.pk)
    assert scan(c).scan_complete
    assert user_balances(c["published"].claim.principal.ledger_owner_id, "UNIT-SPL")["total"] == 0
    assert LedgerTransaction.objects.filter(ref_type="Deposit", ref_id=str(deposit.pk)).count() == 2


def test_missing_selected_owner_rolls_back_cursor_and_all_credits(deposits):
    c = deposits
    original = copy.deepcopy(c["published"].user_wallet.solana_scan_cursor)
    del c["incoming_meta"]["preTokenBalances"][0]["owner"]
    with pytest.raises(IndexerUnavailable):
        scan(c)
    assert not Deposit.objects.filter(asset_key="UNIT-SPL").exists()
    c["published"].user_wallet.refresh_from_db()
    assert c["published"].user_wallet.solana_scan_cursor == original


def owner_change(c):
    """Known-key SDK wire with external X -> external Y -> customer ownership."""
    tx, meta = c["incoming_tx"], c["incoming_meta"]
    keys, ix = tx.message.account_keys, tx.message.instructions[0]
    old_owner = Keypair.from_seed(bytes([97]) * 32)
    new_owner = Keypair.from_seed(bytes([94]) * 32)
    sponsor = Keypair.from_seed(bytes([95]) * 32)
    change = Instruction(
        Pubkey.from_string(CLASSIC_TOKEN_PROGRAM),
        bytes([6, 2, 1]) + bytes(new_owner.pubkey()),
        [
            AccountMeta(keys[ix.accounts[0]], False, True),
            AccountMeta(old_owner.pubkey(), True, False),
        ],
    )
    transfer = Instruction(
        Pubkey.from_string(CLASSIC_TOKEN_PROGRAM),
        bytes(ix.data),
        [
            AccountMeta(new_owner.pubkey() if n == 3 else keys[index], n == 3, n in (0, 2))
            for n, index in enumerate(ix.accounts)
        ],
    )
    changed = Transaction.new_signed_with_payer(
        [change, transfer], sponsor.pubkey(), [sponsor, new_owner, old_owner], Hash.default()
    )
    for name in ("preTokenBalances", "postTokenBalances"):
        for entry in meta[name]:
            if name == "postTokenBalances" and entry["accountIndex"] == ix.accounts[0]:
                entry["owner"] = str(new_owner.pubkey())
            entry["accountIndex"] = changed.message.account_keys.index(keys[entry["accountIndex"]])
    meta["fee"] = 15_000
    meta["preBalances"] = [10_000_000] * len(changed.message.account_keys)
    meta["postBalances"] = meta["preBalances"].copy()
    meta["postBalances"][0] -= 15_000
    signature = str(changed.signatures[0])
    c["rpc"].responses["getTransaction"].update(
        transaction=[base64.b64encode(bytes(changed)).decode(), "base64"], meta=meta
    )
    c["rpc"].responses["getBlock"]["signatures"] = [signature]
    c["rpc"].responses["getSignaturesForAddress"][0]["signature"] = signature
    return str(old_owner.pubkey()), str(new_owner.pubkey())


def test_funding_classification_after_observation_rechecks_every_historical_owner(deposits):
    from custody.solana_financial_deposits import _observe

    c = deposits
    old_owner, new_owner = owner_change(c)

    def observed(*args):
        result = _observe(*args)
        event = result[1][0][0]
        assert event.source_owner_address == new_owner
        assert event.source_owner_history == sorted([old_owner, new_owner])
        register_operator_funding_source(
            address=old_owner, reference="concurrent-funding", operator_ref="operator"
        )
        return result

    with patch("custody.solana_financial_deposits._observe", side_effect=observed):
        assert scan(c).scan_complete
    assert not Deposit.objects.filter(asset_key="UNIT-SPL").exists()
    assert user_balances(c["published"].claim.principal.ledger_owner_id, "UNIT-SPL")["total"] == 0


def test_credit_before_funding_classification_permanently_preserves_all_source_owners(deposits):
    from custody.models import MpcSolanaOperatorFundingSource

    c = deposits
    old_owner, new_owner = owner_change(c)
    assert scan(c).scan_complete
    proof = MpcSolanaDepositProvenance.objects.get()
    assert proof.source_owner_address == new_owner
    assert proof.source_owner_history == sorted([old_owner, new_owner])
    with pytest.raises(MpcBindingError, match="reconciliation"):
        register_operator_funding_source(
            address=old_owner, reference="late-history", operator_ref="operator"
        )
    with pytest.raises(DatabaseError, match="external attribution"), transaction.atomic():
        MpcSolanaOperatorFundingSource.objects.create(
            genesis_hash=proof.genesis_hash, address=old_owner, reference="late-history-sql"
        )
