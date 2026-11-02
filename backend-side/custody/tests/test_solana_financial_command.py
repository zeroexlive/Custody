"""Operator CLI exercises real holds/provenance with synthetic public fixtures."""

import io
import json
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from custody.ledger import user_balances
from custody.models import (
    Deposit,
    LedgerTransaction,
    MpcSolanaFinancialOperation,
    MpcSolanaFinancialQuery,
    MpcSolanaFinancialSession,
    OnchainTransactionAttempt,
)
from custody.tests import test_solana_financial_deposits as fixtures
from custody.tests import test_solana_financial_sessions as sessions

pytestmark = pytest.mark.django_db(transaction=True)
clean_mode = fixtures.clean_mode
context = fixtures.context
financial = fixtures.financial
signer_receipt_trust = fixtures.signer_receipt_trust
deposits = fixtures.deposits


def run(c, action, *args):
    output = io.StringIO()
    call_command(
        "solana_financial",
        action,
        "--tenant-id",
        str(c["tenant"].pk),
        "--operator-ref",
        "unit-operator",
        *args,
        stdout=output,
    )
    return json.loads(output.getvalue())


def test_cli_explicit_treasury_allocation_retains_one_hold_and_original_ids(financial):
    c = financial
    before = LedgerTransaction.objects.count()
    args = (
        "--withdrawal-id",
        str(c["withdrawal"].pk),
        "--source-id",
        str(c["TREASURY"].pk),
        "--fee-budget-lamports",
        "20000",
    )
    op = run(c, "withdrawal-allocate", *args)
    assert run(c, "withdrawal-allocate", *args) == op
    row = MpcSolanaFinancialOperation.objects.get(pk=op["reservation_id"])
    assert row.source == c["TREASURY"] and row.principal == c["CUSTOMER"].claim.principal
    session_args = ("--reservation-id", op["reservation_id"], "--selected-signers")
    session = run(c, "session-allocate", *session_args, "signer-a", "signer-b")
    assert run(c, "session-allocate", *session_args, "signer-a", "signer-b") == session
    with pytest.raises(CommandError):
        run(c, "session-allocate", *session_args, "signer-a", "signer-c")
    assert (
        OnchainTransactionAttempt.objects.count() == MpcSolanaFinancialSession.objects.count() == 1
    )
    assert not MpcSolanaFinancialQuery.objects.exists()
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1
    assert LedgerTransaction.objects.count() == before


def test_cli_cannot_substitute_customer_source_or_other_tenant(financial):
    c = financial
    args = ("--withdrawal-id", str(c["withdrawal"].pk), "--fee-budget-lamports", "20000")
    with pytest.raises(CommandError):
        run(c, "withdrawal-allocate", *args, "--source-id", str(c["CUSTOMER"].pk))
    other = dict(c, tenant=type("OtherTenant", (), {"pk": uuid4()})())
    with pytest.raises(CommandError):
        run(other, "withdrawal-allocate", *args, "--source-id", str(c["TREASURY"].pk))
    assert not MpcSolanaFinancialOperation.objects.exists()
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1


@pytest.mark.parametrize("body", [b'{"grant":1,"grant":2}', b"[]", b"x" * (1024 * 1024 + 1)])
def test_cli_invalid_policy_file_cannot_allocate_query_or_touch_private_dispatch(
    financial, tmp_path, body
):
    path = tmp_path / "public-policy.json"
    path.write_bytes(body)
    with pytest.raises(CommandError):
        run(
            financial,
            "approve",
            "--session-id",
            str(uuid4()),
            "--policy-authorization",
            str(path),
        )
    assert not MpcSolanaFinancialQuery.objects.exists()
    assert not OnchainTransactionAttempt.objects.exists()


def test_cli_scan_credits_verified_provenance_once_without_balance_credit(deposits):
    c = deposits
    fixtures.wire(c)
    args = ("--user-wallet-id", str(c["CUSTOMER"].user_wallet_id))
    before = LedgerTransaction.objects.count()
    with patch("custody.solana_financial_deposits.RequestsTransport", return_value=c["rpc"]):
        assert run(c, "deposit-scan", *args)["scan_complete"] is True
        assert run(c, "deposit-scan", *args)["scan_complete"] is True
    assert Deposit.objects.count() == 1
    assert LedgerTransaction.objects.count() == before + 1
    assert user_balances(c["withdrawal"].user_id, "SOL")["total"] == Decimal("5.002")


def test_cli_terminal_retry_creates_no_query_or_private_work_and_keeps_hold(financial):
    c = financial
    row = sessions.session(c)
    sessions.no_signature(c, row, sessions.query(c, row))
    before = MpcSolanaFinancialQuery.objects.count()
    with (
        patch("custody.solana_financial_signing._runtime"),
        patch("custody.management.commands.solana_financial.query_witness") as remote,
    ):
        assert run(c, "execute", "--session-id", str(row.pk))["status"] == "NO_SIGNATURE"
        assert run(c, "no-signature", "--session-id", str(row.pk))["status"] == "NO_SIGNATURE"
        remote.assert_not_called()
    assert MpcSolanaFinancialQuery.objects.count() == before
    assert OnchainTransactionAttempt.objects.count() == 1
    assert user_balances(c["withdrawal"].user_id, "SOL")["reserved"] == 1
