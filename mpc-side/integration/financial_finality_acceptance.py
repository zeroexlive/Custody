"""Actual MPC/PG/validator original native sweep and exactly-once fee accounting.

Operator faucet funds and a synthetic sweep snapshot: this is not deposit-credit
or customer withdrawal/liability acceptance.
"""

import json
from decimal import Decimal
from unittest.mock import patch

from custody.models import AdminActionLog, LedgerTransaction, MpcSolanaFinancialEffect
from custody.native_tx import RequestsTransport
from custody.solana_financial_outbound import broadcast_session, reconcile_finality
from environment import private_file
from financial_signing_acceptance import run_financial_signing
from test_dkg import encrypted_files


def run_financial_finality(root_path, *, fault=None):
    def settle(g, root_path, tenant, row):
        before = LedgerTransaction.objects.count()
        ciphertexts = encrypted_files(g.net, g.dkg_binding)
        source = row.intent["financial_source"]
        base = row.intent["fee_payer"]
        destination = row.operation.destination_address
        balances = {
            a: g.validator.rpc("getBalance", [a, {"commitment": "finalized"}])["value"]
            for a in [source, base, destination]
        }
        transport = RequestsTransport()
        original = transport.rpc
        sends = []

        def rpc(url, method, params):
            result = original(url, method, params)
            if method == "sendTransaction":
                sends.append(params)
                if fault == "lost_ack":
                    raise TimeoutError("actual send accepted, acknowledgement lost")
            return result

        transport.rpc = rpc
        args = dict(
            session_id=row.pk, tenant_id=tenant.pk, operator_ref="integration", transport=transport
        )
        if fault == "lost_ack":
            try:
                broadcast_session(**args)
            except TimeoutError:
                pass
            else:
                raise AssertionError("lost acknowledgement did not occur")
            row.operation.refresh_from_db()
            assert row.operation.status == "HELD"
            assert broadcast_session(**args).status == "RECONCILIATION_REQUIRED"
        else:
            assert broadcast_session(**args).status == "BROADCASTED"
        g.validator.wait(row.attempt.network_tx_id)
        if fault == "settlement_audit":
            audit = AdminActionLog.objects.create

            def fail(**kwargs):
                if kwargs["action_type"] == "SOL_FIN_FINALIZED_SETTLE":
                    raise RuntimeError("settlement audit")
                return audit(**kwargs)

            with patch.object(AdminActionLog.objects, "create", side_effect=fail):
                try:
                    reconcile_finality(**args)
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("settlement audit did not fail")
            assert LedgerTransaction.objects.count() == before
            assert not MpcSolanaFinancialEffect.objects.exists()
            row.operation.refresh_from_db()
            assert row.operation.status == "HELD"
        result = reconcile_finality(**args)
        assert result.status == "CONFIRMED"
        assert reconcile_finality(**args).status == "CONFIRMED"
        assert broadcast_session(**args).status == "CONFIRMED"
        assert len(sends) == 1
        row.operation.refresh_from_db()
        assert row.operation.status == "SETTLED"
        effect = MpcSolanaFinancialEffect.objects.get(attempt=result)
        assert effect.evidence["effect"] == "seeded_system_transfer"
        assert LedgerTransaction.objects.count() == before + 1
        journal = LedgerTransaction.objects.get(event_key=f"solana:{result.pk}:network_fee")
        assert journal.event_type == "NETWORK_FEE"
        assert sum(journal.postings.values_list("amount", flat=True)) == Decimal(0)
        assert not journal.postings.filter(account__owner_type="USER").exists()
        after = {
            a: g.validator.rpc("getBalance", [a, {"commitment": "finalized"}])["value"]
            for a in balances
        }
        assert after[source] - balances[source] == -int(row.operation.base_unit_amount)
        assert after[destination] - balances[destination] == int(row.operation.base_unit_amount)
        assert after[base] - balances[base] == -int(effect.evidence["fee_lamports"])
        assert encrypted_files(g.net, g.dkg_binding) == ciphertexts
        name = f"solana-financial-finality-{fault or 'success'}-public-evidence.json"
        private_file(
            root_path / name,
            json.dumps(
                {
                    "scope": (
                        "actual upstream FROST native sweep/finality/fee journal; "
                        "synthetic sweep snapshot and operator faucet funds, "
                        "no deposit or customer liability acceptance"
                    ),
                    "original_signed_transaction_broadcast_once": True,
                    "finalized_original_claim_principal_and_separate_root_fee": True,
                    "exactly_one_existing_ledger_network_fee_journal": True,
                    "sweep_created_no_customer_liability_journal": True,
                    "lost_ack_reconciled_without_resending": fault == "lost_ack",
                    "audit_failure_rolled_back_all_db_settlement_before_recovery": fault
                    == "settlement_audit",
                    "terminal_replay_no_new_broadcast_or_journal": True,
                    "original_three_dkg_ciphertexts_unchanged": True,
                },
                sort_keys=True,
            ).encode(),
        )

    run_financial_signing(root_path, after_signed=settle)
