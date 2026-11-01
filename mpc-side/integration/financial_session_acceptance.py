"""Actual PG/Rust W allocation and unprepared abandonment, without private signing.

Sweep snapshot is synthetic. No funds are inferred from it, no ledger journal is
created, and this is not deposit/sweep/withdraw settlement acceptance.
"""

import json
from decimal import Decimal
from unittest.mock import patch

import pytest
from custody.models import AdminActionLog, LedgerTransaction, MpcSolanaFinancialQuery, SweepJob
from custody.mpc_binding import MpcBindingError
from custody.solana_financial_sessions import (
    allocate_session,
    allocate_sweep,
    complete_no_signature,
    request_query,
)
from custody.solana_witness_client import query_witness
from django.test import override_settings
from environment import private_file
from financial_wallet_acceptance import run_financial_wallets
from ops.models import Chain
from test_dkg import encrypted_files
from witness_acceptance import verify


def run_financial_sessions(root_path):
    run_financial_wallets(root_path, after_wallets=allocate_and_abandon)


def allocate_and_abandon(g, root_path, tenant, records):
    customer, treasury = records
    ciphertexts = encrypted_files(g.net, g.dkg_binding)
    before = LedgerTransaction.objects.count()
    Chain.objects.filter(chain_id="SOL").update(gas_settings={"max_fee_lamports": "20000"})
    sweep = SweepJob.objects.create(
        user_wallet=customer.user_wallet,
        asset_key="SOL",
        balance_snapshot=Decimal(1),
        idempotency_key="actual-witness-synthetic-sweep-snapshot",
    )
    operation = allocate_sweep(
        sweep_id=sweep.pk,
        destination_id=treasury.pk,
        tenant_id=tenant.pk,
        fee_budget_lamports=20_000,
        operator_ref="integration",
    )
    rows = []
    with override_settings(
        MPC_SOLANA_WITNESS_URL=f"https://localhost:{g.w.port}",
        MPC_SOLANA_WITNESS_CA_CERT=str(g.w.identity / "ca.crt"),
        MPC_SOLANA_WITNESS_COURIER_CERT=str(g.w.courier / "tls.crt"),
        MPC_SOLANA_WITNESS_COURIER_KEY=str(g.w.courier / "tls.key"),
    ):
        for pair in [["signer-a", "signer-b"], ["signer-a", "signer-c"]]:
            row = allocate_session(
                reservation_id=operation.pk,
                tenant_id=tenant.pk,
                selected_signers=pair,
                operator_ref="integration",
            )
            assert row.status == "ALLOCATED" and not row.intent and not bytes(row.payload)
            request = request_query(
                session_id=row.pk,
                tenant_id=tenant.pk,
                purpose="TERMINAL",
                operator_ref="integration",
            )
            arguments = {
                "session_id": row.pk,
                "tenant_id": tenant.pk,
                "challenge": request["query"]["challenge"],
                "operator_ref": "integration",
            }
            absent = query_witness(request["query"])
            assert absent["value"]["abandoned"] is False and absent["value"]["execution"] is None
            with pytest.raises(MpcBindingError, match="abandonment"):
                complete_no_signature(**arguments, evidence=absent)
            # Test driver alone owns Life: the backend exports only a public
            # action and has no command route or Lifecycle private key.
            command = g.w.command(request["lifecycle_action"], g.w.query()["root"]["revision"])
            code, ack = g.w.request("command", command)
            assert code == 200
            verify(g.w.identity, "WITNESS_ACK_V1", ack)
            g.w.stop()
            g.w.start()
            sequence = g.w.query()["sequence"]
            code, replay = g.w.request("command", command)
            assert code == 200
            verify(g.w.identity, "WITNESS_ACK_V1", replay)
            assert replay["value"]["value_fingerprint"] == ack["value"]["value_fingerprint"]
            assert g.w.query()["sequence"] == sequence
            proof = query_witness(request["query"])
            assert proof["value"]["root"]["phase"] == "Frozen"
            assert proof["value"]["abandoned"] is True
            with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit")):
                with pytest.raises(RuntimeError, match="audit"):
                    complete_no_signature(**arguments, evidence=proof)
            row.refresh_from_db()
            assert row.status == "ALLOCATED"
            assert (
                MpcSolanaFinancialQuery.objects.get(pk=request["query"]["challenge"]).status
                == "PENDING"
            )
            row = complete_no_signature(**arguments, evidence=proof)
            assert row.status == "NO_SIGNATURE"
            assert complete_no_signature(**arguments, evidence=None).pk == row.pk
            assert (
                row.operation_id == operation.pk
                and row.operation.approval_id == operation.approval_id
            )
            rows.append(row)
    assert rows[0].pk != rows[1].pk and rows[0].crypto_execution_id != rows[1].crypto_execution_id
    assert [r.attempt.attempt_number for r in rows] == [1, 2]
    operation.refresh_from_db()
    assert operation.status == "HELD" and not operation.withdrawal_id
    assert LedgerTransaction.objects.count() == before
    assert encrypted_files(g.net, g.dkg_binding) == ciphertexts
    private_file(
        root_path / "solana-financial-session-allocation-public-evidence.json",
        json.dumps(
            {
                "scope": (
                    "actual PG/Rust W unprepared allocation/abandonment only; "
                    "synthetic sweep snapshot, no signing/settlement"
                ),
                "all_attempt_ids_committed_before_query_or_lifecycle_action": True,
                "absence_without_permanent_abandonment_cannot_authorize_retry": True,
                "independent_lifecycle_abandonment_survived_witness_restart": True,
                "original_command_replay_preserved_digest_and_witness_sequence": True,
                "frozen_original_root_terminal_proof_accepted": True,
                "after_remote_abandonment_db_audit_failure_retained_pending_ids": True,
                "distinct_crypto_attempts_reused_one_original_business_reservation": True,
                "business_hold_retained": True,
                "ledger_journals_created": 0,
                "private_signing_or_broadcast_performed": False,
                "original_three_dkg_ciphertexts_unchanged": True,
            },
            sort_keys=True,
        ).encode(),
    )
