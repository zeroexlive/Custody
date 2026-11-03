"""Actual independent mTLS FROST processes, local validator and PostgreSQL custody.

Only faults are injected: lost responses or process/worker interruptions after
real cryptographic or chain effects. No mocked signature or finalized evidence.
"""

import hashlib
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import pytest
import requests
from custody.deposits import ingest_event
from custody.gas_station import admin_topup, execute_gas_intent
from custody.indexer.sol import SolIndexer
from custody.ledger import ensure_accounts, post_transaction, user_balances
from custody.models import (
    Asset,
    HotWallet,
    LedgerAccount,
    LedgerTransaction,
    MpcKeyset,
    MpcSigningSession,
    OnchainTransactionAttempt,
    SweepJob,
    UserWallet,
)
from custody.mpc_signing import advance_mpc_signing
from custody.native_tx import AmbiguousBroadcast, RequestsTransport
from custody.outbound import execute_attempt
from custody.reconciliation import reconcile_attempt
from custody.signer_adapter import SelfHostedMpcAdapter
from custody.spl import derive_ata
from custody.sweeper import advance_sweep, trigger_sweep
from custody.token_metadata import verify_token_asset
from custody.withdrawals import approve, create_request, process_withdrawal
from django.core.management import call_command
from django.db import close_old_connections, connection
from django.test import override_settings
from environment import ROLES, Processes
from ops.models import Chain, NodeEndpoint
from solana_local.validator import Validator
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from test_dkg import dkg_request, execute
from test_network import settings_for

CAPS = {
    "max_fee_lamports": "20000",
    "max_ata_rent_lamports": "3000000",
    "native_reserve_lamports": "0",
    "topup_amount": "0.01",
}


def test_phase6gc_witness_replacement_reservation_and_original_signed_store_upgrade(tmp_path):
    from replacement_acceptance import run_reserved_upgrade

    run_reserved_upgrade(tmp_path)


def test_phase6gc_profile_migration_current_dual_authority_and_fresh_witness_time(tmp_path):
    from profile_migration_acceptance import run_public_registration

    run_public_registration(tmp_path)


def test_phase6gc_original_profile_terminal_fence_and_successor_history_import(tmp_path):
    from profile_migration_acceptance import run_terminal_fence

    run_terminal_fence(
        tmp_path,
        Path(os.environ["PHASE6GC_PROFILE_COMPAT_BIN"]).resolve(),
        Path("mpc-side/target/debug").resolve(),
        import_successor=True,
    )


def test_phase6gc_migrated_profile_two_root_runtime_refresh_and_restart(tmp_path):
    from profile_migration_acceptance import run_migrated_runtime

    run_migrated_runtime(
        tmp_path,
        Path(os.environ["PHASE6GC_PROFILE_COMPAT_BIN"]).resolve(),
        Path("mpc-side/target/debug").resolve(),
    )


def test_phase6gc_migrated_profile_cold_two_root_courier_runtime(tmp_path):
    from profile_migration_acceptance import run_migrated_runtime

    run_migrated_runtime(
        tmp_path,
        Path(os.environ["PHASE6GC_PROFILE_COMPAT_BIN"]).resolve(),
        Path("mpc-side/target/debug").resolve(),
        custody_class="COLD",
    )


def test_phase6gc_legacy_refresh_local_identifier_cross_field_fence(tmp_path):
    from refresh_acceptance import run_historical_identifier_fence

    run_historical_identifier_fence(
        tmp_path,
        Path(os.environ["PHASE6GC_PROFILE_COMPAT_BIN"]).resolve(),
        Path("mpc-side/target/debug").resolve(),
    )


def test_phase6gc_class_custody_read_query_without_private_or_lifecycle_authority(tmp_path):
    from protected_financial_acceptance import run_custody_read_query

    run_custody_read_query(tmp_path)


def test_phase6gc_irreversible_financial_root_mode_and_explicit_reservation_crypto(tmp_path):
    from protected_financial_acceptance import run_financial_mode

    run_financial_mode(tmp_path)


def test_phase6gc_protected_coordinator_all_pairs_and_durable_public_recovery(tmp_path):
    from protected_coordinator_acceptance import run_coordinator

    run_coordinator(tmp_path)


@pytest.mark.django_db(transaction=True)
def test_phase6gc_financial_root_mode_import_before_claims_with_actual_witness(tmp_path):
    from financial_root_acceptance import run_financial_mode_import

    run_financial_mode_import(tmp_path)


@pytest.mark.django_db(transaction=True)
def test_phase6gc_native_financial_customer_treasury_publication_and_unknown_grant_recovery(
    tmp_path,
):
    from financial_wallet_acceptance import run_financial_wallets

    run_financial_wallets(tmp_path)


@pytest.mark.django_db(transaction=True)
def test_phase6gc_financial_session_allocation_and_unprepared_witness_abandonment(tmp_path):
    from financial_session_acceptance import run_financial_sessions

    run_financial_sessions(tmp_path)


@pytest.mark.django_db(transaction=True)
def test_phase6gc_backend_native_wire_and_class_policy_rust_authorization(tmp_path):
    from financial_preparation_acceptance import run_financial_preparation

    run_financial_preparation(tmp_path)


@pytest.mark.django_db(transaction=True)
def test_phase6gc_backend_protected_frost_and_permanent_signature_ownership(tmp_path):
    from financial_signing_acceptance import run_financial_signing

    run_financial_signing(tmp_path)


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("fault", ["before_record", "audit_and_cache_loss"])
def test_phase6gc_backend_signature_recovery_preserves_original_holds(tmp_path, fault):
    from financial_signing_acceptance import run_financial_signing

    run_financial_signing(tmp_path, fault=fault)


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("fault", [None, "lost_ack", "settlement_audit"])
def test_phase6gc_backend_original_native_sweep_finality_and_existing_ledger_fee(tmp_path, fault):
    from financial_finality_acceptance import run_financial_finality

    run_financial_finality(tmp_path, fault=fault)


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("incoming", ["legacy", "v0", "pda"])
def test_phase6gc_native_deposit_sweep_approved_withdrawal_single_ledger(tmp_path, incoming):
    from financial_native_acceptance import run_native_financial_flow

    run_native_financial_flow(tmp_path, incoming=incoming)


@pytest.mark.django_db(transaction=True)
def test_phase6gc_classic_token_publication_deposit_sweep_and_approved_withdrawals(tmp_path):
    from financial_token_acceptance import run_token_financial_flow

    run_token_financial_flow(tmp_path)


def test_phase6gc_current_claim_authority_recovers_original_prepare_and_candidate_aliases(tmp_path):
    from current_claim_authority_acceptance import run_current_claim_authority

    run_current_claim_authority(tmp_path)


def test_phase6gc_current_claim_receipts_refresh_restart_and_historical_spend(tmp_path):
    from current_claim_acceptance import run_current_claim

    run_current_claim(tmp_path)


def test_phase6gc_current_claim_receipts_cold_explicit_courier(tmp_path):
    from current_claim_acceptance import run_current_claim

    run_current_claim(tmp_path, custody_class="COLD")


def test_phase6gc_repaired_identity_current_claim_receipts_and_real_spend(tmp_path):
    from current_claim_acceptance import run_repaired_current_claim

    run_repaired_current_claim(tmp_path)


def test_phase6gc_repaired_identity_current_claim_cold_courier(tmp_path):
    from current_claim_acceptance import run_repaired_current_claim

    run_repaired_current_claim(tmp_path, custody_class="COLD")


def test_phase6gc_current_claim_storage_write_and_maintenance_faults(tmp_path):
    from current_claim_acceptance import run_current_claim_faults

    run_current_claim_faults(tmp_path)


def test_phase6gc_current_claim_upgrade_genuine_rules2_repaired_store(tmp_path):
    from current_claim_acceptance import run_historical_repair_upgrade

    run_historical_repair_upgrade(tmp_path)


@pytest.mark.django_db(transaction=True)
def test_phase6gc_current_claim_financial_publication_and_native_spl_execution_after_repair(tmp_path):
    from current_claim_financial_acceptance import run_current_claim_financial

    run_current_claim_financial(tmp_path)


@pytest.mark.parametrize(
    "fault",
    (
        "last_r2",
        "before_record",
        "first_r2",
        "round1",
        "client_disconnect",
        "coordinator_restart",
        "write_failure",
        "invalid_share",
    ),
)
def test_phase6gc_protected_coordinator_ambiguous_private_outcomes(tmp_path, fault):
    from protected_coordinator_acceptance import run_coordinator_fault

    run_coordinator_fault(tmp_path, fault)


def test_phase6gc_private_replacement_repair_refresh_and_restart(tmp_path):
    from repair_acceptance import run_repair

    run_repair(tmp_path)


def test_phase6gc_private_replacement_staging_failure_and_provenance_faults(tmp_path):
    from repair_acceptance import run_repair

    run_repair(tmp_path, faults=True)


def test_phase6gc_private_replacement_cold_courier_repair_refresh(tmp_path):
    from repair_acceptance import run_repair

    run_repair(tmp_path, custody_class="COLD")


def test_phase6gc_private_replacement_wrong_tls_peer_and_interrupted_retry(tmp_path):
    from repair_acceptance import run_private_fences

    run_private_fences(tmp_path)


def test_phase6gc_private_replacement_expiry_after_tls_before_private_body(tmp_path):
    from repair_acceptance import run_private_fences

    run_private_fences(tmp_path, delay=True)


def test_phase6gc_witness_independent_authorization_and_round_replay(tmp_path):
    from witness_acceptance import run_authorization

    run_authorization(tmp_path)


def test_phase6gc_witness_journal_restart_corruption_and_concurrency(tmp_path):
    from witness_acceptance import run_durability

    run_durability(tmp_path)


def test_phase6gc_witness_rust_transport_pins_before_sending_body(tmp_path):
    from witness_acceptance import run_transport_pin

    run_transport_pin(tmp_path)


def test_phase6gc_witness_claim_owner_survives_all_three_old_backups(tmp_path):
    from witness_acceptance import run_claim_rollback_fence

    run_claim_rollback_fence(tmp_path)


def test_phase6gc_witness_current_detached_pin_and_nonactive_key(tmp_path):
    from witness_acceptance import run_detached_node_pins

    run_detached_node_pins(tmp_path)


def test_phase6gc_protected_native_spending_all_pairs_and_restart(tmp_path):
    from protected_acceptance import run_native_pairs

    run_native_pairs(tmp_path)


def test_phase6gc_protected_cold_manual_signed_courier(tmp_path):
    from protected_acceptance import run_cold_courier

    run_cold_courier(tmp_path)


def test_phase6gc_protected_old_backup_and_partial_nonce_loss(tmp_path):
    from protected_acceptance import run_backup_and_partial

    run_backup_and_partial(tmp_path)


def test_phase6gc_protected_r2_unknown_recovery_and_journal_faults(tmp_path):
    from protected_acceptance import run_r2_uncertainty

    run_r2_uncertainty(tmp_path)


def test_phase6gc_protected_expired_permit_after_real_rpc_delay(tmp_path):
    from protected_acceptance import run_delayed_private_expiry

    run_delayed_private_expiry(tmp_path)


def test_phase6gc_protected_atomic_classic_spl_creation_and_all_pairs(tmp_path):
    from protected_acceptance import run_token_pairs

    run_token_pairs(tmp_path)


def test_phase6gc_protected_seeded_spl_treasury_sweep_and_external_transfer(tmp_path):
    from seeded_token_acceptance import run_seeded_token_sweeps

    run_seeded_token_sweeps(tmp_path)


def test_phase6gc_protected_warm_independent_approval_credentials(tmp_path):
    from protected_acceptance import run_warm_independent_credentials

    run_warm_independent_credentials(tmp_path)


def test_phase6gc_protected_full_nonce_queue_can_drain_round_two(tmp_path):
    from protected_acceptance import run_full_queue_drain

    run_full_queue_drain(tmp_path)


def test_phase6gc_distributed_refresh_original_identity_all_pairs_restart(tmp_path):
    from refresh_acceptance import run_refresh

    run_refresh(tmp_path)


def test_phase6gc_distributed_refresh_cold_manual_query_and_restart(tmp_path):
    from refresh_acceptance import run_refresh

    run_refresh(tmp_path, custody_class="COLD")


def test_phase6gc_distributed_refresh_interrupted_missing_generation_and_second_epoch(tmp_path):
    from refresh_acceptance import run_interrupted_refresh

    run_interrupted_refresh(tmp_path)


@pytest.mark.parametrize("grantees", [1, 2])
def test_phase6gc_terminal_no_release_all_actual_grantees_refresh_retry(tmp_path, grantees):
    from no_release_acceptance import run_close_unreleased

    run_close_unreleased(tmp_path, grantees)


def test_phase6gc_terminal_no_release_apply_cancellation_race(tmp_path):
    from no_release_acceptance import run_cancel_apply_race

    run_cancel_apply_race(tmp_path)


def test_phase6gc_terminal_no_release_rejects_withheld_durable_partial(tmp_path):
    from no_release_acceptance import run_durable_partial_cannot_cancel

    run_durable_partial_cannot_cancel(tmp_path)


def test_phase6gc_terminal_no_release_cold_manual_refresh_retry(tmp_path):
    from no_release_acceptance import run_close_unreleased

    run_close_unreleased(tmp_path, 2, custody_class="COLD")


@pytest.mark.django_db(transaction=True)
def test_phase6gc_genuine_native_wallet_publication_and_all_pair_spending(tmp_path):
    from native_issuance_acceptance import run_native_issuance

    run_native_issuance(tmp_path, 3)


@pytest.mark.django_db(transaction=True)
def test_phase6gc_genuine_one_thousand_native_wallets_actually_issued(tmp_path):
    from native_issuance_acceptance import run_native_issuance

    run_native_issuance(tmp_path, 1000)


def test_phase6gc_seeded_authenticated_immutable_store_approvals(tmp_path):
    from seeded_enrollment import run_approvals

    run_approvals(tmp_path)


def test_phase6gc_seeded_historical_signing_and_enrollment_race(tmp_path):
    from seeded_enrollment import run_historical_and_race

    run_historical_and_race(tmp_path)


def test_phase6gc_seeded_three_store_coordinator_agreement(tmp_path):
    from seeded_enrollment import run_coordinator_agreement

    run_coordinator_agreement(tmp_path)


@pytest.mark.django_db(transaction=True)
def test_phase6gc_seeded_authoritative_registry_and_partial_approvals(tmp_path):
    from seeded_registry import run_custody_registry

    run_custody_registry(tmp_path / "custody-registry")


def test_phase6gc_seeded_all_party_history_preflight_and_global_fence(tmp_path):
    from seeded_enrollment import run_global_history_preflight

    run_global_history_preflight(tmp_path)


@pytest.mark.parametrize("fault", ["role", "index", "alias"])
def test_phase6gc_seeded_corrupt_original_store_rejected(tmp_path, fault):
    from seeded_enrollment import run_corruption

    run_corruption(tmp_path, fault)


def import_root(binding):
    keyset = MpcKeyset.objects.create(
        keyset_id=binding["keyset_id"],
        algorithm="FROST_ED25519",
        curve="ed25519",
        scope="SOLANA",
        derivation_version="frost_keyset_v1",
        threshold=2,
        party_count=3,
    )
    call_command("mpc_keyset", "import-dkg", keyset_id=str(keyset.keyset_id))
    call_command("mpc_keyset", "activate", keyset_id=str(keyset.keyset_id))
    keyset.refresh_from_db()
    assert keyset.status == "ACTIVE" and not keyset.active_for_new_wallets
    return keyset, str(Pubkey.from_bytes(bytes.fromhex(keyset.public_key)))


def wait_signed(attempt):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        attempt.refresh_from_db()
        if attempt.status == "SIGNED":
            return attempt
        assert attempt.status in {"SIGNING", "RECONCILIATION_REQUIRED"}, (
            attempt.status,
            attempt.error_code,
        )
        execute_attempt(attempt.pk, "solana-acceptance")
        time.sleep(0.05)
    pytest.fail("genuine FROST custody signature unavailable")


def withdrawal(asset, destination, amount, suffix):
    user = "solana-acceptance-" + suffix
    ensure_accounts(user, asset)
    available = LedgerAccount.objects.get(owner_id=user, asset_key=asset, bucket="AVAILABLE")
    clearing = LedgerAccount.objects.get(
        owner_type="SYSTEM", asset_key=asset, bucket="CUSTODY_CLEARING"
    )
    post_transaction(
        event_key=user + ":fund",
        event_type="DEPOSIT_CREDIT",
        asset_key=asset,
        ref_type="Acceptance",
        ref_id=user,
        postings=[(available, Decimal(100)), (clearing, Decimal(-100))],
    )
    operation = create_request(
        user, "SOL", destination, amount, asset_key=asset, idempotency_key=user
    )
    approve("acceptance-reviewer", operation.pk)
    process_withdrawal("acceptance-reviewer", operation.pk)
    return operation, wait_signed(
        OnchainTransactionAttempt.objects.get(
            operation_type="WITHDRAWAL", operation_id=operation.pk
        )
    )


def settle(validator, attempt, expected="CONFIRMED"):
    validator.wait(attempt.network_tx_id)
    initial_status = OnchainTransactionAttempt.objects.get(pk=attempt.pk).status

    def worker(_):
        close_old_connections()
        try:
            return reconcile_attempt(attempt.pk)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(worker, range(2)))
    # The non-owner returns its current snapshot while the owner settles.
    assert any(result.status == expected for result in results), [
        (result.status, result.error_code, result.confirmation_metadata) for result in results
    ]
    assert all(result.status in {expected, initial_status} for result in results)
    result = OnchainTransactionAttempt.objects.get(pk=attempt.pk)
    assert result.status == expected, (result.error_code, result.confirmation_metadata)
    assert reconcile_attempt(attempt.pk).status == expected
    assert result.confirmation_metadata["finalized"]
    return result


def public_signing(attempt):
    session = MpcSigningSession.objects.select_related("keyset").get(attempt=attempt)
    return {
        "signature": attempt.network_tx_id,
        "session_id": str(session.session_id),
        "execution_id": str(session.crypto_execution_id),
        "signers": session.selected_signers,
        "dkg_fingerprint": session.keyset.dkg_result_fingerprint,
        "public_key": session.keyset.public_key,
        "signed_bytes_sha256": hashlib.sha256(bytes.fromhex(attempt.signed_payload)).hexdigest(),
        "finalization": attempt.confirmation_metadata,
    }


@pytest.mark.django_db(transaction=True)
def test_genuine_solana_frost_custody_and_recovery(tmp_path):
    assert connection.vendor == "postgresql"
    net = Processes(tmp_path / "services")
    validator = None
    evidence = {"transactions": [], "deposits": [], "validator_version": "Agave 2.1.21"}
    started = time.monotonic()
    try:
        for role in ROLES[:4]:
            net.start(role)
        hot_binding, deposit_binding = dkg_request(), dkg_request()
        for binding in (hot_binding, deposit_binding):
            status, result = execute(net, binding)
            assert status == 200 and result["status"] == "COMPLETED"
        validator = Validator(tmp_path / "validator")
        evidence["network"] = validator.policy
        with (
            settings_for(net),
            patch.dict(os.environ, {"CUSTODY_INDEXER_MODE": "live"}),
            override_settings(
                MPC_SIGNER_BACKEND="self_hosted_mpc",
                MPC_SOLANA_INTEGRATION_ENABLED=True,
                MPC_SOLANA_NETWORK=validator.policy,
                MPC_EVM_INTEGRATION_ENABLED=False,
                MPC_TRON_INTEGRATION_ENABLED=False,
                MPC_INTEGRATION_ENVIRONMENT="development",
                CUSTODY_DEMO_MODE=False,
                CUSTODY_TX_MODE="live",
                CUSTODY_INDEXER_MODE="live",
            ),
        ):
            hot_keyset, hot = import_root(hot_binding)
            deposit_keyset, deposit = import_root(deposit_binding)
            Chain.objects.filter(chain_id="SOL").update(
                kind="solana",
                is_testnet=True,
                enabled=True,
                evm_chain_id=None,
                native_asset_key="SOL",
                min_confirmations=1,
                sweep_threshold=Decimal("0.001"),
                gas_settings=CAPS,
            )
            NodeEndpoint.objects.filter(chain_id="SOL", kind="rpc").update(enabled=False)
            NodeEndpoint.objects.create(
                chain_id="SOL",
                name="genuine-local-sol",
                kind="rpc",
                url=validator.url,
                enabled=True,
            )
            HotWallet.objects.filter(chain_id="SOL").update(
                address=hot, mpc_keyset=None, signing_key_ref=None
            )
            call_command("bind_mpc_hot_wallet", chain="SOL", keyset_id=str(hot_keyset.keyset_id))
            recipient = str(Keypair().pubkey())
            validator.fund(hot, 50 * 10**9)
            validator.fund(recipient, 10**9)
            # A registered address with a local key is not FROST custody authority.
            UserWallet.objects.create(
                user_id="unbound-gas-recipient",
                chain_id="SOL",
                asset_key="SOL",
                deposit_address=recipient,
                derivation_path="unbound",
            )
            sessions_before = MpcSigningSession.objects.count()
            with (
                patch.object(SelfHostedMpcAdapter, "create_signing_session") as create_session,
                patch.object(SelfHostedMpcAdapter, "execute_signing_session") as execute_session,
                patch("custody.native_tx.SolanaNativeExecutor.broadcast") as broadcast,
            ):
                with pytest.raises(ValueError, match="no explicit MPC keyset"):
                    admin_topup("admin", "SOL", recipient, Decimal("0.01"), "unbound-gas")
                create_session.assert_not_called()
                execute_session.assert_not_called()
                broadcast.assert_not_called()
            assert MpcSigningSession.objects.count() == sessions_before
            assert not MpcSigningSession.objects.filter(
                attempt__operation_type="GAS_TOPUP"
            ).exists()
            evidence["unauthorized_gas_funding"] = {
                "registered_unbound_destination_rejected": True,
                "signing_session_count": 0,
                "mpc_execution_count": 0,
                "broadcast_count": 0,
            }
            # Genuine Django signing verifies every independent pair.
            original_execute = SelfHostedMpcAdapter.execute_signing_session
            signing_calls = []

            def concurrent_signing(adapter, session_id):
                session = MpcSigningSession.objects.get(session_id=session_id)

                def competitor():
                    close_old_connections()
                    try:
                        return advance_mpc_signing(session.attempt_id).status
                    finally:
                        close_old_connections()

                with ThreadPoolExecutor(max_workers=1) as workers:
                    assert workers.submit(competitor).result(timeout=15) == "SIGNING"
                signing_calls.append(session_id)
                return original_execute(adapter, session_id)

            for suffix, stop, pair in (
                ("ab", "signer-c", ["signer-a", "signer-b"]),
                ("ac", "signer-b", ["signer-a", "signer-c"]),
                ("bc", "signer-a", ["signer-b", "signer-c"]),
            ):
                net.stop(stop)
                try:
                    with patch.object(
                        SelfHostedMpcAdapter, "execute_signing_session", concurrent_signing
                    ):
                        operation, attempt = withdrawal("SOL", recipient, Decimal("0.01"), suffix)
                    assert MpcSigningSession.objects.get(attempt=attempt).selected_signers == pair
                    execute_attempt(attempt.pk, "worker")
                    attempt = settle(validator, attempt)
                    assert user_balances(operation.user_id, "SOL")["reserved"] == 0
                    evidence["transactions"].append(public_signing(attempt))
                finally:
                    net.start(stop)
            assert len(signing_calls) == len(set(signing_calls)) == 3
            evidence["concurrent_signing"] = {"owned_execution_count": 3, "competing_workers": 2}
            evidence["concurrent_reconciliation_workers"] = 2
            # External native deposit and genuine root-bound sweep.
            native_wallet = UserWallet.objects.create(
                user_id="sol-deposit",
                chain_id="SOL",
                asset_key="SOL",
                deposit_address=deposit,
                derivation_path=f"keyset:{deposit_keyset.keyset_id}",
                derivation_version="mpc_root_v1",
                mpc_keyset=deposit_keyset,
            )
            from solders.system_program import TransferParams, transfer

            signature = validator.send(
                [
                    transfer(
                        TransferParams(
                            from_pubkey=validator.faucet.pubkey(),
                            to_pubkey=Pubkey.from_string(deposit),
                            lamports=300_000_000,
                        )
                    ),
                    transfer(
                        TransferParams(
                            from_pubkey=validator.faucet.pubkey(),
                            to_pubkey=Pubkey.from_string(deposit),
                            lamports=700_000_000,
                        )
                    ),
                ]
            )
            balance = SolIndexer().get_balance(deposit, asset_key="SOL")
            assert {ev.tx_hash for ev in balance.deposit_events} == {signature}
            for _ in range(2):
                for ev in balance.deposit_events:
                    ingest_event(native_wallet, ev)
            assert user_balances(native_wallet.user_id, "SOL")["available"] == 1
            evidence["deposits"].append(
                {
                    "signature": signature,
                    "asset": "SOL",
                    "credit_count": 2,
                    "event_indices": [ev.event_index for ev in balance.deposit_events],
                }
            )
            triggered, job_id, reason = trigger_sweep(native_wallet, "acceptance", balance)
            assert triggered, reason
            sweep = wait_signed(
                OnchainTransactionAttempt.objects.get(operation_type="SWEEP", operation_id=job_id)
            )
            execute_attempt(sweep.pk, "worker")
            sweep = settle(validator, sweep)
            evidence["transactions"].append(public_signing(sweep))
            # Classic token mint is independently configured; no USDT symbol assumption.
            validator.create_mint()
            mint = str(validator.mint.pubkey())
            evidence["mint"] = mint
            asset = Asset.objects.create(
                asset_key="SOL-ACCEPT-CLASSIC",
                chain_id="SOL",
                symbol="REVIEWED",
                decimals=6,
                is_native=False,
                token_standard="SPL",
                contract_address=mint,
                enabled=True,
                deposit_supported=True,
                withdrawal_supported=True,
                sweep_supported=True,
                deposit_threshold=Decimal("0.001"),
            )
            verify_token_asset(asset.asset_key)
            validator.mint_to(hot, 100_000_000)
            validator.mint_to(str(validator.faucet.pubkey()), 100_000_000)
            # Recipient ATA absent; same single-signature message creates it idempotently.
            assert (
                validator.rpc(
                    "getAccountInfo", [derive_ata(recipient, mint), {"encoding": "base64"}]
                )["value"]
                is None
            )
            operation, token = withdrawal(asset.asset_key, recipient, Decimal("1.25"), "token")
            assert token.prepared_metadata["createDestinationAta"] is True
            session = MpcSigningSession.objects.get(attempt=token)
            original_identity = (
                session.session_id,
                session.crypto_execution_id,
                token.signed_payload,
                token.network_tx_id,
            )
            for role in ("coordinator", "signer-a", "signer-b"):
                net.stop(role)
                net.start(role)
            original_rpc = RequestsTransport.rpc
            sends = []

            def lost_response(transport, url, method, params):
                result = original_rpc(transport, url, method, params)
                if method == "sendTransaction":
                    sends.append(params[0])
                    raise requests.Timeout("lost response after validator accepted original bytes")
                return result

            with patch.object(RequestsTransport, "rpc", lost_response):
                with pytest.raises(AmbiguousBroadcast):
                    execute_attempt(token.pk, "worker")
                assert execute_attempt(token.pk, "worker").status == "RECONCILIATION_REQUIRED"
            assert len(sends) == 1 and user_balances(operation.user_id, asset.asset_key)[
                "reserved"
            ] == Decimal("1.25")
            deadline = time.monotonic() + 90
            while (
                validator.rpc("getBlockHeight", [{"commitment": "finalized"}])
                <= token.last_valid_block
            ):
                assert time.monotonic() < deadline
                time.sleep(0.2)

            def pruned_history(transport, url, method, params):
                if method == "getSignatureStatuses":
                    return {"value": [None]}
                if method == "getTransaction":
                    return None
                return original_rpc(transport, url, method, params)

            with patch.object(RequestsTransport, "rpc", pruned_history):
                unresolved = reconcile_attempt(token.pk)
                assert unresolved.status == "RECONCILIATION_REQUIRED"
                assert user_balances(operation.user_id, asset.asset_key)["reserved"] == Decimal(
                    "1.25"
                )
                assert execute_attempt(token.pk, "worker").status == "RECONCILIATION_REQUIRED"
                assert MpcSigningSession.objects.filter(attempt=token).count() == 1
            evidence["expired_accepted_pruned_history"] = {
                "signature": token.network_tx_id,
                "reservation_retained": True,
                "session_id": str(session.session_id),
                "execution_id": str(session.crypto_execution_id),
                "new_execution_count": 0,
            }
            token = settle(validator, token)
            session.refresh_from_db()
            assert (
                session.session_id,
                session.crypto_execution_id,
                token.signed_payload,
                token.network_tx_id,
            ) == original_identity
            assert (
                LedgerTransaction.objects.filter(
                    event_key=f"withdrawal:{operation.pk}:settle"
                ).count()
                == 1
            )
            assert (
                LedgerTransaction.objects.filter(event_key=f"solana:{token.pk}:ata_rent").count()
                == 1
            )
            evidence["transactions"].append(public_signing(token))
            # External SPL deposit and durable source-native fee grant before sweep.
            token_wallet = UserWallet.objects.create(
                user_id="sol-deposit",
                chain_id="SOL",
                asset_key=asset.asset_key,
                deposit_address=deposit,
                asset_account_address=derive_ata(deposit, mint),
                derivation_path=f"keyset:{deposit_keyset.keyset_id}",
                derivation_version="mpc_root_v1",
                mpc_keyset=deposit_keyset,
            )
            signature = validator.token_transfer(deposit, 2_500_000)
            balance = SolIndexer().get_balance(deposit, asset_key=asset.asset_key)
            assert [ev.tx_hash for ev in balance.deposit_events] == [signature]
            for _ in range(2):
                for ev in balance.deposit_events:
                    ingest_event(token_wallet, ev)
            assert user_balances(token_wallet.user_id, asset.asset_key)["available"] == Decimal(
                "2.5"
            )
            evidence["deposits"].append(
                {"signature": signature, "asset": asset.asset_key, "credit_count": 1}
            )
            triggered, job_id, reason = trigger_sweep(token_wallet, "acceptance", balance)
            assert triggered, reason
            job = SweepJob.objects.get(pk=job_id)
            assert job.gas_topup_intent_id
            gas = wait_signed(
                OnchainTransactionAttempt.objects.get(
                    operation_type="GAS_TOPUP", operation_id=job.gas_topup_intent_id
                )
            )
            execute_attempt(gas.pk, "worker")
            gas = settle(validator, gas)
            evidence["authorized_gas_funding"] = public_signing(gas)
            execute_gas_intent(job.gas_topup_intent_id)
            funding_observation = SolIndexer().get_balance(deposit, asset_key="SOL")
            assert all(ev.tx_hash != gas.network_tx_id for ev in funding_observation.deposit_events)
            evidence["internal_grant_customer_credit_count"] = 0
            advance_sweep(job_id)
            token_sweep = wait_signed(
                OnchainTransactionAttempt.objects.get(operation_type="SWEEP", operation_id=job_id)
            )
            # Competing workers share one physical exact-byte broadcast.
            entered, release = threading.Event(), threading.Event()
            sends = []

            def blocked(transport, url, method, params):
                if method == "sendTransaction":
                    sends.append(params[0])
                    entered.set()
                    assert release.wait(15)
                return original_rpc(transport, url, method, params)

            def worker():
                close_old_connections()
                try:
                    return execute_attempt(token_sweep.pk, "worker").status
                finally:
                    close_old_connections()

            with (
                patch.object(RequestsTransport, "rpc", blocked),
                ThreadPoolExecutor(max_workers=2) as pool,
            ):
                first = pool.submit(worker)
                assert entered.wait(15)
                assert pool.submit(worker).result(timeout=15) == "BROADCASTING"
                release.set()
                assert first.result(timeout=15) == "BROADCASTED"
            assert len(sends) == 1
            token_sweep = settle(validator, token_sweep)
            assert (
                SolIndexer().get_balance(deposit, asset_key=asset.asset_key).confirmed_balance == 0
            )
            evidence["transactions"].extend([public_signing(gas), public_signing(token_sweep)])
            failed_operation, failed = withdrawal(
                "SOL", recipient, Decimal("0.01"), "finalized-failure"
            )
            lamports = validator.rpc("getBalance", [hot, {"commitment": "finalized"}])["value"]
            drain_amount = Decimal(lamports - 1005000) / (10**9)
            _, drain = withdrawal("SOL", recipient, drain_amount, "drain-for-failure")
            execute_attempt(drain.pk, "worker")
            drain = settle(validator, drain)

            def inject_finalized_failure(transport, url, method, params):
                if method == "sendTransaction":
                    # Deliberately force actual runtime inclusion of an insufficient-balance
                    # transaction. The signed bytes and production preflight policy are unchanged.
                    params = [params[0], {**params[1], "skipPreflight": True}]
                return original_rpc(transport, url, method, params)

            with patch.object(RequestsTransport, "rpc", inject_finalized_failure):
                execute_attempt(failed.pk, "worker")
            failed = settle(validator, failed, expected="FAILED")
            assert user_balances(failed_operation.user_id, "SOL")["reserved"] == 0
            assert (
                LedgerTransaction.objects.filter(
                    event_key=f"withdrawal:{failed_operation.pk}:release"
                ).count()
                == 1
            )
            evidence["transactions"].extend([public_signing(drain), public_signing(failed)])
            validator.fund(hot, 5 * 10**9)
            # Genuine signer unavailability cannot allocate a replacement execution.
            net.stop("signer-b")
            net.stop("signer-c")
            try:
                user = "solana-unavailable"
                ensure_accounts(user, "SOL")
                available = LedgerAccount.objects.get(
                    owner_id=user, asset_key="SOL", bucket="AVAILABLE"
                )
                clearing = LedgerAccount.objects.get(
                    owner_type="SYSTEM", asset_key="SOL", bucket="CUSTODY_CLEARING"
                )
                post_transaction(
                    event_key=user + ":fund",
                    event_type="DEPOSIT_CREDIT",
                    asset_key="SOL",
                    ref_type="Acceptance",
                    ref_id=user,
                    postings=[(available, Decimal(1)), (clearing, Decimal(-1))],
                )
                unavailable_operation = create_request(
                    user, "SOL", recipient, Decimal("0.01"), idempotency_key=user
                )
                approve("acceptance-reviewer", unavailable_operation.pk)
                process_withdrawal("acceptance-reviewer", unavailable_operation.pk)
                unavailable = OnchainTransactionAttempt.objects.get(
                    operation_type="WITHDRAWAL", operation_id=unavailable_operation.pk
                )
                assert (
                    unavailable.status == "RECONCILIATION_REQUIRED"
                    and not unavailable.signed_payload
                )
                original_session = MpcSigningSession.objects.get(attempt=unavailable)
                execute_attempt(unavailable.pk, "worker")
                original_session.refresh_from_db()
                assert MpcSigningSession.objects.filter(attempt=unavailable).count() == 1
                evidence["unavailable_signers"] = {
                    "session_id": str(original_session.session_id),
                    "execution_id": str(original_session.crypto_execution_id),
                    "reservation_retained": user_balances(user, "SOL")["reserved"]
                    == Decimal("0.01"),
                    "new_execution_count": 0,
                }
            finally:
                net.start("signer-b")
                net.start("signer-c")
            evidence["ledger_counts"] = {
                "network_fee": LedgerTransaction.objects.filter(event_type="NETWORK_FEE").count(),
                "ata_rent": LedgerTransaction.objects.filter(event_type="ATA_RENT").count(),
                "withdrawal_settle": LedgerTransaction.objects.filter(
                    event_type="WITHDRAWAL_SETTLE"
                ).count(),
            }
    finally:
        if validator:
            validator.close()
        net.close()
        evidence["wall_seconds"] = round(time.monotonic() - started, 3)
        (tmp_path / "solana-evidence.json").write_text(json.dumps(evidence, indent=2))
    print("REAL_SOLANA_ACCEPTANCE", json.dumps(evidence, sort_keys=True))


@pytest.mark.django_db(transaction=True)
def test_genuine_nonce_loss_and_expiration_preserve_owned_execution(tmp_path):
    """Kill a real selected signer after another signer durably generated nonces."""
    net = Processes(tmp_path / "services")
    validator = None
    evidence = {}
    try:
        for role in ROLES[:4]:
            net.start(role)
        binding = dkg_request()
        status, dkg = execute(net, binding)
        assert status == 200 and dkg["status"] == "COMPLETED"
        validator = Validator(tmp_path / "validator")
        with (
            settings_for(net),
            patch.dict(os.environ, {"CUSTODY_INDEXER_MODE": "live"}),
            override_settings(
                MPC_SIGNER_BACKEND="self_hosted_mpc",
                MPC_SOLANA_INTEGRATION_ENABLED=True,
                MPC_SOLANA_NETWORK=validator.policy,
                MPC_EVM_INTEGRATION_ENABLED=False,
                MPC_TRON_INTEGRATION_ENABLED=False,
                MPC_INTEGRATION_ENVIRONMENT="development",
                CUSTODY_DEMO_MODE=False,
                CUSTODY_TX_MODE="live",
                CUSTODY_INDEXER_MODE="live",
            ),
        ):
            keyset, hot = import_root(binding)
            Chain.objects.filter(chain_id="SOL").update(
                kind="solana",
                is_testnet=True,
                enabled=True,
                evm_chain_id=None,
                native_asset_key="SOL",
                min_confirmations=1,
                gas_settings=CAPS,
            )
            NodeEndpoint.objects.filter(chain_id="SOL", kind="rpc").update(enabled=False)
            NodeEndpoint.objects.create(
                chain_id="SOL",
                name="nonce-expiry-local",
                kind="rpc",
                url=validator.url,
                enabled=True,
            )
            HotWallet.objects.filter(chain_id="SOL").update(
                address=hot, mpc_keyset=keyset, signing_key_ref=f"keyset:{keyset.keyset_id}"
            )
            validator.fund(hot, 5 * 10**9)
            user = "nonce-expiry-customer"
            ensure_accounts(user, "SOL")
            available = LedgerAccount.objects.get(
                owner_id=user, asset_key="SOL", bucket="AVAILABLE"
            )
            clearing = LedgerAccount.objects.get(
                owner_type="SYSTEM", asset_key="SOL", bucket="CUSTODY_CLEARING"
            )
            post_transaction(
                event_key=user + ":fund",
                event_type="DEPOSIT_CREDIT",
                asset_key="SOL",
                ref_type="Acceptance",
                ref_id=user,
                postings=[(available, Decimal(1)), (clearing, Decimal(-1))],
            )
            operation = create_request(
                user, "SOL", str(Keypair().pubkey()), Decimal("0.01"), idempotency_key=user
            )
            approve("acceptance-reviewer", operation.pk)
            observed = threading.Event()
            captured = []
            stop_watcher = threading.Event()

            def stop_after_nonce():
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline and not stop_watcher.is_set():
                    for path in (net.root / "signer-a/storage/signing").glob("*.json"):
                        report = json.loads(path.read_text())
                        if report["status"] == "NONCES_CREATED":
                            captured.append(report["execution"]["crypto_execution_id"])
                            net.stop("signer-a")
                            net.stop("signer-b")
                            observed.set()
                            return
                    time.sleep(0.0001)

            watcher = threading.Thread(target=stop_after_nonce, daemon=True)
            watcher.start()
            try:
                process_withdrawal("acceptance-reviewer", operation.pk)
                assert observed.wait(10), (
                    "nonce-loss injection did not observe real durable nonce creation"
                )
            finally:
                stop_watcher.set()
                watcher.join(timeout=15)
            attempt = OnchainTransactionAttempt.objects.get(
                operation_type="WITHDRAWAL", operation_id=operation.pk
            )
            assert attempt.status == "RECONCILIATION_REQUIRED" and not attempt.signed_payload
            session = MpcSigningSession.objects.get(attempt=attempt)
            original = (
                session.session_id,
                session.crypto_execution_id,
                bytes(session.signing_payload),
                attempt.prepared_metadata,
            )
            assert str(session.crypto_execution_id) == captured[0]
            net.start("signer-a")
            net.start("signer-b")
            net.stop("coordinator")
            net.start("coordinator")
            deadline = time.monotonic() + 90
            while (
                validator.rpc("getBlockHeight", [{"commitment": "finalized"}])
                <= attempt.last_valid_block
            ):
                assert time.monotonic() < deadline
                time.sleep(0.2)
            for _ in range(2):
                assert execute_attempt(attempt.pk, "recovery").status == "RECONCILIATION_REQUIRED"
            attempt.refresh_from_db()
            session.refresh_from_db()
            assert (
                session.session_id,
                session.crypto_execution_id,
                bytes(session.signing_payload),
                attempt.prepared_metadata,
            ) == original
            assert MpcSigningSession.objects.filter(attempt=attempt).count() == 1
            assert user_balances(user, "SOL")["reserved"] == Decimal("0.01")
            for party in ("signer-a", "signer-b"):
                ids = {
                    json.loads(path.read_text())["execution"]["crypto_execution_id"]
                    for path in (net.root / party / "storage/signing").glob("*.json")
                }
                assert ids.issubset({captured[0]})
            evidence = {
                "session_id": str(session.session_id),
                "execution_id": str(session.crypto_execution_id),
                "dkg_fingerprint": keyset.dkg_result_fingerprint,
                "nonce_creation_observed": True,
                "expired_during_uncertain_frost_execution": True,
                "coordinator_restart": True,
                "new_execution_count": 0,
                "reservation_retained": True,
            }
    finally:
        if validator:
            validator.close()
        net.close()
        (tmp_path / "solana-evidence.json").write_text(json.dumps(evidence, indent=2))


def test_phase6gc_seeded_wire_primitive_spendability(tmp_path):
    from seeded_acceptance import run_seeded_spendability

    run_seeded_spendability(tmp_path / "seeded-primitive")
