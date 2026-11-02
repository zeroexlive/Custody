"""Actual native deposit -> MPC sweep -> approved MPC withdrawal, one ledger."""

import json
import os
from decimal import Decimal
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from custody.ledger import user_balances
from custody.models import (
    Deposit,
    LedgerPosting,
    LedgerTransaction,
    MpcSolanaDepositProvenance,
    SweepJob,
)
from custody.solana_financial_deposits import (
    register_operator_funding_source,
    scan_financial_wallet,
)
from custody.solana_financial_outbound import broadcast_session, reconcile_finality
from custody.solana_financial_preparation import _content, approve_session, prepare_session
from custody.solana_financial_sessions import (
    allocate_session,
    allocate_sweep,
    allocate_withdrawal,
    request_query,
)
from custody.solana_financial_signing import execute_session
from custody.solana_witness_client import query_witness
from custody.withdrawals import approve, create_request
from django.db.models import Sum
from django.test import override_settings
from environment import private_file
from financial_wallet_acceptance import run_financial_wallets
from ops.models import Chain
from protected_coordinator_acceptance import enable_coordinator
from solana_local.cpi_deposit import deploy_fixture, pda_transfer
from solana_local.incoming import external_transfer
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from test_dkg import encrypted_files


def run_native_financial_flow(root_path, *, incoming="legacy"):
    def complete(g, root_path, tenant, records):
        native_financial_flow(g, root_path, tenant, records, incoming=incoming)

    run_financial_wallets(root_path, after_wallets=complete, freeze_before_completion=False)


def _finish(
    g,
    tenant,
    operation,
    pair,
    *,
    expected_source,
    expected_destination,
    expected_units,
    expected_action=None,
):
    row = allocate_session(
        reservation_id=operation.pk,
        tenant_id=tenant.pk,
        selected_signers=list(pair),
        operator_ref="integration",
    )

    def fresh():
        request = request_query(
            session_id=row.pk, tenant_id=tenant.pk, purpose="ADMISSION", operator_ref="integration"
        )
        return request, query_witness(request["query"])

    request, proof = fresh()
    row = prepare_session(
        session_id=row.pk,
        tenant_id=tenant.pk,
        challenge=request["query"]["challenge"],
        evidence=proof,
        operator_ref="integration",
    )
    # The independent test Policy driver checks the intended economic action;
    # it does not blindly approve an arbitrary backend payload.
    assert row.intent["financial_source"] == expected_source
    if expected_action is None:
        assert row.intent["action"]["destination"] == expected_destination
    else:
        assert row.intent["action"] == expected_action
    assert int(row.intent["action"].get("amount", 0)) == expected_units
    assert row.intent["expected_fee_lamports"] == 5000
    cert = x509.load_pem_x509_certificate((g.w.policy / "tls.crt").read_bytes())
    # Independent test driver, not backend configuration, owns this Policy key.
    policy_key = serialization.load_pem_private_key((g.w.policy / "tls.key").read_bytes(), None)
    grant = {
        "certificate_chain_der_hex": [cert.public_bytes(serialization.Encoding.DER).hex()],
        "signature_der_hex": policy_key.sign(
            b"Wallet-MPC/OPERATOR_SEEDED_SPEND_V1\0" + _content(row), ec.ECDSA(hashes.SHA256())
        ).hex(),
    }
    request, proof = fresh()
    row = approve_session(
        session_id=row.pk,
        tenant_id=tenant.pk,
        challenge=request["query"]["challenge"],
        evidence=proof,
        policy_authorization=grant,
        operator_ref="integration",
    )
    request, proof = fresh()
    row = execute_session(
        session_id=row.pk,
        tenant_id=tenant.pk,
        challenge=request["query"]["challenge"],
        evidence=proof,
        operator_ref="integration",
    )
    assert row.status == "COMPLETED"
    result = broadcast_session(session_id=row.pk, tenant_id=tenant.pk, operator_ref="integration")
    assert result.status == "BROADCASTED"
    g.validator.wait(result.network_tx_id)
    result = reconcile_finality(session_id=row.pk, tenant_id=tenant.pk, operator_ref="integration")
    assert result.status == "CONFIRMED"
    assert (
        reconcile_finality(
            session_id=row.pk, tenant_id=tenant.pk, operator_ref="integration"
        ).status
        == "CONFIRMED"
    )
    return row, result


def native_financial_flow(g, root_path, tenant, records, *, incoming):
    customer, treasury = records
    ciphertexts = encrypted_files(g.net, g.dkg_binding)
    original_journals = LedgerTransaction.objects.count()
    owner = customer.claim.principal.ledger_owner_id
    assert user_balances(owner, "SOL")["total"] == 0
    Chain.objects.filter(chain_id="SOL").update(gas_settings={"max_fee_lamports": "20000"})
    g.validator.fund(customer.claim.root.base_address, 200_000_000)
    pins = {party: [str(identity / "tls.crt")] for party, identity in g.w.node.items()}
    with (
        override_settings(
            MPC_SOLANA_SEEDED_DEPOSITS_ENABLED=True,
            MPC_SOLANA_WITNESS_URL=f"https://localhost:{g.w.port}",
            MPC_SOLANA_WITNESS_CA_CERT=str(g.w.identity / "ca.crt"),
            MPC_SOLANA_WITNESS_COURIER_CERT=str(g.w.courier / "tls.crt"),
            MPC_SOLANA_WITNESS_COURIER_KEY=str(g.w.courier / "tls.key"),
            MPC_SOLANA_FINANCIAL_POLICY_CERTIFICATE=str(g.w.policy / "tls.crt"),
            MPC_SOLANA_FINANCIAL_POLICY_VERSION=7,
            MPC_SOLANA_FINANCIAL_MAX_LIFETIME_SECONDS=120,
            MPC_SOLANA_FINANCIAL_SIGNER_CERTIFICATES=pins,
            MPC_REQUEST_TIMEOUT_SECONDS=30,
        ),
        patch.dict(os.environ, {"CUSTODY_INDEXER_MODE": "live"}),
    ):
        register_operator_funding_source(
            address=str(g.validator.faucet.pubkey()),
            reference="isolated-operator-faucet",
            operator_ref="integration",
        )
        # Known operator principal is swept but never creates a USER liability.
        g.validator.fund(customer.claim.address, 1_000_000)
        if incoming == "pda":
            fixture = deploy_fixture(g.validator, root_path / "external-pda-program")
            g.validator.fund(str(fixture[1]), 20_000_000)
            signature = pda_transfer(g.validator, fixture, customer.claim.address, 10_000_000)
        else:
            sender = Keypair()
            g.validator.fund(str(sender.pubkey()), 20_000_000)
            signature = external_transfer(
                g.validator,
                sender,
                customer.claim.address,
                10_000_000,
                versioned=incoming == "v0",
                directory=root_path / "external-alt",
            )
        scan_args = dict(
            user_wallet_id=customer.user_wallet_id, tenant_id=tenant.pk, operator_ref="integration"
        )
        observed = scan_financial_wallet(**scan_args)
        assert observed.scan_complete and observed.confirmed_balance == Decimal("0.011")
        assert scan_financial_wallet(**scan_args).scan_complete
        accepted = Deposit.objects.get(user_wallet_id=customer.user_wallet_id, tx_hash=signature)
        assert accepted.status == "CONFIRMED" and accepted.amount == Decimal("0.01")
        assert MpcSolanaDepositProvenance.objects.get(deposit=accepted).signature == signature
        assert user_balances(owner, "SOL") == {
            "available": Decimal("0.01"),
            "reserved": 0,
            "total": Decimal("0.01"),
        }
        assert LedgerTransaction.objects.count() == original_journals + 1
        sweep = SweepJob.objects.create(
            user_wallet=customer.user_wallet,
            asset_key="SOL",
            balance_snapshot=observed.confirmed_balance,
            idempotency_key="actual-observed-customer-sweep",
        )
        operation = allocate_sweep(
            sweep_id=sweep.pk,
            destination_id=treasury.pk,
            tenant_id=tenant.pk,
            fee_budget_lamports=20_000,
            operator_ref="integration",
        )
        enable_coordinator(g, root_path)
        pairs = {
            "legacy": (["signer-a", "signer-b"], ["signer-a", "signer-c"]),
            "v0": (["signer-b", "signer-c"], ["signer-a", "signer-b"]),
            "pda": (["signer-a", "signer-c"], ["signer-b", "signer-c"]),
        }
        _, sweep_attempt = _finish(
            g,
            tenant,
            operation,
            pairs[incoming][0],
            expected_source=customer.claim.address,
            expected_destination=treasury.claim.address,
            expected_units=11_000_000,
        )
        assert user_balances(owner, "SOL")["total"] == Decimal("0.01")
        assert not LedgerPosting.objects.filter(
            transaction__ref_type="SweepJob", account__owner_type="USER"
        ).exists()
        destination = str(Pubkey.new_unique())
        withdrawal = create_request(
            owner,
            "SOL",
            destination,
            Decimal("0.002"),
            asset_key="SOL",
            idempotency_key="actual-customer-native-withdrawal",
        )
        assert user_balances(owner, "SOL")["reserved"] == Decimal("0.002")
        assert approve("independent-admin", withdrawal.pk).status == "APPROVED"
        operation = allocate_withdrawal(
            withdrawal_id=withdrawal.pk,
            source_id=treasury.pk,
            tenant_id=tenant.pk,
            fee_budget_lamports=20_000,
            operator_ref="integration",
        )
        _, withdrawal_attempt = _finish(
            g,
            tenant,
            operation,
            pairs[incoming][1],
            expected_source=treasury.claim.address,
            expected_destination=destination,
            expected_units=2_000_000,
        )
        assert user_balances(owner, "SOL") == {
            "available": Decimal("0.008"),
            "reserved": 0,
            "total": Decimal("0.008"),
        }
        balances = {
            label: g.validator.rpc("getBalance", [address, {"commitment": "finalized"}])["value"]
            for label, address in {
                "customer": customer.claim.address,
                "treasury": treasury.claim.address,
                "recipient": destination,
                "base": customer.claim.root.base_address,
            }.items()
        }
        assert balances == {
            "customer": 0,
            "treasury": 9_000_000,
            "recipient": 2_000_000,
            "base": 199_990_000,
        }
        assert (
            Decimal(balances["treasury"] - 1_000_000) / Decimal(10**9)
            == user_balances(owner, "SOL")["total"]
        )
        assert LedgerTransaction.objects.count() == original_journals + 5
        for attempt in [sweep_attempt, withdrawal_attempt]:
            journal = LedgerTransaction.objects.get(event_key=f"solana:{attempt.pk}:network_fee")
            assert (
                journal.postings.count() == 2
                and journal.postings.aggregate(total=Sum("amount"))["total"] == 0
            )
        assert LedgerPosting.objects.aggregate(total=Sum("amount"))["total"] == 0
        assert encrypted_files(g.net, g.dkg_binding) == ciphertexts
        private_file(
            root_path / f"solana-native-financial-{incoming}-public-evidence.json",
            json.dumps(
                {
                    "scope": (
                        "actual finalized incoming native provenance, genuine MPC sweep "
                        "and manually approved MPC withdrawal through existing authoritative "
                        "ledger; isolated validator only"
                    ),
                    "incoming_kind": incoming,
                    "actual_external_incoming_signature_and_finalized_block_verified": True,
                    "operator_funding_lamports_excluded_from_user_liability": 1_000_000,
                    "external_customer_deposit_lamports": 10_000_000,
                    "withdrawal_lamports": 2_000_000,
                    "remaining_customer_liability_lamports": 8_000_000,
                    "separate_root_network_fees_lamports": 10_000,
                    "sweep_created_no_user_liability_journal": True,
                    "manual_admin_and_independent_hot_policy_required_for_exact_wire": True,
                    "genuine_upstream_two_node_frost_for_sweep_and_withdrawal": True,
                    "exactly_once_replay_and_double_entry_conservation": True,
                    "original_three_dkg_ciphertexts_unchanged": True,
                },
                sort_keys=True,
            ).encode(),
        )
