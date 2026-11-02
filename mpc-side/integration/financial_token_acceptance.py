"""Actual classic SPL publication -> deposit -> MPC sweep -> approved withdrawal."""

import base64
import json
import os
from decimal import Decimal
from unittest.mock import patch

from custody.ledger import user_balances
from custody.models import (
    Asset,
    Deposit,
    LedgerPosting,
    LedgerTransaction,
    MpcSolanaDepositProvenance,
    SweepJob,
    UserWallet,
)
from custody.solana_financial_deposits import (
    register_operator_funding_source,
    scan_financial_wallet,
)
from custody.solana_financial_sessions import allocate_sweep, allocate_withdrawal
from custody.solana_financial_wallet import complete_financial_wallet, financial_wallet_request
from custody.solana_provisioning import approve_claim, reserve_claim
from custody.solana_token_provisioning import allocate_provision
from custody.solana_witness_client import query_witness
from custody.spl import derive_ata
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM, verify_token_asset
from custody.withdrawals import approve, create_request
from django.db.models import Sum
from django.test import override_settings
from environment import private_file
from financial_native_acceptance import _finish
from financial_wallet_acceptance import run_financial_wallets
from ops.models import Chain
from protected_coordinator_acceptance import enable_coordinator
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from test_dkg import PARTIES, encrypted_files


def run_token_financial_flow(root_path):
    run_financial_wallets(
        root_path, after_wallets=token_financial_flow, freeze_before_completion=False
    )


def token_financial_flow(g, root_path, tenant, native_records):
    ciphertexts = encrypted_files(g.net, g.dkg_binding)
    journals_before = LedgerTransaction.objects.count()
    base = native_records[0].claim.root.base_address
    # Bootstrap-only mode has sent no transaction yet. Finalize ordinary Root
    # fee funding before invoking genesis-loaded BPF programs at the first bank.
    g.validator.fund(base, 200_000_000)
    g.validator.create_mint()
    mint = str(g.validator.mint.pubkey())
    asset = Asset.objects.create(
        asset_key="LOCAL-CLASSIC-SPL",
        chain_id="SOL",
        symbol="LOCAL-SPL",
        decimals=6,
        is_native=False,
        token_standard="SPL",
        contract_address=mint,
    )
    asset = verify_token_asset(asset.asset_key)
    Chain.objects.filter(chain_id="SOL").update(
        gas_settings={"max_fee_lamports": "20000", "max_ata_rent_lamports": "3000000"}
    )
    rent = g.validator.rpc("getMinimumBalanceForRentExemption", [165])
    pins = {party: [str(identity / "tls.crt")] for party, identity in g.w.node.items()}
    with (
        override_settings(
            MPC_SOLANA_SEEDED_SPL_ENABLED=True,
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
        enable_coordinator(g, root_path)
        records, attempts = [], []
        for n, native in enumerate(native_records):
            claim = reserve_claim(
                keyset_id=native.claim.root.keyset.keyset_id,
                tenant_id=tenant.pk,
                principal_id=native.claim.principal_id,
                asset_key=asset.asset_key,
                idempotency_key=f"actual-classic-{n}",
                operator_ref="integration",
            )
            claim = approve_claim(
                reservation_id=claim.pk, tenant_id=tenant.pk, operator_ref="integration"
            )
            g.w.register_claim(claim.statement, claim.evidence["participant_agreement"])
            args = dict(reservation_id=claim.pk, tenant_id=tenant.pk, operator_ref="integration")
            request = financial_wallet_request(**args)
            assert request["initialization_required"] and request["witness_action"] is None
            assert not UserWallet.objects.filter(solana_claim=claim).exists()
            operation = allocate_provision(
                **args,
                idempotency_key=f"actual-initialize-{n}",
                fee_budget_lamports=20_000,
                rent_budget_lamports=3_000_000,
            )
            _, attempt = _finish(
                g,
                tenant,
                operation,
                PARTIES[:2] if n == 0 else PARTIES[1:],
                expected_source=claim.address,
                expected_destination=claim.address,
                expected_units=0,
                expected_action={"kind": "CreateClassicToken", "rent_lamports": rent},
            )
            attempts.append(attempt)
            request = financial_wallet_request(**args)
            assert request["witness_action"]["kind"] == "IssueClassicClaim"
            command = g.w.command(request["witness_action"], g.w.query()["root"]["revision"])
            assert g.w.request("command", command)[0] == 200
            proof = query_witness(request["query"])
            record = complete_financial_wallet(**args, evidence=proof)
            assert record.status == "ACTIVE"
            assert complete_financial_wallet(**args, evidence=None).pk == record.pk
            records.append(record)
        customer, treasury = records
        assert treasury.user_wallet_id is None
        owner = customer.claim.principal.ledger_owner_id
        assert user_balances(owner, asset.asset_key)["total"] == 0
        register_operator_funding_source(
            address=str(g.validator.faucet.pubkey()),
            reference="isolated-token-operator",
            operator_ref="integration",
        )
        external = Keypair()
        forwarding = Keypair()
        g.validator.fund(str(external.pubkey()), 20_000_000)
        g.validator.mint_to(str(external.pubkey()), 10_000_000)
        g.validator.mint_to(str(forwarding.pubkey()), 0)
        source = derive_ata(str(external.pubkey()), mint)
        intermediary = derive_ata(str(forwarding.pubkey()), mint)

        def transfer(source, target, authority):
            return Instruction(
                Pubkey.from_string(CLASSIC_TOKEN_PROGRAM),
                b"\x0c" + (10_000_000).to_bytes(8, "little") + bytes([6]),
                [
                    AccountMeta(Pubkey.from_string(source), False, True),
                    AccountMeta(Pubkey.from_string(mint), False, False),
                    AccountMeta(Pubkey.from_string(target), False, True),
                    AccountMeta(authority.pubkey(), True, False),
                ],
            )

        signature = g.validator.send(
            [
                transfer(source, intermediary, external),
                transfer(intermediary, customer.claim.address, forwarding),
            ],
            [g.validator.faucet, external, forwarding],
        )
        scan_args = dict(
            user_wallet_id=customer.user_wallet_id, tenant_id=tenant.pk, operator_ref="integration"
        )
        observation = scan_financial_wallet(**scan_args)
        assert observation.scan_complete and observation.confirmed_balance == Decimal(10)
        assert scan_financial_wallet(**scan_args).scan_complete
        deposit = Deposit.objects.get(user_wallet_id=customer.user_wallet_id, tx_hash=signature)
        assert deposit.status == "CONFIRMED" and deposit.amount == 10
        original = MpcSolanaDepositProvenance.objects.get(deposit=deposit)
        observed_wire = Transaction.from_bytes(
            base64.b64decode(original.evidence["transaction"]["transaction"][0])
        )
        intermediary_index = observed_wire.message.account_keys.index(
            Pubkey.from_string(intermediary)
        )
        for name in ("preTokenBalances", "postTokenBalances"):
            entry = next(
                item
                for item in original.evidence["transaction"]["meta"][name]
                if item["accountIndex"] == intermediary_index
            )
            assert entry["owner"] == str(forwarding.pubkey())
            assert entry["uiTokenAmount"]["amount"] == "0"
        assert deposit.event_index == "ix:1" and original.source_address == intermediary
        assert user_balances(owner, asset.asset_key)["total"] == 10
        sweep = SweepJob.objects.create(
            user_wallet=customer.user_wallet,
            asset_key=asset.asset_key,
            balance_snapshot=Decimal(10),
            idempotency_key="actual-token-sweep",
        )
        operation = allocate_sweep(
            sweep_id=sweep.pk,
            destination_id=treasury.pk,
            tenant_id=tenant.pk,
            fee_budget_lamports=20_000,
            operator_ref="integration",
        )
        _, attempt = _finish(
            g,
            tenant,
            operation,
            [PARTIES[0], PARTIES[2]],
            expected_source=customer.claim.address,
            expected_destination=treasury.claim.address,
            expected_units=10_000_000,
            expected_action={
                "kind": "ClassicSeededTransfer",
                "destination_base": base,
                "destination_index": treasury.claim.index,
                "amount": 10_000_000,
            },
        )
        attempts.append(attempt)
        recipient = str(Pubkey.new_unique())
        withdrawal = create_request(
            owner,
            "SOL",
            recipient,
            Decimal(2),
            asset_key=asset.asset_key,
            idempotency_key="actual-classic-withdrawal",
        )
        assert approve("independent-admin", withdrawal.pk).status == "APPROVED"
        operation = allocate_withdrawal(
            withdrawal_id=withdrawal.pk,
            source_id=treasury.pk,
            tenant_id=tenant.pk,
            fee_budget_lamports=20_000,
            rent_budget_lamports=3_000_000,
            operator_ref="integration",
        )
        _, attempt = _finish(
            g,
            tenant,
            operation,
            PARTIES[1:],
            expected_source=treasury.claim.address,
            expected_destination=recipient,
            expected_units=2_000_000,
            expected_action={
                "kind": "ClassicTransfer",
                "destination_owner": recipient,
                "amount": 2_000_000,
                "create_ata": True,
            },
        )
        attempts.append(attempt)
        # Reuse the now-existing ATA: authorize maximum rent again, charge only
        # the actual zero rent on chain, preserving the original withdrawal hold.
        second = create_request(
            owner,
            "SOL",
            recipient,
            Decimal(1),
            asset_key=asset.asset_key,
            idempotency_key="actual-classic-existing-ata-withdrawal",
        )
        assert approve("independent-admin", second.pk).status == "APPROVED"
        operation = allocate_withdrawal(
            withdrawal_id=second.pk,
            source_id=treasury.pk,
            tenant_id=tenant.pk,
            fee_budget_lamports=20_000,
            rent_budget_lamports=3_000_000,
            operator_ref="integration",
        )
        _, attempt = _finish(
            g,
            tenant,
            operation,
            PARTIES[:2],
            expected_source=treasury.claim.address,
            expected_destination=recipient,
            expected_units=1_000_000,
            expected_action={
                "kind": "ClassicTransfer",
                "destination_owner": recipient,
                "amount": 1_000_000,
                "create_ata": True,
            },
        )
        attempts.append(attempt)

        def units(address):
            return int(
                g.validator.rpc("getTokenAccountBalance", [address, {"commitment": "finalized"}])[
                    "value"
                ]["amount"]
            )

        assert (
            units(customer.claim.address),
            units(treasury.claim.address),
            units(derive_ata(recipient, mint)),
        ) == (0, 7_000_000, 3_000_000)
        assert user_balances(owner, asset.asset_key) == {
            "available": Decimal(7),
            "reserved": 0,
            "total": Decimal(7),
        }
        assert (
            g.validator.rpc("getBalance", [base, {"commitment": "finalized"}])["value"]
            == 200_000_000 - 3 * rent - 25_000
        )
        assert not LedgerPosting.objects.filter(
            transaction__ref_type="SweepJob", account__owner_type="USER"
        ).exists()
        assert LedgerPosting.objects.aggregate(total=Sum("amount"))["total"] == 0
        assert LedgerTransaction.objects.count() == journals_before + 13
        assert not LedgerTransaction.objects.filter(
            event_key=f"solana:{attempts[-1].pk}:ata_rent"
        ).exists()
        g.w.stop()
        for party in PARTIES:
            g.net.stop(party)
        g.w.start()
        for party in PARTIES:
            g.start(party)
        assert encrypted_files(g.net, g.dkg_binding) == ciphertexts
        private_file(
            root_path / "solana-token-financial-public-evidence.json",
            json.dumps(
                {
                    "scope": (
                        "actual isolated classic SPL initialization/publication/deposit/sweep/"
                        "approved withdrawal using original FROST and existing ledger"
                    ),
                    "genuine_initializers": 2,
                    "actual_external_deposit_units": 10_000_000,
                    "actual_atomic_external_forwarding_with_zero_net_source_balance": True,
                    "remaining_customer_liability_units": 7_000_000,
                    "external_withdrawal_units": 3_000_000,
                    "root_network_fee_lamports": 25_000,
                    "rent_accounts_funded": 3,
                    "existing_ata_authorized_maximum_but_charged_zero_rent": True,
                    "treasury_user_wallets": 0,
                    "new_financial_journals": 13,
                    "original_dkg_ciphertexts_unchanged_after_restart": True,
                },
                sort_keys=True,
            ).encode(),
        )
