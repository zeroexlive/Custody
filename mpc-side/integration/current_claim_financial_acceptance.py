"""Actual repair/current Claims -> PG publication/deposits -> genuine financial MPC."""

import copy
import hashlib
import json
import os
from decimal import Decimal
from unittest.mock import patch
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from custody.financial_identity import register_financial_principal
from custody.ledger import user_balances
from custody.models import (
    AdminActionLog,
    Asset,
    Deposit,
    LedgerTransaction,
    MpcSolanaClaimApproval,
    MpcSolanaClaimRegistration,
    MpcSolanaFinancialWallet,
    SweepJob,
    UserWallet,
)
from custody.solana_claim_registration import (
    begin_current_claim_approval,
    claim_query_request,
    collect_current_claim_evidence,
    complete_claim_registration,
)
from custody.solana_financial_deposits import (
    register_operator_funding_source,
    scan_financial_wallet,
)
from custody.solana_financial_sessions import allocate_session, allocate_sweep
from custody.solana_financial_wallet import complete_financial_wallet, financial_wallet_request
from custody.solana_provisioning import approve_claim, reserve_claim
from custody.solana_token_provisioning import allocate_provision
from custody.solana_witness_client import query_witness
from custody.spl import derive_ata
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM, verify_token_asset
from django.db.models import Sum
from django.test import override_settings
from environment import private_file
from financial_native_acceptance import _finish
from financial_wallet_acceptance import run_financial_wallets
from ops.models import Chain
from protected_coordinator_acceptance import enable_coordinator
from refresh_acceptance import freeze
from repair_acceptance import activate, call, recipient, reserve, start
from solana_local.incoming import external_transfer
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from test_dkg import PARTIES
from witness_acceptance import sign, verify


def repair(g):
    freeze(g)
    identity, profile, anchor = recipient(g)
    p = reserve(g, identity, profile, anchor)
    for party in PARTIES:
        assert start(g, party, p)[0] == 200
    for action in ("round1", "round2"):
        for party in PARTIES[1:]:
            code, result = call(g, party, action, p)
            assert code == 200, result
    code, result = call(g, PARTIES[0], "finalize", p)
    assert code == 200 and result["repaired"] and result["generation_ready"] is None, result
    for party in PARTIES:
        assert start(g, party, p, "refresh")[0] == 200
    for action in ("round1", "round2"):
        for party in PARTIES:
            code, result = call(g, party, action, p, "refresh")
            assert code == 200, result
    ready = []
    for party in PARTIES:
        code, result = call(g, party, "finalize", p, "refresh")
        assert code == 200, result
        ready.append(result["generation_ready"])
        verify(g.w.node[party], "WITNESS_GENERATION_READY_V1", ready[-1])
    activate(g, p, ready)


def register(g, tenant, claim, *, rollback=False):
    arguments = dict(tenant_id=tenant.pk, operator_ref="integration")
    discovery = claim_query_request(reservation_id=claim.pk, **arguments)
    proof = query_witness(discovery["query"])
    attempt = begin_current_claim_approval(
        challenge=discovery["challenge"],
        evidence=proof,
        node_certificates_der_hex={
            p: x509.load_pem_x509_certificate((identity / "tls.crt").read_bytes())
            .public_bytes(serialization.Encoding.DER)
            .hex()
            for p, identity in g.w.node.items()
        },
        **arguments,
    )
    original_command_id = attempt.command_id
    attempt = collect_current_claim_evidence(attempt_id=attempt.pk, **arguments)
    assert MpcSolanaClaimApproval.objects.get(pk=attempt.pk).status == "REPORTED"
    request = claim_query_request(reservation_id=claim.pk, attempt_id=attempt.pk, **arguments)
    command = g.w.command(request["witness_action"], g.w.query()["root"]["revision"])
    command["value"]["request_id"] = str(attempt.command_id)
    command = sign(g.w.life, "WITNESS_COMMAND_V1", command["value"])
    code, ack = g.w.request("command", command)
    assert code == 200, ack
    verify(g.w.identity, "WITNESS_ACK_V1", ack)
    g.w.stop()
    g.w.start()
    proof = query_witness(request["query"])
    if rollback:
        with patch.object(
            AdminActionLog.objects, "create", side_effect=RuntimeError("audit fault")
        ):
            with pytest.raises(RuntimeError, match="audit fault"):
                complete_claim_registration(
                    challenge=request["challenge"], evidence=proof, **arguments
                )
        assert not MpcSolanaClaimRegistration.objects.filter(claim=claim).exists()
        assert g.w.query(claim_id=str(claim.pk))["claim"] == attempt.evidence
    result = complete_claim_registration(
        challenge=request["challenge"], evidence=proof, **arguments
    )
    assert result.evidence == attempt.evidence
    assert MpcSolanaClaimApproval.objects.get(pk=attempt.pk).command_id == original_command_id
    claim.refresh_from_db()
    assert claim.status == "APPROVED"
    return result


def publish(g, tenant, claim):
    args = dict(reservation_id=claim.pk, tenant_id=tenant.pk, operator_ref="integration")
    request = financial_wallet_request(**args)
    assert request["witness_action"] is not None
    code, result = g.w.request(
        "command", g.w.command(request["witness_action"], g.w.query()["root"]["revision"])
    )
    assert code == 200, result
    proof = query_witness(request["query"])
    return complete_financial_wallet(**args, evidence=proof)


def run_current_claim_financial(root_path):
    run_financial_wallets(root_path, after_wallets=flow, freeze_before_completion=False)


def flow(g, root_path, tenant, original_wallets):
    _, treasury_native = original_wallets
    base = treasury_native.claim.root.base_address
    original_ciphertexts = {
        p: hashlib.sha256(p.read_bytes()).hexdigest()
        for party in PARTIES
        for p in (g.net.root / party / "storage").rglob("*.share.enc")
    }
    assert len(original_ciphertexts) == 3
    g.validator.fund(base, 200_000_000)
    g.validator.create_mint()
    mint = str(g.validator.mint.pubkey())
    asset = Asset.objects.create(
        asset_key="CURRENT-SPL",
        chain_id="SOL",
        symbol="CURRENT",
        decimals=6,
        is_native=False,
        token_standard="SPL",
        contract_address=mint,
    )
    asset = verify_token_asset(asset.asset_key)
    chain = Chain.objects.get(chain_id="SOL")
    chain.gas_settings |= {"max_fee_lamports": "20000", "max_ata_rent_lamports": "3000000"}
    chain.save(update_fields=["gas_settings"])
    customer = register_financial_principal(
        tenant_id=tenant.pk,
        reference="current-customer",
        role="CUSTOMER",
        operator_ref="integration",
    )
    rootargs = dict(
        keyset_id=treasury_native.claim.root.keyset.keyset_id,
        tenant_id=tenant.pk,
        operator_ref="integration",
    )
    claims = []
    pending = []
    with override_settings(MPC_SOLANA_SEEDED_SPL_ENABLED=True):
        for key in ("SOL", asset.asset_key):
            claim = reserve_claim(
                **rootargs, principal_id=customer.pk, asset_key=key, idempotency_key="old-" + key
            )
            claim = approve_claim(
                reservation_id=claim.pk, tenant_id=tenant.pk, operator_ref="integration"
            )
            assert g.w.query(claim_id=str(claim.pk))["claim"] is None
            claims.append(claim)
            pending.append(
                financial_wallet_request(
                    reservation_id=claim.pk, tenant_id=tenant.pk, operator_ref="integration"
                )
            )
        native, token = claims
        original_evidence = [copy.deepcopy(c.evidence) for c in claims]
        held = allocate_provision(
            reservation_id=token.pk,
            tenant_id=tenant.pk,
            idempotency_key="pre-refresh-init",
            fee_budget_lamports=20_000,
            rent_budget_lamports=3_000_000,
            operator_ref="integration",
        )
        allocated = allocate_session(
            reservation_id=held.pk,
            tenant_id=tenant.pk,
            selected_signers=list(PARTIES[:2]),
            operator_ref="integration",
        )
        original_ids = (allocated.pk, allocated.crypto_execution_id, allocated.attempt_id, held.pk)
        repair(g)
        pins = {p: [str(identity / "tls.crt")] for p, identity in g.w.node.items()}
        with (
            override_settings(
                MPC_SOLANA_CURRENT_CLAIMS_ENABLED=True,
                MPC_SOLANA_LIFECYCLE_CERTIFICATE=str(g.w.life / "tls.crt"),
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
            register(g, tenant, native, rollback=True)
            register(g, tenant, token)
            assert [c.evidence for c in claims] == original_evidence
            assert [MpcSolanaFinancialWallet.objects.get(pk=c.pk).issuance_id for c in claims] == [
                UUID(r["issuance_id"]) for r in pending
            ]
            native_wallet = publish(g, tenant, native)
            # A genuinely new Pending Claim after replacement uses no legacy
            # approval; it becomes APPROVED only with exact W registration.
            treasury_token = reserve_claim(
                **rootargs,
                principal_id=treasury_native.claim.principal_id,
                asset_key=asset.asset_key,
                idempotency_key="new-current-treasury",
            )
            assert treasury_token.status == "PENDING" and treasury_token.evidence == {}
            register(g, tenant, treasury_token)
            financial_wallet_request(
                reservation_id=treasury_token.pk, tenant_id=tenant.pk, operator_ref="integration"
            )
            enable_coordinator(g, root_path)
            for claim, operation in ((token, held), (treasury_token, None)):
                operation = operation or allocate_provision(
                    reservation_id=claim.pk,
                    tenant_id=tenant.pk,
                    idempotency_key="new-current-init",
                    fee_budget_lamports=20_000,
                    rent_budget_lamports=3_000_000,
                    operator_ref="integration",
                )
                _finish(
                    g,
                    tenant,
                    operation,
                    list(PARTIES[:2]),
                    expected_source=claim.address,
                    expected_destination=claim.address,
                    expected_units=0,
                    expected_action={"kind": "CreateClassicToken", "rent_lamports": 2_039_280},
                )
            allocated.refresh_from_db()
            assert (
                allocated.pk,
                allocated.crypto_execution_id,
                allocated.attempt_id,
                allocated.operation_id,
            ) == original_ids
            token_wallet = publish(g, tenant, token)
            token_treasury = publish(g, tenant, treasury_token)
            assert token_treasury.user_wallet_id is None
            register_operator_funding_source(
                address=str(g.validator.faucet.pubkey()),
                reference="current-operator-faucet",
                operator_ref="integration",
            )
            sender = Keypair()
            g.validator.fund(str(sender.pubkey()), 30_000_000)
            native_signature = external_transfer(g.validator, sender, native.address, 10_000_000)
            g.validator.mint_to(str(sender.pubkey()), 10_000_000)
            source = derive_ata(str(sender.pubkey()), mint)
            token_signature = g.validator.send(
                [
                    Instruction(
                        Pubkey.from_string(CLASSIC_TOKEN_PROGRAM),
                        b"\x0c" + (10_000_000).to_bytes(8, "little") + bytes([6]),
                        [
                            AccountMeta(Pubkey.from_string(source), False, True),
                            AccountMeta(Pubkey.from_string(mint), False, False),
                            AccountMeta(Pubkey.from_string(token.address), False, True),
                            AccountMeta(sender.pubkey(), True, False),
                        ],
                    )
                ],
                [g.validator.faucet, sender],
            )
            for wallet, signature, units, destination in (
                (native_wallet, native_signature, Decimal(".01"), treasury_native),
                (token_wallet, token_signature, Decimal(10), token_treasury),
            ):
                observation = scan_financial_wallet(
                    user_wallet_id=wallet.user_wallet_id,
                    tenant_id=tenant.pk,
                    operator_ref="integration",
                )
                assert observation.scan_complete and observation.confirmed_balance == units
                assert (
                    Deposit.objects.get(
                        user_wallet_id=wallet.user_wallet_id, tx_hash=signature
                    ).status
                    == "CONFIRMED"
                )
                assert (
                    user_balances(customer.ledger_owner_id, wallet.claim.asset.asset_key)["total"]
                    == units
                )
                sweep = SweepJob.objects.create(
                    user_wallet=wallet.user_wallet,
                    asset_key=wallet.claim.asset.asset_key,
                    balance_snapshot=units,
                    idempotency_key="current-sweep-" + wallet.claim.asset.asset_key,
                )
                operation = allocate_sweep(
                    sweep_id=sweep.pk,
                    destination_id=destination.pk,
                    tenant_id=tenant.pk,
                    fee_budget_lamports=20_000,
                    operator_ref="integration",
                )
                action = (
                    None
                    if wallet.claim.asset.is_native
                    else dict(
                        kind="ClassicSeededTransfer",
                        destination_base=base,
                        destination_index=destination.claim.index,
                        amount=10_000_000,
                    )
                )
                _finish(
                    g,
                    tenant,
                    operation,
                    list(PARTIES[:2]),
                    expected_source=wallet.claim.address,
                    expected_destination=destination.claim.address,
                    expected_units=10_000_000,
                    expected_action=action,
                )
                assert (
                    user_balances(customer.ledger_owner_id, wallet.claim.asset.asset_key)["total"]
                    == units
                )
            assert not UserWallet.objects.filter(solana_claim=treasury_token).exists()
            assert all(
                hashlib.sha256(p.read_bytes()).hexdigest() == h
                for p, h in original_ciphertexts.items()
            )
            assert (
                not LedgerTransaction.objects.annotate(total=Sum("postings__amount"))
                .exclude(total=0)
                .exists()
            )
            private_file(
                root_path / "solana-current-claim-financial-public-evidence.json",
                json.dumps(
                    dict(
                        scope=(
                            "actual repair/current registration/PG publication/"
                            "native+SPL deposits/MPC sweeps"
                        ),
                        old_approved_unregistered_claims_recovered=2,
                        original_approval_evidence_unchanged=True,
                        pending_issuance_ids_unchanged=True,
                        held_initializer_and_session_ids_unchanged=True,
                        pending_new_claim_approved_only_with_registration=True,
                        actual_mpc_initializers=2,
                        actual_mpc_native_and_token_sweeps=2,
                        native_liability=".01",
                        token_liability="10",
                        treasury_user_wallets=0,
                        original_dkg_ciphertexts_unchanged=3,
                    ),
                    sort_keys=True,
                ).encode(),
            )
