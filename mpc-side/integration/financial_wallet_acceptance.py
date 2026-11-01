"""Actual PG/three original nodes/Rust W native membership, without ledger use."""

import hashlib
import json
from decimal import Decimal
from unittest.mock import patch

import pytest
from custody.deposits import ingest_event
from custody.financial_identity import register_financial_principal
from custody.indexer.base import DepositEvent
from custody.ledger import credit_deposit
from custody.models import (
    AdminActionLog,
    Deposit,
    LedgerTransaction,
    MpcSolanaFinancialWallet,
    MpcSolanaIssuance,
    UserWallet,
)
from custody.solana_financial_wallet import (
    complete_financial_wallet,
    financial_wallet_request,
    validate_financial_wallet,
)
from custody.solana_provisioning import approve_claim, reserve_claim
from custody.solana_witness_client import query_witness
from django.test import override_settings
from environment import private_file
from financial_root_acceptance import run_financial_mode_import
from test_dkg import encrypted_files
from witness_acceptance import verify


def run_financial_wallets(root_path):
    run_financial_mode_import(root_path, after_mode=publish_native_wallets)


def publish_native_wallets(g, root_path, tenant, customer_claim, arguments):
    ciphertexts = encrypted_files(g.net, g.dkg_binding)
    before = LedgerTransaction.objects.count()
    treasury = register_financial_principal(
        tenant_id=tenant.pk,
        reference="actual-native-treasury",
        role="TREASURY",
        operator_ref="integration",
    )
    treasury_claim = reserve_claim(
        **arguments, principal_id=treasury.pk, asset_key="SOL", idempotency_key="treasury-native"
    )
    treasury_claim = approve_claim(
        reservation_id=treasury_claim.pk, tenant_id=tenant.pk, operator_ref="integration"
    )
    g.w.register_claim(treasury_claim.statement, treasury_claim.evidence["participant_agreement"])
    claims = [customer_claim, treasury_claim]
    requests = [
        financial_wallet_request(
            reservation_id=claim.pk, tenant_id=tenant.pk, operator_ref="integration"
        )
        for claim in claims
    ]
    assert [r["role"] for r in requests] == ["CUSTOMER_DEPOSIT", "TENANT_TREASURY"]
    commands, acknowledgements = [], []
    for request in requests:
        command = g.w.command(request["witness_action"], g.w.query()["root"]["revision"])
        code, ack = g.w.request("command", command)
        assert code == 200
        verify(g.w.identity, "WITNESS_ACK_V1", ack)
        commands.append(command)
        acknowledgements.append(ack)
    g.w.stop()
    g.w.start()
    before_retry = g.w.query()["sequence"]
    for command, ack in zip(commands, acknowledgements, strict=True):
        code, recovered_ack = g.w.request("command", command)
        assert code == 200
        verify(g.w.identity, "WITNESS_ACK_V1", recovered_ack)
        assert recovered_ack["value"]["anchor_id"] == ack["value"]["anchor_id"]
        assert recovered_ack["value"]["value_fingerprint"] == ack["value"]["value_fingerprint"]
        assert recovered_ack["value"]["sequence"] == before_retry
    assert g.w.query()["sequence"] == before_retry
    frozen = g.w.command({"kind": "Freeze"}, g.w.query()["root"]["revision"])
    assert g.w.request("command", frozen)[0] == 200
    records = []
    for claim, request in zip(claims, requests, strict=True):
        with override_settings(
            MPC_SOLANA_WITNESS_URL=f"https://localhost:{g.w.port}",
            MPC_SOLANA_WITNESS_CA_CERT=str(g.w.identity / "ca.crt"),
            MPC_SOLANA_WITNESS_COURIER_CERT=str(g.w.courier / "tls.crt"),
            MPC_SOLANA_WITNESS_COURIER_KEY=str(g.w.courier / "tls.key"),
        ):
            proof = query_witness(request["query"])
        assert proof["value"]["root"]["phase"] == "Frozen"
        verify(g.w.identity, "WITNESS_QUERY_REPLY_V1", proof)
        complete_args = {
            "reservation_id": claim.pk,
            "tenant_id": tenant.pk,
            "operator_ref": "integration",
            "evidence": proof,
        }
        # W has durably granted issuance. A real DB failure rolls back every
        # local activation effect, preserving the original pending intent/IDs.
        with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit")):
            with pytest.raises(RuntimeError, match="audit"):
                complete_financial_wallet(**complete_args)
        assert MpcSolanaFinancialWallet.objects.get(claim=claim).status == "PENDING"
        assert MpcSolanaIssuance.objects.get(pk=request["issuance_id"]).status == "PENDING"
        assert not UserWallet.objects.filter(solana_claim=claim).exists()
        record = complete_financial_wallet(**complete_args)
        assert record.status == "ACTIVE" and validate_financial_wallet(record).evidence == proof
        assert complete_financial_wallet(**(complete_args | {"evidence": None})).pk == record.pk
        records.append(record)
    customer, treasury_record = records
    wallet = UserWallet.objects.get(pk=customer.user_wallet_id)
    assert wallet.user_id == customer_claim.principal.ledger_owner_id
    assert wallet.deposit_address == customer_claim.address
    assert treasury_record.user_wallet_id is None
    assert not UserWallet.objects.filter(user_id=treasury.ledger_owner_id).exists()
    with pytest.raises(ValueError, match="financial activation"):
        ingest_event(
            wallet, DepositEvent("unaccepted-provenance", Decimal("1"), 1, 100, asset_key="SOL")
        )
    deposit = Deposit.objects.create(
        user_wallet=wallet, asset_key="SOL", tx_hash="direct-unaccepted-credit", amount=Decimal("1")
    )
    with pytest.raises(ValueError, match="financial activation"):
        credit_deposit(deposit)
    assert LedgerTransaction.objects.count() == before
    assert encrypted_files(g.net, g.dkg_binding) == ciphertexts
    private_file(
        root_path / "solana-financial-wallet-public-evidence.json",
        json.dumps(
            {
                "scope": (
                    "genuine native financial membership only; no financial signing/ledger flow"
                ),
                "customer_and_treasury_have_original_all_three_claim_receipts": True,
                "financial_intents_and_native_issuers_committed_before_lifecycle_grants": True,
                "original_command_ack_fingerprints_recovered_after_witness_restart": True,
                "original_publication_completed_after_freeze": True,
                "after_remote_grant_db_failure_preserved_original_pending_ids": True,
                "customer_owner_and_claim_address_preserved": True,
                "treasury_user_wallets": 0,
                "financial_memberships_activated": len(records),
                "seeded_credit_still_closed_until_provenance_and_ledger_integration": True,
                "ledger_journals_created": 0,
                "original_three_dkg_ciphertexts_unchanged": True,
                "original_ciphertext_sha256": {
                    p: hashlib.sha256(v).hexdigest() for p, v in ciphertexts.items()
                },
            },
            sort_keys=True,
        ).encode(),
    )
