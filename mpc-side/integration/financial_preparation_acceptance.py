"""Actual RPC/PG and class-specific Rust authorization, no R1 apply or broadcast.

The sweep snapshot and operator account funding do not establish a credited
customer deposit. This is preparation/authority compatibility acceptance only.
"""

import json
from decimal import Decimal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from custody.models import LedgerTransaction, MpcSolanaMessageOwner, SweepJob
from custody.solana_financial_preparation import _content, approve_session, prepare_session
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


def run_financial_preparation(root_path, *, after_ready=None, before_keyset_import=None):
    def prepare(g, root_path, tenant, records):
        prepare_and_authorize(g, root_path, tenant, records, after_ready=after_ready)

    run_financial_wallets(
        root_path,
        after_wallets=prepare,
        freeze_before_completion=False,
        before_keyset_import=before_keyset_import,
    )


def prepare_and_authorize(g, root_path, tenant, records, *, after_ready=None):
    customer, treasury = records
    before = LedgerTransaction.objects.count()
    ciphertexts = encrypted_files(g.net, g.dkg_binding)
    Chain.objects.filter(chain_id="SOL").update(gas_settings={"max_fee_lamports": "20000"})
    g.validator.fund(customer.claim.root.base_address, 200_000_000)
    g.validator.fund(customer.claim.address, 10_000_000)
    sweep = SweepJob.objects.create(
        user_wallet=customer.user_wallet,
        asset_key="SOL",
        balance_snapshot=Decimal("0.001"),
        idempotency_key="preparation-synthetic-snapshot",
    )
    op = allocate_sweep(
        sweep_id=sweep.pk,
        destination_id=treasury.pk,
        tenant_id=tenant.pk,
        fee_budget_lamports=20_000,
        operator_ref="integration",
    )
    row = allocate_session(
        reservation_id=op.pk,
        tenant_id=tenant.pk,
        selected_signers=["signer-a", "signer-b"],
        operator_ref="integration",
    )
    with override_settings(
        MPC_SOLANA_WITNESS_URL=f"https://localhost:{g.w.port}",
        MPC_SOLANA_WITNESS_CA_CERT=str(g.w.identity / "ca.crt"),
        MPC_SOLANA_WITNESS_COURIER_CERT=str(g.w.courier / "tls.crt"),
        MPC_SOLANA_WITNESS_COURIER_KEY=str(g.w.courier / "tls.key"),
        MPC_SOLANA_FINANCIAL_POLICY_CERTIFICATE=str(g.w.policy / "tls.crt"),
        MPC_SOLANA_FINANCIAL_POLICY_VERSION=7,
        MPC_SOLANA_FINANCIAL_MAX_LIFETIME_SECONDS=120,
    ):

        def fresh(purpose):
            request = request_query(
                session_id=row.pk, tenant_id=tenant.pk, purpose=purpose, operator_ref="integration"
            )
            return request, query_witness(request["query"])

        request, proof = fresh("ADMISSION")
        row = prepare_session(
            session_id=row.pk,
            tenant_id=tenant.pk,
            challenge=request["query"]["challenge"],
            evidence=proof,
            operator_ref="integration",
        )
        assert row.status == "WAITING_POLICY"
        # Driver alone supplies the independent HOT Policy signature. Backend
        # settings contain its public certificate and no Policy private key.
        cert = x509.load_pem_x509_certificate((g.w.policy / "tls.crt").read_bytes())
        key = serialization.load_pem_private_key((g.w.policy / "tls.key").read_bytes(), None)
        grant = {
            "certificate_chain_der_hex": [cert.public_bytes(serialization.Encoding.DER).hex()],
            "signature_der_hex": key.sign(
                b"Wallet-MPC/OPERATOR_SEEDED_SPEND_V1\0" + _content(row), ec.ECDSA(hashes.SHA256())
            ).hex(),
        }
        request, proof = fresh("ADMISSION")
        row = approve_session(
            session_id=row.pk,
            tenant_id=tenant.pk,
            challenge=request["query"]["challenge"],
            evidence=proof,
            policy_authorization=grant,
            operator_ref="integration",
        )
        assert row.status == "READY"
        if after_ready is not None:
            after_ready(g, root_path, tenant, row)
            return
        binding = {
            "authorized": {
                "intent": row.intent,
                "payload_hex": bytes(row.payload).hex(),
                "claim_evidence": customer.claim.evidence,
                "custody_authorization": row.custody_authorization,
                "operator_authorization": row.policy_authorization,
            },
            "selected_signers": row.selected_signers,
        }
        control = {"binding": binding, "round": 1, "signing_package": None}
        code, challenge = g.call("signer-a", "challenge", control)
        assert code == 200, (code, challenge)
        code, permit = g.w.request("permit", challenge, identity=g.w.courier)
        assert code == 200, (code, permit)
        verify(g.w.identity, "WITNESS_PERMIT_V1", permit)
        # No apply/auto call occurs. Close the actual known Open execution and
        # let backend verify Rust's binding fingerprint against its stored wire.
        action = {"kind": "CloseNoSignature", "execution_id": str(row.crypto_execution_id)}
        assert (
            g.w.request("command", g.w.command(action, g.w.query()["root"]["revision"]))[0] == 200
        )
        request, proof = fresh("TERMINAL")
        assert proof["value"]["execution"]["status"] == "NoSignature"
        row = complete_no_signature(
            session_id=row.pk,
            tenant_id=tenant.pk,
            challenge=request["query"]["challenge"],
            evidence=proof,
            operator_ref="integration",
        )
        assert row.status == "NO_SIGNATURE"
    assert MpcSolanaMessageOwner.objects.get(operation=op).first_session_id == row.pk
    assert LedgerTransaction.objects.count() == before
    assert encrypted_files(g.net, g.dkg_binding) == ciphertexts
    private_file(
        root_path / "solana-financial-preparation-public-evidence.json",
        json.dumps(
            {
                "scope": (
                    "actual PG/RPC/backend wire and Rust class authority acceptance only; "
                    "synthetic sweep snapshot, no transfer/ledger acceptance"
                ),
                "original_customer_source_and_separate_root_fee_authority": True,
                "backend_custody_exact_wire_signature_accepted_by_actual_node": True,
                "independent_policy_hot_signature_accepted_by_actual_node_and_witness": True,
                "actual_witness_known_no_signature_binding_matches_backend_digest": True,
                "permanent_wire_owner_retained_after_terminal_no_signature": True,
                "round1_apply_or_auto_calls": 0,
                "broadcasts": 0,
                "ledger_journals_created": 0,
                "original_three_dkg_ciphertexts_unchanged": True,
            },
            sort_keys=True,
        ).encode(),
    )
