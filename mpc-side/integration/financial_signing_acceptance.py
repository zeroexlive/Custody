"""Actual backend/PG/coordinator/FROST/W signature capture, no broadcast/ledger."""

import json
from collections import Counter
from unittest.mock import patch

from custody.models import AdminActionLog, LedgerTransaction, MpcSolanaSignatureOwner
from custody.mpc_transport import coordinator_request as actual_request
from custody.solana_financial_sessions import request_query
from custody.solana_financial_signing import execute_session, reconcile_session
from custody.solana_witness_client import query_witness
from django.test import override_settings
from environment import private_file
from financial_preparation_acceptance import run_financial_preparation
from protected_coordinator_acceptance import SignerRelay, enable_coordinator
from test_dkg import encrypted_files


def run_financial_signing(root_path, fault=None, *, after_signed=None):
    def capture(g, root_path, tenant, row):
        signed = sign_and_capture(g, root_path, tenant, row, fault=fault)
        if after_signed is not None:
            after_signed(g, root_path, tenant, signed)

    run_financial_preparation(root_path, after_ready=capture)


def sign_and_capture(g, root_path, tenant, row, *, fault=None):
    before = LedgerTransaction.objects.count()
    ciphertexts = encrypted_files(g.net, g.dkg_binding)
    enable_coordinator(g, root_path)
    relay = SignerRelay(g, "signer-b", "before_record") if fault == "before_record" else None
    pins = {party: [str(identity / "tls.crt")] for party, identity in g.w.node.items()}
    try:
        with override_settings(
            MPC_SOLANA_FINANCIAL_SIGNER_CERTIFICATES=pins, MPC_REQUEST_TIMEOUT_SECONDS=30
        ):
            request = request_query(
                session_id=row.pk,
                tenant_id=tenant.pk,
                purpose="ADMISSION",
                operator_ref="integration",
            )
            evidence = query_witness(request["query"])
            arguments = {
                "session_id": row.pk,
                "tenant_id": tenant.pk,
                "challenge": request["query"]["challenge"],
                "evidence": evidence,
                "operator_ref": "integration",
            }
            with patch(
                "custody.solana_financial_signing.coordinator_request", wraps=actual_request
            ) as calls:
                if fault == "audit_and_cache_loss":
                    original_audit = AdminActionLog.objects.create

                    def failed_public_audit(**kwargs):
                        if kwargs["action_type"] == "SOL_FIN_PUBLIC_RESULT":
                            raise RuntimeError("after-remote audit")
                        return original_audit(**kwargs)

                    with patch.object(
                        AdminActionLog.objects, "create", side_effect=failed_public_audit
                    ):
                        try:
                            execute_session(**arguments)
                        except RuntimeError as exc:
                            assert "after-remote audit" in str(exc)
                        else:
                            raise AssertionError("DB audit fault did not occur")
                    row.refresh_from_db()
                    assert (
                        row.status == "RECONCILIATION_REQUIRED" and not row.attempt.signed_payload
                    )
                    assert (
                        g.w.query(str(row.crypto_execution_id))["execution"]["status"]
                        == "SignedPending"
                    )
                    g.net.stop("coordinator")
                    saved = g.coordinator_directory / f"{row.pk}.json"
                    saved.rename(root_path / "held-coordinator-session.json")
                    g.net.start("coordinator")
                    signed = reconcile_session(
                        session_id=row.pk, tenant_id=tenant.pk, operator_ref="integration"
                    )
                else:
                    signed = execute_session(**arguments)
                    if relay:
                        assert (
                            signed.status == "RECONCILIATION_REQUIRED"
                            and not signed.attempt.signed_payload
                        )
                        assert (
                            g.w.query(str(row.crypto_execution_id))["execution"]["status"] == "Open"
                        )
                        private_calls = Counter(relay.calls)
                        g.net.stop("coordinator")
                        g.net.start("coordinator")
                        signed = reconcile_session(
                            session_id=row.pk, tenant_id=tenant.pk, operator_ref="integration"
                        )
                        assert all(
                            count == private_calls[(action, round_number)]
                            for (action, round_number), count in relay.calls.items()
                            if action == "auto"
                        )
                        assert not relay.errors, relay.errors
                assert signed.status == "COMPLETED"
                before_replay = calls.call_count
                assert execute_session(**arguments).signature_hex == signed.signature_hex
                assert calls.call_count == before_replay
                assert sum(call.args[1].endswith("/execute") for call in calls.call_args_list) == 1
            signed.attempt.refresh_from_db()
            assert signed.attempt.status == "SIGNED" and signed.attempt.signed_payload
            owner = MpcSolanaSignatureOwner.objects.get(session=signed)
            assert (
                owner.signature == signed.attempt.network_tx_id
                and owner.message.operation_id == row.operation_id
            )
        assert LedgerTransaction.objects.count() == before
        assert encrypted_files(g.net, g.dkg_binding) == ciphertexts
        name = (
            f"solana-financial-signature-{fault}-public-evidence.json"
            if fault
            else "solana-financial-signature-public-evidence.json"
        )
        private_file(
            root_path / name,
            json.dumps(
                {
                    "scope": (
                        "genuine backend/PG/protected coordinator/FROST/W signature capture only; "
                        "synthetic sweep snapshot, no transfer/settlement/ledger acceptance"
                    ),
                    "original_binding_and_dispatch_committed_before_private_rpc": True,
                    "actual_upstream_two_node_frost_signature": True,
                    "original_authenticated_public_reports_redelivered_via_backend_courier": True,
                    "fresh_witness_signed_pending_and_independent_python_ed25519_verifiers": True,
                    "signature_owner_and_original_signed_payload_committed_atomically": True,
                    "terminal_execute_replay_performed_no_new_private_work": True,
                    "missing_witness_result_recovered_by_backend_courier": fault == "before_record",
                    "remote_signature_survived_db_audit_and_coordinator_cache_loss": fault
                    == "audit_and_cache_loss",
                    "broadcasts": 0,
                    "ledger_journals_created": 0,
                    "original_three_dkg_ciphertexts_unchanged": True,
                },
                sort_keys=True,
            ).encode(),
        )
        return signed
    finally:
        if relay:
            relay.close()
