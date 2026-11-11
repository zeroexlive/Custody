"""PG dispatch/ambiguity guards with synthetic public authorities; not MPC acceptance."""

import copy
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.db import DatabaseError, transaction
from ops.models import Chain
from solders.keypair import Keypair

from custody.models import (
    AdminActionLog,
    LedgerTransaction,
    MpcSolanaFinancialQuery,
    MpcSolanaFinancialSession,
    MpcSolanaSignatureOwner,
)
from custody.mpc_binding import MpcBindingError
from custody.solana_financial_signing import (
    _binding_id,
    consume_signature,
    execute_session,
    reconcile_session,
)
from custody.solana_witness_client import _message, _point_id
from custody.tests.test_solana_financial_preparation import (
    approve,
    prepare,
    proof,
)
from custody.tests.test_solana_financial_preparation import clean_mode as mode_fixture
from custody.tests.test_solana_financial_preparation import context as context_fixture
from custody.tests.test_solana_financial_preparation import financial as financial_fixture
from custody.tests.test_solana_financial_preparation import preparation as preparation_fixture
from custody.tests.test_solana_financial_preparation import signer_receipt_trust as receipt_fixture
from custody.tests.test_solana_financial_sessions import query
from custody.tests.test_solana_issuance import signed
from custody.tests.test_solana_witness_client import identity

pytestmark = pytest.mark.django_db(transaction=True)
clean_mode = mode_fixture
context = context_fixture
financial = financial_fixture
preparation = preparation_fixture
signer_receipt_trust = receipt_fixture


@pytest.fixture
def signing(preparation, settings, tmp_path):
    c = preparation
    ca = identity(tmp_path / "node-ca", "ca")
    keys = {}
    c["node_signers"] = {}
    for party in ["signer-a", "signer-b", "signer-c"]:
        node_key, cert = identity(tmp_path / party, party, ca)
        c["node_signers"][party] = node_key
        keys[party] = _point_id(cert.public_key())
    settings.MPC_SOLANA_FINANCIAL_SIGNER_CERTIFICATES = {
        p: [str(tmp_path / p / "tls.crt")] for p in keys
    }
    original = proof

    def current_proof(c, row):
        request, evidence = original(c, row)
        evidence["value"]["root"]["node_keys"] = keys
        return request, signed(c, evidence["key_id"], evidence["value"])

    c["proof"] = current_proof
    with (
        patch("custody.tests.test_solana_financial_preparation.proof", side_effect=current_proof),
        patch("custody.solana_financial_signing._runtime"),
    ):
        c["ready"] = approve(c, prepare(c))
        yield c


def start(c):
    row = c["ready"]
    request, evidence = c["proof"](c, row)
    return {
        "session_id": row.pk,
        "tenant_id": c["tenant"].pk,
        "challenge": request["query"]["challenge"],
        "evidence": evidence,
        "operator_ref": "operator",
        "transport": c["rpc"],
    }


def timeout_client():
    calls = []

    def call(method, path, **kwargs):
        calls.append((method, path, kwargs))
        if path.endswith("/execute"):
            raise TimeoutError("response lost")
        return {
            "request": kwargs["json_payload"],
            "status": "CREATED",
            "round1": {},
            "round2": {},
            "signing_package": None,
            "signature_hex": None,
            "error_code": None,
        }

    return calls, call


def test_timeout_preserves_original_dispatch_and_repeated_execute_never_retries_private_work(
    signing,
):
    c = signing
    arguments = start(c)
    calls, client = timeout_client()
    before = LedgerTransaction.objects.count()
    with patch("custody.solana_financial_signing.coordinator_request", side_effect=client):
        with pytest.raises(TimeoutError):
            execute_session(**arguments)
        row = execute_session(**arguments)
    assert len(calls) == 2 and row.status == "RECONCILIATION_REQUIRED"
    assert row.coordinator_evidence["request"]["binding"]["authorized"]["intent"] == row.intent
    assert all(call[2]["dispatch_deadline"] is not None for call in calls)
    assert LedgerTransaction.objects.count() == before
    assert row.operation.status == "HELD" and not row.attempt.signed_payload


def test_audit_failure_before_dispatch_does_not_issue_any_private_rpc(signing):
    c = signing
    arguments = start(c)
    with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit")):
        with patch("custody.solana_financial_signing.coordinator_request") as client:
            with pytest.raises(RuntimeError, match="audit"):
                execute_session(**arguments)
            client.assert_not_called()
    row = c["ready"]
    row.refresh_from_db()
    assert row.status == "READY" and not row.coordinator_evidence
    assert MpcSolanaFinancialQuery.objects.get(pk=arguments["challenge"]).status == "PENDING"


def test_missing_independent_node_pin_ring_blocks_private_dispatch(signing, settings):
    settings.MPC_SOLANA_FINANCIAL_SIGNER_CERTIFICATES = {}
    with patch("custody.solana_financial_signing.coordinator_request") as client:
        with pytest.raises(MpcBindingError, match="pin rings"):
            execute_session(**start(signing))
        client.assert_not_called()
    signing["ready"].refresh_from_db()
    assert signing["ready"].status == "READY"


def test_dispatched_original_request_is_immutable_even_after_http_failure(signing):
    c = signing
    arguments = start(c)
    _, client = timeout_client()
    with patch("custody.solana_financial_signing.coordinator_request", side_effect=client):
        with pytest.raises(TimeoutError):
            execute_session(**arguments)
    row = MpcSolanaFinancialSession.objects.get(pk=c["ready"].pk)
    changed = copy.deepcopy(row.coordinator_evidence)
    changed["request"]["binding"]["selected_signers"] = ["signer-a", "signer-c"]
    with pytest.raises(DatabaseError, match="dispatch request"), transaction.atomic():
        MpcSolanaFinancialSession.objects.filter(pk=row.pk).update(coordinator_evidence=changed)


def test_public_reconciliation_issues_no_create_or_execute_and_never_assumes_absence_is_failure(
    signing,
):
    c = signing
    _, client = timeout_client()
    with patch("custody.solana_financial_signing.coordinator_request", side_effect=client):
        with pytest.raises(TimeoutError):
            execute_session(**start(c))
    row = MpcSolanaFinancialSession.objects.get(pk=c["ready"].pk)
    reply = {
        "request": row.coordinator_evidence["request"],
        "status": "RECONCILIATION_REQUIRED",
        "round1": {},
        "round2": {},
        "signing_package": None,
        "signature_hex": None,
        "error_code": "lost",
    }

    def absent(query):
        evidence = copy.deepcopy(c["TREASURY"].evidence)
        evidence["value"].update(query=query, execution=None, abandoned=False)
        return signed(c, evidence["key_id"], evidence["value"])

    with (
        patch("custody.solana_financial_signing.coordinator_request", return_value=reply) as public,
        patch("custody.solana_financial_signing.query_witness", side_effect=absent),
    ):
        result = reconcile_session(
            session_id=row.pk, tenant_id=c["tenant"].pk, operator_ref="operator"
        )
    assert public.call_count == 1 and public.call_args.args[1].endswith("/reconcile")
    assert result.status == "RECONCILIATION_REQUIRED" and result.operation.status == "HELD"


@pytest.mark.parametrize(
    "setting,value", [("max_fee_lamports", "3000"), ("native_reserve_lamports", "999999999999")]
)
def test_gas_policy_change_during_rpc_quote_blocks_private_dispatch(signing, setting, value):
    c = signing
    arguments = start(c)
    original = c["rpc"].rpc
    changed = False

    def policy_change(url, method, params):
        nonlocal changed
        result = original(url, method, params)
        if method == "getFeeForMessage" and not changed:
            changed = True
            chain = Chain.objects.get(chain_id="SOL")
            chain.gas_settings = chain.gas_settings | {setting: value}
            chain.save(update_fields=["gas_settings"])
        return result

    c["rpc"].rpc = policy_change
    with patch("custody.solana_financial_signing.coordinator_request") as private:
        with pytest.raises(MpcBindingError, match="policy changed"):
            execute_session(**arguments)
        private.assert_not_called()
    c["ready"].refresh_from_db()
    assert c["ready"].status == "READY"


def synthetic_completion(c, row, request):
    """Known unit-fixture key, never genuine MPC or customer custody acceptance."""
    evidence = copy.deepcopy(row.coordinator_evidence["request"]["witness"])
    reports = {}
    for party in row.selected_signers:
        for number in [1, 2]:
            report = {
                "key_id": _point_id(c["node_signers"][party].public_key()),
                "value": {
                    "anchor_id": request["query"]["anchor_id"],
                    "execution_id": str(row.crypto_execution_id),
                    "binding_fingerprint": _binding_id(row),
                    "party_id": party,
                    "round": number,
                    "commitments": [4] if number == 1 else None,
                    "signature_share": [2] * 32 if number == 2 else None,
                    "signing_package": [3] if number == 2 else None,
                },
            }
            report["signature"] = (
                c["node_signers"][party]
                .sign(_message("WITNESS_PUBLIC_ROUND_V1", report), ec.ECDSA(hashes.SHA256()))
                .hex()
            )
            reports[f"{party}:{number}"] = report
    signature = bytes(Keypair.from_seed(bytes([87]) * 32).sign_message(bytes(row.payload))).hex()
    evidence["value"].update(
        query=request["query"],
        abandoned=False,
        execution={
            "status": "SignedPending",
            "signature": signature,
            "binding_fingerprint": _binding_id(row),
            "reports": reports,
        },
    )
    return evidence


def completed(c):
    """Explicit synthetic positive reference for signature/finality unit faults."""
    _, client = timeout_client()
    with patch("custody.solana_financial_signing.coordinator_request", side_effect=client):
        with pytest.raises(TimeoutError):
            execute_session(**start(c))
    row = MpcSolanaFinancialSession.objects.get(pk=c["ready"].pk)
    request = query(c, row, "RECOVERY")
    evidence = synthetic_completion(c, row, request)
    row = consume_signature(
        session_id=row.pk,
        tenant_id=c["tenant"].pk,
        challenge=request["query"]["challenge"],
        evidence=signed(c, evidence["key_id"], evidence["value"]),
        operator_ref="operator",
    )
    row.attempt.refresh_from_db()
    return row


def test_synthetic_positive_reference_consumes_original_signature_once(signing):
    row = completed(signing)
    assert row.status == "COMPLETED" and row.attempt.status == "SIGNED"
    assert MpcSolanaSignatureOwner.objects.get(session=row).signature == row.attempt.network_tx_id


@pytest.mark.parametrize(
    "fault", ["node_signature", "node_pin", "party", "binding", "aggregate", "execution"]
)
def test_authenticated_witness_cannot_hide_invalid_original_report_or_signature(signing, fault):
    c = signing
    _, client = timeout_client()
    with patch("custody.solana_financial_signing.coordinator_request", side_effect=client):
        with pytest.raises(TimeoutError):
            execute_session(**start(c))
    row = MpcSolanaFinancialSession.objects.get(pk=c["ready"].pk)
    request = query(c, row, "RECOVERY")
    evidence = synthetic_completion(c, row, request)
    report = evidence["value"]["execution"]["reports"]["signer-a:2"]
    if fault == "node_signature":
        report["signature"] = "00" * 64
    elif fault == "node_pin":
        report["key_id"] = "ab" * 32
    elif fault == "party":
        report["value"]["party_id"] = "signer-c"
    elif fault == "binding":
        report["value"]["binding_fingerprint"] = "cd" * 32
    elif fault == "aggregate":
        evidence["value"]["execution"]["signature"] = bytes(
            Keypair.from_seed(bytes([87]) * 32).sign_message(b"different-message")
        ).hex()
    else:
        evidence["value"]["execution"]["binding_fingerprint"] = "ef" * 32
    evidence = signed(c, evidence["key_id"], evidence["value"])
    with pytest.raises(ValueError):
        consume_signature(
            session_id=row.pk,
            tenant_id=c["tenant"].pk,
            challenge=request["query"]["challenge"],
            evidence=evidence,
            operator_ref="operator",
        )
    row.refresh_from_db()
    assert row.status == "RECONCILIATION_REQUIRED" and not row.attempt.signed_payload
    assert not MpcSolanaSignatureOwner.objects.exists()


def test_local_transport_failure_keeps_ready_and_no_private_dispatch(signing, settings):
    settings.MPC_CA_CERT = "/nonexistent/original-coordinator-ca.crt"
    with patch("custody.solana_financial_signing.coordinator_request") as private:
        with pytest.raises(OSError):
            execute_session(**start(signing))
        private.assert_not_called()
    row = MpcSolanaFinancialSession.objects.get(pk=signing["ready"].pk)
    assert row.status == "READY" and row.coordinator_evidence == {}
    assert row.operation.status == "HELD"


def test_public_witness_recovery_survives_unavailable_coordinator_route(signing):
    _, client = timeout_client()
    with patch("custody.solana_financial_signing.coordinator_request", side_effect=client):
        with pytest.raises(TimeoutError):
            execute_session(**start(signing))
    row = MpcSolanaFinancialSession.objects.get(pk=signing["ready"].pk)
    original = row.pk, row.crypto_execution_id, row.attempt_id, row.operation_id

    def authoritative_witness(query_value):
        evidence = synthetic_completion(signing, row, {"query": query_value})
        return signed(signing, evidence["key_id"], evidence["value"])

    with (
        patch(
            "custody.solana_financial_signing.resolve_route",
            side_effect=MpcBindingError("route unavailable"),
        ),
        patch("custody.solana_financial_signing.coordinator_request") as coordinator,
        patch(
            "custody.solana_financial_signing.query_witness", side_effect=authoritative_witness
        ) as witness,
    ):
        result = reconcile_session(
            session_id=row.pk, tenant_id=signing["tenant"].pk, operator_ref="operator"
        )
        coordinator.assert_not_called()
        witness.assert_called_once()
    assert result.status == "COMPLETED"
    assert (
        result.pk,
        result.crypto_execution_id,
        result.attempt_id,
        result.operation_id,
    ) == original
    assert result.operation.status == "HELD"
