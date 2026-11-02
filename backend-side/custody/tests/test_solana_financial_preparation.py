"""Real PG/wire/P256 proofs with synthetic funds and W receipts; not MPC acceptance."""

import copy
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.db import DatabaseError, connection, transaction

from custody.models import (
    AdminActionLog,
    LedgerTransaction,
    MpcSolanaFinancialQuery,
    MpcSolanaMessageOwner,
    WithdrawalRequest,
)
from custody.mpc_binding import MpcBindingError
from custody.solana_financial_preparation import _content, approve_session, prepare_session
from custody.tests.test_solana_financial_sessions import (
    clean_mode as mode_fixture,
)
from custody.tests.test_solana_financial_sessions import (
    context as context_fixture,
)
from custody.tests.test_solana_financial_sessions import (
    financial as financial_fixture,
)
from custody.tests.test_solana_financial_sessions import (
    no_signature,
    operation,
    query,
    session,
    terminal,
)
from custody.tests.test_solana_financial_sessions import (
    signer_receipt_trust as receipt_fixture,
)
from custody.tests.test_solana_issuance import signed
from custody.tests.test_solana_witness_client import identity

pytestmark = pytest.mark.django_db(transaction=True)
clean_mode = mode_fixture
context = context_fixture
financial = financial_fixture
signer_receipt_trust = receipt_fixture


@pytest.fixture
def preparation(financial, settings, tmp_path):
    c = financial
    custody_ca = identity(tmp_path / "custody-ca", "ca")
    policy_ca = identity(tmp_path / "policy-ca", "ca")
    c["custody_key"], _ = identity(tmp_path / "custody", "custody", custody_ca)
    c["policy_key"], c["policy_cert"] = identity(tmp_path / "policy", "policy-hot", policy_ca)
    settings.MPC_CLIENT_CERT = str(tmp_path / "custody/tls.crt")
    settings.MPC_CLIENT_KEY = str(tmp_path / "custody/tls.key")
    settings.MPC_SOLANA_FINANCIAL_POLICY_CERTIFICATE = str(tmp_path / "policy/tls.crt")
    settings.MPC_SOLANA_FINANCIAL_POLICY_VERSION = 7
    settings.MPC_SOLANA_FINANCIAL_MAX_LIFETIME_SECONDS = 120
    req = c["withdrawal"]
    req.refresh_from_db()
    AdminActionLog.objects.create(
        actor_id="independent-admin",
        action_type="WITHDRAWAL_APPROVE",
        entity_type="WithdrawalRequest",
        entity_id=str(req.pk),
        metadata={"to": req.to_address, "amount": str(req.amount)},
    )
    original = c["rpc"].rpc

    def observed_rpc(*args):
        assert not connection.in_atomic_block
        result = original(*args)
        if args[1] == "getAccountInfo":
            result["context"] = {"slot": 10}
        return result

    c["rpc"].rpc = observed_rpc
    with patch("custody.solana_financial_preparation._runtime"):
        yield c


def proof(c, row):
    request = query(c, row, "ADMISSION")
    result = terminal(c, row, request)
    result["value"]["abandoned"] = False
    return request, signed(c, result["key_id"], result["value"])


def prepare(c, row=None):
    row = row or session(c)
    request, evidence = proof(c, row)
    return prepare_session(
        session_id=row.pk,
        tenant_id=c["tenant"].pk,
        challenge=request["query"]["challenge"],
        evidence=evidence,
        operator_ref="operator",
        transport=c["rpc"],
    )


def policy(c, row, content=None):
    return {
        "certificate_chain_der_hex": [
            c["policy_cert"].public_bytes(serialization.Encoding.DER).hex()
        ],
        "signature_der_hex": c["policy_key"]
        .sign(
            b"Wallet-MPC/OPERATOR_SEEDED_SPEND_V1\0" + (content or _content(row)),
            ec.ECDSA(hashes.SHA256()),
        )
        .hex(),
    }


def approve(c, row, authorization=None):
    request, evidence = proof(c, row)
    return approve_session(
        session_id=row.pk,
        tenant_id=c["tenant"].pk,
        challenge=request["query"]["challenge"],
        evidence=evidence,
        policy_authorization=authorization or policy(c, row),
        operator_ref="operator",
    )


def test_native_wire_custody_and_independent_policy_preserve_separate_source_and_fee_authority(
    preparation,
):
    c = preparation
    before = LedgerTransaction.objects.count()
    row = prepare(c)
    assert row.status == "WAITING_POLICY" and not row.policy_authorization
    assert row.intent["financial_source"] == c["TREASURY"].claim.address
    assert row.intent["fee_payer"] == c["root"].base_address != row.intent["financial_source"]
    assert (
        row.intent["financial"]["reservation_owner_ref"]
        == c["CUSTOMER"].claim.principal.ledger_owner_id
    )
    assert (
        row.intent["financial"]["source_owner_ref"] == c["TREASURY"].claim.principal.ledger_owner_id
    )
    c["custody_key"].public_key().verify(
        bytes.fromhex(row.custody_authorization["signature_der_hex"]),
        b"Wallet-MPC/CUSTODY_SOLANA_SEEDED_INTENT_V1\0" + _content(row),
        ec.ECDSA(hashes.SHA256()),
    )
    owner = MpcSolanaMessageOwner.objects.get(operation=row.operation)
    assert owner.message_fingerprint == row.intent["message_fingerprint"]
    assert approve(c, row).status == "READY"
    assert LedgerTransaction.objects.count() == before


def test_policy_grant_for_different_wire_is_rejected_without_replacing_intent(preparation):
    c = preparation
    row = prepare(c)
    intent = copy.deepcopy(row.intent)
    with pytest.raises(MpcBindingError, match="exact original wire"):
        approve(c, row, policy(c, row, b"different wire"))
    row.refresh_from_db()
    assert row.intent == intent and row.status == "WAITING_POLICY" and not row.policy_authorization


def test_preparation_audit_failure_retains_allocated_ids_and_original_hold(preparation):
    c = preparation
    row = session(c)
    request, evidence = proof(c, row)
    with patch.object(AdminActionLog.objects, "create", side_effect=RuntimeError("audit")):
        with pytest.raises(RuntimeError, match="audit"):
            prepare_session(
                session_id=row.pk,
                tenant_id=c["tenant"].pk,
                challenge=request["query"]["challenge"],
                evidence=evidence,
                operator_ref="operator",
                transport=c["rpc"],
            )
    row.refresh_from_db()
    row.attempt.refresh_from_db()
    assert row.status == "ALLOCATED" and row.attempt.status == "PREPARING" and not row.intent
    assert not MpcSolanaMessageOwner.objects.exists()
    assert MpcSolanaFinancialQuery.objects.get(pk=request["query"]["challenge"]).status == "PENDING"


@pytest.mark.parametrize("role", ["policy", "policy-warm", "policy-cold", "lifecycle"])
def test_wrong_policy_class_is_rejected_before_custody_key_read(
    preparation, settings, tmp_path, role
):
    c = preparation
    ca = identity(tmp_path / "wrong-ca", "ca")
    identity(tmp_path / "wrong-policy", role, ca)
    settings.MPC_SOLANA_FINANCIAL_POLICY_CERTIFICATE = str(tmp_path / "wrong-policy/tls.crt")
    settings.MPC_CLIENT_KEY = str(tmp_path / "MUST-NOT-BE-READ")
    with pytest.raises(MpcBindingError):
        prepare(c)
    assert not MpcSolanaMessageOwner.objects.exists()


@pytest.mark.parametrize("stage", ["prepare", "approve"])
def test_intent_expiry_during_audit_cannot_commit_authorization(preparation, settings, stage):
    c = preparation
    settings.MPC_SOLANA_FINANCIAL_MAX_LIFETIME_SECONDS = 3
    original = AdminActionLog.objects.create
    row = prepare(c) if stage == "approve" else session(c)
    request, evidence = proof(c, row)

    def delayed(**kwargs):
        result = original(**kwargs)
        time.sleep(3.1)
        return result

    with patch.object(AdminActionLog.objects, "create", side_effect=delayed):
        with pytest.raises(DatabaseError, match="intent expired"):
            if stage == "prepare":
                prepare_session(
                    session_id=row.pk,
                    tenant_id=c["tenant"].pk,
                    challenge=request["query"]["challenge"],
                    evidence=evidence,
                    operator_ref="operator",
                    transport=c["rpc"],
                )
            else:
                approve_session(
                    session_id=row.pk,
                    tenant_id=c["tenant"].pk,
                    challenge=request["query"]["challenge"],
                    evidence=evidence,
                    policy_authorization=policy(c, row),
                    operator_ref="operator",
                )
    row.refresh_from_db()
    assert row.status == ("ALLOCATED" if stage == "prepare" else "WAITING_POLICY")
    assert MpcSolanaFinancialQuery.objects.get(pk=request["query"]["challenge"]).status == "PENDING"


@pytest.mark.parametrize("terminal_kind", ["abandoned", "known_no_signature"])
def test_prepared_terminal_proof_retains_wire_owner_and_reuses_business_hold(
    preparation, terminal_kind
):
    from custody.solana_issuance import _fingerprint

    c = preparation
    row = prepare(c)
    request = query(c, row, "TERMINAL")
    evidence = terminal(c, row, request)
    if terminal_kind == "known_no_signature":
        evidence["value"].update(
            abandoned=False,
            execution={
                "status": "NoSignature",
                "signature": None,
                "binding_fingerprint": _fingerprint(
                    "WITNESS_EXECUTION_V1",
                    [
                        _fingerprint("WITNESS_INTENT_V1", [row.intent, bytes(row.payload).hex()]),
                        row.selected_signers,
                    ],
                ),
                "reports": {},
            },
        )
        evidence = signed(c, evidence["key_id"], evidence["value"])
    assert no_signature(c, row, request, evidence).status == "NO_SIGNATURE"
    retry = session(c, row.operation, selected_signers=["signer-a", "signer-c"])
    assert retry.pk != row.pk and retry.operation_id == row.operation_id
    assert MpcSolanaMessageOwner.objects.get(operation=row.operation).first_session_id == row.pk


def second_withdrawal(c):
    from custody.ledger import reserve_withdrawal

    original = c["withdrawal"]
    with transaction.atomic():
        req = WithdrawalRequest.objects.create(
            user_id=original.user_id,
            chain_id="SOL",
            asset_key="SOL",
            to_address=original.to_address,
            amount=original.amount,
            status="APPROVED",
        )
        reserve_withdrawal(req)
        req.refresh_from_db()
        AdminActionLog.objects.create(
            actor_id="independent-admin",
            action_type="WITHDRAWAL_APPROVE",
            entity_type="WithdrawalRequest",
            entity_id=str(req.pk),
            metadata={"to": req.to_address, "amount": str(req.amount)},
        )
    return operation(c, withdrawal_id=req.pk)


def test_same_wire_cannot_be_owned_by_a_second_business_before_private_work(preparation):
    c = preparation
    first = prepare(c)
    second = second_withdrawal(c)
    row = session(c, second)
    with pytest.raises(MpcBindingError, match="another business"):
        prepare(c, row)
    row.refresh_from_db()
    row.attempt.refresh_from_db()
    assert row.status == "ALLOCATED" and row.attempt.status == "PREPARING"
    assert MpcSolanaMessageOwner.objects.count() == 1
    assert MpcSolanaMessageOwner.objects.get().operation_id == first.operation_id


@pytest.mark.parametrize("balance_kind", ["source", "base"])
def test_liquidity_covers_all_businesses_and_keeps_source_separate_from_fee_base(
    preparation, balance_kind
):
    from custody.native_tx import InsufficientBalance

    c = preparation
    row = session(c)
    second_withdrawal(c)
    original = c["rpc"].rpc

    def limited(url, method, params):
        result = original(url, method, params)
        if method == "getAccountInfo":
            if balance_kind == "base" and params[0] == c["root"].base_address:
                result["value"]["lamports"] = 30_000  # actual5k fits; both20k caps do not.
            if balance_kind == "source" and params[0] == c["TREASURY"].claim.address:
                result["value"]["lamports"] = 1_500_000_000  # one1SOL fits, both do not.
        return result

    c["rpc"].rpc = limited
    with pytest.raises(InsufficientBalance):
        prepare(c, row)
    row.refresh_from_db()
    assert row.status == "ALLOCATED"


def test_hold_birth_during_rpc_observation_requires_new_quote(preparation):
    c = preparation
    row = session(c)
    original = c["rpc"].rpc
    changed = False

    def concurrent_birth(url, method, params):
        nonlocal changed
        result = original(url, method, params)
        if method == "getAccountInfo" and not changed:
            changed = True
            second_withdrawal(c)
        return result

    c["rpc"].rpc = concurrent_birth
    with pytest.raises(MpcBindingError, match="reservations changed"):
        prepare(c, row)
    row.refresh_from_db()
    assert row.status == "ALLOCATED"


def test_lagging_rpc_context_cannot_precede_accepted_effect_floor(preparation):
    c = preparation
    with patch("custody.solana_financial_preparation._effect_slot", return_value=20):
        with pytest.raises(MpcBindingError, match="predates accepted"):
            prepare(c)
    assert any(
        method == "getAccountInfo" and params[1]["minContextSlot"] == 20
        for _, method, params in c["rpc"].calls
    )


def test_fresh_liquidity_quote_never_replaces_original_prepared_blockhash(preparation):
    from solders.hash import Hash

    from custody.solana_financial_preparation import _quote

    c = preparation
    row = prepare(c)
    original_wire = bytes(row.payload)
    original_hash = row.intent["recent_blockhash"]
    c["rpc"].blockhash = str(Hash.from_bytes(bytes([8]) * 32))
    observed = _quote(row, c["rpc"], fixed=True)
    assert observed.signing_payload == original_wire
    assert observed.unsigned_payload["recentBlockhash"] == original_hash
    assert row.intent["recent_blockhash"] != c["rpc"].blockhash


@pytest.mark.parametrize("role", ["custody", "policy"])
def test_expired_installed_authority_is_rejected_before_custody_private_key(
    preparation, settings, tmp_path, role
):
    c = preparation
    key = c["custody_key"] if role == "custody" else c["policy_key"]
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "expired authority")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now - timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        "spiffe://wallet-mpc/" + ("custody" if role == "custody" else "policy-hot")
                    )
                ]
            ),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "expired.crt"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if role == "custody":
        settings.MPC_CLIENT_CERT = str(path)
    else:
        settings.MPC_SOLANA_FINANCIAL_POLICY_CERTIFICATE = str(path)
    settings.MPC_CLIENT_KEY = str(tmp_path / "MUST-NOT-BE-READ")
    with pytest.raises(MpcBindingError):
        prepare(c)
