"""Actual PG/P256 boundaries with synthetic W readiness; no MPC acceptance claim."""

import copy
import hashlib
import secrets
import time
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.db import DatabaseError, connection, transaction
from django.utils import timezone

from custody.models import (
    LedgerTransaction,
    MpcSolanaClaimApproval,
    MpcSolanaClaimQuery,
    MpcSolanaClaimRegistration,
    MpcSolanaIssuance,
    UserWallet,
)
from custody.mpc_binding import MpcBindingError
from custody.solana_claim_registration import (
    _query,
    begin_current_claim_approval,
    claim_query_request,
    complete_claim_registration,
    effective_claim_evidence,
    record_current_claim_evidence,
)
from custody.solana_issuance import _canonical, _fingerprint
from custody.solana_provisioning import _claim_evidence
from custody.solana_witness_client import _point_id
from custody.tests import test_solana_token_provisioning as token_fixtures
from custody.tests.test_solana_issuance import (
    begin as begin_publication,
)
from custody.tests.test_solana_issuance import (
    complete as complete_publication,
)
from custody.tests.test_solana_issuance import (
    context as context_fixture,
)
from custody.tests.test_solana_issuance import (
    issuance as issuance_fixture,
)
from custody.tests.test_solana_issuance import (
    reply as publication_reply,
)
from custody.tests.test_solana_issuance import (
    signed as witness_signed,
)
from custody.tests.test_solana_issuance import (
    signer_receipt_trust as receipt_fixture,
)
from custody.tests.test_solana_witness_client import identity

pytestmark = pytest.mark.django_db(transaction=True)
context = context_fixture
issuance = issuance_fixture
signer_receipt_trust = receipt_fixture


def signed(key, domain, value):
    body = dict(key_id=_point_id(key.public_key()), value=value)
    body["signature"] = key.sign(
        f"Wallet-MPC/{domain}\0".encode() + _canonical(body), ec.ECDSA(hashes.SHA256())
    ).hex()
    return body


def configure(c, settings, tmp_path):
    ca = identity(tmp_path / "current-ca", "ca")
    life, _ = identity(tmp_path / "life", "lifecycle", ca)
    identity(tmp_path / "custody", "custody", ca)
    keys, certificates = {}, {}
    for party in ("signer-a", "signer-b", "signer-c"):
        key, cert = identity(tmp_path / party, party, ca)
        keys[party] = key
        certificates[party] = cert.public_bytes(serialization.Encoding.DER).hex()
    settings.MPC_SOLANA_CURRENT_CLAIMS_ENABLED = True
    settings.MPC_SOLANA_LIFECYCLE_CERTIFICATE = str(tmp_path / "life/tls.crt")
    settings.MPC_CLIENT_CERT = str(tmp_path / "custody/tls.crt")
    settings.MPC_CLIENT_KEY = str(tmp_path / "custody/tls.key")
    root = c["claim"].root.statement
    package = root["public_key_package"]
    previous = dict(
        epoch=0,
        ceremony_id=root["dkg"]["execution_id"],
        public_key_package_sha256=hashlib.sha256(bytes(package)).hexdigest(),
    )
    generation = dict(previous, epoch=1, ceremony_id=str(uuid4()))
    ready = [
        signed(
            key,
            "WITNESS_GENERATION_READY_V1",
            dict(
                root_identity=_fingerprint("SOLANA_SEEDED_ROOT_V1", root),
                previous_generation=previous,
                generation=generation,
                public_key_package=package,
                party_id=party,
            ),
        )
        for party, key in keys.items()
    ]
    prepare = signed(
        life,
        "WITNESS_COMMAND_V1",
        dict(
            anchor_id=settings.MPC_SOLANA_WITNESS_ANCHOR_ID,
            root_identity=_fingerprint("SOLANA_SEEDED_ROOT_V1", root),
            request_id=str(uuid4()),
            expected_revision=2,
            expires_at=1,
            action=dict(
                kind="Prepare",
                ready=ready,
                node_keys={party: _point_id(key.public_key()) for party, key in keys.items()},
            ),
        ),
    )
    c.update(current_keys=keys, certificates=certificates, prepare=prepare)
    return c


@pytest.fixture
def current(issuance, settings, tmp_path):
    c = configure(issuance, settings, tmp_path)
    with patch("custody.solana_claim_registration._runtime"):
        yield c


def ask(c, attempt=None):
    return claim_query_request(
        reservation_id=c["claim"].pk,
        tenant_id=c["tenant"].pk,
        operator_ref="operator",
        attempt_id=attempt.pk if attempt else None,
    )


def reply(c, request, *, registered=None, phase="Active"):
    action = c["prepare"]["value"]["action"]
    row = MpcSolanaClaimQuery.objects.get(pk=request["challenge"])
    value = dict(
        query=request["query"],
        sequence=6,
        root=dict(
            original=c["claim"].root.statement,
            revision=6,
            phase=phase,
            generation=action["ready"][0]["value"]["generation"],
            public_key_package=action["ready"][0]["value"]["public_key_package"],
            node_keys=action["node_keys"],
            prepared=None,
            next_claim_index=c["claim"].index + (registered is not None),
        ),
        claim=registered,
        execution=None,
        abandoned=False,
        lifecycle_key_id=c["prepare"]["key_id"],
        generation_authority=c["prepare"],
        claim_availability=dict(
            reservation_id=str(c["claim"].pk), index=None, owner=None, retry=None
        ),
    )
    return witness_signed(c, row.witness_key_id, value)


def begin(c, request=None, proof=None):
    request = request or ask(c)
    return begin_current_claim_approval(
        challenge=request["challenge"],
        tenant_id=c["tenant"].pk,
        evidence=proof or reply(c, request),
        node_certificates_der_hex=c["certificates"],
        operator_ref="operator",
    )


def reports(c, attempt):
    claim, authority = attempt.approval["statement"], attempt.approval["authority"]
    values = []
    for party, key in c["current_keys"].items():
        body = dict(statement=claim, authority=authority, party_id=party, durable=True)
        signature = key.sign(
            b"Wallet-MPC/SIGNER_SOLANA_CURRENT_CLAIM_V1\0" + _canonical(body),
            ec.ECDSA(hashes.SHA256()),
        ).hex()
        values.append(
            dict(
                statement=copy.deepcopy(claim),
                party_id=party,
                durable=True,
                signer_signature=signature,
            )
        )
    return dict(
        statement=copy.deepcopy(claim),
        authority=copy.deepcopy(authority),
        participant_agreement=values,
    )


def record(c, attempt):
    return record_current_claim_evidence(
        attempt_id=attempt.pk,
        tenant_id=c["tenant"].pk,
        evidence=reports(c, attempt),
        operator_ref="operator",
    )


def finish(c, attempt, phase="Active"):
    request = ask(c, attempt)
    proof = reply(c, request, registered=attempt.evidence, phase=phase)
    registration = complete_claim_registration(
        challenge=request["challenge"],
        tenant_id=c["tenant"].pk,
        evidence=proof,
        operator_ref="operator",
    )
    return registration, request, proof


def test_legacy_approval_is_immutable_but_effective_registered_context_is_current(current):
    c = current
    original = copy.deepcopy(c["claim"].evidence)
    ledger = LedgerTransaction.objects.count()
    attempt = begin(c)
    assert MpcSolanaClaimApproval.objects.get(pk=attempt.pk).status == "PENDING"
    attempt = record(c, attempt)
    assert not MpcSolanaClaimRegistration.objects.exists()
    assert _claim_evidence(c["claim"]) == original
    registration, request, proof = finish(c, attempt)
    c["claim"].refresh_from_db()
    assert c["claim"].evidence == original
    assert effective_claim_evidence(c["claim"]) == attempt.evidence == registration.evidence
    assert (
        complete_claim_registration(
            challenge=request["challenge"],
            tenant_id=c["tenant"].pk,
            evidence=proof,
            operator_ref="operator",
        ).pk
        == registration.pk
    )
    assert not UserWallet.objects.exists()
    assert LedgerTransaction.objects.count() == ledger


def test_pending_publication_keeps_original_ids_and_consumes_current_registered_evidence(current):
    c = current
    original = copy.deepcopy(c["claim"].evidence)
    first = begin_publication(c)
    attempt = record(c, begin(c))
    finish(c, attempt)
    request = begin_publication(c)
    assert request["issuance_id"] == first["issuance_id"]
    legacy_proof = publication_reply(c, request)
    with pytest.raises(MpcBindingError):
        complete_publication(c, request, legacy_proof)
    value = copy.deepcopy(legacy_proof["value"])
    value["claim"] = attempt.evidence
    proof = witness_signed(c, legacy_proof["key_id"], value)
    wallet = complete_publication(c, request, proof)
    assert wallet.solana_claim_id == c["claim"].pk
    c["claim"].refresh_from_db()
    assert c["claim"].evidence == original
    assert MpcSolanaIssuance.objects.get(pk=first["issuance_id"]).status == "WITNESSED"


def test_registered_archival_import_is_allowed_when_root_is_frozen(current):
    c = current
    request = ask(c)
    proof = reply(c, request, registered=c["claim"].evidence, phase="Frozen")
    row = complete_claim_registration(
        challenge=request["challenge"],
        tenant_id=c["tenant"].pk,
        evidence=proof,
        operator_ref="operator",
    )
    assert row.evidence == c["claim"].evidence
    assert not MpcSolanaClaimApproval.objects.exists()


@pytest.mark.parametrize("fault", range(10))
def test_changed_discovery_or_authority_cannot_create_an_attempt(current, fault):
    c = current
    request = ask(c)
    proof = reply(c, request)
    value = proof["value"]
    if fault == 0:
        value["query"]["challenge"] = "00" * 32
    elif fault == 1:
        value["root"]["original"]["ownership_scope"] = str(uuid4())
    elif fault == 2:
        value["root"]["phase"] = "Frozen"
    elif fault == 3:
        value["root"]["next_claim_index"] += 1
    elif fault == 4:
        value["claim_availability"]["owner"] = str(uuid4())
    elif fault == 5:
        value["claim"] = c["claim"].evidence
    elif fault == 6:
        value["root"]["node_keys"]["signer-a"] = "00" * 32
    elif fault == 7:
        value["generation_authority"]["signature"] = "00" * 70
    elif fault == 8:
        c["certificates"]["signer-a"] = c["certificates"]["signer-b"]
    else:
        value["query"]["candidate_claim"]["owner_ref"] += "changed"
    proof = witness_signed(c, proof["key_id"], value)
    with pytest.raises((MpcBindingError, ValueError)):
        begin(c, request, proof)
    assert not MpcSolanaClaimApproval.objects.exists()
    assert MpcSolanaClaimQuery.objects.get(pk=request["challenge"]).status == "PENDING"


def test_audit_rollback_after_registered_public_result_recovers_same_ids(current):
    c = current
    attempt = record(c, begin(c))
    request = ask(c, attempt)
    proof = reply(c, request, registered=attempt.evidence)
    with patch("custody.solana_claim_registration._audit", side_effect=RuntimeError("audit fault")):
        with pytest.raises(RuntimeError):
            complete_claim_registration(
                challenge=request["challenge"],
                tenant_id=c["tenant"].pk,
                evidence=proof,
                operator_ref="operator",
            )
    assert not MpcSolanaClaimRegistration.objects.exists()
    assert MpcSolanaClaimQuery.objects.get(pk=request["challenge"]).status == "PENDING"
    row = complete_claim_registration(
        challenge=request["challenge"],
        tenant_id=c["tenant"].pk,
        evidence=proof,
        operator_ref="operator",
    )
    assert row.evidence == attempt.evidence
    assert MpcSolanaClaimApproval.objects.get(pk=attempt.pk).command_id == attempt.command_id


def test_expiry_at_commit_rolls_back_query_and_approval(current):
    c = current
    request = ask(c)
    # Use a new genuine short lease; immutable existing leases cannot be edited.
    original = MpcSolanaClaimQuery.objects.get(pk=request["challenge"])
    row = MpcSolanaClaimQuery.objects.create(
        claim=c["claim"],
        purpose="DISCOVERY",
        witness_anchor_id=original.witness_anchor_id,
        witness_key_id=original.witness_key_id,
        challenge=secrets.token_hex(32),
        expires_at=timezone.now() + timedelta(seconds=0.15),
    )
    row.claim = c["claim"]
    short = dict(challenge=row.pk, query=_query(row))
    from custody.solana_claim_registration import _audit as original_audit

    def delayed(*args, **kwargs):
        original_audit(*args, **kwargs)
        time.sleep(0.25)

    with patch("custody.solana_claim_registration._audit", side_effect=delayed):
        with pytest.raises(DatabaseError, match="expired before commit"):
            begin(c, short)
    assert not MpcSolanaClaimApproval.objects.exists()
    assert MpcSolanaClaimQuery.objects.get(pk=row.pk).status == "PENDING"


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
def test_raw_query_birth_rejects_stale_snapshot_isolation(current, isolation):
    c = current
    ref = MpcSolanaClaimQuery.objects.get(pk=ask(c)["challenge"])
    with pytest.raises(DatabaseError, match="READ COMMITTED"):
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL " + isolation)
                cursor.execute("SELECT 1")
            MpcSolanaClaimQuery.objects.create(
                claim=c["claim"],
                purpose="DISCOVERY",
                witness_anchor_id=ref.witness_anchor_id,
                witness_key_id=ref.witness_key_id,
                challenge=secrets.token_hex(32),
                expires_at=timezone.now() + timedelta(seconds=15),
            )


@pytest.mark.parametrize("entity", ["query", "approval", "registration"])
@pytest.mark.parametrize("action", ["update", "delete"])
def test_accepted_public_history_is_immutable_to_raw_sql(current, entity, action):
    c = current
    attempt = record(c, begin(c))
    registration, _, _ = finish(c, attempt)
    obj = {"query": registration.query, "approval": attempt, "registration": registration}[entity]
    with pytest.raises(DatabaseError):
        if action == "delete":
            type(obj).objects.filter(pk=obj.pk).delete()
        else:
            type(obj).objects.filter(pk=obj.pk).update(evidence={})


def test_new_workflow_default_off_leaves_no_public_attempt(current, settings):
    settings.MPC_SOLANA_CURRENT_CLAIMS_ENABLED = False
    with pytest.raises(MpcBindingError, match="disabled"):
        ask(current)
    assert not MpcSolanaClaimQuery.objects.exists()
    assert not MpcSolanaClaimApproval.objects.exists()


clean_mode = token_fixtures.clean_mode
financial = token_fixtures.financial
preparation = token_fixtures.preparation
pending = token_fixtures.pending


@pytest.fixture
def current_pending(pending, settings, tmp_path):
    pending["claim"] = pending["token_claim"]
    c = configure(pending, settings, tmp_path / "current")
    with patch("custody.solana_claim_registration._runtime"):
        yield c


@pytest.mark.parametrize("allocated", [False, True])
def test_unprepared_classic_hold_and_empty_session_keep_all_original_ids(
    current_pending, allocated
):
    from custody.models import MpcSolanaFinancialOperation, MpcSolanaFinancialSession
    from custody.solana_financial_sessions import allocate_session

    c = current_pending
    operation = token_fixtures.allocate(c)
    before = LedgerTransaction.objects.count()
    row = None
    if allocated:
        row = allocate_session(
            reservation_id=operation.pk,
            tenant_id=c["tenant"].pk,
            selected_signers=["signer-a", "signer-b"],
            operator_ref="operator",
        )
        identity_before = (row.pk, row.crypto_execution_id, row.attempt_id, row.operation_id)
    attempt = record(c, begin(c))
    finish(c, attempt)
    assert MpcSolanaFinancialOperation.objects.get(pk=operation.pk).status == "HELD"
    if row:
        row.refresh_from_db()
        assert (
            row.pk,
            row.crypto_execution_id,
            row.attempt_id,
            row.operation_id,
        ) == identity_before
        assert row.status == "ALLOCATED" and row.intent == {} and bytes(row.payload) == b""
        assert MpcSolanaFinancialSession.objects.filter(operation=operation).count() == 1
    assert LedgerTransaction.objects.count() == before
    assert not UserWallet.objects.filter(solana_claim_id=c["claim"].pk).exists()


def test_prepared_classic_business_cannot_migrate_even_with_conflicting_absence_proof(
    current_pending,
):
    c = current_pending
    row = token_fixtures.prepared(c)
    assert row.status == "WAITING_POLICY"
    with pytest.raises(MpcBindingError, match="consumed or uncertain"):
        begin(c)
    assert not MpcSolanaClaimRegistration.objects.exists()
    row.refresh_from_db()
    assert row.status == "WAITING_POLICY"


@pytest.mark.parametrize("fault", range(15))
def test_sql_current_shape_rejects_malformed_public_data(current, fault):
    from django.db.backends.postgresql.psycopg_any import Jsonb

    c = current
    attempt = begin(c)
    original = reports(c, attempt)
    value = copy.deepcopy(original)
    authority = value["authority"]
    command = authority["prepare"]["value"]
    ready = command["action"]["ready"]
    if fault == 0:
        authority["version"] = True
    elif fault == 1:
        authority["extra"] = "unknown"
    elif fault == 2:
        command.pop("anchor_id")
    elif fault == 3:
        command.pop("expected_revision")
    elif fault == 4:
        ready[0]["value"]["generation"].pop("ceremony_id")
    elif fault == 5:
        ready.pop()
    elif fault == 6:
        command["expected_revision"] = None
    elif fault == 7:
        ready[0]["value"]["previous_generation"]["epoch"] = "unknown"
    elif fault == 8:
        ready[0]["value"]["public_key_package"][0] = True
    elif fault == 9:
        ready[0]["value"]["public_key_package"][0] = 256
    elif fault == 10:
        ready[0]["value"]["previous_generation"]["public_key_package_sha256"] = "bad"
    elif fault == 11:
        command["action"]["node_keys"]["signer-a"] = command["action"]["node_keys"]["signer-b"]
    elif fault == 12:
        authority["prepare"]["signature"] = "a" * 17
    elif fault == 13:
        value["participant_agreement"][0]["durable"] = 1
    else:
        value["statement"] = {}
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT custody_sol_claim_evidence_valid(%s,%s)",
            [Jsonb(c["claim"].statement), Jsonb(original)],
        )
        assert cursor.fetchone() == (True,)
        cursor.execute(
            "SELECT custody_sol_claim_evidence_valid(%s,%s)",
            [Jsonb(c["claim"].statement), Jsonb(value)],
        )
        assert cursor.fetchone() == (False,)
        cursor.execute(
            "SELECT custody_sol_evidence_valid(%s,%s)",
            [Jsonb(c["claim"].statement), Jsonb(original)],
        )
        assert cursor.fetchone() == (False,)


@pytest.mark.parametrize("first", ["registration", "publication"])
@pytest.mark.parametrize("raw_publication", [False, True])
def test_registration_and_old_publication_serialize_in_both_orders(current, first, raw_publication):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from django.db import close_old_connections

    from custody.models import AdminActionLog
    from custody.tests.test_solana_financial_root import wait_for_database_lock

    c = current
    publication = begin_publication(c)
    old_grant = publication_reply(c, publication)
    attempt = record(c, begin(c))
    registration = ask(c, attempt)
    current_proof = reply(c, registration, registered=attempt.evidence)
    # Deliberately conflicting synthetic signed snapshots exercise PG protection;
    # a genuine permanent W registry cannot register both different Evidences.
    entered, release = threading.Event(), threading.Event()
    old_create = AdminActionLog.objects.create

    def audit(*args, **kwargs):
        value = old_create(*args, **kwargs)
        expected = {
            "registration": "SOL_CURRENT_CLAIM_REGISTER",
            "publication": "SOLANA_NATIVE_WALLET_PUBLISH",
        }[first]
        if kwargs.get("action_type") == expected:
            entered.set()
            assert release.wait(5)
        return value

    def worker(kind):
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT set_config('application_name',%s,false)",
                    ["current-evidence-race-" + kind],
                )
            if kind == "registration":
                return complete_claim_registration(
                    challenge=registration["challenge"],
                    tenant_id=c["tenant"].pk,
                    evidence=current_proof,
                    operator_ref="operator",
                )
            if not raw_publication:
                return complete_publication(c, publication, old_grant)
            with transaction.atomic():
                value = MpcSolanaIssuance.objects.filter(pk=publication["issuance_id"]).update(
                    status="WITNESSED", evidence=old_grant
                )
                if first == "publication":
                    entered.set()
                    assert release.wait(5)
                return value
        finally:
            close_old_connections()

    second = "publication" if first == "registration" else "registration"
    with patch.object(AdminActionLog.objects, "create", side_effect=audit):
        with ThreadPoolExecutor(max_workers=2) as workers:
            leading = workers.submit(worker, first)
            try:
                assert entered.wait(5)
                trailing = workers.submit(worker, second)
                wait_for_database_lock("current-evidence-race-" + second)
                assert not trailing.done()
            finally:
                release.set()
            leading.result(timeout=10)
            with pytest.raises((MpcBindingError, DatabaseError)):
                trailing.result(timeout=10)
    assert MpcSolanaClaimRegistration.objects.filter(claim=c["claim"]).exists() == (
        first == "registration"
    )
    assert MpcSolanaIssuance.objects.get(pk=publication["issuance_id"]).status == (
        "PENDING" if first == "registration" else "WITNESSED"
    )
    assert (
        not UserWallet.objects.filter(solana_claim=c["claim"]).exists()
        if (first == "registration" or raw_publication)
        else UserWallet.objects.filter(solana_claim=c["claim"]).exists()
    )


@pytest.mark.parametrize("first", ["registration", "metadata"])
def test_empty_attempt_classification_locks_raw_metadata_in_both_orders(current_pending, first):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from django.db import close_old_connections

    from custody.models import AdminActionLog, OnchainTransactionAttempt
    from custody.solana_financial_sessions import allocate_session
    from custody.tests.test_solana_financial_root import wait_for_database_lock

    c = current_pending
    operation = token_fixtures.allocate(c)
    session = allocate_session(
        reservation_id=operation.pk,
        tenant_id=c["tenant"].pk,
        selected_signers=["signer-a", "signer-b"],
        operator_ref="operator",
    )
    attempt = record(c, begin(c))
    request = ask(c, attempt)
    proof = reply(c, request, registered=attempt.evidence)
    entered, release = threading.Event(), threading.Event()
    original_create = AdminActionLog.objects.create

    def audit(*args, **kwargs):
        value = original_create(*args, **kwargs)
        if first == "registration" and kwargs.get("action_type") == "SOL_CURRENT_CLAIM_REGISTER":
            entered.set()
            assert release.wait(5)
        return value

    def worker(kind):
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT set_config('application_name',%s,false)", ["current-empty-race-" + kind]
                )
            if kind == "registration":
                return complete_claim_registration(
                    challenge=request["challenge"],
                    tenant_id=c["tenant"].pk,
                    evidence=proof,
                    operator_ref="operator",
                )
            with transaction.atomic():
                value = OnchainTransactionAttempt.objects.filter(pk=session.attempt_id).update(
                    prepared_metadata={"classification": "raw-metadata-consumed"}
                )
                if first == "metadata":
                    entered.set()
                    assert release.wait(5)
                return value
        finally:
            close_old_connections()

    second = "metadata" if first == "registration" else "registration"
    with patch.object(AdminActionLog.objects, "create", side_effect=audit):
        with ThreadPoolExecutor(max_workers=2) as workers:
            leading = workers.submit(worker, first)
            try:
                assert entered.wait(5)
                trailing = workers.submit(worker, second)
                wait_for_database_lock("current-empty-race-" + second)
                assert not trailing.done()
            finally:
                release.set()
            leading.result(timeout=10)
            if first == "metadata":
                with pytest.raises((MpcBindingError, DatabaseError)):
                    trailing.result(timeout=10)
            else:
                trailing.result(timeout=10)
    assert MpcSolanaClaimRegistration.objects.filter(claim=c["claim"]).exists() == (
        first == "registration"
    )
    operation.refresh_from_db()
    session.refresh_from_db()
    assert operation.status == "HELD" and session.status == "ALLOCATED" and session.intent == {}


def test_privileged_cli_public_handoff_uses_original_query_attempt_and_command(current, tmp_path):
    import json
    from io import StringIO

    from django.core.management import call_command

    c = current
    shared = dict(tenant_id=str(c["tenant"].pk), operator_ref="operator")

    def command(action, **arguments):
        output = StringIO()
        call_command("solana_current_claim", action, **shared, **arguments, stdout=output)
        return json.loads(output.getvalue())

    request = command("query", reservation_id=str(c["claim"].pk))
    proof_file = tmp_path / "public-witness.json"
    certificates = tmp_path / "public-node-certificates.json"
    proof_file.write_text(json.dumps(reply(c, request)))
    certificates.write_text(json.dumps(c["certificates"]))
    created = command(
        "begin",
        challenge=request["challenge"],
        evidence=str(proof_file),
        node_certificates=str(certificates),
    )
    attempt = MpcSolanaClaimApproval.objects.get(pk=created["attempt_id"])
    assert created["command_id"] == str(attempt.command_id)
    proof_file.write_text(json.dumps(reports(c, attempt)))
    recorded = command("record", attempt_id=str(attempt.pk), evidence=str(proof_file))
    assert recorded["attempt_id"] == created["attempt_id"]
    assert recorded["status"] == "REPORTED" and not recorded["publication_performed"]
    attempt.refresh_from_db()
    request = command("query", reservation_id=str(c["claim"].pk), attempt_id=str(attempt.pk))
    assert request["command_id"] == created["command_id"]
    proof_file.write_text(json.dumps(reply(c, request, registered=attempt.evidence)))
    result = command("complete", challenge=request["challenge"], evidence=str(proof_file))
    assert result == {"claim_id": str(c["claim"].pk), "publication_performed": False}
    assert not UserWallet.objects.filter(solana_claim=c["claim"]).exists()


def test_raw_registration_from_previously_verified_query_rechecks_commit_expiry(current):
    c = current
    attempt = record(c, begin(c))
    reference = MpcSolanaClaimQuery.objects.get(pk=ask(c, attempt)["challenge"])
    query = MpcSolanaClaimQuery.objects.create(
        claim=c["claim"],
        attempt=attempt,
        purpose="REGISTRATION",
        witness_anchor_id=reference.witness_anchor_id,
        witness_key_id=reference.witness_key_id,
        challenge=secrets.token_hex(32),
        expires_at=timezone.now() + timedelta(seconds=0.2),
    )
    query.claim = c["claim"]
    request = dict(challenge=query.pk, query=_query(query))
    proof = reply(c, request, registered=attempt.evidence)
    query.status, query.evidence = "VERIFIED", proof
    query.save(update_fields=["status", "evidence"])  # Genuine separate fresh commit.
    assert MpcSolanaClaimQuery.objects.get(pk=query.pk).status == "VERIFIED"
    with pytest.raises(DatabaseError, match="registration query expired before commit"):
        with transaction.atomic():
            MpcSolanaClaimRegistration.objects.create(
                claim=c["claim"], query=query, evidence=attempt.evidence
            )
            time.sleep(0.3)
    assert not MpcSolanaClaimRegistration.objects.exists()
    assert MpcSolanaClaimQuery.objects.get(pk=query.pk).evidence == proof
