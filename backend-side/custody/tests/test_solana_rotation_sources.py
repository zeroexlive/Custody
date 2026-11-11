"""Actual PG/P256 contracts with synthetic W data; not MPC acceptance."""

import copy
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, close_old_connections, connection, transaction
from django.utils import timezone

from custody.models import (
    AdminActionLog,
    LedgerTransaction,
    MpcSolanaClaimRegistration,
    MpcSolanaFinancialOperation,
    MpcSolanaFinancialWallet,
    MpcSolanaIssuance,
    MpcSolanaRotationInventoryEntry,
    MpcSolanaRotationSourceQuery,
    UserWallet,
)
from custody.mpc_binding import MpcBindingError
from custody.solana_issuance import _fingerprint
from custody.solana_rotation_sources import (
    accept_source_query,
    request_source_query,
    source_control_archive,
)
from custody.solana_witness_client import _point_id
from custody.tests.test_phase6gb_issuance import _RECEIPT_KEYS
from custody.tests.test_solana_claim_registration import configure, reports
from custody.tests.test_solana_financial_root import clean_mode as clean_mode_fixture
from custody.tests.test_solana_financial_root import wait_for_database_lock
from custody.tests.test_solana_issuance import signed
from custody.tests.test_solana_provisioning import approve, evidence, reserve, token
from custody.tests.test_solana_provisioning import context as context_fixture
from custody.tests.test_solana_receipt_pins import certificates
from custody.tests.test_solana_rotation_inventory import accept, begin, query, reply

pytestmark = pytest.mark.django_db(transaction=True)
context = context_fixture
clean_mode = clean_mode_fixture


@pytest.fixture
def signer_receipt_trust(settings, tmp_path):
    settings.MPC_HD_SIGNER_CERTIFICATES = certificates(tmp_path)


@pytest.fixture(autouse=True)
def enabled(settings):
    settings.MPC_SOLANA_ALLOCATION_PAUSE_ENABLED = True
    settings.MPC_SOLANA_ROTATION_INVENTORY_ENABLED = True
    with (
        patch("custody.solana_rotation_inventory._runtime"),
        patch("custody.solana_rotation_sources._runtime"),
    ):
        yield


def captured(
    c,
    *,
    approved=False,
    registered=False,
    asset="SOL",
    current=None,
    current_epoch=1,
    original_current=False,
):
    claim = reserve(c, asset=asset)
    if approved:
        claim = approve(c, claim)
    c["claim"] = claim
    c["source_evidence"] = evidence("claim", claim.statement)
    if current is not None:
        settings, tmp_path = current
        configure(c, settings, tmp_path)
        authority = dict(
            version=1, prepare=c["prepare"], node_certificates_der_hex=c["certificates"]
        )
        c["current_evidence"] = reports(
            c, SimpleNamespace(approval=dict(statement=claim.statement, authority=authority))
        )
        if original_current:
            c["source_evidence"] = c["current_evidence"]
        action = c["prepare"]["value"]["action"]
        c["root_context"] = dict(
            generation=dict(action["ready"][0]["value"]["generation"], epoch=current_epoch),
            public_key_package=claim.root.statement["public_key_package"],
            node_keys=action["node_keys"],
        )
        if not registered:
            c["source_evidence"] = c["current_evidence"]
    else:
        c["root_context"] = dict(
            node_keys={p: _point_id(k.public_key()) for p, k in _RECEIPT_KEYS.items()}
        )
    c["inventory_known_count"] = int(registered)
    row = begin(c, roles={str(claim.principal_id): "CUSTOMER_DEPOSIT"})
    for purpose, index in (("ROOT", None), ("ENTRY", 0), ("SEAL", None)):
        request = query(c, row, purpose, index)
        value = reply(
            c,
            row,
            request,
            claim=c["source_evidence"] if purpose == "ENTRY" and registered else None,
        )
        value["value"]["root"].update(copy.deepcopy(c["root_context"]))
        accept(c, request, signed(c, row.witness_key_id, value["value"]))
        row.refresh_from_db()
    c["source_snapshot"], c["rotation_id"] = row, uuid4()
    return row


def ask(c, **changes):
    arguments = dict(
        snapshot_id=c["source_snapshot"].pk,
        tenant_id=c["tenant"].pk,
        ordinal=0,
        rotation_id=c["rotation_id"],
        operator_ref="operator",
    )
    arguments.update(changes)
    return request_source_query(**arguments)


def proof(c, request):
    snapshot = c["source_snapshot"]
    entry = MpcSolanaRotationInventoryEntry.objects.get(snapshot=snapshot)
    root = copy.deepcopy(snapshot.seal_query.evidence["value"]["root"])
    root.update(
        revision=root["revision"] + 5,
        next_claim_index=1,
        rotation=dict(
            rotation_id=str(c["rotation_id"]),
            source_identity=snapshot.root_identity,
            target_identity="ab" * 32,
            business_fingerprint="cd" * 32,
            status="Sealed",
            next_index=1,
            allocated_high_water=1,
            inventory_fingerprint=snapshot.inventory_fingerprint,
        ),
    )
    claim_id = str(c["claim"].pk)
    value = dict(
        query=copy.deepcopy(request["query"]),
        sequence=15,
        root=root,
        execution=None,
        abandoned=False,
        claim=copy.deepcopy(c["source_evidence"]),
        claim_availability=dict(
            reservation_id=claim_id, index=claim_id, owner=claim_id, retry=claim_id
        ),
    )
    if "current_evidence" in c:
        value["generation_authority"] = c["prepare"]
    if "witness_evidence_fingerprint" not in entry.source:
        value["rotation_claim_registration"] = dict(
            rotation_id=str(c["rotation_id"]),
            command_id=str(uuid4()),
            reservation_id=claim_id,
            source_fingerprint=_fingerprint("SOLANA_ROTATION_SOURCE_V1", entry.source),
            evidence_fingerprint=_fingerprint("SOLANA_ROTATION_CLAIM_EVIDENCE_V1", value["claim"]),
        )
    return signed(c, snapshot.witness_key_id, value)


def accept_control(c, request, value):
    return accept_source_query(
        challenge=request["query"]["challenge"],
        tenant_id=c["tenant"].pk,
        evidence=value,
        operator_ref="operator",
    )


@pytest.mark.parametrize("approved", [False, True])
@pytest.mark.parametrize("classic", [False, True])
def test_new_control_proof_preserves_original_claim_membership_and_ledger(
    clean_mode, approved, classic
):
    c = clean_mode
    if classic:
        token("rotation-SPL")
    captured(c, approved=approved, asset="rotation-SPL" if classic else "SOL")
    original = copy.deepcopy((c["claim"].status, c["claim"].evidence))
    request = ask(c)
    connection.close()
    value = proof(c, request)
    row = accept_control(c, request, value)
    assert accept_control(c, request, value).pk == row.pk
    with patch("custody.solana_rotation_sources.timezone.now", return_value=row.expires_at):
        archive = source_control_archive(challenge=row.pk, tenant_id=c["tenant"].pk)
        assert accept_control(c, request, value).pk == row.pk
    assert archive["original_source"]["membership"] == {"kind": "Unpublished"}
    assert "witness_evidence_fingerprint" not in archive["original_source"]
    assert archive["registration"] == value["value"]["rotation_claim_registration"]
    c["claim"].refresh_from_db()
    assert (c["claim"].status, c["claim"].evidence) == original
    assert not any(
        model.objects.exists()
        for model in (
            MpcSolanaIssuance,
            MpcSolanaFinancialWallet,
            MpcSolanaFinancialOperation,
            MpcSolanaClaimRegistration,
            UserWallet,
            LedgerTransaction,
        )
    )


def test_new_current_control_requires_exact_accepted_prepare(clean_mode, settings, tmp_path):
    c = clean_mode
    captured(c, current=(settings, tmp_path))
    request = ask(c)
    value = proof(c, request)
    assert accept_control(c, request, value).status == "VERIFIED"


@pytest.mark.parametrize("original_current,current_epoch", [(False, 1), (True, 2)])
def test_original_registered_evidence_remains_archival_after_refresh(
    clean_mode, settings, tmp_path, original_current, current_epoch
):
    c = clean_mode
    captured(
        c,
        registered=True,
        current=(settings, tmp_path),
        current_epoch=current_epoch,
        original_current=original_current,
    )
    request = ask(c)
    value = proof(c, request)
    row = accept_control(c, request, value)
    assert "rotation_claim_registration" not in value["value"]
    archive = source_control_archive(challenge=row.pk, tenant_id=c["tenant"].pk)
    assert archive["registration"] is None
    assert archive["registered_evidence"] == c["source_evidence"]


@pytest.mark.parametrize(
    "damage",
    [
        "query_nonce",
        "query_rotation",
        "query_claim",
        "phase",
        "rotation_id",
        "status",
        "manifest",
        "frontier",
        "prefix",
        "generation",
        "roster",
        "prepared",
        "refresh",
        "issuance",
        "alias",
        "source_fp",
        "evidence_fp",
        "command",
        "registration_claim",
        "registration_rotation",
        "missing_provenance",
        "source_statement",
        "receipt",
        "witness",
        "sequence",
        "revision",
        "role",
        "target_identity",
        "business_fingerprint",
    ],
)
def test_authentic_wrong_context_never_consumes_own_query(clean_mode, damage):
    c = clean_mode
    captured(c)
    request = ask(c)
    value = proof(c, request)["value"]
    if damage.startswith("query_"):
        name = {
            "query_nonce": "challenge",
            "query_rotation": "rotation_id",
            "query_claim": "claim_reservation_id",
        }[damage]
        value["query"][name] = "ef" * 32 if name == "challenge" else str(uuid4())
    elif damage in {"phase", "prefix", "generation", "roster", "prepared", "revision"}:
        root = value["root"]
        if damage == "phase":
            root["phase"] = "Active"
        elif damage == "prefix":
            root["next_claim_index"] = 0
        elif damage == "generation":
            root["generation"]["epoch"] += 1
        elif damage == "roster":
            root["node_keys"]["signer-a"] = "12" * 32
        elif damage == "prepared":
            root["prepared"] = root["generation"]
        else:
            root["revision"] = True
    elif damage in {
        "rotation_id",
        "status",
        "manifest",
        "frontier",
        "target_identity",
        "business_fingerprint",
    }:
        name = {"manifest": "inventory_fingerprint", "frontier": "allocated_high_water"}.get(
            damage, damage
        )
        value["root"]["rotation"][name] = {
            "rotation_id": str(uuid4()),
            "status": "Abandoned",
            "manifest": "12" * 32,
            "frontier": 0,
            "target_identity": "00" * 32,
            "business_fingerprint": "not-a-fingerprint",
        }[damage]
    elif damage == "refresh":
        value["refresh"] = {}
    elif damage == "issuance":
        value["claim_issuance"] = {"issuance_id": str(uuid4())}
    elif damage == "alias":
        value["claim_availability"]["retry"] = str(uuid4())
    elif damage == "missing_provenance":
        del value["rotation_claim_registration"]
    elif damage in {
        "source_fp",
        "evidence_fp",
        "command",
        "registration_claim",
        "registration_rotation",
    }:
        name = {
            "source_fp": "source_fingerprint",
            "evidence_fp": "evidence_fingerprint",
            "command": "command_id",
            "registration_claim": "reservation_id",
            "registration_rotation": "rotation_id",
        }[damage]
        value["rotation_claim_registration"][name] = (
            "12" * 32
            if "fingerprint" in name
            else str(c["rotation_id"] if damage == "command" else uuid4())
        )
    elif damage == "source_statement":
        value["claim"]["statement"]["owner_ref"] = "another-owner"
    elif damage == "receipt":
        value["claim"]["participant_agreement"][0]["signer_signature"] = "00" * 70
    elif damage == "sequence":
        value["sequence"] = True
    elif damage == "role":
        # Preserve SQL history; simulate damaged declaration before crypto use.
        with patch("custody.solana_rotation_sources._entry") as entry:
            original = MpcSolanaRotationInventoryEntry.objects.select_related(
                "snapshot__pause__root", "snapshot__seal_query", "claim__root__keyset"
            ).get(snapshot=c["source_snapshot"])
            original.source["role"] = "TENANT_TREASURY"
            entry.return_value = original
            with pytest.raises(MpcBindingError):
                accept_control(c, request, signed(c, c["source_snapshot"].witness_key_id, value))
        return
    signed_value = signed(c, c["source_snapshot"].witness_key_id, value)
    if damage == "witness":
        signed_value["signature"] = "00" * 70
    with pytest.raises(MpcBindingError):
        accept_control(c, request, signed_value)
    row = MpcSolanaRotationSourceQuery.objects.get(pk=request["query"]["challenge"])
    assert row.status == "PENDING" and row.evidence == {}


@pytest.mark.parametrize("damage", ["prepare", "receipt", "generation_authority"])
def test_current_registration_cannot_substitute_authority(clean_mode, settings, tmp_path, damage):
    c = clean_mode
    captured(c, current=(settings, tmp_path))
    request = ask(c)
    value = proof(c, request)["value"]
    if damage == "prepare":
        value["claim"]["authority"]["prepare"]["signature"] = "00" * 70
    elif damage == "receipt":
        value["claim"]["participant_agreement"][0]["signer_signature"] = "00" * 70
    else:
        value["generation_authority"] = dict(value["generation_authority"], signature="00" * 70)
    with pytest.raises(MpcBindingError):
        accept_control(c, request, signed(c, c["source_snapshot"].witness_key_id, value))


@pytest.mark.parametrize(
    "field,value",
    [
        ("rotation_id", uuid4()),
        ("challenge", "12" * 32),
        ("expires_at", timezone.now() + timedelta(hours=1)),
        ("evidence", {"replaced": True}),
    ],
)
def test_raw_subject_and_deadline_are_permanent(clean_mode, field, value):
    c = clean_mode
    captured(c)
    request = ask(c)
    with pytest.raises(DatabaseError), transaction.atomic():
        MpcSolanaRotationSourceQuery.objects.filter(pk=request["query"]["challenge"]).update(
            **{field: value}
        )


def test_accepted_proof_is_append_only_and_audit_rolls_back_acceptance(clean_mode):
    c = clean_mode
    captured(c)
    request = ask(c)
    value = proof(c, request)
    with patch("custody.solana_rotation_sources._audit", side_effect=RuntimeError("audit")):
        with pytest.raises(RuntimeError):
            accept_control(c, request, value)
    assert MpcSolanaRotationSourceQuery.objects.get().status == "PENDING"
    row = accept_control(c, request, value)
    with pytest.raises(DatabaseError), transaction.atomic():
        MpcSolanaRotationSourceQuery.objects.filter(pk=row.pk).update(status="PENDING", evidence={})
    with pytest.raises(DatabaseError), transaction.atomic():
        MpcSolanaRotationSourceQuery.objects.filter(pk=row.pk).delete()
    changed = copy.deepcopy(value)
    changed["value"]["sequence"] += 1
    with pytest.raises(MpcBindingError):
        accept_control(c, request, signed(c, c["source_snapshot"].witness_key_id, changed["value"]))
    assert AdminActionLog.objects.filter(action_type="SOLANA_ROTATION_SOURCE_ACCEPT").count() == 1


def test_expired_unknown_query_retained_and_new_query_has_distinct_nonce(clean_mode):
    c = clean_mode
    captured(c)
    request = ask(c)
    value = proof(c, request)
    row = MpcSolanaRotationSourceQuery.objects.get()
    with patch("custody.solana_rotation_sources.timezone.now", return_value=row.expires_at):
        with pytest.raises(MpcBindingError, match="expired"):
            accept_control(c, request, value)
    newer = ask(c)
    assert newer["query"]["challenge"] != row.pk
    assert MpcSolanaRotationSourceQuery.objects.filter(status="PENDING").count() == 2
    with pytest.raises(MpcBindingError):
        accept_control(c, newer, value)


def test_raw_authentic_reply_cannot_commit_after_deadline(clean_mode):
    c = clean_mode
    captured(c)
    request = ask(c)
    row = MpcSolanaRotationSourceQuery.objects.get()
    value = proof(c, request)
    with connection.cursor() as cursor:
        cursor.execute("SELECT clock_timestamp() + interval '1 second'")
        short_deadline = cursor.fetchone()[0]
    # A shorter bound is legal at INSERT, not a mutable lease.
    request["query"]["challenge"] = "45" * 32
    row = MpcSolanaRotationSourceQuery.objects.create(
        challenge=request["query"]["challenge"],
        entry=row.entry,
        rotation_id=row.rotation_id,
        expires_at=short_deadline,
    )
    value["value"]["query"] = request["query"]
    value = signed(c, c["source_snapshot"].witness_key_id, value["value"])
    with pytest.raises(DatabaseError, match="expired before commit"):
        with transaction.atomic():
            MpcSolanaRotationSourceQuery.objects.filter(pk=row.pk).update(
                status="VERIFIED", evidence=value
            )
            time.sleep(1.1)
    row.refresh_from_db()
    assert row.status == "PENDING"


def test_new_queries_off_recovery_and_archives_still_work(clean_mode, settings):
    c = clean_mode
    captured(c)
    request = ask(c)
    settings.MPC_SOLANA_ROTATION_INVENTORY_ENABLED = False
    with pytest.raises(MpcBindingError, match="disabled"):
        ask(c)
    row = accept_control(c, request, proof(c, request))
    assert source_control_archive(challenge=row.pk, tenant_id=c["tenant"].pk)


def test_cross_tenant_challenges_cannot_be_adopted(clean_mode):
    c = clean_mode
    captured(c)
    request = ask(c)
    with pytest.raises(MpcSolanaRotationSourceQuery.DoesNotExist):
        accept_source_query(
            challenge=request["query"]["challenge"],
            tenant_id=uuid4(),
            evidence=proof(c, request),
            operator_ref="operator",
        )


def test_query_birth_audit_failure_leaves_no_nonce(clean_mode):
    c = clean_mode
    captured(c)
    with patch("custody.solana_rotation_sources._audit", side_effect=RuntimeError("audit")):
        with pytest.raises(RuntimeError):
            ask(c)
    assert not MpcSolanaRotationSourceQuery.objects.exists()


def test_concurrent_acceptance_commits_one_original_proof(clean_mode):
    c = clean_mode
    captured(c)
    request = ask(c)
    value = proof(c, request)
    entered, release = threading.Event(), threading.Event()
    original_audit = __import__("custody.solana_rotation_sources", fromlist=["_audit"])._audit

    def audit(action, row, operator_ref):
        if action.endswith("ACCEPT") and not entered.is_set():
            entered.set()
            assert release.wait(5)
        original_audit(action, row, operator_ref)

    def run():
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET application_name = 'rotation-source-accept'")
            return accept_control(c, request, value).pk
        finally:
            close_old_connections()

    with patch("custody.solana_rotation_sources._audit", side_effect=audit):
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(run)
            assert entered.wait(5)
            second = pool.submit(run)
            try:
                wait_for_database_lock("rotation-source-accept")
            finally:
                release.set()
            assert first.result(5) == second.result(5)
    assert AdminActionLog.objects.filter(action_type="SOLANA_ROTATION_SOURCE_ACCEPT").count() == 1


def test_operator_handoff_binds_snapshot_and_exports_archival_data(clean_mode, tmp_path):
    c = clean_mode
    captured(c)
    common = dict(
        snapshot_id=str(c["source_snapshot"].pk),
        tenant_id=str(c["tenant"].pk),
        operator_ref="operator",
    )
    output = StringIO()
    call_command(
        "solana_rotation_source",
        "query",
        **common,
        rotation_id=str(c["rotation_id"]),
        index=0,
        stdout=output,
    )
    request = json.loads(output.getvalue())
    reply_path = tmp_path / "source-public-reply.json"
    reply_path.write_text(json.dumps(proof(c, request)))
    challenge = request["query"]["challenge"]
    with pytest.raises(CommandError):
        call_command(
            "solana_rotation_source",
            "accept",
            **dict(common, snapshot_id=str(uuid4())),
            challenge=challenge,
            evidence=str(reply_path),
            stdout=StringIO(),
        )
    call_command(
        "solana_rotation_source",
        "accept",
        **common,
        challenge=challenge,
        evidence=str(reply_path),
        stdout=StringIO(),
    )
    archive = StringIO()
    call_command("solana_rotation_source", "archive", **common, challenge=challenge, stdout=archive)
    assert json.loads(archive.getvalue())["original_source"]["membership"] == {
        "kind": "Unpublished"
    }


@pytest.mark.parametrize("damage", ["deadline", "nil_rotation", "verified_birth", "challenge"])
def test_raw_birth_cannot_skip_original_nonce_deadline_or_pending_state(clean_mode, damage):
    c = clean_mode
    captured(c)
    entry = MpcSolanaRotationInventoryEntry.objects.get(snapshot=c["source_snapshot"])
    fields = dict(
        challenge="45" * 32,
        entry=entry,
        rotation_id=c["rotation_id"],
        expires_at=timezone.now() + timedelta(seconds=15),
    )
    if damage == "deadline":
        fields["expires_at"] += timedelta(seconds=1)
    elif damage == "nil_rotation":
        fields["rotation_id"] = "00000000-0000-0000-0000-000000000000"
    elif damage == "verified_birth":
        fields.update(status="VERIFIED", evidence={"invented": True})
    else:
        fields["challenge"] = "00" * 32
    with pytest.raises(DatabaseError), transaction.atomic():
        MpcSolanaRotationSourceQuery.objects.create(**fields)


def test_registered_source_cannot_replace_original_receipts_even_with_valid_new_signatures(
    clean_mode,
):
    c = clean_mode
    captured(c, registered=True)
    request = ask(c)
    # Same statement, exact original keys, authentic but different ECDSA receipts.
    c["source_evidence"] = evidence("claim", c["claim"].statement)
    replacement = proof(c, request)
    with pytest.raises(MpcBindingError):
        accept_control(c, request, replacement)
    with pytest.raises(DatabaseError), transaction.atomic():
        MpcSolanaRotationSourceQuery.objects.filter(pk=request["query"]["challenge"]).update(
            status="VERIFIED", evidence=replacement
        )
    assert MpcSolanaRotationSourceQuery.objects.get().status == "PENDING"


@pytest.mark.parametrize(
    "damage", ["nonce", "missing_provenance", "alias", "generation", "publication", "phase"]
)
def test_raw_sql_cannot_adopt_structurally_wrong_source_context(clean_mode, damage):
    c = clean_mode
    captured(c)
    request = ask(c)
    value = proof(c, request)["value"]
    if damage == "nonce":
        value["query"]["challenge"] = "13" * 32
    elif damage == "missing_provenance":
        del value["rotation_claim_registration"]
    elif damage == "alias":
        value["claim_availability"]["owner"] = None
    elif damage == "generation":
        value["root"]["generation"]["epoch"] = 1
    elif damage == "publication":
        value["claim_issuance"] = {"invented": True}
    else:
        value["root"]["phase"] = "Active"
    with pytest.raises(DatabaseError), transaction.atomic():
        MpcSolanaRotationSourceQuery.objects.filter(pk=request["query"]["challenge"]).update(
            status="VERIFIED", evidence=signed(c, c["source_snapshot"].witness_key_id, value)
        )


def test_populated_source_queries_cannot_lose_database_guards(clean_mode):
    from importlib import import_module

    c = clean_mode
    captured(c)
    ask(c)
    reverse = import_module("custody.migrations.0051_solana_rotation_source_proofs").REVERSE
    with pytest.raises(DatabaseError, match="cannot lose their guards"), transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(reverse)
