"""Real PostgreSQL and synthetic public authorities; not MPC acceptance."""

import copy
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from io import StringIO
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.core.management import call_command
from django.db import DatabaseError, close_old_connections, connection, transaction
from django.utils import timezone

from custody.models import (
    Asset,
    CustodyPrincipalRole,
    LedgerTransaction,
    MpcSolanaRotationInventory,
    MpcSolanaRotationInventoryEntry,
    MpcSolanaRotationInventoryQuery,
)
from custody.mpc_binding import MpcBindingError
from custody.solana_rotation_inventory import (
    accept_query,
    begin_inventory,
    export_slice,
    request_query,
)
from custody.tests.test_solana_allocation_pause import pause
from custody.tests.test_solana_financial_preparation import preparation as preparation_fixture
from custody.tests.test_solana_financial_root import clean_mode as clean_mode_fixture
from custody.tests.test_solana_financial_root import wait_for_database_lock
from custody.tests.test_solana_financial_sessions import financial as financial_fixture
from custody.tests.test_solana_issuance import signed
from custody.tests.test_solana_provisioning import approve, reserve
from custody.tests.test_solana_provisioning import context as context_fixture
from custody.tests.test_solana_provisioning import signer_receipt_trust as trust_fixture
from custody.tests.test_solana_token_provisioning import (
    pending as pending_fixture,
)
from custody.tests.test_solana_token_provisioning import (
    publication as token_publication,
)
from custody.tests.test_solana_token_provisioning import (
    publish as publish_token,
)

pytestmark = pytest.mark.django_db(transaction=True)
context = context_fixture
signer_receipt_trust = trust_fixture
clean_mode = clean_mode_fixture
financial = financial_fixture
preparation = preparation_fixture
pending = pending_fixture


@pytest.fixture(autouse=True)
def enabled(settings):
    settings.MPC_SOLANA_ALLOCATION_PAUSE_ENABLED = True
    settings.MPC_SOLANA_ROTATION_INVENTORY_ENABLED = True
    with patch("custody.solana_rotation_inventory._runtime"):
        yield


def begin(c, *, roles=None):
    row = pause(c)
    return begin_inventory(
        pause_id=row.pk,
        snapshot_id=uuid4(),
        tenant_id=c["tenant"].pk,
        legacy_roles=roles or {},
        operator_ref="operator",
    )


def query(c, row, purpose, ordinal=None):
    return request_query(
        snapshot_id=row.pk,
        tenant_id=c["tenant"].pk,
        purpose=purpose,
        ordinal=ordinal,
        operator_ref="operator",
    )


def reply(c, row, request, *, claim=None, grant=None):
    value = dict(
        query=copy.deepcopy(request["query"]),
        sequence=5,
        execution=None,
        abandoned=False,
        claim=claim,
        claim_issuance=grant,
        root=dict(
            original=c["root"].statement,
            revision=1,
            phase="Frozen",
            prepared=None,
            public_key_package=c["root"].statement["public_key_package"],
            generation=dict(
                epoch=0,
                ceremony_id=c["root"].statement["dkg"]["execution_id"],
                public_key_package_sha256=hashlib.sha256(
                    bytes(c["root"].statement["public_key_package"])
                ).hexdigest(),
            ),
            node_keys={
                p: k * 64
                for p, k in zip(("signer-a", "signer-b", "signer-c"), ("1", "2", "3"), strict=True)
            },
            next_claim_index=c.get(
                "inventory_known_count", 2 if "CUSTOMER" in c and "TREASURY" in c else 0
            ),
            financial_mode=row.local_mode or None,
        ),
    )
    if request["query"].get("claim_reservation_id"):
        value["claim_availability"] = dict(
            reservation_id=request["query"]["claim_reservation_id"],
            index=request["query"]["claim_reservation_id"] if claim else None,
            owner=request["query"]["claim_reservation_id"] if claim else None,
            retry=request["query"]["claim_reservation_id"] if claim else None,
        )
    return signed(c, row.witness_key_id, value)


def accept(c, request, proof):
    return accept_query(
        challenge=request["query"]["challenge"],
        tenant_id=c["tenant"].pk,
        evidence=proof,
        operator_ref="operator",
    )


def header(c, row):
    q = query(c, row, "ROOT")
    accept(c, q, reply(c, row, q))
    row.refresh_from_db()


def test_empty_paused_source_seals_without_fake_base_claim(clean_mode):
    c = clean_mode
    row = begin(c)
    header(c, row)
    q = query(c, row, "SEAL")
    completed = accept(c, q, reply(c, row, q))
    result = export_slice(snapshot_id=row.pk, tenant_id=c["tenant"].pk, start_index=0)
    assert completed.status == "SEALED" and len(result["inventory_fingerprint"]) == 64
    assert result["entries"] == [] and result["allocated_high_water"] == 0
    assert not LedgerTransaction.objects.exists()


@pytest.mark.parametrize("approved", [False, True])
def test_pending_and_approved_unissued_claims_stay_unpublished(clean_mode, approved):
    c = clean_mode
    claim = reserve(c)
    if approved:
        claim = approve(c, claim)
    roles = {str(claim.principal_id): "CUSTOMER_DEPOSIT"}
    row = begin(c, roles=roles)
    header(c, row)
    q = query(c, row, "ENTRY", 0)
    accept(c, q, reply(c, row, q))
    q = query(c, row, "SEAL")
    accept(c, q, reply(c, row, q))
    result = export_slice(snapshot_id=row.pk, tenant_id=c["tenant"].pk, start_index=0)
    assert result["entries"][0]["membership"] == {"kind": "Unpublished"}
    assert "witness_evidence_fingerprint" not in result["entries"][0]
    claim.refresh_from_db()
    assert claim.status == ("APPROVED" if approved else "PENDING")


def test_financial_grants_preserve_original_membership_and_ledger(financial):
    c = financial
    before = LedgerTransaction.objects.count()
    row = begin(c)
    header(c, row)
    for ordinal, role in enumerate(("CUSTOMER", "TREASURY")):
        wallet = c[role]
        q = query(c, row, "ENTRY", ordinal)
        accept(
            c,
            q,
            reply(
                c,
                row,
                q,
                claim=wallet.claim.evidence,
                grant=wallet.evidence["value"]["claim_issuance"],
            ),
        )
    q = query(c, row, "SEAL")
    accept(c, q, reply(c, row, q))
    result = export_slice(snapshot_id=row.pk, tenant_id=c["tenant"].pk, start_index=0)
    assert all(e["membership"]["publication"] == "ACTIVE" for e in result["entries"])
    assert LedgerTransaction.objects.count() == before


@pytest.mark.parametrize("damage", ["nonce", "phase", "genesis", "revision"])
def test_authentic_wrong_context_cannot_answer_inventory_query(clean_mode, damage):
    c = clean_mode
    row = begin(c)
    header(c, row)
    q = query(c, row, "SEAL")
    proof = reply(c, row, q)
    value = proof["value"]
    if damage == "nonce":
        value["query"]["challenge"] = "fe" * 32
    elif damage == "phase":
        value["root"]["phase"] = "Active"
    elif damage == "genesis":
        value["root"]["original"]["genesis_hash"] = "wrong-network"
    else:
        value["root"]["revision"] += 1
    bad = signed(c, row.witness_key_id, value)
    with pytest.raises(MpcBindingError):
        accept(c, q, bad)
    row.refresh_from_db()
    assert row.status == "COLLECTING"


def test_raw_entry_alias_and_sealed_data_cannot_change(clean_mode):
    c = clean_mode
    claim = approve(c, reserve(c))
    row = begin(c, roles={str(claim.principal_id): "CUSTOMER_DEPOSIT"})
    entry = MpcSolanaRotationInventoryEntry.objects.get(snapshot=row)
    with pytest.raises(DatabaseError), transaction.atomic():
        MpcSolanaRotationInventoryEntry.objects.filter(pk=entry.pk).update(ordinal=3)


@pytest.mark.parametrize("which", ["issuer", "wallet"])
def test_captured_active_proofs_are_reverified_before_export(financial, which):
    from custody.solana_rotation_inventory import _source

    c = financial
    row = begin(c)
    header(c, row)
    q = query(c, row, "ENTRY", 0)
    saved = MpcSolanaRotationInventoryQuery.objects.select_related(
        "snapshot__pause__root", "entry__claim__root__keyset", "entry__claim__asset"
    ).get(pk=q["query"]["challenge"])
    saved.snapshot = row
    record = copy.deepcopy(saved.entry.original_record)
    key = "issuance" if which == "issuer" else "financial_wallet"
    record[key]["evidence"]["signature"] = "00" * 70
    saved.entry.original_record = (
        record  # Simulate damaged archive, not permission to alter SQL history.
    )
    wallet = c["CUSTOMER"]
    value = reply(
        c, row, q, claim=wallet.claim.evidence, grant=wallet.evidence["value"]["claim_issuance"]
    )["value"]
    with pytest.raises(MpcBindingError):
        _source(saved, value)


def test_archival_validation_of_disabled_deposits_preserves_ordinary_admission(financial):
    from custody.solana_financial_wallet import (
        validate_financial_wallet,
        validate_financial_wallet_history,
    )

    c = financial
    # The native runtime asset remains enabled, as required for network identity.
    Asset.objects.filter(asset_key="SOL").update(deposit_supported=False)
    with pytest.raises(MpcBindingError):
        validate_financial_wallet(c["CUSTOMER"])
    assert validate_financial_wallet_history(c["CUSTOMER"]).pk == c["CUSTOMER"].pk
    row = begin(c)
    header(c, row)
    q = query(c, row, "ENTRY", 0)
    wallet = c["CUSTOMER"]
    accept(
        c,
        q,
        reply(
            c, row, q, claim=wallet.claim.evidence, grant=wallet.evidence["value"]["claim_issuance"]
        ),
    )
    assert (
        MpcSolanaRotationInventoryEntry.objects.get(snapshot=row, ordinal=0).source["membership"][
            "publication"
        ]
        == "ACTIVE"
    )


@pytest.mark.parametrize("first", ["inventory", "classification"])
def test_role_capture_serializes_with_customer_classification_birth(clean_mode, first):
    from custody import solana_rotation_inventory as module

    c = clean_mode
    claim = reserve(c)
    paused, snapshot_id = pause(c), uuid4()
    arguments = dict(
        pause_id=paused.pk,
        snapshot_id=snapshot_id,
        tenant_id=c["tenant"].pk,
        legacy_roles={str(claim.principal_id): "TENANT_TREASURY"},
        operator_ref="operator",
    )
    entered, release = threading.Event(), threading.Event()
    original_audit = module._audit

    def hold(action, obj, actor):
        original_audit(action, obj, actor)
        if first == "inventory" and action == "SOLANA_ROTATION_INVENTORY_BEGIN":
            entered.set()
            assert release.wait(15)

    def inventory():
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET application_name='inventory-role-capture'")
            if first == "classification":
                with pytest.raises(MpcBindingError, match="preserve known roles"):
                    begin_inventory(**arguments)
            else:
                begin_inventory(**arguments)
        finally:
            close_old_connections()

    def classify():
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET application_name='inventory-role-classification'")
            with transaction.atomic():
                CustodyPrincipalRole.objects.create(principal=claim.principal, role="CUSTOMER")
                if first == "classification":
                    entered.set()
                    assert release.wait(15)
        finally:
            close_old_connections()

    with (
        patch.object(module, "_audit", side_effect=hold),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        head = pool.submit(inventory if first == "inventory" else classify)
        try:
            assert entered.wait(10)
            tail = pool.submit(classify if first == "inventory" else inventory)
            wait_for_database_lock(
                "inventory-role-classification"
                if first == "inventory"
                else "inventory-role-capture"
            )
        finally:
            release.set()
        head.result(timeout=10)
        tail.result(timeout=10)
    assert CustodyPrincipalRole.objects.get(principal=claim.principal).role == "CUSTOMER"
    if first == "inventory":
        row = MpcSolanaRotationInventory.objects.get(pk=snapshot_id)
        header(c, row)
        q = query(c, row, "ENTRY", 0)
        with pytest.raises(MpcBindingError, match="role changed after capture"):
            accept(c, q, reply(c, row, q))
        assert MpcSolanaRotationInventoryEntry.objects.get(snapshot=row).source == {}
    else:
        assert not MpcSolanaRotationInventory.objects.exists()


def test_pending_spl_grant_does_not_synthesize_active_membership(pending):
    c = pending
    _, proof = token_publication(c)
    c["inventory_known_count"] = 3
    row = begin(c)
    header(c, row)
    q = query(c, row, "ENTRY", c["token_claim"].index)
    before = LedgerTransaction.objects.count()
    accept(
        c,
        q,
        reply(c, row, q, claim=c["token_claim"].evidence, grant=proof["value"]["claim_issuance"]),
    )
    entry = MpcSolanaRotationInventoryEntry.objects.get(snapshot=row, claim=c["token_claim"])
    assert entry.source["membership"]["publication"] == "PENDING"
    c["token_wallet"].refresh_from_db()
    assert c["token_wallet"].status == "PENDING" and c["token_wallet"].user_wallet_id is None
    assert LedgerTransaction.objects.count() == before


def test_spl_active_archive_rejects_corrupt_owned_initialization(pending):
    from custody.models import MpcSolanaFinancialEffect
    from custody.solana_rotation_inventory import _source

    c = pending
    _, proof = token_publication(c)
    wallet = publish_token(c, proof)
    c["inventory_known_count"] = 3
    row = begin(c)
    header(c, row)
    q = query(c, row, "ENTRY", c["token_claim"].index)
    saved = MpcSolanaRotationInventoryQuery.objects.select_related(
        "snapshot__pause__root", "entry__claim__root__keyset", "entry__claim__asset"
    ).get(pk=q["query"]["challenge"])
    saved.snapshot = row
    value = reply(
        c, row, q, claim=c["token_claim"].evidence, grant=wallet.evidence["value"]["claim_issuance"]
    )["value"]
    original_get = MpcSolanaFinancialEffect.objects.get

    def corrupted(*args, **kwargs):
        effect = original_get(*args, **kwargs)
        effect.evidence = copy.deepcopy(effect.evidence)
        effect.evidence["signature"] = "corrupted-archive"
        return effect

    with patch.object(
        MpcSolanaFinancialEffect.objects, "get", side_effect=corrupted
    ) as read_effect:
        with pytest.raises(MpcBindingError):
            _source(saved, value)
        assert read_effect.called


def test_disabled_spl_asset_keeps_original_active_provenance(pending):
    from custody.solana_financial_wallet import validate_financial_wallet_history

    c = pending
    _, proof = token_publication(c)
    wallet = publish_token(c, proof)
    Asset.objects.filter(pk=c["token_asset"].pk).update(enabled=False, deposit_supported=False)
    assert validate_financial_wallet_history(wallet).pk == wallet.pk
    c["inventory_known_count"] = 3
    row = begin(c)
    header(c, row)
    q = query(c, row, "ENTRY", c["token_claim"].index)
    accept(
        c,
        q,
        reply(
            c,
            row,
            q,
            claim=c["token_claim"].evidence,
            grant=wallet.evidence["value"]["claim_issuance"],
        ),
    )
    assert (
        MpcSolanaRotationInventoryEntry.objects.get(snapshot=row, claim=c["token_claim"]).source[
            "membership"
        ]["publication"]
        == "ACTIVE"
    )


def test_original_query_deadline_cannot_be_renewed_by_raw_sql(clean_mode):
    row = begin(clean_mode)
    q = query(clean_mode, row, "ROOT")
    with pytest.raises(DatabaseError, match="cannot change"), transaction.atomic():
        MpcSolanaRotationInventoryQuery.objects.filter(pk=q["query"]["challenge"]).update(
            expires_at=timezone.now() + timedelta(seconds=60)
        )


def test_expired_original_query_cannot_be_accepted_but_verified_retry_is_archival(clean_mode):
    from custody import solana_rotation_inventory as module

    c = clean_mode
    row = begin(c)
    q = query(c, row, "ROOT")
    proof = reply(c, row, q)
    with patch.object(module.timezone, "now", return_value=timezone.now() + timedelta(seconds=16)):
        with pytest.raises(MpcBindingError, match="expired"):
            accept(c, q, proof)
    accept(c, q, proof)
    with patch.object(module.timezone, "now", return_value=timezone.now() + timedelta(seconds=16)):
        assert accept(c, q, proof).pk == row.pk


def test_commit_deadline_rolls_back_query_header_and_audit(clean_mode):
    from custody import solana_rotation_inventory as module

    c = clean_mode
    row = begin(c)
    with patch.object(module, "timedelta", return_value=timedelta(milliseconds=800)):
        q = query(c, row, "ROOT")
    proof = reply(c, row, q)
    original_audit = module._audit

    def cross_deadline(action, obj, actor):
        original_audit(action, obj, actor)
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_sleep(1.1)")

    with patch.object(module, "_audit", side_effect=cross_deadline):
        with pytest.raises(DatabaseError, match="expired before commit"):
            accept(c, q, proof)
    row.refresh_from_db()
    assert row.header_query_id is None
    assert (
        MpcSolanaRotationInventoryQuery.objects.get(pk=q["query"]["challenge"]).status == "PENDING"
    )


def test_snapshot_cannot_hide_captured_issuer_or_wallet_archive(financial):
    from custody import solana_rotation_inventory as module

    original_record = module._local_record

    def altered(claim):
        record = original_record(claim)
        record["issuance"] = None
        record["financial_wallet"] = None
        return record

    with patch.object(module, "_local_record", side_effect=altered):
        with pytest.raises(DatabaseError, match="original reserved Claim"):
            begin(financial)
    assert not MpcSolanaRotationInventory.objects.exists()


def test_seal_cannot_omit_original_pending_index(clean_mode):
    c = clean_mode
    claim = reserve(c)
    row = begin(c, roles={str(claim.principal_id): "CUSTOMER_DEPOSIT"})
    header(c, row)
    with pytest.raises(MpcBindingError, match="every original entry"):
        query(c, row, "SEAL")
    assert MpcSolanaRotationInventoryEntry.objects.get(snapshot=row).query_id is None


def test_default_disabled_entry_does_not_erase_original_snapshot(clean_mode, settings):
    c = clean_mode
    row = begin(c)
    settings.MPC_SOLANA_ROTATION_INVENTORY_ENABLED = False
    arguments = dict(
        pause_id=row.pause_id, tenant_id=c["tenant"].pk, legacy_roles={}, operator_ref="operator"
    )
    assert begin_inventory(**arguments, snapshot_id=row.pk).pk == row.pk
    with pytest.raises(MpcBindingError, match="disabled"):
        begin_inventory(**arguments, snapshot_id=uuid4())
    header(c, row)


def test_operator_command_never_adopts_another_snapshot_challenge(clean_mode, tmp_path):
    c = clean_mode
    row = begin(c)
    q = query(c, row, "ROOT")
    evidence = tmp_path / "public.json"
    import json

    evidence.write_text(json.dumps(reply(c, row, q)))
    from django.core.management.base import CommandError

    with pytest.raises(CommandError):
        call_command(
            "solana_rotation_inventory",
            "accept",
            snapshot_id=str(uuid4()),
            tenant_id=str(c["tenant"].pk),
            operator_ref="operator",
            challenge=q["query"]["challenge"],
            evidence=str(evidence),
            stdout=StringIO(),
        )
    assert (
        MpcSolanaRotationInventoryQuery.objects.get(pk=q["query"]["challenge"]).status == "PENDING"
    )


def test_populated_inventory_cannot_lose_its_sql_guards(clean_mode):
    from django.db.migrations.executor import MigrationExecutor

    row = begin(clean_mode)
    try:
        with pytest.raises(DatabaseError, match="cannot lose their guards"):
            MigrationExecutor(connection).migrate([("custody", "0049_solana_allocation_pause")])
    finally:
        MigrationExecutor(connection).migrate(
            [("custody", "0050_solana_rotation_inventory_snapshot")]
        )
    assert MpcSolanaRotationInventory.objects.get(pk=row.pk).status == "COLLECTING"


@pytest.mark.parametrize("inconsistent", ["prefix", "index", "owner", "retry"])
def test_authentic_inconsistent_absence_cannot_hide_registered_source(clean_mode, inconsistent):
    c = clean_mode
    claim = reserve(c)
    if inconsistent == "prefix":
        c["inventory_known_count"] = 1
    row = begin(c, roles={str(claim.principal_id): "CUSTOMER_DEPOSIT"})
    header(c, row)
    q = query(c, row, "ENTRY", 0)
    proof = reply(c, row, q)
    if inconsistent != "prefix":
        proof["value"]["claim_availability"][inconsistent] = str(claim.pk)
        proof = signed(c, row.witness_key_id, proof["value"])
    with pytest.raises(MpcBindingError):
        accept(c, q, proof)
    assert MpcSolanaRotationInventoryEntry.objects.get(snapshot=row).source == {}
