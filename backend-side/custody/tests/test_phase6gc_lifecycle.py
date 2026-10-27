"""Command lifecycle safety; these tests do not claim cryptographic rotation."""

from io import StringIO
from uuid import uuid4

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from custody.models import MpcKeyset

pytestmark = pytest.mark.django_db


def keyset(**changes):
    fields = dict(
        keyset_id=uuid4(),
        algorithm="FROST_ED25519",
        curve="ed25519",
        scope="SOLANA",
        derivation_version="frost_keyset_v1",
    )
    fields.update(changes)
    return MpcKeyset.objects.create(**fields)


def command(action, row):
    call_command("mpc_keyset", action, keyset_id=str(row.keyset_id), stdout=StringIO())


@pytest.mark.parametrize(
    "fields",
    [
        {"status": "ACTIVE"},
        {"public_key": "11" * 32},
        {"dkg_execution_id": uuid4()},
        {"dkg_result_fingerprint": "ab" * 32},
        {"participant_identities": ["signer-a"]},
        {"dkg_public_evidence": {"unverified": True}},
        {"network_bindings": {"SOL": {"unverified": True}}},
    ],
)
def test_imported_or_active_keyset_cannot_be_retired_without_drain_protocol(fields):
    row = keyset(**fields)
    before = MpcKeyset.objects.values().get(pk=row.pk)
    with pytest.raises(CommandError, match="drain"):
        command("retire", row)
    assert MpcKeyset.objects.values().get(pk=row.pk) == before


def test_unused_metadata_can_be_retired_idempotently():
    row = keyset()
    command("retire", row)
    row.refresh_from_db()
    assert row.status == "RETIRED" and not row.active_for_new_wallets
    assert row.retired_at is not None
    before = MpcKeyset.objects.values().get(pk=row.pk)
    command("retire", row)
    assert MpcKeyset.objects.values().get(pk=row.pk) == before


@pytest.mark.parametrize("action", ["import-dkg", "activate"])
def test_retired_keyset_cannot_be_reopened_or_contact_coordinator(action, monkeypatch):
    row = keyset()
    command("retire", row)

    def unexpected(*args, **kwargs):
        pytest.fail("retired metadata must be rejected before contacting a coordinator")

    monkeypatch.setattr("custody.signer_adapter.SelfHostedMpcAdapter.get_keyset", unexpected)
    with pytest.raises(CommandError, match="retired"):
        command(action, row)
    row.refresh_from_db()
    assert row.status == "RETIRED"


def test_unused_but_referenced_metadata_cannot_be_retired():
    from custody.models import UserWallet

    row = keyset()
    UserWallet.objects.create(
        user_id="customer",
        chain_id="SOL",
        asset_key="SOL",
        derivation_path="legacy",
        deposit_address="reference-only-fixture",
        mpc_keyset=row,
    )
    with pytest.raises(CommandError, match="drain"):
        command("retire", row)
    row.refresh_from_db()
    assert row.status == "CREATING"


@pytest.mark.django_db(transaction=True)
def test_retirement_waits_for_concurrent_keyset_import():
    import time
    from concurrent.futures import ThreadPoolExecutor
    from queue import Queue

    from django.db import close_old_connections, connection, transaction

    assert connection.vendor == "postgresql"
    row = keyset()
    worker_pid = Queue()

    def retire():
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                worker_pid.put(cursor.fetchone()[0])
            command("retire", row)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=1) as workers:
        with transaction.atomic():
            locked = MpcKeyset.objects.select_for_update().get(pk=row.pk)
            future = workers.submit(retire)
            pid = worker_pid.get(timeout=10)
            deadline = time.monotonic() + 10
            while True:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s", [pid]
                    )
                    activity = cursor.fetchone()
                if activity and activity[0] == "Lock":
                    break
                assert not future.done(), "retirement did not serialize on the keyset"
                assert time.monotonic() < deadline, "retirement did not reach its row lock"
                time.sleep(0.01)
            locked.public_key = "11" * 32
            locked.save(update_fields=["public_key"])
        with pytest.raises(CommandError, match="drain"):
            future.result(timeout=10)
    row.refresh_from_db()
    assert row.status == "CREATING" and row.public_key == "11" * 32
