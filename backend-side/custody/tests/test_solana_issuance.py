"""PostgreSQL publication guards; synthetic evidence is NOT genuine MPC acceptance."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.db import DatabaseError, close_old_connections, connection, transaction

from custody.models import (
    AdminActionLog,
    Asset,
    LedgerTransaction,
    MpcSolanaClaim,
    MpcSolanaIssuance,
    UserWallet,
)
from custody.mpc_binding import MpcBindingError
from custody.solana_issuance import _canonical, complete_publication, publication_request
from custody.solana_seeded import account_address
from custody.tests.solana_fixture import root as fixture_root
from custody.tests.test_solana_provisioning import (
    PublicClient,
    approve,
    enroll,
    reserve,
)
from custody.tests.test_solana_provisioning import context as registry_context_fixture
from custody.tests.test_solana_provisioning import signer_receipt_trust as receipt_trust_fixture

pytestmark = pytest.mark.django_db(transaction=True)
context = registry_context_fixture
signer_receipt_trust = receipt_trust_fixture


@pytest.fixture
def issuance(context, signer_receipt_trust, settings, tmp_path):
    c = context
    enroll(c)
    claim = approve(c, reserve(c))
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated witness fixture")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier("spiffe://wallet-mpc/witness")]
            ),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "witness-public.crt"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    settings.MPC_SOLANA_WITNESS_ANCHOR_ID = str(uuid4())
    settings.MPC_SOLANA_WITNESS_CERTIFICATE = str(path)
    c.update(claim=claim, witness_key=key)
    with patch("custody.solana_issuance._runtime"):
        yield c


def begin(c):
    return publication_request(
        reservation_id=c["claim"].pk, tenant_id=c["tenant"].pk, operator_ref="operator"
    )


def reply(c, request, *, grant=True):
    row = MpcSolanaIssuance.objects.get(pk=request["issuance_id"])
    value = {
        "query": request["query"],
        "sequence": 4,
        "root": {"original": c["claim"].root.statement, "revision": 4, "phase": "Active"},
        "claim": c["claim"].evidence,
        "execution": None,
        "abandoned": False,
        "claim_issuance": {
            "issuance_id": str(row.pk),
            "reservation_id": str(row.claim_id),
            "command_id": str(uuid4()),
        }
        if grant
        else None,
    }
    return signed(c, row.witness_key_id, value)


def signed(c, key_id, value):
    message = b"Wallet-MPC/WITNESS_QUERY_REPLY_V1\0" + _canonical(
        {"key_id": key_id, "value": value}
    )
    return {
        "key_id": key_id,
        "value": value,
        "signature": c["witness_key"].sign(message, ec.ECDSA(hashes.SHA256())).hex(),
    }


def complete(c, request, proof):
    return complete_publication(
        issuance_id=request["issuance_id"],
        tenant_id=c["tenant"].pk,
        operator_ref="operator",
        evidence=proof,
        transport=c["rpc"],
    )


def test_original_native_publication_and_exact_retry(issuance):
    c = issuance
    count = LedgerTransaction.objects.count()
    request = begin(c)
    assert begin(c) == request and not UserWallet.objects.filter(solana_claim=c["claim"]).exists()
    assert AdminActionLog.objects.filter(action_type="SOLANA_ISSUANCE_RESERVE").count() == 1
    wallet = complete(c, request, reply(c, request))
    assert wallet.user_id == c["principal"].ledger_owner_id
    assert wallet.deposit_address == c["claim"].address
    assert wallet.deposit_address != c["claim"].root.base_address
    assert wallet.address_index == c["claim"].index
    assert wallet.custody_account_id is None and wallet.asset_account_address is None
    assert complete(c, request, None).pk == wallet.pk
    assert LedgerTransaction.objects.count() == count


@pytest.mark.parametrize("field", ["challenge", "claim", "grant", "anchor", "key", "signature"])
def test_signed_but_unbound_or_forged_proof_cannot_publish(issuance, field):
    c = issuance
    request = begin(c)
    proof = reply(c, request)
    v = proof["value"]
    if field == "challenge":
        v["query"]["challenge"] = "ab" * 32
    elif field == "claim":
        v["claim"]["statement"]["owner_ref"] = f"p1:{uuid4()}"
    elif field == "grant":
        v["claim_issuance"] = None
    elif field == "anchor":
        v["query"]["anchor_id"] = str(uuid4())
    if field in {"key", "signature"}:
        proof[field if field == "signature" else "key_id"] = "ab" * (
            70 if field == "signature" else 32
        )
    else:
        proof = signed(c, proof["key_id"], v)
    with pytest.raises(MpcBindingError):
        complete(c, request, proof)
    assert not UserWallet.objects.filter(solana_claim=c["claim"]).exists()
    assert MpcSolanaIssuance.objects.get(pk=request["issuance_id"]).status == "PENDING"


def test_publication_audit_failure_rolls_back_wallet_and_evidence(issuance):
    c = issuance
    request = begin(c)
    proof = reply(c, request)
    with patch("custody.solana_issuance._audit", side_effect=RuntimeError("audit unavailable")):
        with pytest.raises(RuntimeError):
            complete(c, request, proof)
    assert not UserWallet.objects.filter(solana_claim=c["claim"]).exists()
    assert MpcSolanaIssuance.objects.get(pk=request["issuance_id"]).status == "PENDING"
    assert complete(c, request, proof).solana_claim_id == c["claim"].pk


@pytest.mark.parametrize(
    "changes",
    [
        {"user_id": "other"},
        {"deposit_address": "foreign"},
        {"address_index": 1},
        {"solana_claim_id": None},
        {"mpc_keyset_id": None},
        {"asset_account_address": "foreign"},
    ],
)
def test_published_native_identity_is_immutable(issuance, changes):
    c = issuance
    request = begin(c)
    wallet = complete(c, request, reply(c, request))
    with pytest.raises(DatabaseError):
        UserWallet.objects.filter(pk=wallet.pk).update(**changes)
    assert UserWallet.objects.get(pk=wallet.pk).solana_claim_id == c["claim"].pk


def test_foreign_tenant_and_unlinked_wallet_cannot_adopt_claim(issuance):
    c = issuance
    with pytest.raises(MpcSolanaIssuance.DoesNotExist):
        complete_publication(issuance_id=uuid4(), tenant_id=uuid4(), evidence={}, operator_ref="x")
    with pytest.raises(DatabaseError):
        UserWallet.objects.create(
            user_id="foreign",
            chain_id="SOL",
            asset_key="SOL",
            deposit_address=c["claim"].address,
            derivation_path="legacy/0",
        )


def test_distinct_original_roots_allow_same_owner_index_without_reassignment(issuance):
    c = issuance
    request = begin(c)
    old = complete(c, request, reply(c, request))
    _, keyset = fixture_root(88)
    c = dict(c, keyset=keyset, client=PublicClient(keyset.dkg_public_evidence))
    enroll(c)
    c["claim"] = approve(c, reserve(c, retry="second-root"))
    request = begin(c)
    new = complete(c, request, reply(c, request))
    assert old.user_id == new.user_id and old.address_index == new.address_index == 0
    assert old.derivation_path != new.derivation_path
    assert old.deposit_address != new.deposit_address


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
@pytest.mark.parametrize("source_field", ["deposit_address", "asset_account_address"])
def test_stale_allocation_snapshot_cannot_adopt_committed_legacy_owner(
    context, signer_receipt_trust, isolation, source_field
):
    c = context
    root = enroll(c)
    source = account_address(root.base_address, 0)

    def writer():
        close_old_connections()
        try:
            return UserWallet.objects.create(
                user_id="original-legacy-owner",
                chain_id="SOL",
                asset_key="SOL",
                derivation_path="legacy/0",
                deposit_address=source
                if source_field == "deposit_address"
                else account_address(root.base_address, 99),
                asset_account_address=source if source_field == "asset_account_address" else None,
            ).pk
        finally:
            close_old_connections()

    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation}")
            cursor.execute("SELECT count(*) FROM custody_mpcsolanaroot")
        with ThreadPoolExecutor(max_workers=1) as pool:
            wallet_id = pool.submit(writer).result(timeout=5)
        reservation = uuid4()
        with pytest.raises(DatabaseError, match="READ COMMITTED"):
            MpcSolanaClaim.objects.create(
                reservation_id=reservation,
                root=root,
                principal=c["principal"],
                asset=Asset.objects.get(asset_key="SOL"),
                asset_namespace="SOL",
                idempotency_key="stale",
                index=0,
                address=source,
                statement={
                    "root": root.statement,
                    "reservation_id": str(reservation),
                    "owner_ref": c["principal"].ledger_owner_id,
                    "idempotency_key": "stale",
                    "index": 0,
                    "asset": {"kind": "Native"},
                },
            )
    assert not MpcSolanaClaim.objects.exists()
    assert UserWallet.objects.get(pk=wallet_id).user_id == "original-legacy-owner"
    with pytest.raises(DatabaseError, match="historical"):
        reserve(c)


def test_seeded_retirement_and_admin_mutation_wait_for_lifecycle_acceptance(issuance):
    from django.contrib import admin
    from django.test import RequestFactory

    c = issuance
    request = begin(c)
    wallet = complete(c, request, reply(c, request))
    with pytest.raises(DatabaseError, match="drain"):
        UserWallet.objects.filter(pk=wallet.pk).update(status="RETIRED")
    model_admin = admin.site._registry[UserWallet]
    http = RequestFactory().get("/admin/")
    assert not model_admin.has_change_permission(http, wallet)
    assert not model_admin.has_delete_permission(http, wallet)
    assert set(model_admin.get_readonly_fields(http, wallet)) == {
        f.name for f in UserWallet._meta.fields
    }


def test_expired_query_refresh_preserves_issuance_and_rejects_delayed_reply(issuance):
    import time

    c = issuance
    original = begin(c)
    delayed = reply(c, original)
    expires = MpcSolanaIssuance.objects.get(pk=original["issuance_id"]).query_expires_at
    # Real expiry also exercises PostgreSQL's independently bounded clock guard.
    time.sleep(max(0, (expires - datetime.now(timezone.utc)).total_seconds()) + 0.05)
    with pytest.raises(MpcBindingError, match="expired"):
        complete(c, original, delayed)
    renewed = begin(c)
    assert renewed["issuance_id"] == original["issuance_id"]
    assert renewed["query"]["challenge"] != original["query"]["challenge"]
    assert renewed["witness_action"] == original["witness_action"]
    with pytest.raises(MpcBindingError):
        complete(c, renewed, delayed)
    wallet = complete(c, renewed, reply(c, renewed))
    assert wallet.solana_claim_id == c["claim"].pk
    assert AdminActionLog.objects.filter(action_type="SOLANA_ISSUANCE_QUERY_REFRESH").count() == 1


def test_concurrent_request_and_publication_share_one_original_identity(issuance):
    from threading import Barrier

    c = issuance
    start = Barrier(2)

    def reserve_once():
        close_old_connections()
        try:
            start.wait(timeout=10)
            return begin(c)
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        requests = list(pool.map(lambda _: reserve_once(), range(2)))
    assert requests[0] == requests[1]
    assert MpcSolanaIssuance.objects.count() == 1
    assert AdminActionLog.objects.filter(action_type="SOLANA_ISSUANCE_RESERVE").count() == 1
    proof = reply(c, requests[0])
    start = Barrier(2)

    def publish_once():
        close_old_connections()
        try:
            start.wait(timeout=10)
            return complete(c, requests[0], proof).pk
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: publish_once(), range(2)))
    assert results[0] == results[1]
    assert UserWallet.objects.filter(solana_claim=c["claim"]).count() == 1
    assert AdminActionLog.objects.filter(action_type="SOLANA_NATIVE_WALLET_PUBLISH").count() == 1


def test_permanent_active_grant_can_finish_publication_after_freeze(issuance):
    c = issuance
    request = begin(c)
    proof = reply(c, request)
    proof["value"]["root"]["phase"] = "Frozen"
    proof = signed(c, proof["key_id"], proof["value"])
    assert complete(c, request, proof).solana_claim_id == c["claim"].pk


def test_published_claim_does_not_enable_generic_root_signing_or_deposit_path(issuance):
    from custody.mpc_binding import UnsupportedMpcDerivation, _wallet_root_keyset

    c = issuance
    request = begin(c)
    wallet = complete(c, request, reply(c, request))
    with pytest.raises(UnsupportedMpcDerivation):
        _wallet_root_keyset(wallet, "SOL", wallet.deposit_address)


@pytest.mark.parametrize("custody_class", [None, "WARM", "COLD", "hot", "UNKNOWN"])
def test_backend_import_does_not_relabel_unsupported_dkg_birth_classes(issuance, custody_class):
    import copy

    from custody.mpc_binding import verify_coordinator_keyset

    keyset = issuance["keyset"]
    metadata = copy.deepcopy(keyset.dkg_public_evidence)
    metadata["custody_class"] = custody_class
    with pytest.raises(MpcBindingError, match="classified original DKG birth"):
        verify_coordinator_keyset(keyset, metadata)


@pytest.mark.parametrize("published", [False, True])
def test_original_issuance_history_refuses_schema_downgrade(issuance, published):
    from django.db.migrations.executor import MigrationExecutor

    c = issuance
    request = begin(c)
    if published:
        complete(c, request, reply(c, request))
    executor = MigrationExecutor(connection)
    final = executor.loader.graph.leaf_nodes()
    try:
        with pytest.raises(DatabaseError, match="populated issuance/ownership"):
            executor.migrate([("custody", "0034_solana_authoritative_claims")])
        assert MpcSolanaIssuance.objects.get(pk=request["issuance_id"]).claim_id == c["claim"].pk
        assert UserWallet.objects.filter(solana_claim=c["claim"]).count() == int(published)
    finally:
        MigrationExecutor(connection).migrate(final)
