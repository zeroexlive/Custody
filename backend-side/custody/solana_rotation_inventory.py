"""Durable public source inventory over an already paused allocator.

Every response answers its own committed nonce/deadline. Historical local
publication state and authenticated W state are retained separately. Export is
data for independent rotation approval, never private or ledger authority.
"""

import copy
import hashlib
import re
import secrets
from datetime import timedelta
from uuid import UUID

from django.conf import settings
from django.db import connection, transaction
from django.utils import timezone

from .identity_registry import _standalone, _text, _uuid
from .models import (
    AdminActionLog,
    CustodyPrincipalRole,
    MpcKeyset,
    MpcSolanaAllocationPause,
    MpcSolanaClaim,
    MpcSolanaFinancialRoot,
    MpcSolanaFinancialSession,
    MpcSolanaFinancialWallet,
    MpcSolanaIssuance,
    MpcSolanaRoot,
    MpcSolanaRotationInventory,
    MpcSolanaRotationInventoryEntry,
    MpcSolanaRotationInventoryQuery,
    UserWallet,
)
from .mpc_binding import MpcBindingError
from .mpc_solana_network import network_identity
from .solana_claim_registration import _verify_evidence
from .solana_financial_root import verify_financial_mode
from .solana_issuance import _canonical, _fingerprint, _pin
from .solana_provisioning import _runtime, _validate_root, _verify, historical_asset_statement
from .solana_seeded import account_address
from .solana_witness_client import _verify as verify_witness

ROLES = {"CUSTOMER": "CUSTOMER_DEPOSIT", "TREASURY": "TENANT_TREASURY"}
PARTIES = {"signer-a", "signer-b", "signer-c"}


def _audit(action, row, operator_ref):
    AdminActionLog.objects.create(
        actor_id=operator_ref,
        action_type=action,
        entity_type="solana_rotation_inventory",
        entity_id=str(row.pk),
        metadata={"authority": "privileged_operator"},
    )


def _root_lock(root_id):
    MpcKeyset.objects.select_for_update().get(pk=root_id)
    return MpcSolanaRoot.objects.select_for_update().select_related("keyset").get(pk=root_id)


def _known_role(claim):
    # The absence decision shares0037's stable principal lock. KEY SHARE permits
    # other customer readers but excludes creation of a new immutable role.
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT principal_id FROM custody_custodyprincipal WHERE principal_id=%s FOR KEY SHARE",
            [claim.principal_id],
        )
        if cursor.fetchone() is None:
            raise MpcBindingError("original source principal required")
    classification = CustodyPrincipalRole.objects.filter(principal_id=claim.principal_id).first()
    if classification:
        return ROLES[classification.role]
    return "CUSTOMER_DEPOSIT" if UserWallet.objects.filter(solana_claim=claim).exists() else None


def _current_role(entry):
    known = _known_role(entry.claim)
    if known is not None and known != entry.declared_role:
        raise MpcBindingError(
            "source role changed after capture; preserve history and create a new snapshot"
        )


def _locked(snapshot_id, tenant_id):
    ref = MpcSolanaRotationInventory.objects.select_related("pause").get(
        pk=snapshot_id, pause__root__tenant_id=tenant_id
    )
    _root_lock(ref.pause.root_id)
    return (
        MpcSolanaRotationInventory.objects.select_for_update(of=("self",))
        .select_related("pause__root__keyset", "header_query", "seal_query")
        .get(pk=ref.pk)
    )


def _historical_claim(claim):
    """Validate immutable identity without requiring currently enabled deposits."""
    asset, root = claim.asset, claim.root
    expected, namespace = historical_asset_statement(asset)
    owner = claim.principal.ledger_owner_id
    if (
        asset.chain_id != "SOL"
        or claim.principal.tenant_id != root.tenant_id
        or owner != "p1:" + str(claim.principal_id)
        or claim.asset_namespace != namespace
        or claim.statement
        != dict(
            root=root.statement,
            reservation_id=str(claim.pk),
            owner_ref=owner,
            idempotency_key=claim.idempotency_key,
            index=claim.index,
            asset=expected,
        )
        or claim.address
        != account_address(root.base_address, claim.index, token=not asset.is_native)
    ):
        raise MpcBindingError("original reserved owner/asset/alias/address required")
    if claim.status == "APPROVED":
        _verify_evidence(claim, claim.evidence)
    elif claim.status != "PENDING" or claim.evidence:
        raise MpcBindingError("original Claim approval state required")


def _local_record(claim):
    issuance = MpcSolanaIssuance.objects.filter(claim=claim).first()
    wallet = MpcSolanaFinancialWallet.objects.filter(claim=claim).first()
    return {
        "version": 1,
        "claim": copy.deepcopy(claim.statement),
        "claim_status": claim.status,
        "original_evidence": copy.deepcopy(claim.evidence),
        "asset_key": claim.asset.asset_key,
        "issuance": None
        if issuance is None
        else {
            "issuance_id": str(issuance.pk),
            "witness_anchor_id": str(issuance.witness_anchor_id),
            "witness_key_id": issuance.witness_key_id,
            "status": issuance.status,
            "evidence": copy.deepcopy(issuance.evidence),
        },
        "financial_wallet": None
        if wallet is None
        else {
            "mode_root_id": wallet.mode_id,
            "issuance_id": str(wallet.issuance_id),
            "role": wallet.role,
            "status": wallet.status,
            "user_wallet_id": wallet.user_wallet_id,
            "evidence": copy.deepcopy(wallet.evidence),
        },
        "legacy_user_wallet_ids": list(
            UserWallet.objects.filter(solana_claim=claim)
            .order_by("pk")
            .values_list("pk", flat=True)
        ),
        "initialization_executions": [
            str(value)
            for value in MpcSolanaFinancialSession.objects.filter(
                operation__source_id=claim.pk, operation__provision__isnull=False
            )
            .order_by("created_at", "session_id")
            .values_list("crypto_execution_id", flat=True)
        ],
    }


def begin_inventory(*, pause_id, snapshot_id, tenant_id, legacy_roles, operator_ref):
    _standalone()
    _runtime()
    if connection.vendor != "postgresql":
        raise MpcBindingError("durable rotation inventory requires PostgreSQL")
    pause_id, snapshot_id, tenant_id = map(_uuid, (pause_id, snapshot_id, tenant_id))
    operator_ref = _text(operator_ref, "operator audit reference")
    if not isinstance(legacy_roles, dict) or any(
        str(_uuid(k)) != k or v not in ROLES.values() for k, v in legacy_roles.items()
    ):
        raise MpcBindingError("explicit canonical legacy source role declarations required")
    anchor, key_id, _ = _pin()
    with transaction.atomic():
        ref = MpcSolanaAllocationPause.objects.get(pk=pause_id, root__tenant_id=tenant_id)
        root = _root_lock(ref.root_id)
        existing = MpcSolanaRotationInventory.objects.filter(pk=snapshot_id).first()
        if existing:
            if existing.pause_id != pause_id or existing.roles != legacy_roles:
                raise MpcBindingError("original inventory snapshot and role declarations required")
            return existing
        if not settings.MPC_SOLANA_ROTATION_INVENTORY_ENABLED:
            raise MpcBindingError("new rotation inventory snapshots are disabled")
        _validate_root(root)
        _verify("root", root.statement, root.evidence)
        if (
            root.status != "APPROVED"
            or root.next_index != ref.frontier
            or (root.network_identity != network_identity("SOL"))
        ):
            raise MpcBindingError("original paused Root/frontier/network required")
        mode = MpcSolanaFinancialRoot.objects.filter(root=root).first()
        local_mode = {}
        if mode:
            verify_financial_mode(mode)
            if (mode.witness_anchor_id, mode.witness_key_id) != (anchor, key_id):
                raise MpcBindingError("original financial witness identity required")
            local_mode = dict(
                version=1, activation_id=str(mode.activation_id), command_id=str(mode.command_id)
            )
        row = MpcSolanaRotationInventory.objects.create(
            snapshot_id=snapshot_id,
            pause=ref,
            root_identity=_fingerprint("SOLANA_SEEDED_ROOT_V1", root.statement),
            witness_anchor_id=anchor,
            witness_key_id=key_id,
            roles=copy.deepcopy(legacy_roles),
            local_mode=local_mode,
        )
        used_roles, count = set(), 0
        for claim in (
            MpcSolanaClaim.objects.filter(root=root)
            .select_related("root__keyset", "principal", "asset")
            .order_by("index")
        ):
            _historical_claim(claim)
            if claim.index != count:
                raise MpcBindingError("complete contiguous original allocator namespace required")
            record = _local_record(claim)
            known = _known_role(claim)
            declared = legacy_roles.get(str(claim.principal_id))
            if declared is not None:
                used_roles.add(str(claim.principal_id))
            if (known is None and declared is None) or (known and declared and known != declared):
                raise MpcBindingError(
                    "preserve known roles; declare every unknown legacy source role"
                )
            role = known or declared
            if record["financial_wallet"] and record["financial_wallet"]["role"] != role:
                raise MpcBindingError("original financial source role cannot change")
            MpcSolanaRotationInventoryEntry.objects.create(
                snapshot=row, claim=claim, ordinal=count, declared_role=role, original_record=record
            )
            count += 1
        if count != ref.frontier or used_roles != set(legacy_roles):
            raise MpcBindingError("exact complete inventory and used role declarations required")
        _audit("SOLANA_ROTATION_INVENTORY_BEGIN", row, operator_ref)
        return row


def _query(row):
    snapshot = row.snapshot
    value = dict(
        anchor_id=str(snapshot.witness_anchor_id),
        root_identity=snapshot.root_identity,
        challenge=row.challenge,
        execution_id=None,
    )
    if row.entry_id is not None:
        value.update(
            claim_reservation_id=str(row.entry.claim_id),
            candidate_claim=row.entry.original_record["claim"],
        )
    return value


def request_query(*, snapshot_id, tenant_id, purpose, operator_ref, ordinal=None):
    _standalone()
    _runtime()
    snapshot_id, tenant_id = _uuid(snapshot_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    if purpose not in {"ROOT", "ENTRY", "SEAL"} or (
        (purpose == "ENTRY") != (type(ordinal) is int and ordinal >= 0)
    ):
        raise MpcBindingError("explicit original inventory query subject required")
    with transaction.atomic():
        snapshot = _locked(snapshot_id, tenant_id)
        if snapshot.status != "COLLECTING":
            raise MpcBindingError("original collecting inventory required")
        if purpose != "ROOT" and snapshot.header_query_id is None:
            raise MpcBindingError("accept original Frozen Root header before entries or sealing")
        if purpose == "ROOT" and snapshot.header_query_id is not None:
            raise MpcBindingError("original Root header already accepted")
        entry = None
        if purpose == "ENTRY":
            entry = MpcSolanaRotationInventoryEntry.objects.get(snapshot=snapshot, ordinal=ordinal)
            if entry.query_id:
                raise MpcBindingError("original entry already accepted; read its durable source")
        if (
            purpose == "SEAL"
            and MpcSolanaRotationInventoryEntry.objects.filter(
                snapshot=snapshot, query__isnull=True
            ).exists()
        ):
            raise MpcBindingError("every original entry needs its own accepted witness proof")
        row = MpcSolanaRotationInventoryQuery.objects.create(
            challenge=secrets.token_hex(32),
            snapshot=snapshot,
            entry=entry,
            purpose=purpose,
            expires_at=timezone.now() + timedelta(seconds=15),
        )
        _audit("SOLANA_ROTATION_INVENTORY_QUERY", row, operator_ref)
        return dict(query=_query(row), expires_at=row.expires_at.isoformat())


def _proof(row, evidence, *, fresh):
    snapshot = row.snapshot
    anchor, key_id, _ = _pin()
    if (anchor, key_id) != (snapshot.witness_anchor_id, snapshot.witness_key_id):
        raise MpcBindingError("original pinned inventory witness required")
    if len(_canonical(evidence)) > 1024 * 1024:
        raise MpcBindingError("bounded inventory witness response required")
    value = verify_witness("WITNESS_QUERY_REPLY_V1", evidence)
    try:
        root = value["root"]
        package, generation, roster = (
            root["public_key_package"],
            root["generation"],
            root["node_keys"],
        )
        original = snapshot.pause.root.statement
        if (
            value["query"] != _query(row)
            or snapshot.root_identity != _fingerprint("SOLANA_SEEDED_ROOT_V1", original)
            or value["execution"] is not None
            or value["abandoned"] is not False
            or type(value["sequence"]) is not int
            or value["sequence"] <= 0
            or root["original"] != original
            or root["phase"] != "Frozen"
            or root["prepared"] is not None
            or root.get("rotation") is not None
            or type(root["revision"]) is not int
            or root["revision"] <= 0
            or type(root["next_claim_index"]) is not int
            or not 0 <= root["next_claim_index"] <= snapshot.pause.frontier
            or (root.get("financial_mode") or {}) != snapshot.local_mode
            or value.get("refresh") is not None
            or value.get("replacement") is not None
            or not isinstance(package, list)
            or not 1 <= len(package) <= 4096
            or any(type(x) is not int or not 0 <= x <= 255 for x in package)
            or set(roster) != PARTIES
            or len(set(roster.values())) != 3
            or any(not re.fullmatch("[0-9a-f]{64}", x) or x == "00" * 32 for x in roster.values())
            or type(generation["epoch"]) is not int
            or generation["epoch"] < 0
            or generation["public_key_package_sha256"] != hashlib.sha256(bytes(package)).hexdigest()
            or not UUID(generation["ceremony_id"]).int
        ):
            raise ValueError
        if generation["epoch"] == 0 and (
            generation["ceremony_id"] != original["dkg"]["execution_id"]
            or package != original["public_key_package"]
        ):
            raise ValueError
        if row.purpose != "ROOT" and root != snapshot.header_query.evidence["value"]["root"]:
            raise ValueError
        if row.entry_id is None and (
            value.get("claim") is not None or value.get("claim_issuance") is not None
        ):
            raise ValueError
        if fresh and timezone.now() >= row.expires_at:
            raise MpcBindingError(
                "inventory query expired; retain snapshot, entries and old challenges"
            )
    except MpcBindingError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError):
        raise MpcBindingError(
            "exact frozen source context and original inventory query required"
        ) from None
    return value


def _captured_provenance(entry, snapshot):
    """Verify positive archives; Pending captures never acquire publication."""
    from .solana_financial_wallet import validate_financial_wallet_history
    from .solana_issuance import _witness

    record = entry.original_record
    issued, wallet = record["issuance"], record["financial_wallet"]
    if issued is not None:
        if issued["status"] == "WITNESSED":
            original = MpcSolanaIssuance.objects.get(pk=issued["issuance_id"], claim=entry.claim)
            _witness(original, issued["evidence"])
            if (
                issued["evidence"]["value"]["root"].get("financial_mode") or {}
            ) != snapshot.local_mode:
                raise MpcBindingError("original publication mode must match captured source")
        elif issued["status"] != "PENDING" or issued["evidence"]:
            raise MpcBindingError("original issuance archive state required")
    if wallet is not None:
        if wallet["status"] == "ACTIVE":
            original = validate_financial_wallet_history(
                MpcSolanaFinancialWallet.objects.get(pk=entry.claim_id)
            )
            if (
                issued is None
                or issued["status"] != "WITNESSED"
                or original.issuance.evidence != issued["evidence"]
                or original.evidence != wallet["evidence"]
                or original.user_wallet_id != wallet["user_wallet_id"]
                or original.role != wallet["role"]
            ):
                raise MpcBindingError("original captured active membership provenance required")
        elif (
            wallet["status"] != "PENDING"
            or wallet["evidence"]
            or wallet["user_wallet_id"] is not None
        ):
            raise MpcBindingError("pending membership cannot synthesize publication")
    elif issued and issued["status"] == "WITNESSED":
        ids = record["legacy_user_wallet_ids"]
        if len(ids) != 1:
            raise MpcBindingError("original legacy publication wallet link required")
        original = UserWallet.objects.get(pk=ids[0], solana_claim=entry.claim)
        claim = entry.claim
        if (
            original.user_id != claim.principal.ledger_owner_id
            or original.chain_id != "SOL"
            or original.asset_key != claim.asset.asset_key
            or original.deposit_address != claim.address
            or original.mpc_keyset_id != claim.root_id
            or original.derivation_version != "solana_seeded_v1"
            or original.derivation_path != f"solana:{claim.root.keyset.keyset_id}:{claim.index}"
            or original.address_index != claim.index
            or original.memo is not None
            or original.asset_account_address is not None
            or original.custody_account_id is not None
        ):
            raise MpcBindingError("original legacy customer wallet identity required")


def _source_value(row, value):
    entry, snapshot = row.entry, row.snapshot
    record = entry.original_record
    _captured_provenance(entry, snapshot)
    proof, grant = value.get("claim"), value.get("claim_issuance")
    availability = value.get("claim_availability")
    if (
        not isinstance(availability, dict)
        or availability.get("reservation_id") != str(entry.claim_id)
        or any(
            availability.get(k) not in (None, str(entry.claim_id))
            for k in ("index", "owner", "retry")
        )
    ):
        raise MpcBindingError("exact original allocation aliases required")
    source = dict(
        claim=copy.deepcopy(record["claim"]),
        asset_key=record["asset_key"],
        role=entry.declared_role,
        membership={"kind": "Unpublished"},
    )
    if (proof is not None) != (entry.ordinal < value["root"]["next_claim_index"]):
        raise MpcBindingError("complete contiguous witness registration prefix required")
    if proof is None and any(availability.get(k) is not None for k in ("index", "owner", "retry")):
        raise MpcBindingError("unregistered source cannot occupy registered aliases")
    if proof is not None:
        if entry.ordinal >= value["root"]["next_claim_index"] or any(
            availability.get(k) != str(entry.claim_id) for k in ("index", "owner", "retry")
        ):
            raise MpcBindingError("registered source must retain exact witness index/owner/retry")
        _verify_evidence(entry.claim, proof)
        source["witness_evidence_fingerprint"] = _fingerprint(
            "SOLANA_ROTATION_CLAIM_EVIDENCE_V1", proof
        )
    original_issuance, wallet = record["issuance"], record["financial_wallet"]
    if grant is None:
        if (
            (original_issuance and original_issuance["status"] == "WITNESSED")
            or (wallet and wallet["status"] == "ACTIVE")
            or record["legacy_user_wallet_ids"]
        ):
            raise MpcBindingError("existing publication cannot hide its original witness grant")
        return source
    if proof is None or original_issuance is None:
        raise MpcBindingError("original registered evidence and local issuance identity required")
    expected_keys = {"reservation_id", "issuance_id", "command_id"}
    if not entry.claim.asset.is_native:
        expected_keys.add("initialization_execution_id")
    if (
        set(grant) != expected_keys
        or grant["reservation_id"] != str(entry.claim_id)
        or grant["issuance_id"] != original_issuance["issuance_id"]
        or original_issuance["witness_anchor_id"] != str(snapshot.witness_anchor_id)
        or original_issuance["witness_key_id"] != snapshot.witness_key_id
        or not UUID(grant["command_id"]).int
        or len({grant["reservation_id"], grant["issuance_id"], grant["command_id"]}) != 3
        or (
            not entry.claim.asset.is_native
            and grant["initialization_execution_id"] not in record["initialization_executions"]
        )
    ):
        raise MpcBindingError("exact original publication and initialization IDs required")
    if (
        original_issuance["status"] == "WITNESSED"
        and original_issuance["evidence"]["value"].get("claim_issuance") != grant
    ):
        raise MpcBindingError("original accepted issuance cannot be replaced")
    if snapshot.local_mode:
        if (
            wallet is None
            or wallet["mode_root_id"] != snapshot.pause.root_id
            or wallet["issuance_id"] != grant["issuance_id"]
        ):
            raise MpcBindingError("preserve original financial membership without adoption")
        source["membership"] = dict(
            kind="Financial", issuance=copy.deepcopy(grant), publication=wallet["status"]
        )
    else:
        if wallet is not None:
            raise MpcBindingError("mode-off source cannot acquire financial membership")
        source["membership"] = dict(kind="LegacyControl", issuance=copy.deepcopy(grant))
    return source


def _source(row, value):
    try:
        return _source_value(row, value)
    except MpcBindingError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError):
        raise MpcBindingError(
            "exact original source evidence, membership and grant required"
        ) from None


def accept_query(*, challenge, tenant_id, evidence, operator_ref):
    _standalone()
    _runtime()
    tenant_id = _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    evidence = copy.deepcopy(evidence)
    ref = MpcSolanaRotationInventoryQuery.objects.get(
        pk=challenge, snapshot__pause__root__tenant_id=tenant_id
    )
    with transaction.atomic():
        snapshot = _locked(ref.snapshot_id, tenant_id)
        entry = (
            None
            if ref.entry_id is None
            else MpcSolanaRotationInventoryEntry.objects.select_for_update()
            .select_related("claim__root__keyset", "claim__asset", "claim__principal")
            .get(pk=ref.entry_id)
        )
        row = MpcSolanaRotationInventoryQuery.objects.select_for_update().get(pk=challenge)
        row.snapshot, row.entry = snapshot, entry
        if row.status == "VERIFIED":
            if row.evidence != evidence:
                raise MpcBindingError("original inventory reply cannot change")
            _proof(row, evidence, fresh=False)
            return snapshot
        if snapshot.status != "COLLECTING":
            raise MpcBindingError("original collecting inventory required")
        value = _proof(row, evidence, fresh=True)
        if row.purpose == "ROOT":
            if snapshot.header_query_id is not None:
                raise MpcBindingError("preserve the original accepted Root header")
            snapshot.header_query = row
            fields = ["header_query"]
        elif row.purpose == "ENTRY":
            _current_role(entry)
            source = _source(row, value)
            if entry.query_id is not None:
                if entry.source != source:
                    raise MpcBindingError("original inventory source cannot change")
                return snapshot
            entry.source, entry.query = source, row
            fields = []
        else:
            entries = list(
                MpcSolanaRotationInventoryEntry.objects.filter(snapshot=snapshot).order_by(
                    "ordinal"
                )
            )
            if len(entries) != snapshot.pause.frontier or any(
                e.ordinal != n or e.query_id is None or not e.source for n, e in enumerate(entries)
            ):
                raise MpcBindingError("every original reserved entry must be accounted for")
            for entry_row in entries:
                _current_role(entry_row)
            snapshot.inventory_fingerprint = _fingerprint(
                "SOLANA_ROTATION_INVENTORY_V1",
                [
                    _fingerprint("SOLANA_SEEDED_ROOT_V1", snapshot.pause.root.statement),
                    len(entries),
                    [e.source for e in entries],
                ],
            )
            snapshot.status, snapshot.seal_query = "SEALED", row
            fields = ["status", "seal_query", "inventory_fingerprint"]
        row.status, row.evidence = "VERIFIED", evidence
        row.save(update_fields=["status", "evidence"])
        if entry is not None:
            entry.save(update_fields=["source", "query"])
        if fields:
            snapshot.save(update_fields=fields)
        _audit("SOLANA_ROTATION_INVENTORY_ACCEPT", row, operator_ref)
        return snapshot


def export_slice(*, snapshot_id, tenant_id, start_index):
    """Bounded source data only; callers still need the exact approved plan."""
    if type(start_index) is not int or start_index < 0:
        raise MpcBindingError("canonical source slice index required")
    row = MpcSolanaRotationInventory.objects.select_related(
        "pause__root", "header_query", "seal_query"
    ).get(pk=_uuid(snapshot_id), pause__root__tenant_id=_uuid(tenant_id), status="SEALED")
    if start_index >= row.pause.frontier and not (start_index == 0 and row.pause.frontier == 0):
        raise MpcBindingError("source slice outside original inventory")
    _validate_root(row.pause.root)
    _verify("root", row.pause.root.statement, row.pause.root.evidence)
    for query in (row.header_query, row.seal_query):
        query.snapshot = row
        if query.status != "VERIFIED":
            raise MpcBindingError("original accepted inventory header and seal required")
        _proof(query, query.evidence, fresh=False)
    rows = list(
        MpcSolanaRotationInventoryEntry.objects.filter(snapshot=row, ordinal__gte=start_index)
        .select_related("query", "claim__root__keyset", "claim__asset", "claim__principal")
        .order_by("ordinal")[:32]
    )
    result = dict(
        snapshot_id=str(row.pk),
        source=copy.deepcopy(row.pause.root.statement),
        allocated_high_water=int(row.pause.frontier),
        inventory_fingerprint=row.inventory_fingerprint,
        start_index=start_index,
        entries=[],
        next_index=start_index,
    )
    for entry in rows:
        if entry.ordinal != result["next_index"] or entry.query_id is None:
            raise MpcBindingError("complete original sealed source slice required")
        query = entry.query
        query.snapshot, query.entry = row, entry
        if (
            query.status != "VERIFIED"
            or _source(query, _proof(query, query.evidence, fresh=False)) != entry.source
        ):
            raise MpcBindingError("original independently witnessed source declaration required")
        candidate = dict(
            result,
            entries=result["entries"] + [copy.deepcopy(entry.source)],
            next_index=result["next_index"] + 1,
        )
        if len(_canonical(candidate)) > 128 * 1024:
            break
        result = candidate
    if len(_canonical(result)) > 128 * 1024 or (row.pause.frontier and not result["entries"]):
        raise MpcBindingError("source slice exceeds bounded public envelope")
    return result
