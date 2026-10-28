"""Privileged operator provisioning, not external IAM or customer issuance.

Commit original dedication/reservation before RPC. All three independently pinned
signer receipts are required for APPROVED. No wallet, balance, transaction or
spending grant is created here; SPL approval does not initialize an account.
"""

from uuid import uuid4

from django.conf import settings
from django.db import transaction
from solders.pubkey import Pubkey

from .identity_registry import _standalone, _text, _uuid, resolve_principal
from .models import AdminActionLog, Asset, CustodyTenant, MpcKeyset, MpcSolanaClaim, MpcSolanaRoot
from .mpc_binding import MpcBindingError, _freeze_root_network, verify_coordinator_keyset
from .mpc_receipts import verify_receipts
from .mpc_solana_network import (
    authorize_solana_network,
    network_identity,
    verify_solana_rpc_endpoints,
)
from .native_tx import RequestsTransport
from .signer_adapter import SelfHostedMpcAdapter, assert_mpc_backend_runtime_safe
from .solana_seeded import MAX_SEED_INDEX, account_address
from .token_metadata import assert_verified_token

VERSION = "solana_seeded_v1"


def _runtime():
    if settings.MPC_SIGNER_BACKEND != "self_hosted_mpc":
        raise MpcBindingError("seeded provisioning requires genuine self-hosted MPC")
    assert_mpc_backend_runtime_safe("SOL")


def _audit(action, row, operator_ref):
    AdminActionLog.objects.create(
        actor_id=operator_ref,
        action_type=action,
        entity_type="solana_provisioning",
        entity_id=str(row.pk),
        metadata={"authority": "privileged_operator", "status": row.status},
    )


def _root_statement(keyset, tenant_id, network):
    metadata = keyset.dkg_public_evidence
    verify_coordinator_keyset(keyset, metadata)
    if keyset.scope != "SOLANA" or not keyset.dkg_execution_id or keyset.active_for_new_wallets:
        raise MpcBindingError("original inactive-for-auto-issuance SOLANA root required")
    report = metadata["participant_agreement"][0]
    if len(report["public_key_package"]) > 4096 or bytes(
        Pubkey.from_string(network["genesis_hash"])
    ) == bytes(32):
        raise MpcBindingError("bounded original public package and nonzero genesis required")
    account_address(str(Pubkey.from_bytes(bytes.fromhex(keyset.public_key))), 0)
    return {
        "dkg": report["request"],
        "group_public_key": keyset.public_key,
        "public_key_package": report["public_key_package"],
        "ownership_scope": str(tenant_id),
        "chain_id": "SOL",
        "genesis_hash": network["genesis_hash"],
        "purpose": "DEPOSIT",
        "wallet_class": "HOT",
        "derivation_version": VERSION,
        "generation": 0,
    }


def _validate_root(root):
    expected = _root_statement(root.keyset, root.tenant_id, root.network_identity)
    if (
        root.statement != expected
        or root.base_address != str(Pubkey.from_bytes(bytes.fromhex(root.keyset.public_key)))
        or root.dkg_public_evidence != root.keyset.dkg_public_evidence
        or root.keyset.network_bindings
        != {
            "SOL": {
                "scope": root.keyset.scope,
                "algorithm": root.keyset.algorithm,
                "public_key": root.keyset.public_key,
                "dkg_execution_id": str(root.keyset.dkg_execution_id),
                "dkg_fingerprint": root.keyset.dkg_result_fingerprint,
                "network": root.network_identity,
            }
        }
    ):
        raise MpcBindingError("original seeded root identity mismatch")


def _verify(kind, statement, evidence):
    try:
        if (
            set(evidence) != {"statement", "participant_agreement"}
            or evidence["statement"] != statement
        ):
            raise ValueError
        verify_receipts(f"solana_{kind}", statement, evidence["participant_agreement"])
    except (TypeError, KeyError, ValueError) as exc:
        raise MpcBindingError("unverifiable original seeded approval") from exc


def register_root(*, keyset_id, tenant_id, operator_ref, client=None, transport=None):
    """Durably bind the original root to one tenant before any signer dedication.

    A timeout or invalid response leaves PENDING. Retry these original IDs; never
    delete a pending intent or assign its potentially dedicated keyset elsewhere.
    """
    _standalone()
    _runtime()
    keyset_id, tenant_id = _uuid(keyset_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    client = client or SelfHostedMpcAdapter()
    transport = transport or RequestsTransport()
    spec = authorize_solana_network("SOL")
    network = network_identity("SOL")
    existing = (
        MpcSolanaRoot.objects.select_related("keyset").filter(keyset__keyset_id=keyset_id).first()
    )
    metadata = None if existing else client.get_keyset(str(keyset_id))
    with transaction.atomic():
        keyset = MpcKeyset.objects.select_for_update().get(keyset_id=keyset_id)
        root = MpcSolanaRoot.objects.select_related("keyset").filter(keyset=keyset).first()
        if root:
            if root.tenant_id != tenant_id or root.network_identity != network:
                raise MpcBindingError("original tenant/network cannot be replaced")
            _validate_root(root)
        else:
            if keyset.status != "ACTIVE" or not CustodyTenant.objects.filter(pk=tenant_id).exists():
                raise MpcBindingError("active root and registered tenant required")
            verify_coordinator_keyset(keyset, metadata)
            _freeze_root_network(keyset, spec)
            keyset.refresh_from_db()
            root = MpcSolanaRoot.objects.create(
                keyset=keyset,
                tenant_id=tenant_id,
                statement=_root_statement(keyset, tenant_id, network),
                network_identity=network,
                dkg_public_evidence=metadata,
                base_address=str(Pubkey.from_bytes(bytes.fromhex(keyset.public_key))),
            )
            _audit("SOLANA_ROOT_RESERVE", root, operator_ref)
        if root.status == "APPROVED":
            _verify("root", root.statement, root.evidence)
            return root
        if keyset.status != "ACTIVE":
            raise MpcBindingError("root unavailable for new dedication")
    # No database transaction spans a network side effect. The original claim
    # is committed even if the remote signer commit/response outcome is unknown.
    verify_solana_rpc_endpoints("SOL", transport)
    evidence = client.enroll_solana_root(str(keyset_id), root.statement)
    _verify("root", root.statement, evidence)
    with transaction.atomic():
        root = MpcSolanaRoot.objects.select_for_update().get(pk=root.pk)
        if root.status == "PENDING":
            root.status, root.evidence = "APPROVED", evidence
            root.save(update_fields=["status", "evidence"])
            _audit("SOLANA_ROOT_APPROVE", root, operator_ref)
        else:
            _verify("root", root.statement, root.evidence)
    return root


def _asset_statement(asset):
    if asset.chain_id != "SOL" or not asset.enabled or not asset.deposit_supported:
        raise MpcBindingError("enabled reviewed SOL asset required")
    if asset.is_native:
        if asset.decimals != 9 or asset.token_standard or asset.contract_address:
            raise MpcBindingError("native SOL identity mismatch")
        return {"kind": "Native"}, "SOL"
    assert_verified_token(asset.asset_key)
    mint = asset.contract_address
    if (
        asset.token_standard != "SPL"
        or not 0 <= asset.decimals <= 18
        or str(Pubkey.from_string(mint)) != mint
        or bytes(Pubkey.from_string(mint)) == bytes(32)
    ):
        raise MpcBindingError("verified classic SPL mint required")
    return {"kind": "ClassicToken", "mint": mint, "decimals": asset.decimals}, mint


def reserve_claim(*, keyset_id, tenant_id, principal_id, asset_key, idempotency_key, operator_ref):
    """Allocate once across all owners/assets; no remote side effects or issuance."""
    _standalone()
    _runtime()
    keyset_id, tenant_id = _uuid(keyset_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    if (
        not isinstance(idempotency_key, str)
        or not 1 <= len(idempotency_key) <= 128
        or idempotency_key != idempotency_key.strip()
        or "\0" in idempotency_key
    ):
        raise MpcBindingError("invalid original idempotency key")
    principal = resolve_principal(tenant_id=tenant_id, principal_id=principal_id)
    with transaction.atomic():
        keyset = MpcKeyset.objects.select_for_update().get(keyset_id=keyset_id)
        root = MpcSolanaRoot.objects.select_for_update().select_related("keyset").get(keyset=keyset)
        if root.tenant_id != tenant_id or root.network_identity != network_identity("SOL"):
            raise MpcBindingError("root tenant/network mismatch")
        _validate_root(root)
        if root.status != "APPROVED":
            raise MpcBindingError("root has not obtained three independent approvals")
        _verify("root", root.statement, root.evidence)
        asset = Asset.objects.select_for_update().get(asset_key=asset_key)
        original = MpcSolanaClaim.objects.filter(root=root, idempotency_key=idempotency_key).first()
        if original:
            if original.principal_id != principal.pk or original.asset_id != asset.pk:
                raise MpcBindingError("retry conflicts with original owner/asset")
            return original
        statement_asset, namespace = _asset_statement(asset)
        if MpcSolanaClaim.objects.filter(
            root=root, principal=principal, asset_namespace=namespace
        ).exists():
            raise MpcBindingError("owner/asset already has an original reservation; retry its key")
        if keyset.status != "ACTIVE" or root.next_index > MAX_SEED_INDEX:
            raise MpcBindingError("root unavailable or index space exhausted")
        index, reservation = int(root.next_index), uuid4()
        statement = {
            "root": root.statement,
            "reservation_id": str(reservation),
            "owner_ref": principal.ledger_owner_id,
            "idempotency_key": idempotency_key,
            "index": index,
            "asset": statement_asset,
        }
        claim = MpcSolanaClaim.objects.create(
            reservation_id=reservation,
            root=root,
            principal=principal,
            asset=asset,
            asset_namespace=namespace,
            idempotency_key=idempotency_key,
            index=index,
            statement=statement,
            address=account_address(
                str(Pubkey.from_bytes(bytes.fromhex(keyset.public_key))),
                index,
                token=statement_asset["kind"] == "ClassicToken",
            ),
        )
        _audit("SOLANA_CLAIM_RESERVE", claim, operator_ref)
        return claim


def approve_claim(*, reservation_id, tenant_id, operator_ref, client=None, transport=None):
    """Approve an existing immutable reservation. Never publish a UserWallet."""
    _standalone()
    _runtime()
    reservation_id, tenant_id = _uuid(reservation_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    claim = MpcSolanaClaim.objects.select_related("root__keyset", "principal", "asset").get(
        pk=reservation_id, root__tenant_id=tenant_id
    )
    root = claim.root
    _validate_root(root)
    _verify("root", root.statement, root.evidence)
    if root.network_identity != network_identity("SOL"):
        raise MpcBindingError("original network differs from active isolated policy")
    statement_asset, namespace = _asset_statement(claim.asset)
    expected = {
        "root": root.statement,
        "reservation_id": str(claim.pk),
        "owner_ref": claim.principal.ledger_owner_id,
        "idempotency_key": claim.idempotency_key,
        "index": claim.index,
        "asset": statement_asset,
    }
    address = account_address(
        str(Pubkey.from_bytes(bytes.fromhex(root.keyset.public_key))),
        claim.index,
        token=statement_asset["kind"] == "ClassicToken",
    )
    if (
        claim.principal.tenant_id != tenant_id
        or claim.statement != expected
        or claim.asset_namespace != namespace
        or claim.address != address
    ):
        raise MpcBindingError("original claim identity mismatch")
    if claim.status == "APPROVED":
        _verify("claim", claim.statement, claim.evidence)
        return claim
    if root.keyset.status != "ACTIVE":
        raise MpcBindingError("root unavailable for new approvals")
    if (
        MpcSolanaClaim.objects.filter(root=root, index__lt=claim.index)
        .exclude(status="APPROVED")
        .exists()
    ):
        raise MpcBindingError("recover earlier pending reservations before later approval")
    verify_solana_rpc_endpoints("SOL", transport or RequestsTransport())
    evidence = (client or SelfHostedMpcAdapter()).approve_solana_claim(
        str(root.keyset.keyset_id), claim.statement
    )
    _verify("claim", claim.statement, evidence)
    with transaction.atomic():
        claim = MpcSolanaClaim.objects.select_for_update().get(pk=reservation_id)
        if claim.status == "PENDING":
            claim.status, claim.evidence = "APPROVED", evidence
            claim.save(update_fields=["status", "evidence"])
            _audit("SOLANA_CLAIM_APPROVE", claim, operator_ref)
        else:
            _verify("claim", claim.statement, claim.evidence)
    return claim
