"""Commit a local source fence before exporting a rotation inventory.

This operator action performs no remote work and asserts no witness liveness.
Release requires a future authenticated lifecycle implementation; there is no
local reset/delete escape hatch. Existing public recovery remains available.
"""

from django.conf import settings
from django.db import connection, transaction

from .identity_registry import _standalone, _text, _uuid
from .models import AdminActionLog, MpcKeyset, MpcSolanaAllocationPause, MpcSolanaRoot
from .mpc_binding import MpcBindingError


def require_allocation_open(root_id):
    # Persisted fences apply even when the entry feature flag is switched off.
    if MpcSolanaAllocationPause.objects.filter(root_id=root_id).exists():
        raise MpcBindingError("original Solana Root is locally paused for rotation")


def require_operation_open(operation):
    require_allocation_open(operation.source.claim.root_id)
    if operation.treasury_destination_id:
        require_allocation_open(operation.treasury_destination.claim.root_id)


def pause_allocation(*, keyset_id, tenant_id, pause_id, operator_ref):
    _standalone()
    if connection.vendor != "postgresql":
        raise MpcBindingError("durable allocation pause requires PostgreSQL")
    keyset_id, tenant_id, pause_id = map(_uuid, (keyset_id, tenant_id, pause_id))
    operator_ref = _text(operator_ref, "operator audit reference")
    from .solana_provisioning import _runtime, _validate_root, _verify

    _runtime()
    with transaction.atomic():
        keyset = MpcKeyset.objects.select_for_update().get(keyset_id=keyset_id)
        root = (
            MpcSolanaRoot.objects.select_for_update()
            .select_related("keyset")
            .get(keyset=keyset, tenant_id=tenant_id)
        )
        existing = MpcSolanaAllocationPause.objects.filter(root=root).first()
        if existing:
            if existing.pk != pause_id:
                raise MpcBindingError("retry the original allocation pause ID")
            return existing
        if not settings.MPC_SOLANA_ALLOCATION_PAUSE_ENABLED:
            raise MpcBindingError("new local allocation pauses are disabled")
        if keyset.status != "ACTIVE" or root.status != "APPROVED":
            raise MpcBindingError("original approved active source required")
        _validate_root(root)
        _verify("root", root.statement, root.evidence)
        # The SQL birth guard checks outstanding source AND known incoming work
        # under these same Root locks, and binds the exact allocator frontier.
        row = MpcSolanaAllocationPause.objects.create(
            pause_id=pause_id, root=root, frontier=root.next_index
        )
        AdminActionLog.objects.create(
            actor_id=operator_ref,
            action_type="SOLANA_ALLOCATION_PAUSE",
            entity_type="solana_allocation_pause",
            entity_id=str(row.pk),
            metadata={
                "authority": "privileged_operator",
                "keyset_id": str(keyset_id),
                "frontier": str(row.frontier),
            },
        )
        return row
