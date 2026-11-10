"""Local PG pause over genuine original FROST receipts, not fund migration."""

from uuid import uuid4

import pytest
from custody.identity_registry import register_principal
from custody.models import MpcSolanaAllocationPause
from custody.mpc_binding import MpcBindingError
from custody.solana_allocation_pause import pause_allocation
from custody.solana_provisioning import reserve_claim
from django.db import close_old_connections
from django.test import override_settings


def check_source_pause(tenant, principal, old_root, old_claim, fresh_root):
    arguments = dict(tenant_id=tenant.pk, operator_ref="integration")
    original_id = uuid4()
    with override_settings(MPC_SOLANA_ALLOCATION_PAUSE_ENABLED=True):
        row = pause_allocation(
            **arguments, keyset_id=old_root.keyset.keyset_id, pause_id=original_id
        )
    assert row.frontier == 1
    new_principal = register_principal(**arguments, customer_ref="local-pause-new-owner")
    close_old_connections()
    # Disabling entry cannot erase an existing pause. Neither operation below
    # asks the globally configured fresh coordinator to authorize the old Root.
    with override_settings(MPC_SOLANA_ALLOCATION_PAUSE_ENABLED=False):
        assert (
            pause_allocation(
                **arguments, keyset_id=old_root.keyset.keyset_id, pause_id=original_id
            ).pk
            == original_id
        )
        assert (
            reserve_claim(
                **arguments,
                keyset_id=old_root.keyset.keyset_id,
                principal_id=principal.pk,
                asset_key="SOL",
                idempotency_key=old_claim.idempotency_key,
            ).pk
            == old_claim.pk
        )
        with pytest.raises(MpcBindingError, match="locally paused"):
            reserve_claim(
                **arguments,
                keyset_id=old_root.keyset.keyset_id,
                principal_id=new_principal.pk,
                asset_key="SOL",
                idempotency_key="new-alias-denied",
            )
        successor_claim = reserve_claim(
            **arguments,
            keyset_id=fresh_root.keyset.keyset_id,
            principal_id=new_principal.pk,
            asset_key="SOL",
            idempotency_key="fresh-root-still-open",
        )
    assert successor_claim.index == 1
    old_root.refresh_from_db()
    assert old_root.next_index == 1 and old_root.status == "APPROVED"
    assert MpcSolanaAllocationPause.objects.get(root=old_root).pk == original_id
