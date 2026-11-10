"""Complete backend allocation inventory with real DKG/receipts and Rust W.

One actual registered source retains its pending financial publication; remaining
allocations are explicitly unpublished. No private signing, movement or ledger.
"""

import copy
import hashlib
import json
from uuid import uuid4

from custody.financial_identity import register_financial_principal
from custody.models import (
    LedgerTransaction,
    MpcSolanaClaim,
    MpcSolanaFinancialWallet,
    MpcSolanaIssuance,
    MpcSolanaRotationInventoryQuery,
)
from custody.solana_allocation_pause import pause_allocation
from custody.solana_financial_wallet import financial_wallet_request
from custody.solana_provisioning import reserve_claim
from custody.solana_rotation_inventory import (
    accept_query,
    begin_inventory,
    export_slice,
    request_query,
)
from django.db import close_old_connections, connection
from django.test import override_settings
from environment import private_file
from financial_root_acceptance import run_financial_mode_import
from test_dkg import encrypted_files
from witness_acceptance import fingerprint, sign, verify


def run_backend_inventory(root_path, *, count=1000):
    def collect(g, root_path, tenant, first_claim, arguments):
        assert count > 0
        shares = encrypted_files(g.net, g.dkg_binding)
        before_ledger = LedgerTransaction.objects.count()
        root = first_claim.root
        first_public = copy.deepcopy((root.evidence, first_claim.evidence))
        pending = financial_wallet_request(
            reservation_id=first_claim.pk, tenant_id=tenant.pk, operator_ref="integration"
        )
        command = g.w.command(pending["witness_action"], g.w.query()["root"]["revision"])
        assert g.w.request("command", command)[0] == 200
        # Deliberately retain the original backend PENDING publication after W
        # accepted it, representing a lost public response, not synthetic ACTIVE.
        for index in range(1, count):
            owner = register_financial_principal(
                tenant_id=tenant.pk,
                reference=f"actual-inventory-owner-{index}",
                role="CUSTOMER",
                operator_ref="integration",
            )
            reserved = reserve_claim(
                **arguments,
                principal_id=owner.pk,
                asset_key="SOL",
                idempotency_key=f"actual-inventory-reservation-{index}",
            )
            assert reserved.index == index and reserved.status == "PENDING"
        assert MpcSolanaClaim.objects.filter(root=root).count() == count
        with override_settings(
            MPC_SOLANA_ALLOCATION_PAUSE_ENABLED=True, MPC_SOLANA_ROTATION_INVENTORY_ENABLED=True
        ):
            paused = pause_allocation(**arguments, pause_id=uuid4())
            snapshot = begin_inventory(
                pause_id=paused.pk,
                snapshot_id=uuid4(),
                tenant_id=tenant.pk,
                legacy_roles={},
                operator_ref="integration",
            )
        frozen = g.w.command({"kind": "Freeze"}, g.w.query()["root"]["revision"])
        assert g.w.request("command", frozen)[0] == 200
        frozen_sequence = g.w.query()["sequence"]

        def observe(purpose, ordinal=None):
            request = request_query(
                snapshot_id=snapshot.pk,
                tenant_id=tenant.pk,
                purpose=purpose,
                ordinal=ordinal,
                operator_ref="integration",
            )
            assert not connection.in_atomic_block
            assert MpcSolanaRotationInventoryQuery.objects.filter(
                pk=request["query"]["challenge"], status="PENDING", snapshot=snapshot
            ).exists()
            code, reply = g.w.request(
                "query",
                sign(g.w.custody, "WITNESS_QUERY_V1", request["query"]),
                identity=g.w.courier,
            )
            assert code == 200, (code, reply)
            verify(g.w.identity, "WITNESS_QUERY_REPLY_V1", reply)
            return accept_query(
                challenge=request["query"]["challenge"],
                tenant_id=tenant.pk,
                evidence=reply,
                operator_ref="integration",
            )

        with override_settings(MPC_SOLANA_ROTATION_INVENTORY_ENABLED=False):
            observe("ROOT")
            for index in range(count):
                if index == count // 2:
                    close_old_connections()
                    g.w.stop()
                    g.w.start()
                observe("ENTRY", index)
            completed = observe("SEAL")
        assert completed.status == "SEALED"
        entries, start, slices = [], 0, 0
        while start < count:
            result = export_slice(snapshot_id=snapshot.pk, tenant_id=tenant.pk, start_index=start)
            assert result["start_index"] == start and len(result["entries"]) <= 32
            assert result["next_index"] > start
            entries.extend(result["entries"])
            start, slices = result["next_index"], slices + 1
        assert len(entries) == count
        assert entries[0]["membership"]["kind"] == "Financial"
        assert entries[0]["membership"]["publication"] == "PENDING"
        assert entries[0]["membership"]["issuance"]["issuance_id"] == pending["issuance_id"]
        assert all(e["membership"] == {"kind": "Unpublished"} for e in entries[1:])
        assert all("witness_evidence_fingerprint" not in e for e in entries[1:])
        assert [e["claim"]["index"] for e in entries] == list(range(count))
        assert completed.inventory_fingerprint == fingerprint(
            "SOLANA_ROTATION_INVENTORY_V1",
            [fingerprint("SOLANA_SEEDED_ROOT_V1", root.statement), count, entries],
        )
        assert g.w.query()["sequence"] == frozen_sequence
        first_claim.refresh_from_db()
        root.refresh_from_db()
        assert (root.evidence, first_claim.evidence) == first_public
        assert int(root.next_index) == count
        assert MpcSolanaIssuance.objects.get(claim=first_claim).status == "PENDING"
        assert MpcSolanaFinancialWallet.objects.get(claim=first_claim).status == "PENDING"
        assert LedgerTransaction.objects.count() == before_ledger
        assert encrypted_files(g.net, g.dkg_binding) == shares
        private_file(
            root_path / "solana-backend-inventory-public-evidence.json",
            json.dumps(
                {
                    "scope": (
                        "actual backend inventory with real FROST receipts and pinned Rust W"
                    ),
                    "allocated_claims": count,
                    "registered_claims": 1,
                    "source_slices": slices,
                    "pending_financial_membership_preserved": True,
                    "other_allocations_remain_explicitly_unpublished": True,
                    "fresh_original_own_nonce_per_header_entry_seal": True,
                    "backend_connection_and_witness_restart": True,
                    "entry_disable_does_not_discard_existing_snapshot": True,
                    "original_shares_receipts_and_ledger_unchanged": True,
                    "witness_commands_during_inventory_observation": 0,
                    "movement_or_retirement_acceptance": False,
                },
                sort_keys=True,
            ).encode(),
        )

    run_financial_mode_import(root_path, after_mode=collect)


def run_repaired_active_inventory(root_path):
    from current_claim_financial_acceptance import run_current_claim_financial
    from custody.models import MpcSolanaRoot

    def collect(g, root_path, tenant, original_wallets):
        root = MpcSolanaRoot.objects.get(pk=original_wallets[0].claim.root_id)
        count = int(root.next_index)
        ledger_count = LedgerTransaction.objects.count()
        originals = list(
            MpcSolanaClaim.objects.filter(root=root)
            .order_by("index")
            .values_list("pk", "status", "evidence")
        )
        ciphertexts = {
            p: hashlib.sha256(p.read_bytes()).hexdigest() for p in g.net.root.rglob("*.share.enc")
        }
        with override_settings(
            MPC_SOLANA_ALLOCATION_PAUSE_ENABLED=True, MPC_SOLANA_ROTATION_INVENTORY_ENABLED=True
        ):
            paused = pause_allocation(
                keyset_id=root.keyset.keyset_id,
                tenant_id=tenant.pk,
                pause_id=uuid4(),
                operator_ref="integration",
            )
            snapshot = begin_inventory(
                pause_id=paused.pk,
                snapshot_id=uuid4(),
                tenant_id=tenant.pk,
                legacy_roles={},
                operator_ref="integration",
            )
        command = g.w.command({"kind": "Freeze"}, g.w.query()["root"]["revision"])
        assert g.w.request("command", command)[0] == 200

        def observe(purpose, ordinal=None):
            request = request_query(
                snapshot_id=snapshot.pk,
                tenant_id=tenant.pk,
                purpose=purpose,
                ordinal=ordinal,
                operator_ref="integration",
            )
            assert not connection.in_atomic_block
            code, response = g.w.request(
                "query",
                sign(g.w.custody, "WITNESS_QUERY_V1", request["query"]),
                identity=g.w.courier,
            )
            assert code == 200, (code, response)
            return accept_query(
                challenge=request["query"]["challenge"],
                tenant_id=tenant.pk,
                evidence=response,
                operator_ref="integration",
            )

        observe("ROOT")
        for index in range(count):
            observe("ENTRY", index)
        observe("SEAL")
        entries, start = [], 0
        while start < count:
            result = export_slice(snapshot_id=snapshot.pk, tenant_id=tenant.pk, start_index=start)
            entries.extend(result["entries"])
            start = result["next_index"]
        active = [e for e in entries if e["membership"].get("publication") == "ACTIVE"]
        assert any(e["claim"]["asset"]["kind"] == "Native" for e in active)
        assert any(e["claim"]["asset"]["kind"] == "ClassicToken" for e in active)
        assert ledger_count == LedgerTransaction.objects.count()
        assert (
            list(
                MpcSolanaClaim.objects.filter(root=root)
                .order_by("index")
                .values_list("pk", "status", "evidence")
            )
            == originals
        )
        assert all(hashlib.sha256(p.read_bytes()).hexdigest() == h for p, h in ciphertexts.items())
        private_file(
            root_path / "solana-repaired-active-inventory-public-evidence.json",
            json.dumps(
                {
                    "scope": (
                        "actual repaired native/SPL provenance plus frozen backend inventory"
                    ),
                    "allocated_claims": count,
                    "active_native_and_classic_sources": True,
                    "original_claim_status_receipts_shares_and_ledger_unchanged": True,
                    "original_claim_and_publication_proofs_reverified": True,
                    "movement_or_retirement_acceptance": False,
                },
                sort_keys=True,
            ).encode(),
        )

    run_current_claim_financial(root_path, after_flow=collect)
