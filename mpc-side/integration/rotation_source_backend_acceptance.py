"""Actual PG reservations, independent cohorts, source receipts and Rust W.

Only the target's ACTIVE treasury status is a C/P declaration. This acceptance
does not publish the readonly sources, adopt liabilities or authorize movement.
"""

import hashlib
import json
import time
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from custody.models import (
    AdminActionLog,
    LedgerTransaction,
    MpcSolanaClaim,
    MpcSolanaFinancialWallet,
    MpcSolanaIssuance,
    MpcSolanaRotationSourceQuery,
)
from custody.mpc_binding import MpcBindingError
from custody.solana_rotation_sources import (
    accept_source_query,
    request_source_query,
    source_control_archive,
)
from django.db import close_old_connections, connection
from django.test import override_settings
from environment import private_file
from refresh_acceptance import activate, freeze, plan, run_rounds
from rotation_backend_inventory_acceptance import run_backend_inventory
from rotation_claim_acceptance import authorize, collect
from rotation_inventory_acceptance import approved, business, command, enable, query, registered
from seeded_enrollment import approval, call, enroll_all, fresh_root, services
from test_dkg import PARTIES
from witness_acceptance import fingerprint, key_id, sign, verify


def run_backend_source_control(root_path, *, refreshed=False, count=33):
    def refresh(g):
        freeze(g)
        value = plan(g)
        activate(g, value, run_rounds(g, value))
        assert g.w.query()["root"]["generation"]["epoch"] == 1

    def exercise(g, root_path, tenant, snapshot, entries):
        with (
            services(root_path / "target-public-cohort") as target_net,
            override_settings(MPC_SOLANA_LIFECYCLE_CERTIFICATE=str(g.w.life / "tls.crt")),
        ):
            target, _ = fresh_root(target_net)
            source = g.w.root
            target["ownership_scope"] = source["ownership_scope"]
            target["genesis_hash"] = source["genesis_hash"]
            target_nodes = {p: target_net.root / p / "identity" for p in PARTIES}
            g.w.stop()
            for name in ("node_certificates", "receipt_certificates"):
                for party in PARTIES:
                    g.w.config["profiles"]["HOT"][name][party].append(
                        str(target_nodes[party] / "tls.crt")
                    )
            g.w.start()
            command(
                g.w,
                target,
                dict(
                    kind="Enroll",
                    evidence=dict(
                        statement=target, participant_agreement=enroll_all(target_net, target)
                    ),
                    node_keys={p: key_id(d) for p, d in target_nodes.items()},
                ),
            )
            enable(g.w, target)
            treasury, _ = registered(g.w, target_net, target, financial=True)
            treasury["role"] = "TENANT_TREASURY"
            treasury["membership"]["publication"] = "ACTIVE"
            source_view, target_view = query(g.w, source)["root"], query(g.w, target)["root"]
            value = dict(
                version=1,
                rotation_id=str(uuid4()),
                authorization_id=str(uuid4()),
                witness_anchor=g.w.config["anchor_id"],
                source=source,
                source_generation=source_view["generation"],
                source_node_keys=source_view["node_keys"],
                target=target,
                target_generation=target_view["generation"],
                target_node_keys=target_view["node_keys"],
                allocated_high_water=count,
                inventory_fingerprint=snapshot.inventory_fingerprint,
                destinations=[dict(treasury=treasury)],
                max_fee_per_movement_lamports=20000,
                total_fee_budget_lamports=100000,
                retained_root_gas_lamports=1000000,
                retained_classic_rent_lamports=0,
                expires_at=int(time.time()) + 120,
            )
            approvals = approved(g.w, value, "WITNESS_SOLANA_ROTATION_PLAN_V1")
            for start in range(0, count, 32):
                command(
                    g.w,
                    source,
                    dict(
                        kind="StageRotationInventory",
                        approvals=approvals,
                        chunk=dict(
                            business_fingerprint=business(value),
                            start_index=start,
                            entries=entries[start : start + 32],
                        ),
                    ),
                )
            assert g.w.query()["root"]["rotation"]["status"] == "Sealed"
            original_claims = list(
                MpcSolanaClaim.objects.filter(root_id=snapshot.pause.root_id)
                .order_by("index")
                .values_list("pk", "status", "evidence")
            )
            immutable = {
                str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in g.net.root.rglob("*.share.enc")
            }
            original_membership = list(
                MpcSolanaFinancialWallet.objects.values_list("pk", "status", "evidence")
            )
            original_issuance = list(
                MpcSolanaIssuance.objects.values_list("pk", "status", "evidence")
            )
            ledger_count = LedgerTransaction.objects.count()

            def own_query(index):
                with override_settings(MPC_SOLANA_ROTATION_INVENTORY_ENABLED=True):
                    request = request_source_query(
                        snapshot_id=snapshot.pk,
                        tenant_id=tenant.pk,
                        ordinal=index,
                        rotation_id=value["rotation_id"],
                        operator_ref="integration",
                    )
                assert not connection.in_atomic_block
                assert MpcSolanaRotationSourceQuery.objects.filter(
                    pk=request["query"]["challenge"], status="PENDING"
                ).exists()
                code, reply = g.w.request(
                    "query",
                    sign(g.w.custody, "WITNESS_QUERY_V1", request["query"]),
                    identity=g.w.courier,
                )
                assert code == 200, reply
                assert (
                    verify(g.w.identity, "WITNESS_QUERY_REPLY_V1", reply)["query"]
                    == request["query"]
                )
                return request, reply

            archives = []
            for index in (0, 1, 2):
                if index:
                    candidate = entries[index]["claim"]
                    if refreshed:
                        from current_claim_acceptance import current_approval

                        authority = current_approval(g, candidate)["authority"]
                        body = authorize(g, candidate, authority, approvals)
                        reports = collect(g, body)
                        evidence = dict(
                            statement=candidate, authority=authority, participant_agreement=reports
                        )
                    else:
                        reports = []
                        for party in PARTIES:
                            code, report = call(
                                g.net, party, "approve", approval(g.net, "claim", candidate)
                            )
                            assert code == 200, report
                            reports.append(report)
                        evidence = dict(statement=candidate, participant_agreement=reports)
                    command(
                        g.w,
                        source,
                        dict(kind="RegisterRotationClaim", approvals=approvals, evidence=evidence),
                    )
                request, reply = own_query(index)
                if index == 1:
                    # Lose the first backend acceptance through an audit failure;
                    # public W registration and durable original nonce survive.
                    with patch(
                        "custody.solana_rotation_sources._audit",
                        side_effect=RuntimeError("injected audit failure"),
                    ):
                        with pytest.raises(RuntimeError):
                            accept_source_query(
                                challenge=request["query"]["challenge"],
                                tenant_id=tenant.pk,
                                evidence=reply,
                                operator_ref="integration",
                            )
                    assert (
                        MpcSolanaRotationSourceQuery.objects.get(
                            pk=request["query"]["challenge"]
                        ).status
                        == "PENDING"
                    )
                    unresolved_challenge = request["query"]["challenge"]
                    close_old_connections()
                    g.w.stop()
                    g.w.start(startup_timeout=60)
                    # Replay readiness is separate from an authorization lease.
                    # Recover through a new public-only own nonce; preserve the
                    # original unknown row and registration/entry/rotation IDs.
                    request, reply = own_query(index)
                    assert request["query"]["challenge"] != unresolved_challenge
                    assert (
                        MpcSolanaRotationSourceQuery.objects.get(pk=unresolved_challenge).status
                        == "PENDING"
                    )
                accepted = accept_source_query(
                    challenge=request["query"]["challenge"],
                    tenant_id=tenant.pk,
                    evidence=reply,
                    operator_ref="integration",
                )
                if index:
                    assert accepted.evidence["value"]["rotation_claim_registration"][
                        "source_fingerprint"
                    ] == fingerprint("SOLANA_ROTATION_SOURCE_V1", entries[index])
                assert (
                    accept_source_query(
                        challenge=accepted.pk,
                        tenant_id=tenant.pk,
                        evidence=reply,
                        operator_ref="integration",
                    ).pk
                    == accepted.pk
                )
                archives.append(accepted.pk)

            # A stored proof remains historical after real W abandonment/restart.
            command(
                g.w, source, dict(kind="AbandonRotationInventory", rotation_id=value["rotation_id"])
            )
            g.w.stop()
            g.w.start(startup_timeout=60)
            for challenge in archives:
                archive = source_control_archive(challenge=challenge, tenant_id=tenant.pk)
                assert (
                    archive["original_source"]
                    == entries[archive["registered_evidence"]["statement"]["index"]]
                )
            request, reply = own_query(1)
            with pytest.raises(MpcBindingError):
                accept_source_query(
                    challenge=request["query"]["challenge"],
                    tenant_id=tenant.pk,
                    evidence=reply,
                    operator_ref="integration",
                )
            assert (
                list(
                    MpcSolanaClaim.objects.filter(root_id=snapshot.pause.root_id)
                    .order_by("index")
                    .values_list("pk", "status", "evidence")
                )
                == original_claims
            )
            assert (
                list(MpcSolanaFinancialWallet.objects.values_list("pk", "status", "evidence"))
                == original_membership
            )
            assert (
                list(MpcSolanaIssuance.objects.values_list("pk", "status", "evidence"))
                == original_issuance
            )
            assert LedgerTransaction.objects.count() == ledger_count
            assert all(
                hashlib.sha256(Path(p).read_bytes()).hexdigest() == h for p, h in immutable.items()
            )
            assert (
                AdminActionLog.objects.filter(action_type="SOLANA_ROTATION_SOURCE_ACCEPT").count()
                == 3
            )
            private_file(
                root_path / "solana-backend-source-control-public-evidence.json",
                json.dumps(
                    dict(
                        scope=(
                            "actual PG reservations and Gen0/Gen1 receipts; readonly source control"
                        ),
                        allocated_claims=count,
                        source_generation=int(refreshed),
                        accepted_source_proofs=3,
                        newly_registered_unpublished_sources=2,
                        target_active_is_policy_declaration=True,
                        original_claim_membership_shares_and_ledger_unchanged=True,
                        own_durable_nonce_audit_rollback_and_witness_restart=True,
                        archival_read_survives_abandonment_but_new_acceptance_fails=True,
                        private_movement_retirement_or_financial_publication=False,
                    ),
                    sort_keys=True,
                ).encode(),
            )

    run_backend_inventory(
        root_path,
        count=count,
        before_inventory=refresh if refreshed else None,
        after_inventory=exercise,
    )
