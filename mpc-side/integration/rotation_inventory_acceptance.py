"""Genuine two-cohort W manifest admission, with no fund movement or DB membership.

Only index0 has actual all-party receipts; the remainder are explicitly declared
unpublished allocation fixtures. A target ACTIVE membership is an independent
Custody/Policy declaration here, not a backend financial-wallet acceptance.
"""

import copy
import hashlib
import json
import time
import uuid
from contextlib import contextmanager

from custody.mpc_request_auth import _canonical
from environment import private_file
from profile_migration_acceptance import chain
from seeded_enrollment import approval, call, claim, enroll_all, fresh_root, services
from test_dkg import PARTIES, encrypted_files
from witness_acceptance import Witness, fingerprint, key_id, sign, verify


@contextmanager
def root_context(w, root):
    original = w.root
    w.root = root
    try:
        yield
    finally:
        w.root = original


def query(w, root, claim_id=None):
    with root_context(w, root):
        return w.query(claim_id=claim_id)


def command(w, root, action, *, expected=200):
    with root_context(w, root):
        body = w.command(action, 0 if action["kind"] == "Enroll" else w.query()["root"]["revision"])
    code, response = w.request("command", body)
    assert code == expected, (code, response)
    if code == 200:
        verify(w.identity, "WITNESS_ACK_V1", response)
    return body


def approved(w, value, domain):
    return {
        "custody": sign(w.custody, domain, value),
        "policy": sign(w.policy, domain, value),
        "custody_certificate_chain_der_hex": chain(w.custody),
        "policy_certificate_chain_der_hex": chain(w.policy),
    }


def enable(w, root):
    view = query(w, root)["root"]
    value = {
        "version": 1,
        "activation_id": str(uuid.uuid4()),
        "witness_anchor": w.config["anchor_id"],
        "root": root,
        "generation": view["generation"],
        "node_keys": view["node_keys"],
        "expires_at": int(time.time()) + 120,
    }
    command(
        w,
        root,
        {
            "kind": "EnableFinancialMode",
            "approvals": approved(w, value, "WITNESS_SOLANA_FINANCIAL_MODE_V1"),
        },
    )


def registered(w, net, root, *, financial):
    c = claim(root, owner=f"p1:{uuid.uuid4()}")
    reports = []
    for party in PARTIES:
        code, report = call(net, party, "approve", approval(net, "claim", c))
        assert code == 200
        reports.append(report)
    with root_context(w, root):
        w.register_claim(c, reports)
    command(
        w,
        root,
        {
            "kind": "IssueNativeClaim",
            "reservation_id": c["reservation_id"],
            "issuance_id": str(uuid.uuid4()),
        },
    )
    view = query(w, root, c["reservation_id"])
    membership = (
        {"kind": "Financial", "publication": "PENDING", "issuance": view["claim_issuance"]}
        if financial
        else {"kind": "LegacyControl", "issuance": view["claim_issuance"]}
    )
    return {
        "claim": c,
        "asset_key": "SOL",
        "role": "CUSTOMER_DEPOSIT",
        "membership": membership,
        "witness_evidence_fingerprint": fingerprint(
            "SOLANA_ROTATION_CLAIM_EVIDENCE_V1", view["claim"]
        ),
    }, reports


def business(plan):
    return fingerprint(
        "SOLANA_ROTATION_BUSINESS_V1",
        [
            plan[k]
            for k in (
                "version",
                "rotation_id",
                "witness_anchor",
                "source",
                "target",
                "allocated_high_water",
                "inventory_fingerprint",
                "destinations",
                "max_fee_per_movement_lamports",
                "total_fee_budget_lamports",
                "retained_root_gas_lamports",
                "retained_classic_rent_lamports",
            )
        ],
    )


def run_rotation_inventory(root_path, *, financial=False, count=33):
    with services(root_path / "cohort-A") as a, services(root_path / "cohort-B") as b:
        source, _ = fresh_root(a)
        target, _ = fresh_root(b)
        source["ownership_scope"] = target["ownership_scope"] = str(uuid.uuid4())
        assert source["group_public_key"] != target["group_public_key"]
        before_shares = [
            encrypted_files(net, root["dkg"]) for net, root in ((a, source), (b, target))
        ]
        wrapping_paths = [net.root / p / "identity/wrapping.key" for net in (a, b) for p in PARTIES]
        wrapping_before = [p.read_bytes() for p in wrapping_paths]
        assert len(set(wrapping_before)) == 6
        w = Witness(a, source)
        profile = w.config["profiles"]["HOT"]
        b_nodes = {p: b.root / p / "identity" for p in PARTIES}
        for name in ("node_certificates", "receipt_certificates"):
            for party in PARTIES:
                profile[name][party].append(str(b_nodes[party] / "tls.crt"))
        assert set(key_id(p) for p in w.node.values()).isdisjoint(
            key_id(p) for p in b_nodes.values()
        )
        try:
            w.start(initialize=True)
            w.enroll(enroll_all(a, source))
            command(
                w,
                target,
                {
                    "kind": "Enroll",
                    "evidence": {
                        "statement": target,
                        "participant_agreement": enroll_all(b, target),
                    },
                    "node_keys": {p: key_id(d) for p, d in b_nodes.items()},
                },
            )
            if financial:
                enable(w, source)
            enable(w, target)
            first, reports = registered(w, a, source, financial=financial)
            treasury, _ = registered(w, b, target, financial=True)
            treasury["role"] = "TENANT_TREASURY"
            treasury["membership"]["publication"] = "ACTIVE"
            entries = [first] + [
                {
                    "claim": claim(source, index=i, owner=f"p1:{uuid.uuid4()}"),
                    "asset_key": "SOL",
                    "role": "CUSTOMER_DEPOSIT",
                    "membership": {"kind": "Unpublished"},
                }
                for i in range(1, count)
            ]
            a_view, b_view = query(w, source)["root"], query(w, target)["root"]
            plan = {
                "version": 1,
                "rotation_id": str(uuid.uuid4()),
                "authorization_id": str(uuid.uuid4()),
                "witness_anchor": w.config["anchor_id"],
                "source": source,
                "source_generation": a_view["generation"],
                "source_node_keys": a_view["node_keys"],
                "target": target,
                "target_generation": b_view["generation"],
                "target_node_keys": b_view["node_keys"],
                "allocated_high_water": count,
                "inventory_fingerprint": fingerprint(
                    "SOLANA_ROTATION_INVENTORY_V1",
                    [fingerprint("SOLANA_SEEDED_ROOT_V1", source), count, entries],
                ),
                "destinations": [{"treasury": treasury}],
                "max_fee_per_movement_lamports": 20000,
                "total_fee_budget_lamports": 100000,
                "retained_root_gas_lamports": 1000000,
                "retained_classic_rent_lamports": 0,
                "expires_at": int(time.time()) + 120,
            }
            domain = "WITNESS_SOLANA_ROTATION_PLAN_V1"
            approvals = approved(w, plan, domain)

            def action(start, chunk, proofs=None):
                proofs = approvals if proofs is None else proofs
                return {
                    "kind": "StageRotationInventory",
                    "approvals": proofs,
                    "chunk": {
                        "business_fingerprint": business(plan),
                        "start_index": start,
                        "entries": chunk,
                    },
                }

            command(w, source, action(0, entries[:32]), expected=409)  # Source still Active.
            command(w, source, {"kind": "Freeze"})
            for role in ("custody", "policy"):
                wrong = copy.deepcopy(approvals)
                wrong[role]["signature"] = "00" * 70
                command(w, source, action(0, entries[:32], wrong), expected=409)
            wrong = copy.deepcopy(approvals)
            wrong["custody"] = sign(w.policy, domain, plan)
            command(w, source, action(0, entries[:32], wrong), expected=409)
            wrong = copy.deepcopy(approvals)
            wrong["custody"] = sign(w.custody, "WITNESS_SOLANA_FINANCIAL_MODE_V1", plan)
            command(w, source, action(0, entries[:32], wrong), expected=409)
            with root_context(w, source):
                body = w.command(action(0, entries[:32]), w.query()["root"]["revision"])
            assert (
                w.request("command", sign(w.custody, "WITNESS_COMMAND_V1", body["value"]))[0] == 409
            )
            assert query(w, source)["root"].get("rotation") is None
            head_path = w.directory / "journal/initialized.json"
            old_head = head_path.read_bytes()
            if not financial:
                # Fail head publication AFTER the immutable staging event. No
                # acknowledgement escapes; the live writer remains poisoned.
                with root_context(w, source):
                    first_command = w.command(
                        action(0, entries[:32]), w.query()["root"]["revision"]
                    )
                head_backup = head_path.with_name("fault-head-backup")
                head_path.rename(head_backup)
                head_path.mkdir()
                try:
                    assert w.request("command", first_command)[0] == 409
                    assert w.request("command", first_command)[0] == 409
                finally:
                    w.stop()
                    head_path.rmdir()
                    head_backup.rename(head_path)
                w.start(startup_timeout=60)
            else:
                first_command = command(w, source, action(0, entries[:32]))
            saved = query(w, source)["root"]
            assert (
                saved["rotation"]["next_index"] == 32
                and saved["rotation"]["status"] == "Collecting"
            )
            w.stop()
            # A durable event may outlive head publication. Recovery must replay
            # it rather than treating the unacknowledged chunk as nonexistent.
            private_file(head_path, old_head)
            w.start(startup_timeout=60)
            assert query(w, source)["root"] == saved
            assert w.request("command", first_command)[0] == 200
            # All three B nodes can authentically approve a competing alias;
            # A's original staged allocation must still win in external W.
            foreign = dict(entries[1]["claim"], root=target)
            foreign_reports = []
            for party in PARTIES:
                code, report = call(b, party, "approve", approval(b, "claim", foreign))
                assert code == 200
                foreign_reports.append(report)
            foreign_action = {
                "kind": "RegisterClaim",
                "evidence": {"statement": foreign, "participant_agreement": foreign_reports},
            }
            command(w, target, foreign_action, expected=409)
            candidate_query = {
                "anchor_id": w.config["anchor_id"],
                "root_identity": fingerprint("SOLANA_SEEDED_ROOT_V1", source),
                "challenge": hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
                "execution_id": None,
                "claim_reservation_id": entries[1]["claim"]["reservation_id"],
                "candidate_claim": entries[1]["claim"],
            }
            code, proof = w.request("query", sign(w.life, "WITNESS_QUERY_V1", candidate_query))
            assert code == 200
            availability = verify(w.identity, "WITNESS_QUERY_REPLY_V1", proof)["claim_availability"]
            assert availability == {
                "reservation_id": entries[1]["claim"]["reservation_id"],
                "index": None,
                "owner": None,
                "retry": None,
            }
            candidate_query["candidate_claim"] = dict(
                entries[1]["claim"], owner_ref=f"p1:{uuid.uuid4()}"
            )
            # Life's partial proposals are not authenticated owner bindings.
            assert w.request("query", sign(w.life, "WITNESS_QUERY_V1", candidate_query))[0] == 200
            command(w, source, {"kind": "Activate"}, expected=409)
            command(
                w,
                source,
                {"kind": "AbandonRefresh", "ceremony_id": str(uuid.uuid4())},
                expected=409,
            )
            # Recover the original committed data after abandoning a partial
            # upload. Chunks missing at W must match the original C/P full hash.
            old_plan = copy.deepcopy(plan)
            command(
                w, source, {"kind": "AbandonRotationInventory", "rotation_id": plan["rotation_id"]}
            )
            recovery_id = str(uuid.uuid4())

            def recovery_view(root=source):
                request = {
                    "anchor_id": w.config["anchor_id"],
                    "root_identity": fingerprint("SOLANA_SEEDED_ROOT_V1", root),
                    "challenge": hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
                    "execution_id": None,
                    "materialization_id": recovery_id,
                }
                code, result = w.request("query", sign(w.life, "WITNESS_QUERY_V1", request))
                assert code == 200, (code, result)
                reply = verify(w.identity, "WITNESS_QUERY_REPLY_V1", result)
                assert reply["query"] == request
                return reply.get("inventory_materialization")

            assert recovery_view() is None
            for start in range(0, count, 32):
                original_chunk = entries[start : start + 32]
                recovery_action = {
                    "kind": "MaterializeRotationInventory",
                    "rotation_id": old_plan["rotation_id"],
                    "materialization_id": recovery_id,
                    "chunk": {
                        "business_fingerprint": business(old_plan),
                        "start_index": start,
                        "entries": original_chunk,
                    },
                }
                if start == 0:
                    with root_context(w, source):
                        no_life = w.command(recovery_action, w.query()["root"]["revision"])
                    assert (
                        w.request(
                            "command", sign(w.custody, "WITNESS_COMMAND_V1", no_life["value"])
                        )[0]
                        == 409
                    )
                if start + len(original_chunk) == count:
                    before_recovery = recovery_view()
                    altered = copy.deepcopy(recovery_action)
                    altered["chunk"]["entries"][-1]["claim"]["owner_ref"] = f"p1:{uuid.uuid4()}"
                    command(w, source, altered, expected=409)
                    assert recovery_view() == before_recovery
                accepted = command(w, source, recovery_action)
                if start == 0:
                    progress = recovery_view()
                    assert progress["status"] == "Collecting" and progress["next_index"] == 32
                    w.stop()
                    w.start(startup_timeout=60)
                    assert recovery_view() == progress
                    assert w.request("command", accepted)[0] == 200
            recovered = recovery_view()
            assert recovered["status"] == "Verified" and recovered["next_index"] == count
            assert recovered["inventory_fingerprint"] == old_plan["inventory_fingerprint"]
            assert "conflict" not in recovered
            if financial:
                entries[0]["membership"]["publication"] = "ACTIVE"
            plan = dict(
                plan,
                rotation_id=str(uuid.uuid4()),
                authorization_id=str(uuid.uuid4()),
                inventory_fingerprint=fingerprint(
                    "SOLANA_ROTATION_INVENTORY_V1",
                    [fingerprint("SOLANA_SEEDED_ROOT_V1", source), count, entries],
                ),
                expires_at=int(time.time()) + 120,
            )
            approvals = approved(w, plan, domain)
            command(w, source, action(0, entries[:32]))
            for start in range(32, count, 32):
                command(w, source, action(start, entries[start : start + 32]))
            sealed = query(w, source)["root"]
            assert (
                sealed["rotation"]["next_index"] == count
                and sealed["rotation"]["status"] == "Sealed"
            )
            binding = w.binding(first["claim"], reports)
            if financial:
                i = binding["authorized"]["intent"]
                i["financial"] = {
                    "version": 1,
                    "reservation_id": str(uuid.uuid4()),
                    "tenant_id": source["ownership_scope"],
                    "reservation_owner_ref": first["claim"]["owner_ref"],
                    "source_owner_ref": first["claim"]["owner_ref"],
                    "source_role": "CUSTOMER_DEPOSIT",
                    "operation_type": "SWEEP",
                    "operation_id": i["operation_id"],
                    "approval_id": str(uuid.uuid4()),
                    "asset_key": "SOL",
                }
                binding = w.authorize(binding["authorized"])
            assert w.request("permit", w.permit(binding), identity=w.courier)[0] == 409
            # Renewal is a fresh signed context for the SAME immutable business.
            renewed_plan = dict(
                plan, authorization_id=str(uuid.uuid4()), expires_at=int(time.time()) + 120
            )
            renewed = approved(w, renewed_plan, domain)
            command(w, source, {"kind": "BeginRotation", "approvals": renewed})
            assert query(w, source)["root"]["phase"] == "Migrating"
            w.stop()
            w.start(startup_timeout=60)
            assert query(w, source)["root"]["rotation"]["status"] == "Migrating"
            command(
                w, source, {"kind": "AbandonRotationInventory", "rotation_id": plan["rotation_id"]}
            )
            assert query(w, source)["root"]["phase"] == "Frozen"
            command(w, source, action(0, entries[:32]), expected=409)
            reduced = dict(
                plan,
                rotation_id=str(uuid.uuid4()),
                authorization_id=str(uuid.uuid4()),
                allocated_high_water=1,
                expires_at=int(time.time()) + 120,
                inventory_fingerprint=fingerprint(
                    "SOLANA_ROTATION_INVENTORY_V1",
                    [fingerprint("SOLANA_SEEDED_ROOT_V1", source), 1, entries[:1]],
                ),
            )
            command(
                w,
                source,
                {
                    "kind": "StageRotationInventory",
                    "approvals": approved(w, reduced, domain),
                    "chunk": {
                        "business_fingerprint": business(reduced),
                        "start_index": 0,
                        "entries": entries[:1],
                    },
                },
                expected=409,
            )
            # An authenticated current event cannot downgrade the journal even
            # when the signed head/hash chain is coherently recomputed.
            w.stop()
            last_path = sorted((w.directory / "journal/events").glob("*.json"))[-1]
            event_original, head_original = last_path.read_bytes(), head_path.read_bytes()
            altered = json.loads(event_original)["value"]
            altered["rules"] = 3
            signed_event = sign(w.identity, "WITNESS_EVENT_V1", altered)
            private_file(last_path, json.dumps(signed_event).encode())
            head = json.loads(head_original)["value"]
            head["event_hash"] = hashlib.sha256(_canonical(signed_event)).hexdigest()
            private_file(head_path, json.dumps(sign(w.identity, "WITNESS_HEAD_V1", head)).encode())
            w.rejected_start(startup_timeout=60)
            assert "cannot downgrade" in (w.directory / "service.log").read_text()
            private_file(last_path, event_original)
            private_file(head_path, head_original)
            replay_started = time.monotonic()
            w.start(startup_timeout=60)
            replay_seconds = time.monotonic() - replay_started
            assert query(w, source)["root"]["phase"] == "Frozen"
            command(w, target, foreign_action, expected=409)
            assert query(w, source)["root"]["next_claim_index"] == 1
            assert query(w, source, entries[1]["claim"]["reservation_id"])["claim"] is None
            events = [
                json.loads(p.read_text())["value"]
                for p in sorted((w.directory / "journal/events").glob("*.json"))
            ]
            assert all(e["rules"] == 7 for e in events)
            assert all(e["transition"]["kind"] != "Permit" for e in events)
            assert [
                encrypted_files(net, root["dkg"]) for net, root in ((a, source), (b, target))
            ] == before_shares
            assert [p.read_bytes() for p in wrapping_paths] == wrapping_before
            private_file(
                root_path / "solana-rotation-inventory-public-evidence.json",
                json.dumps(
                    {
                        "scope": "W manifest only; no chain movement or DB membership acceptance",
                        "source_financial_mode": financial,
                        "manifest_entries": count,
                        "actual_registered_source_claims": 1,
                        "actual_two_frost_cohorts": True,
                        "independent_three_authorities_verified": True,
                        "restart_and_exact_retry_and_sticky_source_pause": True,
                        "original_mode_off_issuance_preserved": not financial,
                        "signed_events": len(events),
                        "final_replay_seconds": replay_seconds,
                        "startup_wait_seconds": 60,
                        "authenticated_rules_downgrade_rejected": True,
                        "foreign_three_node_receipts_rejected_after_restart_abandonment": True,
                        "retained_allocation_frontier_cannot_shrink_after_abandonment": True,
                        "partial_original_commitment_materialized_before_new_plan": True,
                        "materialization_restart_and_exact_retry": True,
                        "materialization_wrong_whole_hash_rollback": True,
                        "pending_to_active_metadata_evolution_is_declaration_only": financial,
                        "partial_life_proposal_does_not_bind_owner": True,
                        "staged_candidate_has_no_registered_evidence_or_issuance": True,
                        "head_write_failure_poisoned_then_recovered": not financial,
                        "private_permits": 0,
                        "six_original_encrypted_shares_unchanged": True,
                        "six_distinct_wrapping_keys_unchanged": True,
                        "public_manifest_sha256": hashlib.sha256(_canonical(entries)).hexdigest(),
                    },
                    sort_keys=True,
                ).encode(),
            )
        finally:
            w.stop()
