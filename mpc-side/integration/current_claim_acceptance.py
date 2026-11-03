"""Genuine current-identity receipts and FROST spends; no financial activation."""

import copy
import hashlib
import json
import shutil
import time
from pathlib import Path
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from custody.mpc_request_auth import _authorize_message, _canonical
from environment import private_file
from protected_acceptance import balance, group
from refresh_acceptance import activate, freeze, plan, run_rounds
from seeded_enrollment import approval, call, claim
from test_dkg import PARTIES, request
from witness_acceptance import verify

PREFIX = "/internal/v1/solana/current-claim/"


def legacy_pending(g):
    candidate = claim(g.w.root, index=1, owner=f"p1:{uuid4()}")
    reports = []
    for party in PARTIES:
        code, report = call(g.net, party, "approve", approval(g.net, "claim", candidate))
        assert code == 200, (party, report)
        reports.append(report)
    if g.custody_class != "COLD":
        base = f"/v1/keysets/{g.w.root['dkg']['keyset_id']}"
        code, root = request(
            g.net,
            "coordinator",
            "custody",
            base + "/solana-seeded-root",
            approval(g.net, "root", g.w.root),
        )
        assert code == 200 and root["statement"] == g.w.root, root
        code, cached = request(
            g.net,
            "coordinator",
            "custody",
            base + "/solana-seeded-claims",
            approval(g.net, "claim", candidate),
        )
        assert code == 200 and cached["participant_agreement"] == reports, cached
    assert g.w.query(claim_id=candidate["reservation_id"])["claim"] is None
    return candidate, reports


def current_approval(g, candidate, *, authority=None):
    # Read-only initial discovery is not a signer freshness proof. Each node
    # subsequently commits its own challenge and checks the resulting W reply.
    from current_claim_authority_acceptance import candidate_query

    reply = candidate_query(g, candidate) if authority is None else None
    authority = authority or {
        "version": 1,
        "prepare": reply["generation_authority"],
        "node_certificates_der_hex": {
            party: x509.load_pem_x509_certificate((identity / "tls.crt").read_bytes())
            .public_bytes(serialization.Encoding.DER)
            .hex()
            for party, identity in g.w.node.items()
        },
    }
    now = int(time.time())
    body = dict(statement=candidate, authority=authority, issued_at=now, expires_at=now + 120)
    identity = g.net.root / "custody/identity"
    body["custody_authorization"] = _authorize_message(
        b"Wallet-MPC/CUSTODY_SOLANA_CURRENT_CLAIM_V1\0" + _canonical(body),
        identity / "tls.crt",
        identity / "tls.key",
    )
    return body


def invoke(g, party, action, payload):
    return request(
        g.net,
        party,
        "courier" if g.custody_class == "COLD" else "coordinator",
        PREFIX + action,
        payload,
    )


def approve_current(g, candidate):
    authorized = current_approval(g, candidate)
    collected = None
    if g.custody_class != "COLD":
        code, collected = request(
            g.net,
            "coordinator",
            "custody",
            f"/v1/keysets/{g.w.root['dkg']['keyset_id']}/solana-current-claims",
            authorized,
        )
        assert code == 200, collected
        assert collected["statement"] == candidate
        assert collected["authority"] == authorized["authority"]
    reports = []
    for party in PARTIES:
        proof = None
        if g.custody_class == "COLD":
            assert invoke(g, party, "approve", {"approval": authorized, "witness": None})[0] == 409
            code, query = invoke(g, party, "query", authorized)
            assert code == 200, (party, query)
            code, proof = g.w.request("query", query, identity=g.w.courier)
            assert code == 200, proof
        code, report = invoke(g, party, "approve", {"approval": authorized, "witness": proof})
        assert code == 200, (party, report)
        assert (
            report["statement"] == candidate and report["party_id"] == party and report["durable"]
        )
        cert = x509.load_pem_x509_certificate((g.w.node[party] / "tls.crt").read_bytes())
        message = b"Wallet-MPC/SIGNER_SOLANA_CURRENT_CLAIM_V1\0" + _canonical(
            dict(
                statement=candidate, authority=authorized["authority"], party_id=party, durable=True
            )
        )
        cert.public_key().verify(
            bytes.fromhex(report["signer_signature"]), message, ec.ECDSA(hashes.SHA256())
        )
        reports.append(report)
        assert invoke(g, party, "recover", authorized) == (200, report)
    if collected is not None:
        assert collected["participant_agreement"] == reports
    return authorized, reports


def register_current(g, candidate, authorized, reports):
    evidence = dict(
        statement=candidate, participant_agreement=reports, authority=authorized["authority"]
    )
    from custody.solana_claim_authority import verify_current_claim

    verify_current_claim(
        candidate,
        evidence,
        lifecycle_certificate=g.w.life / "tls.crt",
        witness_anchor_id=g.w.config["anchor_id"],
    )
    command = g.w.command(
        {"kind": "RegisterClaim", "evidence": evidence}, g.w.query()["root"]["revision"]
    )
    code, result = g.w.request("command", command)
    assert code == 200, result
    verify(g.w.identity, "WITNESS_ACK_V1", result)
    assert g.w.query(claim_id=candidate["reservation_id"])["claim"] == evidence
    return evidence


def exercise_current(g, candidate, legacy_reports, *, operation=19000):
    authorized, reports = approve_current(g, candidate)
    assert reports != legacy_reports
    evidence = register_current(g, candidate, authorized, reports)
    binding = g.binding(candidate, reports, operation)
    binding["authorized"]["claim_evidence"] = evidence
    source = binding["authorized"]["intent"]["financial_source"]
    g.validator.fund(source, 5000000)
    for party in PARTIES:
        g.net.stop(party)
        g.start(party)
        assert invoke(g, party, "recover", authorized) == (200, reports[PARTIES.index(party)])
    before = balance(g, source)
    g.broadcast(binding, g.sign(binding))
    assert balance(g, source) == before - 1000000
    # Current frontier cannot be used to mint a fresh original-roster receipt.
    fresh = claim(g.w.root, index=2, owner=f"p1:{uuid4()}")
    for party in PARTIES:
        assert call(g.net, party, "approve", approval(g.net, "claim", fresh))[0] in (404, 409)
    return authorized, reports, evidence


def run_current_claim(root_path, *, custody_class="HOT"):
    with group(root_path, custody_class, lifecycle=True) as (g, original, original_reports):
        candidate, legacy_reports = legacy_pending(g)
        archives = {
            path: hashlib.sha256(path.read_bytes()).hexdigest()
            for party in PARTIES
            for path in (g.net.root / party / "storage").rglob("*.share.enc")
        }
        freeze(g)
        refresh = plan(g)
        activate(g, refresh, run_rounds(g, refresh))
        authorized, reports, evidence = exercise_current(g, candidate, legacy_reports)
        # A registered Gen1 approval remains archival evidence during Gen2 use.
        freeze(g)
        refresh2 = plan(g)
        activate(g, refresh2, run_rounds(g, refresh2))
        for party in PARTIES:
            assert invoke(g, party, "recover", authorized) == (200, reports[PARTIES.index(party)])
        b = g.binding(candidate, reports, 19001)
        b["authorized"]["claim_evidence"] = evidence
        g.broadcast(b, g.sign(b))
        old = g.binding(original, original_reports, 19002)
        g.broadcast(old, g.sign(old))
        assert all(
            hashlib.sha256(path.read_bytes()).hexdigest() == digest
            for path, digest in archives.items()
        )
        private_file(
            root_path / "solana-current-claim-public-evidence.json",
            json.dumps(
                dict(
                    scope=(
                        "actual refresh/current receipts/W registration/FROST spends; "
                        "no financial publication"
                    ),
                    custody_class=custody_class,
                    legacy_unregistered_claim_reapproved_by_current_identities=True,
                    all_three_receipts_recovered_after_restart=True,
                    original_and_current_claims_spent_after_second_refresh=True,
                    original_dkg_ciphertexts_unchanged=True,
                ),
                sort_keys=True,
            ).encode(),
        )


def run_repaired_current_claim(root_path, *, custody_class="HOT"):
    from repair_acceptance import run_repair

    pending = []

    def before(g):
        pending.extend(legacy_pending(g))

    def after(g):
        candidate, legacy_reports = pending
        authorized, reports, _ = exercise_current(g, candidate, legacy_reports, operation=19100)
        assert reports[0]["signer_signature"] != legacy_reports[0]["signer_signature"]
        assert authorized["authority"]["node_certificates_der_hex"][PARTIES[0]] == (
            x509.load_pem_x509_certificate((g.w.node[PARTIES[0]] / "tls.crt").read_bytes())
            .public_bytes(serialization.Encoding.DER)
            .hex()
        )
        private_file(
            root_path / "solana-repaired-current-claim-public-evidence.json",
            json.dumps(
                dict(
                    scope=(
                        "actual replacement RTS/refresh/current receipt/W registration/FROST spend"
                    ),
                    custody_class=custody_class,
                    replacement_current_identity_used=True,
                    legacy_unregistered_claim_reapproved=True,
                    exact_reports_recovered_after_restart=True,
                    no_financial_publication_or_ledger_activation=True,
                ),
                sort_keys=True,
            ).encode(),
        )

    run_repair(
        root_path, custody_class=custody_class, before_maintenance=before, after_repair=after
    )


def run_current_claim_faults(root_path):
    with group(root_path, lifecycle=True) as (g, _, _):
        candidate, legacy_reports = legacy_pending(g)
        freeze(g)
        refresh = plan(g)
        activate(g, refresh, run_rounds(g, refresh))
        authorized = current_approval(g, candidate)
        party = PARTIES[0]
        storage = g.net.root / party / "storage"
        backup = root_path / "before-current-share-storage"
        shutil.copytree(storage, backup)
        control = dict(approval=authorized, witness=None)
        # No synthetic readiness or staged artifact can replace this node's
        # committed encrypted generation. Restore only our injected fixture move.
        store = g.net.root / party / "storage/solana-generations"
        (artifact,) = store.glob(f"*-{refresh['value']['ceremony_id']}.enc")
        moved = artifact.with_suffix(".fault-held")
        artifact.rename(moved)
        try:
            assert invoke(g, party, "approve", control)[0] == 409
            assert invoke(g, party, "recover", authorized) == (200, None)
        finally:
            moved.rename(artifact)
        artifact.rename(moved)
        artifact.symlink_to(moved)
        try:
            assert invoke(g, party, "approve", control)[0] == 409
        finally:
            artifact.unlink()
            moved.rename(artifact)
        forged = copy.deepcopy(control)
        forged["approval"]["custody_authorization"]["signature_der_hex"] = "00" * 70
        assert invoke(g, party, "approve", forged)[0] == 409
        for field, value in (("owner_ref", "different-owner"), ("index", 2)):
            other = copy.deepcopy(candidate)
            other[field] = value
            approval_other = current_approval(g, other)
            assert (
                invoke(g, party, "approve", dict(approval=approval_other, witness=None))[0] == 409
            )
        # The query is committed first. Occupy the exact next immutable report
        # event and ensure a signed receipt cannot escape a failed durable write.
        code, query = invoke(g, party, "query", authorized)
        assert code == 200, query
        code, proof = g.w.request("query", query, identity=g.w.courier)
        assert code == 200, proof
        events = g.net.root / party / "protected-anchor/events"
        prior = sorted(events.glob("*.json"))
        blocked = events / f"{len(prior):020}.json"
        blocked.mkdir()
        try:
            assert invoke(g, party, "approve", dict(approval=authorized, witness=proof))[0] == 409
            assert invoke(g, party, "recover", authorized)[0] == 409
        finally:
            blocked.rmdir()
        g.net.stop(party)
        g.start(party)
        assert invoke(g, party, "recover", authorized) == (200, None)
        authorized, reports = approve_current(g, candidate)
        assert reports != legacy_reports
        marker = storage / "solana-provisioning" / f"{g.w.root['dkg']['keyset_id']}.current"
        assert marker.is_file()
        marker.unlink()  # Fault only our isolated share-storage marker.
        legacy_next = claim(g.w.root, 2, f"p1:{uuid4()}")
        assert call(g.net, party, "approve", approval(g.net, "claim", legacy_next))[0] == 409
        assert invoke(g, party, "recover", authorized) == (200, reports[0])
        # Restore the entire original pre-current share directory, retaining the
        # independent external protected journal and immutable profile.
        g.net.stop(party)
        shutil.rmtree(storage)
        shutil.copytree(backup, storage)
        assert not marker.exists()
        g.start(party)
        assert marker.is_file()
        assert call(g.net, party, "approve", approval(g.net, "claim", legacy_next))[0] == 409
        assert invoke(g, party, "recover", authorized) == (200, reports[0])
        # A context can remain as immutable local history while registration
        # loses the maintenance race. New registration must use the new context.
        freeze(g)
        assert (
            invoke(
                g,
                PARTIES[1],
                "approve",
                dict(
                    approval=current_approval(g, claim(g.w.root, 2, f"p1:{uuid4()}")),
                    witness=None,
                ),
            )[0]
            == 409
        )
        second = plan(g)
        activate(g, second, run_rounds(g, second))
        stale = dict(
            statement=candidate, participant_agreement=reports, authority=authorized["authority"]
        )
        cmd = g.w.command(
            {"kind": "RegisterClaim", "evidence": stale}, g.w.query()["root"]["revision"]
        )
        assert g.w.request("command", cmd)[0] == 409
        # Still-live fresh Custody signatures do not make an old roster current.
        fresh_approval_old_context = current_approval(
            g, candidate, authority=authorized["authority"]
        )
        other = copy.deepcopy(candidate)
        other.update(
            index=2,
            reservation_id=str(uuid4()),
            owner_ref=f"p1:{uuid4()}",
            idempotency_key=str(uuid4()),
        )
        old_for_new = current_approval(g, other, authority=authorized["authority"])
        assert invoke(g, party, "approve", dict(approval=old_for_new, witness=None))[0] == 409
        assert invoke(g, party, "recover", fresh_approval_old_context) == (200, reports[0])
        next_approval, next_reports = approve_current(g, candidate)
        assert next_approval["authority"] != authorized["authority"]
        register_current(g, candidate, next_approval, next_reports)
        assert invoke(g, party, "recover", authorized) == (200, reports[0])
        private_file(
            root_path / "solana-current-claim-faults-public-evidence.json",
            json.dumps(
                dict(
                    scope="actual node/W public approval faults; no financial publication",
                    missing_and_symlink_generation_denied=True,
                    unauthorized_and_permanent_alias_reassignment_denied=True,
                    failed_report_write_released_no_receipt_and_recovered_after_restart=True,
                    frozen_and_stale_context_denied=True,
                    same_claim_new_context_registered_without_overwriting_old_receipts=True,
                    live_missing_frontier_marker_fails_closed=True,
                    share_only_restore_reconciles_frontier_from_external_journal=True,
                ),
                sort_keys=True,
            ).encode(),
        )


def run_historical_repair_upgrade(root_path):
    from current_claim_baseline import SOURCE_SHA, baseline_directory
    from repair_acceptance import profile_hash, run_repair

    pending = []

    def before(g):
        for party in PARTIES:
            assert invoke(g, party, "query", {})[0] == 404  # Actual old binary canary.
        pending.extend(legacy_pending(g))

    def after(g):
        assert g.w.query().get("node_profiles", {}) == {}
        events = Path(g.w.config["directory"]) / "events"
        original_events = {
            p: hashlib.sha256(p.read_bytes()).hexdigest() for p in events.glob("*.json")
        }
        original_commands = []
        for path in events.glob("*.json"):
            event = json.loads(path.read_text())["value"]
            assert event["rules"] == 2, "actual rules2 writer required before upgrade"
            transition = event["transition"]
            if transition["kind"] == "Command":
                command = transition["command"]["value"]
                if command["action"]["kind"] == "ReserveReplacement":
                    original_commands.append(command["request_id"])
        assert len(original_commands) == 1
        g.w.stop()
        for party in PARTIES:
            g.net.stop(party)
        g.net.stop("coordinator")
        g.net.bin = Path(__file__).resolve().parents[1] / "target/debug"
        g.net.start("coordinator")
        for party in PARTIES:
            g.start(party)
        g.w.start()
        candidate, legacy_reports = pending
        approval_before = current_approval(g, candidate)
        assert (
            invoke(g, PARTIES[0], "approve", dict(approval=approval_before, witness=None))[0] == 409
        )
        freeze(g)
        promotion = g.w.command(
            {"kind": "PinReplacementProfile", "replacement_command_id": original_commands[0]},
            g.w.query()["root"]["revision"],
        )
        code, ack = g.w.request("command", promotion)
        assert code == 200, ack
        verify(g.w.identity, "WITNESS_ACK_V1", ack)
        pin = g.w.query()["node_profiles"][PARTIES[0]]
        assert pin["profile_sha256"] == profile_hash(g.profiles[PARTIES[0]])
        g.w.stop()
        g.w.start()
        assert g.w.query()["node_profiles"][PARTIES[0]] == pin
        assert g.w.request("command", promotion)[0] == 200
        refresh = plan(g)
        activate(g, refresh, run_rounds(g, refresh))
        exercise_current(g, candidate, legacy_reports, operation=19200)
        assert all(
            hashlib.sha256(p.read_bytes()).hexdigest() == digest
            for p, digest in original_events.items()
        )
        private_file(
            root_path / "solana-current-claim-upgrade-public-evidence.json",
            json.dumps(
                dict(
                    scope=(
                        "genuine fixed rules2 repaired store upgraded with explicit "
                        "Life profile promotion"
                    ),
                    old_writer_source_sha=SOURCE_SHA,
                    original_signed_events_unchanged=True,
                    missing_recipient_pin_initially_denied=True,
                    exact_original_reservation_promoted_and_replayed_after_restart=True,
                    all_three_actual_refresh_then_new_current_claim_and_real_mpc_spend=True,
                ),
                sort_keys=True,
            ).encode(),
        )

    run_repair(
        root_path,
        before_maintenance=before,
        after_repair=after,
        binary_directory=baseline_directory(),
    )
