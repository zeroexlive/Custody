"""Actual Gen1 Frozen public receipts; no financial publication or private move."""

import copy
import hashlib
import json
import time
import uuid
from pathlib import Path
from threading import Event

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from current_claim_acceptance import current_approval, invoke, legacy_pending
from custody.mpc_request_auth import _authorize_message, _canonical
from environment import ca, issue, private_file
from profile_migration_acceptance import chain
from protected_acceptance import group
from refresh_acceptance import activate, freeze, plan, run_rounds
from rotation_inventory_acceptance import approved, business, command, enable, query, registered
from seeded_enrollment import claim, enroll_all, fresh_root, services
from test_dkg import PARTIES, dkg_request, execute, request
from witness_acceptance import fingerprint, key_id, sign, verify

DOMAIN = "WITNESS_SOLANA_ROTATION_PLAN_V1"


def authorize(g, candidate, authority, approvals, *, expires_at=None):
    now = int(time.time())
    body = {
        "statement": candidate,
        "authority": authority,
        "issued_at": now,
        "expires_at": expires_at or now + 120,
        "rotation": approvals,
    }
    identity = g.net.root / "custody/identity"
    body["custody_authorization"] = _authorize_message(
        b"Wallet-MPC/CUSTODY_SOLANA_ROTATION_CLAIM_V1\0" + _canonical(body),
        identity / "tls.crt",
        identity / "tls.key",
    )
    return body


def resign(g, body):
    identity = g.net.root / "custody/identity"
    value = {k: v for k, v in body.items() if k != "custody_authorization"}
    body["custody_authorization"] = _authorize_message(
        b"Wallet-MPC/CUSTODY_SOLANA_ROTATION_CLAIM_V1\0" + _canonical(value),
        identity / "tls.crt",
        identity / "tls.key",
    )
    return body


def own_proof(g, party, body):
    code, nonce = invoke(g, party, "query", body)
    assert code == 200, (party, nonce)
    code, proof = g.w.request("query", nonce, identity=g.w.courier)
    assert code == 200, proof
    verify(g.w.identity, "WITNESS_QUERY_REPLY_V1", proof)
    return nonce, proof


def check_reports(g, body, reports):
    for party, report in zip(PARTIES, reports, strict=True):
        assert report["statement"] == body["statement"] and report["party_id"] == party
        assert report["durable"]
        cert = x509.load_pem_x509_certificate((g.w.node[party] / "tls.crt").read_bytes())
        message = b"Wallet-MPC/SIGNER_SOLANA_CURRENT_CLAIM_V1\0" + _canonical(
            {
                "statement": body["statement"],
                "authority": body["authority"],
                "party_id": party,
                "durable": True,
            }
        )
        cert.public_key().verify(
            bytes.fromhex(report["signer_signature"]), message, ec.ECDSA(hashes.SHA256())
        )


def collect(g, body):
    if g.custody_class != "COLD":
        code, evidence = request(
            g.net,
            "coordinator",
            "custody",
            f"/v1/keysets/{g.w.root['dkg']['keyset_id']}/solana-current-claims",
            body,
        )
        assert code == 200, evidence
        assert (
            evidence["statement"] == body["statement"]
            and evidence["authority"] == body["authority"]
        )
        reports = evidence["participant_agreement"]
    else:
        reports = []
        for party in PARTIES:
            assert invoke(g, party, "approve", {"approval": body, "witness": None})[0] == 409
            _, proof = own_proof(g, party, body)
            code, report = invoke(g, party, "approve", {"approval": body, "witness": proof})
            assert code == 200, (party, report)
            reports.append(report)
    check_reports(g, body, reports)
    return reports


def anchors(g):
    return {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for profile in g.profiles.values()
        for path in Path(profile["anchor_directory"]).rglob("*")
        if path.is_file()
    }


def run_rotation_claim(root_path, *, custody_class):
    with (
        group(root_path / "source", custody_class, lifecycle=True) as (g, original, _),
        services(root_path / "target") as b,
    ):
        pending, _ = legacy_pending(g)
        freeze(g)
        refresh = plan(g)
        activate(g, refresh, run_rounds(g, refresh))
        assert g.w.query()["root"]["generation"]["epoch"] == 1
        source = g.w.root
        candidates = [pending] + [
            claim(source, index=i, owner=f"p1:{uuid.uuid4()}") for i in (2, 3)
        ]
        # Install independent target public identities as operator-owned test pins.
        if custody_class == "HOT":
            target, _ = fresh_root(b)
        else:
            binding = dict(dkg_request(), custody_class=custody_class)
            code, target_dkg = execute(b, binding)
            assert code == 200 and target_dkg["status"] == "COMPLETED", target_dkg
            target = {
                "dkg": binding,
                "group_public_key": target_dkg["group_public_key"],
                "public_key_package": target_dkg["participant_agreement"][0]["public_key_package"],
                "chain_id": "SOL",
                "purpose": "DEPOSIT",
                "derivation_version": "solana_seeded_v1",
                "generation": 0,
            }
        target.update(
            ownership_scope=source["ownership_scope"],
            genesis_hash=source["genesis_hash"],
            wallet_class=custody_class,
        )
        nodes = {p: b.root / p / "identity" for p in PARTIES}
        g.w.stop()
        profile = g.w.config["profiles"][custody_class]
        for name in ("node_certificates", "receipt_certificates"):
            for party in PARTIES:
                profile[name][party].append(str(nodes[party] / "tls.crt"))
        g.w.start(startup_timeout=60)
        command(
            g.w,
            target,
            {
                "kind": "Enroll",
                "evidence": {"statement": target, "participant_agreement": enroll_all(b, target)},
                "node_keys": {p: key_id(path) for p, path in nodes.items()},
            },
        )
        enable(g.w, target)
        treasury, _ = registered(g.w, b, target, financial=True)
        treasury["role"] = "TENANT_TREASURY"
        treasury["membership"]["publication"] = "ACTIVE"
        positive = g.w.query(claim_id=original["reservation_id"])
        entries = [
            {
                "claim": original,
                "asset_key": "SOL",
                "role": "CUSTOMER_DEPOSIT",
                "membership": {"kind": "Unpublished"},
                "witness_evidence_fingerprint": fingerprint(
                    "SOLANA_ROTATION_CLAIM_EVIDENCE_V1", positive["claim"]
                ),
            }
        ]
        entries += [
            {
                "claim": candidate,
                "asset_key": "SOL",
                "role": "CUSTOMER_DEPOSIT",
                "membership": {"kind": "Unpublished"},
            }
            for candidate in candidates
        ]
        command(g.w, source, {"kind": "Freeze"})
        src, dst = g.w.query()["root"], query(g.w, target)["root"]
        value = {
            "version": 1,
            "rotation_id": str(uuid.uuid4()),
            "authorization_id": str(uuid.uuid4()),
            "witness_anchor": g.w.config["anchor_id"],
            "source": source,
            "source_generation": src["generation"],
            "source_node_keys": src["node_keys"],
            "target": target,
            "target_generation": dst["generation"],
            "target_node_keys": dst["node_keys"],
            "allocated_high_water": 4,
            "inventory_fingerprint": fingerprint(
                "SOLANA_ROTATION_INVENTORY_V1",
                [fingerprint("SOLANA_SEEDED_ROOT_V1", source), 4, entries],
            ),
            "destinations": [{"treasury": treasury}],
            "max_fee_per_movement_lamports": 20000,
            "total_fee_budget_lamports": 100000,
            "retained_root_gas_lamports": 1000000,
            "retained_classic_rent_lamports": 0,
            "expires_at": int(time.time()) + 120,
        }
        approvals = approved(g.w, value, DOMAIN)
        command(
            g.w,
            source,
            {
                "kind": "StageRotationInventory",
                "approvals": approvals,
                "chunk": {
                    "business_fingerprint": business(value),
                    "start_index": 0,
                    "entries": entries,
                },
            },
        )
        ordinary = current_approval(g, pending)
        authority = ordinary["authority"]
        _, proof = own_proof(g, PARTIES[0], ordinary)
        assert invoke(g, PARTIES[0], "approve", {"approval": ordinary, "witness": proof})[0] == 409
        body = authorize(g, pending, authority, approvals)
        for role in ("custody", "policy"):
            changed = copy.deepcopy(body)
            changed["rotation"][role]["signature"] = "00" * 70
            resign(g, changed)
            assert invoke(g, PARTIES[0], "query", changed)[0] == 409
        unpinned_policy = root_path / "unpinned-policy"
        issue(unpinned_policy, f"policy-{custody_class.lower()}", ca())
        wrong_pin = copy.deepcopy(body)
        wrong_pin["rotation"]["policy"] = sign(unpinned_policy, DOMAIN, value)
        wrong_pin["rotation"]["policy_certificate_chain_der_hex"] = chain(unpinned_policy)
        resign(g, wrong_pin)
        assert invoke(g, PARTIES[0], "query", wrong_pin)[0] == 409
        stale_generation = copy.deepcopy(value)
        stale_generation["source_generation"] = {
            "epoch": 0,
            "ceremony_id": source["dkg"]["execution_id"],
            "public_key_package_sha256": hashlib.sha256(
                bytes(source["public_key_package"])
            ).hexdigest(),
        }
        stale_body = authorize(g, pending, authority, approved(g.w, stale_generation, DOMAIN))
        assert invoke(g, PARTIES[0], "query", stale_body)[0] == 409
        wrong = copy.deepcopy(value)
        wrong["rotation_id"] = str(uuid.uuid4())
        wrong["authorization_id"] = str(uuid.uuid4())
        wrong_body = authorize(g, pending, authority, approved(g.w, wrong, DOMAIN))
        _, proof = own_proof(g, PARTIES[0], wrong_body)
        assert (
            invoke(g, PARTIES[0], "approve", {"approval": wrong_body, "witness": proof})[0] == 409
        )
        unaccepted = copy.deepcopy(authority)
        modified = copy.deepcopy(unaccepted["prepare"]["value"])
        modified["request_id"] = str(uuid.uuid4())
        unaccepted["prepare"] = sign(g.w.life, "WITNESS_COMMAND_V1", modified)
        fake_prepare = authorize(g, pending, unaccepted, approvals)
        _, proof = own_proof(g, PARTIES[0], fake_prepare)
        assert (
            invoke(g, PARTIES[0], "approve", {"approval": fake_prepare, "witness": proof})[0] == 409
        )
        if custody_class == "COLD":
            assert (
                request(
                    g.net,
                    PARTIES[0],
                    "coordinator",
                    "/internal/v1/solana/current-claim/query",
                    body,
                )[0]
                == 409
            )
        encrypted = {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for party in PARTIES
            for path in Path(g.profiles[party]["signer"]["storage_directory"]).rglob("*.enc")
        }
        assert len(encrypted) >= 6  # Original and real Gen1 encrypted material at all three nodes.
        registrations = []

        def register(body, reports, proofs):
            evidence = {
                "statement": body["statement"],
                "authority": body["authority"],
                "participant_agreement": reports,
            }
            signed = command(
                g.w,
                source,
                {"kind": "RegisterRotationClaim", "approvals": proofs, "evidence": evidence},
            )
            selector = {
                "anchor_id": g.w.config["anchor_id"],
                "root_identity": fingerprint("SOLANA_SEEDED_ROOT_V1", source),
                "challenge": uuid.uuid4().hex + uuid.uuid4().hex,
                "execution_id": None,
                "claim_reservation_id": body["statement"]["reservation_id"],
                "rotation_id": value["rotation_id"],
            }
            code, reply = g.w.request("query", sign(g.w.life, "WITNESS_QUERY_V1", selector))
            assert code == 200, reply
            observed = verify(g.w.identity, "WITNESS_QUERY_REPLY_V1", reply)
            assert observed["query"] == selector and observed["claim"] == evidence
            assert "claim_issuance" not in observed
            item = observed["rotation_claim_registration"]
            assert item["command_id"] == signed["value"]["request_id"]
            assert item["source_fingerprint"] == fingerprint(
                "SOLANA_ROTATION_SOURCE_V1", entries[body["statement"]["index"]]
            )
            assert item["evidence_fingerprint"] == fingerprint(
                "SOLANA_ROTATION_CLAIM_EVIDENCE_V1", evidence
            )
            registrations.append(item)

        reports = collect(g, body)
        register(body, reports, approvals)
        short_plan = dict(
            value, authorization_id=str(uuid.uuid4()), expires_at=int(time.time()) + 15
        )
        short_proofs = approved(g.w, short_plan, DOMAIN)
        short = authorize(
            g, candidates[1], authority, short_proofs, expires_at=short_plan["expires_at"]
        )
        short_reports = collect(g, short)
        register(short, short_reports, short_proofs)
        saved_anchors, sequence = anchors(g), g.w.query()["sequence"]
        Event().wait(max(0, short_plan["expires_at"] + 1 - time.time()))
        assert int(time.time()) >= short_plan["expires_at"]
        for party, report in zip(PARTIES, short_reports, strict=True):
            assert invoke(g, party, "recover", short) == (200, report)
            assert invoke(g, party, "approve", {"approval": short, "witness": None}) == (
                200,
                report,
            )
        assert anchors(g) == saved_anchors and g.w.query()["sequence"] == sequence
        delayed = authorize(g, candidates[2], authority, approvals)
        old_nonce, stale = own_proof(g, PARTIES[0], delayed)
        Event().wait(17)  # Approval/plan remain live; the original own15s lease expires.
        assert int(time.time()) < value["expires_at"]
        assert invoke(g, PARTIES[0], "approve", {"approval": delayed, "witness": stale})[0] == 409
        assert invoke(g, PARTIES[0], "recover", delayed) == (200, None)
        new_nonce, _ = own_proof(g, PARTIES[0], delayed)
        assert old_nonce["value"]["challenge"] != new_nonce["value"]["challenge"]
        delayed_reports = collect(g, delayed)
        register(delayed, delayed_reports, approvals)
        cross_root = {
            "anchor_id": g.w.config["anchor_id"],
            "root_identity": fingerprint("SOLANA_SEEDED_ROOT_V1", target),
            "challenge": uuid.uuid4().hex + uuid.uuid4().hex,
            "execution_id": None,
            "claim_reservation_id": treasury["claim"]["reservation_id"],
            "rotation_id": value["rotation_id"],
        }
        assert g.w.request("query", sign(g.w.life, "WITNESS_QUERY_V1", cross_root))[0] == 409
        assert g.w.query()["root"]["next_claim_index"] == 4
        assert g.w.query()["root"]["phase"] == "Frozen"
        assert all(
            hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
            for path, digest in encrypted.items()
        )
        command(
            g.w, source, {"kind": "AbandonRotationInventory", "rotation_id": value["rotation_id"]}
        )
        g.w.stop()
        g.w.start(startup_timeout=60)
        assert g.w.query()["root"]["next_claim_index"] == 4
        private_file(
            root_path / "solana-rotation-claim-public-evidence.json",
            json.dumps(
                {
                    "scope": "Gen1 Frozen public receipts; no financial/private movement",
                    "custody_class": custody_class,
                    "actual_source_generation": 1,
                    "registered_source_claims": 4,
                    "new_readonly_current_registrations": 3,
                    "two_actual_frost_cohorts": True,
                    "ordinary_frozen_receipt_denied": True,
                    "independent_custody_policy_tamper_denied": True,
                    "unpinned_correct_role_policy_denied": True,
                    "stale_generation_context_denied": True,
                    "unaccepted_life_prepare_denied": True,
                    "wrong_sealed_rotation_denied": True,
                    "cross_root_registration_provenance_denied": True,
                    "expired_plan_report_recovery_without_new_grant": True,
                    "original_own15s_lease_not_renewed": True,
                    "three_source_current_encrypted_artifacts_unchanged": True,
                    "manual_cold_courier": custody_class == "COLD",
                    "registrations": registrations,
                    "private_movement_permits": 0,
                },
                sort_keys=True,
            ).encode(),
        )
