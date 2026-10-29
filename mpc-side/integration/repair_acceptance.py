"""Genuine upstream RTS between two helpers and one fresh replacement process.

The controller never reads/decrypts MPC shares or carries private RTS packets.
Original TLS identities, Root/Claim receipts and DKG ciphertexts remain intact.
"""

import copy
import hashlib
import json
import os
import socket
import ssl
import threading
import time
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from environment import issue, private_file
from protected_acceptance import balance, group
from refresh_acceptance import freeze
from test_dkg import PARTIES, request
from witness_acceptance import fingerprint, key_id, sign, verify

PREFIX = "/internal/v1/solana/replacement/"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def profile_hash(p):
    files = [
        p["tls"]["ca"],
        p["tls"]["cert"],
        p["witness_tls"]["ca"],
        p["witness_tls"]["cert"],
        p["witness_certificate"],
        *[
            p["policy"][f]
            for f in ("custody_ca", "custody_certificate", "policy_ca", "policy_certificate")
        ],
        *[f for fs in p["policy"]["receipt_certificates"].values() for f in fs],
        p["lifecycle_certificate"],
    ]
    material = {f: hashlib.sha256(Path(f).read_bytes()).hexdigest() for f in files}
    return hashlib.sha256(canonical({"profile": p, "public_trust_material": material})).hexdigest()


def call(g, party, action, p, stage="repair", frozen=None):
    return request(
        g.net,
        party,
        "courier" if g.custody_class == "COLD" else "coordinator",
        PREFIX + action,
        {"plan": p, "stage": stage, "frozen": frozen},
    )


def start(g, party, p, stage="repair"):
    frozen = None
    if g.custody_class == "COLD":
        code, q = call(g, party, "query", p, stage)
        assert code == 200
        code, frozen = g.w.request("query", q, identity=g.w.courier)
        assert code == 200
    return call(g, party, "start", p, stage, frozen)


def recipient(g, name="replacement-a"):
    """New files/credentials; do not mutate trust material pinned by helpers."""
    party = PARTIES[0]
    old = g.net.root / party / "identity"
    issuer = (
        serialization.load_pem_private_key((g.net.root / "issuer/ca.key").read_bytes(), None),
        x509.load_pem_x509_certificate((old / "ca.crt").read_bytes()),
    )
    directory = g.net.root / name
    identity = directory / "identity"
    issue(identity, party, issuer)
    private_file(identity / "wrapping.key", os.urandom(32))
    p = copy.deepcopy(g.profiles[party])
    p["tls"] = {
        "ca": str(identity / "ca.crt"),
        "cert": str(identity / "tls.crt"),
        "key": str(identity / "tls.key"),
    }
    if g.custody_class == "COLD":
        private_file(identity / "clients.crt", (old / "protected-clients.crt").read_bytes())
        p["tls"]["ca"] = str(identity / "clients.crt")
    p["witness_tls"] = dict(p["tls"], ca=p["witness_tls"]["ca"])
    p["signer"]["storage_directory"] = str(directory / "storage")
    p["signer"]["wrapping_key_path"] = str(identity / "wrapping.key")
    p["anchor_directory"] = str(directory / "protected-anchor")
    p["replacement_bootstrap"] = {
        "root_identity": fingerprint("SOLANA_SEEDED_ROOT_V1", g.w.root),
        "anchor_id": str(uuid.uuid4()),
    }
    path = identity / "protected.json"
    private_file(path, canonical(p))
    g.net.stop(party)
    g.net.configs[party]["MPC_PROTECTED_PROFILE"] = str(path)
    g.profiles[party] = p
    g.start(party, initialize=True)
    g.w.stop()
    g.w.config["profiles"][g.custody_class]["node_certificates"][party].append(
        str(identity / "tls.crt")
    )
    g.w.start()
    g.w.node[party] = identity
    return identity, profile_hash(p), p["replacement_bootstrap"]["anchor_id"]


def reserve(g, identity, profile, anchor, *, lifetime=240):
    current = g.w.query()["root"]
    p = {
        "refresh": {
            "anchor_id": g.w.config["anchor_id"],
            "root": g.w.root,
            "previous": current["generation"],
            "previous_public_key_package": current["public_key_package"],
            "session_id": str(uuid.uuid4()),
            "ceremony_id": str(uuid.uuid4()),
            "next_epoch": current["generation"]["epoch"] + 1,
            "node_keys": dict(current["node_keys"], **{PARTIES[0]: key_id(identity)}),
            "expires_at": int(time.time()) + lifetime,
        },
        "previous_node_keys": current["node_keys"],
        "party_id": PARTIES[0],
        "recipient_anchor_id": anchor,
        "recipient_profile_sha256": profile,
        "repair_session_id": str(uuid.uuid4()),
        "repair_ceremony_id": str(uuid.uuid4()),
    }
    code, _ = g.w.request(
        "command", g.w.command({"kind": "ReserveReplacement", "plan": p}, current["revision"])
    )
    assert code == 200
    return sign(g.w.life, "WITNESS_FROST_REPLACEMENT_PLAN_V1", p)


def activate(g, p, ready):
    assert (
        g.w.request(
            "command",
            g.w.command(
                {
                    "kind": "Prepare",
                    "ready": ready,
                    "node_keys": p["value"]["refresh"]["node_keys"],
                },
                g.w.query()["root"]["revision"],
            ),
        )[0]
        == 200
    )
    assert (
        g.w.request("command", g.w.command({"kind": "Activate"}, g.w.query()["root"]["revision"]))[
            0
        ]
        == 200
    )
    view = g.w.query()
    assert view.get("replacement") is None
    assert view["root"]["generation"] == ready[0]["value"]["generation"]


def wrong_private_peer(g, p, *, delay=False):
    """Count actual upstream Delta release; never retain private HTTP bytes."""
    party = PARTIES[2]
    original = g.net.root / party / "identity"
    identity = original
    if not delay:
        issuer = (
            serialization.load_pem_private_key((g.net.root / "issuer/ca.key").read_bytes(), None),
            x509.load_pem_x509_certificate((original / "ca.crt").read_bytes()),
        )
        identity = g.net.root / "wrong-repair-peer"
        issue(identity, party, issuer)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(identity / "tls.crt", identity / "tls.key")
    context.load_verify_locations(cafile=str(original / "ca.crt"))
    context.verify_mode = ssl.CERT_REQUIRED
    observed = {"bytes": 0, "error": None, "handshake_finished": None}
    g.net.stop(party)
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", g.net.ports[party]))
        listener.listen(1)
        listener.settimeout(10)

        def server():
            try:
                conn, _ = listener.accept()
                if delay:
                    # The real caller has already entered TLS. Complete its
                    # handshake after the exact plan's release deadline, within
                    # the unchanged five-second transport timeout.
                    remaining = p["value"]["refresh"]["expires_at"] - time.time() + 0.15
                    threading.Event().wait(max(0, remaining))
                with context.wrap_socket(conn, server_side=True) as stream:
                    observed["handshake_finished"] = time.time()
                    stream.settimeout(5)
                    while True:
                        data = stream.recv(4096)
                        if not data:
                            break
                        observed["bytes"] += len(data)
            except Exception as error:
                observed["error"] = type(error).__name__

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        assert call(g, PARTIES[1], "round1", p)[0] == 409
        thread.join(timeout=10)
        assert not thread.is_alive()
        assert observed["bytes"] == 0
        assert observed["error"] in (
            None,
            "ConnectionResetError",
            "SSLEOFError",
            "BrokenPipeError",
        )
        if delay:
            assert observed["handshake_finished"] is not None
            assert observed["handshake_finished"] >= p["value"]["refresh"]["expires_at"]
    g.start(party)
    return observed["bytes"]


def run_private_fences(root_path, *, delay=False):
    with group(root_path, lifecycle=True) as (g, c, receipts):
        freeze(g)
        identity, profile, anchor = recipient(g)
        p = reserve(g, identity, profile, anchor, lifetime=4 if delay else 240)
        for party in PARTIES:
            code, report = start(g, party, p)
            assert code == 200, (party, report)
        assert wrong_private_peer(g, p, delay=delay) == 0
        for party in PARTIES:
            g.net.stop(party)
            g.start(party)
            code, report = call(g, party, "report", p)
            assert code == 200 and report["status"] == "REPAIR_INTERRUPTED"
            # Reports remain possible after expiry; no private step is resumed.
            assert call(g, party, "round1", p)[0] == 409
        assert (
            g.w.request(
                "command",
                g.w.command(
                    {
                        "kind": "AbandonReplacement",
                        "repair_ceremony_id": p["value"]["repair_ceremony_id"],
                    },
                    g.w.query()["root"]["revision"],
                ),
            )[0]
            == 200
        )
        identity, profile, anchor = recipient(g, "replacement-a-retry")
        fresh = reserve(g, identity, profile, anchor)
        for party in PARTIES:
            assert start(g, party, fresh)[0] == 200
        for action in ("round1", "round2"):
            for party in PARTIES[1:]:
                code, report = call(g, party, action, fresh)
                assert code == 200, (party, action, report)
        code, report = call(g, PARTIES[0], "finalize", fresh)
        assert code == 200 and report["repaired"] is not None
        verify(identity, "WITNESS_FROST_REPAIR_READY_V1", report["repaired"])
        private_file(
            root_path / "solana-repair-fence-public-evidence.json",
            canonical(
                {
                    "scope": "actual upstream Delta release and interrupted repair",
                    "wrong_peer_pin_zero_http_bytes": not delay,
                    "post_tls_expiry_zero_http_bytes": delay,
                    "all_restarted_ceremonies_remain_interrupted": True,
                    "explicit_abandon_and_fresh_recipient_repair_succeeded": True,
                    "new_generation_activated": False,
                }
            ),
        )


def staging_faults(g, p, identity):
    storage = identity.parent / "storage"
    paths = list((storage / "solana-repair-staging").glob("*.enc"))
    assert len(paths) == 1
    path = paths[0]
    before = path.read_bytes()  # Encrypted bytes only; no share decryption.
    hidden = path.with_suffix(".temporarily-unavailable")
    path.rename(hidden)
    try:
        assert call(g, PARTIES[0], "report", p)[0] == 409
        assert start(g, PARTIES[0], p, "refresh")[0] == 409
    finally:
        hidden.rename(path)
    try:
        private_file(path, before[:-1] + bytes([before[-1] ^ 1]))
        assert call(g, PARTIES[0], "report", p)[0] == 409
        # A genuine original ciphertext has the wrong wrapper/AAD/format and
        # cannot be adopted as the explicitly staged repaired participant.
        original = next((g.net.root / PARTIES[0] / "storage").glob("*.share.enc"))
        private_file(path, original.read_bytes())
        assert call(g, PARTIES[0], "report", p)[0] == 409
    finally:
        private_file(path, before)
    path.rename(hidden)
    try:
        path.symlink_to(hidden)
        assert call(g, PARTIES[0], "report", p)[0] == 409
    finally:
        path.unlink()
        hidden.rename(path)
    code, report = call(g, PARTIES[0], "report", p)
    assert code == 200 and report["repaired"] is not None
    g.net.stop(PARTIES[0])
    profile_path = Path(g.net.configs[PARTIES[0]]["MPC_PROTECTED_PROFILE"])
    original_profile = profile_path.read_bytes()
    bad = json.loads(original_profile)
    bad["replacement_bootstrap"]["anchor_id"] = str(uuid.uuid4())
    try:
        private_file(profile_path, canonical(bad))
        g.rejected_start(PARTIES[0])
    finally:
        private_file(profile_path, original_profile)
    g.start(PARTIES[0])
    assert call(g, PARTIES[0], "report", p)[0] == 200


def run_repair(root_path, *, custody_class="HOT", faults=False):
    with group(root_path, custody_class, lifecycle=True) as (g, c, receipts):
        original = copy.deepcopy(g.w.root)
        original_receipts = copy.deepcopy(receipts)
        ciphertexts = {
            path: hashlib.sha256(path.read_bytes()).hexdigest()
            for party in PARTIES
            for path in (g.net.root / party / "storage").rglob("*.share.enc")
        }
        assert len(ciphertexts) == 3
        freeze(g)
        identity, profile, anchor = recipient(g)
        p = reserve(g, identity, profile, anchor)
        for party in PARTIES:
            code, report = start(g, party, p)
            assert code == 200, (party, report)
            assert report["status"] == "REPAIR_ACTIVE"
        forbidden = copy.deepcopy(p)
        forbidden["signature"] = "00" * 70
        assert call(g, PARTIES[1], "round1", forbidden)[0] == 409
        for action in ("round1", "round2"):
            for party in PARTIES[1:]:
                code, report = call(g, party, action, p)
                assert code == 200, (party, action, report)
        if faults:
            # The private staged artifact commits before the public Ready event;
            # fault the actual next immutable journal path, then recover exactly
            # that same artifact on restart without rerunning any private RTS.
            events = identity.parent / "protected-anchor/events"
            prior = sorted(events.glob("*.json"))
            blocked = events / f"{len(prior):020}.json"
            blocked.mkdir()
            try:
                assert call(g, PARTIES[0], "finalize", p)[0] == 409
                staged = list((identity.parent / "storage/solana-repair-staging").glob("*.enc"))
                assert len(staged) == 1
                digest = hashlib.sha256(staged[0].read_bytes()).hexdigest()
                # The journal's uncertain write fences already-active helpers
                # in this process, and no public success can be issued.
                assert call(g, PARTIES[0], "report", p)[0] == 409
            finally:
                blocked.rmdir()  # Only the unaccepted injected directory.
            g.net.stop(PARTIES[0])
            g.start(PARTIES[0])
            code, report = call(g, PARTIES[0], "report", p)
            assert hashlib.sha256(staged[0].read_bytes()).hexdigest() == digest
            assert len(list(events.glob("*.json"))) == len(prior) + 1
            staging_faults(g, p, identity)
        else:
            code, report = call(g, PARTIES[0], "finalize", p)
        assert code == 200, report
        assert report["repaired"] is not None and report["generation_ready"] is None
        verify(identity, "WITNESS_FROST_REPAIR_READY_V1", report["repaired"])
        # A RepairReady is not an active GenerationReady or a signing grant.
        blocked_binding = g.binding(c, receipts, 8999)
        assert (
            g.call(
                PARTIES[0],
                "auto",
                {
                    "binding": blocked_binding,
                    "round": 1,
                    "signing_package": None,
                },
            )[0]
            == 409
        )
        for party in PARTIES:
            code, report = start(g, party, p, "refresh")
            assert code == 200, (party, "refresh", report)
        for action in ("round1", "round2"):
            for party in PARTIES:
                code, report = call(g, party, action, p, "refresh")
                assert code == 200, (party, action, report)
        ready = []
        for party in PARTIES:
            code, report = call(g, party, "finalize", p, "refresh")
            assert code == 200, (party, report)
            verify(g.w.node[party], "WITNESS_GENERATION_READY_V1", report["generation_ready"])
            ready.append(report["generation_ready"])
            recovered = call(g, party, "report", p, "refresh")
            assert recovered[0] == 200 and recovered[1]["generation_ready"] == ready[-1]
        activate(g, p, ready)
        assert g.w.root == original and receipts == original_receipts
        assert all(hashlib.sha256(f.read_bytes()).hexdigest() == h for f, h in ciphertexts.items())
        assert not list((identity.parent / "storage").rglob("*.share.enc"))
        assert request(g.net, PARTIES[0], "coordinator", "/internal/v1/dkg/start", {})[0] == 404
        for party in PARTIES:
            g.net.stop(party)
            g.start(party)
        pairs = ((PARTIES[0], PARTIES[1]), (PARTIES[0], PARTIES[2]), (PARTIES[1], PARTIES[2]))
        source = g.binding(c, receipts)["authorized"]["intent"]["financial_source"]
        before = balance(g, source)
        for operation, pair in enumerate(pairs, 9001):
            b = g.binding(c, receipts, operation, pair, amount=1000000)
            g.broadcast(b, g.sign(b))
        assert balance(g, source) == before - 3000000
        private_file(
            root_path / "solana-repair-public-evidence.json",
            canonical(
                {
                    "scope": "genuine one-share RTS and all-three refresh, isolated development",
                    "custody_class": custody_class,
                    "original_dkg_ciphertexts_unchanged": 3,
                    "original_root_claim_receipts_unchanged": True,
                    "recipient_original_dkg_share_absent": True,
                    "all_three_pairs_finalized_after_restart": True,
                    "new_epoch": g.w.query()["root"]["generation"]["epoch"],
                    "staging_publication_failure_restart_recovered": faults,
                    "missing_corrupt_transplanted_symlink_stage_denied": faults,
                    "changed_profile_anchor_restart_denied": faults,
                }
            ),
        )
