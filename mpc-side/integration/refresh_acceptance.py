"""Distributed upstream same-key refresh, never a reconstructed custody key."""

import copy
import hashlib
import shutil
import socket
import ssl
import threading
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from environment import issue
from protected_acceptance import group
from test_dkg import PARTIES, request
from witness_acceptance import sign, verify

PREFIX = "/internal/v1/solana/generation/"


def call(g, party, action, body):
    return request(
        g.net,
        party,
        "courier" if g.custody_class == "COLD" else "coordinator",
        PREFIX + action,
        body,
    )


def freeze(g):
    view = g.w.query()
    command = g.w.command({"kind": "Freeze"}, view["root"]["revision"])
    assert g.w.request("command", command)[0] == 200


def plan(g):
    root = g.w.query()["root"]
    value = {
        "anchor_id": g.w.config["anchor_id"],
        "root": g.w.root,
        "previous": root["generation"],
        "previous_public_key_package": root["public_key_package"],
        "session_id": str(uuid.uuid4()),
        "ceremony_id": str(uuid.uuid4()),
        "next_epoch": root["generation"]["epoch"] + 1,
        "node_keys": root["node_keys"],
        "expires_at": int(time.time()) + 240,
    }
    return sign(g.w.life, "WITNESS_FROST_REFRESH_PLAN_V1", value)


def start(g, p, party):
    status = None
    if g.custody_class == "COLD":
        code, query = call(g, party, "query", p)
        assert code == 200
        code, status = g.w.request("query", query, identity=g.w.courier)
        assert code == 200
    return call(g, party, "start", {"plan": p, "frozen": status})


def run_rounds(g, p, *, interrupt_ready=False):
    for party in PARTIES:
        assert start(g, p, party)[0] == 200
    for action in ("round1", "round2"):
        for party in PARTIES:
            code, report = call(g, party, action, {"plan": p, "frozen": None})
            assert code == 200, (party, action, report)
    ready = []
    for party in PARTIES:
        control = {"plan": p, "frozen": None}
        if interrupt_ready and party == PARTIES[-1]:
            # The encrypted share is durable, but the public Ready publication
            # encounters an actual filesystem failure before its journal event.
            events = g.net.root / party / "protected-anchor" / "events"
            prior = sorted(events.glob("*.json"))
            blocked = events / f"{len(prior):020}.json"
            blocked.mkdir()  # Occupy the immutable next-event path with a directory.
            try:
                assert call(g, party, "finalize", control)[0] == 409
                completed = g.net.root / party / "storage" / "solana-generations"
                files = list(completed.glob(f"*-{p['value']['ceremony_id']}.enc"))
                assert len(files) == 1
                digest = hashlib.sha256(files[0].read_bytes()).hexdigest()
            finally:
                blocked.rmdir()  # Restore the injected path, no accepted event is removed.
            g.net.stop(party)
            g.start(party)
            code, report = call(g, party, "report", control)
            assert hashlib.sha256(files[0].read_bytes()).hexdigest() == digest
            assert len(list(events.glob("*.json"))) == len(prior) + 1
        else:
            code, report = call(g, party, "finalize", control)
        assert code == 200, (party, report)
        assert report["status"] == "READY"
        verify(g.w.node[party], "WITNESS_GENERATION_READY_V1", report["ready"])
        ready.append(report["ready"])
    assert all(
        r["value"]["public_key_package"] == ready[0]["value"]["public_key_package"] for r in ready
    )
    assert ready[0]["value"]["public_key_package"] != p["value"]["previous_public_key_package"]
    return ready


def activate(g, p, ready):
    revision = g.w.query()["root"]["revision"]
    bad = g.w.command(
        {"kind": "Prepare", "ready": ready[:2], "node_keys": p["value"]["node_keys"]}, revision
    )
    assert g.w.request("command", bad)[0] == 409
    prepare = g.w.command(
        {"kind": "Prepare", "ready": ready, "node_keys": p["value"]["node_keys"]}, revision
    )
    assert g.w.request("command", prepare)[0] == 200
    assert g.w.query()["root"]["phase"] == "Prepared"
    activate = g.w.command({"kind": "Activate"}, g.w.query()["root"]["revision"])
    assert g.w.request("command", activate)[0] == 200
    current = g.w.query()["root"]
    assert current["phase"] == "Active" and current["generation"] == ready[0]["value"]["generation"]


def wrong_peer_private_round(g):
    """An actual upstream private R2 must send zero HTTP to a retired peer key."""
    p = plan(g)
    for party in PARTIES:
        assert start(g, p, party)[0] == 200
    for party in PARTIES:
        assert call(g, party, "round1", {"plan": p, "frozen": None})[0] == 200
    party = PARTIES[1]
    identity = g.net.root / party / "identity"
    issuer = (
        serialization.load_pem_private_key((g.net.root / "issuer" / "ca.key").read_bytes(), None),
        x509.load_pem_x509_certificate((identity / "ca.crt").read_bytes()),
    )
    replacement = g.net.root / "wrong-refresh-peer"
    issue(replacement, party, issuer)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(replacement / "tls.crt", replacement / "tls.key")
    context.load_verify_locations(cafile=str(identity / "ca.crt"))
    context.verify_mode = ssl.CERT_REQUIRED
    observed = {"http_bytes": 0, "error": None}
    g.net.stop(party)
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", g.net.ports[party]))
        listener.listen(1)
        listener.settimeout(10)

        def server():
            try:
                conn, _ = listener.accept()
                with context.wrap_socket(conn, server_side=True) as stream:
                    stream.settimeout(5)
                    while True:
                        data = stream.recv(4096)
                        if not data:
                            break
                        observed["http_bytes"] += len(data)
            except Exception as error:
                observed["error"] = type(error).__name__

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        assert call(g, PARTIES[0], "round2", {"plan": p, "frozen": None})[0] == 409
        thread.join(timeout=10)
        assert not thread.is_alive()
        # Count every byte, including partial headers, without retaining a
        # private packet that pytest could print if this security check failed.
        assert observed["http_bytes"] == 0
        assert observed["error"] in (None, "ConnectionResetError", "SSLEOFError", "BrokenPipeError")
    g.start(party)
    for remaining in (PARTIES[0], PARTIES[2]):
        assert call(g, remaining, "abort", {"plan": p, "frozen": None})[0] == 200
    assert start(g, p, party)[0] == 409
    # Malformed direct messages cannot rebind this consumed ceremony. No
    # private packet is exported by the test or accepted from the controller.
    assert request(g.net, PARTIES[0], "coordinator", PREFIX + "message", {})[0] == 409


def run_refresh(root_path, *, custody_class="HOT"):
    with group(root_path, custody_class, lifecycle=True) as (g, c, receipts):
        original = copy.deepcopy(g.w.root)
        before = {
            p: {
                f.name: hashlib.sha256(f.read_bytes()).hexdigest()
                for f in (g.net.root / p / "storage").glob("*.share.enc")
            }
            for p in PARTIES
        }
        freeze(g)
        p = plan(g)
        forged = copy.deepcopy(p)
        forged["signature"] = "00" * 70
        assert call(g, PARTIES[0], "start", {"plan": forged, "frozen": None})[0] == 409
        if custody_class == "HOT":
            for field, value in (
                ("anchor_id", str(uuid.uuid4())),
                ("expires_at", int(time.time()) - 1),
                ("next_epoch", 2),
            ):
                bad = copy.deepcopy(p["value"])
                bad[field] = value
                bad = sign(g.w.life, "WITNESS_FROST_REFRESH_PLAN_V1", bad)
                assert start(g, bad, PARTIES[0])[0] == 409
            bad = copy.deepcopy(p["value"])
            bad["node_keys"][PARTIES[1]] = "ab" * 32
            bad = sign(g.w.life, "WITNESS_FROST_REFRESH_PLAN_V1", bad)
            assert start(g, bad, PARTIES[0])[0] == 409
        else:
            code, query = call(g, PARTIES[0], "query", p)
            assert code == 200
            code, response = g.w.request("query", query, identity=g.w.courier)
            assert code == 200
            # A valid witness signature must still answer this participant's
            # own in-memory original challenge; another node cannot use it.
            assert call(g, PARTIES[1], "start", {"plan": p, "frozen": response})[0] == 409
        ready = run_rounds(g, p)
        for party in PARTIES:
            g.net.stop(party)
            g.start(party)
            code, report = call(g, party, "report", {"plan": p, "frozen": None})
            assert code == 200 and report["ready"] == ready[PARTIES.index(party)]
            assert start(g, p, party)[0] == 409  # No regenerated private ceremony.
        activate(g, p, ready)
        assert g.w.query()["root"]["original"] == original
        assert g.w.query(claim_id=c["reservation_id"])["claim"]["statement"] == c
        for party in PARTIES:
            now = {
                f.name: hashlib.sha256(f.read_bytes()).hexdigest()
                for f in (g.net.root / party / "storage").glob("*.share.enc")
            }
            assert now == before[party]
            g.net.stop(party)
            g.start(party)
        pairs = ((PARTIES[0], PARTIES[1]), (PARTIES[0], PARTIES[2]), (PARTIES[1], PARTIES[2]))
        for operation, pair in enumerate(pairs if custody_class == "HOT" else pairs[:1], 1):
            binding = g.binding(c, receipts, operation, pair)
            assert binding["authorized"]["intent"]["generation"]["epoch"] == 1
            g.broadcast(binding, g.sign(binding))
        old = g.binding(c, receipts, 100)
        old["authorized"]["intent"]["generation"] = p["value"]["previous"]
        old = g.w.authorize(old["authorized"])
        assert (
            g.call(PARTIES[0], "auto", {"binding": old, "round": 1, "signing_package": None})[0]
            == 409
        )


def run_interrupted_refresh(root_path):
    with group(root_path, lifecycle=True) as (g, c, receipts):
        freeze(g)
        p = plan(g)
        for party in PARTIES:
            assert start(g, p, party)[0] == 200
        for party in PARTIES[:2]:
            assert call(g, party, "round1", {"plan": p, "frozen": None})[0] == 200
        lost = PARTIES[1]
        g.net.stop(lost)
        g.start(lost)
        assert start(g, p, lost)[0] == 409
        code, report = call(g, lost, "report", {"plan": p, "frozen": None})
        assert code == 200 and report["ready"] is None
        for party in (PARTIES[0], PARTIES[2]):
            assert call(g, party, "abort", {"plan": p, "frozen": None})[0] == 200
            assert start(g, p, party)[0] == 409
        # A consumed logical session cannot be relabeled as another ceremony.
        renamed = copy.deepcopy(p["value"])
        renamed["ceremony_id"] = str(uuid.uuid4())
        renamed = sign(g.w.life, "WITNESS_FROST_REFRESH_PLAN_V1", renamed)
        assert start(g, renamed, lost)[0] == 409
        wrong_peer_private_round(g)
        p = plan(g)  # Explicitly authorized new ceremony, same frozen generation.
        ready = run_rounds(g, p)
        activate(g, p, ready)
        # Remove only the refreshed share, leaving the original genuine DKG
        # artifact and intact independent public journal. There is no fallback.
        party = PARTIES[0]
        g.net.stop(party)
        files = list((g.net.root / party / "storage" / "solana-generations").glob("*.enc"))
        assert len(files) == 1
        saved = root_path / "retained-generation.enc"
        shutil.move(files[0], saved)
        g.start(party)
        assert call(g, party, "report", {"plan": p, "frozen": None})[0] == 409
        binding = g.binding(c, receipts)
        control = {"binding": binding, "round": 1, "signing_package": None}
        assert g.call(party, "auto", control)[0] == 409
        assert g.call(party, "recover", control) == (200, None)
        close = g.w.command(
            {
                "kind": "CloseNoSignature",
                "execution_id": binding["authorized"]["intent"]["crypto_execution_id"],
            },
            g.w.query()["root"]["revision"],
        )
        assert g.w.request("command", close)[0] == 200
        # Explicitly restore the same immutable artifact, not another epoch.
        g.net.stop(party)
        shutil.move(saved, files[0])
        original_bytes = files[0].read_bytes()
        other = next(
            (g.net.root / PARTIES[1] / "storage" / "solana-generations").glob("*.enc")
        ).read_bytes()
        for invalid in (other, original_bytes[:-1] + bytes([original_bytes[-1] ^ 1])):
            files[0].write_bytes(invalid)
            g.start(party)
            assert call(g, party, "report", {"plan": p, "frozen": None})[0] == 409
            g.net.stop(party)
        files[0].write_bytes(original_bytes)
        g.start(party)
        binding = g.binding(c, receipts, 2, amount=1000001)
        g.broadcast(binding, g.sign(binding))
        # A second real refresh must use the current private shares, and keep
        # both original receipts and immutable prior encrypted generations.
        freeze(g)
        second = plan(g)
        assert second["value"]["previous"]["epoch"] == 1
        next_ready = run_rounds(g, second, interrupt_ready=True)
        activate(g, second, next_ready)
        for pty in PARTIES:
            assert (
                len(list((g.net.root / pty / "storage" / "solana-generations").glob("*.enc"))) == 2
            )
            g.net.stop(pty)
            g.start(pty)
        binding = g.binding(c, receipts, 3, amount=1000002)
        assert binding["authorized"]["intent"]["generation"]["epoch"] == 2
        g.broadcast(binding, g.sign(binding))
