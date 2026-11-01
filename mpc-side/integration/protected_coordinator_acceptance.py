"""Actual protected coordinator HTTP and public-state recovery; no DB ledger."""

import copy
import hashlib
import http.client
import json
import os
import shutil
import ssl
import threading
import time
import uuid
from collections import Counter
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from custody.solana_seeded import account_address
from environment import private_file
from profile_migration_acceptance import chain
from protected_acceptance import group
from seeded_enrollment import approval, call, claim, enroll_all
from solders.pubkey import Pubkey
from test_dkg import PARTIES, request
from witness_acceptance import fingerprint, sign, verify

PREFIX = "/v1/solana-protected-sessions"


@contextmanager
def financial_group(root_path):
    with group(root_path, lifecycle=True, bootstrap_only=True) as (g, _, _):
        reports = enroll_all(g.net, g.original_root)
        g.w.start(initialize=True)
        g.w.enroll(reports)
        view = g.w.query()["root"]
        plan = {
            "version": 1,
            "activation_id": str(uuid.uuid4()),
            "witness_anchor": g.w.config["anchor_id"],
            "root": g.original_root,
            "generation": view["generation"],
            "node_keys": view["node_keys"],
            "expires_at": int(time.time()) + 120,
        }
        domain = "WITNESS_SOLANA_FINANCIAL_MODE_V1"
        approvals = {
            "custody": sign(g.w.custody, domain, plan),
            "policy": sign(g.w.policy, domain, plan),
            "custody_certificate_chain_der_hex": chain(g.w.custody),
            "policy_certificate_chain_der_hex": chain(g.w.policy),
        }
        assert (
            g.w.request(
                "command",
                g.w.command(
                    {"kind": "EnableFinancialMode", "approvals": approvals}, view["revision"]
                ),
            )[0]
            == 200
        )
        c = claim(g.original_root, owner=f"p1:{uuid.uuid4()}")
        receipts = []
        for party in PARTIES:
            code, receipt = call(g.net, party, "approve", approval(g.net, "claim", c))
            assert code == 200
            receipts.append(receipt)
        g.w.register_claim(c, receipts)
        assert (
            g.w.request(
                "command",
                g.w.command(
                    {
                        "kind": "IssueNativeClaim",
                        "reservation_id": c["reservation_id"],
                        "issuance_id": str(uuid.uuid4()),
                    },
                    g.w.query()["root"]["revision"],
                ),
            )[0]
            == 200
        )
        base = str(Pubkey.from_bytes(bytes.fromhex(g.original_root["group_public_key"])))
        g.validator.fund(base, 200000000)
        g.validator.fund(account_address(base, c["index"]), 10000000)
        yield g, c, receipts


def enable_coordinator(g, root_path):
    p = g.w.config["profiles"]["HOT"]
    profile = {
        "environment": "isolated-development-protected-coordinator-v1",
        "directory": str(root_path / "protected-coordinator-public"),
        "witness_anchor": g.w.config["anchor_id"],
        "witness_certificate": str(g.w.identity / "tls.crt"),
        "node_certificates": {party: [str(g.w.node[party] / "tls.crt")] for party in PARTIES},
        **{
            key: p[key]
            for key in (
                "genesis_hash",
                "policy_version",
                "max_fee_lamports",
                "max_rent_lamports",
                "max_lifetime_seconds",
            )
        },
    }
    file = root_path / "protected-coordinator-profile.json"
    private_file(file, json.dumps(profile).encode())
    g.net.stop("coordinator")
    g.net.configs["coordinator"]["MPC_SOLANA_PROTECTED_COORDINATOR_PROFILE"] = str(file)
    g.net.start("coordinator")
    g.coordinator_directory = root_path / "protected-coordinator-public"
    return profile


def signing_request(g, c, receipts, operation, pair=PARTIES[:2], *, amount=1000000, attempt=None):
    binding = g.binding(c, receipts, operation, pair, amount=amount)
    i = binding["authorized"]["intent"]
    if attempt is not None:
        i["attempt_id"] = attempt
    i["financial"] = {
        "version": 1,
        "reservation_id": str(uuid.uuid4()),
        "tenant_id": g.original_root["ownership_scope"],
        "reservation_owner_ref": c["owner_ref"],
        "source_owner_ref": c["owner_ref"],
        "source_role": "CUSTOMER_DEPOSIT",
        "operation_type": i["operation_type"],
        "operation_id": operation,
        "approval_id": str(uuid.uuid4()),
        "asset_key": i["asset_key"],
    }
    binding = g.w.authorize(binding["authorized"])
    binding["selected_signers"] = list(pair)
    query = {
        "anchor_id": g.w.config["anchor_id"],
        "root_identity": fingerprint("SOLANA_SEEDED_ROOT_V1", g.original_root),
        "challenge": os.urandom(32).hex(),
        "execution_id": i["crypto_execution_id"],
        "claim_reservation_id": c["reservation_id"],
    }
    code, proof = g.w.request(
        "query", sign(g.w.custody, "WITNESS_QUERY_V1", query), identity=g.w.courier
    )
    assert code == 200
    verify(g.w.identity, "WITNESS_QUERY_REPLY_V1", proof)
    return {"binding": binding, "witness": proof}


def call_coordinator(g, path, body=None, method="POST"):
    return request(g.net, "coordinator", "custody", PREFIX + path, body, method)


class SignerRelay:
    """Faults only: original TLS leaf, real protected private calls and reports."""

    def __init__(self, g, party, fault, before_response=None):
        self.g, self.party, self.fault = g, party, fault
        self.before_response = before_response
        self.calls = Counter()
        self.errors = []
        self.entered = threading.Event()
        self.release = threading.Event()
        relay = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    action = self.path.rsplit("/", 1)[-1]
                    round_number = body["round"]
                    relay.calls[(action, round_number)] += 1
                    target = action == "auto" and round_number == (1 if fault == "round1" else 2)
                    if target:
                        sid = body["binding"]["authorized"]["intent"]["session_id"]
                        durable = json.loads((g.coordinator_directory / f"{sid}.json").read_bytes())
                        if round_number == 2:
                            assert len(durable["round1"]) == 2
                            assert durable["signing_package"] == body["signing_package"]
                        if fault == "before_record":
                            # Stop at the real durable node result before W.record.
                            code, challenge = g.call(party, "challenge", body)
                            assert code == 200
                            code, permit = g.w.request("permit", challenge, identity=g.w.courier)
                            assert code == 200
                            code, result = g.call(party, "apply", permit)
                        else:
                            code, result = g.call(party, action, body)
                        assert code == 200
                        verify(g.w.node[party], "WITNESS_PUBLIC_ROUND_V1", result)
                        if fault == "invalid_share":
                            corrupted = copy.deepcopy(result["value"])
                            corrupted["signature_share"] = [0] * 32
                            result = sign(g.w.node[party], "WITNESS_PUBLIC_ROUND_V1", corrupted)
                        if relay.before_response:
                            relay.before_response(sid)
                        relay.entered.set()
                        if fault in ("client_disconnect", "coordinator_restart"):
                            assert relay.release.wait(15), "fault release not received"
                        if fault in (
                            "last_r2",
                            "first_r2",
                            "round1",
                            "before_record",
                            "coordinator_restart",
                        ):
                            self.close_connection = True
                            return
                    else:
                        code, result = g.call(party, action, body)
                    data = json.dumps(result).encode()
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # Deliberate original client/coordinator disconnection.
                except Exception as exc:
                    relay.errors.append(type(exc).__name__ + ": " + str(exc))
                    self.close_connection = True

        identity = g.net.root / party / "identity"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(identity / "tls.crt", identity / "tls.key")
        context.load_verify_locations(identity / "ca.crt")
        context.verify_mode = ssl.CERT_REQUIRED
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        g.net.stop("coordinator")
        suffix = party[-1].upper()
        g.net.configs["coordinator"][f"MPC_SIGNER_{suffix}_ADDR"] = (
            f"127.0.0.1:{self.server.server_port}"
        )
        g.net.start("coordinator")

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def run_coordinator(root_path):
    with financial_group(root_path) as (g, c, receipts):
        # Optional financial profile is absent, so no unreviewed generic route.
        assert call_coordinator(g, "", {})[0] == 404
        profile = enable_coordinator(g, root_path)
        g.net.stop("coordinator")
        old_address = g.net.configs["coordinator"]["MPC_SIGNER_A_ADDR"]
        g.net.configs["coordinator"]["MPC_SIGNER_A_ADDR"] = "192.0.2.1:9"
        try:
            g.net.start("coordinator")
            raise AssertionError("protected coordinator accepted a non-loopback peer")
        except RuntimeError as exc:
            assert "protected peers must be loopback" in str(exc)
        finally:
            g.net.stop("coordinator")
            g.net.configs["coordinator"]["MPC_SIGNER_A_ADDR"] = old_address
        g.net.start("coordinator")
        original = {
            f: hashlib.sha256(f.read_bytes()).hexdigest()
            for party in PARTIES
            for f in (g.net.root / party / "storage").glob("*.share.enc")
        }
        finalized = []
        for n, pair in enumerate(
            ((PARTIES[0], PARTIES[1]), (PARTIES[0], PARTIES[2]), (PARTIES[1], PARTIES[2])), 10010
        ):
            body = signing_request(g, c, receipts, n, pair)
            sid = body["binding"]["authorized"]["intent"]["session_id"]
            code, created = call_coordinator(g, "", body)
            assert code == 200 and created["status"] == "CREATED"
            assert call_coordinator(g, "", body) == (200, created)
            # Distinct wires/crypto IDs must not hide conflicting logical ownership.
            contradictory_operation = signing_request(
                g, c, receipts, n, pair, amount=2000000, attempt=n + 20000
            )
            assert call_coordinator(g, "", contradictory_operation)[0] == 409
            contradictory_attempt = signing_request(
                g, c, receipts, n + 20000, pair, amount=2000000, attempt=n
            )
            assert call_coordinator(g, "", contradictory_attempt)[0] == 409
            changed = copy.deepcopy(body)
            changed["binding"]["authorized"]["intent"]["operation_id"] += 1
            assert call_coordinator(g, "", changed)[0] == 409
            code, result = call_coordinator(g, f"/{sid}/execute")
            assert code == 200 and result["status"] == "COMPLETED", result
            record = json.loads(
                (root_path / "protected-coordinator-public" / f"{sid}.json").read_bytes()
            )
            assert len(record["round1"]) == len(record["round2"]) == 2
            assert record["signing_package"] is not None
            assert all(
                r["value"]["signing_package"] == record["signing_package"]
                for r in record["round2"].values()
            )
            g.net.stop("coordinator")
            g.net.start("coordinator")
            assert call_coordinator(g, f"/{sid}", method="GET") == (200, result)
            assert call_coordinator(g, f"/{sid}/execute") == (200, result)
            assert call_coordinator(g, f"/{sid}/reconcile") == (200, result)
            finalized.append(
                g.broadcast(body["binding"], bytes.fromhex(result["signature_hex"]))[0]
            )
        assert all(
            hashlib.sha256(f.read_bytes()).hexdigest() == digest for f, digest in original.items()
        )
        stale = signing_request(g, c, receipts, 10020)
        view = g.w.query()
        assert (
            g.w.request("command", g.w.command({"kind": "Freeze"}, view["root"]["revision"]))[0]
            == 200
        )
        code, created = call_coordinator(g, "", stale)
        assert code == 200 and created["status"] == "CREATED"
        stale_sid = stale["binding"]["authorized"]["intent"]["session_id"]
        code, refused = call_coordinator(g, f"/{stale_sid}/execute")
        assert code == 200 and refused["status"] == "RECONCILIATION_REQUIRED"
        assert not refused["round1"] and not refused["round2"]
        # Original public outcomes remain recoverable after lifecycle changes.
        assert call_coordinator(g, f"/{sid}/reconcile") == (200, result)
        private_file(
            root_path / "solana-protected-coordinator-public-evidence.json",
            json.dumps(
                {
                    "scope": (
                        "typed durable coordinator, genuine MPC and finalized transfers; "
                        "synthetic refs/no ledger"
                    ),
                    "unconfigured_typed_routes_absent": True,
                    "immutable_original_request_reports_and_first_r2_package": True,
                    "completed_public_signature_recovery_after_coordinator_restart": True,
                    "stale_active_view_cannot_bypass_live_frozen_witness": True,
                    "conflicting_logical_operation_and_attempt_rejected_before_dispatch": True,
                    "all_three_fixed_pairs_finalized": len(finalized),
                    "transaction_ids": finalized,
                    "original_three_dkg_ciphertexts_unchanged": True,
                    "backend_ledger_or_financial_wallet_activation_executed": False,
                    "public_store_directory_is_separate": bool(profile["directory"]),
                },
                sort_keys=True,
            ).encode(),
        )


def run_coordinator_fault(root_path, fault):
    with financial_group(root_path) as (g, c, receipts):
        enable_coordinator(g, root_path)
        body = signing_request(g, c, receipts, 10100)
        intent = body["binding"]["authorized"]["intent"]
        sid = intent["session_id"]
        assert call_coordinator(g, "", body)[0] == 200
        party = PARTIES[1] if fault in ("last_r2", "before_record", "invalid_share") else PARTIES[0]

        def fail_public_write(job_id):
            original = g.coordinator_directory / f"{job_id}.json"
            original.rename(original.with_suffix(".json.tmp-held"))
            original.mkdir()

        relay = SignerRelay(
            g, party, fault, fail_public_write if fault == "write_failure" else None
        )
        finalized = []
        try:
            if fault in ("client_disconnect", "coordinator_restart"):
                identity = g.net.root / "custody" / "identity"
                context = ssl.create_default_context(cafile=str(identity / "ca.crt"))
                context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
                context.load_cert_chain(identity / "tls.crt", identity / "tls.key")
                conn = http.client.HTTPSConnection(
                    "localhost", g.net.ports["coordinator"], context=context, timeout=20
                )
                try:
                    conn.request("POST", PREFIX + f"/{sid}/execute")
                    assert relay.entered.wait(15), relay.errors
                    status = call_coordinator(g, f"/{sid}/execute")[1]
                    assert status["status"] == "IN_PROGRESS"
                    conn.close()
                    if fault == "coordinator_restart":
                        g.net.stop("coordinator")
                    relay.release.set()
                    if fault == "client_disconnect":
                        deadline = time.monotonic() + 15
                        while time.monotonic() < deadline:
                            status = call_coordinator(g, f"/{sid}", method="GET")[1]
                            if status["status"] == "COMPLETED":
                                break
                            time.sleep(0.05)
                        assert status["status"] == "COMPLETED", status
                    else:
                        g.net.start("coordinator")
                finally:
                    conn.close()
            else:
                code, status = call_coordinator(g, f"/{sid}/execute")
                assert relay.entered.is_set(), relay.errors
                if fault == "write_failure":
                    assert code == 409
                    assert call_coordinator(g, f"/{sid}", method="GET")[0] == 409
                    original = g.coordinator_directory / f"{sid}.json"
                    g.net.stop("coordinator")
                    shutil.rmtree(original)
                    original.with_suffix(".json.tmp-held").rename(original)
                    g.net.start("coordinator")
                else:
                    assert code == 200 and status["status"] == "RECONCILIATION_REQUIRED"
                    if fault == "invalid_share":
                        assert len(status["round2"]) == 1
                        assert party not in status["round2"]
            g.net.stop("coordinator")
            g.net.start("coordinator")
            private_calls = Counter(relay.calls)
            code, recovered = call_coordinator(g, f"/{sid}/reconcile")
            assert code == 200
            if fault in ("last_r2", "before_record", "client_disconnect", "invalid_share"):
                assert recovered["status"] == "COMPLETED", recovered
                execution = g.w.query(intent["crypto_execution_id"])["execution"]
                if fault == "before_record":
                    assert execution["status"] == "Open"
                    # Existing courier delivers authentic recovered public reports;
                    # the coordinator's Completed alone does not certify W state.
                    for report in recovered["round2"].values():
                        code, ack = g.w.request("record", report, identity=g.w.courier)
                        assert code == 200
                        verify(g.w.identity, "WITNESS_ACK_V1", ack)
                    execution = g.w.query(intent["crypto_execution_id"])["execution"]
                assert execution["status"] == "SignedPending"
                assert execution["signature"] == recovered["signature_hex"]
                finalized.append(
                    g.broadcast(body["binding"], bytes.fromhex(recovered["signature_hex"]))[0]
                )
            else:
                assert recovered["status"] == "RECONCILIATION_REQUIRED", recovered
                assert recovered["signature_hex"] is None
                assert len(recovered["round2"]) == (0 if fault == "round1" else 1)
            assert call_coordinator(g, f"/{sid}/execute") == (200, recovered)
            assert call_coordinator(g, f"/{sid}/reconcile") == (200, recovered)
            assert all(
                count == private_calls[(action, round_number)]
                for (action, round_number), count in relay.calls.items()
                if action == "auto"
            ), "public recovery caused new private dispatch"
            assert not relay.errors, relay.errors
            private_file(
                root_path / f"solana-protected-coordinator-{fault}-public-evidence.json",
                json.dumps(
                    {
                        "scope": "genuine crypto fault acceptance; synthetic refs/no DB ledger",
                        "fault": fault,
                        "status": recovered["status"],
                        "round1_reports": len(recovered["round1"]),
                        "round2_reports": len(recovered["round2"]),
                        "recovery_dispatched_no_private_work": True,
                        "first_package_present_before_r2_rpc": fault != "round1",
                        "coordinator_completed_is_signature_only": True,
                        "transaction_ids": finalized,
                    },
                    sort_keys=True,
                ).encode(),
            )
        finally:
            relay.close()
