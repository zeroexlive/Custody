"""Independent witness process with genuine three-party original DKG receipts.

These cases exercise authorization and durable private-round permission only;
they do not claim an on-chain payout or protected-signer integration.
"""

import copy
import hashlib
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from custody.mpc_request_auth import _authorize_message, _canonical
from custody.solana_seeded import account_address, build_native_transfer
from environment import ca, issue, private_file
from seeded_enrollment import approval, call, claim, enroll_all, fresh_root, services
from solders.pubkey import Pubkey
from test_dkg import PARTIES


def fingerprint(domain, value):
    return hashlib.sha256(domain.encode() + b"\0" + _canonical(value)).hexdigest()


def key_id(identity):
    public = x509.load_pem_x509_certificate((identity / "tls.crt").read_bytes()).public_key()
    return hashlib.sha256(
        public.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
    ).hexdigest()


def sign(identity, domain, value):
    ident = key_id(identity)
    key = serialization.load_pem_private_key((identity / "tls.key").read_bytes(), None)
    message = f"Wallet-MPC/{domain}\0".encode() + _canonical({"key_id": ident, "value": value})
    return {
        "key_id": ident,
        "value": value,
        "signature": key.sign(message, ec.ECDSA(hashes.SHA256())).hex(),
    }


def verify(identity, domain, signed):
    assert signed["key_id"] == key_id(identity)
    cert = x509.load_pem_x509_certificate((identity / "tls.crt").read_bytes())
    message = f"Wallet-MPC/{domain}\0".encode() + _canonical(
        {"key_id": signed["key_id"], "value": signed["value"]}
    )
    cert.public_key().verify(bytes.fromhex(signed["signature"]), message, ec.ECDSA(hashes.SHA256()))
    return signed["value"]


class Witness:
    def __init__(self, net, root, *, name="witness"):
        self.net, self.root = net, root
        custody_class = root.get("wallet_class", "HOT")
        self.directory = net.root / name
        self.identity = self.directory / "identity"
        self.issuer = ca()
        issue(self.identity, "witness", self.issuer)
        self.life = self.directory / "lifecycle"
        issue(self.life, "lifecycle", ca())
        self.policy = self.directory / "policy"
        issue(self.policy, f"policy-{custody_class.lower()}", ca())
        self.courier = self.directory / "courier"
        issue(self.courier, "courier", ca())
        self.node = {p: net.root / p / "identity" for p in PARTIES}
        self.custody = net.root / "custody" / "identity"
        roots = (
            (self.custody / "ca.crt").read_bytes()
            + (self.life / "ca.crt").read_bytes()
            + (self.courier / "ca.crt").read_bytes()
        )
        private_file(self.identity / "clients.crt", roots)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.config = {
            "environment": "isolated-development-v1",
            "anchor_id": str(uuid.uuid4()),
            "directory": str(self.directory / "journal"),
            "bind": f"127.0.0.1:{self.port}",
            "tls_ca": str(self.identity / "clients.crt"),
            "tls_cert": str(self.identity / "tls.crt"),
            "tls_key": str(self.identity / "tls.key"),
            "archived_witness_certificates": [],
            "lifecycle_certificate": str(self.life / "tls.crt"),
            "profiles": {
                custody_class: {
                    "genesis_hash": root["genesis_hash"],
                    "genesis_artifact_sha256": hashlib.sha256(
                        b"isolated witness test artifact"
                    ).hexdigest(),
                    "policy_version": 7,
                    "max_fee_lamports": 20000,
                    "max_rent_lamports": 3000000,
                    "max_lifetime_seconds": 120,
                    "custody_ca": str(self.custody / "ca.crt"),
                    "custody_certificate": str(self.custody / "tls.crt"),
                    "policy_ca": str(self.policy / "ca.crt"),
                    "policy_certificate": str(self.policy / "tls.crt"),
                    "node_certificates": {p: [str(d / "tls.crt")] for p, d in self.node.items()},
                    "receipt_certificates": {p: [str(d / "tls.crt")] for p, d in self.node.items()},
                }
            },
        }
        self.process = None

    def launch(self, initialize=False):
        private_file(self.directory / "config.json", json.dumps(self.config).encode())
        log = (self.directory / "service.log").open("ab")
        try:
            return subprocess.Popen(
                [
                    str(self.net.bin / "wallet-mpc-witness"),
                    *(["--initialize"] if initialize else []),
                ],
                env=os.environ | {"MPC_WITNESS_CONFIG": str(self.directory / "config.json")},
                stdout=log,
                stderr=log,
            )
        finally:
            log.close()

    def start(self, initialize=False):
        self.process = self.launch(initialize)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError((self.directory / "service.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.05)
        raise AssertionError("witness failed to listen")

    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=10)
            self.process = None

    def rejected_start(self, initialize=False):
        process = self.launch(initialize)
        try:
            assert process.wait(timeout=10) != 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    def request(self, action, body, *, identity=None, raw=False):
        identity = identity or self.life
        context = ssl.create_default_context(cafile=str(self.identity / "ca.crt"))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(identity / "tls.crt", identity / "tls.key")
        connection = http.client.HTTPSConnection(
            "localhost", self.port, context=context, timeout=15
        )
        try:
            connection.request(
                "POST",
                f"/v1/witness/{action}",
                json.dumps(body),
                {"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            data = response.read()
            return response.status, data if raw else json.loads(data)
        finally:
            connection.close()

    def command(self, action, revision=1):
        return sign(
            self.life,
            "WITNESS_COMMAND_V1",
            {
                "anchor_id": self.config["anchor_id"],
                "request_id": str(uuid.uuid4()),
                "root_identity": fingerprint("SOLANA_SEEDED_ROOT_V1", self.root),
                "expected_revision": revision,
                "expires_at": int(time.time()) + 120,
                "action": action,
            },
        )

    def enroll(self, receipts):
        body = self.command(
            {
                "kind": "Enroll",
                "evidence": {
                    "statement": self.root,
                    "participant_agreement": receipts,
                },
                "node_keys": {p: key_id(d) for p, d in self.node.items()},
            },
            0,
        )
        code, response = self.request("command", body)
        assert code == 200
        verify(self.identity, "WITNESS_ACK_V1", response)

    def register_claim(self, claim_value, receipts):
        value = {
            "kind": "RegisterClaim",
            "evidence": {"statement": claim_value, "participant_agreement": receipts},
        }
        body = self.command(value, self.query()["root"]["revision"])
        code, response = self.request("command", body)
        assert code == 200
        verify(self.identity, "WITNESS_ACK_V1", response)
        return body, response

    def query(self, execution=None, claim_id=None):
        query = {
            "anchor_id": self.config["anchor_id"],
            "root_identity": fingerprint("SOLANA_SEEDED_ROOT_V1", self.root),
            "challenge": os.urandom(32).hex(),
            "execution_id": execution,
        }
        if claim_id is not None:
            query["claim_reservation_id"] = claim_id
        body = sign(
            self.life,
            "WITNESS_QUERY_V1",
            query,
        )
        code, response = self.request("query", body)
        assert code == 200
        return verify(self.identity, "WITNESS_QUERY_REPLY_V1", response)

    def binding(self, claim_value, receipts):
        base = str(Pubkey.from_bytes(bytes.fromhex(self.root["group_public_key"])))
        destination = str(Pubkey.from_bytes(hashlib.sha256(b"witness-test-target").digest()))
        block = str(Pubkey.from_bytes(hashlib.sha256(b"non-chain-witness-only-test").digest()))
        payload = build_native_transfer(base, claim_value["index"], destination, 500000, block)
        now = int(time.time())
        intent = {
            "version": "solana_seeded_intent_v1",
            "claim": claim_value,
            "generation": {
                "epoch": 0,
                "ceremony_id": self.root["dkg"]["execution_id"],
                "public_key_package_sha256": hashlib.sha256(
                    bytes(self.root["public_key_package"])
                ).hexdigest(),
            },
            "session_id": str(uuid.uuid4()),
            "crypto_execution_id": str(uuid.uuid4()),
            "attempt_id": 1,
            "operation_id": 1,
            "operation_type": "SWEEP",
            "asset_key": "SOL",
            "financial_source": account_address(base, claim_value["index"]),
            "fee_payer": base,
            "rent_payer": None,
            "action": {"kind": "NativeTransfer", "destination": destination, "amount": 500000},
            "recent_blockhash": block,
            "last_valid_block_height": 100,
            "policy_version": 7,
            "expected_fee_lamports": 5000,
            "expected_rent_lamports": 0,
            "issued_at": now,
            "expires_at": now + 100,
            "message_fingerprint": hashlib.sha256(payload).hexdigest(),
        }
        return self.authorize(
            {
                "intent": intent,
                "payload_hex": payload.hex(),
                "claim_evidence": {"statement": claim_value, "participant_agreement": receipts},
            }
        )

    def authorize(self, authorized):
        a = copy.deepcopy(authorized)
        content = _canonical({"intent": a["intent"], "payload_hex": a["payload_hex"]})
        a["custody_authorization"] = _authorize_message(
            b"Wallet-MPC/CUSTODY_SOLANA_SEEDED_INTENT_V1\0" + content,
            self.custody / "tls.crt",
            self.custody / "tls.key",
        )
        # This independent policy grant deliberately uses another issuer/key and domain.
        key = serialization.load_pem_private_key((self.policy / "tls.key").read_bytes(), None)
        cert = x509.load_pem_x509_certificate((self.policy / "tls.crt").read_bytes())
        a["operator_authorization"] = {
            "certificate_chain_der_hex": [cert.public_bytes(serialization.Encoding.DER).hex()],
            "signature_der_hex": key.sign(
                b"Wallet-MPC/OPERATOR_SEEDED_SPEND_V1\0" + content, ec.ECDSA(hashes.SHA256())
            ).hex(),
        }
        return {"authorized": a, "selected_signers": list(PARTIES[:2])}

    def permit(self, binding, party=PARTIES[0]):
        return sign(
            self.node[party],
            "WITNESS_PERMIT_REQUEST_V1",
            {
                "anchor_id": self.config["anchor_id"],
                "binding": binding,
                "party_id": party,
                "round": 1,
                "challenge": os.urandom(32).hex(),
                "expires_at": int(time.time()) + 15,
                "signing_package": None,
            },
        )


def original(net):
    root, _ = fresh_root(net)
    root["ownership_scope"] = str(uuid.uuid4())
    receipts = enroll_all(net, root)
    c = claim(root, owner=f"p1:{uuid.uuid4()}")
    reports = []
    for party in PARTIES:
        code, report = call(net, party, "approve", approval(net, "claim", c))
        assert code == 200
        reports.append(report)
    return root, receipts, c, reports


def run_authorization(root_path):
    with services(root_path / "services") as net:
        root, receipts, c, reports = original(net)
        w = Witness(net, root)
        try:
            w.start(initialize=True)
            forged = copy.deepcopy(receipts)
            forged[0]["signer_signature"] = "00" * 70
            body = w.command(
                {
                    "kind": "Enroll",
                    "evidence": {"statement": root, "participant_agreement": forged},
                    "node_keys": {p: key_id(d) for p, d in w.node.items()},
                },
                0,
            )
            assert w.request("command", body)[0] == 409
            w.enroll(receipts)
            w.register_claim(c, reports)
            binding = w.binding(c, reports)
            for fault in (
                "policy",
                "custody",
                "claim",
                "network",
                "epoch",
                "anchor",
                "identity",
                "expiry",
            ):
                bad = copy.deepcopy(binding)
                if fault == "policy":
                    bad["authorized"]["operator_authorization"] = bad["authorized"][
                        "custody_authorization"
                    ]
                elif fault == "custody":
                    bad["authorized"]["custody_authorization"] = bad["authorized"][
                        "operator_authorization"
                    ]
                elif fault == "claim":
                    bad["authorized"]["claim_evidence"]["participant_agreement"][1][
                        "signer_signature"
                    ] = "00" * 70
                elif fault in ("network", "epoch"):
                    if fault == "network":
                        bad["authorized"]["intent"]["claim"]["root"]["genesis_hash"] = str(
                            Pubkey.from_bytes(b"x" * 32)
                        )
                    else:
                        bad["authorized"]["intent"]["generation"]["epoch"] += 1
                    bad = w.authorize(bad["authorized"])
                body = w.permit(bad)
                if fault in ("anchor", "identity", "expiry"):
                    if fault == "anchor":
                        body["value"]["anchor_id"] = str(uuid.uuid4())
                    elif fault == "expiry":
                        body["value"]["expires_at"] = int(time.time()) - 1
                    else:
                        body["signature"] = "00" * 70
                    if fault != "identity":
                        body = sign(w.node[PARTIES[0]], "WITNESS_PERMIT_REQUEST_V1", body["value"])
                assert w.request("permit", body, identity=w.node[PARTIES[0]])[0] == 409, fault
            assert w.query()["sequence"] == 2
            body = w.permit(binding)
            assert w.request("permit", body, identity=w.node[PARTIES[1]])[0] == 403
            code, response = w.request("permit", body, identity=w.courier)
            assert code == 200
            permit = verify(w.identity, "WITNESS_PERMIT_V1", response)
            assert permit["request"] == body["value"] and permit["sequence"] == 3
            # Neither an identical request nor a fresh challenge permits secret retries.
            assert w.request("permit", body, identity=w.node[PARTIES[0]])[0] == 409
            assert w.request("permit", w.permit(binding), identity=w.node[PARTIES[0]])[0] == 409
            new = copy.deepcopy(binding)
            new["authorized"]["intent"]["crypto_execution_id"] = str(uuid.uuid4())
            new["authorized"]["intent"]["session_id"] = str(uuid.uuid4())
            new["authorized"]["intent"]["attempt_id"] += 1
            new = w.authorize(new["authorized"])
            assert w.request("permit", w.permit(new), identity=w.node[PARTIES[0]])[0] == 409
            other_operation = copy.deepcopy(new)
            other_operation["authorized"]["intent"]["operation_id"] += 1
            other_operation["authorized"]["intent"]["attempt_id"] += 100
            other_operation = w.authorize(other_operation["authorized"])
            assert w.request("permit", w.permit(other_operation), identity=w.courier)[0] == 409
            w.stop()
            w.start()
            assert w.query()["sequence"] == 3
            assert w.request("permit", w.permit(binding), identity=w.node[PARTIES[0]])[0] == 409
            close = w.command(
                {
                    "kind": "CloseNoSignature",
                    "execution_id": binding["authorized"]["intent"]["crypto_execution_id"],
                },
                3,
            )
            assert w.request("command", close)[0] == 200
            # Even after a proven zero-R2 closure, this exact wire remains owned
            # by the original logical operation, not a different payout record.
            assert w.request("permit", w.permit(other_operation), identity=w.courier)[0] == 409
            assert w.request("permit", w.permit(new), identity=w.node[PARTIES[0]])[0] == 200
        finally:
            w.stop()


def run_durability(root_path):
    with services(root_path / "services") as net:
        root, receipts, c, reports = original(net)
        w = Witness(net, root)
        try:
            w.rejected_start()  # No automatic recovery of missing authority history.
            w.start(initialize=True)
            w.enroll(receipts)
            w.register_claim(c, reports)
            w.rejected_start()  # Exclusive durable writer lock, before bind.
            binding = w.binding(c, reports)
            old_head = Path(w.config["directory"], "initialized.json").read_bytes()
            # Lost response after a genuine successful permit still consumes the slot.
            code, _ = w.request("permit", w.permit(binding), identity=w.node[PARTIES[0]])
            assert code == 200
            w.stop()
            directory = Path(w.config["directory"])
            backup = w.directory / "original-journal"
            shutil.copytree(directory, backup)
            # Crash window: immutable grant exists, head publication absent. Replaying
            # this write-ahead event must retain the grant and advance the signed head.
            private_file(directory / "initialized.json", old_head)
            w.start()
            assert w.query()["sequence"] == 3
            assert w.request("permit", w.permit(binding), identity=w.node[PARTIES[0]])[0] == 409
            w.stop()
            for fault in ("tail", "middle", "event", "head", "missing-head", "reinitialize"):
                shutil.rmtree(directory)
                shutil.copytree(backup, directory)
                if fault in ("tail", "middle"):
                    (directory / "events" / f"{3 if fault == 'tail' else 1:020}.json").unlink()
                elif fault == "event":
                    event = directory / "events" / f"{3:020}.json"
                    value = json.loads(event.read_bytes())
                    value["value"]["time"] += 1
                    private_file(event, json.dumps(value).encode())
                elif fault in ("head", "missing-head"):
                    (directory / "initialized.json").unlink()
                    if fault == "head":
                        private_file(directory / "initialized.json", b"{}")
                w.rejected_start(initialize=fault == "reinitialize")
            shutil.rmtree(directory)
            shutil.copytree(backup, directory)
            w.start()
            # Two genuine signed requests race under one durable CAS. Exactly one
            # party-round grant is issued even though their challenges differ.
            requests = [w.permit(binding, PARTIES[1]) for _ in range(2)]
            with ThreadPoolExecutor(max_workers=2) as pool:
                codes = list(
                    pool.map(
                        lambda r: w.request("permit", r, identity=w.node[PARTIES[1]])[0], requests
                    )
                )
            assert sorted(codes) == [200, 409]
            revision = w.query()["root"]["revision"]
            absent = str(uuid.uuid4())
            close = w.command({"kind": "CloseNoSignature", "execution_id": absent}, revision)
            assert w.request("command", close)[0] == 200
            w.stop()
            w.start()
            assert w.query(absent)["abandoned"] is True
        finally:
            w.stop()


def run_transport_pin(root_path):
    """Exercise the actual Rust AuthorityClient, not Python's TLS client."""
    from environment import Processes

    net = Processes(root_path / "services")
    w = Witness(net, {"genesis_hash": str(Pubkey.from_bytes(b"g" * 32))})
    other = w.directory / "other-valid-witness"
    issue(other, "witness", w.issuer)
    for certificate, expected in ((w.identity, 0), (other, 1)):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certificate / "tls.crt", certificate / "tls.key")
        context.load_verify_locations(cafile=str(w.custody / "ca.crt"))
        context.verify_mode = ssl.CERT_REQUIRED
        observed = {"handshake": False, "http": b"", "error": None, "reason": None}
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)

            def server():
                try:
                    conn, _ = listener.accept()
                    with context.wrap_socket(conn, server_side=True) as stream:
                        observed["handshake"] = True
                        stream.settimeout(5)
                        data = b""
                        try:
                            data = stream.recv(4096)
                            observed["http"] = data
                            while data and len(data) < 8192:
                                headers, separator, body = data.partition(b"\r\n\r\n")
                                lengths = [
                                    line.split(b":", 1)[1].strip()
                                    for line in headers.split(b"\r\n")
                                    if line.lower().startswith(b"content-length:")
                                ]
                                if separator and lengths and len(body) >= int(lengths[0]):
                                    break
                                chunk = stream.recv(4096)
                                if not chunk:
                                    break
                                data += chunk
                                observed["http"] = data
                        except (ssl.SSLError, ConnectionResetError):
                            pass  # Retain every byte already received, including partial headers.
                        if data:
                            stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                except Exception as error:
                    observed["error"] = type(error).__name__
                    observed["reason"] = str(error)

            thread = threading.Thread(target=server, daemon=True)
            thread.start()
            process = subprocess.run(
                [
                    str(net.bin / "examples" / "authority_client_probe"),
                    str(w.identity / "ca.crt"),
                    str(w.node[PARTIES[0]] / "tls.crt"),
                    str(w.node[PARTIES[0]] / "tls.key"),
                    f"127.0.0.1:{listener.getsockname()[1]}",
                    str(w.identity / "tls.crt"),
                ],
                capture_output=True,
                timeout=15,
                check=False,
            )
            thread.join(timeout=10)
            assert not thread.is_alive()
            if expected == 0:
                assert observed["error"] is None and observed["handshake"]
                assert process.returncode == 0, process.stderr.decode()
                assert b"must-not-reach-an-unpinned-server" in observed["http"]
            else:
                assert process.returncode != 0
                assert b"authority TLS key pin mismatch" in process.stderr
                # rustls has validated the same-CA witness chain/role before
                # checking the pin. Closing at that point may reset the peer
                # before its final TLS flight is observed; neither case sends HTTP.
                assert observed["error"] in (
                    None,
                    "ConnectionResetError",
                    "SSLEOFError",
                    "BrokenPipeError",
                ), observed
                assert observed["http"] == b""  # No HTTP headers OR public partial body escaped.


def run_claim_rollback_fence(root_path):
    with services(root_path / "services") as net:
        root, _ = fresh_root(net)
        root["ownership_scope"] = str(uuid.uuid4())
        root_receipts = enroll_all(net, root)
        backups = root_path / "pre-claim-backups"
        for p in PARTIES:
            shutil.copytree(net.root / p / "storage", backups / p)

        def approve_all(c):
            reports = []
            for p in PARTIES:
                code, receipt = call(net, p, "approve", approval(net, "claim", c))
                assert code == 200
                reports.append(receipt)
            return reports

        original_claim = claim(root, owner=f"p1:{uuid.uuid4()}")
        original_receipts = approve_all(original_claim)
        w = Witness(net, root)
        try:
            w.start(initialize=True)
            w.enroll(root_receipts)
            original_command, original_ack = w.register_claim(original_claim, original_receipts)
            # The response may be lost before issuance. Exact command retry and
            # fresh authenticated query recover original public registration.
            w.stop()
            w.start()
            code, recovered_ack = w.request("command", original_command)
            assert code == 200 and recovered_ack["value"] == original_ack["value"]
            view = w.query(claim_id=original_claim["reservation_id"])
            assert view["claim"]["statement"] == original_claim
            assert view["root"]["next_claim_index"] == 1
            assert view["execution"] is None  # Original claim has NEVER spent.
            for p in PARTIES:
                net.stop(p)
                shutil.rmtree(net.root / p / "storage")
                shutil.copytree(backups / p, net.root / p / "storage")
                net.start(p)
            fork = claim(root, owner=f"p1:{uuid.uuid4()}")
            fork_receipts = approve_all(fork)  # Three authentic signatures after backup restore.
            register = w.command(
                {
                    "kind": "RegisterClaim",
                    "evidence": {
                        "statement": fork,
                        "participant_agreement": fork_receipts,
                    },
                },
                w.query()["root"]["revision"],
            )
            assert w.request("command", register)[0] == 409
            binding = w.binding(fork, fork_receipts)
            assert w.request("permit", w.permit(binding), identity=w.node[PARTIES[0]])[0] == 409
            assert (
                w.query(claim_id=original_claim["reservation_id"])["claim"]["statement"]
                == original_claim
            )

            # Reservation UUID is global across roots, even when every local
            # signer has lost the old alias and independently signs the new one.
            second_root, _ = fresh_root(net)
            second_root["ownership_scope"] = root["ownership_scope"]
            second_root_receipts = enroll_all(net, second_root)
            second_claim = claim(second_root, owner=f"p1:{uuid.uuid4()}")
            second_claim["reservation_id"] = original_claim["reservation_id"]
            second_receipts = approve_all(second_claim)
            w.root = second_root
            w.enroll(second_root_receipts)
            collision = w.command(
                {
                    "kind": "RegisterClaim",
                    "evidence": {
                        "statement": second_claim,
                        "participant_agreement": second_receipts,
                    },
                },
                w.query()["root"]["revision"],
            )
            assert w.request("command", collision)[0] == 409
            assert w.query()["root"]["next_claim_index"] == 0
            w.root = root
            assert (
                w.query(claim_id=original_claim["reservation_id"])["claim"]["statement"]
                == original_claim
            )
        finally:
            w.stop()


def run_detached_node_pins(root_path):
    with services(root_path / "services") as net:
        root, receipts, c, reports = original(net)
        issuer_cert = x509.load_pem_x509_certificate(
            (net.root / PARTIES[0] / "identity" / "ca.crt").read_bytes()
        )
        issuer_key = serialization.load_pem_private_key(
            (net.root / "issuer" / "ca.key").read_bytes(), None
        )
        original_cert = x509.load_pem_x509_certificate(
            (net.root / PARTIES[0] / "identity" / "tls.crt").read_bytes()
        )
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(original_cert.subject)
            .issuer_name(issuer_cert.subject)
            .public_key(original_cert.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(now - timedelta(days=1))
        )
        for extension in original_cert.extensions:
            builder = builder.add_extension(extension.value, extension.critical)
        expired = builder.sign(issuer_key, hashes.SHA256())
        w = Witness(net, root)
        expired_path = w.directory / "expired-current-node.crt"
        private_file(expired_path, expired.public_bytes(serialization.Encoding.PEM))
        nonactive = w.directory / "configured-nonactive-node"
        issue(nonactive, PARTIES[0], (issuer_key, issuer_cert))
        w.config["profiles"]["HOT"]["node_certificates"][PARTIES[0]] = [
            str(expired_path),
            str(nonactive / "tls.crt"),
        ]
        try:
            w.start(initialize=True)
            w.enroll(receipts)
            w.register_claim(c, reports)
            binding = w.binding(c, reports)
            request = w.permit(binding)
            archival = sign(nonactive, "WITNESS_PERMIT_REQUEST_V1", request["value"])
            assert w.request("permit", archival, identity=w.courier)[0] == 409
            code, permit = w.request("permit", request, identity=w.courier)
            assert code == 200
            verify(w.identity, "WITNESS_PERMIT_V1", permit)
            # Detached node authority is the CURRENT root pin, independent of
            # this expired certificate's time window. Live custody/operator
            # proofs and courier mTLS remain time-valid and independently checked.
            assert permit["value"]["request"] == request["value"]
        finally:
            w.stop()
