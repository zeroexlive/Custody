"""Genuine protected FROST processes, independent witness and pinned Agave.

No private DKG package, signing key or nonce leaves its owning signer process.
The helper only assembles public signing packages and finalized transactions.
"""

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from custody.mpc_request_auth import _authorize_message, _canonical
from custody.solana_seeded import (
    account_address,
    build_native_transfer,
    build_token_creation,
    build_token_transfer,
)
from custody.spl import derive_ata
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM
from environment import Processes, ca, issue, private_file
from seeded_enrollment import approval, call, claim, enroll_all
from solana_local.validator import Validator
from solders.instruction import AccountMeta, Instruction
from solders.message import Message
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import Transaction
from test_dkg import PARTIES, dkg_request, execute, request
from witness_acceptance import Witness, sign, verify

PREFIX = "/internal/v1/solana/protected/"


class DelayedRpc:
    """Fault injection only: every response still comes from the real validator."""

    def __init__(self, validator):
        self.hold_until = None
        self.entered = None
        self.released = None
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                query = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if proxy.hold_until:
                    if proxy.entered is None:
                        proxy.entered = time.time()
                    # Each real RPC stays below its unchanged 5s deadline. The
                    # cumulative six checks cross the permit lifetime instead.
                    deadline = min(proxy.hold_until, time.time() + 3)
                    threading.Event().wait(max(0, deadline - time.time()))
                    proxy.released = time.time()
                    if proxy.released >= proxy.hold_until:
                        proxy.hold_until = None
                # Forward the actual RPC result. No fee/account/genesis evidence is fabricated.
                result = validator.rpc(query["method"], query["params"])
                body = json.dumps({"jsonrpc": "2.0", "id": query["id"], "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.address = f"127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class Group:
    def __init__(self, net, witness, validator, custody_class, rpc_address=None):
        self.net, self.w, self.validator, self.custody_class = (
            net,
            witness,
            validator,
            custody_class,
        )
        self.profiles = {}
        for party in PARTIES:
            env = net.configs[party]
            identity = net.root / party / "identity"
            tls = {k: str(identity / f"tls.{ext}") for k, ext in (("cert", "crt"), ("key", "key"))}
            tls["ca"] = str(identity / "ca.crt")
            if custody_class == "COLD":
                bundle = (identity / "ca.crt").read_bytes() + (
                    witness.courier / "ca.crt"
                ).read_bytes()
                private_file(identity / "protected-clients.crt", bundle)
                tls["ca"] = str(identity / "protected-clients.crt")
            policy = copy.deepcopy(witness.config["profiles"][custody_class])
            del policy["node_certificates"]
            self.profiles[party] = {
                "environment": "isolated-development-protected-v1",
                "class": custody_class,
                "anchor_directory": str(net.root / party / "protected-anchor"),
                "witness_anchor": witness.config["anchor_id"],
                "bind": env["MPC_BIND_ADDR"],
                "signer": {
                    "party_id": party,
                    "certificate_identity": env["MPC_CERTIFICATE_IDENTITY"],
                    "storage_directory": env["MPC_SHARE_STORAGE_DIR"],
                    "wrapping_key_path": env["MPC_WRAPPING_KEY_FILE"],
                    "supported_algorithms": ["FROST_ED25519"],
                    "trusted_peers": dict(
                        s.split("=", 1) for s in env["MPC_TRUSTED_PEERS"].split(",")
                    ),
                },
                "tls": tls,
                "peer_targets": [[p, f"127.0.0.1:{net.ports[p]}", "localhost"] for p in PARTIES],
                "witness_tls": dict(tls, ca=str(witness.identity / "ca.crt")),
                "witness_address": f"127.0.0.1:{witness.port}",
                "witness_server_name": "localhost",
                "witness_certificate": str(witness.identity / "tls.crt"),
                "rpc_address": rpc_address or f"127.0.0.1:{validator.port}",
                "policy": policy,
            }
            self.save(party)

    def save(self, party):
        path = self.net.root / party / "identity" / "protected.json"
        private_file(path, json.dumps(self.profiles[party]).encode())
        self.net.configs[party]["MPC_PROTECTED_PROFILE"] = str(path)

    def start(self, party, initialize=False):
        self.net.start(
            party,
            binary="wallet-mpc-protected-signer",
            arguments=("--initialize",) if initialize else (),
        )

    def rejected_start(self, party, *, initialize=False):
        process = subprocess.Popen(
            [
                str(self.net.bin / "wallet-mpc-protected-signer"),
                *(["--initialize"] if initialize else []),
            ],
            env=os.environ | self.net.configs[party],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            assert process.wait(timeout=10) != 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    def call(self, party, action, payload, role="coordinator"):
        return request(self.net, party, role, PREFIX + action, payload)

    def binding(self, c, receipts, operation=1, pair=PARTIES[:2], *, amount=1000000):
        binding = self.w.binding(c, receipts)
        i = binding["authorized"]["intent"]
        block = self.validator.rpc("getLatestBlockhash", [{"commitment": "finalized"}])["value"]
        i["recent_blockhash"] = block["blockhash"]
        i["last_valid_block_height"] = block["lastValidBlockHeight"]
        i["attempt_id"] = operation
        i["operation_id"] = operation
        i["action"]["amount"] = amount
        raw = build_native_transfer(
            i["fee_payer"],
            c["index"],
            i["action"]["destination"],
            i["action"]["amount"],
            i["recent_blockhash"],
        )
        i["message_fingerprint"] = hashlib.sha256(raw).hexdigest()
        binding["authorized"]["payload_hex"] = raw.hex()
        binding = self.w.authorize(binding["authorized"])
        binding["selected_signers"] = list(pair)
        return binding

    def token_binding(
        self, c, receipts, operation=1, pair=PARTIES[:2], *, create=False, create_ata=False
    ):
        authorized = self.w.binding(c, receipts)["authorized"]
        i = authorized["intent"]
        block = self.validator.rpc("getLatestBlockhash", [{"commitment": "finalized"}])["value"]
        base, mint = i["fee_payer"], c["asset"]["mint"]
        rent = self.validator.rpc("getMinimumBalanceForRentExemption", [165])
        i.update(
            recent_blockhash=block["blockhash"],
            last_valid_block_height=block["lastValidBlockHeight"],
            attempt_id=operation,
            operation_id=operation,
            asset_key="ISOLATED-SPL",
            financial_source=account_address(base, c["index"], token=True),
        )
        if create:
            i.update(
                operation_type="PROVISION",
                action={"kind": "CreateClassicToken", "rent_lamports": rent},
                rent_payer=base,
                expected_rent_lamports=rent,
            )
            raw = build_token_creation(base, c["index"], mint, rent, i["recent_blockhash"])
        else:
            owner = str(Pubkey.from_bytes(hashlib.sha256(b"protected-spl-target").digest()))
            target = derive_ata(owner, mint)
            exists = (
                self.validator.rpc(
                    "getAccountInfo", [target, {"commitment": "finalized", "encoding": "base64"}]
                )["value"]
                is not None
            )
            i.update(
                operation_type="SWEEP",
                action={
                    "kind": "ClassicTransfer",
                    "destination_owner": owner,
                    "amount": 1000000,
                    "create_ata": create_ata,
                },
                rent_payer=base if create_ata else None,
                expected_rent_lamports=rent if create_ata and not exists else 0,
            )
            raw = build_token_transfer(
                base,
                c["index"],
                mint,
                owner,
                1000000,
                c["asset"]["decimals"],
                i["recent_blockhash"],
                create_ata=create_ata,
            )
        i["message_fingerprint"] = hashlib.sha256(raw).hexdigest()
        authorized["payload_hex"] = raw.hex()
        binding = self.w.authorize(authorized)
        binding["selected_signers"] = list(pair)
        return binding

    def round(self, party, control):
        if self.custody_class != "COLD":
            code, report = self.call(party, "auto", control)
            assert code == 200, (party, code, report)
        else:
            # Explicit manual transport: signer challenge -> courier -> witness
            # -> courier -> original signer. No witness client exists in COLD.
            code, challenge = self.call(party, "challenge", control, "courier")
            assert code == 200
            code, permit = self.w.request("permit", challenge, identity=self.w.courier)
            assert code == 200
            code, report = self.call(party, "apply", permit, "courier")
            assert code == 200, (party, code, report)
            code, ack = self.w.request("record", report, identity=self.w.courier)
            assert code == 200
            verify(self.w.identity, "WITNESS_ACK_V1", ack)
        verify(self.w.node[party], "WITNESS_PUBLIC_ROUND_V1", report)
        return report

    def sign(self, binding):
        commitments = {}
        for p in binding["selected_signers"]:
            control = {"binding": binding, "round": 1, "signing_package": None}
            report = self.round(p, control)
            commitments[p] = report["value"]["commitments"]
        raw = bytes.fromhex(binding["authorized"]["payload_hex"])
        package = json.loads(
            subprocess.check_output(
                [str(self.net.bin / "examples" / "frost_signing_package")],
                input=json.dumps({"commitments": commitments, "message": list(raw)}).encode(),
            )
        )
        for p in binding["selected_signers"]:
            control = {"binding": binding, "round": 2, "signing_package": package}
            report = self.round(p, control)
            # Public result recovery is read-only and returns the exact signed
            # receipt. No refreshed proof or private round is involved.
            code, recovered = self.call(p, "recover", control)
            assert code == 200 and recovered == report
        result = self.w.query(binding["authorized"]["intent"]["crypto_execution_id"])
        assert result["execution"]["status"] == "SignedPending"
        signature = bytes.fromhex(result["execution"]["signature"])
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.w.root["group_public_key"])).verify(
            signature, raw
        )
        return signature

    def broadcast(self, binding, signature):
        tx = Transaction.populate(
            Message.from_bytes(bytes.fromhex(binding["authorized"]["payload_hex"])),
            [Signature.from_bytes(signature)],
        )
        result = self.validator.rpc(
            "sendTransaction", [base64.b64encode(bytes(tx)).decode(), {"encoding": "base64"}]
        )
        status, record = self.validator.wait(result)
        assert status["err"] is None and record["meta"]["err"] is None
        assert record["meta"]["fee"] == binding["authorized"]["intent"]["expected_fee_lamports"]
        return result, record


@contextmanager
def group(root_path, custody_class="HOT", *, delayed_rpc=False):
    validator = Validator(root_path / "validator")
    proxy = DelayedRpc(validator) if delayed_rpc else None
    net = Processes(root_path / "services")
    witness = None
    try:
        preliminary = {
            "genesis_hash": validator.policy["genesis_hash"],
            "wallet_class": custody_class,
        }
        witness = Witness(net, preliminary)
        witness.config["profiles"][custody_class]["genesis_artifact_sha256"] = validator.policy[
            "genesis_artifact_sha256"
        ]
        g = Group(net, witness, validator, custody_class, proxy.address if proxy else None)
        g.proxy = proxy
        net.start("coordinator")
        for party in PARTIES:
            g.rejected_start(party)  # Explicit bootstrap required outside backups.
            g.start(party, initialize=True)
        binding = dict(dkg_request(), custody_class=custody_class)
        code, dkg = execute(net, binding)
        assert code == 200 and dkg["status"] == "COMPLETED"
        root = {
            "dkg": binding,
            "group_public_key": dkg["group_public_key"],
            "public_key_package": dkg["participant_agreement"][0]["public_key_package"],
            "ownership_scope": str(uuid.uuid4()),
            "chain_id": "SOL",
            "genesis_hash": validator.policy["genesis_hash"],
            "purpose": "DEPOSIT",
            "wallet_class": custody_class,
            "derivation_version": "solana_seeded_v1",
            "generation": 0,
        }
        g.original_backups = {}
        for party in PARTIES:
            backup = root_path / f"pre-enrollment-{party}"
            shutil.copytree(net.root / party / "storage", backup)
            g.original_backups[party] = backup
        root_reports = enroll_all(net, root)
        c = claim(root, owner=f"p1:{uuid.uuid4()}")
        receipts = []
        for party in PARTIES:
            code, receipt = call(net, party, "approve", approval(net, "claim", c))
            assert code == 200
            receipts.append(receipt)
        witness.root = root
        witness.start(initialize=True)
        witness.enroll(root_reports)
        witness.register_claim(c, receipts)
        if custody_class == "COLD":
            courier = net.root / "courier" / "identity"
            shutil.copytree(witness.courier, courier)
            private_file(
                courier / "ca.crt", (net.root / PARTIES[0] / "identity" / "ca.crt").read_bytes()
            )
        base = str(Pubkey.from_bytes(bytes.fromhex(root["group_public_key"])))
        validator.fund(base, 200000000)
        validator.fund(account_address(base, c["index"]), 5000000)
        yield g, c, receipts
    finally:
        try:
            if witness:
                witness.stop()
        finally:
            try:
                net.close()
            finally:
                try:
                    if proxy:
                        proxy.close()
                finally:
                    validator.close()


def balance(g, address):
    return g.validator.rpc("getBalance", [address, {"commitment": "finalized"}])["value"]


def run_native_pairs(root_path):
    with group(root_path) as (g, c, receipts):
        original = g.binding(c, receipts)
        i = original["authorized"]["intent"]
        source_before = balance(g, i["financial_source"])
        base_before = balance(g, i["fee_payer"])
        destination = i["action"]["destination"]
        destination_before = balance(g, destination)
        for n, pair in enumerate(
            ((PARTIES[0], PARTIES[1]), (PARTIES[0], PARTIES[2]), (PARTIES[1], PARTIES[2])), 1
        ):
            binding = g.binding(c, receipts, n, pair)
            assert (
                g.call(
                    pair[0],
                    "auto",
                    {"binding": binding, "round": 1, "signing_package": None},
                    "custody",
                )[0]
                == 403
            )
            assert (
                request(
                    g.net, pair[0], "coordinator", "/internal/v1/sign/round1", {}, method="POST"
                )[0]
                == 404
            )
            sig = g.sign(binding)
            g.broadcast(binding, sig)
            # Public signature recovery does not allow a second execution with a
            # fresh UUID/blockhash to reuse the same financial operation.
            changed = g.binding(c, receipts, n, pair)
            assert (
                changed["authorized"]["intent"]["recent_blockhash"]
                != binding["authorized"]["intent"]["recent_blockhash"]
            )
            changed["authorized"]["intent"]["attempt_id"] += 100
            changed = g.w.authorize(changed["authorized"])
            changed["selected_signers"] = list(pair)
            assert (
                g.call(pair[0], "auto", {"binding": changed, "round": 1, "signing_package": None})[
                    0
                ]
                == 409
            )
        assert balance(g, i["financial_source"]) == source_before - 3000000
        assert balance(g, destination) == destination_before + 3000000
        assert balance(g, i["fee_payer"]) == base_before - 15000
        for p in PARTIES:
            g.net.stop(p)
            g.start(p)
        # Real private stores and independent execution journals reopen together.
        assert g.w.query()["root"]["generation"]["epoch"] == 0


def run_cold_courier(root_path):
    with group(root_path, "COLD") as (g, c, receipts):
        binding = g.binding(c, receipts)
        control = {"binding": binding, "round": 1, "signing_package": None}
        assert g.call(PARTIES[0], "auto", control)[0] == 409
        signature = g.sign(binding)
        g.broadcast(binding, signature)


def run_backup_and_partial(root_path):
    with group(root_path) as (g, c, receipts):
        binding = g.binding(c, receipts)
        first = {"binding": binding, "round": 1, "signing_package": None}
        r1 = {p: g.round(p, first) for p in PARTIES[:2]}
        raw = bytes.fromhex(binding["authorized"]["payload_hex"])
        package = json.loads(
            subprocess.check_output(
                [str(g.net.bin / "examples" / "frost_signing_package")],
                input=json.dumps(
                    {
                        "commitments": {p: r["value"]["commitments"] for p, r in r1.items()},
                        "message": list(raw),
                    }
                ).encode(),
            )
        )
        second = {"binding": binding, "round": 2, "signing_package": package}
        party = PARTIES[0]
        g.net.stop(party)
        storage = g.net.root / party / "storage"
        current = root_path / "approved-current-backup"
        shutil.copytree(storage, current)
        shutil.rmtree(storage)
        shutil.copytree(g.original_backups[party], storage)
        g.start(party)
        assert request(g.net, party, "coordinator", "/internal/v1/sign/round1", {})[0] == 404
        assert g.call(party, "auto", second)[0] == 409
        # Original public result recovery is safe even from a pre-enrollment
        # private backup: the independent public execution journal remains current.
        assert g.call(party, "recover", first) == (200, r1[party])
        g.net.stop(party)
        shutil.rmtree(storage)
        shutil.copytree(current, storage)
        g.start(party)
        assert g.call(party, "auto", second)[0] == 409  # Lost nonce, never regenerated.
        execution = binding["authorized"]["intent"]["crypto_execution_id"]
        view = g.w.query(execution)
        assert view["execution"]["status"] == "Open"
        close = g.w.command(
            {"kind": "CloseNoSignature", "execution_id": execution}, view["root"]["revision"]
        )
        assert g.w.request("command", close)[0] == 200
        # The old execution is terminal; a new authorized same-business attempt
        # is possible only after the witness atomically closes every old R2 path.
        renewed = g.binding(c, receipts, pair=(PARTIES[0], PARTIES[2]))
        renewed["authorized"]["intent"]["attempt_id"] = 2
        renewed = g.w.authorize(renewed["authorized"])
        renewed["selected_signers"] = [PARTIES[0], PARTIES[2]]
        signature = g.sign(renewed)
        g.broadcast(renewed, signature)
        assert g.call(PARTIES[1], "auto", second)[0] == 409


def run_r2_uncertainty(root_path):
    with group(root_path) as (g, c, receipts):
        binding = g.binding(c, receipts)
        first = {"binding": binding, "round": 1, "signing_package": None}
        r1 = {p: g.round(p, first) for p in PARTIES[:2]}
        package = json.loads(
            subprocess.check_output(
                [str(g.net.bin / "examples" / "frost_signing_package")],
                input=json.dumps(
                    {
                        "commitments": {p: r["value"]["commitments"] for p, r in r1.items()},
                        "message": list(bytes.fromhex(binding["authorized"]["payload_hex"])),
                    }
                ).encode(),
            )
        )
        second = {"binding": binding, "round": 2, "signing_package": package}
        party = PARTIES[0]
        code, challenge = g.call(party, "challenge", second)
        assert code == 200
        code, permit = g.w.request("permit", challenge, identity=g.w.courier)
        assert code == 200
        # A genuine private R2 operation completes and persists its signed public
        # result; its response is deliberately not delivered to the witness.
        code, lost_report = g.call(party, "apply", permit)
        assert code == 200
        g.round(PARTIES[1], second)
        g.net.stop(party)
        anchor = g.net.root / party / "protected-anchor"
        backup = root_path / "protected-r2-anchor-backup"
        shutil.copytree(anchor, backup)
        sequence = json.loads((anchor / "initialized.json").read_bytes())["value"]["sequence"]
        for fault in ("tail", "middle", "head", "reinitialize"):
            shutil.rmtree(anchor)
            shutil.copytree(backup, anchor)
            if fault in ("tail", "middle"):
                (anchor / "events" / f"{sequence if fault == 'tail' else 1:020}.json").unlink()
            elif fault == "head":
                private_file(anchor / "initialized.json", b"{}")
            g.rejected_start(party, initialize=fault == "reinitialize")
        shutil.rmtree(anchor)
        shutil.copytree(backup, anchor)
        g.start(party)
        g.rejected_start(party)  # Live anchor owns its exclusive writer lock.
        execution = binding["authorized"]["intent"]["crypto_execution_id"]
        view = g.w.query(execution)
        assert view["execution"]["status"] == "Open" and view["execution"]["signature"] is None
        close = g.w.command(
            {"kind": "CloseNoSignature", "execution_id": execution}, view["root"]["revision"]
        )
        assert g.w.request("command", close)[0] == 409
        changed = copy.deepcopy(binding)
        changed["authorized"]["intent"]["crypto_execution_id"] = str(uuid.uuid4())
        changed["authorized"]["intent"]["session_id"] = str(uuid.uuid4())
        changed["authorized"]["intent"]["attempt_id"] += 1
        changed = g.w.authorize(changed["authorized"])
        assert (
            g.call(party, "auto", {"binding": changed, "round": 1, "signing_package": None})[0]
            == 409
        )
        freeze = g.w.command({"kind": "Freeze"}, view["root"]["revision"])
        assert g.w.request("command", freeze)[0] == 200
        code, recovered = g.call(party, "recover", second)
        assert code == 200 and recovered == lost_report
        assert g.w.request("record", recovered, identity=g.w.courier)[0] == 200
        view = g.w.query(execution)
        assert view["execution"]["status"] == "SignedPending"
        signature = bytes.fromhex(view["execution"]["signature"])
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(g.w.root["group_public_key"])).verify(
            signature, bytes.fromhex(binding["authorized"]["payload_hex"])
        )
        g.broadcast(binding, signature)


def run_delayed_private_expiry(root_path):
    with group(root_path, delayed_rpc=True) as (g, c, receipts):
        binding = g.binding(c, receipts)
        first = {"binding": binding, "round": 1, "signing_package": None}
        r1 = {p: g.round(p, first) for p in PARTIES[:2]}
        package = json.loads(
            subprocess.check_output(
                [str(g.net.bin / "examples" / "frost_signing_package")],
                input=json.dumps(
                    {
                        "commitments": {p: r["value"]["commitments"] for p, r in r1.items()},
                        "message": list(bytes.fromhex(binding["authorized"]["payload_hex"])),
                    }
                ).encode(),
            )
        )
        second = {"binding": binding, "round": 2, "signing_package": package}
        party = PARTIES[0]
        code, challenge = g.call(party, "challenge", second)
        assert code == 200
        code, permit = g.w.request("permit", challenge, identity=g.w.courier)
        assert code == 200
        expires = permit["value"]["request"]["expires_at"]
        g.proxy.hold_until = expires + 1
        assert g.call(party, "apply", permit)[0] == 409
        assert g.proxy.entered < expires < g.proxy.released
        assert g.call(party, "recover", second) == (200, None)

        execution = binding["authorized"]["intent"]["crypto_execution_id"]
        view = g.w.query(execution)
        assert view["execution"]["status"] == "Open"
        close = g.w.command(
            {"kind": "CloseNoSignature", "execution_id": execution}, view["root"]["revision"]
        )
        assert g.w.request("command", close)[0] == 409  # Any R2 permission stays conservative.
        g.net.stop(party)
        g.start(party)
        assert g.call(party, "apply", permit)[0] == 409
        assert g.call(party, "recover", second) == (200, None)


def run_token_pairs(root_path):
    with group(root_path) as (g, native, _):
        g.validator.create_mint()
        mint = str(g.validator.mint.pubkey())
        c = claim(
            g.w.root,
            index=1,
            owner=native["owner_ref"],
            asset={"kind": "ClassicToken", "mint": mint, "decimals": 6},
        )
        receipts = []
        for party in PARTIES:
            code, receipt = call(g.net, party, "approve", approval(g.net, "claim", c))
            assert code == 200
            receipts.append(receipt)
        create = g.token_binding(c, receipts, create=True)
        g.w.register_claim(c, receipts)
        i = create["authorized"]["intent"]
        source, base = i["financial_source"], i["fee_payer"]
        base_before = balance(g, base)
        rent = i["expected_rent_lamports"]
        g.broadcast(create, g.sign(create))
        account = g.validator.rpc(
            "getAccountInfo", [source, {"encoding": "base64", "commitment": "finalized"}]
        )["value"]
        data = base64.b64decode(account["data"][0])
        assert account["owner"] == CLASSIC_TOKEN_PROGRAM and len(data) == 165
        assert data[:32] == bytes(Pubkey.from_string(mint)) and data[32:64] == bytes(
            Pubkey.from_string(base)
        )
        assert data[108] == 1 and account["lamports"] == rent
        assert balance(g, base) == base_before - rent - 5000
        # The isolated auxiliary mint authority creates test tokens directly in
        # the genuine initialized seeded account; it is never the custody key.
        g.validator.send(
            [
                Instruction(
                    Pubkey.from_string(CLASSIC_TOKEN_PROGRAM),
                    b"\x07" + (9000000).to_bytes(8, "little"),
                    [
                        AccountMeta(Pubkey.from_string(mint), False, True),
                        AccountMeta(Pubkey.from_string(source), False, True),
                        AccountMeta(g.validator.faucet.pubkey(), True, False),
                    ],
                )
            ]
        )
        pairs = ((PARTIES[0], PARTIES[1]), (PARTIES[0], PARTIES[2]), (PARTIES[1], PARTIES[2]))
        for n, pair in enumerate(pairs, 2):
            binding = g.token_binding(c, receipts, n, pair, create_ata=n != 3)
            g.broadcast(binding, g.sign(binding))
        target = derive_ata(binding["authorized"]["intent"]["action"]["destination_owner"], mint)

        def units(address):
            return int(
                g.validator.rpc("getTokenAccountBalance", [address, {"commitment": "finalized"}])[
                    "value"
                ]["amount"]
            )

        assert units(source) == 6000000 and units(target) == 3000000
        assert balance(g, source) == rent
        assert balance(g, base) == base_before - 2 * rent - 4 * 5000


def run_warm_independent_credentials(root_path):
    with group(root_path, "WARM") as (g, c, receipts):
        binding = g.binding(c, receipts, pair=(PARTIES[0], PARTIES[2]))
        hot_custody = root_path / "unrelated-hot-custody"
        hot_policy = root_path / "unrelated-hot-policy"
        hot_lifecycle = root_path / "unrelated-hot-lifecycle"
        issue(hot_custody, "custody", ca())
        issue(hot_policy, "policy-hot", ca())
        issue(hot_lifecycle, "lifecycle", ca())
        content = _canonical(
            {
                "intent": binding["authorized"]["intent"],
                "payload_hex": binding["authorized"]["payload_hex"],
            }
        )
        wrong = copy.deepcopy(binding)
        wrong["authorized"]["custody_authorization"] = _authorize_message(
            b"Wallet-MPC/CUSTODY_SOLANA_SEEDED_INTENT_V1\0" + content,
            hot_custody / "tls.crt",
            hot_custody / "tls.key",
        )
        assert (
            g.call(PARTIES[0], "auto", {"binding": wrong, "round": 1, "signing_package": None})[0]
            == 409
        )
        wrong = copy.deepcopy(binding)
        # Construct an authentic Hot-class signature over the exact Warm intent;
        # it still has no Warm policy authority.
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        cert = x509.load_pem_x509_certificate((hot_policy / "tls.crt").read_bytes())
        key = serialization.load_pem_private_key((hot_policy / "tls.key").read_bytes(), None)
        wrong["authorized"]["operator_authorization"] = {
            "certificate_chain_der_hex": [cert.public_bytes(serialization.Encoding.DER).hex()],
            "signature_der_hex": key.sign(
                b"Wallet-MPC/OPERATOR_SEEDED_SPEND_V1\0" + content, ec.ECDSA(hashes.SHA256())
            ).hex(),
        }
        assert (
            g.call(PARTIES[0], "auto", {"binding": wrong, "round": 1, "signing_package": None})[0]
            == 409
        )
        freeze = g.w.command({"kind": "Freeze"}, g.w.query()["root"]["revision"])
        wrong_command = sign(hot_lifecycle, "WITNESS_COMMAND_V1", freeze["value"])
        assert g.w.request("command", wrong_command)[0] == 409
        assert g.w.query()["sequence"] == 2
        g.broadcast(binding, g.sign(binding))


def run_full_queue_drain(root_path):
    with group(root_path) as (g, c, receipts):
        base = str(Pubkey.from_bytes(bytes.fromhex(g.w.root["group_public_key"])))
        g.validator.fund(account_address(base, c["index"]), 50000000)
        first_binding = None
        first_report = None
        for operation in range(1, 33):
            binding = g.binding(c, receipts, operation, amount=1000000 + operation)
            report = g.round(PARTIES[0], {"binding": binding, "round": 1, "signing_package": None})
            if first_binding is None:
                first_binding, first_report = binding, report
        extra = g.binding(c, receipts, 33, amount=1000033)
        assert (
            g.call(PARTIES[0], "auto", {"binding": extra, "round": 1, "signing_package": None})[0]
            == 409
        )
        other = g.round(PARTIES[1], {"binding": first_binding, "round": 1, "signing_package": None})
        package = json.loads(
            subprocess.check_output(
                [str(g.net.bin / "examples" / "frost_signing_package")],
                input=json.dumps(
                    {
                        "commitments": {
                            PARTIES[0]: first_report["value"]["commitments"],
                            PARTIES[1]: other["value"]["commitments"],
                        },
                        "message": list(bytes.fromhex(first_binding["authorized"]["payload_hex"])),
                    }
                ).encode(),
            )
        )
        second = {"binding": first_binding, "round": 2, "signing_package": package}
        g.round(PARTIES[0], second)  # R2 consumes an existing slot, even when all32 are occupied.
        g.round(PARTIES[1], second)
        view = g.w.query(first_binding["authorized"]["intent"]["crypto_execution_id"])
        assert view["execution"]["status"] == "SignedPending"
        g.broadcast(first_binding, bytes.fromhex(view["execution"]["signature"]))
        # Draining one execution creates capacity without a process restart or
        # forgetting the other31 consumed R1 permissions.
        g.round(PARTIES[0], {"binding": extra, "round": 1, "signing_package": None})
