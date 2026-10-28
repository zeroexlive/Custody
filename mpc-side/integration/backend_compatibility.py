"""Real legacy-to-candidate store acceptance; private fixtures never leave work-dir.

The fixed historical baseline is built by CI. No signing shares are reconstructed.
Only a small public report is eligible for upload; never upload the work directory.
"""

import argparse
import hashlib
import json
import shutil
import time
import uuid
from pathlib import Path

import test_cggmp_aux as aux
import test_signing as frost
from custody.mpc_request_auth import (
    authorize_child_approval,
    authorize_child_request,
    authorize_root_dedication,
    dedication_statement,
)
from environment import ROLES, Processes, private_file
from test_cggmp import PARTIES
from test_dkg import dkg_request, request
from test_dkg import execute as frost_dkg


class OldProcesses(Processes):
    def __init__(self, root):
        super().__init__(root)
        self.bin = OLD


class Factory:
    def __init__(self, label):
        self.label = label

    def mktemp(self, _):
        p = BASE / self.label
        p.mkdir(mode=0o700)
        return p


def save(net, data):
    data["ports"] = net.ports
    private_file(net.root.parent / "fixture.json", json.dumps(data, sort_keys=True).encode())
    print("LEGACY_FIXTURE_READY", net.root.parent.name, flush=True)


def snap(net):
    return {
        str(p.relative_to(net.root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for role in ROLES[:4]
        for p in (net.root / role / "storage").rglob("*")
        if p.is_file()
    }


def cggmp(label, hd):
    gen = aux._auxiliary_network(Factory(label))
    net = next(gen)
    try:
        if hd:
            ctx, state = net.aux_context, net.aux_state
            scope = {
                "ownership_scope": "migration-compatibility",
                "chain_id": "ETH",
                "purpose": "DEPOSIT",
                "wallet_class": "HOT",
                "derivation_version": "cggmp_slip10_nonhardened_v1",
                "root_identity": {
                    "keyset_id": ctx["keyset_id"],
                    "chain_id": "ETH",
                    "scope": "EVM",
                    "algorithm": ctx["algorithm"],
                    "public_key": state["group_public_key"],
                    "dkg_execution_id": ctx["execution_id"],
                    "dkg_fingerprint": state["result_fingerprint"],
                    "network": {"evm_chain_id": 31337, "genesis_hash": "0x" + "11" * 32},
                },
            }
            identity = net.root / "custody/identity"
            hd_request = {"auxiliary": state["auxiliary"]["request"], "scope": scope}
            stmt = dedication_statement(hd_request)
            dedication = {
                "statement": stmt,
                "custody_authorization": authorize_root_dedication(
                    stmt, identity / "tls.crt", identity / "tls.key"
                ),
            }
            code, evidence = request(
                net,
                "coordinator",
                "custody",
                f"/v1/keysets/{ctx['keyset_id']}/hd-attestation",
                dedication,
            )
            assert code == 200, "old HD attestation failed"
            child_req = {
                "root": evidence["root"],
                "reservation_id": str(uuid.uuid4()),
                "customer_ref": "original-customer",
                "idempotency_key": "original-reservation",
                "child_index": 7,
                "derivation_path": "m/0/7",
            }
            grant = {
                "request": child_req,
                "custody_authorization": authorize_child_approval(
                    child_req, identity / "tls.crt", identity / "tls.key"
                ),
            }
            code, child = request(
                net, "coordinator", "custody", f"/v1/keysets/{ctx['keyset_id']}/children", grant
            )
            assert code == 200, f"old child approval status {code}"
            data = {
                "kind": "cggmp-hd",
                "context": ctx,
                "state": state,
                "dedication": dedication,
                "root_evidence": evidence,
                "child_approval": grant,
                "child_evidence": child,
            }
        else:
            ctx = aux.signing_request(
                net, digest=hashlib.sha256(b"legacy-completed-migration").digest()
            )
            assert request(net, "coordinator", "custody", "/v1/sign-sessions", ctx)[0] == 200
            assert aux.advance_sign(net, ctx)[0] == 200
            done = aux.wait_sign(net, ctx)
            assert done["status"] == "COMPLETED"
            aux.verify_independently(net, ctx, done)
            pending = aux.signing_request(
                net, digest=hashlib.sha256(b"legacy-prepared-migration").digest()
            )
            code, s = request(net, "coordinator", "custody", "/v1/sign-sessions", pending)
            assert code == 200
            execution = {
                "request": pending,
                "crypto_execution_id": s["crypto_execution_id"],
                "selected_signers": list(PARTIES[:2]),
                "auxiliary": net.aux_state["auxiliary"]["request"],
            }
            for p in PARTIES[:2]:
                assert aux.sign_control(net, p, "prepare", execution)[0] == 200
            assert aux.sign_control(net, "signer-a", "start", execution)[0] == 200
            consumed = (
                net.root
                / "signer-a"
                / "storage"
                / "cggmp-signing"
                / f"{s['crypto_execution_id']}.consumed"
            )
            deadline = time.monotonic() + 5
            while not consumed.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert json.loads(consumed.read_text()) == execution
            data = {
                "kind": "cggmp-root",
                "context": net.aux_context,
                "state": net.aux_state,
                "completed_request": ctx,
                "completed_state": done,
                "pending_request": pending,
                "pending_state": s,
                "pending_execution": execution,
            }
        net.close()
        data["storage_sha256"] = snap(net)
        save(net, data)
    finally:
        gen.close()


def prepare_frost():
    net = OldProcesses(BASE / "frost/services")
    try:
        for role in ROLES[:4]:
            net.start(role)
        context = dkg_request()
        code, dkg = frost_dkg(net, context)
        assert code == 200
        payload = frost.sign_request(dkg, b"legacy-frost-completed-migration")
        code, done = frost.run_sign(net, payload)
        assert code == 200
        frost.assert_signature(payload, done, dkg, PARTIES[:2])
        pending, session, binding, reports = frost.manual_round1(net, dkg)
        net.close()
        save(
            net,
            {
                "kind": "frost",
                "context": context,
                "dkg": dkg,
                "completed_request": payload,
                "completed_state": done,
                "pending_request": pending,
                "pending_state": session,
                "pending_execution": binding,
                "pending_reports": reports,
                "storage_sha256": snap(net),
            },
        )
    finally:
        net.close()


def reopen(label):
    data = json.loads((BASE / label / "fixture.json").read_text())
    net = Processes.__new__(Processes)
    source = BASE / label / "services"
    net.root = BASE / label / ("candidate-services-" + uuid.uuid4().hex)
    net.ports = data["ports"]
    net.bin = BIN
    net.running = {}
    shutil.copytree(source, net.root)
    net.configs = {
        role: dict(
            line.replace(str(source), str(net.root)).split("=", 1)
            for line in (source / role / "service.env").read_text().splitlines()
        )
        for role in ROLES[:4]
    }
    for relative, digest in data["storage_sha256"].items():
        assert hashlib.sha256((net.root / relative).read_bytes()).hexdigest() == digest
    try:
        for role in ROLES[:4]:
            net.start(role)
    except BaseException:
        net.close()
        raise
    return net, data


def assert_immutable(net, data):
    # Volatile json status can fail closed across restart. Keys, auxiliary, HD
    # approvals, completed records and durable execution tombstones cannot change.
    for relative, digest in data["storage_sha256"].items():
        p = Path(relative)
        if (
            p.suffix == ".enc"
            or p.suffix
            in {".root", ".child", ".role", ".owner", ".index", ".consumed", ".completed"}
            or (
                p.suffix == ".state"
                and (net.root.parent / "services" / p).read_bytes() == b"COMPLETED"
            )
        ):
            assert hashlib.sha256((net.root / relative).read_bytes()).hexdigest() == digest, (
                relative
            )


def frost_check():
    net, d = reopen("frost")
    try:
        old, done = d["completed_request"], d["completed_state"]
        assert frost.run_sign(net, old) == (200, done)
        frost.assert_signature(old, done, d["dkg"], done["selected_signers"])
        package = frost.package_for(net, d["pending_execution"], d["pending_reports"])
        for p in PARTIES[:2]:
            code, report = frost.sign_control(net, p, "report", d["pending_execution"])
            assert code == 200 and report["status"] == "RECONCILIATION_REQUIRED"
            assert frost.sign_control(net, p, "round1", d["pending_execution"])[0] == 409
            assert frost.sign_control(net, p, "round2", d["pending_execution"], package)[0] == 409
        assert frost.run_sign(net, d["pending_request"])[0] == 409
        for omitted in reversed(PARTIES):
            net.stop(omitted)
            try:
                payload = frost.sign_request(d["dkg"], uuid.uuid4().bytes)
                code, done = frost.run_sign(net, payload)
                assert code == 200
                frost.assert_signature(
                    payload, done, d["dkg"], [p for p in PARTIES if p != omitted]
                )
            finally:
                net.start(omitted)
        assert_immutable(net, d)
        print(
            "LEGACY_FROST_COMPAT passed completed_recovery pending_nonce_fencing all_pairs "
            "unchanged_encrypted_shares",
            flush=True,
        )
    finally:
        net.close()


def root_check():
    net, d = reopen("root")
    net.aux_context = d["context"]
    net.aux_state = d["state"]
    try:
        assert aux.advance_sign(net, d["completed_request"]) == (200, d["completed_state"])
        aux.verify_independently(net, d["completed_request"], d["completed_state"])
        for p in PARTIES[:2]:
            code, report = aux.sign_control(net, p, "report", d["pending_execution"])
            assert code == 200 and report["status"] == "RECONCILIATION_REQUIRED"
            assert aux.sign_control(net, p, "start", d["pending_execution"])[0] == 409
            assert aux.sign_control(net, p, "prepare", d["pending_execution"])[0] == 409
        assert aux.advance_sign(net, d["pending_request"])[0] == 200
        uncertain = aux.wait_sign(net, d["pending_request"])
        assert uncertain["status"] == "RECONCILIATION_REQUIRED"
        assert uncertain["signature"] is None
        assert uncertain["crypto_execution_id"] == d["pending_state"]["crypto_execution_id"]
        assert aux.advance_sign(net, d["pending_request"])[0] == 409
        assert aux.advance_sign(net, d["pending_request"], "reconcile")[0] == 409
        for omitted in reversed(PARTIES):
            net.stop(omitted)
            try:
                context = aux.signing_request(
                    net, digest=hashlib.sha256(uuid.uuid4().bytes).digest()
                )
                assert (
                    request(net, "coordinator", "custody", "/v1/sign-sessions", context)[0] == 200
                )
                assert aux.advance_sign(net, context)[0] == 200
                done = aux.wait_sign(net, context)
                assert done["status"] == "COMPLETED"
                assert done["selected_signers"] == [p for p in PARTIES if p != omitted]
                aux.verify_independently(net, context, done)
            finally:
                net.start(omitted)
        assert_immutable(net, d)
        print(
            "LEGACY_CGGMP_ROOT_COMPAT passed completed_recovery "
            "consumed_and_prepared_fencing all_pairs "
            "unchanged_core_aux",
            flush=True,
        )
    finally:
        net.close()


def hd_check():
    from coincurve import PublicKey, ecdsa

    net, d = reopen("hd")
    net.aux_context = d["context"]
    net.aux_state = d["state"]
    try:
        key = net.aux_context["keyset_id"]
        url = f"/v1/keysets/{key}"
        assert request(net, "coordinator", "custody", url + "/hd-attestation", d["dedication"]) == (
            200,
            d["root_evidence"],
        )
        assert request(net, "coordinator", "custody", url + "/children", d["child_approval"]) == (
            200,
            d["child_evidence"],
        )
        child = d["child_evidence"]["child"]
        ref = (
            "child:"
            + child["request"]["reservation_id"]
            + ":"
            + hashlib.sha256(
                b"CGGMP24_CHILD_V1\0"
                + json.dumps(child, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        for omitted in reversed(PARTIES):
            net.stop(omitted)
            try:
                context = aux.signing_request(
                    net, digest=hashlib.sha256(uuid.uuid4().bytes).digest()
                )
                context.update(
                    child_authorization=child,
                    expected_source=child["address"],
                    derivation_reference=ref,
                )
                identity = net.root / "custody/identity"
                context["custody_authorization"] = authorize_child_request(
                    context, identity / "tls.crt", identity / "tls.key"
                )
                assert (
                    request(net, "coordinator", "custody", "/v1/sign-sessions", context)[0] == 200
                )
                assert aux.advance_sign(net, context)[0] == 200
                done = aux.wait_sign(net, context)
                assert done["status"] == "COMPLETED"
                sig = done["signature"]
                compact = bytes.fromhex(sig["signature_hex"])
                digest = bytes.fromhex(context["payload_hex"])
                pub = PublicKey(bytes.fromhex(child["public_key"]))
                assert pub.verify(
                    ecdsa.cdata_to_der(ecdsa.deserialize_compact(compact)), digest, hasher=None
                )
                recovered = PublicKey.from_signature_and_message(
                    compact + bytes([sig["recovery_id"]]), digest, hasher=None
                )
                assert recovered.format() == pub.format()
                assert not PublicKey(bytes.fromhex(net.aux_state["group_public_key"])).verify(
                    ecdsa.cdata_to_der(ecdsa.deserialize_compact(compact)), digest, hasher=None
                )
            finally:
                net.start(omitted)
        assert_immutable(net, d)
        print(
            "LEGACY_CGGMP_HD_COMPAT passed exact_original_receipts child_all_pairs "
            "independent_recovery unchanged_core_aux_hd",
            flush=True,
        )
    finally:
        net.close()


def main():
    global BASE, OLD, BIN
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-bin", type=Path, required=True)
    parser.add_argument("--candidate-bin", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--public-report", type=Path, required=True)
    args = parser.parse_args()
    BASE = args.work_dir.resolve()
    OLD = args.legacy_bin.resolve()
    BIN = args.candidate_bin.resolve()
    for directory in (OLD, BIN):
        for binary in ("wallet-mpc-signer", "wallet-mpc-coordinator"):
            if not (directory / binary).is_file():
                parser.error("missing required service binary")
    if OLD == BIN or all(
        hashlib.sha256((OLD / binary).read_bytes()).digest()
        == hashlib.sha256((BIN / binary).read_bytes()).digest()
        for binary in ("wallet-mpc-signer", "wallet-mpc-coordinator")
    ):
        parser.error("legacy and candidate binaries must differ")
    if not (BIN / "examples" / "frost_signing_package").is_file():
        parser.error("build the candidate frost_signing_package public helper")
    if BASE.exists():
        parser.error("work-dir must be new; never overwrite original identities/stores")
    BASE.mkdir(parents=True, mode=0o700)
    started = time.monotonic()
    aux.Processes = OldProcesses
    prepare_frost()
    cggmp("root", False)
    cggmp("hd", True)
    frost_check()
    root_check()
    hd_check()
    # Recheck original legacy stores were not rewritten by candidate execution.
    for label in ("frost", "root", "hd"):
        data = json.loads((BASE / label / "fixture.json").read_text())
        for relative, digest in data["storage_sha256"].items():
            assert (
                hashlib.sha256((BASE / label / "services" / relative).read_bytes()).hexdigest()
                == digest
            )
    report = {
        "legacy_main_sha": "3d32b763ff777347f77eae7a8a7936d85dc2d770",
        "status": "passed",
        "cases": [
            "frost_completed_and_pending_nonce_recovery",
            "frost_all_pairs",
            "cggmp_original_core_aux_and_root_all_pairs",
            "cggmp_consumed_and_prepared_fencing",
            "original_hd_receipts_and_child_all_pairs",
            "original_stores_unchanged",
        ],
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "binaries": {
            kind: {
                binary: hashlib.sha256((directory / binary).read_bytes()).hexdigest()
                for binary in ("wallet-mpc-signer", "wallet-mpc-coordinator")
            }
            for kind, directory in (("legacy", OLD), ("candidate", BIN))
        },
    }
    args.public_report.parent.mkdir(parents=True, exist_ok=True)
    args.public_report.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print("BACKEND_STORE_COMPATIBILITY passed; public report saved")


if __name__ == "__main__":
    main()
