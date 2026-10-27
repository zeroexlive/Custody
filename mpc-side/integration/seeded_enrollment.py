"""Real-store approval acceptance; deliberately no customer/on-chain issuance claim."""

import hashlib
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from custody.mpc_binding import MpcBindingError
from custody.mpc_receipts import verify_receipts
from custody.mpc_request_auth import _authorize_message, _canonical
from django.test import override_settings
from environment import ROLES, Processes
from solders.pubkey import Pubkey
from test_dkg import PARTIES, dkg_request, encrypted_files, execute, request
from test_signing import (
    assert_signature,
    create,
    execution,
    run_sign,
    sign_control,
    sign_request,
)

PREFIX = "/internal/v1/solana/seeded/"


@contextmanager
def services(root):
    net = Processes(root)
    try:
        for role in ROLES[:4]:
            net.start(role)
        yield net
    finally:
        net.close()


def fresh_root(net):
    binding = dkg_request()
    code, dkg = execute(net, binding)
    assert code == 200 and dkg["status"] == "COMPLETED"
    return {
        "dkg": binding,
        "group_public_key": dkg["group_public_key"],
        "public_key_package": dkg["participant_agreement"][0]["public_key_package"],
        "ownership_scope": "isolated-operator-scope",
        "chain_id": "SOL",
        "genesis_hash": str(Pubkey.from_bytes(hashlib.sha256(b"enrollment-only-network").digest())),
        "purpose": "DEPOSIT",
        "wallet_class": "HOT",
        "derivation_version": "solana_seeded_v1",
        "generation": 0,
    }, dkg


def approval(net, kind, statement, role="custody"):
    identity = net.root / role / "identity"
    # Construct the exact original proof independently in Python. A coordinator
    # transport certificate never substitutes for this signed custody statement.
    message = f"Wallet-MPC/CUSTODY_SOLANA_{kind.upper()}_V1\0".encode() + _canonical(statement)
    if role == "custody":
        auth = _authorize_message(message, identity / "tls.crt", identity / "tls.key")
    else:
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_pem_x509_certificate((identity / "tls.crt").read_bytes())
        key = serialization.load_pem_private_key((identity / "tls.key").read_bytes(), None)
        auth = {
            "certificate_chain_der_hex": [cert.public_bytes(serialization.Encoding.DER).hex()],
            "signature_der_hex": key.sign(message, ec.ECDSA(hashes.SHA256())).hex(),
        }
    return {"statement": statement, "custody_authorization": auth}


def call(net, party, action, payload, role="coordinator"):
    return request(net, party, role, PREFIX + action, payload)


def verify(net, kind, report, statement, party):
    assert report["statement"] == statement and report["party_id"] == party and report["durable"]
    cert = x509.load_pem_x509_certificate((net.root / party / "identity" / "tls.crt").read_bytes())
    message = f"Wallet-MPC/SIGNER_SOLANA_{kind.upper()}_V1\0".encode() + _canonical(
        {"statement": statement, "party_id": party, "durable": True}
    )
    cert.public_key().verify(
        bytes.fromhex(report["signer_signature"]), message, ec.ECDSA(hashes.SHA256())
    )


def claim(root, index=0, owner="original-ledger-owner", asset=None):
    return {
        "root": root,
        "reservation_id": str(uuid.uuid4()),
        "owner_ref": owner,
        "idempotency_key": str(uuid.uuid4()),
        "index": index,
        "asset": asset or {"kind": "Native"},
    }


def enroll_all(net, root):
    reports = []
    for party in PARTIES:
        code, report = call(net, party, "enroll", approval(net, "root", root))
        assert code == 200
        verify(net, "root", report, root, party)
        reports.append(report)
    return reports


def store(net, party):
    return net.root / party / "storage" / "solana-provisioning"


def run_approvals(root_path):
    with services(root_path / "services") as net:
        root, dkg = fresh_root(net)
        original_shares = encrypted_files(net, root["dkg"])
        for role in ("coordinator", *PARTIES):
            assert call(net, PARTIES[0], "enroll", approval(net, "root", root, role))[0] == 409
        for role in ("custody", *PARTIES):
            assert call(net, PARTIES[0], "enroll", approval(net, "root", root), role)[0] == 403
        tampered = approval(net, "root", root)
        tampered["statement"] = dict(root, ownership_scope="substituted")
        assert call(net, PARTIES[0], "enroll", tampered)[0] == 409
        for mutation in (
            {"wallet_class": "COLD"},
            {"generation": 1},
            {"chain_id": "TON"},
            {"group_public_key": "00" * 32},
            {"genesis_hash": "1" * 32},
            {"dkg": dict(root["dkg"], execution_id=str(uuid.uuid4()))},
            {"public_key_package": root["public_key_package"][:-1]},
        ):
            assert call(net, PARTIES[0], "enroll", approval(net, "root", root | mutation))[0] == 409
        # Partial all-party enrollment is retained; completing a retry returns
        # exactly the originally randomized signature, never a replacement.
        code, first = call(net, PARTIES[0], "enroll", approval(net, "root", root))
        assert code == 200
        net.stop(PARTIES[0])
        net.start(PARTIES[0])
        enrolled = enroll_all(net, root)
        assert enrolled[0] == first
        for field, value in (
            ("ownership_scope", "another-scope"),
            ("genesis_hash", str(Pubkey.from_bytes(bytes([23]) * 32))),
        ):
            assert (
                call(net, PARTIES[0], "enroll", approval(net, "root", root | {field: value}))[0]
                == 409
            )
        payload = sign_request(dkg)
        code, state = create(net, payload)
        assert code == 200
        binding = execution(payload, state, dkg)
        for party in PARTIES:
            for action in ("probe", "round1"):
                assert sign_control(net, party, action, binding)[0] == 409
            assert not list((net.root / party / "storage" / "signing").glob("*.json"))

        original = claim(root)
        proof = approval(net, "claim", original)
        for party in PARTIES:
            # Wrong domain and coordinator-only credential cannot allocate.
            wrong = approval(net, "root", original)
            assert call(net, party, "approve", wrong)[0] == 409
            assert (
                call(net, party, "approve", approval(net, "claim", original, "coordinator"))[0]
                == 409
            )
        with ThreadPoolExecutor(max_workers=8) as pool:
            duplicates = list(pool.map(lambda _: call(net, PARTIES[0], "approve", proof), range(8)))
        assert all(result == duplicates[0] and result[0] == 200 for result in duplicates)
        reports = []
        for party in PARTIES:
            code, report = call(net, party, "approve", proof)
            assert code == 200
            verify(net, "claim", report, original, party)
            reports.append(report)

        # Simulate process loss immediately after the authoritative index commit,
        # before any aliases. A distinct same-owner/retry cannot steal next index.
        party = PARTIES[0]
        directory = store(net, party)
        net.stop(party)
        temporary = directory / f"{root['dkg']['keyset_id']}.tmp-{uuid.uuid4()}"
        temporary.write_bytes(b"interrupted uncommitted atomic write")
        for path in directory.iterdir():
            if path.suffix in {".claim", ".owner", ".retry"}:
                path.unlink()
        net.start(party)
        assert temporary.read_bytes() == b"interrupted uncommitted atomic write"
        # Reservation IDs are global, including across roots when the original
        # root's alias has not been written yet. Reject before any second commit.
        second_root, _ = fresh_root(net)
        enroll_all(net, second_root)
        cross_root = claim(second_root)
        cross_root["reservation_id"] = original["reservation_id"]
        assert call(net, party, "approve", approval(net, "claim", cross_root))[0] == 409
        same_owner = claim(root, index=1)
        assert call(net, party, "approve", approval(net, "claim", same_owner))[0] == 409
        same_retry = claim(root, index=1, owner="other-owner")
        same_retry["idempotency_key"] = original["idempotency_key"]
        assert call(net, party, "approve", approval(net, "claim", same_retry))[0] == 409
        assert call(net, party, "approve", proof) == (200, reports[0])
        assert len(list(directory.glob("*.index"))) == 1
        for field, value in (
            ("owner_ref", "other-owner"),
            ("index", 1),
            ("idempotency_key", "different-retry"),
            ("reservation_id", str(uuid.uuid4())),
            ("asset", {"kind": "ClassicToken", "mint": str(Pubkey.new_unique()), "decimals": 6}),
            ("root", root | {"ownership_scope": "different-owner-scope"}),
            ("root", root | {"genesis_hash": str(Pubkey.new_unique())}),
            ("index", 2**63),
        ):
            changed = original | {field: value}
            assert call(net, party, "approve", approval(net, "claim", changed))[0] == 409
        skipped = claim(root, index=2, owner="next-owner")
        assert call(net, party, "approve", approval(net, "claim", skipped))[0] == 409
        # Two independent mints consume different monotonic indices even for the
        # same owner. Changing decimals cannot create a second mint namespace.
        mints = [str(Pubkey.new_unique()), str(Pubkey.new_unique())]
        for index, mint in enumerate(mints, 1):
            token = claim(
                root, index=index, asset={"kind": "ClassicToken", "mint": mint, "decimals": 6}
            )
            for p in PARTIES:
                code, report = call(net, p, "approve", approval(net, "claim", token))
                assert code == 200
                verify(net, "claim", report, token, p)
            if index == 1:
                changed = claim(
                    root, index=2, asset={"kind": "ClassicToken", "mint": mint, "decimals": 7}
                )
                assert call(net, party, "approve", approval(net, "claim", changed))[0] == 409
        # Concurrent distinct requests for the same next index have one winner.
        competitors = [claim(root, index=3, owner=f"racing-owner-{i}") for i in range(2)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(
                pool.map(
                    lambda c: call(net, party, "approve", approval(net, "claim", c)), competitors
                )
            )
        assert sorted(c for c, _ in outcomes) == [200, 409]
        before = {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file()}
        for p in PARTIES:
            net.stop(p)
            net.start(p)
            assert call(net, p, "enroll", approval(net, "root", root)) == (
                200,
                enrolled[PARTIES.index(p)],
            )
            assert call(net, p, "approve", proof) == (200, reports[PARTIES.index(p)])
            assert sign_control(net, p, "round1", binding)[0] == 409
        assert {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file()} == before
        assert encrypted_files(net, root["dkg"]) == original_shares


def run_historical_and_race(root_path):
    with services(root_path / "services") as net:
        root, dkg = fresh_root(net)
        code, completed = run_sign(net, sign_request(dkg))
        assert code == 200 and completed["status"] == "COMPLETED"
        # Completed historical roots stay signable but cannot be dedicated.
        for party in completed["selected_signers"]:
            net.stop(party)
            net.start(party)
            assert call(net, party, "enroll", approval(net, "root", root))[0] == 409
        assert run_sign(net, sign_request(dkg))[0] == 200
        # Fresh root: enrollment vs round1 must serialize at the same role marker.
        root, dkg = fresh_root(net)
        payload = sign_request(dkg)
        code, state = create(net, payload)
        assert code == 200
        binding = execution(payload, state, dkg)
        party = PARTIES[0]
        with ThreadPoolExecutor(max_workers=2) as pool:
            enrolled = pool.submit(call, net, party, "enroll", approval(net, "root", root))
            prepared = pool.submit(sign_control, net, party, "round1", binding)
            codes = [enrolled.result()[0], prepared.result()[0]]
        assert sorted(codes) == [200, 409]
        net.stop(party)
        net.start(party)
        if codes[0] == 200:
            assert sign_control(net, party, "round1", binding)[0] == 409
        else:
            assert call(net, party, "enroll", approval(net, "root", root))[0] == 409


def run_corruption(root_path, fault):
    with services(root_path / "services") as net:
        root, _ = fresh_root(net)
        enroll_all(net, root)
        original = claim(root)
        assert call(net, PARTIES[0], "approve", approval(net, "claim", original))[0] == 200
        party = PARTIES[0]
        net.stop(party)
        directory = store(net, party)
        path = next(directory.glob("*." + ("owner" if fault == "alias" else fault)))
        original_bytes = path.read_bytes()
        damaged = json.loads(original_bytes)
        if fault == "role":
            damaged["enrollment"]["report"]["statement"]["ownership_scope"] = "tampered"
        elif fault == "index":
            damaged["statement"]["owner_ref"] = "tampered"
        else:
            damaged["signer_signature"] = "00" * 70
        path.write_text(json.dumps(damaged))
        with pytest.raises(RuntimeError, match="Solana provisioning recovery failed"):
            net.start(party)
        net.stop(party)
        path.write_bytes(original_bytes)
        net.start(party)
        assert call(net, party, "approve", approval(net, "claim", original))[0] == 200


def run_coordinator_agreement(root_path):
    with services(root_path / "services") as net:
        root, dkg = fresh_root(net)
        base = f"/v1/keysets/{root['dkg']['keyset_id']}/solana-seeded-"
        pins = {p: str(net.root / p / "identity" / "tls.crt") for p in PARTIES}

        def rpc(suffix, payload):
            return request(net, "coordinator", "custody", base + suffix, payload)

        def checked(kind, evidence, expected):
            assert evidence["statement"] == expected
            for party, report in zip(PARTIES, evidence["participant_agreement"], strict=True):
                verify(net, kind, report, expected, party)
            with override_settings(MPC_HD_SIGNER_CERTIFICATES=pins):
                verify_receipts("solana_" + kind, expected, evidence["participant_agreement"])

        original_shares = encrypted_files(net, root["dkg"])
        root_proof = approval(net, "root", root)
        original_claim = claim(root)
        claim_proof = approval(net, "claim", original_claim)
        for role in ROLES[:4]:
            assert request(net, "coordinator", role, base + "root", root_proof)[0] == 403
        assert rpc("claims", claim_proof)[0] == 409
        assert rpc("root", approval(net, "root", root, "coordinator"))[0] == 409
        # Recover a previously interrupted direct party approval. A fresh
        # coordinator preflight itself does not mutate any unused party.
        assert call(net, PARTIES[0], "enroll", root_proof)[0] == 200
        # Third signer offline: two receipts cannot become completed evidence.
        net.stop(PARTIES[2])
        assert rpc("root", root_proof)[0] == 409
        state = Path(net.configs["coordinator"]["MPC_COORDINATOR_STATE"]).with_suffix(
            ".solana-seeded"
        )
        assert not state.exists() or not list(state.glob("*.root"))
        first_roles = {
            p: (store(net, p) / f"{root['dkg']['keyset_id']}.role").read_bytes()
            for p in PARTIES[:1]
        }
        net.stop("coordinator")
        net.start("coordinator")
        net.start(PARTIES[2])
        code, root_evidence = rpc("root", root_proof)
        assert code == 200
        checked("root", root_evidence, root)
        assert len(list(state.glob("*.root"))) == 1
        for p, raw in first_roles.items():
            assert (store(net, p) / f"{root['dkg']['keyset_id']}.role").read_bytes() == raw
        # A partial claim survives coordinator+signer restart and returns the
        # original signatures; custody independently verifies all three pins.
        net.stop(PARTIES[2])
        assert rpc("claims", claim_proof)[0] == 409
        assert not list(state.glob("*.claim"))
        first_claims = {p: next(store(net, p).glob("*.index")).read_bytes() for p in PARTIES[:2]}
        for p in PARTIES[:2]:
            net.stop(p)
            net.start(p)
        net.stop("coordinator")
        net.start("coordinator")
        net.start(PARTIES[2])
        code, claim_evidence = rpc("claims", claim_proof)
        assert code == 200
        checked("claim", claim_evidence, original_claim)
        for p, raw in first_claims.items():
            assert next(store(net, p).glob("*.index")).read_bytes() == raw
        # Completed public retries need no online signer quorum and retain exact
        # original evidence. They cannot substitute a new root/claim identity.
        for p in PARTIES:
            net.stop(p)
        net.stop("coordinator")
        net.start("coordinator")
        assert rpc("root", root_proof) == (200, root_evidence)
        assert rpc("claims", claim_proof) == (200, claim_evidence)
        changed = original_claim | {"owner_ref": "different-owner"}
        assert rpc("claims", approval(net, "claim", changed))[0] == 409
        assert rpc("root", approval(net, "root", root | {"ownership_scope": "different"}))[0] == 409
        assert encrypted_files(net, root["dkg"]) == original_shares
        # Neither response shape nor a coordinator-key forgery constitutes a
        # signer receipt. Use fixed archival pins, never response-provided keys.
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_private_key(
            (net.root / "coordinator" / "identity" / "tls.key").read_bytes(), None
        )
        reports = claim_evidence["participant_agreement"]
        hostile = []
        for report in reports:
            message = b"Wallet-MPC/SIGNER_SOLANA_CLAIM_V1\0" + _canonical(
                {"statement": original_claim, "party_id": report["party_id"], "durable": True}
            )
            hostile.append(
                report | {"signer_signature": key.sign(message, ec.ECDSA(hashes.SHA256())).hex()}
            )
        with override_settings(MPC_HD_SIGNER_CERTIFICATES=pins):
            for bad in (hostile, reports[:2], list(reversed(reports)), [reports[0]] * 3):
                with pytest.raises(MpcBindingError, match="unverifiable independent"):
                    verify_receipts("solana_claim", original_claim, bad)
            with pytest.raises(MpcBindingError, match="unverifiable independent"):
                verify_receipts("solana_root", original_claim, reports)


def run_global_history_preflight(root_path):
    with services(root_path / "services") as net:
        root, dkg = fresh_root(net)
        path = f"/v1/keysets/{root['dkg']['keyset_id']}/solana-seeded-root"
        proof = approval(net, "root", root)
        # Historical first signature uses b/c, so the coordinator's fixed first
        # party a has no local usage evidence. Never dedicate a before checking b.
        net.stop(PARTIES[0])
        payload = sign_request(dkg)
        code, completed = run_sign(net, payload)
        assert code == 200
        assert_signature(payload, completed, dkg, PARTIES[1:])
        net.start(PARTIES[0])

        def roles():
            return {
                p: f.read_bytes()
                if (f := store(net, p) / f"{root['dkg']['keyset_id']}.role").exists()
                else None
                for p in PARTIES
            }

        before = roles()
        assert before[PARTIES[0]] is None
        assert request(net, "coordinator", "custody", path, proof)[0] == 409
        assert roles() == before
        # A restored old coordinator snapshot can lack signing history while
        # independent signer stores retain it. All-party readonly probes still
        # reject without changing the unused first signer.
        state = Path(net.configs["coordinator"]["MPC_COORDINATOR_STATE"])
        net.stop("coordinator")
        original = state.read_bytes()
        older = json.loads(original)
        older["signing"] = {}
        state.write_text(json.dumps(older))
        net.start("coordinator")
        assert request(net, "coordinator", "custody", path, proof)[0] == 409
        assert roles() == before
        net.stop("coordinator")
        state.write_bytes(original)
        net.start("coordinator")
        for omitted in PARTIES:
            net.stop(omitted)
            try:
                payload = sign_request(dkg)
                code, completed = run_sign(net, payload)
                assert code == 200
                assert_signature(payload, completed, dkg, [p for p in PARTIES if p != omitted])
            finally:
                net.start(omitted)

        # Coordinator create_sign and root dedication share the durable-data
        # lock. Exactly one can reserve the fresh keyset's original role.
        root, dkg = fresh_root(net)
        path = f"/v1/keysets/{root['dkg']['keyset_id']}/solana-seeded-root"
        proof = approval(net, "root", root)
        payload = sign_request(dkg)
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(request, net, "coordinator", "custody", path, proof)
            b = pool.submit(create, net, payload)
            enrollment, signing = a.result(), b.result()
        assert sorted([enrollment[0], signing[0]]) == [200, 409], (enrollment[0], signing[0])
        if signing[0] == 200:
            assert run_sign(net, payload)[0] == 200
        else:
            assert create(net, payload)[0] == 409

        # A durable pending fence survives loss of the completed coordinator
        # cache; none of the original party receipts or shares are replaced.
        root, dkg = fresh_root(net)
        path = f"/v1/keysets/{root['dkg']['keyset_id']}/solana-seeded-root"
        proof = approval(net, "root", root)
        code, evidence = request(net, "coordinator", "custody", path, proof)
        assert code == 200
        cache = state.with_suffix(".solana-seeded") / f"{root['dkg']['keyset_id']}.root"
        pending = cache.with_suffix(".pending")
        assert pending.exists()
        net.stop("coordinator")
        cache.unlink()
        net.start("coordinator")
        assert create(net, sign_request(dkg))[0] == 409
        assert request(net, "coordinator", "custody", path, proof) == (200, evidence)
