"""Terminal original-key cancellation, never timeout-based absence of a signature."""

import copy
import hashlib
import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from custody.mpc_request_auth import _canonical
from protected_acceptance import group
from refresh_acceptance import activate, freeze, plan, run_rounds
from test_dkg import PARTIES
from witness_acceptance import fingerprint, sign, verify


def prepared(g, binding):
    commitments = {}
    for p in binding["selected_signers"]:
        report = g.round(p, {"binding": binding, "round": 1, "signing_package": None})
        commitments[p] = report["value"]["commitments"]
    package = json.loads(
        subprocess.check_output(
            [str(g.net.bin / "examples" / "frost_signing_package")],
            input=json.dumps(
                {
                    "commitments": commitments,
                    "message": list(bytes.fromhex(binding["authorized"]["payload_hex"])),
                }
            ).encode(),
        )
    )
    return {"binding": binding, "round": 2, "signing_package": package}


def authority(g, request):
    r = request["value"]
    signed_message = b"Wallet-MPC/WITNESS_PERMIT_REQUEST_V1\0" + _canonical(
        {"key_id": request["key_id"], "value": r}
    )
    value = {
        "anchor_id": r["anchor_id"],
        "root_identity": fingerprint("SOLANA_SEEDED_ROOT_V1", g.w.root),
        "execution_id": r["binding"]["authorized"]["intent"]["crypto_execution_id"],
        "binding_fingerprint": fingerprint(
            "WITNESS_EXECUTION_V1",
            [
                fingerprint(
                    "WITNESS_INTENT_V1",
                    [
                        r["binding"]["authorized"]["intent"],
                        r["binding"]["authorized"]["payload_hex"],
                    ],
                ),
                r["binding"]["selected_signers"],
            ],
        ),
        "request_fingerprint": hashlib.sha256(signed_message).hexdigest(),
        "expires_at": int(time.time()) + 120,
    }
    return sign(g.w.life, "WITNESS_CANCELLATION_V1", value)


def close(g, binding, attestations):
    return g.w.request(
        "command",
        g.w.command(
            {
                "kind": "CloseUnreleased",
                "execution_id": binding["authorized"]["intent"]["crypto_execution_id"],
                "attestations": attestations,
            },
            g.w.query()["root"]["revision"],
        ),
    )


def run_close_unreleased(root_path, grantees, *, custody_class="HOT"):
    with group(root_path, custody_class, lifecycle=True) as (g, c, receipts):
        binding = g.binding(c, receipts)
        control = prepared(g, binding)
        absent = g.w.permit(binding)
        absent["value"].update(round=2, signing_package=control["signing_package"])
        absent = sign(g.w.node[PARTIES[0]], "WITNESS_PERMIT_REQUEST_V1", absent["value"])
        assert (
            g.call(
                PARTIES[0], "cancel", {"control": control, "authorization": authority(g, absent)}
            )[0]
            == 409
        )
        requests, permits, controls = {}, {}, {}
        for p in PARTIES[:2]:
            code, request = g.call(p, "challenge", control)
            assert code == 200
            requests[p] = request
            controls[p] = {"control": control, "authorization": authority(g, request)}
        expired = copy.deepcopy(controls[PARTIES[0]])
        value = expired["authorization"]["value"]
        value["expires_at"] = int(time.time()) - 1
        expired["authorization"] = sign(g.w.life, "WITNESS_CANCELLATION_V1", value)
        assert g.call(PARTIES[0], "cancel", expired)[0] == 409
        if grantees == 2:
            # A terminal node may later receive its originally requested grant
            # while the root is still ACTIVE. It must remain terminal locally.
            role = "courier" if custody_class == "COLD" else "coordinator"
            assert g.call(PARTIES[1], "cancel", controls[PARTIES[1]], role=role)[0] == 200
        for p in PARTIES[:grantees]:
            code, permits[p] = g.w.request("permit", requests[p], identity=g.w.node[p])
            assert code == 200
        # No declared timeout, empty set or unrelated original key closes it.
        assert close(g, binding, [])[0] == 409
        freeze(g)
        no_proof = g.w.command(
            {
                "kind": "CloseNoSignature",
                "execution_id": binding["authorized"]["intent"]["crypto_execution_id"],
            },
            g.w.query()["root"]["revision"],
        )
        assert g.w.request("command", no_proof)[0] == 409
        attestations = []
        for p in PARTIES[:grantees]:
            # An altered lifecycle approval cannot mutate the original history.
            forged = copy.deepcopy(controls[p])
            forged["authorization"]["signature"] = "00" * 70
            assert g.call(p, "cancel", forged)[0] == 409
            if grantees == 1:
                # Cancel event commits but head publication fails. Preserve
                # the accepted event and restore only the injected head path.
                anchor = g.net.root / p / "protected-anchor"
                marker = anchor / "initialized.json"
                retained_head = anchor / "fault-retained-head"
                marker.rename(retained_head)
                marker.mkdir()
                try:
                    assert g.call(p, "cancel", controls[p])[0] == 409
                    assert g.call(p, "apply", permits[p])[0] == 409
                finally:
                    marker.rmdir()
                    retained_head.rename(marker)
                event = sorted((anchor / "events").glob("*.json"))[-1]
                original = json.loads(event.read_bytes())["value"]["change"]["attestation"]
                g.net.stop(p)
                g.start(p)
            code, attestation = g.call(p, "cancel", controls[p])
            assert code == 200, attestation
            if grantees == 1:
                assert attestation == original
            verify(g.w.node[p], "WITNESS_NO_RELEASE_V1", attestation)
            attestations.append(attestation)
            # Simulate a lost cancellation response and restart. Cached public
            # evidence is immutable, while the original live permit is terminal.
            g.net.stop(p)
            g.start(p)
            assert g.call(p, "cancel", controls[p]) == (200, attestation)
            assert g.call(p, "apply", permits[p])[0] == 409
            assert g.call(p, "challenge", control)[0] == 409
            assert g.call(p, "recover", control)[0] == 409
            assert g.call(p, "auto", control)[0] == 409
        assert close(g, binding, attestations[:-1])[0] == 409
        bad = copy.deepcopy(attestations)
        bad[0] = sign(g.w.node[PARTIES[-1]], "WITNESS_NO_RELEASE_V1", bad[0]["value"])
        assert close(g, binding, bad)[0] == 409
        bad = copy.deepcopy(attestations)
        r = bad[0]["value"]["request"]
        r["value"]["challenge"] = "cd" * 32
        r = sign(g.w.node[PARTIES[0]], "WITNESS_PERMIT_REQUEST_V1", r["value"])
        bad[0] = sign(
            g.w.node[PARTIES[0]],
            "WITNESS_NO_RELEASE_V1",
            {"request": r, "authorization": authority(g, r)},
        )
        assert close(g, binding, bad)[0] == 409
        assert close(g, binding, attestations + attestations[:1])[0] == 409
        assert close(g, binding, attestations)[0] == 200
        fresh = copy.deepcopy(requests[PARTIES[0]]["value"])
        fresh.update(expires_at=int(time.time()) + 15, challenge=os.urandom(32).hex())
        fresh = sign(g.w.node[PARTIES[0]], "WITNESS_PERMIT_REQUEST_V1", fresh)
        assert g.w.request("permit", fresh, identity=g.w.node[PARTIES[0]])[0] == 409
        g.w.stop()
        g.w.start()
        execution_id = binding["authorized"]["intent"]["crypto_execution_id"]
        assert g.w.query(execution_id)["execution"]["status"] == "NoSignature"
        if grantees == 1:
            assert (
                g.w.request("permit", requests[PARTIES[1]], identity=g.w.node[PARTIES[1]])[0] == 409
            )
        p = plan(g)
        ready = run_rounds(g, p)
        activate(g, p, ready)
        retry = g.binding(c, receipts)
        retry["authorized"]["intent"]["attempt_id"] = 2
        retry = g.w.authorize(retry["authorized"])
        g.broadcast(retry, g.sign(retry))


def run_cancel_apply_race(root_path):
    with group(root_path, lifecycle=True) as (g, c, receipts):
        binding = g.binding(c, receipts)
        control = prepared(g, binding)
        requests, permits, controls = {}, {}, {}
        for p in PARTIES[:2]:
            code, requests[p] = g.call(p, "challenge", control)
            assert code == 200
            code, permits[p] = g.w.request("permit", requests[p], identity=g.w.node[p])
            assert code == 200
            controls[p] = {"control": control, "authorization": authority(g, requests[p])}
        p = PARTIES[0]
        with ThreadPoolExecutor(max_workers=2) as pool:
            apply_future = pool.submit(g.call, p, "apply", permits[p])
            cancel_future = pool.submit(g.call, p, "cancel", controls[p])
            applied, cancelled = apply_future.result(), cancel_future.result()
        assert sorted((applied[0], cancelled[0])) == [200, 409]
        g.net.stop(p)
        g.start(p)
        if applied[0] == 200:
            assert g.call(p, "cancel", controls[p])[0] == 409
            assert g.call(p, "recover", control) == (200, applied[1])
        else:
            assert g.call(p, "cancel", controls[p]) == cancelled
            assert g.call(p, "apply", permits[p])[0] == 409


def run_durable_partial_cannot_cancel(root_path):
    with group(root_path, lifecycle=True) as (g, c, receipts):
        binding = g.binding(c, receipts)
        control = prepared(g, binding)
        p = PARTIES[0]
        code, request = g.call(p, "challenge", control)
        assert code == 200
        code, permit = g.w.request("permit", request, identity=g.w.node[p])
        assert code == 200
        code, withheld = g.call(p, "apply", permit)
        assert code == 200  # This real partial is NOT delivered to the witness yet.
        cancel = {"control": control, "authorization": authority(g, request)}
        assert g.call(p, "cancel", cancel)[0] == 409
        g.net.stop(p)
        g.start(p)
        assert g.call(p, "cancel", cancel)[0] == 409
        freeze(g)
        assert close(g, binding, [])[0] == 409
        assert g.call(p, "recover", control) == (200, withheld)
        code, _ = g.w.request("record", withheld, identity=g.w.node[p])
        assert code == 200
        assert close(g, binding, [])[0] == 409
