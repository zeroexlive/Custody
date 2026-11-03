"""Actual W/three-node FROST generation proof; no new Claim receipt or wallet."""

import copy
import json
import secrets
from pathlib import Path
from uuid import uuid4

from environment import private_file
from protected_acceptance import group
from refresh_acceptance import activate, freeze, plan, run_rounds
from test_dkg import PARTIES, encrypted_files
from witness_acceptance import fingerprint, sign, verify


def candidate_query(g, candidate):
    value = dict(
        anchor_id=g.w.config["anchor_id"],
        root_identity=fingerprint("SOLANA_SEEDED_ROOT_V1", g.w.root),
        challenge=secrets.token_hex(32),
        execution_id=None,
        claim_reservation_id=candidate["reservation_id"],
        candidate_claim=candidate,
    )
    code, proof = g.w.request(
        "query", sign(g.w.node[PARTIES[0]], "WITNESS_QUERY_V1", value), identity=g.w.courier
    )
    assert code == 200, proof
    verify(g.w.identity, "WITNESS_QUERY_REPLY_V1", proof)
    assert proof["value"]["query"] == value
    return proof["value"]


def run_current_claim_authority(root_path):
    with group(root_path, lifecycle=True) as (g, original, _):
        ciphertexts = encrypted_files(g.net, g.w.root["dkg"])
        freeze(g)
        refresh = plan(g)
        ready = run_rounds(g, refresh)
        activate(g, refresh, ready)
        candidate = copy.deepcopy(original)
        candidate.update(
            reservation_id=str(uuid4()),
            owner_ref=f"p1:{uuid4()}",
            idempotency_key="actual-current-authority-query",
            index=1,
        )

        def query(claim):
            value = dict(
                anchor_id=g.w.config["anchor_id"],
                root_identity=fingerprint("SOLANA_SEEDED_ROOT_V1", g.w.root),
                challenge=secrets.token_hex(32),
                execution_id=None,
                claim_reservation_id=claim["reservation_id"],
                candidate_claim=claim,
            )
            code, proof = g.w.request(
                "query", sign(g.w.node[PARTIES[0]], "WITNESS_QUERY_V1", value), identity=g.w.courier
            )
            assert code == 200, proof
            verify(g.w.identity, "WITNESS_QUERY_REPLY_V1", proof)
            assert proof["value"]["query"] == value
            return proof["value"]

        before = g.w.query()["sequence"]
        observed = query(candidate)
        assert observed["claim"] is None and observed["root"]["next_claim_index"] == 1
        availability = observed["claim_availability"]
        assert availability == dict(
            reservation_id=candidate["reservation_id"], index=None, owner=None, retry=None
        )
        prepare = observed["generation_authority"]
        verify(g.w.life, "WITNESS_COMMAND_V1", prepare)
        assert prepare["value"]["action"]["kind"] == "Prepare"
        assert prepare["value"]["action"]["ready"] == ready
        assert prepare["value"]["action"]["node_keys"] == observed["root"]["node_keys"]
        for party, report in zip(PARTIES, prepare["value"]["action"]["ready"], strict=True):
            verify(g.w.node[party], "WITNESS_GENERATION_READY_V1", report)
        originals = []
        for path in (Path(g.w.config["directory"]) / "events").glob("*.json"):
            event = json.loads(path.read_text())["value"]["transition"]
            if (
                event["kind"] == "Command"
                and event["command"]["value"]["request_id"] == prepare["value"]["request_id"]
            ):
                originals.append(event["command"])
        assert originals == [prepare]
        conflicting = copy.deepcopy(candidate)
        conflicting["owner_ref"] = original["owner_ref"]
        assert query(conflicting)["claim_availability"]["owner"] == original["reservation_id"]
        assert g.w.query()["sequence"] == before
        g.w.stop()
        g.w.start()
        recovered = query(candidate)
        assert recovered["generation_authority"] == prepare
        assert recovered["claim_availability"] == availability
        assert recovered["sequence"] == before
        assert encrypted_files(g.net, g.w.root["dkg"]) == ciphertexts
        private_file(
            root_path / "solana-current-claim-authority-public-evidence.json",
            json.dumps(
                {
                    "scope": (
                        "actual W/FROST refresh proof and read-only candidate aliases; "
                        "no current Claim receipt/wallet/ledger activation"
                    ),
                    "actual_all_three_generation_ready": True,
                    "original_signed_prepare_recovered_exactly_after_restart": True,
                    "candidate_alias_query_is_read_only": True,
                    "occupied_original_owner_reported": True,
                    "original_dkg_ciphertexts_unchanged": True,
                },
                sort_keys=True,
            ).encode(),
        )
