"""Actual node/RPC/W public finality, without ledger or migration acceptance.

Custody FROST keys/shares stay in their signers. Ephemeral TLS signatures are
used only to fault-inject a malicious public observer proof in negative cases.
"""

import copy
import hashlib
import json
import time
import uuid

from environment import private_file
from protected_acceptance import group
from refresh_acceptance import activate, freeze, plan, run_rounds
from seeded_enrollment import approval, call, claim
from test_dkg import PARTIES, encrypted_files, request
from witness_acceptance import sign, verify

PREFIX = "/internal/v1/solana/finality/"
PLAN_DOMAIN = "WITNESS_SOLANA_FINALITY_PLAN_V1"
REPORT_DOMAIN = "WITNESS_SOLANA_FINALITY_READY_V1"


def invoke(g, party, action, body, *, role=None):
    return request(
        g.net,
        party,
        role or ("courier" if g.custody_class == "COLD" else "coordinator"),
        PREFIX + action,
        body,
    )


def command(w, action):
    return w.command(action, w.query()["root"]["revision"])


def observe_execution(g, binding, package, *, head_fault=False, restart_node=False):
    execution = binding["authorized"]["intent"]["crypto_execution_id"]
    before = g.w.query(execution)
    source = before["root"]
    original = copy.deepcopy(before["execution"])
    value = {
        "version": 1,
        "observation_id": str(uuid.uuid4()),
        "witness_anchor": g.w.config["anchor_id"],
        "root": g.w.root,
        "observing_generation": source["generation"],
        "observing_node_keys": source["node_keys"],
        "expected_revision": source["revision"],
        "execution_id": execution,
        "binding_fingerprint": original["binding_fingerprint"],
        "signature_hex": original["signature"],
        "expires_at": int(time.time()) + 120,
    }
    payload = {
        "authorization": sign(g.w.life, PLAN_DOMAIN, value),
        "binding": binding,
        "signing_public_key_package": package,
    }
    wrong = copy.deepcopy(payload)
    wrong["authorization"]["signature"] = "00" * 70
    assert invoke(g, PARTIES[0], "query", wrong)[0] == 409
    queries, initial, final_queries = {}, {}, {}
    for party in PARTIES:
        code, queries[party] = invoke(g, party, "query", payload)
        assert code == 200, (party, queries[party])
        verify(g.w.node[party], "WITNESS_QUERY_V1", queries[party])
        code, initial[party] = g.w.request("query", queries[party], identity=g.w.courier)
        assert code == 200
        forged = copy.deepcopy(initial[party])
        forged["signature"] = "00" * 70
        assert invoke(g, party, "observe", forged)[0] == 409
        code, final_queries[party] = invoke(g, party, "observe", initial[party])
        assert code == 200, (party, final_queries[party])
        assert final_queries[party]["value"]["challenge"] != queries[party]["value"]["challenge"]
    if restart_node:
        g.net.stop(PARTIES[0])
        g.start(PARTIES[0])
    reports = []
    for party in PARTIES:
        # A correctly signed old initial reply cannot answer the final nonce.
        assert (
            invoke(
                g,
                party,
                "complete",
                {"observation_id": value["observation_id"], "witness": initial[party]},
            )[0]
            == 409
        )
        code, proof = g.w.request("query", final_queries[party], identity=g.w.courier)
        assert code == 200
        code, report = invoke(
            g, party, "complete", {"observation_id": value["observation_id"], "witness": proof}
        )
        assert code == 200, (party, report)
        verify(g.w.node[party], REPORT_DOMAIN, report)
        assert invoke(g, party, "recover", payload) == (200, report)
        reports.append(report)
    # A genuine observer signature cannot replace the independently pinned W
    # proof embedded in that observer's public report.
    forged = copy.deepcopy(reports)
    forged[0]["value"]["observed"]["initial_witness"]["signature"] = "00" * 70
    forged[0] = sign(g.w.node[PARTIES[0]], REPORT_DOMAIN, forged[0]["value"])
    assert (
        g.w.request("command", command(g.w, {"kind": "AcknowledgeFinality", "reports": forged}))[0]
        == 409
    )
    assert (
        g.w.request(
            "command",
            command(g.w, {"kind": "AcknowledgeFinality", "reports": reports[:2] + reports[1:2]}),
        )[0]
        == 409
    )
    acknowledgement = command(g.w, {"kind": "AcknowledgeFinality", "reports": reports})
    if head_fault:
        head = g.w.directory / "journal/initialized.json"
        backup = head.with_name("before-finality-head-fault")
        head.rename(backup)
        head.mkdir()
        try:
            assert g.w.request("command", acknowledgement)[0] == 409
            assert g.w.request("command", acknowledgement)[0] == 409
        finally:
            g.w.stop()
            head.rmdir()
            backup.rename(head)
        g.w.start()
    else:
        code, reply = g.w.request("command", acknowledgement)
        assert code == 200, reply
    after = g.w.query(execution)
    receipt = after["execution"]["finality"]
    assert after["execution"]["status"] == "SignedPending"
    assert after["execution"]["signature"] == original["signature"]
    assert after["execution"]["binding_fingerprint"] == original["binding_fingerprint"]
    assert (
        receipt["execution_id"] == execution
        and receipt["command_id"] == acknowledgement["value"]["request_id"]
    )
    assert receipt["observing_generation"] == source["generation"]
    assert set(receipt["status_context_slots"]) == set(PARTIES)
    assert g.w.request("command", acknowledgement)[0] == 200
    g.w.stop()
    g.w.start()
    assert g.w.query(execution)["execution"]["finality"] == receipt
    return receipt


def expired_binding(g, binding):
    binding["authorized"]["intent"]["expires_at"] = int(time.time()) + 8
    return g.w.authorize(binding["authorized"])


def run_public_finality(root_path, custody_class="HOT"):
    with group(root_path, custody_class, lifecycle=True) as (g, native, receipts):
        original_shares = encrypted_files(g.net, g.w.root["dkg"])
        signing_package = g.w.query()["root"]["public_key_package"]
        native_binding = expired_binding(g, g.binding(native, receipts, 9100))
        g.broadcast(native_binding, g.sign(native_binding))
        bindings = [native_binding]
        if custody_class == "HOT":
            g.validator.create_mint()
            token = claim(
                g.w.root,
                index=1,
                owner=native["owner_ref"],
                asset={
                    "kind": "ClassicToken",
                    "mint": str(g.validator.mint.pubkey()),
                    "decimals": 6,
                },
            )
            token_receipts = []
            for party in PARTIES:
                code, receipt = call(g.net, party, "approve", approval(g.net, "claim", token))
                assert code == 200
                token_receipts.append(receipt)
            g.w.register_claim(token, token_receipts)
            initialize = expired_binding(
                g, g.token_binding(token, token_receipts, 9101, create=True)
            )
            g.broadcast(initialize, g.sign(initialize))
            bindings.append(initialize)
        assert all(int(time.time()) >= b["authorized"]["intent"]["expires_at"] for b in bindings)
        freeze(g)
        if custody_class == "HOT":
            # A genuine same-key generation change precedes observation; the
            # old wire is verified with its OLD accepted public package.
            refresh = plan(g)
            ready = run_rounds(g, refresh)
            activate(g, refresh, ready)
            freeze(g)
        frames_before = {}
        for party in PARTIES:
            events = g.net.root / party / "protected-anchor/events"
            frames_before[party] = sum(
                json.loads(p.read_text())["value"]["change"]["kind"]
                in {"Request", "Consume", "Result"}
                for p in events.glob("*.json")
            )
        facts = []
        for n, binding in enumerate(bindings):
            unavailable = []
            if custody_class == "HOT" and n == 0:
                # Make every OLD original DKG artifact unavailable after genuine
                # Gen1 establishment. Public observation must not reload it.
                for party in PARTIES:
                    original_path = (
                        g.net.root / party / "storage" / f"{g.w.root['dkg']['keyset_id']}.share.enc"
                    )
                    backup_path = original_path.with_suffix(".enc.public-observation-fault")
                    original_path.rename(backup_path)
                    unavailable.append((original_path, backup_path))
            try:
                assert all(not old.exists() for old, _ in unavailable)
                facts.append(
                    observe_execution(
                        g,
                        binding,
                        signing_package,
                        head_fault=n == 0,
                        restart_node=(custody_class == "COLD" or n == 1),
                    )
                )
            finally:
                for old, backup in unavailable:
                    backup.rename(old)
            # Original generic daemon startup still requires its complete DKG
            # store. Node restart is tested after these original bytes return.

        assert encrypted_files(g.net, g.w.root["dkg"]) == original_shares
        for party in PARTIES:
            events = g.net.root / party / "protected-anchor/events"
            assert (
                sum(
                    json.loads(p.read_text())["value"]["change"]["kind"]
                    in {"Request", "Consume", "Result"}
                    for p in events.glob("*.json")
                )
                == frames_before[party]
            )
        private_file(
            root_path / "solana-public-finality-public-evidence.json",
            json.dumps(
                {
                    "scope": "actual public finality only; no financial settlement or migration",
                    "class": custody_class,
                    "actual_finalized_wires": len(facts),
                    "source_generation": g.w.query()["root"]["generation"]["epoch"],
                    "old_original_intents_expired": True,
                    "all_three_actual_nodes_queried_pinned_rpc": True,
                    "native_and_classic_initializer": custody_class == "HOT",
                    "observation_with_all_old_dkg_share_files_unavailable": custody_class == "HOT",
                    "signed_pending_and_signature_ownership_preserved": True,
                    "node_restart_and_witness_head_failure_recovered": True,
                    "new_private_requests_consumptions_results": 0,
                    "original_three_encrypted_dkg_shares_unchanged": True,
                    "metadata_fingerprints": [f["fact"]["metadata_fingerprint"] for f in facts],
                    "public_receipts_sha256": hashlib.sha256(
                        json.dumps(facts, sort_keys=True).encode()
                    ).hexdigest(),
                },
                sort_keys=True,
            ).encode(),
        )


def run_failed_public_finality(root_path):
    import base64

    from solders.message import Message
    from solders.signature import Signature
    from solders.transaction import Transaction

    with group(root_path, lifecycle=True) as (g, native, receipts):
        package = g.w.query()["root"]["public_key_package"]
        original = expired_binding(g, g.binding(native, receipts, 9200, amount=4000000))
        signature = g.sign(original)
        # Two genuinely approved legacy-control wires race for the same source.
        # The second lands first; the captured first wire then fails on-chain.
        competing = g.binding(native, receipts, 9201, amount=2000000)
        g.broadcast(competing, g.sign(competing))
        tx = Transaction.populate(
            Message.from_bytes(bytes.fromhex(original["authorized"]["payload_hex"])),
            [Signature.from_bytes(signature)],
        )
        txid = g.validator.rpc(
            "sendTransaction",
            [base64.b64encode(bytes(tx)).decode(), {"encoding": "base64", "skipPreflight": True}],
        )
        status, transaction = g.validator.wait(txid)
        assert status["err"] is not None and transaction["meta"]["err"] == status["err"]
        freeze(g)
        receipt = observe_execution(g, original, package)
        assert receipt["fact"]["outcome"]["kind"] == "Failed"
        assert (
            receipt["fact"]["fee_lamports"]
            == original["authorized"]["intent"]["expected_fee_lamports"]
        )
        refresh = plan(g)
        ready = run_rounds(g, refresh)
        activate(g, refresh, ready)
        # Replenish isolated operator test funding so a new attempt would pass
        # account preflight. The original signed logical operation stays owned.
        g.validator.fund(original["authorized"]["intent"]["financial_source"], 2000000)
        retry = g.binding(native, receipts, 9200, amount=4000000)
        events = g.w.directory / "journal/events"
        permits_before = sum(
            json.loads(p.read_text())["value"]["transition"]["kind"] == "Permit"
            for p in events.glob("*.json")
        )
        assert (
            g.call(PARTIES[0], "auto", {"binding": retry, "round": 1, "signing_package": None})[0]
            == 409
        )
        assert (
            sum(
                json.loads(p.read_text())["value"]["transition"]["kind"] == "Permit"
                for p in events.glob("*.json")
            )
            == permits_before
        )
        original_view = g.w.query(original["authorized"]["intent"]["crypto_execution_id"])[
            "execution"
        ]
        assert (
            original_view["status"] == "SignedPending"
            and original_view["signature"] == signature.hex()
        )
        private_file(
            root_path / "solana-public-finality-failure-public-evidence.json",
            json.dumps(
                {
                    "scope": "actual failed wire fact; no DB hold or ledger settlement",
                    "actual_two_genuine_mpc_wires_and_finalized_rollback": True,
                    "failed_wire_is_not_no_signature": True,
                    "actual_original_fee_retained": receipt["fact"]["fee_lamports"],
                    "logical_retry_denied_after_refresh_and_operator_refunding": True,
                    "new_witness_private_permits_for_retry": 0,
                },
                sort_keys=True,
            ).encode(),
        )
