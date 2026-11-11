"""Protected financial-boundary acceptance; no generic signing fallback."""

import hashlib
import json
import os

from environment import ca, issue, private_file
from protected_acceptance import group
from witness_acceptance import fingerprint, sign, verify


def run_custody_read_query(root_path):
    """Existing courier transport, exact classCustody signature, read-only result."""
    with group(root_path) as (g, c, receipts):
        before = g.w.query()
        events = {f: f.read_bytes() for f in (g.w.directory / "journal" / "events").glob("*.json")}
        query = {
            "anchor_id": g.w.config["anchor_id"],
            "root_identity": fingerprint("SOLANA_SEEDED_ROOT_V1", g.w.root),
            "challenge": os.urandom(32).hex(),
            "execution_id": None,
            "claim_reservation_id": c["reservation_id"],
        }
        signed = sign(g.w.custody, "WITNESS_QUERY_V1", query)
        code, response = g.w.request("query", signed, identity=g.w.courier)
        assert code == 200
        view = verify(g.w.identity, "WITNESS_QUERY_REPLY_V1", response)
        assert view["query"] == query and view["root"] == before["root"]
        assert view["claim"]["statement"] == c
        wrong = root_path / "unrelated-custody-key"
        issue(wrong, "custody", ca())
        assert (
            g.w.request("query", sign(wrong, "WITNESS_QUERY_V1", query), identity=g.w.courier)[0]
            == 409
        )
        assert (
            g.w.request(
                "query", sign(g.w.custody, "WITNESS_PERMIT_REQUEST_V1", query), identity=g.w.courier
            )[0]
            == 409
        )
        permit = g.w.permit(g.binding(c, receipts, 9900))
        permit = sign(g.w.custody, "WITNESS_PERMIT_REQUEST_V1", permit["value"])
        assert g.w.request("permit", permit, identity=g.w.courier)[0] == 409
        command = g.w.command({"kind": "Freeze"}, before["root"]["revision"])
        wrong_command = sign(g.w.custody, "WITNESS_COMMAND_V1", command["value"])
        assert g.w.request("command", wrong_command, identity=g.w.courier)[0] == 403
        assert g.w.request("command", wrong_command, identity=g.w.life)[0] == 409
        after = g.w.query()
        assert after["root"] == before["root"] and after["sequence"] == before["sequence"]
        assert set((g.w.directory / "journal" / "events").glob("*.json")) == set(events)
        assert all(f.read_bytes() == raw for f, raw in events.items())
        private_file(
            root_path / "solana-custody-read-query-public-evidence.json",
            json.dumps(
                {
                    "scope": "class-pinned Custody read query over existing courier TLS transport",
                    "exact_signed_witness_query_echo_root_and_registered_claim": True,
                    "wrong_custody_key_and_wrong_signature_domain_denied": True,
                    "custody_signature_cannot_create_private_permit_or_lifecycle_command": True,
                    "no_witness_event_sequence_root_or_raw_history_changed": True,
                    "tls_roles_and_trust_store_not_broadened": True,
                    "public_claim_json_sha256": hashlib.sha256(
                        json.dumps(c, sort_keys=True).encode()
                    ).hexdigest(),
                    "financial_signing_or_ledger_activation_executed": False,
                },
                sort_keys=True,
            ).encode(),
        )


def run_financial_mode(root_path):
    """Genuine crypto/mode boundary; reservation refs are synthetic, no DB ledger."""
    import copy
    import time
    import uuid

    from custody.solana_seeded import account_address
    from profile_migration_acceptance import chain
    from seeded_enrollment import approval, call, claim, enroll_all
    from solders.pubkey import Pubkey
    from test_dkg import PARTIES

    domain = "WITNESS_SOLANA_FINANCIAL_MODE_V1"
    with group(root_path, lifecycle=True, bootstrap_only=True) as (g, _, _):
        reports = enroll_all(g.net, g.original_root)
        g.w.start(initialize=True)
        g.w.enroll(reports)
        before = g.w.query()
        assert before["root"].get("financial_mode") is None
        value = {
            "version": 1,
            "activation_id": str(uuid.uuid4()),
            "witness_anchor": g.w.config["anchor_id"],
            "root": g.original_root,
            "generation": before["root"]["generation"],
            "node_keys": before["root"]["node_keys"],
            "expires_at": int(time.time()) + 120,
        }
        approvals = {
            "custody": sign(g.w.custody, domain, value),
            "policy": sign(g.w.policy, domain, value),
            "custody_certificate_chain_der_hex": chain(g.w.custody),
            "policy_certificate_chain_der_hex": chain(g.w.policy),
        }
        wrong = copy.deepcopy(approvals)
        wrong["policy"]["signature"] = "00" * 70
        assert (
            g.w.request(
                "command",
                g.w.command(
                    {"kind": "EnableFinancialMode", "approvals": wrong}, before["root"]["revision"]
                ),
            )[0]
            == 409
        )
        enable = g.w.command(
            {"kind": "EnableFinancialMode", "approvals": approvals}, before["root"]["revision"]
        )
        assert g.w.request("command", enable)[0] == 200
        mode = g.w.query()["root"]["financial_mode"]
        assert mode == {
            "version": 1,
            "activation_id": value["activation_id"],
            "command_id": enable["value"]["request_id"],
        }
        g.w.stop()
        g.w.start()
        assert g.w.query()["root"]["financial_mode"] == mode
        assert g.w.request("command", enable)[0] == 200
        second = copy.deepcopy(value)
        second["activation_id"] = str(uuid.uuid4())
        again = dict(
            approvals,
            custody=sign(g.w.custody, domain, second),
            policy=sign(g.w.policy, domain, second),
        )
        assert (
            g.w.request(
                "command",
                g.w.command(
                    {"kind": "EnableFinancialMode", "approvals": again},
                    g.w.query()["root"]["revision"],
                ),
            )[0]
            == 409
        )
        c = claim(g.original_root, owner=f"p1:{uuid.uuid4()}")
        receipts = []
        for party in PARTIES:
            code, receipt = call(g.net, party, "approve", approval(g.net, "claim", c))
            assert code == 200
            receipts.append(receipt)
        g.w.register_claim(c, receipts)
        base = str(Pubkey.from_bytes(bytes.fromhex(g.original_root["group_public_key"])))
        g.validator.fund(base, 200000000)
        g.validator.fund(account_address(base, c["index"]), 5000000)
        legacy = g.binding(c, receipts, 9910)
        denied = g.w.permit(legacy)
        assert g.w.request("permit", denied, identity=g.w.courier)[0] == 409
        assert g.w.query(legacy["authorized"]["intent"]["crypto_execution_id"])["execution"] is None
        binding = g.binding(c, receipts, 9911)
        i = binding["authorized"]["intent"]
        i["operation_type"] = "WITHDRAWAL"
        i["financial"] = {
            "version": 1,
            "reservation_id": str(uuid.uuid4()),
            "tenant_id": g.original_root["ownership_scope"],
            "reservation_owner_ref": f"p1:{uuid.uuid4()}",
            "source_owner_ref": c["owner_ref"],
            "source_role": "TENANT_TREASURY",
            "operation_type": "WITHDRAWAL",
            "operation_id": i["operation_id"],
            "approval_id": str(uuid.uuid4()),
            "asset_key": i["asset_key"],
        }
        binding = g.w.authorize(binding["authorized"])
        code, request = g.call(
            PARTIES[0], "challenge", {"binding": binding, "round": 1, "signing_package": None}
        )
        assert code == 200
        code, permit = g.w.request("permit", request, identity=g.w.courier)
        assert code == 200 and permit["value"]["financial_mode"] == mode
        code, first_report = g.call(PARTIES[0], "apply", permit)
        assert code == 200
        assert g.w.request("record", first_report, identity=g.w.courier)[0] == 200
        # Normal auto advancement recovers this exact original public result.
        tx, _ = g.broadcast(binding, g.sign(binding))
        other = g.binding(c, receipts, 9912)
        other["authorized"]["intent"]["operation_type"] = "WITHDRAWAL"
        reused = copy.deepcopy(i["financial"])
        reused["operation_id"] = 9912
        other["authorized"]["intent"]["financial"] = reused
        other = g.w.authorize(other["authorized"])
        assert (
            g.call(PARTIES[0], "auto", {"binding": other, "round": 1, "signing_package": None})[0]
            == 409
        )
        assert g.w.query()["root"]["financial_mode"] == mode
        from refresh_acceptance import activate, freeze, plan, run_rounds

        freeze(g)
        maintenance = plan(g)
        ready = run_rounds(g, maintenance)
        activate(g, maintenance, ready)
        assert g.w.query()["root"]["financial_mode"] == mode
        for party in PARTIES:
            g.net.stop(party)
            g.start(party)
        next_binding = g.binding(c, receipts, 9913)
        next_intent = next_binding["authorized"]["intent"]
        next_intent["operation_type"] = "WITHDRAWAL"
        next_financial = copy.deepcopy(i["financial"])
        next_financial.update(
            reservation_id=str(uuid.uuid4()), approval_id=str(uuid.uuid4()), operation_id=9913
        )
        next_intent["financial"] = next_financial
        next_binding = g.w.authorize(next_binding["authorized"])
        next_binding["selected_signers"] = [PARTIES[0], PARTIES[2]]
        assert next_intent["generation"]["epoch"] == 1
        next_tx, _ = g.broadcast(next_binding, g.sign(next_binding))
        private_file(
            root_path / "solana-financial-mode-public-evidence.json",
            json.dumps(
                {
                    "scope": "financial Root crypto guard; synthetic refs, no DB ledger",
                    "custody_policy_and_lifecycle_required_before_first_claim": True,
                    "activation_and_exact_ack_recovered_after_witness_restart": True,
                    "no_disable_or_second_activation": True,
                    "legacy_none_financial_intent_denied_before_any_witness_grant": True,
                    "explicit_reservation_owner_differs_from_treasury_source_owner": True,
                    "mode_metadata_in_current_private_permission": True,
                    "same_financial_reservation_cannot_back_another_operation": True,
                    "mode_retained_through_actual_refresh_activate_and_signer_restart": True,
                    "genuine_mpc_transfers_finalized_original_and_refreshed_generations": [
                        tx,
                        next_tx,
                    ],
                    "database_financial_wallet_activation_or_ledger_integration_executed": False,
                },
                sort_keys=True,
            ).encode(),
        )
