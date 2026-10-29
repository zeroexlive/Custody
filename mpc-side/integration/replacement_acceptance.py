"""Public replacement authority and original signed-store upgrade acceptance.

The archive is actual public witness history from an independently executed
three-party DKG/claim acceptance. No private share or historical private key is
included. This case does NOT claim share repair, refresh or financial settlement.
"""

import hashlib
import json
import time
import uuid
from pathlib import Path

from environment import ca, issue, private_file
from seeded_enrollment import services
from test_dkg import PARTIES
from witness_acceptance import Witness, key_id, sign


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def run_reserved_upgrade(root_path):
    archive = json.loads(
        (
            Path(__file__).parents[1] / "witness/tests/fixtures/pre-replacement-journal.json"
        ).read_bytes()
    )
    root = archive["events"][1]["value"]["transition"]["command"]["value"]["action"]["evidence"][
        "statement"
    ]
    claim = archive["events"][2]["value"]["transition"]["command"]["value"]["action"]["evidence"]
    with services(root_path / "services") as net:
        w = Witness(net, root)
        public = w.directory / "original-public-certificates"
        public.mkdir()
        for role, pem in archive["certificates"].items():
            private_file(public / f"{role}.crt", pem.encode())
        next_recipient = w.directory / "second-recipient"
        issue(next_recipient, PARTIES[0], ca())
        w.config["anchor_id"] = archive["head"]["value"]["anchor_id"]
        w.config["archived_witness_certificates"] = [str(public / "witness.crt")]
        profile = w.config["profiles"]["HOT"]
        profile["receipt_certificates"] = {p: [str(public / f"{p}.crt")] for p in PARTIES}
        for p in PARTIES:
            profile["node_certificates"][p].append(str(public / f"{p}.crt"))
        profile["node_certificates"][PARTIES[0]].append(str(next_recipient / "tls.crt"))
        journal = Path(w.config["directory"])
        events = journal / "events"
        events.mkdir(parents=True)
        private_file(journal / "initialized.json", archive["original_head_json"].encode())
        originals = {}
        for index, event in enumerate(archive["events"]):
            path = events / f"{index:020}.json"
            originals[path.name] = archive["original_event_json"][index].encode()
            assert json.loads(originals[path.name]) == event
            private_file(path, originals[path.name])
        try:
            w.start()
            assert (journal / "initialized.json").read_bytes() == archive[
                "original_head_json"
            ].encode()
            view = w.query(claim_id=claim["statement"]["reservation_id"])
            assert view["root"]["original"] == root and view["claim"] == claim
            assert view["sequence"] == archive["head"]["value"]["sequence"]
            assert view.get("replacement") is None
            code, _ = w.request("command", w.command({"kind": "Freeze"}, view["root"]["revision"]))
            assert code == 200
            view = w.query()

            def plan(identity):
                roster = dict(view["root"]["node_keys"], **{PARTIES[0]: key_id(identity)})
                return {
                    "refresh": {
                        "anchor_id": w.config["anchor_id"],
                        "root": root,
                        "previous": view["root"]["generation"],
                        "previous_public_key_package": view["root"]["public_key_package"],
                        "session_id": str(uuid.uuid4()),
                        "ceremony_id": str(uuid.uuid4()),
                        "next_epoch": view["root"]["generation"]["epoch"] + 1,
                        "node_keys": roster,
                        "expires_at": int(time.time()) + 120,
                    },
                    "previous_node_keys": view["root"]["node_keys"],
                    "party_id": PARTIES[0],
                    "recipient_anchor_id": str(uuid.uuid4()),
                    "recipient_profile_sha256": hashlib.sha256(
                        b"public authority contract only"
                    ).hexdigest(),
                    "repair_session_id": str(uuid.uuid4()),
                    "repair_ceremony_id": str(uuid.uuid4()),
                }

            def reserve(p):
                return w.request(
                    "command",
                    w.command(
                        {"kind": "ReserveReplacement", "plan": p},
                        w.query()["root"]["revision"],
                    ),
                )

            def abandon(p):
                code, _ = w.request(
                    "command",
                    w.command(
                        {
                            "kind": "AbandonReplacement",
                            "repair_ceremony_id": p["repair_ceremony_id"],
                        },
                        w.query()["root"]["revision"],
                    ),
                )
                assert code == 200

            first = plan(w.node[PARTIES[0]])
            assert reserve(first)[0] == 200
            value = w.query()
            assert value["replacement"]["plan"] == first
            assert (
                value["replacement"]["original_evidence"]
                == archive["events"][1]["value"]["transition"]["command"]["value"]["action"][
                    "evidence"
                ]
            )
            assert value["root"]["node_keys"] == view["root"]["node_keys"]
            abandon(first)
            assert w.query().get("replacement") is None
            reused_key = plan(w.node[PARTIES[0]])
            assert reserve(reused_key)[0] == 409
            reused_anchor = plan(next_recipient)
            reused_anchor["recipient_anchor_id"] = first["recipient_anchor_id"]
            assert reserve(reused_anchor)[0] == 409
            second = plan(next_recipient)
            assert reserve(second)[0] == 200
            abandon(second)
            w.stop()
            w.start()
            assert w.query().get("replacement") is None
            assert reserve(plan(w.node[PARTIES[0]]))[0] == 409
            w.stop()
            for name, before in originals.items():
                assert (events / name).read_bytes() == before
            paths = sorted(events.glob("*.json"))
            new_event = paths[len(originals)]
            original_new_bytes = new_event.read_bytes()
            tampered = json.loads(original_new_bytes)
            assert tampered["value"]["rules"] == 1
            del tampered["value"]["rules"]  # Keep the real original signature.
            try:
                private_file(new_event, canonical(tampered))
                w.rejected_start()
            finally:
                private_file(new_event, original_new_bytes)
            w.start()
            current = w.query()
            duplicate = w.command(
                {"kind": "RegisterClaim", "evidence": claim}, current["root"]["revision"]
            )
            w.stop()
            last = json.loads(paths[-1].read_bytes())
            # A correctly signed, correctly chained orphan WAL event still may
            # not downgrade rules after the first new admission. This injected
            # event was never admitted/committed by the authority service.
            forged = sign(
                w.identity,
                "WITNESS_EVENT_V1",
                {
                    "anchor_id": w.config["anchor_id"],
                    "sequence": current["sequence"] + 1,
                    "previous_hash": hashlib.sha256(canonical(last)).hexdigest(),
                    "time": int(time.time()),
                    "transition": {"kind": "Command", "command": duplicate},
                },
            )
            injected = events / f"{current['sequence'] + 1:020}.json"
            try:
                private_file(injected, canonical(forged))
                w.rejected_start()
                assert (
                    b"authority event rules cannot downgrade"
                    in (w.directory / "service.log").read_bytes()
                )
            finally:
                injected.unlink()  # Only this deliberately invalid injected event.
            w.start()
            final = w.query(claim_id=claim["statement"]["reservation_id"])
            assert final["root"]["original"] == root and final["claim"] == claim
            assert final["root"]["generation"] == view["root"]["generation"]
            assert final["root"]["node_keys"] == view["root"]["node_keys"]
            assert final["sequence"] == current["sequence"]
            report = {
                "scope": "public replacement reservation and signed-store upgrade only",
                "original_signed_events_unchanged": len(originals),
                "original_root_claim_generation_roster_preserved": True,
                "explicit_abandon_and_fresh_identity_retry": True,
                "abandoned_identity_anchor_reuse_denied_after_restart": True,
                "stripped_rules_signature_rejected": True,
                "correctly_signed_chained_rules_downgrade_rejected": True,
                "private_share_repair_executed": False,
                "new_generation_activated": False,
            }
            private_file(
                root_path / "solana-replacement-witness-public-evidence.json", canonical(report)
            )
        finally:
            w.stop()
