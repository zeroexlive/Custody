"""Genuine original-profile migration and separate public authority negatives.

Public-registration cases exercise witness authority only. Terminal/import cases
use fixed original4a binaries and preserve their exact signed raw history; runtime
cases additionally migrate the original nodes, resolve an original pending R2,
refresh and finalize transfers. Controllers never read MPC shares or nonces.
"""

import copy
import hashlib
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from environment import private_file
from profile_migration_baseline import binary_sha256
from protected_acceptance import group
from refresh_acceptance import freeze
from repair_acceptance import canonical, profile_hash
from test_dkg import PARTIES
from witness_acceptance import fingerprint, key_id, sign

APPROVAL = "WITNESS_PROFILE_MIGRATION_APPROVAL_V1"
FENCE = "WITNESS_PROFILE_MIGRATION_FENCE_V1"
RENEWAL = "WITNESS_PROFILE_MIGRATION_RENEWAL_V1"


def chain(identity):
    return [
        x509.load_pem_x509_certificate((identity / "tls.crt").read_bytes())
        .public_bytes(serialization.Encoding.DER)
        .hex()
    ]


def approvals(g, value, domain):
    return {
        "custody": sign(g.w.custody, domain, value),
        "policy": sign(g.w.policy, domain, value),
        "lifecycle": sign(g.w.life, domain, value),
        "custody_certificate_chain_der_hex": chain(g.w.custody),
        "policy_certificate_chain_der_hex": chain(g.w.policy),
    }


def fence(g, *, expired=False):
    view = g.w.query()["root"]
    node = g.profiles[PARTIES[0]]
    head = json.loads((Path(node["anchor_directory"]) / "initialized.json").read_bytes())["value"]
    original_profile = profile_hash(node)
    assert head["profile"] == original_profile
    now = int(time.time())
    value = {
        "migration_id": str(uuid.uuid4()),
        "witness_anchor": g.w.config["anchor_id"],
        "party_id": PARTIES[0],
        "node_key_id": key_id(g.w.node[PARTIES[0]]),
        "old_profile_sha256": original_profile,
        "new_profile_sha256": hashlib.sha256(b"public authority contract only").hexdigest(),
        "source_sequence": head["sequence"],
        "source_event_hash": head["event_hash"],
        "new_anchor_id": str(uuid.uuid4()),
        "new_lifecycle_key_id": key_id(g.w.life),
        "cohort": [
            {k: view[k] for k in ("original", "generation", "public_key_package", "node_keys")}
        ],
        "expires_at": now - 1 if expired else now + 240,
    }
    # Intentionally signed now with a BACKDATED local timestamp. Independent
    # witness freshness must refuse it when original dual approval expired.
    return sign(
        g.w.node[PARTIES[0]],
        FENCE,
        {
            "approvals": approvals(g, value, APPROVAL),
            "fenced_at": now - 5 if expired else now,
        },
    )


def install(g, original, renewal=None, *, command=None):
    command = command or g.w.command(
        {
            "kind": "InstallNodeProfile",
            "fence": original,
            "renewal": renewal,
        },
        g.w.query()["root"]["revision"],
    )
    code, reply = g.w.request("command", command)
    return code, reply, command


def run_public_registration(root_path):
    with group(root_path, lifecycle=False) as (g, c, receipts):
        assert all("lifecycle_certificate" not in p for p in g.profiles.values())
        originals = {
            f: hashlib.sha256(f.read_bytes()).hexdigest()
            for party in PARTIES
            for f in (g.net.root / party / "storage").glob("*.share.enc")
        }
        freeze(g)
        before = g.w.query()
        original_events = {
            f: f.read_bytes() for f in (g.w.directory / "journal/events").glob("*.json")
        }
        expired = fence(g, expired=True)
        assert install(g, expired)[0] == 409
        assert g.w.query()["sequence"] == before["sequence"]
        current = fence(g)
        bad = copy.deepcopy(current["value"])
        bad["approvals"]["policy"]["signature"] = "00" * 70
        assert install(g, sign(g.w.node[PARTIES[0]], FENCE, bad))[0] == 409
        bad = copy.deepcopy(current["value"])
        bad["approvals"]["custody_certificate_chain_der_hex"] = chain(g.w.policy)
        assert install(g, sign(g.w.node[PARTIES[0]], FENCE, bad))[0] == 409
        p = expired["value"]["approvals"]["custody"]["value"]
        renewal = approvals(
            g,
            {
                "migration_id": p["migration_id"],
                "plan_identity": fingerprint("SOLANA_PROFILE_MIGRATION_PLAN_V1", p),
                "fence_identity": fingerprint(
                    "SOLANA_PROFILE_MIGRATION_FENCE_V1", expired["value"]
                ),
                "renewal_id": str(uuid.uuid4()),
                "expires_at": int(time.time()) + 120,
            },
            RENEWAL,
        )
        wrong = copy.deepcopy(renewal)
        wrong["custody"]["signature"] = "00" * 70
        assert install(g, expired, wrong)[0] == 409
        code, ack, original_command = install(g, expired, renewal)
        assert code == 200, ack
        view = g.w.query()
        pin = view["node_profiles"][PARTIES[0]]
        assert pin["profile_sha256"] == p["new_profile_sha256"]
        assert pin["authority_id"] == p["migration_id"]
        assert pin["node_key_id"] == p["node_key_id"]
        assert (
            view["root"]["phase"] == "Frozen"
            and view["root"]["generation"] == before["root"]["generation"]
        )
        # A genuinely running old LC=None profile can still create a public
        # challenge here, but the independently pinned witness denies its actual
        # old fingerprint before granting private authority. This is not a local
        # terminal journal-fence test or a successor-import claim.
        b = g.binding(c, receipts, 9201)
        assert (
            g.call(
                PARTIES[0],
                "auto",
                {
                    "binding": b,
                    "round": 1,
                    "signing_package": None,
                },
            )[0]
            == 409
        )
        g.w.stop()
        g.w.start()
        after = g.w.query()
        assert after["node_profiles"] == view["node_profiles"]
        assert install(g, expired, renewal, command=original_command)[0] == 200
        assert g.w.query()["sequence"] == after["sequence"]
        assert all(f.read_bytes() == raw for f, raw in original_events.items())
        assert all(
            hashlib.sha256(f.read_bytes()).hexdigest() == digest for f, digest in originals.items()
        )
        private_file(
            root_path / "solana-profile-migration-public-evidence.json",
            canonical(
                {
                    "scope": "public witness profile migration authority only",
                    "original_lifecycle_none_profiles": True,
                    "backdated_local_fence_expired_dual_approval_denied": True,
                    "wrong_policy_signature_and_current_custody_role_chain_denied": True,
                    "fresh_exact_original_dual_renewal_admitted": True,
                    "same_command_ack_loss_restart_replay_idempotent": True,
                    "original_witness_events_and_dkg_ciphertexts_unchanged": True,
                    "local_terminal_journal_migration_executed": False,
                    "successor_profile_private_signing_executed": False,
                }
            ),
        )


def cli(
    binary, command, old, *, new=None, approvals_path=None, leases=None, frozen=None, output=None
):
    args = [str(binary), command, "--old-profile", str(old)]
    for flag, value in (
        ("--new-profile", new),
        ("--approvals", approvals_path),
        ("--leases", leases),
        ("--frozen", frozen),
        ("--output", output),
    ):
        if value is not None:
            args.extend([flag, str(value)])
    result = subprocess.run(args, capture_output=True, text=True, check=True, timeout=20)
    return (
        json.loads(Path(output).read_bytes()) if output is not None else json.loads(result.stdout)
    )


def rejected(binary, environment, *, initialize=False):
    process = subprocess.Popen(
        [str(binary), *(["--initialize"] if initialize else [])],
        env=os.environ | environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert process.wait(timeout=10) != 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def run_terminal_fence(root_path, baseline_bin, current_bin, *, import_successor=False):
    """Actual old LC=None history, terminal fencing and optional offline import."""
    baseline_bin, current_bin = Path(baseline_bin), Path(current_bin)
    metadata = json.loads((baseline_bin.parent / "build-identity.json").read_bytes())
    assert metadata["source_sha"] == "4a4e6ffca0d7107d53e742144f52838a3473f32e"
    assert all(
        binary_sha256(baseline_bin / name) == digest
        for name, digest in metadata["binaries"].items()
    )
    tool = current_bin / "wallet-mpc-profile-migration"
    with group(root_path, lifecycle=False, binary_directory=baseline_bin) as (g, c, receipts):
        b = g.binding(c, receipts, 9301)
        g.broadcast(b, g.sign(b))
        old = Path(g.net.configs[PARTIES[0]]["MPC_PROTECTED_PROFILE"])
        anchor = Path(g.profiles[PARTIES[0]]["anchor_directory"])
        original_events = {f: f.read_bytes() for f in (anchor / "events").glob("*.json")}
        requests = 0
        consumes = 0
        for raw in original_events.values():
            change = json.loads(raw)["value"]["change"]
            if change["kind"] == "Request":
                assert "node_profile_sha256" not in change["request"]["value"]
                requests += 1
            if change["kind"] == "Consume":
                permit = change["permit"]["value"]
                assert "node_profile" not in permit
                assert "node_profile_sha256" not in permit["request"]
                consumes += 1
        assert requests == consumes == 2
        original_head_bytes = (anchor / "initialized.json").read_bytes()
        ciphertexts = {
            f: hashlib.sha256(f.read_bytes()).hexdigest()
            for party in PARTIES
            for f in (g.net.root / party / "storage").glob("*.share.enc")
        }
        assert len(ciphertexts) == 3
        freeze(g)
        for party in PARTIES:
            g.net.stop(party)
        g.w.stop()
        g.net.bin = current_bin
        g.w.start()  # Genuine original None-request witness replay through new binary.
        inspected = cli(tool, "inspect", old)
        p = fence(g)["value"]["approvals"]["custody"]["value"]
        assert inspected["source_profile_sha256"] == p["old_profile_sha256"]
        assert inspected["source_head"]["value"]["sequence"] == p["source_sequence"]
        successor = copy.deepcopy(g.profiles[PARTIES[0]])
        successor["lifecycle_certificate"] = str(g.w.life / "tls.crt")
        successor["anchor_directory"] = str(g.net.root / PARTIES[0] / "successor-anchor")
        successor["profile_migration"] = {
            "migration_id": p["migration_id"],
            "anchor_id": p["new_anchor_id"],
            "source_profile": str(old),
            "source_profile_sha256": p["old_profile_sha256"],
            "source_anchor": str(anchor),
            "source_sequence": p["source_sequence"],
            "source_event_hash": p["source_event_hash"],
            "cohort": [fingerprint("SOLANA_SEEDED_ROOT_V1", g.w.root)],
        }
        new = old.parent / "successor.json"
        private_file(new, canonical(successor))
        p["new_profile_sha256"] = profile_hash(successor)
        approved = old.parent / "migration-approvals.json"
        private_file(approved, canonical(approvals(g, p, APPROVAL)))
        leases = cli(tool, "challenge", old, new=new, approvals_path=approved)
        replies = {}
        for root, lease in leases.items():
            code, replies[root] = g.w.request(
                "query", lease["value"]["query"], identity=g.w.courier
            )
            assert code == 200
        lease_file, reply_file = old.parent / "leases.json", old.parent / "frozen.json"
        private_file(lease_file, canonical(leases))
        private_file(reply_file, canonical(replies))
        # Wrong source pointers and unsafe output destinations must fail BEFORE
        # the irreversible original journal fence, not merely fail to return it.
        wrong_source = old.parent / "wrong-source-reference.json"
        private_file(wrong_source, b"{}")
        wrong_successor = copy.deepcopy(successor)
        wrong_successor["profile_migration"]["source_profile"] = str(wrong_source)
        wrong_path = old.parent / "wrong-successor.json"
        private_file(wrong_path, canonical(wrong_successor))
        try:
            cli(tool, "inspect", old, new=wrong_path)
        except subprocess.CalledProcessError as error:
            assert "exact predecessor" in error.stderr
        else:
            raise AssertionError("wrong successor source pointer accepted")
        existing_output = root_path / "occupied-output.json"
        private_file(existing_output, b"public fault input")
        before_head = cli(tool, "inspect", old, new=new)["source_head"]
        for destination in (
            anchor / "events" / f"{p['source_sequence'] + 1:020}.json",
            Path(successor["signer"]["storage_directory"]) / "not-an-output.json",
            old.parent / "not-a-profile-output.json",
            existing_output,
        ):
            try:
                cli(
                    tool,
                    "fence",
                    old,
                    new=new,
                    approvals_path=approved,
                    leases=lease_file,
                    frozen=reply_file,
                    output=destination,
                )
            except subprocess.CalledProcessError as error:
                assert "migration output" in error.stderr
            else:
                raise AssertionError("unsafe output accepted before original fence")
            assert cli(tool, "inspect", old, new=new)["source_head"] == before_head
            assert len(list((anchor / "events").glob("*.json"))) == len(original_events)
        result = cli(
            tool,
            "fence",
            old,
            new=new,
            approvals_path=approved,
            leases=lease_file,
            frozen=reply_file,
        )
        assert result["terminal_fence"] is not None and result["successor_import_available"] is True
        after = result["source_head"]
        assert after["value"]["sequence"] == p["source_sequence"] + 1
        retry = cli(
            tool,
            "fence",
            old,
            new=new,
            approvals_path=approved,
            leases=lease_file,
            frozen=reply_file,
        )
        assert retry == result
        assert all(f.read_bytes() == raw for f, raw in original_events.items())
        assert len(list((anchor / "events").glob("*.json"))) == len(original_events) + 1
        terminal = json.loads(sorted((anchor / "events").glob("*.json"))[-1].read_bytes())
        assert (
            terminal["value"]["change"]["admission"]["original_head_json"].encode()
            == original_head_bytes
        )
        rejected(baseline_bin / "wallet-mpc-protected-signer", g.net.configs[PARTIES[0]])
        rejected(current_bin / "wallet-mpc-protected-signer", g.net.configs[PARTIES[0]])
        target_env = dict(g.net.configs[PARTIES[0]], MPC_PROTECTED_PROFILE=str(new))
        rejected(current_bin / "wallet-mpc-protected-signer", target_env, initialize=True)
        assert not (Path(successor["anchor_directory"]) / "initialized.json").exists()
        if import_successor:
            # Own source-stage leases never authorize successor genesis. Even
            # fresh successor-stage proofs must contain the actual installed pin.
            def successor_proofs():
                successor_leases = cli(tool, "successor-challenge", old, new=new)
                successor_replies = {}
                for root, lease in successor_leases.items():
                    code, successor_replies[root] = g.w.request(
                        "query", lease["value"]["query"], identity=g.w.courier
                    )
                    assert code == 200
                private_file(lease_file, canonical(successor_leases))
                private_file(reply_file, canonical(successor_replies))

            def rejected_import():
                try:
                    cli(tool, "import", old, new=new, leases=lease_file, frozen=reply_file)
                except subprocess.CalledProcessError:
                    pass
                else:
                    raise AssertionError("uninstalled or source-purpose proof authorized import")
                assert not (Path(successor["anchor_directory"]) / "initialized.json").exists()
                assert not list((Path(successor["anchor_directory"]) / "events").glob("*.json"))

            rejected_import()
            successor_proofs()
            rejected_import()
        code, _, _ = install(g, result["terminal_fence"])
        assert code == 200
        if import_successor:
            from refresh_acceptance import abandon as abandon_refresh
            from refresh_acceptance import plan as refresh_plan
            from refresh_acceptance import reserve as reserve_refresh

            pending_refresh = refresh_plan(g)
            assert reserve_refresh(g, pending_refresh)[0] == 200
            successor_proofs()
            rejected_import()  # Known pending lifecycle must be abandoned first.
            abandon_refresh(g, pending_refresh)
            successor_proofs()
            imported = cli(tool, "import", old, new=new, leases=lease_file, frozen=reply_file)
            assert imported["successor_history_imported"] is True
            assert imported["private_round_executed"] is False
            assert imported["records"] == {
                "requests": 2,
                "consumed": 2,
                "reports": 2,
                "ceremonies": 0,
                "ready": 0,
                "cancelled": 0,
                "repairs": 0,
                "repaired": 0,
                "replacement_refresh": 0,
            }
            assert cli(tool, "verify", old, new=new) == imported
            assert (
                cli(tool, "import", old, new=new, leases=lease_file, frozen=reply_file) == imported
            )
            target = Path(successor["anchor_directory"])
            genesis_path = target / "events" / f"{0:020}.json"
            genesis_bytes = genesis_path.read_bytes()
            source_head_bytes = (anchor / "initialized.json").read_bytes()
            genesis = json.loads(genesis_bytes)
            assert (
                genesis["value"]["change"]["admission"]["source_head_json"].encode()
                == source_head_bytes
            )
            # A missing predecessor byte cannot be replaced by signed genesis.
            original_path, original_raw = next(iter(original_events.items()))
            private_file(original_path, original_raw + b"fault")
            try:
                cli(tool, "verify", old, new=new)
            except subprocess.CalledProcessError:
                pass
            else:
                raise AssertionError("successor bypassed corrupt original source")
            private_file(original_path, original_raw)
            assert cli(tool, "verify", old, new=new) == imported
            # Simulate death after immutable genesis durability but before head.
            (target / "initialized.json").unlink()
            try:
                cli(tool, "verify", old, new=new)
            except subprocess.CalledProcessError:
                pass
            else:
                raise AssertionError("normal replay accepted missing successor head")
            recovered = cli(tool, "import", old, new=new, leases=lease_file, frozen=reply_file)
            assert recovered["records"] == imported["records"]
            assert recovered["successor_head"]["value"] == imported["successor_head"]["value"]
            assert genesis_path.read_bytes() == genesis_bytes
            assert (anchor / "initialized.json").read_bytes() == source_head_bytes
            assert all(f.read_bytes() == raw for f, raw in original_events.items())
            private_file(
                root_path / "solana-profile-successor-import-public-evidence.json",
                canonical(
                    {
                        "scope": "offline verified successor import; no private round executed",
                        "genuine_original4a_none_requests": 2,
                        "genuine_original4a_none_consumes": 2,
                        "original_public_results_imported": 2,
                        "all_original_raw_events_and_final_head_unchanged": True,
                        "source_stage_and_uninstalled_profile_queries_rejected": True,
                        "pending_refresh_requires_abandon_before_import": True,
                        "successor_requires_complete_original_source_on_every_replay": True,
                        "exact_retry_and_orphan_genesis_recovery_preserve_original_genesis": True,
                        "successor_private_signing_executed": False,
                    }
                ),
            )
        assert g.w.query()["node_profiles"][PARTIES[0]]["profile_sha256"] == p["new_profile_sha256"]
        assert g.w.query()["root"]["phase"] == "Frozen"
        assert all(
            hashlib.sha256(f.read_bytes()).hexdigest() == digest
            for f, digest in ciphertexts.items()
        )
        private_file(
            root_path / "solana-profile-terminal-fence-public-evidence.json",
            canonical(
                {
                    "scope": "genuine original4a LC=None source journal terminal fence only",
                    "original_none_requests_preserved": requests,
                    "original_none_consumes_preserved": consumes,
                    "original_raw_events_preserved": len(original_events),
                    "exact_one_terminal_event": True,
                    "old_and_current_old_profile_writers_rejected": True,
                    "normal_successor_initialize_cannot_reset_history": True,
                    "exact_retry_retains_same_head_and_fence": True,
                    "original_dkg_ciphertexts_unchanged": 3,
                    "witness_profile_pin_registered_root_frozen": True,
                    "successor_history_import_executed": import_successor,
                    "successor_private_signing_executed": False,
                    "wrong_source_reference_and_unsafe_output_denied_before_mutation": True,
                }
            ),
        )


def migrate_stopped_party(g, party, cohort, tool):
    """All private services are stopped; all Roots remain independently Frozen."""
    old = Path(g.net.configs[party]["MPC_PROTECTED_PROFILE"])
    original = g.profiles[party]
    inspected = cli(tool, "inspect", old)
    head = inspected["source_head"]["value"]
    p = {
        "migration_id": str(uuid.uuid4()),
        "witness_anchor": g.w.config["anchor_id"],
        "party_id": party,
        "node_key_id": key_id(g.w.node[party]),
        "old_profile_sha256": inspected["source_profile_sha256"],
        "source_sequence": head["sequence"],
        "source_event_hash": head["event_hash"],
        "new_anchor_id": str(uuid.uuid4()),
        "new_lifecycle_key_id": key_id(g.w.life),
        "cohort": cohort,
        "expires_at": int(time.time()) + 240,
    }
    successor = copy.deepcopy(original)
    successor["lifecycle_certificate"] = str(g.w.life / "tls.crt")
    successor["anchor_directory"] = str(g.net.root / party / "successor-anchor")
    successor["profile_migration"] = {
        "migration_id": p["migration_id"],
        "anchor_id": p["new_anchor_id"],
        "source_profile": str(old),
        "source_profile_sha256": p["old_profile_sha256"],
        "source_anchor": original["anchor_directory"],
        "source_sequence": head["sequence"],
        "source_event_hash": head["event_hash"],
        "cohort": [fingerprint("SOLANA_SEEDED_ROOT_V1", r["original"]) for r in cohort],
    }
    new = old.parent / "successor.json"
    private_file(new, canonical(successor))
    p["new_profile_sha256"] = profile_hash(successor)
    approved = old.parent / "migration-approvals.json"
    private_file(approved, canonical(approvals(g, p, APPROVAL)))
    lease_file, reply_file = old.parent / "leases.json", old.parent / "frozen.json"

    def proofs(command):
        leases = cli(tool, command, old, new=new, approvals_path=approved)
        replies = {}
        for root, lease in leases.items():
            code, replies[root] = g.w.request(
                "query", lease["value"]["query"], identity=g.w.courier
            )
            assert code == 200
        private_file(lease_file, canonical(leases))
        private_file(reply_file, canonical(replies))

    proofs("challenge")
    fenced = cli(
        tool, "fence", old, new=new, approvals_path=approved, leases=lease_file, frozen=reply_file
    )
    for root in cohort:
        g.w.root = root["original"]
        code, _, command = install(g, fenced["terminal_fence"])
        assert code == 200
        assert install(g, fenced["terminal_fence"], command=command)[0] == 200
    proofs("successor-challenge")
    imported = cli(tool, "import", old, new=new, leases=lease_file, frozen=reply_file)
    assert imported["successor_history_imported"] is True
    assert cli(tool, "verify", old, new=new) == imported
    g.profiles[party] = successor
    g.net.configs[party]["MPC_PROTECTED_PROFILE"] = str(new)
    return imported


def run_migrated_runtime(root_path, baseline_bin, current_bin, *, custody_class="HOT"):
    """Two migrated old Roots plus one excluded Root; preserve unknown old R2."""
    from custody.solana_seeded import account_address
    from no_release_acceptance import authority, close, prepared
    from refresh_acceptance import activate, plan, run_rounds
    from refresh_acceptance import call as refresh_call
    from refresh_acceptance import start as refresh_start
    from seeded_enrollment import approval, call, claim, enroll_all
    from solders.pubkey import Pubkey
    from test_dkg import control as dkg_control
    from test_dkg import dkg_request, execute

    baseline_bin, current_bin = Path(baseline_bin), Path(current_bin)
    metadata = json.loads((baseline_bin.parent / "build-identity.json").read_bytes())
    assert metadata["source_sha"] == "4a4e6ffca0d7107d53e742144f52838a3473f32e"
    assert all(
        binary_sha256(baseline_bin / name) == digest
        for name, digest in metadata["binaries"].items()
    )
    with group(root_path, custody_class, lifecycle=False, binary_directory=baseline_bin) as (
        g,
        c,
        receipts,
    ):
        roots = [(copy.deepcopy(g.w.root), c, receipts)]
        for _ in range(2):
            dkg = dict(dkg_request(), custody_class=custody_class)
            code, report = execute(g.net, dkg)
            assert code == 200 and report["status"] == "COMPLETED"
            second = dict(
                g.w.root,
                dkg=dkg,
                group_public_key=report["group_public_key"],
                public_key_package=report["participant_agreement"][0]["public_key_package"],
            )
            root_reports = enroll_all(g.net, second)
            second_claim = claim(second, owner=f"p1:{uuid.uuid4()}")
            second_receipts = []
            for party in PARTIES:
                code, receipt = call(
                    g.net, party, "approve", approval(g.net, "claim", second_claim)
                )
                assert code == 200
                second_receipts.append(receipt)
            g.w.root = second
            g.w.enroll(root_reports)
            g.w.register_claim(second_claim, second_receipts)
            base = str(Pubkey.from_bytes(bytes.fromhex(second["group_public_key"])))
            g.validator.fund(base, 200000000)
            roots.append((second, second_claim, second_receipts))
        for n, (root, current_claim, current_receipts) in enumerate(roots):
            g.w.root = root
            base = str(Pubkey.from_bytes(bytes.fromhex(root["group_public_key"])))
            g.validator.fund(account_address(base, current_claim["index"]), 20000000)
            binding = g.binding(
                current_claim,
                current_receipts,
                9400 + n,
                pair=((PARTIES[0], PARTIES[1]), (PARTIES[0], PARTIES[2]), (PARTIES[1], PARTIES[2]))[
                    n
                ],
            )
            g.broadcast(binding, g.sign(binding))
        g.w.root = roots[0][0]
        pending = g.binding(c, receipts, 9410)
        pending_control = prepared(g, pending)
        pending_requests, pending_permits = {}, {}
        role = "courier" if custody_class == "COLD" else "coordinator"
        for party in PARTIES[:2]:
            code, pending_requests[party] = g.call(party, "challenge", pending_control, role=role)
            assert code == 200
            assert "node_profile_sha256" not in pending_requests[party]["value"]
            code, pending_permits[party] = g.w.request(
                "permit", pending_requests[party], identity=g.w.courier
            )
            assert code == 200 and "node_profile" not in pending_permits[party]["value"]
        execution = pending["authorized"]["intent"]["crypto_execution_id"]
        assert g.w.query(execution)["execution"]["status"] == "Open"
        cohort = []
        for root, _, _ in roots:
            g.w.root = root
            freeze(g)
            view = g.w.query()["root"]
            if root != roots[-1][0]:
                cohort.append(
                    {
                        k: view[k]
                        for k in ("original", "generation", "public_key_package", "node_keys")
                    }
                )
        cohort.sort(key=lambda r: fingerprint("SOLANA_SEEDED_ROOT_V1", r["original"]))
        original_profiles = copy.deepcopy(g.profiles)
        originals, original_heads, historical = {}, {}, {}
        for party in PARTIES:
            anchor = Path(g.profiles[party]["anchor_directory"])
            originals[party] = {f: f.read_bytes() for f in (anchor / "events").glob("*.json")}
            original_heads[party] = (anchor / "initialized.json").read_bytes()
            values = [json.loads(raw)["value"]["change"] for raw in originals[party].values()]
            requests = {
                (
                    r["request"]["value"]["binding"]["authorized"]["intent"]["crypto_execution_id"],
                    r["request"]["value"]["round"],
                ): r["request"]["value"]
                for r in values
                if r["kind"] == "Request"
            }
            historical[party] = []
            for r in values:
                if r["kind"] == "Result":
                    public = r["report"]
                    request = requests[(public["value"]["execution_id"], public["value"]["round"])]
                    historical[party].append(
                        (
                            {
                                "binding": request["binding"],
                                "round": request["round"],
                                "signing_package": request["signing_package"],
                            },
                            public,
                        )
                    )
            g.net.stop(party)
        ciphertexts = {
            f: hashlib.sha256(f.read_bytes()).hexdigest()
            for party in PARTIES
            for f in (g.net.root / party / "storage").glob("*.share.enc")
        }
        assert len(ciphertexts) == 9
        g.w.stop()
        g.net.bin = current_bin
        g.w.start()
        tool = current_bin / "wallet-mpc-profile-migration"
        for party in PARTIES:
            migrate_stopped_party(g, party, cohort, tool)
        for party in PARTIES:
            old_path = g.net.root / party / "identity" / "protected.json"
            rejected(
                baseline_bin / "wallet-mpc-protected-signer",
                dict(g.net.configs[party], MPC_PROTECTED_PROFILE=str(old_path)),
            )
            rejected(
                current_bin / "wallet-mpc-protected-signer",
                dict(g.net.configs[party], MPC_PROTECTED_PROFILE=str(old_path)),
            )
            g.start(party)
            for control, public in historical[party]:
                assert g.call(party, "recover", control, role=role) == (200, public)
            assert (
                dkg_control(
                    g.net, party, "start", dict(dkg_request(), custody_class=custody_class)
                )[0]
                == 409
            )
        # The predecessor lock remains owned while a successor serves requests.
        for party in PARTIES:
            old = Path(g.profiles[party]["profile_migration"]["source_profile"])
            try:
                cli(tool, "inspect", old, new=Path(g.net.configs[party]["MPC_PROTECTED_PROFILE"]))
            except subprocess.CalledProcessError as error:
                assert "already owned" in error.stderr
            else:
                raise AssertionError("successor released original journal flock")
        unlisted, unlisted_claim, unlisted_receipts = roots[-1]
        g.w.root = unlisted
        assert g.w.query().get("node_profiles", {}) == {}
        unlisted_binding = g.binding(unlisted_claim, unlisted_receipts, 9490)
        unlisted_plan = plan(g)

        for party in PARTIES:
            assert (
                g.call(
                    party,
                    "challenge",
                    {"binding": unlisted_binding, "round": 1, "signing_package": None},
                    role=role,
                )[0]
                == 409
            )
            assert call(g.net, party, "approve", approval(g.net, "claim", unlisted_claim))[0] == 409
            if custody_class == "COLD":
                assert refresh_call(g, party, "query", unlisted_plan)[0] == 409
            else:
                assert refresh_start(g, unlisted_plan, party)[0] == 409
        # Every successor boot verifies its original bytes, independently of the
        # already signed successor genesis; restoring only the injected fault is safe.
        party = PARTIES[0]
        g.net.stop(party)
        fault_path, original_bytes = next(iter(originals[party].items()))
        private_file(fault_path, original_bytes + b"fault")
        g.rejected_start(party)
        private_file(fault_path, original_bytes)
        g.start(party)
        g.w.root = roots[0][0]
        assert g.w.query(execution)["execution"]["status"] == "Open"
        assert close(g, pending, [])[0] == 409
        attestations = []
        for party in PARTIES[:2]:
            assert g.call(party, "apply", pending_permits[party], role=role)[0] == 409
            code, attestation = g.call(
                party,
                "cancel",
                {
                    "control": pending_control,
                    "authorization": authority(g, pending_requests[party]),
                },
                role=role,
            )
            assert code == 200
            assert attestation["value"]["request"] == pending_requests[party]
            attestations.append(attestation)
        assert close(g, pending, attestations[:-1])[0] == 409
        assert close(g, pending, attestations)[0] == 200
        assert g.w.query(execution)["execution"]["status"] == "NoSignature"
        finalized = []
        for root_number, (root, current_claim, current_receipts) in enumerate(roots[:2]):
            g.w.root = root
            assert len(g.w.query()["node_profiles"]) == 3
            refresh = plan(g)
            ready = run_rounds(g, refresh)
            activate(g, refresh, ready)
            for party in PARTIES:
                g.net.stop(party)
                g.start(party)
            for n, pair in enumerate(
                ((PARTIES[0], PARTIES[1]), (PARTIES[0], PARTIES[2]), (PARTIES[1], PARTIES[2]))
            ):
                binding = g.binding(
                    current_claim, current_receipts, 9500 + root_number * 100 + n, pair=pair
                )
                if n == 0:
                    control = {"binding": binding, "round": 1, "signing_package": None}
                    code, current_request = g.call(PARTIES[0], "challenge", control, role=role)
                    assert code == 200 and g.w.query()["root"]["phase"] == "Active"
                    for fp in (None, "ab" * 32):
                        old_schema = copy.deepcopy(current_request["value"])
                        if fp is None:
                            old_schema.pop("node_profile_sha256")
                        else:
                            old_schema["node_profile_sha256"] = fp
                        forged = sign(g.w.node[PARTIES[0]], "WITNESS_PERMIT_REQUEST_V1", old_schema)
                        assert g.w.request("permit", forged, identity=g.w.courier)[0] == 409
                    assert (
                        g.w.query(binding["authorized"]["intent"]["crypto_execution_id"])[
                            "execution"
                        ]
                        is None
                    )
                finalized.append(g.broadcast(binding, g.sign(binding))[0])
        assert len(finalized) == 6
        for party in PARTIES:
            assert all(f.read_bytes() == raw for f, raw in originals[party].items())
            anchor = Path(original_profiles[party]["anchor_directory"])
            assert len(list((anchor / "events").glob("*.json"))) == len(originals[party]) + 1
            terminal = json.loads(sorted((anchor / "events").glob("*.json"))[-1].read_bytes())
            assert (
                terminal["value"]["change"]["admission"]["original_head_json"].encode()
                == original_heads[party]
            )
        assert all(
            hashlib.sha256(f.read_bytes()).hexdigest() == digest
            for f, digest in ciphertexts.items()
        )
        private_file(
            root_path / "solana-profile-migrated-runtime-public-evidence.json",
            canonical(
                {
                    "scope": "original4a migration: three nodes, two Roots, refreshed signing",
                    "baseline_source_sha": metadata["source_sha"],
                    "class": custody_class,
                    "migrated_roots": 2,
                    "excluded_original_roots": 1,
                    "migrated_original_nodes": 3,
                    "original_dkg_ciphertexts_unchanged": 9,
                    "all_original_raw_events_and_signed_pre_heads_preserved": True,
                    "original_public_results_recovered_unchanged": sum(
                        map(len, historical.values())
                    ),
                    "old_unknown_r2_preserved_until_actual_grantee_no_release": True,
                    "old_none_requests_used_unchanged_in_terminal_no_release": 2,
                    "cohort_profile_pins_installed": 6,
                    "new_dkg_routes_rejected": True,
                    "noncohort_original_root_public_history_preserved_private_routes_closed": True,
                    "predecessor_flock_held_and_source_corruption_fences_restart": True,
                    "ordinary_three_node_refresh_and_restart_for_each_root": True,
                    "active_root_old_schema_and_wrong_profile_requests_denied": 4,
                    "all_three_pairs_for_both_roots_finalized": len(finalized),
                    "transaction_ids": finalized,
                }
            ),
        )
