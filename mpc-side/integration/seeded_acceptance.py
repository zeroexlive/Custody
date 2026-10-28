"""Genuine seeded SOL/SPL primitive acceptance, before issuance/ledger integration.

This uses the existing root-signing contract. Client-side typed wire verification
is not signer-side seeded authorization; no customer account is issued here.
"""

import base64
import json
import os
import struct
import subprocess

import test_signing as frost
from custody import solana_seeded as seeded
from custody.spl import derive_ata
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM
from environment import ROLES, Processes
from solana_local.validator import Validator
from solders.instruction import AccountMeta, Instruction
from solders.message import Message
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import Transaction
from test_dkg import PARTIES, dkg_request, execute


def run_seeded_spendability(root):
    affinity = os.sched_getaffinity(0) if hasattr(os, "sched_getaffinity") else None
    root.mkdir(mode=0o700)
    net = Processes(root / "services")
    validator = None
    if affinity:
        os.sched_setaffinity(0, sorted(affinity)[:4])
    report = {
        "scope": "primitive genuine spendability only; no issuance/ledger/authorization acceptance",
        "transactions": [],
    }
    try:
        for role in ROLES[:4]:
            net.start(role)
        context = dkg_request()
        code, dkg = execute(net, context)
        assert code == 200 and dkg["status"] == "COMPLETED"
        base = str(Pubkey.from_bytes(bytes.fromhex(dkg["group_public_key"])))
        validator = Validator(root / "validator")
        report["network"] = validator.policy
        report["base"] = base
        report["dkg_identity"] = {
            k: dkg[k]
            for k in (
                "keyset_id",
                "execution_id",
                "group_public_key",
                "result_fingerprint",
                "participants",
            )
        }
        validator.fund(base, 1_000_000_000)
        source = seeded.account_address(base, 7)
        validator.fund(source, 5_000_000)
        destination = str(validator.faucet.pubkey())

        def balance(address):
            return validator.rpc("getBalance", [address, {"commitment": "finalized"}])["value"]

        def signed(raw, params, omitted):
            params.update(base=base, index=7, message_hex=raw.hex())
            result = subprocess.check_output(
                [str(net.bin / "examples" / "seeded_message_check")],
                input=json.dumps(params).encode(),
            )
            assert result.strip() == b"verified"
            selected = [p for p in PARTIES if p != omitted]
            net.stop(omitted)
            try:
                payload = frost.sign_request(dkg, raw)
                code, state = frost.run_sign(net, payload)
                assert code == 200
                frost.assert_signature(payload, state, dkg, selected)
                transaction = Transaction.populate(
                    Message.from_bytes(raw),
                    [Signature.from_bytes(bytes.fromhex(state["signature"]["signature_hex"]))],
                )
                transaction.verify()
                sig = validator.rpc(
                    "sendTransaction",
                    [base64.b64encode(bytes(transaction)).decode(), {"encoding": "base64"}],
                )
                status, tx = validator.wait(sig)
                assert status["err"] is None and tx["meta"]["err"] is None
                received = Transaction.from_bytes(base64.b64decode(tx["transaction"][0]))
                received.verify()
                assert bytes(received) == bytes(transaction)
                assert (
                    str(Signature.from_bytes(bytes.fromhex(state["signature"]["signature_hex"])))
                    == sig
                )
                keys = [str(k) for k in Message.from_bytes(raw).account_keys]
                assert (
                    len(tx["meta"]["preBalances"]) == len(keys) == len(tx["meta"]["postBalances"])
                )
                tx["_deltas"] = {
                    k: post - pre
                    for k, pre, post in zip(
                        keys, tx["meta"]["preBalances"], tx["meta"]["postBalances"]
                    )
                }
                assert 0 < tx["meta"]["fee"] <= 20000
                report["transactions"].append(
                    {
                        "kind": params["kind"],
                        "signature": sig,
                        "selected_signers": selected,
                        "message_sha256": payload["message_fingerprint"],
                        "fee": tx["meta"]["fee"],
                        "finalized": True,
                        "message_hex": raw.hex(),
                        "signature_hex": state["signature"]["signature_hex"],
                        "logical_session_id": state["session_id"],
                        "crypto_execution_id": state["crypto_execution_id"],
                        "lamport_deltas": tx["_deltas"],
                    }
                )
                return tx
            finally:
                net.start(omitted)

        for omitted in reversed(PARTIES):
            before = balance(source)
            payer = balance(base)
            block = validator.blockhash()
            raw = seeded.build_native_transfer(base, 7, destination, 12345, block)
            tx = signed(
                raw,
                dict(kind="native", destination=destination, amount=12345, blockhash=block),
                omitted,
            )
            assert balance(source) == before - 12345
            assert balance(base) == payer - tx["meta"]["fee"]
            assert tx["_deltas"][source] == -12345 and tx["_deltas"][destination] == 12345
            assert tx["_deltas"][base] == -tx["meta"]["fee"]
            assert all(
                delta == 0
                for k, delta in tx["_deltas"].items()
                if k not in {base, source, destination}
            )
            print(
                "SOL_SEEDED_FROST_PAIR passed",
                ",".join(report["transactions"][-1]["selected_signers"]),
                flush=True,
            )
        validator.create_mint()
        mint = str(validator.mint.pubkey())
        rent = validator.rpc("getMinimumBalanceForRentExemption", [165])
        block = validator.blockhash()
        token_account = seeded.account_address(base, 7, token=True)
        raw = seeded.build_token_creation(base, 7, mint, rent, block)
        tx = signed(
            raw, dict(kind="create_token", mint=mint, amount=rent, blockhash=block), "signer-c"
        )
        info = validator.rpc(
            "getAccountInfo", [token_account, {"encoding": "jsonParsed", "commitment": "finalized"}]
        )["value"]
        assert (
            info["owner"] == CLASSIC_TOKEN_PROGRAM
            and info["data"]["parsed"]["info"]["owner"] == base
        )
        assert info["data"]["parsed"]["info"]["mint"] == mint and info["lamports"] == rent
        raw_info = validator.rpc(
            "getAccountInfo", [token_account, {"encoding": "base64", "commitment": "finalized"}]
        )["value"]
        data = base64.b64decode(raw_info["data"][0])
        assert len(data) == 165 and data[108] == 1
        assert data[:32] == bytes(Pubkey.from_string(mint)) and data[32:64] == bytes(
            Pubkey.from_string(base)
        )
        assert (
            int.from_bytes(data[64:72], "little") == 0
            and data[72:76] == bytes(4)
            and data[129:133] == bytes(4)
        )
        assert 0 < rent <= 3000000
        assert (
            tx["_deltas"][base] == -rent - tx["meta"]["fee"]
            and tx["_deltas"][token_account] == rent
        )
        assert all(
            delta == 0 for k, delta in tx["_deltas"].items() if k not in {base, token_account}
        )
        program = Pubkey.from_string(CLASSIC_TOKEN_PROGRAM)
        mint_to = Instruction(
            program,
            b"\x07" + struct.pack("<Q", 1000000),
            [
                AccountMeta(validator.mint.pubkey(), False, True),
                AccountMeta(Pubkey.from_string(token_account), False, True),
                AccountMeta(validator.faucet.pubkey(), True, False),
            ],
        )
        validator.send([mint_to])

        def token_units():
            return int(
                validator.rpc(
                    "getTokenAccountBalance", [token_account, {"commitment": "finalized"}]
                )["value"]["amount"]
            )

        for number, omitted in enumerate(reversed(PARTIES)):
            before = token_units()
            block = validator.blockhash()
            create = number in (0, 2)  # Last pair repeats idempotent ATA creation.
            target = derive_ata(destination, mint)
            prior = validator.rpc(
                "getAccountInfo", [target, {"encoding": "jsonParsed", "commitment": "finalized"}]
            )["value"]
            recipient_before = (
                int(prior["data"]["parsed"]["info"]["tokenAmount"]["amount"]) if prior else 0
            )
            assert prior is not None or create
            raw = seeded.build_token_transfer(
                base, 7, mint, destination, 42, 6, block, create_ata=create
            )
            tx = signed(
                raw,
                dict(
                    kind="token",
                    mint=mint,
                    destination=destination,
                    amount=42,
                    decimals=6,
                    create_ata=create,
                    blockhash=block,
                ),
                omitted,
            )
            assert token_units() == before - 42
            recipient = validator.rpc(
                "getAccountInfo", [target, {"encoding": "jsonParsed", "commitment": "finalized"}]
            )["value"]
            assert recipient["owner"] == CLASSIC_TOKEN_PROGRAM
            assert (
                recipient["data"]["parsed"]["info"]["owner"] == destination
                and recipient["data"]["parsed"]["info"]["mint"] == mint
            )
            assert (
                int(recipient["data"]["parsed"]["info"]["tokenAmount"]["amount"])
                == recipient_before + 42
            )
            added_rent = rent if prior is None else 0
            assert tx["_deltas"][base] == -tx["meta"]["fee"] - added_rent
            assert tx["_deltas"][token_account] == 0 and tx["_deltas"][target] == added_rent
            assert all(delta == 0 for k, delta in tx["_deltas"].items() if k not in {base, target})
            print(
                "SPL_SEEDED_FROST_PAIR passed",
                ",".join(report["transactions"][-1]["selected_signers"]),
                flush=True,
            )
        report["status"] = "passed"
        (root / "solana-seeded-primitive-evidence.json").write_text(
            json.dumps(report, sort_keys=True, indent=2) + "\n"
        )
        print(
            "SEEDED_PRIMITIVE_LIVE_ACCEPTANCE passed; "
            "financial/issuance integration remains unfinished",
            flush=True,
        )
    finally:
        try:
            if validator is not None:
                validator.close()
        finally:
            try:
                net.close()
            finally:
                if affinity:
                    os.sched_setaffinity(0, affinity)
