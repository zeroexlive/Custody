"""Ordinary external transfer/ALT fixtures; never custody MPC key material."""

import base64
import json
import subprocess
import time

from environment import private_file
from solders.address_lookup_table_account import AddressLookupTable, AddressLookupTableAccount
from solders.hash import Hash
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction, VersionedTransaction


def _cli(validator, directory, arguments):
    if not validator.url.startswith("http://127.0.0.1:"):
        raise ValueError("external acceptance fixture requires isolated RPC")
    payer = directory / "external-alt-authority.json"
    private_file(payer, json.dumps(list(bytes(validator.faucet))).encode())
    result = subprocess.run(
        [
            str(validator.bin / "solana"),
            "--url",
            validator.url,
            "--keypair",
            str(payer),
            "--commitment",
            "confirmed",
            "--output",
            "json",
            *arguments,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode:
        raise RuntimeError(
            "isolated ALT fixture failed: " + result.stdout[-1000:] + result.stderr[-1000:]
        )
    return json.loads(result.stdout)


def external_transfer(validator, sender, destination, units, *, versioned=False, directory=None):
    instruction = transfer(
        TransferParams(
            from_pubkey=sender.pubkey(), to_pubkey=Pubkey.from_string(destination), lamports=units
        )
    )
    blockhash = Hash.from_string(validator.blockhash())
    if versioned:
        created = _cli(validator, directory, ["address-lookup-table", "create"])
        validator.wait(created["signature"])
        address = created["lookupTableAddress"]
        extended = _cli(
            validator,
            directory,
            [
                "address-lookup-table",
                "extend",
                address,
                "--addresses",
                destination,
            ],
        )
        validator.wait(extended["signature"])
        account = validator.rpc(
            "getAccountInfo",
            [
                address,
                {
                    "encoding": "base64",
                    "commitment": "finalized",
                },
            ],
        )["value"]
        state = AddressLookupTable.deserialize(base64.b64decode(account["data"][0]))
        deadline = time.monotonic() + 30
        while (
            validator.rpc("getSlot", [{"commitment": "finalized"}]) <= state.meta.last_extended_slot
        ):
            if time.monotonic() >= deadline:
                raise RuntimeError("actual finalized ALT extension has not warmed up")
            time.sleep(0.2)
        table = AddressLookupTableAccount(Pubkey.from_string(address), state.addresses)
        message = MessageV0.try_compile(
            sender.pubkey(), [instruction], [table], Hash.from_string(validator.blockhash())
        )
        assert message.address_table_lookups
        tx = VersionedTransaction(message, [sender])
    else:
        tx = Transaction.new_signed_with_payer([instruction], sender.pubkey(), [sender], blockhash)
    signature = validator.rpc(
        "sendTransaction",
        [
            base64.b64encode(bytes(tx)).decode(),
            {"encoding": "base64"},
        ],
    )
    validator.wait(signature)
    return signature
