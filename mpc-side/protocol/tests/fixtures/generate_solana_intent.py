"""Rebuild public wire/hash fixtures with Solders; no private keys, RPC or grants."""

import argparse
import copy
import hashlib
import json
import os
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[4])
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    sys.path.insert(0, str(args.repository / "backend-side"))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mpc_exchange.settings")
    import django

    django.setup()
    from custody import solana_seeded as wire
    from solders.pubkey import Pubkey

    original = args.fixture.read_text()
    fixture = json.loads(original)
    for case in fixture["cases"]:
        intent = copy.deepcopy(case["intent"])
        claim = intent["claim"]
        claim["root"] = fixture["root"]
        base = str(Pubkey.from_bytes(bytes.fromhex(claim["root"]["group_public_key"])))
        index, action, block = claim["index"], intent["action"], intent["recent_blockhash"]
        kind = action["kind"]
        intent["financial_source"] = wire.account_address(
            base, index, token=kind != "NativeTransfer"
        )
        if kind == "NativeTransfer":
            raw = wire.build_native_transfer(
                base, index, action["destination"], action["amount"], block
            )
        elif kind == "CreateClassicToken":
            raw = wire.build_token_creation(
                base, index, claim["asset"]["mint"], action["rent_lamports"], block
            )
        elif kind == "ClassicTransfer":
            raw = wire.build_token_transfer(
                base,
                index,
                claim["asset"]["mint"],
                action["destination_owner"],
                action["amount"],
                claim["asset"]["decimals"],
                block,
                create_ata=action["create_ata"],
            )
        else:
            raise ValueError("unsupported public fixture action")
        intent["message_fingerprint"] = hashlib.sha256(raw).hexdigest()
        intent["generation"]["public_key_package_sha256"] = hashlib.sha256(
            bytes(claim["root"]["public_key_package"])
        ).hexdigest()
        message = (
            b"Wallet-MPC/CUSTODY_SOLANA_SEEDED_INTENT_V1\0"
            + json.dumps(
                {"intent": intent, "payload_hex": raw.hex()},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        )
        case["message_hex"] = raw.hex()
        case["custody_message_sha256"] = hashlib.sha256(message).hexdigest()
        del intent["claim"]["root"]
        case["intent"] = intent
    rendered = json.dumps(fixture, indent=2) + "\n"
    if args.check:
        assert rendered == original, "public SDK/canonical fixtures differ"
        print(f"Verified {len(fixture['cases'])} public SDK/canonical fixtures")
    else:
        args.fixture.write_text(rendered)


if __name__ == "__main__":
    main()
