"""Bind compatibility fixtures to genuine fixed old-profile writer binaries."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

SOURCE_SHA = "4a4e6ffca0d7107d53e742144f52838a3473f32e"
BINARIES = (
    "wallet-mpc-protected-signer",
    "wallet-mpc-witness",
    "wallet-mpc-coordinator",
    "examples/frost_signing_package",
)


def binary_sha256(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--bin", type=Path, required=True)
    args = parser.parse_args()
    actual = subprocess.check_output(
        ["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True
    ).strip()
    assert actual == SOURCE_SHA, "fixed original-profile baseline required"
    subprocess.run(["git", "-C", str(args.source), "diff", "--exit-code"], check=True)
    report = {
        "source_sha": actual,
        "binaries": {name: binary_sha256(args.bin / name) for name in BINARIES},
    }
    destination = args.bin.parent / "build-identity.json"
    with destination.open("x") as handle:
        json.dump(report, handle, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    main()
