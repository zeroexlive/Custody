"""Fetch only the pinned upstream Solana SBF tools for an acceptance fixture."""

import argparse
import hashlib
import json
import tarfile
import urllib.request
from pathlib import Path

VERSION = "v1.43"
ASSET_ID = 208624772
SHA256 = "7a497174a0484bf8eee2d0a5a03a48f91ea0b5d1ba2d4055f37ef975a64ca8f6"
SIZE = 393244174
URL = f"https://github.com/anza-xyz/platform-tools/releases/download/{VERSION}/platform-tools-linux-x86_64.tar.bz2"


def fetch(cache, destination):
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / f"platform-tools-{VERSION}.tar.bz2"
    if not archive.exists():
        partial = archive.with_suffix(".partial")
        with urllib.request.urlopen(URL, timeout=60) as response, partial.open("wb") as target:
            while chunk := response.read(1024 * 1024):
                target.write(chunk)
                if target.tell() > SIZE:
                    raise ValueError("pinned platform-tools archive size exceeded")
        partial.rename(archive)
    if archive.stat().st_size != SIZE or hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise ValueError("pinned platform-tools archive integrity mismatch")
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:bz2") as bundle:
        bundle.extractall(destination, filter="data")
    if not (destination / "llvm/bin/clang").is_file():
        raise ValueError("upstream SBF compiler missing")
    (destination / "pinned-source.json").write_text(
        json.dumps(
            {
                "release": VERSION,
                "asset_id": ASSET_ID,
                "sha256": SHA256,
                "bytes": SIZE,
                "scope": "isolated-validator CPI acceptance fixture, no custody crypto",
            },
            sort_keys=True,
        )
        + "\n"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    fetch(args.cache, args.output)


if __name__ == "__main__":
    main()
