"""Identify the fixed rules2 writer used for genuine repaired-store upgrades."""

import argparse
import json
import os
import subprocess
from pathlib import Path

from profile_migration_baseline import BINARIES, binary_sha256

SOURCE_SHA = "7ff1e56340a000e9eeefb02ee6f199340062ee85"
SOURCE_TREE = "998033f8a49a8eaf9b9fdfe23cf790537740cd95"


def baseline_directory():
    value = os.environ.get("PHASE6GC_CURRENT_CLAIM_COMPAT_BIN")
    assert value, "fixed genuine rules2 writer binaries are required"
    directory = Path(value).resolve()
    identity = json.loads((directory.parent / "build-identity.json").read_text())
    assert identity["source_sha"] == SOURCE_SHA
    assert identity["source_tree"] == SOURCE_TREE
    assert identity["binaries"] == {name: binary_sha256(directory / name) for name in BINARIES}
    return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--bin", type=Path, required=True)
    args = parser.parse_args()
    actual = subprocess.check_output(
        ["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True
    ).strip()
    assert actual == SOURCE_SHA
    tree = subprocess.check_output(
        ["git", "-C", str(args.source), "rev-parse", "HEAD^{tree}"], text=True
    ).strip()
    assert tree == SOURCE_TREE
    subprocess.run(["git", "-C", str(args.source), "diff", "HEAD", "--exit-code"], check=True)
    assert not subprocess.check_output(
        ["git", "-C", str(args.source), "ls-files", "--others", "--exclude-standard"], text=True
    ).strip(), "untracked baseline source cannot be included in an exact-source build"
    identity = dict(
        source_sha=actual,
        source_tree=tree,
        binaries={name: binary_sha256(args.bin / name) for name in BINARIES},
    )
    with (args.bin.parent / "build-identity.json").open("x") as handle:
        json.dump(identity, handle, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    main()
