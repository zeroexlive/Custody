"""Pinned upstream C-SDK invoke_signed fixture for isolated-validator acceptance."""

import json
import os
import subprocess
from pathlib import Path

from environment import private_file
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.pubkey import Pubkey


def compile_fixture(directory):
    directory.mkdir(parents=True, exist_ok=True)
    tools = Path(os.environ["PHASE6GC_SOLANA_PLATFORM_TOOLS"])
    sdk = Path(os.environ["PHASE6FB_SOLANA_BIN"]) / "sdk/sbf/c"
    source = Path(__file__).with_name("cpi_deposit_fixture.c")
    object_path = directory / "cpi_deposit_fixture.o"
    program_path = directory / "cpi_deposit_fixture.so"
    subprocess.run(
        [
            str(tools / "llvm/bin/clang"),
            "-target",
            "sbf",
            "-Werror",
            "-O2",
            "-fno-builtin",
            "-std=c17",
            "-fPIC",
            "-isystem",
            str(sdk / "inc"),
            "-c",
            str(source),
            "-o",
            str(object_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            str(tools / "llvm/bin/ld.lld"),
            "-z",
            "notext",
            "-shared",
            "--Bdynamic",
            str(sdk / "sbf.ld"),
            "--entry",
            "entrypoint",
            "-L",
            str(tools / "llvm/lib"),
            "-lc",
            str(object_path),
            "-o",
            str(program_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return program_path


def deploy_fixture(validator, directory):
    """Only the disposable validator's external faucet signs deployment."""
    if not validator.url.startswith("http://127.0.0.1:"):
        raise ValueError("CPI acceptance fixture requires an isolated validator")
    program_path = compile_fixture(directory)
    program = Keypair()
    authority_file = directory / "external-deploy-authority.json"
    program_file = directory / "external-program-keypair.json"
    private_file(authority_file, json.dumps(list(bytes(validator.faucet))).encode())
    private_file(program_file, json.dumps(list(bytes(program))).encode())
    result = subprocess.run(
        [
            str(validator.bin / "solana"),
            "--url",
            validator.url,
            "--keypair",
            str(authority_file),
            "--commitment",
            "finalized",
            "--output",
            "json",
            "program",
            "deploy",
            str(program_path),
            "--program-id",
            str(program_file),
            "--use-rpc",
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode:
        raise RuntimeError(
            "isolated CPI fixture deployment failed: "
            + result.stdout[-1000:]
            + result.stderr[-1000:]
        )
    pda, bump = Pubkey.find_program_address([b"phase6gc-pda-deposit"], program.pubkey())
    return program.pubkey(), pda, bump


def pda_transfer(validator, fixture, destination, units):
    program, source, bump = fixture
    instruction = Instruction(
        program,
        int(units).to_bytes(8, "little") + bytes([bump]),
        [
            AccountMeta(source, False, True),
            AccountMeta(Pubkey.from_string(destination), False, True),
            AccountMeta(Pubkey.default(), False, False),
        ],
    )
    return validator.send([instruction])
