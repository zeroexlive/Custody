"""Standard Solana seeded-account wire primitives for Phase 6G-C.

These helpers do not issue custody accounts or authorize signing. A native
seeded address is controlled through SystemProgram TransferWithSeed by the
original FROST base key, not by a derived Ed25519 private key. Classic SPL
accounts have the same base authority and distinct standard seeded addresses.
Durable ownership/index allocation, network pins, signer approval, RPC account
validation and fee/rent policy must precede use by an execution workflow.
"""

import base64
import struct

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import (
    CreateAccountWithSeedParams,
    TransferWithSeedParams,
    create_account_with_seed,
    transfer_with_seed,
)

from .solana_wire import SYSTEM_PROGRAM, decode_message, uint
from .spl import ASSOCIATED_TOKEN_PROGRAM, derive_ata
from .token_metadata import CLASSIC_TOKEN_PROGRAM

# Match PostgreSQL's signed bigint allocation space. Never hash/truncate a
# customer or mint into this index, recycle it, or accept an external seed.
MAX_SEED_INDEX = (1 << 63) - 1
TOKEN_ACCOUNT_BYTES = 165


def account_seed(index, *, token=False):
    if type(index) is not int or not 0 <= index <= MAX_SEED_INDEX or type(token) is not bool:
        raise ValueError("canonical allocated Solana seed index required")
    return f"c1{'t' if token else 'n'}{index:029x}"


def _key(value):
    key = Pubkey.from_string(value)
    if str(key) != value:
        raise ValueError("canonical Solana public key required")
    return key


def _base(value):
    key = _key(value)
    if str(key) == SYSTEM_PROGRAM or not key.is_on_curve():
        raise ValueError("an original on-curve FROST base key is required")
    return key


def account_address(base, index, *, token=False):
    """Derive the standard base+seed+program address, not a signing public key."""
    seed = account_seed(index, token=token)
    owner = CLASSIC_TOKEN_PROGRAM if token else SYSTEM_PROGRAM
    return str(Pubkey.create_with_seed(_base(base), seed, _key(owner)))


def _message(base, blockhash, instructions):
    raw = bytes(Message.new_with_blockhash(instructions, _base(base), Hash.from_string(blockhash)))
    # All messages use exactly one FROST authority, which also pays the fee.
    # decode_message independently checks canonical legacy encoding and flags.
    decode_message(base64.b64encode(raw).decode())
    return raw


def native_transfer_instructions(base, index, destination, units):
    payer = _base(base)
    source = _key(account_address(base, index))
    target = _key(destination)
    if source == target:
        raise ValueError("seeded source and destination must differ")
    return [
        transfer_with_seed(
            TransferWithSeedParams(
                from_pubkey=source,
                from_base=payer,
                from_seed=account_seed(index),
                from_owner=_key(SYSTEM_PROGRAM),
                to_pubkey=target,
                lamports=uint(units, positive=True),
            )
        )
    ]


def build_native_transfer(base, index, destination, units, blockhash):
    return _message(base, blockhash, native_transfer_instructions(base, index, destination, units))


def token_creation_instructions(base, index, mint, rent_lamports):
    """Atomically allocate a rent-funded classic token account and initialize it.

    The index must already be uniquely reserved for this exact mint/owner.
    SPL authority is the FROST base, not the seeded System-account address.
    Rent is explicit; this builder does not attest a current RPC rent quote.
    """
    payer = _base(base)
    account = _key(account_address(base, index, token=True))
    token = _key(CLASSIC_TOKEN_PROGRAM)
    mint_key = _key(mint)
    return [
        create_account_with_seed(
            CreateAccountWithSeedParams(
                from_pubkey=payer,
                to_pubkey=account,
                base=payer,
                seed=account_seed(index, token=True),
                lamports=uint(rent_lamports, positive=True),
                space=TOKEN_ACCOUNT_BYTES,
                owner=token,
            )
        ),
        Instruction(
            token,
            b"\x12" + bytes(payer),  # Classic SPL InitializeAccount3.
            [AccountMeta(account, False, True), AccountMeta(mint_key, False, False)],
        ),
    ]


def build_token_creation(base, index, mint, rent_lamports, blockhash):
    return _message(base, blockhash, token_creation_instructions(base, index, mint, rent_lamports))


def token_transfer_instructions(
    base, index, mint, destination_owner, units, decimals, *, create_ata=False
):
    if type(decimals) is not int or not 0 <= decimals <= 18 or type(create_ata) is not bool:
        raise ValueError("reviewed classic SPL precision and ATA decision required")
    payer = _base(base)
    source = _key(account_address(base, index, token=True))
    mint_key = _key(mint)
    recipient = _key(destination_owner)
    destination = _key(derive_ata(destination_owner, mint))
    if source == destination:
        raise ValueError("seeded token source and destination must differ")
    token = _key(CLASSIC_TOKEN_PROGRAM)
    result = []
    if create_ata:
        result.append(
            Instruction(
                _key(ASSOCIATED_TOKEN_PROGRAM),
                b"\x01",  # Idempotent ATA creation, funded by the base authority.
                [
                    AccountMeta(payer, True, True),
                    AccountMeta(destination, False, True),
                    AccountMeta(recipient, False, False),
                    AccountMeta(mint_key, False, False),
                    AccountMeta(_key(SYSTEM_PROGRAM), False, False),
                    AccountMeta(token, False, False),
                ],
            )
        )
    result.append(
        Instruction(
            token,
            b"\x0c" + struct.pack("<Q", uint(units, positive=True)) + bytes([decimals]),
            [
                AccountMeta(source, False, True),
                AccountMeta(mint_key, False, False),
                AccountMeta(destination, False, True),
                AccountMeta(payer, True, False),
            ],
        )
    )
    return result


def build_token_transfer(
    base, index, mint, destination_owner, units, decimals, blockhash, *, create_ata=False
):
    return _message(
        base,
        blockhash,
        token_transfer_instructions(
            base, index, mint, destination_owner, units, decimals, create_ata=create_ata
        ),
    )


def _validate_exact_message(encoded, expected):
    """Compare a persisted canonical message to freshly rebuilt bound parameters."""
    raw, message, decoded = decode_message(encoded)
    if raw != expected:
        raise ValueError("seeded Solana message differs from original bound instructions")
    return raw, message, decoded


def validate_native_transfer(encoded, base, index, destination, units, blockhash):
    return _validate_exact_message(
        encoded, build_native_transfer(base, index, destination, units, blockhash)
    )


def validate_token_creation(encoded, base, index, mint, rent_lamports, blockhash):
    return _validate_exact_message(
        encoded, build_token_creation(base, index, mint, rent_lamports, blockhash)
    )


def validate_token_transfer(
    encoded, base, index, mint, destination_owner, units, decimals, blockhash, *, create_ata=False
):
    return _validate_exact_message(
        encoded,
        build_token_transfer(
            base, index, mint, destination_owner, units, decimals, blockhash, create_ata=create_ata
        ),
    )
