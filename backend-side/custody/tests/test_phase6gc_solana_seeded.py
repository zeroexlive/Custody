"""Independent SDK/wire checks, not account issuance or genuine chain acceptance."""

import base64
import hashlib

import pytest
from solders.hash import Hash
from solders.instruction import Instruction
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import decode_create_account_with_seed, decode_transfer_with_seed
from spl.token import instructions as token_sdk

from custody.solana_seeded import (
    MAX_SEED_INDEX,
    account_address,
    account_seed,
    build_native_transfer,
    build_token_creation,
    build_token_transfer,
    native_transfer_instructions,
    token_creation_instructions,
    token_transfer_instructions,
    validate_native_transfer,
    validate_token_creation,
    validate_token_transfer,
)
from custody.solana_wire import SYSTEM_PROGRAM, decode_message
from custody.spl import derive_ata
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM

# Public RFC 8032 verification key only. No private key or local signing fixture.
BASE = str(
    Pubkey.from_bytes(
        bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    )
)
MINT = str(Pubkey.from_bytes(bytes([7]) * 32))
DEST = str(Pubkey.from_bytes(bytes([8]) * 32))
BLOCK = str(Hash.from_bytes(bytes([9]) * 32))


def encoded(raw):
    return base64.b64encode(raw).decode()


@pytest.mark.parametrize("index", [0, 1, 2**31, MAX_SEED_INDEX])
@pytest.mark.parametrize("token", [False, True])
def test_seeded_address_matches_standard_hash_and_has_no_derived_private_key(index, token):
    seed = account_seed(index, token=token)
    owner = Pubkey.from_string(CLASSIC_TOKEN_PROGRAM if token else SYSTEM_PROGRAM)
    digest = hashlib.sha256(bytes(Pubkey.from_string(BASE)) + seed.encode() + bytes(owner)).digest()
    assert len(seed.encode()) == 32 and seed.isascii()
    assert account_address(BASE, index, token=token) == str(Pubkey.from_bytes(digest))
    assert account_address(BASE, index, token=token) != BASE


def test_unique_indices_and_account_kinds_do_not_alias():
    addresses = {
        account_address(BASE, index, token=token)
        for index in range(1000)
        for token in [False, True]
    }
    assert len(addresses) == 2000  # Public address derivation only, not issued accounts.


@pytest.mark.parametrize("index", [-1, MAX_SEED_INDEX + 1, True, 1.5, "1", None])
def test_noncanonical_or_unallocated_index_shape_rejected(index):
    with pytest.raises(ValueError, match="index"):
        account_address(BASE, index)


@pytest.mark.parametrize("token", [1, None, "true"])
def test_account_kind_requires_boolean(token):
    with pytest.raises(ValueError):
        account_address(BASE, 0, token=token)


def test_base_must_be_an_on_curve_signing_authority():
    off_curve, _ = Pubkey.find_program_address([b"test-public-address"], Pubkey.from_string(MINT))
    for base in [SYSTEM_PROGRAM, str(off_curve)]:
        with pytest.raises(ValueError, match="FROST base"):
            account_address(base, 0)


def test_native_instruction_is_standard_transfer_with_seed():
    (instruction,) = native_transfer_instructions(BASE, 42, DEST, 1_000_000)
    fields = decode_transfer_with_seed(instruction)
    assert str(instruction.program_id) == SYSTEM_PROGRAM
    assert fields == {
        "from_pubkey": Pubkey.from_string(account_address(BASE, 42)),
        "from_base": Pubkey.from_string(BASE),
        "from_seed": account_seed(42),
        "from_owner": Pubkey.from_string(SYSTEM_PROGRAM),
        "to_pubkey": Pubkey.from_string(DEST),
        "lamports": 1_000_000,
    }
    raw = build_native_transfer(BASE, 42, DEST, 1_000_000, BLOCK)
    message = Message.from_bytes(raw)
    assert message.header.num_required_signatures == 1
    assert str(message.account_keys[0]) == BASE
    _, _, decoded = validate_native_transfer(encoded(raw), BASE, 42, DEST, 1_000_000, BLOCK)
    assert decoded[0]["accounts"][0]["signer"] is False


def test_seeded_native_source_can_sweep_to_base_fee_payer():
    raw = build_native_transfer(BASE, 0, BASE, 100, BLOCK)
    assert validate_native_transfer(encoded(raw), BASE, 0, BASE, 100, BLOCK)[0] == raw
    with pytest.raises(ValueError, match="differ"):
        build_native_transfer(BASE, 0, account_address(BASE, 0), 100, BLOCK)


def test_token_creation_is_atomic_standard_allocation_and_initialize_account3():
    allocation, initialization = token_creation_instructions(BASE, 17, MINT, 2_039_280)
    fields = decode_create_account_with_seed(allocation)
    assert fields["to_pubkey"] == Pubkey.from_string(account_address(BASE, 17, token=True))
    assert fields["seed"] == account_seed(17, token=True)
    assert fields["from_pubkey"] == fields["base"] == Pubkey.from_string(BASE)
    assert fields["space"] == 165 and fields["lamports"] == 2_039_280
    assert str(fields["owner"]) == CLASSIC_TOKEN_PROGRAM
    independent = token_sdk.initialize_account3(
        token_sdk.models.InitializeAccount3Params(
            program_id=Pubkey.from_string(CLASSIC_TOKEN_PROGRAM),
            account=fields["to_pubkey"],
            mint=Pubkey.from_string(MINT),
            owner=Pubkey.from_string(BASE),
        )
    )
    assert initialization == independent
    raw = build_token_creation(BASE, 17, MINT, 2_039_280, BLOCK)
    message = Message.from_bytes(raw)
    assert len(message.instructions) == 2 and message.header.num_required_signatures == 1
    assert validate_token_creation(encoded(raw), BASE, 17, MINT, 2_039_280, BLOCK)[0] == raw


@pytest.mark.parametrize("destination", [DEST, BASE])
@pytest.mark.parametrize("create", [False, True])
def test_token_transfer_uses_seeded_source_and_original_base_authority(destination, create):
    instructions = token_transfer_instructions(
        BASE, 19, MINT, destination, 123456, 6, create_ata=create
    )
    fields = token_sdk.decode_transfer_checked(instructions[-1])
    assert fields.source == Pubkey.from_string(account_address(BASE, 19, token=True))
    assert fields.source != Pubkey.from_string(derive_ata(BASE, MINT))
    assert fields.dest == Pubkey.from_string(derive_ata(destination, MINT))
    assert (
        fields.owner == Pubkey.from_string(BASE)
        and fields.amount == 123456
        and fields.decimals == 6
    )
    assert len(instructions) == (2 if create else 1)
    raw = build_token_transfer(BASE, 19, MINT, destination, 123456, 6, BLOCK, create_ata=create)
    assert (
        validate_token_transfer(
            encoded(raw), BASE, 19, MINT, destination, 123456, 6, BLOCK, create_ata=create
        )[0]
        == raw
    )


@pytest.mark.parametrize("units", [0, -1, 2**64, True, "01"])
def test_native_amount_rejects_noncanonical_or_unsafe_values(units):
    with pytest.raises(ValueError):
        build_native_transfer(BASE, 0, DEST, units, BLOCK)


@pytest.mark.parametrize("decimals", [-1, 19, True, "6"])
def test_token_precision_is_explicit_reviewed_integer(decimals):
    with pytest.raises(ValueError):
        build_token_transfer(BASE, 0, MINT, DEST, 1, decimals, BLOCK)


@pytest.mark.parametrize("alteration", ["index", "destination", "amount", "blockhash", "extra"])
def test_native_revalidation_rejects_any_original_message_substitution(alteration):
    args = [BASE, 2, DEST, 10, BLOCK]
    original = build_native_transfer(*args)
    if alteration == "extra":
        ix = native_transfer_instructions(*args[:4])
        ix.append(Instruction(Pubkey.from_string(MINT), b"unapproved", []))
        changed = bytes(
            Message.new_with_blockhash(ix, Pubkey.from_string(BASE), Hash.from_string(BLOCK))
        )
    else:
        changes = {
            "index": (1, 3),
            "destination": (2, MINT),
            "amount": (3, 11),
            "blockhash": (4, str(Hash.default())),
        }
        index, value = changes[alteration]
        args[index] = value
        changed = build_native_transfer(*args)
    assert changed != original
    with pytest.raises(ValueError, match="original bound"):
        validate_native_transfer(encoded(changed), BASE, 2, DEST, 10, BLOCK)


def test_validators_reject_noncanonical_encoding_and_changed_rent_or_mint():
    raw = build_token_creation(BASE, 5, MINT, 2_039_280, BLOCK)
    with pytest.raises(ValueError):
        validate_token_creation(encoded(raw) + "\n", BASE, 5, MINT, 2_039_280, BLOCK)
    for mint, rent in [(DEST, 2_039_280), (MINT, 2_039_281)]:
        with pytest.raises(ValueError, match="original bound"):
            validate_token_creation(encoded(raw), BASE, 5, mint, rent, BLOCK)
    assert decode_message(encoded(raw))[0] == raw
