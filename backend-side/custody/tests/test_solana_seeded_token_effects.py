"""DB-free synthetic SDK fixtures; genuine MPC/validator acceptance is separate."""

import copy

import pytest
from solders.hash import Hash
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import Transaction

from custody.solana_seeded import account_address, token_creation_instructions
from custody.solana_seeded_token_effects import creation_effect
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM


def fixture():
    # Public known-key unit fixture, never a custody MPC key or genuine evidence.
    authority = Keypair.from_seed(bytes([101]) * 32)
    base, mint, block = str(authority.pubkey()), str(Pubkey.new_unique()), Hash.new_unique()
    rent, fee, index = 2_039_280, 5000, 5
    source = account_address(base, index, token=True)
    tx = Transaction.new_signed_with_payer(
        token_creation_instructions(base, index, mint, rent), authority.pubkey(), [authority], block
    )
    keys = [str(key) for key in tx.message.account_keys]
    token_index = keys.index(source)
    before = [10_000_000 if key == base else 0 for key in keys]
    after = before.copy()
    after[0] -= rent + fee
    after[token_index] += rent
    intent = {
        "claim": {"asset": {"kind": "ClassicToken", "mint": mint, "decimals": 6}, "index": index},
        "action": {"kind": "CreateClassicToken", "rent_lamports": rent},
        "operation_type": "PROVISION",
        "financial_source": source,
        "fee_payer": base,
        "rent_payer": base,
        "recent_blockhash": str(block),
        "expected_fee_lamports": fee,
        "expected_rent_lamports": rent,
    }
    meta = {
        "err": None,
        "fee": fee,
        "preBalances": before,
        "postBalances": after,
        "preTokenBalances": [],
        "postTokenBalances": [
            {
                "accountIndex": token_index,
                "mint": mint,
                "owner": base,
                "programId": CLASSIC_TOKEN_PROGRAM,
                "uiTokenAmount": {"amount": "0", "decimals": 6},
            }
        ],
    }
    return intent, tx, meta


def test_fresh_initialization_uses_exact_original_sdk_wire_and_separate_root_rent():
    intent, tx, meta = fixture()
    result = creation_effect(intent, tx, meta)
    assert result["rent_lamports"] == "2039280"
    assert result["fee_lamports"] == "5000"
    assert result["account"] == intent["financial_source"]


@pytest.mark.parametrize("field", ["mint", "authority", "amount", "rent", "fee", "index"])
def test_creation_rejects_wrong_token_identity_initial_balance_fee_or_effect(field):
    intent, tx, meta = fixture()
    if field == "mint":
        meta["postTokenBalances"][0]["mint"] = str(Pubkey.new_unique())
    elif field == "authority":
        meta["postTokenBalances"][0]["owner"] = str(Pubkey.new_unique())
    elif field == "amount":
        meta["postTokenBalances"][0]["uiTokenAmount"]["amount"] = "1"
    elif field == "rent":
        meta["postBalances"][meta["postTokenBalances"][0]["accountIndex"]] += 1
    elif field == "fee":
        meta["fee"] += 1
    else:
        intent["claim"]["index"] += 1
    with pytest.raises(ValueError):
        creation_effect(intent, tx, meta)


def test_failed_creation_proves_fee_alone_and_no_rent_or_token_effect():
    intent, tx, meta = fixture()
    meta["err"] = {"InstructionError": [0, "Custom"]}
    meta["postBalances"] = copy.deepcopy(meta["preBalances"])
    meta["postBalances"][0] -= 5000
    meta["postTokenBalances"] = []
    assert creation_effect(intent, tx, meta)["rent_lamports"] == "0"
    meta["postBalances"][1] += 1
    with pytest.raises(ValueError):
        creation_effect(intent, tx, meta)
