"""Finalized SDK-wire attribution tests; known external keys, no MPC claim."""

import copy
from decimal import Decimal
from types import SimpleNamespace

import base58
import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import Transaction

from custody.solana_seeded_token_deposits import normalized_token_balances, transfer_events
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM


def incoming(claim, *, payer=None, source=None, owner=None, checked=True, amount=2_000_000):
    payer = payer or Keypair.from_seed(bytes([95]) * 32)
    source = source or str(Keypair.from_seed(bytes([96]) * 32).pubkey())
    owner = owner or str(Keypair.from_seed(bytes([97]) * 32).pubkey())
    mint, destination = claim.asset.contract_address, claim.address
    accounts = [AccountMeta(Pubkey.from_string(source), False, True)]
    if checked:
        accounts.append(AccountMeta(Pubkey.from_string(mint), False, False))
    accounts.extend(
        [
            AccountMeta(Pubkey.from_string(destination), False, True),
            AccountMeta(payer.pubkey(), True, False),
        ]
    )
    data = bytes([12 if checked else 3]) + amount.to_bytes(8, "little")
    if checked:
        data += bytes([claim.asset.decimals])
    tx = Transaction.new_signed_with_payer(
        [Instruction(Pubkey.from_string(CLASSIC_TOKEN_PROGRAM), data, accounts)],
        payer.pubkey(),
        [payer],
        Hash.from_bytes(bytes([9]) * 32),
    )
    keys = [str(key) for key in tx.message.account_keys]

    def balance(address, authority, units):
        return dict(
            accountIndex=keys.index(address),
            mint=mint,
            owner=authority,
            programId=CLASSIC_TOKEN_PROGRAM,
            uiTokenAmount=dict(
                amount=str(units),
                decimals=claim.asset.decimals,
                uiAmount=None,
                uiAmountString="ignored",
            ),
        )

    pre = [balance(source, owner, 9_000_000), balance(destination, claim.root.base_address, 123)]
    post = copy.deepcopy(pre)
    post[0]["uiTokenAmount"]["amount"] = str(9_000_000 - amount)
    post[1]["uiTokenAmount"]["amount"] = str(123 + amount)
    lamps = [10_000_000] * len(keys)
    after = lamps.copy()
    after[0] -= 5000
    return tx, dict(
        err=None,
        fee=5000,
        preBalances=lamps,
        postBalances=after,
        preTokenBalances=pre,
        postTokenBalances=post,
    )


@pytest.fixture
def sample(monkeypatch):
    monkeypatch.setattr(
        "custody.solana_seeded_token_deposits.get_chain_spec",
        lambda _: SimpleNamespace(confirmations=32),
    )

    def key(value):
        return str(Keypair.from_seed(bytes([value]) * 32).pubkey())

    claim = SimpleNamespace(
        address=key(98),
        root=SimpleNamespace(base_address=key(99)),
        asset=SimpleNamespace(contract_address=key(100), decimals=6, asset_key="UNIT-SPL"),
    )
    return claim


def events(claim, tx, meta, internal=()):
    return transfer_events(
        tx,
        meta,
        20,
        str(tx.signatures[0]),
        SimpleNamespace(asset_account_address=claim.address),
        claim,
        internal_addresses=set(internal),
    )


@pytest.mark.parametrize("checked", [False, True])
def test_external_non_ata_delegate_transfer_uses_source_owner_not_fee_payer(sample, checked):
    tx, meta = incoming(sample, checked=checked)
    result = events(sample, tx, meta, [str(tx.message.account_keys[0])])
    assert len(result) == 1 and result[0].amount == Decimal(2)
    assert result[0].source_address != result[0].source_owner_address
    assert result[0].source_owner_address == meta["preTokenBalances"][0]["owner"]


@pytest.mark.parametrize("kind", ["owner", "account"])
def test_internal_source_owner_or_account_cannot_be_credited(sample, kind):
    tx, meta = incoming(sample)
    entry = meta["preTokenBalances"][0]
    internal = (
        entry["owner"] if kind == "owner" else str(tx.message.account_keys[entry["accountIndex"]])
    )
    assert events(sample, tx, meta, [internal]) == []


@pytest.mark.parametrize(
    "fault",
    ["owner", "mint", "program", "decimals", "duplicate", "missing", "amount", "delta"],
)
def test_incomplete_or_conflicting_selected_effect_never_becomes_credit(sample, fault):
    tx, meta = incoming(sample)
    entry = meta["postTokenBalances"][1]
    if fault in {"owner", "mint", "program"}:
        entry[{"owner": "owner", "mint": "mint", "program": "programId"}[fault]] = str(
            Keypair().pubkey()
        )
    elif fault == "decimals":
        entry["uiTokenAmount"]["decimals"] = True
    elif fault == "duplicate":
        meta["postTokenBalances"].append(copy.deepcopy(entry))
    elif fault == "missing":
        del entry["owner"]
    elif fault == "amount":
        entry["uiTokenAmount"]["amount"] = "02000123"
    elif fault == "delta":
        entry["uiTokenAmount"]["amount"] = "123"
    with pytest.raises((ValueError, KeyError)):
        events(sample, tx, meta)


def test_source_replenished_in_transaction_is_not_rejected_for_net_zero_balance(sample):
    tx, meta = incoming(sample)
    meta["postTokenBalances"][0]["uiTokenAmount"]["amount"] = "9000000"
    assert events(sample, tx, meta)[0].amount == 2


def test_closed_source_and_unrelated_foreign_mint_metadata_preserve_attribution(sample):
    tx, meta = incoming(sample, amount=9_000_000)
    meta["postTokenBalances"].pop(0)
    foreign = copy.deepcopy(meta["preTokenBalances"][0])
    foreign.update(accountIndex=0, mint=str(Keypair().pubkey()))
    meta["preTokenBalances"].append(foreign)
    meta["postTokenBalances"].append(copy.deepcopy(foreign))
    assert events(sample, tx, meta)[0].amount == Decimal(9)
    normalized = normalized_token_balances(meta, tx.message.account_keys)
    assert "uiAmount" not in str(normalized)


def test_runtime_cpi_transfer_attribution_uses_original_inner_identity(sample):
    tx, meta = incoming(sample)
    ix = tx.message.instructions[0]
    # Controlled finalized metadata fixture: outer instruction is not a Token
    # transfer, while the runtime inner Token instruction has exact indices.
    outer = Instruction(
        Pubkey.from_string("11111111111111111111111111111111"),
        b"fixture",
        [AccountMeta(key, index == 0, True) for index, key in enumerate(tx.message.account_keys)],
    )
    payer = Keypair.from_seed(bytes([95]) * 32)
    runtime = Transaction.new_signed_with_payer([outer], payer.pubkey(), [payer], Hash.default())
    old_keys, new_keys = tx.message.account_keys, runtime.message.account_keys

    def remap(index):
        return new_keys.index(old_keys[index])

    for name in ("preTokenBalances", "postTokenBalances"):
        for entry in meta[name]:
            entry["accountIndex"] = remap(entry["accountIndex"])
    meta["innerInstructions"] = [
        dict(
            index=0,
            instructions=[
                dict(
                    programIdIndex=remap(ix.program_id_index),
                    accounts=[remap(i) for i in ix.accounts],
                    data=base58.b58encode(bytes(ix.data)).decode(),
                )
            ],
        )
    ]
    result = events(sample, runtime, meta)
    assert result[0].event_index == "inner:0:0"


@pytest.mark.parametrize("initialize", [1, 16, 18])
def test_new_external_source_forwarded_and_closed_uses_executed_initializer_owner(
    sample, initialize
):
    tx, meta = incoming(sample)
    keys, compiled = tx.message.account_keys, tx.message.instructions[0]
    source_index, mint_index = compiled.accounts[:2]
    owner = Keypair.from_seed(bytes([95]) * 32)
    token = Pubkey.from_string(CLASSIC_TOKEN_PROGRAM)
    init_accounts = [
        AccountMeta(keys[source_index], False, True),
        AccountMeta(keys[mint_index], False, False),
    ]
    if initialize == 1:
        init_accounts.extend(
            [
                AccountMeta(owner.pubkey(), False, False),
                AccountMeta(Pubkey.new_unique(), False, False),
            ]
        )
    elif initialize == 16:
        init_accounts.append(AccountMeta(Pubkey.new_unique(), False, False))
    init = Instruction(
        token,
        bytes([initialize]) + (b"" if initialize == 1 else bytes(owner.pubkey())),
        init_accounts,
    )
    transfer = Instruction(
        token,
        bytes(compiled.data),
        [AccountMeta(keys[i], i == 0, i != mint_index) for i in compiled.accounts],
    )
    close = Instruction(
        token,
        b"\x09",
        [
            AccountMeta(keys[source_index], False, True),
            AccountMeta(owner.pubkey(), True, True),
            AccountMeta(owner.pubkey(), True, False),
        ],
    )
    initialized = Transaction.new_signed_with_payer(
        [init, transfer, close], owner.pubkey(), [owner], Hash.default()
    )
    new_keys = initialized.message.account_keys
    for name in ("preTokenBalances", "postTokenBalances"):
        meta[name] = [entry for entry in meta[name] if entry["accountIndex"] != source_index]
        for entry in meta[name]:
            entry["accountIndex"] = new_keys.index(keys[entry["accountIndex"]])
    result = events(sample, initialized, meta)
    assert len(result) == 1 and result[0].source_owner_address == str(owner.pubkey())
    assert result[0].event_index == "ix:1"
    assert events(sample, initialized, meta, [str(owner.pubkey())]) == []


@pytest.mark.parametrize("after_deposit", [False, True])
def test_transient_internal_source_owner_is_sticky_even_after_reassignment(sample, after_deposit):
    payer = Keypair.from_seed(bytes([95]) * 32)
    internal_owner = Keypair.from_seed(bytes([99]) * 32)
    tx, meta = incoming(sample, payer=payer, owner=str(payer.pubkey()))
    keys, compiled = tx.message.account_keys, tx.message.instructions[0]
    token = Pubkey.from_string(CLASSIC_TOKEN_PROGRAM)
    source = keys[compiled.accounts[0]]

    def change(old, new):
        return Instruction(
            token,
            bytes([6, 2, 1]) + bytes(new),
            [
                AccountMeta(source, False, True),
                AccountMeta(old, True, False),
            ],
        )

    transfer = Instruction(
        token,
        bytes(compiled.data),
        [AccountMeta(keys[i], i == 0, n in (0, 2)) for n, i in enumerate(compiled.accounts)],
    )
    changes = [
        change(payer.pubkey(), internal_owner.pubkey()),
        change(internal_owner.pubkey(), payer.pubkey()),
    ]
    instructions = [transfer, *changes] if after_deposit else [*changes, transfer]
    changed = Transaction.new_signed_with_payer(
        instructions, payer.pubkey(), [payer, internal_owner], Hash.default()
    )
    for name in ("preTokenBalances", "postTokenBalances"):
        for entry in meta[name]:
            entry["accountIndex"] = changed.message.account_keys.index(keys[entry["accountIndex"]])
    assert len(events(sample, changed, meta)) == 1
    assert events(sample, changed, meta, [str(internal_owner.pubkey())]) == []


def test_inner_initializer_is_processed_before_later_outer_token_transfer(sample):
    tx, meta = incoming(sample)
    keys, compiled = tx.message.account_keys, tx.message.instructions[0]
    source, mint = compiled.accounts[:2]
    payer = Keypair.from_seed(bytes([95]) * 32)
    outer = Instruction(
        Pubkey.new_unique(),
        b"runtime-init-fixture",
        [AccountMeta(key, index == 0, True) for index, key in enumerate(keys)],
    )
    transfer = Instruction(
        Pubkey.from_string(CLASSIC_TOKEN_PROGRAM),
        bytes(compiled.data),
        [AccountMeta(keys[i], i == 0, n in (0, 2)) for n, i in enumerate(compiled.accounts)],
    )
    changed = Transaction.new_signed_with_payer(
        [outer, transfer], payer.pubkey(), [payer], Hash.default()
    )

    def index(old):
        return changed.message.account_keys.index(keys[old])

    for name in ("preTokenBalances", "postTokenBalances"):
        for entry in meta[name]:
            if entry["accountIndex"] == source:
                entry["owner"] = str(payer.pubkey())
            entry["accountIndex"] = index(entry["accountIndex"])
    meta["preTokenBalances"] = [
        entry for entry in meta["preTokenBalances"] if entry["accountIndex"] != index(source)
    ]
    meta["innerInstructions"] = [
        dict(
            index=0,
            instructions=[
                dict(
                    programIdIndex=index(compiled.program_id_index),
                    accounts=[index(source), index(mint)],
                    data=base58.b58encode(bytes([18]) + bytes(payer.pubkey())).decode(),
                )
            ],
        )
    ]
    assert events(sample, changed, meta)[0].event_index == "ix:1"
