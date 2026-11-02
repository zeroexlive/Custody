"""Synthetic RPC data with real canonical wire signatures; no chain/credit claim."""

import base64
import copy
from unittest.mock import patch

import pytest
from solders.address_lookup_table_account import AddressLookupTableAccount
from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction, VersionedTransaction

from custody.mpc_binding import MpcBindingError
from custody.solana_financial_deposit_observation import observe_deposit_transaction


def observation():
    # Known test-only external sender; never a reconstructed custody key.
    sender = Keypair.from_seed(bytes([91]) * 32)
    destination = Keypair.from_seed(bytes([92]) * 32).pubkey()
    tx = Transaction.new_signed_with_payer(
        [
            transfer(
                TransferParams(
                    from_pubkey=sender.pubkey(), to_pubkey=destination, lamports=2_000_000
                )
            ),
        ],
        sender.pubkey(),
        [sender],
        Hash.from_bytes(bytes([7]) * 32),
    )
    keys = [str(key) for key in tx.message.account_keys]
    before = [10_000_000] * len(keys)
    after = before.copy()
    after[0] -= 2_005_000
    after[keys.index(str(destination))] += 2_000_000
    signature = str(tx.signatures[0])
    meta = dict(err=None, fee=5000, preBalances=before, postBalances=after)
    return tx, {
        "getSignatureStatuses": {
            "value": [dict(confirmationStatus="finalized", slot=20, err=None)]
        },
        "getTransaction": {
            "transaction": [base64.b64encode(bytes(tx)).decode(), "base64"],
            "slot": 20,
            "meta": meta,
            "version": "legacy",
        },
        "getBlock": {
            "blockhash": str(Hash.from_bytes(bytes([8]) * 32)),
            "parentSlot": 19,
            "signatures": [signature],
        },
    }


def collect(responses, fixture=None):
    tx, values = fixture or observation()
    calls = []

    def rpc(chain, endpoint, transport, method, params):
        calls.append((endpoint, method, params))
        value = responses(values, endpoint, method)
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)

    with (
        patch(
            "custody.solana_financial_deposit_observation.rpc_urls",
            return_value=["primary", "fallback"],
        ),
        patch(
            "custody.solana_financial_deposit_observation.network_identity",
            return_value={"genesis_hash": str(Hash.from_bytes(bytes([9]) * 32))},
        ),
        patch("custody.solana_financial_deposit_observation.guarded_solana_rpc", side_effect=rpc),
    ):
        return observe_deposit_transaction(str(tx.signatures[0])), calls


def test_original_canonical_wire_status_and_block_membership_captured_without_credit():
    (tx, meta, evidence, digest), calls = collect(lambda values, endpoint, method: values[method])
    assert tx.verify_with_results() == [True]
    assert evidence["signature"] == str(tx.signatures[0]) and evidence["slot"] == 20
    assert len(digest) == 64 and meta == evidence["transaction"]["meta"]
    assert [method for _, method, _ in calls] == [
        "getSignatureStatuses",
        "getTransaction",
        "getBlock",
    ]


@pytest.mark.parametrize(
    "fault",
    ["signature_missing", "duplicate_signature", "block_hash", "parent", "slot", "wire", "error"],
)
def test_conflicting_finalized_evidence_cannot_be_overridden_by_fallback(fault):
    calls = []

    def response(values, endpoint, method):
        calls.append(endpoint)
        assert endpoint == "primary"
        values = copy.deepcopy(values)
        if fault == "signature_missing":
            values["getBlock"]["signatures"] = []
        elif fault == "duplicate_signature":
            values["getBlock"]["signatures"] *= 2
        elif fault == "block_hash":
            values["getBlock"]["blockhash"] = "invalid"
        elif fault == "parent":
            values["getBlock"]["parentSlot"] = 20
        elif fault == "slot":
            values["getTransaction"]["slot"] = 21
        elif fault == "wire":
            values["getTransaction"]["transaction"][0] = base64.b64encode(b"invalid").decode()
        else:
            values["getTransaction"]["meta"]["err"] = True
            values["getSignatureStatuses"]["value"][0]["err"] = True
        return values[method]

    with pytest.raises(MpcBindingError, match="conflicting/malformed"):
        collect(response)
    assert "fallback" not in calls


@pytest.mark.parametrize("missing", ["status", "transaction", "block", "timeout"])
def test_missing_data_can_recover_on_trusted_fallback(missing):
    def response(values, endpoint, method):
        if endpoint == "primary":
            if missing == "status" and method == "getSignatureStatuses":
                return {"value": [None]}
            if missing == "transaction" and method == "getTransaction":
                return None
            if missing == "block" and method == "getBlock":
                return None
            if missing == "timeout":
                return TimeoutError()
        return values[method]

    (_, _, evidence, _), calls = collect(response)
    assert evidence["slot"] == 20 and any(endpoint == "fallback" for endpoint, _, _ in calls)


def test_all_endpoints_missing_stays_unavailable():
    with pytest.raises(MpcBindingError, match="credit and cursor unchanged"):
        collect(lambda values, endpoint, method: {"value": [None]})


def versioned_observation(*, with_lookup):
    _, values = observation()
    sender = Keypair.from_seed(bytes([91]) * 32)
    destination = Keypair.from_seed(bytes([92]) * 32).pubkey()
    ix = transfer(
        TransferParams(from_pubkey=sender.pubkey(), to_pubkey=destination, lamports=2_000_000)
    )
    table = AddressLookupTableAccount(Pubkey.from_bytes(bytes([23]) * 32), [destination])
    message = MessageV0.try_compile(
        sender.pubkey(), [ix], [table] if with_lookup else [], Hash.from_bytes(bytes([7]) * 32)
    )
    tx = VersionedTransaction(message, [sender])
    loaded = [destination] if with_lookup else []
    keys = list(message.account_keys) + loaded
    before = [10_000_000] * len(keys)
    after = before.copy()
    after[0] -= 2_005_000
    after[keys.index(destination)] += 2_000_000
    values["getTransaction"].update(
        version=0, transaction=[base64.b64encode(bytes(tx)).decode(), "base64"]
    )
    values["getTransaction"]["meta"].update(
        preBalances=before,
        postBalances=after,
        loadedAddresses={"writable": [str(k) for k in loaded], "readonly": []},
    )
    values["getBlock"]["signatures"] = [str(tx.signatures[0])]
    return tx, values


@pytest.mark.parametrize("with_lookup", [False, True])
def test_versioned_incoming_wire_resolves_keys_without_changing_signed_message(with_lookup):
    original, values = versioned_observation(with_lookup=with_lookup)
    (tx, meta, evidence, _), _ = collect(
        lambda values, endpoint, method: values[method], fixture=(original, values)
    )
    assert bytes(tx) == bytes(original) and tx.verify_with_results() == [True]
    assert len(tx.message.account_keys) == len(meta["preBalances"])
    assert evidence["transaction"]["version"] == 0


@pytest.mark.parametrize("fault", ["missing", "duplicate", "balances"])
def test_malformed_versioned_loaded_accounts_are_conflicting_not_fallback(fault):
    tx, values = versioned_observation(with_lookup=True)
    meta = values["getTransaction"]["meta"]
    if fault == "missing":
        meta.pop("loadedAddresses")
    elif fault == "duplicate":
        meta["loadedAddresses"]["writable"] = [str(tx.message.account_keys[0])]
    else:
        meta["postBalances"].pop()

    def reply(values, endpoint, method):
        assert endpoint == "primary"
        return values[method]

    with pytest.raises(MpcBindingError, match="conflicting/malformed"):
        collect(reply, fixture=(tx, values))


def test_optional_rpc_envelope_fields_do_not_change_permanent_native_attribution():
    (_, _, _, original), _ = collect(lambda values, endpoint, method: values[method])

    def extra(values, endpoint, method):
        values["getSignatureStatuses"]["value"][0]["confirmations"] = None
        values["getTransaction"]["meta"].update(computeUnitsConsumed=150, costUnits=750)
        values["getTransaction"]["blockTime"] = 10
        values["getBlock"]["rewards"] = []
        return values[method]

    (_, _, _, current), _ = collect(extra)
    assert current == original
