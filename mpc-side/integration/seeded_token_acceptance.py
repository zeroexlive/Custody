"""Genuine seeded-token wire/finality acceptance, no backend wallet or ledger activation."""

import json
import uuid

from custody.solana_seeded import account_address
from custody.solana_seeded_token_effects import creation_effect
from custody.solana_settlement import finalized_transaction
from custody.spl import derive_ata
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM
from environment import private_file
from protected_acceptance import balance, group
from seeded_enrollment import approval, call, claim
from solders.instruction import AccountMeta, Instruction
from solders.pubkey import Pubkey
from test_dkg import PARTIES, encrypted_files


def run_seeded_token_sweeps(root_path):
    with group(root_path) as (g, native, _):
        ciphertexts = encrypted_files(g.net, g.w.root["dkg"])
        g.validator.create_mint()
        mint = str(g.validator.mint.pubkey())
        base = str(Pubkey.from_bytes(bytes.fromhex(g.w.root["group_public_key"])))
        base_before = balance(g, base)
        rent = g.validator.rpc("getMinimumBalanceForRentExemption", [165])
        claims = []
        for index in (1, 2):
            c = claim(
                g.w.root,
                index=index,
                owner=native["owner_ref"] if index == 1 else f"p1:{uuid.uuid4()}",
                asset={"kind": "ClassicToken", "mint": mint, "decimals": 6},
            )
            receipts = []
            for party in PARTIES:
                code, receipt = call(g.net, party, "approve", approval(g.net, "claim", c))
                assert code == 200
                receipts.append(receipt)
            g.w.register_claim(c, receipts)
            claims.append((c, receipts))

        def initialize(entry, operation, pair):
            c, receipts = entry
            binding = g.token_binding(c, receipts, operation, pair, create=True)
            signature, record = g.broadcast(binding, g.sign(binding))
            status = g.validator.rpc(
                "getSignatureStatuses", [[signature], {"searchTransactionHistory": True}]
            )["value"][0]
            tx, meta, slot = finalized_transaction(record, signature, status)
            effect = creation_effect(binding["authorized"]["intent"], tx, meta)
            assert effect["rent_lamports"] == str(rent) and effect["fee_lamports"] == "5000"
            return signature, slot

        initialization = [initialize(claims[0], 1001, PARTIES[:2])]
        source = account_address(base, 1, token=True)
        destination = account_address(base, 2, token=True)
        # Disposable external mint authority supplies test inventory. This is
        # not customer deposit/provenance or a financial-ledger acceptance claim.
        g.validator.send(
            [
                Instruction(
                    Pubkey.from_string(CLASSIC_TOKEN_PROGRAM),
                    b"\x07" + (9_000_000).to_bytes(8, "little"),
                    [
                        AccountMeta(Pubkey.from_string(mint), False, True),
                        AccountMeta(Pubkey.from_string(source), False, True),
                        AccountMeta(g.validator.faucet.pubkey(), True, False),
                    ],
                )
            ]
        )
        missing = g.token_binding(*claims[0], operation=1002, seeded_destination=(base, 2))
        control = {"binding": missing, "round": 1, "signing_package": None}
        assert g.call(PARTIES[0], "auto", control)[0] == 409
        execution = missing["authorized"]["intent"]["crypto_execution_id"]
        view = g.w.query(execution)
        assert view["execution"]["status"] == "Open"
        assert view["execution"]["reports"] == {}
        assert g.call(PARTIES[0], "recover", control) == (200, None)
        close = g.w.command(
            {"kind": "CloseNoSignature", "execution_id": execution}, view["root"]["revision"]
        )
        assert g.w.request("command", close)[0] == 200
        assert g.w.query(execution)["execution"]["status"] == "NoSignature"
        initialization.append(initialize(claims[1], 1003, (PARTIES[0], PARTIES[2])))

        def units(address):
            return int(
                g.validator.rpc("getTokenAccountBalance", [address, {"commitment": "finalized"}])[
                    "value"
                ]["amount"]
            )

        signatures = []
        for n, pair in enumerate(
            ((PARTIES[0], PARTIES[1]), (PARTIES[0], PARTIES[2]), (PARTIES[1], PARTIES[2])), 1010
        ):
            binding = g.token_binding(
                *claims[0], operation=n, pair=pair, seeded_destination=(base, 2)
            )
            signatures.append(g.broadcast(binding, g.sign(binding))[0])
        assert units(source) == 6_000_000 and units(destination) == 3_000_000
        binding = g.token_binding(
            *claims[1], operation=1020, pair=PARTIES[1:], create_ata=True, amount=2_000_000
        )
        binding["authorized"]["intent"]["operation_type"] = "WITHDRAWAL"
        binding = g.w.authorize(binding["authorized"])
        binding["selected_signers"] = list(PARTIES[1:])
        signatures.append(g.broadcast(binding, g.sign(binding))[0])
        external = derive_ata(binding["authorized"]["intent"]["action"]["destination_owner"], mint)
        assert (units(source), units(destination), units(external)) == (
            6_000_000,
            1_000_000,
            2_000_000,
        )
        assert balance(g, source) == balance(g, destination) == rent
        assert balance(g, base) == base_before - 3 * rent - 6 * 5000
        g.w.stop()
        for party in PARTIES:
            g.net.stop(party)
        g.w.start()
        for party in PARTIES:
            g.start(party)
        assert encrypted_files(g.net, g.w.root["dkg"]) == ciphertexts
        private_file(
            root_path / "solana-seeded-token-sweep-public-evidence.json",
            json.dumps(
                {
                    "scope": (
                        "genuine protected standard seeded SPL wire/finality only; "
                        "no backend wallet/financial activation"
                    ),
                    "original_two_seeded_accounts_initialized_with_exact_finalized_rent": True,
                    "missing_seeded_destination_rejected_before_private_work": True,
                    "explicit_no_signature_closes_failed_first_round": True,
                    "all_three_frost_pairs_finalized_seeded_transfer_checked": True,
                    "separate_external_ata_transfer_finalized": True,
                    "token_units_conserved": 9_000_000,
                    "separate_base_network_fee_lamports": 30_000,
                    "rent_funded_accounts": 3,
                    "original_three_dkg_ciphertexts_unchanged_after_restart": True,
                    "synthetic_business_ids_and_external_fixture_mint_inventory": True,
                    "initialization_slots": [slot for _, slot in initialization],
                },
                sort_keys=True,
            ).encode(),
        )
