"""Actual PostgreSQL issuance plus three protected FROST processes and witness.

Every wallet is really reserved, approved at each signer, registered/issued at
the independent witness and published in PostgreSQL. No synthetic receipts.
"""

import copy
import hashlib
import json
import time
import uuid

import pytest
from custody.identity_registry import register_principal, register_tenant
from custody.models import LedgerTransaction, MpcSolanaIssuance, UserWallet
from custody.mpc_binding import MpcBindingError
from custody.solana_issuance import complete_publication, publication_request
from custody.solana_provisioning import approve_claim, register_root, reserve_claim
from django.test import override_settings
from environment import private_file
from ops.models import Chain, NodeEndpoint
from protected_acceptance import group
from seeded_enrollment import approval, call
from test_dkg import PARTIES, encrypted_files
from test_network import settings_for
from witness_acceptance import sign


def run_native_issuance(root_path, count):
    from test_solana import import_root

    tenant = register_tenant(reference="genuine-native-publication", operator_ref="integration")
    with group(root_path, bootstrap_only=True, tenant_id=tenant.pk) as (g, _, __):
        Chain.objects.filter(chain_id="SOL").update(
            kind="solana", is_testnet=True, enabled=True, evm_chain_id=None
        )
        NodeEndpoint.objects.filter(chain_id="SOL", kind="rpc").update(enabled=False)
        NodeEndpoint.objects.create(
            chain_id="SOL", name="native-publication", kind="rpc", url=g.validator.url, enabled=True
        )
        with (
            settings_for(g.net),
            override_settings(
                MPC_SIGNER_BACKEND="self_hosted_mpc",
                MPC_SOLANA_INTEGRATION_ENABLED=True,
                MPC_SOLANA_NETWORK=g.validator.policy,
                MPC_EVM_INTEGRATION_ENABLED=False,
                MPC_TRON_INTEGRATION_ENABLED=False,
                MPC_INTEGRATION_ENVIRONMENT="development",
                CUSTODY_DEMO_MODE=False,
                CUSTODY_TX_MODE="live",
                CUSTODY_INDEXER_MODE="live",
                MPC_SOLANA_WITNESS_ANCHOR_ID=g.w.config["anchor_id"],
                MPC_SOLANA_WITNESS_CERTIFICATE=str(g.w.identity / "tls.crt"),
            ),
        ):
            keyset, base = import_root(g.dkg_binding)
            arguments = {
                "keyset_id": keyset.keyset_id,
                "tenant_id": tenant.pk,
                "operator_ref": "integration",
            }
            root = register_root(**arguments)
            assert root.statement == g.original_root
            g.w.start(initialize=True)
            g.w.enroll(root.evidence["participant_agreement"])
            original_shares = encrypted_files(g.net, g.dkg_binding)
            ledger_before = LedgerTransaction.objects.count()
            started = time.monotonic()
            issued = []
            for index in range(count):
                principal = register_principal(
                    tenant_id=tenant.pk,
                    customer_ref=f"actual-native-{index}",
                    operator_ref="integration",
                )
                claim = reserve_claim(
                    **arguments,
                    principal_id=principal.pk,
                    asset_key="SOL",
                    idempotency_key=f"actual-{index}",
                )
                claim = approve_claim(
                    reservation_id=claim.pk, tenant_id=tenant.pk, operator_ref="integration"
                )
                assert claim.index == index
                receipts = claim.evidence["participant_agreement"]
                g.w.register_claim(claim.statement, receipts)
                intent = publication_request(
                    reservation_id=claim.pk, tenant_id=tenant.pk, operator_ref="integration"
                )
                if count == 3 and index == 0:
                    # Real registered claim with all three receipts still has
                    # no right to publication without independent issuance.
                    code, not_issued = g.w.request(
                        "query",
                        sign(g.w.life, "WITNESS_QUERY_V1", intent["query"]),
                        identity=g.w.courier,
                    )
                    assert code == 200 and not_issued["value"].get("claim_issuance") is None
                    with pytest.raises(MpcBindingError):
                        complete_publication(
                            issuance_id=intent["issuance_id"],
                            tenant_id=tenant.pk,
                            evidence=not_issued,
                            operator_ref="integration",
                        )
                if count == 3 and index == 1:
                    collision = dict(intent["witness_action"], issuance_id=issued[0][3])
                    forbidden = g.w.command(collision, g.w.query()["root"]["revision"])
                    assert g.w.request("command", forbidden)[0] == 409
                command = g.w.command(intent["witness_action"], g.w.query()["root"]["revision"])
                assert g.w.request("command", command)[0] == 200
                if count == 3 and index == 0:
                    # Lose the first public ACK, restart the actual witness,
                    # then replay the exact authorized original command.
                    g.w.stop()
                    g.w.start()
                    assert g.w.request("command", command)[0] == 200
                # The lifecycle identity lives outside backend configuration;
                # only this explicit independent test/operator relay uses it.
                query = sign(g.w.life, "WITNESS_QUERY_V1", intent["query"])
                code, proof = g.w.request("query", query, identity=g.w.courier)
                assert code == 200
                wallet = complete_publication(
                    issuance_id=intent["issuance_id"],
                    tenant_id=tenant.pk,
                    evidence=proof,
                    operator_ref="integration",
                )
                assert (
                    wallet.solana_claim_id == claim.pk
                    and wallet.user_id == principal.ledger_owner_id
                )
                assert wallet.deposit_address == claim.address and wallet.address_index == index
                if count == 3:
                    # A lost backend response cannot create a second wallet or
                    # a new witness issuance ID on the exact publication retry.
                    assert (
                        complete_publication(
                            issuance_id=intent["issuance_id"],
                            tenant_id=tenant.pk,
                            evidence=None,
                            operator_ref="integration",
                        ).pk
                        == wallet.pk
                    )
                issued.append((wallet, claim, receipts, intent["issuance_id"]))
                if (index + 1) % 100 == 0:
                    print(
                        f"genuinely issued native wallets: {index + 1}; "
                        f"elapsed seconds: {time.monotonic() - started:.2f}",
                        flush=True,
                    )
            if count == 3:
                # Hot-cache checks still consult the real complete index store.
                # Only public receipt bytes are faulted and restored here.
                party = PARTIES[0]
                directory = g.net.root / party / "storage" / "solana-provisioning"
                original_path = directory / f"{keyset.keyset_id}-0.index"
                original_bytes = original_path.read_bytes()
                hypothetical = copy.deepcopy(issued[-1][1].statement)
                hypothetical.update(
                    index=count,
                    reservation_id=str(uuid.uuid4()),
                    owner_ref=f"p1:{uuid.uuid4()}",
                    idempotency_key="cache-fault-denied",
                )
                authorized = approval(g.net, "claim", hypothetical)
                try:
                    private_file(original_path, b"{}")
                    assert call(g.net, party, "approve", authorized)[0] == 409
                    original_path.unlink()
                    assert call(g.net, party, "approve", authorized)[0] == 409
                finally:
                    private_file(original_path, original_bytes)
                # Rebuild all three caches from original durable receipts, not
                # coordinator aliases, before any private spending operation.
                for party in PARTIES:
                    g.net.stop(party)
                    g.start(party)
            assert UserWallet.objects.filter(solana_claim__root=root).count() == count
            assert (
                MpcSolanaIssuance.objects.filter(claim__root=root, status="WITNESSED").count()
                == count
            )
            assert g.w.query()["root"]["next_claim_index"] == count
            assert LedgerTransaction.objects.count() == ledger_before
            elapsed = time.monotonic() - started
            g.validator.fund(base, 200000000)
            transactions = []
            for n, (pair, position) in enumerate(
                zip(
                    ((PARTIES[0], PARTIES[1]), (PARTIES[0], PARTIES[2]), (PARTIES[1], PARTIES[2])),
                    (0, count // 2, count - 1),
                    strict=True,
                ),
                1,
            ):
                wallet, claim, receipts, _ = issued[position]
                g.validator.fund(wallet.deposit_address, 5000000)
                binding = g.binding(claim.statement, receipts, n, pair)
                signature, record = g.broadcast(binding, g.sign(binding))
                transactions.append(
                    {
                        "wallet_index": position,
                        "pair": list(pair),
                        "signature": signature,
                        "finalized": True,
                        "fee_lamports": record["meta"]["fee"],
                    }
                )
            assert encrypted_files(g.net, g.dkg_binding) == original_shares
            public_rows = [
                {
                    "wallet_id": w.pk,
                    "reservation_id": str(c.pk),
                    "owner_ref": w.user_id,
                    "index": w.address_index,
                    "address": w.deposit_address,
                }
                for w, c, _, __ in issued
            ]
            report = {
                "scope": "genuine native issuance; primitive transfers; ledger integration pending",
                "actually_issued_native_wallets": count,
                "issuance_seconds": elapsed,
                "all_three_original_claim_receipts_verified_per_wallet": True,
                "independent_witness_registration_and_issuance_per_wallet": True,
                "postgres_wallets_and_issuances": count,
                "ledger_journals_created_by_issuance": 0,
                "original_encrypted_shares_unchanged": True,
                "restart_lost_ack_unissued_collision_and_index_faults": count == 3,
                "transactions": transactions,
                "public_wallet_rows_sha256": hashlib.sha256(
                    json.dumps(public_rows, sort_keys=True).encode()
                ).hexdigest(),
            }
            private_file(
                root_path / "solana-native-issuance-public-evidence.json",
                (json.dumps(report, indent=2) + "\n").encode(),
            )
