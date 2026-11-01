"""Real PG clean-mode import with original three-node DKG/receipts and Rust W."""

import copy
import json
import time

import pytest
from custody.identity_registry import register_principal, register_tenant
from custody.models import LedgerTransaction, MpcSolanaFinancialRoot
from custody.mpc_binding import MpcBindingError
from custody.solana_financial_root import complete_financial_mode, financial_mode_request
from custody.solana_provisioning import approve_claim, register_root, reserve_claim
from django.test import override_settings
from environment import private_file
from ops.models import Chain, NodeEndpoint
from profile_migration_acceptance import chain
from protected_acceptance import group
from test_network import settings_for
from witness_acceptance import sign, verify


def run_financial_mode_import(root_path):
    from test_solana import import_root

    tenant = register_tenant(reference="genuine-financial-mode-import", operator_ref="integration")
    with group(root_path, bootstrap_only=True, lifecycle=True, tenant_id=tenant.pk) as (g, _, __):
        Chain.objects.filter(chain_id="SOL").update(
            kind="solana", is_testnet=True, enabled=True, evm_chain_id=None
        )
        NodeEndpoint.objects.filter(chain_id="SOL", kind="rpc").update(enabled=False)
        NodeEndpoint.objects.create(
            chain_id="SOL", name="mode-import", kind="rpc", url=g.validator.url, enabled=True
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
            keyset, _base = import_root(g.dkg_binding)
            arguments = {
                "keyset_id": keyset.keyset_id,
                "tenant_id": tenant.pk,
                "operator_ref": "integration",
            }
            root = register_root(**arguments)
            g.w.start(initialize=True)
            g.w.enroll(root.evidence["participant_agreement"])
            original_root = copy.deepcopy(root.evidence)
            original_ledger = LedgerTransaction.objects.count()
            pending = financial_mode_request(**arguments)
            assert "claim_reservation_id" not in pending["query"]
            principal = register_principal(
                tenant_id=tenant.pk, customer_ref="actual-mode-owner", operator_ref="integration"
            )
            claim_arguments = {
                **arguments,
                "principal_id": principal.pk,
                "asset_key": "SOL",
                "idempotency_key": "mode-claim",
            }
            with pytest.raises(MpcBindingError, match="before any Claim"):
                reserve_claim(**claim_arguments)

            def query():
                code, response = g.w.request(
                    "query",
                    sign(g.w.custody, "WITNESS_QUERY_V1", pending["query"]),
                    identity=g.w.courier,
                )
                assert code == 200
                verify(g.w.identity, "WITNESS_QUERY_REPLY_V1", response)
                return response

            mode_off = query()
            with pytest.raises(MpcBindingError):
                complete_financial_mode(**arguments, evidence=mode_off)
            view = g.w.query()["root"]
            plan = {
                "version": 1,
                "activation_id": pending["expected_mode"]["activation_id"],
                "witness_anchor": g.w.config["anchor_id"],
                "root": g.original_root,
                "generation": view["generation"],
                "node_keys": view["node_keys"],
                "expires_at": int(time.time()) + 120,
            }
            domain = "WITNESS_SOLANA_FINANCIAL_MODE_V1"
            action = {
                "kind": "EnableFinancialMode",
                "approvals": {
                    "custody": sign(g.w.custody, domain, plan),
                    "policy": sign(g.w.policy, domain, plan),
                    "custody_certificate_chain_der_hex": chain(g.w.custody),
                    "policy_certificate_chain_der_hex": chain(g.w.policy),
                },
            }
            command = g.w.command(action, view["revision"])
            command["value"]["request_id"] = pending["expected_mode"]["command_id"]
            command = sign(g.w.life, "WITNESS_COMMAND_V1", command["value"])
            assert g.w.request("command", command)[0] == 200
            proof = query()
            assert proof["value"]["root"]["financial_mode"] == pending["expected_mode"]
            assert "claim_reservation_id" not in proof["value"]["query"]
            row = complete_financial_mode(**arguments, evidence=proof)
            assert row.status == "VERIFIED"
            assert complete_financial_mode(**arguments, evidence=None).evidence == proof
            claim = reserve_claim(**claim_arguments)
            claim = approve_claim(
                reservation_id=claim.pk, tenant_id=tenant.pk, operator_ref="integration"
            )
            g.w.register_claim(claim.statement, claim.evidence["participant_agreement"])
            g.w.stop()
            g.w.start()
            assert g.w.query()["root"]["financial_mode"] == pending["expected_mode"]
            assert financial_mode_request(**arguments)["status"] == "VERIFIED"
            assert MpcSolanaFinancialRoot.objects.get(root=root).evidence == proof
            root.refresh_from_db()
            assert root.evidence == original_root
            assert LedgerTransaction.objects.count() == original_ledger
            private_file(
                root_path / "solana-financial-root-import-public-evidence.json",
                json.dumps(
                    {
                        "scope": (
                            "genuine PG and protected Rust clean-mode import; "
                            "no wallet or ledger activation"
                        ),
                        "mode_ids_and_query_committed_before_independent_enable": True,
                        "canonical_no_claim_query_accepted_by_actual_rust_witness": True,
                        "mode_off_and_claim_before_import_rejected": True,
                        "original_three_store_claim_after_verified_import": True,
                        "original_mode_proof_preserved_after_claim_and_witness_restart": True,
                        "original_root_receipts_unchanged": True,
                        "financial_wallet_or_ledger_activation": False,
                    },
                    sort_keys=True,
                ).encode(),
            )
