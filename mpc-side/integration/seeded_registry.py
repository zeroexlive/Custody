"""Genuine FROST/three-store approvals plus authoritative PostgreSQL reservations.

Real isolated genesis and classic mint checks. Deliberately no issued customer
wallet, initialized seeded token account, signing grant or ledger acceptance.
"""

import json
import os
import time
from unittest.mock import patch

import pytest
import requests
from custody.identity_registry import register_principal, register_tenant
from custody.models import Asset, LedgerAccount, MpcSolanaClaim, MpcSolanaRoot, UserWallet
from custody.signer_adapter import SelfHostedMpcAdapter
from custody.solana_provisioning import approve_claim, register_root, reserve_claim
from custody.token_metadata import CLASSIC_TOKEN_PROGRAM, verify_token_asset
from django.db import connection
from django.test import override_settings
from ops.models import Chain, NodeEndpoint
from seeded_enrollment import services
from solana_local.validator import Validator
from test_dkg import dkg_request, encrypted_files, execute
from test_network import settings_for


def run_custody_registry(root_path):
    from test_solana import import_root

    assert connection.vendor == "postgresql"
    root_path.mkdir(mode=0o700)
    affinity = os.sched_getaffinity(0) if hasattr(os, "sched_getaffinity") else None
    validator = None
    if affinity:
        os.sched_setaffinity(0, sorted(affinity)[:4])
    try:
        validator = Validator(root_path / "validator")
        # Health can become ready before bundled SPL deployment is finalized.
        deadline = time.monotonic() + 60
        while True:
            program = validator.rpc(
                "getAccountInfo",
                [CLASSIC_TOKEN_PROGRAM, {"commitment": "finalized", "encoding": "base64"}],
            )["value"]
            slot = validator.rpc("getSlot", [{"commitment": "finalized"}])
            if program and program["executable"] and slot > 1:
                break
            assert time.monotonic() < deadline, "classic SPL program did not finalize"
            time.sleep(0.2)
        validator.create_mint()
        Chain.objects.filter(chain_id="SOL").update(
            kind="solana",
            is_testnet=True,
            enabled=True,
            evm_chain_id=None,
        )
        NodeEndpoint.objects.filter(chain_id="SOL", kind="rpc").update(enabled=False)
        NodeEndpoint.objects.create(
            chain_id="SOL", name="registry-isolated", kind="rpc", url=validator.url, enabled=True
        )
        with services(root_path / "services") as net:
            original = dkg_request()
            code, dkg = execute(net, original)
            assert code == 200 and dkg["status"] == "COMPLETED"
            shares = encrypted_files(net, original)
            with (
                settings_for(net),
                override_settings(
                    MPC_SIGNER_BACKEND="self_hosted_mpc",
                    MPC_SOLANA_INTEGRATION_ENABLED=True,
                    MPC_SOLANA_NETWORK=validator.policy,
                    MPC_EVM_INTEGRATION_ENABLED=False,
                    MPC_TRON_INTEGRATION_ENABLED=False,
                    MPC_INTEGRATION_ENVIRONMENT="development",
                    CUSTODY_DEMO_MODE=False,
                    CUSTODY_TX_MODE="live",
                    CUSTODY_INDEXER_MODE="live",
                ),
            ):
                keyset, base = import_root(original)
                tenant = register_tenant(reference="genuine-SOL-tenant", operator_ref="integration")
                principal = register_principal(
                    tenant_id=tenant.pk, customer_ref="genuine-customer", operator_ref="integration"
                )
                arguments = {
                    "keyset_id": keyset.keyset_id,
                    "tenant_id": tenant.pk,
                    "operator_ref": "integration",
                }
                net.stop("signer-c")
                with pytest.raises(requests.HTTPError):
                    register_root(**arguments)
                pending = MpcSolanaRoot.objects.get()
                assert pending.status == "PENDING" and not pending.evidence
                root_statement = pending.statement
                net.start("signer-c")
                connection.close()
                enrolled = register_root(**arguments)
                assert enrolled.status == "APPROVED" and enrolled.statement == root_statement
                assert enrolled.statement["dkg"] == original
                assert enrolled.statement["ownership_scope"] == str(tenant.pk)
                native = reserve_claim(
                    **arguments,
                    principal_id=principal.pk,
                    asset_key="SOL",
                    idempotency_key="native",
                )
                assert (
                    native.index == 0 and native.statement["owner_ref"] == principal.ledger_owner_id
                )
                net.stop("signer-c")
                with pytest.raises(requests.HTTPError):
                    approve_claim(
                        reservation_id=native.pk, tenant_id=tenant.pk, operator_ref="integration"
                    )
                native.refresh_from_db()
                assert native.status == "PENDING" and not native.evidence
                for party in ("signer-a", "signer-b"):
                    assert (
                        len(
                            list((net.root / party / "storage/solana-provisioning").glob("*.index"))
                        )
                        == 1
                    )
                net.start("signer-c")
                # Restart both custody connection and the coordinator; the
                # original signed statement and randomized receipts must survive.
                net.stop("coordinator")
                net.start("coordinator")
                connection.close()
                approved = approve_claim(
                    reservation_id=native.pk, tenant_id=tenant.pk, operator_ref="integration"
                )
                assert approved.status == "APPROVED" and approved.statement == native.statement
                mint = str(validator.mint.pubkey())
                token = Asset.objects.create(
                    asset_key="REGISTRY-SPL",
                    chain_id="SOL",
                    symbol="RSPL",
                    decimals=6,
                    is_native=False,
                    token_standard="SPL",
                    contract_address=mint,
                )
                verify_token_asset(token.asset_key)
                spl = reserve_claim(
                    **arguments,
                    principal_id=principal.pk,
                    asset_key=token.asset_key,
                    idempotency_key="classic-mint",
                )
                assert spl.index == 1 and spl.address != native.address
                # A lost response after all three actual durable signer commits
                # still leaves the original DB reservation for reconciliation.
                original_approve = SelfHostedMpcAdapter.approve_solana_claim

                def lose(self, *args):
                    original_approve(self, *args)
                    raise TimeoutError("lost after three genuine commits")

                with patch.object(SelfHostedMpcAdapter, "approve_solana_claim", lose):
                    with pytest.raises(TimeoutError):
                        approve_claim(
                            reservation_id=spl.pk, tenant_id=tenant.pk, operator_ref="integration"
                        )
                spl.refresh_from_db()
                assert spl.status == "PENDING"
                spl = approve_claim(
                    reservation_id=spl.pk, tenant_id=tenant.pk, operator_ref="integration"
                )
                assert spl.status == "APPROVED" and MpcSolanaClaim.objects.count() == 2
                assert (
                    validator.rpc("getAccountInfo", [spl.address, {"encoding": "base64"}])["value"]
                    is None
                )
                assert not UserWallet.objects.exists() and not LedgerAccount.objects.exists()
                assert encrypted_files(net, original) == shares
                enrolled.refresh_from_db()
                assert enrolled.next_index == 2
                before = [approved.evidence, spl.evidence]
                for party in ("signer-a", "signer-b", "signer-c"):
                    net.stop(party)
                after = [
                    approve_claim(
                        reservation_id=r.pk, tenant_id=tenant.pk, operator_ref="integration"
                    ).evidence
                    for r in (approved, spl)
                ]
                assert before == after
                report = {
                    "scope": "operator durable reservations and genuine three-store approval only",
                    "issued_wallets": 0,
                    "network": validator.policy,
                    "base": base,
                    "root_statement": enrolled.statement,
                    "root_evidence": enrolled.evidence,
                    "claims": [
                        {"statement": r.statement, "address": r.address, "evidence": r.evidence}
                        for r in (approved, spl)
                    ],
                    "partial_and_lost_response_recovered": True,
                    "original_encrypted_shares_unchanged": True,
                    "spl_account_initialized": False,
                }
                (root_path / "solana-registry-public-evidence.json").write_text(
                    json.dumps(report, indent=2) + "\n"
                )
    finally:
        try:
            if validator:
                validator.close()
        finally:
            if affinity:
                os.sched_setaffinity(0, affinity)
