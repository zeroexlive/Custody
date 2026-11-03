"""Actual Root-scoped coordinator routing, native financial execution and recovery."""

import copy
import json

import pytest
from custody.identity_registry import register_principal, register_tenant
from custody.models import LedgerTransaction, MpcKeyset
from custody.mpc_binding import MpcBindingError
from custody.solana_coordinator import bind_coordinator, resolve_route
from custody.solana_provisioning import approve_claim, register_root, reserve_claim
from django.conf import settings
from django.test import override_settings
from environment import private_file
from financial_native_acceptance import native_financial_flow
from financial_signing_acceptance import run_financial_signing
from financial_wallet_acceptance import run_financial_wallets
from ops.models import Chain, NodeEndpoint
from receipt_pin_acceptance import pins
from seeded_enrollment import services
from solana_local.validator import Validator
from test_dkg import dkg_request, encrypted_files, execute
from test_network import settings_for


def route_config(net):
    return {
        "url": f"https://localhost:{net.ports['coordinator']}",
        "coordinator_certificate": str(net.root / "coordinator/identity/tls.crt"),
        "ca_certificate": str(net.root / "custody/identity/ca.crt"),
        "client_certificate": str(net.root / "custody/identity/tls.crt"),
        "client_key": str(net.root / "custody/identity/tls.key"),
    }


def bind_before_import(g, keyset):
    settings.MPC_SOLANA_COORDINATOR_ROUTES = {str(keyset.keyset_id): route_config(g.net)}
    settings.MPC_SOLANA_ROOT_SIGNER_CERTIFICATES = {str(keyset.keyset_id): pins(g.net)}
    bind_coordinator(keyset_id=keyset.keyset_id, operator_ref="integration")
    keyset.refresh_from_db()
    assert keyset.solana_coordinator_required


def run_coordinator_cohorts(root_path):
    from test_solana import import_root

    tenant = register_tenant(reference="routed-two-cohorts", operator_ref="integration")
    principal = register_principal(
        tenant_id=tenant.pk, customer_ref="routed-owner", operator_ref="integration"
    )
    before = LedgerTransaction.objects.count()
    validator = Validator(root_path / "validator")
    try:
        Chain.objects.filter(chain_id="SOL").update(
            kind="solana", is_testnet=True, enabled=True, evm_chain_id=None
        )
        NodeEndpoint.objects.filter(chain_id="SOL", kind="rpc").update(enabled=False)
        NodeEndpoint.objects.create(
            chain_id="SOL", name="routed-cohorts", kind="rpc", url=validator.url, enabled=True
        )
        with (
            services(root_path / "cohort-A") as a,
            services(root_path / "cohort-B") as b,
            override_settings(
                MPC_SIGNER_BACKEND="self_hosted_mpc",
                MPC_SOLANA_INTEGRATION_ENABLED=True,
                MPC_SOLANA_NETWORK=validator.policy,
                MPC_INTEGRATION_ENVIRONMENT="development",
                CUSTODY_DEMO_MODE=False,
                CUSTODY_TX_MODE="live",
                CUSTODY_INDEXER_MODE="live",
            ),
        ):
            records = []
            for net, wrong in [(a, b), (b, a)]:
                binding = dkg_request()
                code, dkg = execute(net, binding)
                assert code == 200 and dkg["status"] == "COMPLETED"
                shares = encrypted_files(net, binding)
                # Route trust is committed to the otherwise empty local keyset
                # before import-root makes any backend HTTP request.
                with (
                    settings_for(wrong),
                    override_settings(
                        MPC_CLIENT_CERT=str(net.root / "custody/identity/tls.crt"),
                        MPC_CLIENT_KEY=str(net.root / "custody/identity/tls.key"),
                        MPC_SOLANA_COORDINATOR_ROUTES={binding["keyset_id"]: route_config(net)},
                        MPC_SOLANA_ROOT_SIGNER_CERTIFICATES={binding["keyset_id"]: pins(net)},
                    ),
                ):

                    def bind_new(keyset):
                        bind_coordinator(keyset_id=keyset.keyset_id, operator_ref="integration")

                    keyset, _ = import_root(binding, before_import=bind_new)
                    root = register_root(
                        keyset_id=keyset.keyset_id, tenant_id=tenant.pk, operator_ref="integration"
                    )
                    claim = reserve_claim(
                        keyset_id=keyset.keyset_id,
                        tenant_id=tenant.pk,
                        principal_id=principal.pk,
                        asset_key="SOL",
                        idempotency_key="routed-claim",
                        operator_ref="integration",
                    )
                    claim = approve_claim(
                        reservation_id=claim.pk, tenant_id=tenant.pk, operator_ref="integration"
                    )
                    assert resolve_route(keyset.keyset_id).url != settings.MPC_COORDINATOR_URL
                    assert root.receipt_pins_reserved
                    original = copy.deepcopy(root.evidence)
                    net.stop("coordinator")
                    net.start("coordinator")
                    assert (
                        register_root(
                            keyset_id=keyset.keyset_id,
                            tenant_id=tenant.pk,
                            operator_ref="integration",
                        ).evidence
                        == original
                    )
                    with override_settings(MPC_SOLANA_COORDINATOR_ROUTES={}):
                        with pytest.raises(MpcBindingError):
                            resolve_route(keyset.keyset_id)
                    assert encrypted_files(net, binding) == shares
                    records.append((net, binding, root, claim, shares))
            assert records[0][2].base_address != records[1][2].base_address
            assert MpcKeyset.objects.filter(solana_coordinator_required=True).count() == 2
            assert LedgerTransaction.objects.count() == before
            for net, binding, _, __, shares in records:
                assert encrypted_files(net, binding) == shares
            private_file(
                root_path / "solana-coordinator-routing-public-evidence.json",
                json.dumps(
                    {
                        "scope": "two actual FROST cohorts; Root-bound public coordinator routing",
                        "binding_before_backend_metadata_import": True,
                        "global_default_points_to_other_cohort": True,
                        "original_root_and_claim_receipts_verified_after_actual_routed_calls": True,
                        "coordinator_restart_and_missing_route_config_failclosed": True,
                        "all_six_encrypted_shares_unchanged": True,
                        "ledger_changed": False,
                        "fund_migration_or_retirement_acceptance": False,
                    },
                    sort_keys=True,
                ).encode(),
            )
    finally:
        validator.close()


def run_routed_finances(root_path):
    def flow(g, path, tenant, records):
        # Generic application startup retains a valid legacy transport config;
        # actual requests must select the permanent route, not this dead origin.
        with override_settings(MPC_COORDINATOR_URL="https://localhost:1"):
            native_financial_flow(g, path, tenant, records, incoming="legacy")
        private_file(
            path / "solana-routed-financial-public-evidence.json",
            json.dumps(
                {
                    "scope": "actual Root-bound native deposit/sweep/withdrawal; existing ledger",
                    "wrong_global_origin_unused_for_private_create_execute": True,
                    "original_wire_finality_and_customer_liability_conserved": True,
                    "fund_migration_or_retirement_acceptance": False,
                },
                sort_keys=True,
            ).encode(),
        )

    run_financial_wallets(
        root_path / "native",
        after_wallets=flow,
        freeze_before_completion=False,
        before_keyset_import=bind_before_import,
    )
    run_financial_signing(
        root_path / "public-recovery",
        fault="route_config_loss",
        before_keyset_import=bind_before_import,
    )
