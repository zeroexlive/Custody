"""Two real FROST DKG cohorts and archival Root/Claim receipts, no fund migration.

Private shares stay in their owning encrypted stores. This verifies only the
receipt-trust prerequisite; it does not claim protected rotation or retirement.
"""

import copy
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from custody.identity_registry import register_principal, register_tenant
from custody.models import LedgerTransaction, MpcSolanaReceiptPins
from custody.mpc_binding import MpcBindingError
from custody.solana_provisioning import _verify, approve_claim, register_root, reserve_claim
from custody.solana_receipt_pins import import_root_receipt_pins
from django.test import override_settings
from environment import private_file
from ops.models import Chain, NodeEndpoint
from seeded_enrollment import services
from solana_local.validator import Validator
from test_dkg import PARTIES, dkg_request, encrypted_files, execute
from test_network import settings_for


def pins(net):
    return {p: str(net.root / p / "identity" / "tls.crt") for p in PARTIES}


def provision(net, tenant, principal, *, snapshot):
    from test_solana import import_root

    binding = dkg_request()
    code, response = execute(net, binding)
    assert code == 200 and response["status"] == "COMPLETED"
    shares = encrypted_files(net, binding)
    with settings_for(net):
        keyset, _ = import_root(binding)
        with override_settings(
            MPC_SOLANA_ROOT_SIGNER_CERTIFICATES=(
                {str(keyset.keyset_id): pins(net)} if snapshot else {}
            )
        ):
            arguments = dict(
                keyset_id=keyset.keyset_id, tenant_id=tenant.pk, operator_ref="integration"
            )
            root = register_root(**arguments)
            claim = reserve_claim(
                **arguments,
                principal_id=principal.pk,
                asset_key="SOL",
                idempotency_key="receipt-pin-claim",
            )
            claim = approve_claim(
                reservation_id=claim.pk, tenant_id=tenant.pk, operator_ref="integration"
            )
            if snapshot:
                row = MpcSolanaReceiptPins.objects.get(root=root)
                assert row.source == "RESERVATION" and root.receipt_pins_reserved
            else:
                assert not MpcSolanaReceiptPins.objects.filter(root=root).exists()
                row = import_root_receipt_pins(**arguments)
                assert row.source == "ARCHIVAL_IMPORT" and not root.receipt_pins_reserved
    assert encrypted_files(net, binding) == shares
    return binding, root, claim, shares


def run_receipt_pin_cohorts(root_path, *, pause_source=False):
    tenant = register_tenant(reference="actual-receipt-cohorts", operator_ref="integration")
    principal = register_principal(
        tenant_id=tenant.pk, customer_ref="receipt-cohort-owner", operator_ref="integration"
    )
    before_ledger = LedgerTransaction.objects.count()
    validator = Validator(root_path / "validator")
    try:
        Chain.objects.filter(chain_id="SOL").update(
            kind="solana", is_testnet=True, enabled=True, evm_chain_id=None
        )
        NodeEndpoint.objects.filter(chain_id="SOL", kind="rpc").update(enabled=False)
        NodeEndpoint.objects.create(
            chain_id="SOL", name="receipt-pin-cohorts", kind="rpc", url=validator.url, enabled=True
        )
        with (
            override_settings(
                MPC_SIGNER_BACKEND="self_hosted_mpc",
                MPC_SOLANA_INTEGRATION_ENABLED=True,
                MPC_SOLANA_NETWORK=validator.policy,
                MPC_INTEGRATION_ENVIRONMENT="development",
                CUSTODY_DEMO_MODE=False,
                CUSTODY_TX_MODE="live",
                CUSTODY_INDEXER_MODE="live",
            ),
            services(root_path / "cohort-A") as old,
            services(root_path / "cohort-B") as fresh,
        ):
            a_binding, a_root, a_claim, a_shares = provision(old, tenant, principal, snapshot=False)
            original = copy.deepcopy((a_root.evidence, a_claim.evidence))
            b_binding, b_root, b_claim, b_shares = provision(
                fresh, tenant, principal, snapshot=True
            )
            assert a_root.base_address != b_root.base_address
            assert set(
                a_binding[k] for k in ("session_id", "execution_id", "keyset_id")
            ).isdisjoint(b_binding[k] for k in ("session_id", "execution_id", "keyset_id"))
            old_pins = MpcSolanaReceiptPins.objects.get(root=a_root).certificates_der_hex
            new_pins = MpcSolanaReceiptPins.objects.get(root=b_root).certificates_der_hex
            for party in PARTIES:
                a_key = x509.load_der_x509_certificate(bytes.fromhex(old_pins[party])).public_key()
                b_key = x509.load_der_x509_certificate(bytes.fromhex(new_pins[party])).public_key()
                assert a_key.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                ) != b_key.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
                assert (old.root / party / "identity" / "wrapping.key").read_bytes() != (
                    fresh.root / party / "identity" / "wrapping.key"
                ).read_bytes()
            # The globally configured coordinator and receipt pins now refer to
            # B; cached A proof validation must use A's permanent public archive.
            with settings_for(fresh), override_settings(MPC_SOLANA_ROOT_SIGNER_CERTIFICATES={}):
                assert (
                    register_root(
                        keyset_id=a_root.keyset.keyset_id,
                        tenant_id=tenant.pk,
                        operator_ref="integration",
                    ).evidence
                    == a_root.evidence
                )
                assert (
                    approve_claim(
                        reservation_id=a_claim.pk, tenant_id=tenant.pk, operator_ref="integration"
                    ).evidence
                    == a_claim.evidence
                )
            with override_settings(
                MPC_HD_SIGNER_CERTIFICATES={}, MPC_SOLANA_ROOT_SIGNER_CERTIFICATES={}
            ):
                for kind, row in [
                    ("root", a_root),
                    ("claim", a_claim),
                    ("root", b_root),
                    ("claim", b_claim),
                ]:
                    _verify(kind, row.statement, row.evidence)
                for kind, a, b in [("root", a_root, b_root), ("claim", a_claim, b_claim)]:
                    with pytest.raises(MpcBindingError):
                        _verify(kind, a.statement, b.evidence)
            if pause_source:
                from allocation_pause_acceptance import check_source_pause

                with settings_for(fresh):
                    check_source_pause(tenant, principal, a_root, a_claim, b_root)
            a_root.refresh_from_db()
            a_claim.refresh_from_db()
            assert (a_root.evidence, a_claim.evidence) == original
            assert encrypted_files(old, a_binding) == a_shares
            assert encrypted_files(fresh, b_binding) == b_shares
            assert LedgerTransaction.objects.count() == before_ledger
            private_file(
                root_path / "solana-receipt-pin-cohorts-public-evidence.json",
                json.dumps(
                    {
                        "scope": "two actual FROST DKG cohorts; archival Root/Claim receipt pins",
                        "distinct_group_keys_and_dkg_ids": True,
                        "independent_tls_wrapping_keys_and_stores": True,
                        "actual_legacy_root_and_claim_verified_before_explicit_import": True,
                        "fresh_cohort_pins_committed_before_enrollment": True,
                        "both_archives_verify_without_installed_pin_paths_or_global_map": True,
                        "cross_root_receipts_rejected": True,
                        "original_root_and_claim_receipts_unchanged": True,
                        "all_six_original_encrypted_shares_unchanged": True,
                        "ledger_changed": False,
                        "local_allocation_pause_checked": pause_source,
                        "protected_rotation_or_fund_migration_acceptance": False,
                        "production_activation": False,
                    },
                    sort_keys=True,
                ).encode(),
            )
    finally:
        validator.close()
