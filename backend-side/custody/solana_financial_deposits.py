"""Seeded-native finalized provenance and the existing deposit journal.

The indexer selects this default-disabled controller from the stored seeded
wallet identity. Generic credit remains fenced. No caller-supplied amount,
confirmations or evidence can authorize a credit.
"""

import copy
import os
from decimal import Decimal

import base58
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from solders.pubkey import Pubkey

from .chain_registry import rpc_urls
from .config import validate_chain_asset
from .identity_registry import _standalone, _text, _uuid
from .indexer.base import BalanceResult, IndexerUnavailable
from .ledger import clearing_account, financial_precision, lock_user_accounts, post_transaction
from .models import (
    AdminActionLog,
    Asset,
    Deposit,
    HotWallet,
    MpcKeyset,
    MpcSolanaClaim,
    MpcSolanaFinancialWallet,
    MpcSolanaRoot,
    OnchainTransactionAttempt,
    UserWallet,
)
from .mpc_binding import MpcBindingError
from .mpc_solana_network import guarded_solana_rpc, network_identity
from .native_tx import RequestsTransport
from .solana_deposits import transfer_events
from .solana_financial_deposit_observation import observe_deposit_transaction
from .solana_financial_wallet import validate_financial_wallet
from .solana_issuance import _locked_claim
from .solana_policy import account_data
from .solana_provisioning import _audit, _runtime
from .solana_wire import SYSTEM_PROGRAM, uint


def register_operator_funding_source(*, address, reference, operator_ref):
    """Privileged immutable source classification; no automatic historical rewrite."""
    from .models import MpcSolanaDepositProvenance, MpcSolanaOperatorFundingSource

    _standalone()
    _runtime()
    reference, operator_ref = (
        _text(reference, "funding reference"),
        _text(operator_ref, "operator audit reference"),
    )
    if str(Pubkey.from_string(address)) != address or address == SYSTEM_PROGRAM:
        raise MpcBindingError("canonical operator funding address required")
    genesis = network_identity("SOL")["genesis_hash"]
    with transaction.atomic():
        Asset.objects.select_for_update().get(asset_key="SOL", chain_id="SOL", is_native=True)
        existing = MpcSolanaOperatorFundingSource.objects.filter(
            genesis_hash=genesis, address=address
        ).first()
        if existing:
            if existing.reference != reference:
                raise MpcBindingError("original funding classification is immutable")
            return existing
        if MpcSolanaDepositProvenance.objects.filter(
            genesis_hash=genesis, source_address=address
        ).exists():
            raise MpcBindingError(
                "already attributed external source needs explicit reconciliation"
            )
        row = MpcSolanaOperatorFundingSource.objects.create(
            genesis_hash=genesis, address=address, reference=reference
        )
        AdminActionLog.objects.create(
            actor_id=operator_ref,
            action_type="SOL_OPERATOR_FUNDING_REGISTER",
            entity_type="solana_operator_funding_source",
            entity_id=str(row.pk),
            metadata={
                "authority": "privileged_operator",
                "genesis_hash": genesis,
                "address": address,
                "reference": reference,
            },
        )
        return row


def _wallet(user_wallet_id, tenant_id):
    from .models import MpcSolanaOperatorFundingSource

    if (
        settings.CUSTODY_INDEXER_MODE != "live"
        or os.environ.get("CUSTODY_INDEXER_MODE", "live") != "live"
    ):
        raise IndexerUnavailable("seeded financial deposits require live finalized indexing")
    if settings.MPC_SOLANA_SEEDED_DEPOSITS_ENABLED is not True:
        raise MpcBindingError("seeded deposit financial activation is disabled")
    if not MpcSolanaOperatorFundingSource.objects.filter(
        genesis_hash=network_identity("SOL")["genesis_hash"]
    ).exists():
        raise MpcBindingError("explicit operator funding-source classification required")
    row = MpcSolanaFinancialWallet.objects.get(
        user_wallet_id=user_wallet_id, claim__root__tenant_id=tenant_id
    )
    row = validate_financial_wallet(row)
    if row.role != "CUSTOMER_DEPOSIT" or row.claim.asset.asset_key != "SOL":
        raise MpcBindingError("original native customer financial membership required")
    wallet = UserWallet.objects.get(pk=row.user_wallet_id)
    if wallet.status != "ACTIVE":
        raise MpcBindingError("customer deposit wallet unavailable")
    validate_chain_asset("SOL", "SOL", "deposit")
    return row, wallet


def _internal_sources():
    from .models import MpcSolanaOperatorFundingSource

    addresses = set(HotWallet.objects.filter(chain_id="SOL").values_list("address", flat=True))
    addresses.update(
        UserWallet.objects.filter(chain_id="SOL").values_list("deposit_address", flat=True)
    )
    addresses.update(MpcSolanaRoot.objects.values_list("base_address", flat=True))
    # Includes PENDING/unpublished and every historical Claim, not only wallets.
    addresses.update(MpcSolanaClaim.objects.values_list("address", flat=True))
    addresses.update(
        MpcSolanaOperatorFundingSource.objects.filter(
            genesis_hash=network_identity("SOL")["genesis_hash"]
        ).values_list("address", flat=True)
    )
    for key in MpcKeyset.objects.filter(
        algorithm="FROST_ED25519", public_key__regex=r"^[0-9a-f]{64}$"
    ).values_list("public_key", flat=True):
        addresses.add(base58.b58encode(bytes.fromhex(key)).decode())
    return addresses


def _observe(row, wallet, signature, transport):
    tx, meta, evidence, digest = observe_deposit_transaction(signature, transport=transport)
    if evidence["network"] != row.claim.root.network_identity:
        raise MpcBindingError("deposit observation differs from original genesis/network")
    events = transfer_events(
        tx,
        meta,
        evidence["slot"],
        signature,
        wallet,
        row.claim.asset,
        internal_addresses=_internal_sources(),
        allow_runtime_cpi=True,
    )
    for event in events:
        event.block_hash = evidence["block_hash"]
    return evidence, [(event, evidence, digest) for event in events]


def _locked_wallet(row, tenant_id):
    _locked_claim(row.claim_id, tenant_id)
    current, wallet = _wallet(row.user_wallet_id, tenant_id)
    wallet = UserWallet.objects.select_for_update().get(pk=wallet.pk)
    return current, wallet


def _ingest_observed(row, wallet, observations, operator_ref):
    from .models import MpcSolanaDepositProvenance

    current, _ = _wallet(wallet.pk, row.claim.root.tenant_id)
    if current.pk != row.pk:
        raise MpcBindingError("original financial deposit membership changed")
    internal = _internal_sources()
    results = []
    for event, evidence, digest in observations:
        signature = evidence["signature"]
        if (
            event.source_address in internal
            or OnchainTransactionAttempt.objects.filter(
                chain_id="SOL", network_tx_id=signature
            ).exists()
        ):
            continue
        if event.asset_key != "SOL" or event.block != evidence["slot"] or not event.source_address:
            raise MpcBindingError("original native instruction provenance required")
        genesis = evidence["network"]["genesis_hash"]
        previous = MpcSolanaDepositProvenance.objects.filter(
            genesis_hash=genesis, signature=signature, event_index=event.event_index
        ).first()
        if previous:
            deposit = Deposit.objects.select_for_update().get(pk=previous.deposit_id)
            if (
                deposit.user_wallet_id != wallet.pk
                or previous.observation_sha256 != digest
                or deposit.amount != event.amount
                or previous.source_address != event.source_address
            ):
                raise MpcBindingError("original deposit attribution/provenance changed")
            results.append((deposit, False))
            continue
        if Deposit.objects.filter(
            user_wallet=wallet, tx_hash=signature, event_index=event.event_index
        ).exists():
            raise MpcBindingError("existing deposit without original provenance cannot be adopted")
        deposit = Deposit.objects.create(
            user_wallet=wallet,
            asset_key="SOL",
            tx_hash=signature,
            event_index=event.event_index,
            amount=event.amount,
            block=evidence["slot"],
            block_hash=evidence["block_hash"],
            confirmations=event.confirmations,
            status="PENDING",
            chain_evidence={"kind": "SOLANA_SEEDED_NATIVE_V1", "observation_sha256": digest},
        )
        MpcSolanaDepositProvenance.objects.create(
            deposit=deposit,
            genesis_hash=genesis,
            signature=signature,
            event_index=event.event_index,
            source_address=event.source_address,
            slot=evidence["slot"],
            block_hash=evidence["block_hash"],
            observation_sha256=digest,
            evidence=evidence,
        )
        accounts = lock_user_accounts(wallet.user_id, "SOL")
        post_transaction(
            event_key=f"deposit:{deposit.pk}:credit",
            event_type="DEPOSIT_CREDIT",
            asset_key="SOL",
            ref_type="Deposit",
            ref_id=deposit.pk,
            postings=[
                (accounts["AVAILABLE"], deposit.amount),
                (clearing_account("SOL"), -deposit.amount),
            ],
        )
        deposit.status = "CONFIRMED"
        deposit.save(update_fields=["status"])
        _audit("SOL_FIN_DEPOSIT_CREDIT", deposit, operator_ref)
        results.append((deposit, True))
    return results


@financial_precision()
def ingest_financial_event(*, user_wallet_id, tenant_id, event, operator_ref, transport=None):
    """Re-fetch original chain truth; the event is an untrusted lookup hint only."""
    _standalone()
    _runtime()
    tenant_id, operator_ref = _uuid(tenant_id), _text(operator_ref, "operator audit reference")
    row, wallet = _wallet(user_wallet_id, tenant_id)
    _, observations = _observe(row, wallet, event.tx_hash, transport or RequestsTransport())
    matching = [
        (actual, proof, digest)
        for actual, proof, digest in observations
        if actual.event_index == event.event_index
    ]
    if len(matching) != 1:
        raise MpcBindingError("event is not one attributable external native instruction")
    actual = matching[0][0]
    if (
        event.asset_key != "SOL"
        or event.amount != actual.amount
        or event.block != actual.block
        or event.block_hash != matching[0][1]["block_hash"]
    ):
        raise MpcBindingError("event hint differs from original observed instruction")
    with transaction.atomic():
        row, wallet = _locked_wallet(row, tenant_id)
        result = _ingest_observed(row, wallet, matching, operator_ref)
        if len(result) != 1:
            raise MpcBindingError("source became internal; no customer credit")
        return result[0]


@financial_precision()
def scan_financial_wallet(*, user_wallet_id, tenant_id, operator_ref, transport=None):
    """Bounded history backfill, attribution, journal and cursor commit together."""
    _standalone()
    _runtime()
    if (
        settings.CUSTODY_INDEXER_MODE != "live"
        or os.environ.get("CUSTODY_INDEXER_MODE", "live") != "live"
    ):
        raise IndexerUnavailable("seeded financial deposits require live finalized indexing")
    tenant_id, operator_ref = _uuid(tenant_id), _text(operator_ref, "operator audit reference")
    row, wallet = _wallet(user_wallet_id, tenant_id)
    original_cursor = copy.deepcopy(wallet.solana_scan_cursor)
    transport = transport or RequestsTransport()
    errors = []
    observed = None
    for endpoint in rpc_urls("SOL"):
        try:

            def rpc(method, params):
                return guarded_solana_rpc("SOL", endpoint, transport, method, params)

            boundary = original_cursor.get("boundary", int(wallet.last_scanned_block or 0))
            if uint(rpc("getFirstAvailableBlock", [])) > max(1, boundary):
                raise MpcBindingError("original deposit history pruned; no cursor advance")
            head = original_cursor.get("head_slot") or uint(
                rpc("getSlot", [{"commitment": "finalized"}])
            )
            account = rpc(
                "getAccountInfo",
                [wallet.deposit_address, {"encoding": "base64", "commitment": "finalized"}],
            )["value"]
            if account is None:
                units = 0
            else:
                account_data(account, SYSTEM_PROGRAM, 0)
                units = uint(account["lamports"])
            before, previous_slot = (
                original_cursor.get("before"),
                original_cursor.get("before_slot"),
            )
            records, seen, complete = [], set(), False
            for _ in range(4):
                options = {"commitment": "finalized", "limit": 100}
                if before:
                    options["before"] = before
                page = rpc("getSignaturesForAddress", [wallet.deposit_address, options])
                if not isinstance(page, list) or len(page) > 100:
                    raise MpcBindingError("invalid signature page")
                for summary in page:
                    signature, slot = summary["signature"], uint(summary["slot"], positive=True)
                    if previous_slot is not None and slot > previous_slot:
                        raise MpcBindingError("unordered history")
                    if signature in seen or signature == before:
                        raise MpcBindingError("signature cursor made no progress")
                    seen.add(signature)
                    previous_slot = slot
                    if slot < boundary:
                        complete = True
                        continue
                    if slot > head:
                        continue
                    proof, events = _observe(row, wallet, signature, transport)
                    if (
                        proof["slot"] != slot
                        or summary.get("err") != proof["transaction"]["meta"]["err"]
                    ):
                        raise MpcBindingError("signature page conflicts with finalized transaction")
                    records.extend(events)
                if not page or len(page) < 100 or complete:
                    complete = True
                    break
                before = page[-1]["signature"]
            cursor = (
                {}
                if complete
                else {
                    "boundary": boundary,
                    "head_slot": head,
                    "before": before,
                    "before_slot": previous_slot,
                }
            )
            observed = (units, head, complete, cursor, records)
            break
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            raise IndexerUnavailable("conflicting/malformed finalized deposit history") from exc
        except Exception as exc:
            errors.append(type(exc).__name__)
    if observed is None:
        raise IndexerUnavailable(
            "finalized deposit history unavailable; cursor unchanged: " + ",".join(errors)
        )
    units, head, complete, cursor, records = observed
    with transaction.atomic():
        row, current = _locked_wallet(row, tenant_id)
        if (
            current.solana_scan_cursor != original_cursor
            or current.last_scanned_block != wallet.last_scanned_block
        ):
            raise IndexerUnavailable("concurrent scan advanced the original cursor; retry")
        _ingest_observed(row, current, records, operator_ref)
        current.solana_scan_cursor = cursor
        current.last_scanned_at = timezone.now()
        if complete:
            current.last_scanned_block = head
        current.save(update_fields=["solana_scan_cursor", "last_scanned_at", "last_scanned_block"])
        _audit("SOL_FIN_DEPOSIT_SCAN", current, operator_ref)
    result = BalanceResult(
        Decimal(units) / Decimal(10**9), last_scanned_block=head if complete else None
    )
    result.scan_complete, result.scan_cursor = complete, cursor
    return result
