"""Default-off classic seeded SPL provisioning and independent account quotes.

Initialization uses the existing protected financial session/ownership tables.
It creates no USER balance. Account existence alone cannot authorize publication.
"""

import base64
import copy
from decimal import Decimal

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction

from .chain_registry import get_chain_spec, rpc_urls
from .identity_registry import _standalone, _text, _uuid
from .models import (
    MpcSolanaFinancialEffect,
    MpcSolanaFinancialOperation,
    MpcSolanaFinancialSession,
    MpcSolanaFinancialWallet,
    MpcSolanaTokenProvision,
    MpcSolanaTokenPublication,
    UserWallet,
)
from .mpc_binding import MpcBindingError
from .mpc_solana_network import guarded_solana_rpc, network_identity, require_fresh
from .native_tx import PreparedNativeTransaction, _cap
from .solana_issuance import _locked_claim
from .solana_policy import account_data, validate_mint, validate_token_account
from .solana_provisioning import _audit, _runtime
from .solana_seeded import (
    build_token_creation,
    build_token_seeded_transfer,
    build_token_transfer,
)
from .solana_wire import SYSTEM_PROGRAM, uint
from .spl import derive_ata


def require_spl_enabled():
    if settings.MPC_SOLANA_SEEDED_SPL_ENABLED is not True:
        raise MpcBindingError("seeded classic SPL workflow is disabled")


def rent_budget(value):
    cap = _cap(get_chain_spec("SOL").gas_settings, "max_ata_rent_lamports")
    if type(value) is not int or not 0 < value <= min(cap, 2**63 - 1):
        raise MpcBindingError("explicit classic-account rent budget within installed cap required")
    return value


def validate_pending_source(row):
    from .solana_financial_wallet import _membership

    require_spl_enabled()
    row = MpcSolanaFinancialWallet.objects.select_related(
        "claim__root__keyset", "claim__principal", "claim__asset", "mode__root", "issuance"
    ).get(pk=row.pk)
    mode, role = _membership(row.claim)
    if (
        row.status != "PENDING"
        or row.claim.asset.is_native
        or row.claim.root.statement["wallet_class"] != "HOT"
        or row.mode_id != mode.pk
        or row.role != role
        or row.user_wallet_id is not None
        or row.evidence != {}
        or row.issuance.status != "PENDING"
        or row.issuance.claim_id != row.claim_id
        or row.issuance.evidence != {}
        or (row.issuance.witness_anchor_id, row.issuance.witness_key_id)
        != (mode.witness_anchor_id, mode.witness_key_id)
        or UserWallet.objects.filter(solana_claim_id=row.claim_id).exists()
        or MpcSolanaTokenPublication.objects.filter(claim_id=row.claim_id).exists()
    ):
        raise MpcBindingError("exact original pending classic Claim/mode/role/issuer required")
    return row


def allocate_provision(
    *,
    reservation_id,
    tenant_id,
    idempotency_key,
    fee_budget_lamports,
    rent_budget_lamports,
    operator_ref,
):
    from .solana_financial_sessions import _budget

    _standalone()
    _runtime()
    require_spl_enabled()
    reservation_id, tenant_id = _uuid(reservation_id), _uuid(tenant_id)
    key, operator_ref = (
        _text(idempotency_key, "initializer retry key"),
        _text(operator_ref, "operator audit reference"),
    )
    fee, rent = _budget(fee_budget_lamports), rent_budget(rent_budget_lamports)
    with transaction.atomic():
        claim = _locked_claim(reservation_id, tenant_id)
        existing = MpcSolanaTokenProvision.objects.filter(claim=claim, idempotency_key=key).first()
        if existing:
            operation = MpcSolanaFinancialOperation.objects.get(provision=existing)
            if (
                operation.source_id,
                operation.fee_budget_lamports,
                operation.rent_budget_lamports,
            ) != (claim.pk, fee, rent):
                raise MpcBindingError("original initializer business/source/budgets are immutable")
            return operation
        source = validate_pending_source(MpcSolanaFinancialWallet.objects.get(pk=claim.pk))
        if MpcSolanaTokenProvision.objects.filter(claim=claim).exclude(status="FAILED").exists():
            raise MpcBindingError("original unresolved/successful initializer must be preserved")
        from .solana_allocation_pause import require_allocation_open

        require_allocation_open(claim.root_id)
        parent = MpcSolanaTokenProvision.objects.create(claim=claim, idempotency_key=key)
        operation = MpcSolanaFinancialOperation.objects.create(
            provision=parent,
            principal=claim.principal,
            source=source,
            amount=Decimal(0),
            base_unit_amount=0,
            destination_address=claim.address,
            fee_budget_lamports=fee,
            rent_budget_lamports=rent,
        )
        _audit("SOL_TOKEN_PROVISION_RESERVE", parent, operator_ref)
        return operation


def accepted_initialization(claim_id):
    """Reload the one original successful initializer and its permanent owned effect."""
    try:
        parent = MpcSolanaTokenProvision.objects.get(claim_id=claim_id, status="CONFIRMED")
        operation = MpcSolanaFinancialOperation.objects.get(provision=parent, status="SETTLED")
        session = MpcSolanaFinancialSession.objects.select_related(
            "operation__source__claim__root__keyset", "operation__source__claim__asset", "attempt"
        ).get(operation=operation, status="COMPLETED")
        effect = MpcSolanaFinancialEffect.objects.get(attempt=session.attempt, outcome="CONFIRMED")
    except ObjectDoesNotExist:
        raise MpcBindingError("original successful owned classic initialization required") from None
    from .solana_financial_finality import signed_identity

    _, signature = signed_identity(session)
    if (
        parent.tx_hash != signature
        or session.attempt.status != "CONFIRMED"
        or session.intent["action"]["kind"] != "CreateClassicToken"
        or session.intent["operation_type"] != "PROVISION"
        or session.operation.source_id != claim_id
        or effect.evidence["signature"] != signature
        or effect.evidence["effect"] != "classic_seeded_initialization"
        or effect.evidence["amount"] != "0"
    ):
        raise MpcBindingError("original successful owned classic initialization required")
    return session, effect


def publication_action(row):
    if not MpcSolanaTokenProvision.objects.filter(
        claim_id=row.claim_id, status="CONFIRMED"
    ).exists():
        return None
    session, _ = accepted_initialization(row.claim_id)
    return {
        "kind": "IssueClassicClaim",
        "reservation_id": str(row.claim_id),
        "issuance_id": str(row.issuance_id),
        "initialization_execution_id": str(session.crypto_execution_id),
    }


def observe_publication_account(claim, transport):
    """Current exact account evidence is separate from the original zero-token init."""
    from .solana_financial_preparation import _effect_slot

    require_spl_enabled()
    session, effect = accepted_initialization(claim.pk)
    floor = max(effect.slot, _effect_slot(claim.root_id))
    network = network_identity("SOL")
    errors = []
    for endpoint in rpc_urls("SOL"):
        try:

            def rpc(method, params):
                return guarded_solana_rpc("SOL", endpoint, transport, method, params)

            head = max(floor, uint(rpc("getSlot", [{"commitment": "finalized"}])))
            response = rpc(
                "getAccountInfo",
                [
                    claim.address,
                    {
                        "encoding": "base64",
                        "commitment": "finalized",
                        "minContextSlot": head,
                    },
                ],
            )
            slot = uint(response["context"]["slot"], positive=True)
            if slot < head:
                raise MpcBindingError("classic publication account predates finalized effect/head")
            account = response["value"]
            validate_token_account(
                account, claim.root.base_address, claim.asset.contract_address, claim.asset.decimals
            )
            rent = uint(rpc("getMinimumBalanceForRentExemption", [165]), positive=True)
            if uint(account["lamports"]) < rent:
                raise MpcBindingError("classic publication account is below current rent minimum")
            mint = rpc(
                "getAccountInfo",
                [
                    claim.asset.contract_address,
                    {
                        "encoding": "base64",
                        "commitment": "finalized",
                        "minContextSlot": head,
                    },
                ],
            )
            if uint(mint["context"]["slot"]) < head:
                raise MpcBindingError("publication mint observation predates finalized head")
            validate_mint(mint["value"], claim.asset.decimals)
            proof = copy.deepcopy(
                {
                    "version": 1,
                    "network": network,
                    "address": claim.address,
                    "mint": claim.asset.contract_address,
                    "authority": claim.root.base_address,
                    "context_slot": slot,
                    "observed_head": head,
                    "account": account,
                    "minimum_rent_lamports": str(rent),
                }
            )
            return session, effect, proof
        except (ValueError, TypeError, KeyError, IndexError):
            raise MpcBindingError(
                "conflicting/malformed classic publication account evidence"
            ) from None
        except Exception as exc:
            errors.append(type(exc).__name__)
    raise MpcBindingError("classic publication account evidence unavailable: " + ",".join(errors))


def token_quote(row, transport, *, fixed=False):
    """No transaction spans RPC; caller rechecks all holds/effect floors under locks."""
    from .solana_financial_preparation import _effect_slot, _holds

    require_spl_enabled()
    operation, claim = row.operation, row.operation.source.claim
    asset, base_address = claim.asset, claim.root.base_address
    spec, network = get_chain_spec("SOL"), network_identity("SOL")
    fingerprint, floor = _holds(claim.root_id), _effect_slot(claim.root_id)
    contexts = {}
    endpoint = rpc_urls("SOL")[0]

    def rpc(method, params):
        return guarded_solana_rpc("SOL", endpoint, transport, method, params)

    def account(address):
        result = rpc(
            "getAccountInfo",
            [
                address,
                {
                    "encoding": "base64",
                    "commitment": "finalized",
                    "minContextSlot": floor,
                },
            ],
        )
        contexts[address] = uint(result["context"]["slot"])
        if contexts[address] < floor:
            raise MpcBindingError("token RPC account observation predates accepted effect")
        return result["value"]

    base = account(base_address)
    account_data(base, SYSTEM_PROGRAM, 0)
    validate_mint(account(asset.contract_address), asset.decimals)
    source = account(claim.address)
    system_rent = uint(rpc("getMinimumBalanceForRentExemption", [0]))
    token_rent = uint(rpc("getMinimumBalanceForRentExemption", [165]), positive=True)
    source_units, source_lamports, rent = 0, 0, 0
    if operation.provision_id:
        if source is not None:
            raise MpcBindingError(
                "existing/prefunded token address requires governed recovery; "
                "account adoption is forbidden"
            )
        rent = token_rent
        action = {"kind": "CreateClassicToken", "rent_lamports": rent}
        destination = claim.address
    else:
        source_units = validate_token_account(
            source, base_address, asset.contract_address, asset.decimals
        )
        source_lamports = uint(source["lamports"])
        if source_lamports < token_rent:
            raise MpcBindingError("original token source is below current rent minimum")
        if operation.sweep_id:
            target_claim = operation.treasury_destination.claim
            destination = target_claim.address
            target = account(destination)
            validate_token_account(
                target, target_claim.root.base_address, asset.contract_address, asset.decimals
            )
            if uint(target["lamports"]) < token_rent:
                raise MpcBindingError("original treasury token account is below rent minimum")
            action = {
                "kind": "ClassicSeededTransfer",
                "destination_base": target_claim.root.base_address,
                "destination_index": target_claim.index,
                "amount": int(operation.base_unit_amount),
            }
        else:
            destination = derive_ata(operation.destination_address, asset.contract_address)
            target = account(destination)
            if target is not None:
                validate_token_account(
                    target, operation.destination_address, asset.contract_address, asset.decimals
                )
                if uint(target["lamports"]) < token_rent:
                    raise MpcBindingError("external token account is below rent minimum")
            # Always authorize/reserve the full current creation maximum. An
            # existing ATA can close before execution. Its current presence is
            # not permission to reserve/authorize zero potential rent.
            rent = token_rent
            action = {
                "kind": "ClassicTransfer",
                "destination_owner": operation.destination_address,
                "amount": int(operation.base_unit_amount),
                "create_ata": True,
            }
    if rent > min(operation.rent_budget_lamports, _cap(spec.gas_settings, "max_ata_rent_lamports")):
        raise MpcBindingError("classic account creation maximum exceeds original rent budget")
    if fixed and (action != row.intent["action"] or rent != row.intent["expected_rent_lamports"]):
        raise MpcBindingError("original token action/current rent differs; retain original hold")
    block = rpc("getLatestBlockhash", [{"commitment": "finalized", "minContextSlot": floor}])
    context = uint(block["context"]["slot"])
    if context < floor:
        raise MpcBindingError("token blockhash observation predates accepted effect")
    value = (
        block["value"]
        if not fixed
        else {
            "blockhash": row.intent["recent_blockhash"],
            "lastValidBlockHeight": row.intent["last_valid_block_height"],
        }
    )
    height = uint(value["lastValidBlockHeight"], positive=True)
    require_fresh("SOL", height, transport, blockhash=value["blockhash"])
    if operation.provision_id:
        payload = build_token_creation(
            base_address, claim.index, asset.contract_address, rent, value["blockhash"]
        )
    elif operation.sweep_id:
        payload = build_token_seeded_transfer(
            base_address,
            claim.index,
            asset.contract_address,
            action["destination_base"],
            action["destination_index"],
            action["amount"],
            asset.decimals,
            value["blockhash"],
        )
    else:
        payload = build_token_transfer(
            base_address,
            claim.index,
            asset.contract_address,
            operation.destination_address,
            int(operation.base_unit_amount),
            asset.decimals,
            value["blockhash"],
            create_ata=True,
        )
    if fixed and payload != bytes(row.payload):
        raise MpcBindingError("fixed original token wire differs from original business")
    encoded = base64.b64encode(payload).decode()
    fee = uint(
        rpc("getFeeForMessage", [encoded, {"commitment": "finalized"}])["value"], positive=True
    )
    if fee > min(operation.fee_budget_lamports, _cap(spec.gas_settings, "max_fee_lamports")):
        raise MpcBindingError("exact token message fee exceeds original policy/budget")
    unsigned = {
        "message": encoded,
        "recentBlockhash": value["blockhash"],
        "lastValidBlockHeight": height,
        "blockhashContextSlot": context,
        "network": network,
        "from": claim.address,
        "to": operation.destination_address,
        "feePayer": base_address,
        "seeded_action": action,
        "destinationTokenAccount": destination,
    }
    fees = {
        "observed_hold_fingerprint": fingerprint,
        "observed_effect_slot": floor,
        "account_context_slots": contexts,
        "live_blockhash_context_slot": context,
        "fee_lamports": str(fee),
        "ata_rent_lamports": str(rent),
        "source_rent_minimum_lamports": "0",
        "base_rent_minimum_lamports": str(system_rent),
        "native_reserve_lamports": str(uint(spec.gas_settings.get("native_reserve_lamports", "0"))),
        "policy": dict(spec.gas_settings),
        "network": network,
        "source_balance_lamports": str(source_lamports),
        "source_balance_units": str(source_units),
        "base_balance_lamports": str(uint(base["lamports"])),
        "source_is_token": True,
    }
    return PreparedNativeTransaction(
        "SOL",
        asset.asset_key,
        claim.address,
        operation.destination_address,
        operation.amount,
        int(operation.base_unit_amount),
        payload,
        row.attempt.prepared_metadata if fixed else unsigned,
        fees,
        last_valid_block=height,
    )
