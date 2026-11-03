"""Native exact-wire preparation and independent Policy approval, no private RPC.

RPC observations come from the existing independently pinned trusted boundary;
they are not chain proofs. Allocation precedes every query/RPC. Only immutable
prepared bytes/approvals are exported; this module performs no private dispatch,
broadcast or ledger settlement.
"""

import base64
import copy
import hashlib
import re
from datetime import datetime
from datetime import timezone as datetime_timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Sum
from django.utils import timezone

from .chain_registry import get_chain_spec, rpc_urls
from .config import validate_chain_asset
from .identity_registry import _standalone, _text, _uuid
from .ledger import _require_withdrawal_reservation, lock_user_accounts
from .models import (
    AdminActionLog,
    LedgerTransaction,
    MpcSolanaFinancialEffect,
    MpcSolanaFinancialOperation,
    MpcSolanaFinancialQuery,
    MpcSolanaFinancialSession,
    MpcSolanaMessageOwner,
    MpcSolanaTokenProvision,
    SweepJob,
    WithdrawalRequest,
)
from .mpc_binding import MpcBindingError
from .mpc_request_auth import _authorize_message
from .mpc_solana_network import guarded_solana_rpc, network_identity, require_fresh
from .native_tx import InsufficientBalance, PreparedNativeTransaction, RequestsTransport, _cap
from .solana_financial_sessions import _external_destination, _locked_operation, operation_identity
from .solana_financial_wallet import validate_financial_wallet
from .solana_issuance import _canonical, _locked_claim, _pin
from .solana_policy import account_data
from .solana_provisioning import _audit, _claim_evidence, _runtime
from .solana_seeded import build_native_transfer, validate_native_transfer
from .solana_wire import SYSTEM_PROGRAM, uint
from .solana_witness_client import _point_id, _require_role, _verify


def _policy():
    version = settings.MPC_SOLANA_FINANCIAL_POLICY_VERSION
    lifetime = settings.MPC_SOLANA_FINANCIAL_MAX_LIFETIME_SECONDS
    if (
        type(version) is not int
        or not 0 < version < 2**64
        or type(lifetime) is not int
        or not 1 <= lifetime <= 300
    ):
        raise MpcBindingError("explicit installed Policy version and bounded lifetime required")
    try:
        cert = x509.load_pem_x509_certificate(
            Path(settings.MPC_SOLANA_FINANCIAL_POLICY_CERTIFICATE).read_bytes()
        )
        _require_role(cert, "policy-hot")
        _point_id(cert.public_key())
        now = datetime.now(datetime_timezone.utc)
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise ValueError
        custody = x509.load_pem_x509_certificate(Path(settings.MPC_CLIENT_CERT).read_bytes())
        _require_role(custody, "custody")
        if not custody.not_valid_before_utc <= now < custody.not_valid_after_utc or _point_id(
            cert.public_key()
        ) == _point_id(custody.public_key()):
            raise ValueError
    except (OSError, ValueError, x509.ExtensionNotFound):
        raise MpcBindingError(
            "current independent Policy and Custody public leaves required"
        ) from None
    return version, lifetime, cert


def _snapshot(session_id, tenant_id):
    return MpcSolanaFinancialSession.objects.select_related(
        "operation__source__claim__root__keyset",
        "operation__source__claim__asset",
        "operation__source__claim__principal",
        "operation__source__mode",
        "operation__source__issuance",
        "operation__principal",
        "attempt",
    ).get(pk=session_id, operation__principal__tenant_id=tenant_id)


def _locked(snapshot, tenant_id):
    _locked_claim(snapshot.operation.source_id, tenant_id)
    operation = snapshot.operation
    model, pk = (
        (WithdrawalRequest, operation.withdrawal_id)
        if operation.withdrawal_id
        else (SweepJob, operation.sweep_id)
        if operation.sweep_id
        else (MpcSolanaTokenProvision, operation.provision_id)
    )
    parent = model.objects.select_for_update().get(pk=pk)
    operation = _locked_operation(operation.pk, tenant_id)
    row = MpcSolanaFinancialSession.objects.select_for_update().get(
        pk=snapshot.pk, operation=operation
    )
    row.operation = operation
    return row, parent


def _business(operation, parent):
    if operation.provision_id:
        from .solana_token_provisioning import validate_pending_source

        wallet = validate_pending_source(operation.source)
        if (
            operation.status != "HELD"
            or parent.status != "CREATED"
            or parent.claim_id != wallet.claim_id
            or operation.amount != 0
            or operation.base_unit_amount != 0
        ):
            raise MpcBindingError("original held zero-principal token initializer required")
        return wallet
    wallet = validate_financial_wallet(operation.source)
    if operation.status != "HELD" or wallet.claim.root.keyset.status != "ACTIVE":
        raise MpcBindingError("held reservation and active original source required")
    validate_chain_asset("SOL", wallet.claim.asset.asset_key, "withdrawal")
    if operation.withdrawal_id:
        _external_destination(operation.destination_address)
        approval = (
            AdminActionLog.objects.filter(
                action_type="WITHDRAWAL_APPROVE",
                entity_type="WithdrawalRequest",
                entity_id=str(parent.pk),
            )
            .order_by("-id")
            .first()
        )
        if (
            parent.status not in {"APPROVED", "PROCESSING"}
            or not approval
            or approval.metadata != {"to": parent.to_address, "amount": str(parent.amount)}
        ):
            raise MpcBindingError("original manual withdrawal approval required")
        _require_withdrawal_reservation(
            parent, lock_user_accounts(parent.user_id, parent.asset_key)
        )
        if LedgerTransaction.objects.filter(
            event_key__in=[f"withdrawal:{parent.pk}:release", f"withdrawal:{parent.pk}:settle"]
        ).exists():
            raise MpcBindingError("original reserve no longer spendable")
    else:
        destination = validate_financial_wallet(operation.treasury_destination)
        if (
            parent.status != "CREATED"
            or destination.role != "TENANT_TREASURY"
            or destination.claim.root.tenant_id != wallet.claim.root.tenant_id
            or destination.claim.asset_id != wallet.claim.asset_id
            or destination.claim.address != operation.destination_address
        ):
            raise MpcBindingError("original customer sweep and explicit tenant treasury required")
    return wallet


def _fresh_witness(row, lease, evidence):
    value = _verify("WITNESS_QUERY_REPLY_V1", evidence)
    anchor, key_id, _ = _pin()
    source = row.operation.source
    root = value.get("root", {})
    expected_mode = {
        "version": 1,
        "activation_id": str(source.mode.activation_id),
        "command_id": str(source.mode.command_id),
    }
    if (
        lease.purpose != "ADMISSION"
        or value.get("query") != lease.query
        or (anchor, key_id) != (lease.witness_anchor_id, lease.witness_key_id)
        or root.get("original") != source.claim.root.statement
        or root.get("phase") != "Active"
        or root.get("prepared") is not None
        or root.get("financial_mode") != expected_mode
        or value.get("claim") != _claim_evidence(source.claim)
        or value.get("claim_issuance")
        != (None if row.operation.provision_id else source.evidence["value"]["claim_issuance"])
        or value.get("execution") is not None
        or value.get("abandoned") is not False
        or type(value.get("sequence")) is not int
        or value["sequence"] <= 0
    ):
        raise MpcBindingError("fresh original Active financial Claim/issuance query required")
    try:
        package = root["public_key_package"]
        generation = root["generation"]
        epoch = uint(generation["epoch"])
        ceremony = _uuid(generation["ceremony_id"])
        keys = root["node_keys"]
        if (
            set(generation) != {"epoch", "ceremony_id", "public_key_package_sha256"}
            or str(ceremony) != generation["ceremony_id"]
            or not isinstance(package, list)
            or not 1 <= len(package) <= 4096
            or any(type(b) is not int or not 0 <= b <= 255 for b in package)
            or generation["public_key_package_sha256"] != hashlib.sha256(bytes(package)).hexdigest()
            or set(keys) != {"signer-a", "signer-b", "signer-c"}
            or len(set(keys.values())) != 3
            or any(not re.fullmatch(r"[0-9a-f]{64}", k) for k in keys.values())
            or (
                epoch == 0
                and (
                    package != source.claim.root.statement["public_key_package"]
                    or str(ceremony) != source.claim.root.statement["dkg"]["execution_id"]
                )
            )
            or (epoch > 0 and str(ceremony) == source.claim.root.statement["dkg"]["execution_id"])
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise MpcBindingError(
            "exact current original-group generation/package/roster required"
        ) from None
    if timezone.now() >= lease.expires_at:
        raise MpcBindingError("admission query expired; keep original allocated IDs")
    return root


def _quote(row, transport, *, fixed=False):
    if not row.operation.source.claim.asset.is_native:
        from .solana_token_provisioning import token_quote

        return token_quote(row, transport, fixed=fixed)
    operation, claim = row.operation, row.operation.source.claim
    spec = get_chain_spec("SOL")
    network = network_identity("SOL")
    observed_holds = _holds(claim.root_id)
    effect_floor = _effect_slot(claim.root_id)
    contexts = {}
    url = rpc_urls("SOL")[0]

    def rpc(method, params):
        return guarded_solana_rpc("SOL", url, transport, method, params)

    def account(address):
        result = rpc(
            "getAccountInfo",
            [
                address,
                {
                    "encoding": "base64",
                    "commitment": "finalized",
                    "minContextSlot": effect_floor,
                },
            ],
        )
        contexts[address] = uint(result["context"]["slot"])
        if contexts[address] < effect_floor:
            raise MpcBindingError("RPC account observation predates accepted outgoing effect")
        return result["value"]

    source, base = account(claim.address), account(claim.root.base_address)
    account_data(source, SYSTEM_PROGRAM, 0)
    account_data(base, SYSTEM_PROGRAM, 0)
    rent = uint(rpc("getMinimumBalanceForRentExemption", [0]))
    destination = account(operation.destination_address)
    if destination is None:
        if operation.base_unit_amount < rent:
            raise InsufficientBalance("new native recipient is below system-account rent minimum")
    else:
        account_data(destination, SYSTEM_PROGRAM, 0)
    block = rpc("getLatestBlockhash", [{"commitment": "finalized", "minContextSlot": effect_floor}])
    if uint(block["context"]["slot"]) < effect_floor:
        raise MpcBindingError("RPC blockhash observation predates accepted outgoing effect")
    value = block["value"]
    if fixed:
        value = {
            "blockhash": row.intent["recent_blockhash"],
            "lastValidBlockHeight": row.intent["last_valid_block_height"],
        }
    height = uint(value["lastValidBlockHeight"], positive=True)
    require_fresh("SOL", height, transport, blockhash=value["blockhash"])
    raw = build_native_transfer(
        claim.root.base_address,
        claim.index,
        operation.destination_address,
        int(operation.base_unit_amount),
        value["blockhash"],
    )
    encoded = base64.b64encode(raw).decode()
    if fixed and raw != bytes(row.payload):
        raise MpcBindingError("fixed original wire differs from current business/source")
    fee = uint(
        rpc("getFeeForMessage", [encoded, {"commitment": "finalized"}])["value"], positive=True
    )
    if fee > min(operation.fee_budget_lamports, _cap(spec.gas_settings, "max_fee_lamports")):
        raise MpcBindingError("exact seeded message fee exceeds original installed budget")
    unsigned = {
        "message": encoded,
        "recentBlockhash": value["blockhash"],
        "lastValidBlockHeight": height,
        "blockhashContextSlot": uint(block["context"]["slot"]),
        "network": network,
        "from": claim.address,
        "to": operation.destination_address,
        "feePayer": claim.root.base_address,
    }
    fees = {
        "observed_hold_fingerprint": observed_holds,
        "observed_effect_slot": effect_floor,
        "account_context_slots": contexts,
        "live_blockhash_context_slot": uint(block["context"]["slot"]),
        "fee_lamports": str(fee),
        "ata_rent_lamports": "0",
        "source_rent_minimum_lamports": str(rent),
        "native_reserve_lamports": str(uint(spec.gas_settings.get("native_reserve_lamports", "0"))),
        "policy": dict(spec.gas_settings),
        "network": network,
        "source_balance_lamports": str(uint(source["lamports"])),
        "base_balance_lamports": str(uint(base["lamports"])),
    }
    return PreparedNativeTransaction(
        "SOL",
        claim.asset.asset_key,
        claim.address,
        operation.destination_address,
        operation.amount,
        int(operation.base_unit_amount),
        raw,
        row.attempt.prepared_metadata if fixed else unsigned,
        fees,
        last_valid_block=height,
    )


def _effect_slot(root_id):
    # Settlement must persist its finalized effect atomically with removing the
    # business hold. Retain that floor even when a lagging RPC is queried first.
    rows = MpcSolanaFinancialEffect.objects.filter(
        attempt__mpcsolanafinancialsession__operation__source__claim__root_id=root_id,
    ).values_list("evidence", flat=True)
    floor = 0
    for value in rows:
        if value.get("finalized") is not True:
            raise MpcBindingError("terminal signed attempt lacks accepted finalized effect")
        floor = max(floor, uint(value["slot"], positive=True))
    return floor


def _holds(root_id):
    # IDs cannot be recycled or resurrected after terminal settlement. Unlike
    # aggregate sums this also detects equal-size replacement of a removed hold.
    rows = (
        MpcSolanaFinancialOperation.objects.filter(status="HELD", source__claim__root_id=root_id)
        .order_by("reservation_id")
        .values_list(
            "reservation_id",
            "source_id",
            "base_unit_amount",
            "fee_budget_lamports",
            "rent_budget_lamports",
        )
    )
    return hashlib.sha256(_canonical([[str(v) for v in row] for row in rows])).hexdigest()


def _liquidity(operation, prepared):
    if prepared.fee_metadata["observed_hold_fingerprint"] != _holds(operation.source.claim.root_id):
        raise MpcBindingError(
            "Root reservations changed during RPC observation; obtain a new quote"
        )
    if prepared.fee_metadata["observed_effect_slot"] != _effect_slot(
        operation.source.claim.root_id
    ):
        raise MpcBindingError("accepted outgoing effect changed during RPC observation")
    held = MpcSolanaFinancialOperation.objects.filter(status="HELD")
    units = held.filter(source_id=operation.source_id).aggregate(total=Sum("base_unit_amount"))[
        "total"
    ]
    budget = held.filter(source__claim__root_id=operation.source.claim.root_id).aggregate(
        total=Sum("fee_budget_lamports"), rent=Sum("rent_budget_lamports")
    )
    fees = prepared.fee_metadata
    source_left = int(fees.get("source_balance_units", fees["source_balance_lamports"])) - int(
        units
    )
    base_left = (
        int(fees["base_balance_lamports"])
        - int(budget["total"] or 0)
        - int(budget["rent"] or 0)
        - int(fees["native_reserve_lamports"])
    )
    minimum = int(fees["source_rent_minimum_lamports"])
    if (
        min(source_left, base_left) < 0
        or (not fees.get("source_is_token") and 0 < source_left < minimum)
        or 0 < base_left < int(fees.get("base_rent_minimum_lamports", minimum))
    ):
        raise InsufficientBalance(
            "separate source principal and Root fee budgets must cover all held businesses"
        )


def _content(row):
    return _canonical({"intent": row.intent, "payload_hex": bytes(row.payload).hex()})


def prepare_session(*, session_id, tenant_id, challenge, evidence, operator_ref, transport=None):
    _standalone()
    _runtime()
    evidence = copy.deepcopy(evidence)
    session_id, tenant_id = _uuid(session_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    version, lifetime, _ = _policy()
    snapshot = _snapshot(session_id, tenant_id)
    if snapshot.status != "ALLOCATED":
        raise MpcBindingError("only an original unprepared allocation can freeze its wire")
    lease = MpcSolanaFinancialQuery.objects.get(pk=challenge, session=snapshot, purpose="ADMISSION")
    _fresh_witness(snapshot, lease, evidence)
    prepared = _quote(snapshot, transport or RequestsTransport())  # No transaction spans RPC.
    with transaction.atomic():
        row, parent = _locked(snapshot, tenant_id)
        operation = row.operation
        wallet = _business(operation, parent)
        claim = wallet.claim
        lease = MpcSolanaFinancialQuery.objects.select_for_update().get(
            pk=challenge, session=row, purpose="ADMISSION", status="PENDING"
        )
        root = _fresh_witness(row, lease, evidence)
        if (
            row.status != "ALLOCATED"
            or (version, lifetime) != _policy()[:2]
            or prepared.fee_metadata["policy"] != get_chain_spec("SOL").gas_settings
        ):
            raise MpcBindingError("original allocation/current policy required")
        _liquidity(operation, prepared)
        now = int(timezone.now().timestamp())
        kind, operation_id = operation_identity(operation)
        intent = {
            "version": "solana_seeded_intent_v1",
            "claim": claim.statement,
            "generation": root["generation"],
            "session_id": str(row.pk),
            "crypto_execution_id": str(row.crypto_execution_id),
            "attempt_id": row.attempt_id,
            "operation_id": operation_id,
            "operation_type": kind,
            "asset_key": claim.asset.asset_key,
            "financial_source": claim.address,
            "fee_payer": claim.root.base_address,
            "rent_payer": None,
            "action": {
                "kind": "NativeTransfer",
                "destination": operation.destination_address,
                "amount": int(operation.base_unit_amount),
            },
            "recent_blockhash": prepared.unsigned_payload["recentBlockhash"],
            "last_valid_block_height": prepared.last_valid_block,
            "policy_version": version,
            "expected_fee_lamports": int(prepared.fee_metadata["fee_lamports"]),
            "expected_rent_lamports": 0,
            "issued_at": now,
            "expires_at": now + lifetime,
            "message_fingerprint": hashlib.sha256(prepared.signing_payload).hexdigest(),
            "financial": {
                "version": 1,
                "reservation_id": str(operation.pk),
                "approval_id": str(operation.approval_id),
                "tenant_id": str(tenant_id),
                "reservation_owner_ref": operation.principal.ledger_owner_id,
                "source_owner_ref": claim.principal.ledger_owner_id,
                "source_role": wallet.role,
                "operation_type": kind,
                "operation_id": operation_id,
                "asset_key": claim.asset.asset_key,
            },
        }
        if claim.asset.is_native:
            validate_native_transfer(
                prepared.unsigned_payload["message"],
                claim.root.base_address,
                claim.index,
                operation.destination_address,
                int(operation.base_unit_amount),
                intent["recent_blockhash"],
            )
        else:
            from .solana_seeded_token_effects import validate_token_intent_message

            intent.update(
                action=prepared.unsigned_payload["seeded_action"],
                rent_payer=claim.root.base_address
                if (operation.provision_id or operation.withdrawal_id)
                else None,
                expected_rent_lamports=int(prepared.fee_metadata["ata_rent_lamports"]),
            )
            validate_token_intent_message(intent, prepared.unsigned_payload["message"])
        row.intent, row.payload = intent, prepared.signing_payload
        row.custody_authorization = _authorize_message(
            b"Wallet-MPC/CUSTODY_SOLANA_SEEDED_INTENT_V1\0" + _content(row),
            settings.MPC_CLIENT_CERT,
            settings.MPC_CLIENT_KEY,
        )
        attempt = row.attempt
        attempt.prepared_metadata, attempt.fee_metadata, attempt.last_valid_block = (
            prepared.unsigned_payload,
            prepared.fee_metadata,
            prepared.last_valid_block,
        )
        attempt.status = "PREPARED"
        attempt.expires_at = datetime.fromtimestamp(now + lifetime, datetime_timezone.utc)
        attempt.save(
            update_fields=[
                "prepared_metadata",
                "fee_metadata",
                "last_valid_block",
                "expires_at",
                "status",
                "updated_at",
            ]
        )
        row.status = "WAITING_POLICY"
        row.save(
            update_fields=["intent", "payload", "custody_authorization", "status", "updated_at"]
        )
        try:
            with transaction.atomic():
                owner = MpcSolanaMessageOwner.objects.create(
                    genesis_hash=claim.root.statement["genesis_hash"],
                    message_fingerprint=intent["message_fingerprint"],
                    operation=operation,
                    first_session=row,
                )
        except IntegrityError:
            owner = MpcSolanaMessageOwner.objects.get(
                genesis_hash=claim.root.statement["genesis_hash"],
                message_fingerprint=intent["message_fingerprint"],
            )
        if owner.operation_id != operation.pk:
            raise MpcBindingError(
                "canonical message already belongs to another business; wait for a fresh blockhash"
            )
        lease.status, lease.evidence = "VERIFIED", evidence
        lease.save(update_fields=["status", "evidence"])
        _audit("SOL_FIN_NATIVE_PREPARE", row, operator_ref)
        return row


def _verify_policy_grant(row, policy_authorization):
    version, lifetime, cert = _policy()
    if (
        row.intent.get("policy_version") != version
        or row.intent["expires_at"] - row.intent["issued_at"] > lifetime
    ):
        raise MpcBindingError("original intent exceeds current independent Policy bounds")
    try:
        chain = policy_authorization["certificate_chain_der_hex"]
        if set(policy_authorization) != {
            "certificate_chain_der_hex",
            "signature_der_hex",
        } or (
            not isinstance(chain, list)
            or not 1 <= len(chain) <= 5
            or any(not isinstance(encoded, str) or len(encoded) > 32768 for encoded in chain)
            or chain[0] != cert.public_bytes(serialization.Encoding.DER).hex()
            or not re.fullmatch(r"[0-9a-f]{16,160}", policy_authorization["signature_der_hex"])
        ):
            raise ValueError
        for encoded in chain:
            parsed = x509.load_der_x509_certificate(bytes.fromhex(encoded))
            if parsed.public_bytes(serialization.Encoding.DER).hex() != encoded:
                raise ValueError
        cert.public_key().verify(
            bytes.fromhex(policy_authorization["signature_der_hex"]),
            b"Wallet-MPC/OPERATOR_SEEDED_SPEND_V1\0" + _content(row),
            ec.ECDSA(hashes.SHA256()),
        )
    except (KeyError, TypeError, ValueError, InvalidSignature):
        raise MpcBindingError("independent Policy grant for exact original wire required") from None


def approve_session(
    *, session_id, tenant_id, challenge, evidence, policy_authorization, operator_ref
):
    _standalone()
    _runtime()
    evidence, policy_authorization = copy.deepcopy(evidence), copy.deepcopy(policy_authorization)
    session_id, tenant_id = _uuid(session_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    snapshot = _snapshot(session_id, tenant_id)
    with transaction.atomic():
        row, parent = _locked(snapshot, tenant_id)
        _business(row.operation, parent)
        version = _policy()[0]
        if (
            row.status != "WAITING_POLICY"
            or row.intent.get("policy_version") != version
            or int(timezone.now().timestamp()) >= row.intent["expires_at"]
        ):
            raise MpcBindingError("original unexpired WAITING_POLICY intent required")
        _verify_policy_grant(row, policy_authorization)
        lease = MpcSolanaFinancialQuery.objects.select_for_update().get(
            pk=challenge, session=row, purpose="ADMISSION", status="PENDING"
        )
        root = _fresh_witness(row, lease, evidence)
        if root["generation"] != row.intent["generation"]:
            raise MpcBindingError("original prepared generation changed; no in-place update")
        lease.status, lease.evidence = "VERIFIED", evidence
        lease.save(update_fields=["status", "evidence"])
        row.status, row.policy_authorization, row.admission_evidence = (
            "READY",
            policy_authorization,
            evidence,
        )
        row.save(
            update_fields=["status", "policy_authorization", "admission_evidence", "updated_at"]
        )
        _audit("SOL_FIN_POLICY_ACCEPT", row, operator_ref)
        return row
