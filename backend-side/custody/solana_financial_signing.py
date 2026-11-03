"""Typed protected HOT dispatch and public signature recovery; no broadcasting.

Only READY may dispatch private work, once. HTTP ambiguity stays reserved. Public
recovery uses the captured original generation/roster and fresh pinned W truth;
coordinator completion alone never authorizes signature consumption or settlement.
"""

import copy
import re
from datetime import datetime
from datetime import timezone as datetime_timezone
from pathlib import Path

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .chain_registry import get_chain_spec
from .identity_registry import _standalone, _text, _uuid
from .models import (
    MpcSolanaFinancialQuery,
    MpcSolanaMessageOwner,
    MpcSolanaSignatureOwner,
)
from .mpc_binding import MpcBindingError
from .mpc_transport import coordinator_request
from .native_tx import RequestsTransport
from .solana_coordinator import preflight_route, resolve_route
from .solana_financial_preparation import (
    _business,
    _fresh_witness,
    _liquidity,
    _locked,
    _quote,
    _snapshot,
    _verify_policy_grant,
)
from .solana_financial_sessions import request_query
from .solana_issuance import _canonical, _fingerprint, _pin
from .solana_provisioning import _audit, _claim_evidence, _runtime
from .solana_wire import assemble_signature
from .solana_witness_client import (
    _message,
    _point_id,
    _require_role,
    _verify,
    publish_public_result,
    query_witness,
)

PREFIX = "/v1/solana-protected-sessions"


def _binding(row):
    return {
        "authorized": {
            "intent": row.intent,
            "payload_hex": bytes(row.payload).hex(),
            "claim_evidence": _claim_evidence(row.operation.source.claim),
            "custody_authorization": row.custody_authorization,
            "operator_authorization": row.policy_authorization,
        },
        "selected_signers": row.selected_signers,
    }


def _binding_id(row):
    return _fingerprint(
        "WITNESS_EXECUTION_V1",
        [
            _fingerprint("WITNESS_INTENT_V1", [row.intent, bytes(row.payload).hex()]),
            row.selected_signers,
        ],
    )


def _pins(view):
    rings = settings.MPC_SOLANA_FINANCIAL_SIGNER_CERTIFICATES
    if not isinstance(rings, dict) or set(rings) != {"signer-a", "signer-b", "signer-c"}:
        raise MpcBindingError("independently installed protected signer public pin rings required")
    result = {}
    for party, paths in rings.items():
        if not isinstance(paths, list) or not 1 <= len(paths) <= 16:
            raise MpcBindingError("bounded public signer certificate ring required")
        keys = {}
        for path in paths:
            cert = x509.load_pem_x509_certificate(Path(path).read_bytes())
            _require_role(cert, party)
            keys[_point_id(cert.public_key())] = cert.public_key()
        expected = view["node_keys"][party]
        if expected not in keys:
            raise MpcBindingError(
                "captured original signer identity absent from installed pin ring"
            )
        result[party] = (expected, keys[expected])
    return result


def _bytes(value, minimum, maximum):
    return (
        isinstance(value, list)
        and minimum <= len(value) <= maximum
        and all(type(b) is int and 0 <= b <= 255 for b in value)
    )


def _report(row, report, pins):
    try:
        if set(report) != {"key_id", "value", "signature"}:
            raise ValueError
        v = report["value"]
        if set(v) != {
            "anchor_id",
            "execution_id",
            "binding_fingerprint",
            "party_id",
            "round",
            "commitments",
            "signature_share",
            "signing_package",
        }:
            raise ValueError
        party, round_number = v["party_id"], v["round"]
        if (
            party not in row.selected_signers
            or type(round_number) is not int
            or round_number not in [1, 2]
            or v["anchor_id"]
            != row.coordinator_evidence["request"]["witness"]["value"]["query"]["anchor_id"]
            or v["execution_id"] != str(row.crypto_execution_id)
            or v["binding_fingerprint"] != _binding_id(row)
            or report["key_id"] != pins[party][0]
            or not re.fullmatch(r"[0-9a-f]{16,160}", report["signature"])
        ):
            raise ValueError
        if round_number == 1:
            if (
                not _bytes(v["commitments"], 1, 4096)
                or v["signature_share"] is not None
                or v["signing_package"] is not None
            ):
                raise ValueError
        elif (
            v["commitments"] is not None
            or not _bytes(v["signature_share"], 32, 32)
            or not _bytes(v["signing_package"], 1, 4096)
        ):
            raise ValueError
        pins[party][1].verify(
            bytes.fromhex(report["signature"]),
            _message("WITNESS_PUBLIC_ROUND_V1", report),
            ec.ECDSA(hashes.SHA256()),
        )
        return f"{party}:{round_number}"
    except (KeyError, TypeError, ValueError, InvalidSignature):
        raise MpcBindingError(
            "authentic original-node round report for this exact binding required"
        ) from None


def _result(row, result):
    if (
        set(result)
        != {
            "request",
            "status",
            "round1",
            "signing_package",
            "round2",
            "signature_hex",
            "error_code",
        }
        or result["request"] != row.coordinator_evidence["request"]
        or result["status"]
        not in {"CREATED", "IN_PROGRESS", "RECONCILIATION_REQUIRED", "COMPLETED"}
    ):
        raise MpcBindingError("original typed coordinator response identity required")
    pins = _pins(row.coordinator_evidence["request"]["witness"]["value"]["root"])
    reports = {}
    for round_number in [1, 2]:
        values = result[f"round{round_number}"]
        if not isinstance(values, dict) or not set(values).issubset(row.selected_signers):
            raise MpcBindingError("original selected report pair required")
        for party, report in values.items():
            slot = _report(row, report, pins)
            if slot != f"{party}:{round_number}":
                raise MpcBindingError("coordinator report slot mismatch")
            reports[slot] = report
    if result["status"] == "COMPLETED":
        if not isinstance(result["signature_hex"], str) or not re.fullmatch(
            r"[0-9a-f]{128}", result["signature_hex"]
        ):
            raise MpcBindingError("original completed signature encoding required")
    return reports


def _unknown(session_id, tenant_id, operator_ref):
    snapshot = _snapshot(session_id, tenant_id)
    with transaction.atomic():
        row, _parent = _locked(snapshot, tenant_id)
        if row.status in {"IN_PROGRESS", "RECONCILIATION_REQUIRED"}:
            row.status, row.error_code = "RECONCILIATION_REQUIRED", "PROTECTED_OUTCOME_UNCERTAIN"
            row.save(update_fields=["status", "error_code", "updated_at"])
            _audit("SOL_FIN_SIGN_UNKNOWN", row, operator_ref)
        return row


def _remember(row, result, operator_ref):
    result = copy.deepcopy(result)
    with transaction.atomic():
        current, _parent = _locked(row, row.operation.principal.tenant_id)
        if current.status in {"COMPLETED", "NO_SIGNATURE"}:
            return current
        reports = _result(current, result)
        envelope = copy.deepcopy(current.coordinator_evidence)
        for slot, report in reports.items():
            previous = envelope["reports"].get(slot)
            if previous and (
                previous["key_id"] != report["key_id"]
                or _canonical(previous["value"]) != _canonical(report["value"])
            ):
                raise MpcBindingError("original public round report cannot change")
            envelope["reports"].setdefault(slot, report)
        envelope["response"] = result
        current.coordinator_evidence = envelope
        current.save(update_fields=["coordinator_evidence", "updated_at"])
        _audit("SOL_FIN_PUBLIC_RESULT", current, operator_ref)
        return current


def execute_session(*, session_id, tenant_id, challenge, evidence, operator_ref, transport=None):
    """CAS READY before Create/Execute; all later calls are public recovery only."""
    _standalone()
    _runtime()
    session_id, tenant_id = _uuid(session_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    evidence = copy.deepcopy(evidence)
    snapshot = _snapshot(session_id, tenant_id)
    if snapshot.status in {"IN_PROGRESS", "RECONCILIATION_REQUIRED", "COMPLETED", "NO_SIGNATURE"}:
        return snapshot
    if snapshot.status != "READY":
        raise MpcBindingError("original READY policy-approved session required")
    keyset_id = snapshot.operation.source.claim.root.keyset.keyset_id
    route = preflight_route(keyset_id)
    lease = MpcSolanaFinancialQuery.objects.get(
        pk=challenge, session=snapshot, purpose="ADMISSION", status="PENDING"
    )
    _fresh_witness(snapshot, lease, evidence)
    _verify_policy_grant(snapshot, snapshot.policy_authorization)
    quote = _quote(snapshot, transport or RequestsTransport(), fixed=True)
    with transaction.atomic():
        row, parent = _locked(snapshot, tenant_id)
        if row.status != "READY":
            return row
        if preflight_route(keyset_id) != route:
            raise MpcBindingError("coordinator binding changed before dispatch; preserve READY")
        _business(row.operation, parent)
        _verify_policy_grant(row, row.policy_authorization)
        if quote.fee_metadata["policy"] != get_chain_spec("SOL").gas_settings:
            raise MpcBindingError("current fee/reserve policy changed during RPC observation")
        lease = MpcSolanaFinancialQuery.objects.select_for_update().get(
            pk=challenge, session=row, purpose="ADMISSION", status="PENDING"
        )
        view = _fresh_witness(row, lease, evidence)
        if view["generation"] != row.intent["generation"] or quote.fee_metadata[
            "fee_lamports"
        ] != str(row.intent["expected_fee_lamports"]):
            raise MpcBindingError("original generation/message fee changed; never rewrite intent")
        _pins(view)
        _liquidity(row.operation, quote)
        MpcSolanaMessageOwner.objects.get(
            genesis_hash=row.intent["claim"]["root"]["genesis_hash"],
            message_fingerprint=row.intent["message_fingerprint"],
            operation=row.operation,
        )
        request = {"binding": _binding(row), "witness": evidence}
        lease.status, lease.evidence = "VERIFIED", evidence
        lease.save(update_fields=["status", "evidence"])
        row.coordinator_evidence = {
            "request": request,
            "dispatch_quote": quote.fee_metadata,
            "dispatch_query": challenge,
            "reports": {},
        }
        row.status = "IN_PROGRESS"
        row.save(update_fields=["status", "coordinator_evidence", "updated_at"])
        attempt = row.attempt
        attempt.status = "SIGNING"
        attempt.save(update_fields=["status", "updated_at"])
        _audit("SOL_FIN_SIGN_DISPATCH", row, operator_ref)
        deadline = min(
            lease.expires_at,
            datetime.fromtimestamp(row.intent["expires_at"], datetime_timezone.utc),
        )
    try:
        routing = {} if route is None else {"route": route}
        result = coordinator_request(
            "POST", PREFIX, json_payload=request, dispatch_deadline=deadline, **routing
        )
        _result(row, result)
        if result["status"] == "CREATED":
            result = coordinator_request(
                "POST", f"{PREFIX}/{row.pk}/execute", dispatch_deadline=deadline, **routing
            )
        row = _remember(row, result, operator_ref)
        return _recover_witness(row, tenant_id, operator_ref)
    except Exception:
        _unknown(session_id, tenant_id, operator_ref)
        raise


def _recover_witness(row, tenant_id, operator_ref):
    if row.status in {"COMPLETED", "NO_SIGNATURE"}:
        return row
    pins = _pins(row.coordinator_evidence["request"]["witness"]["value"]["root"])
    for report in row.coordinator_evidence["reports"].values():
        _report(row, report, pins)
        publish_public_result(report)  # Authentic public redelivery, never private work.
    request = request_query(
        session_id=row.pk, tenant_id=tenant_id, purpose="RECOVERY", operator_ref=operator_ref
    )
    proof = query_witness(request["query"])
    return consume_signature(
        session_id=row.pk,
        tenant_id=tenant_id,
        challenge=request["query"]["challenge"],
        evidence=proof,
        operator_ref=operator_ref,
    )


def consume_signature(*, session_id, tenant_id, challenge, evidence, operator_ref):
    _standalone()
    _runtime()
    session_id, tenant_id = _uuid(session_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    evidence = copy.deepcopy(evidence)
    snapshot = _snapshot(session_id, tenant_id)
    with transaction.atomic():
        row, _parent = _locked(snapshot, tenant_id)
        if row.status in {"COMPLETED", "NO_SIGNATURE"}:
            return row
        if row.status not in {"IN_PROGRESS", "RECONCILIATION_REQUIRED"}:
            raise MpcBindingError("captured original dispatch required for public recovery")
        lease = MpcSolanaFinancialQuery.objects.select_for_update().get(
            pk=challenge, session=row, purpose="RECOVERY", status="PENDING"
        )
        value = _verify("WITNESS_QUERY_REPLY_V1", evidence)
        anchor, key_id, _ = _pin()
        if (
            value.get("query") != lease.query
            or (anchor, key_id) != (lease.witness_anchor_id, lease.witness_key_id)
            or value.get("root", {}).get("original") != row.intent["claim"]["root"]
            or value.get("claim") != _claim_evidence(row.operation.source.claim)
            or value.get("abandoned") is not False
            or timezone.now() >= lease.expires_at
        ):
            raise MpcBindingError("fresh original execution/root/claim recovery query required")
        execution = value.get("execution")
        if not execution or execution.get("status") != "SignedPending":
            return _unknown(session_id, tenant_id, operator_ref)
        if execution.get("binding_fingerprint") != _binding_id(row):
            raise MpcBindingError("witness execution belongs to another exact binding")
        reports = execution.get("reports", {})
        expected = {f"{p}:{r}" for p in row.selected_signers for r in [1, 2]}
        if set(reports) != expected:
            raise MpcBindingError("complete original two-round report set required")
        pins = _pins(row.coordinator_evidence["request"]["witness"]["value"]["root"])
        for slot, report in reports.items():
            if _report(row, report, pins) != slot:
                raise MpcBindingError("original witness report slot mismatch")
        signature = execution["signature"]
        payload, txid = assemble_signature(
            row.attempt.prepared_metadata["message"],
            row.intent["claim"]["root"]["group_public_key"],
            signature,
        )
        response = row.coordinator_evidence.get("response", {})
        if response.get("status") == "COMPLETED" and response["signature_hex"] != signature:
            raise MpcBindingError("coordinator and witness signatures disagree")
        owner = MpcSolanaMessageOwner.objects.get(
            genesis_hash=row.intent["claim"]["root"]["genesis_hash"],
            message_fingerprint=row.intent["message_fingerprint"],
            operation=row.operation,
        )
        lease.status, lease.evidence = "VERIFIED", evidence
        lease.save(update_fields=["status", "evidence"])
        row.status, row.signature_hex, row.error_code = "COMPLETED", signature, ""
        row.save(update_fields=["status", "signature_hex", "error_code", "updated_at"])
        attempt = row.attempt
        attempt.status, attempt.signed_payload, attempt.network_tx_id = "SIGNED", payload, txid
        attempt.save(update_fields=["status", "signed_payload", "network_tx_id", "updated_at"])
        MpcSolanaSignatureOwner.objects.create(
            genesis_hash=owner.genesis_hash,
            signature=txid,
            message=owner,
            session=row,
            evidence=evidence,
        )
        _audit("SOL_FIN_SIGNATURE_CAPTURE", row, operator_ref)
        return row


def reconcile_session(*, session_id, tenant_id, operator_ref):
    """Read/recover original public R2 only. Never Create, Execute or Node.auto."""
    _standalone()
    _runtime()
    from .signer_adapter import CoordinatorSessionNotFound

    session_id, tenant_id = _uuid(session_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    row = _snapshot(session_id, tenant_id)
    if row.status in {"COMPLETED", "NO_SIGNATURE"}:
        return row
    if row.status not in {"IN_PROGRESS", "RECONCILIATION_REQUIRED"}:
        raise MpcBindingError("original dispatched session required")
    try:
        result = None
        try:
            route = resolve_route(row.operation.source.claim.root.keyset.keyset_id)
        except (MpcBindingError, OSError):
            pass  # W public truth remains usable without any alternate coordinator.
        else:
            routing = {} if route is None else {"route": route}
            try:
                result = coordinator_request("POST", f"{PREFIX}/{row.pk}/reconcile", **routing)
            except (OSError, TimeoutError, requests.RequestException, CoordinatorSessionNotFound):
                pass  # W may already have the signature despite coordinator loss.
        if result is not None:
            row = _remember(row, result, operator_ref)
        return _recover_witness(row, tenant_id, operator_ref)
    except Exception:
        _unknown(session_id, tenant_id, operator_ref)
        raise
