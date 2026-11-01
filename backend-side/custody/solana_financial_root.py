"""Import an independently enabled clean Root mode before reserving any Claim.

The operator relays a signed read-only witness reply. This module has no Lifecycle
or Policy key, never sends EnableFinancialMode and never activates a wallet or
posts a ledger entry. A supplied query reply has no trusted timestamp: its random
challenge and bounded lease must already be committed here before remote I/O.
"""

import hashlib
import re
import secrets
from datetime import timedelta
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.db import transaction
from django.utils import timezone

from .identity_registry import _standalone, _text, _uuid
from .models import MpcKeyset, MpcSolanaClaim, MpcSolanaFinancialRoot, MpcSolanaRoot
from .mpc_binding import MpcBindingError
from .mpc_solana_network import network_identity, verify_solana_rpc_endpoints
from .native_tx import RequestsTransport
from .solana_issuance import _canonical, _fingerprint, _pin
from .solana_provisioning import _audit, _runtime, _validate_root, _verify


def _query(row):
    return {
        "anchor_id": str(row.witness_anchor_id),
        "root_identity": _fingerprint("SOLANA_SEEDED_ROOT_V1", row.root.statement),
        "challenge": row.query_challenge,
        "execution_id": None,
    }


def _locked_root(keyset_id, tenant_id):
    keyset = MpcKeyset.objects.select_for_update().get(keyset_id=keyset_id)
    root = (
        MpcSolanaRoot.objects.select_for_update(of=("self",))
        .select_related("keyset")
        .get(keyset=keyset, tenant_id=tenant_id)
    )
    _validate_root(root)
    _verify("root", root.statement, root.evidence)
    if (
        root.status != "APPROVED"
        or root.keyset.status != "ACTIVE"
        or root.network_identity != network_identity("SOL")
        or root.statement["wallet_class"] != "HOT"
    ):
        raise MpcBindingError("exact approved isolated HOT Root required")
    return root


def financial_mode_request(*, keyset_id, tenant_id, operator_ref):
    """Commit/recover a one-use query lease; no remote side effect or mode grant."""
    _standalone()
    _runtime()
    keyset_id, tenant_id = _uuid(keyset_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    anchor, key_id, _ = _pin()
    with transaction.atomic():
        root = _locked_root(keyset_id, tenant_id)
        row = MpcSolanaFinancialRoot.objects.select_for_update().filter(root=root).first()
        if row is not None and row.status == "VERIFIED":
            verify_financial_mode(row)
        else:
            if root.next_index != 0 or MpcSolanaClaim.objects.filter(root=root).exists():
                raise MpcBindingError("populated Root cannot be adopted into financial mode")
            if row is None:
                row = MpcSolanaFinancialRoot.objects.create(
                    root=root,
                    witness_anchor_id=anchor,
                    witness_key_id=key_id,
                    query_challenge=secrets.token_hex(32),
                    query_expires_at=timezone.now() + timedelta(seconds=15),
                )
                _audit("SOLANA_FINANCIAL_ROOT_RESERVE", row, operator_ref)
            elif (row.witness_anchor_id, row.witness_key_id) != (anchor, key_id):
                raise MpcBindingError("original mode import authority cannot be replaced")
            elif timezone.now() >= row.query_expires_at:
                row.query_challenge = secrets.token_hex(32)
                row.query_expires_at = timezone.now() + timedelta(seconds=15)
                row.save(update_fields=["query_challenge", "query_expires_at"])
                _audit("SOL_FIN_ROOT_QUERY_REFRESH", row, operator_ref)
        return {
            "keyset_id": str(keyset_id),
            "status": row.status,
            "expected_mode": {
                "version": 1,
                "activation_id": str(row.activation_id),
                "command_id": str(row.command_id),
            },
            "query": _query(row),
        }


def verify_financial_mode(row, signed=None):
    """Authenticate the original mode import, preserving its historical query.

    Re-verification is not a new freshness grant or statement about today's phase,
    generation or roster. Current signing and wallet admission need their own lease.
    Witness identity rotation requires explicit archival pin support; no new key is
    silently substituted for this stored original signature.
    """
    signed = row.evidence if signed is None else signed
    try:
        anchor, key_id, key = _pin()
        if (
            (row.witness_anchor_id, row.witness_key_id) != (anchor, key_id)
            or set(signed) != {"key_id", "value", "signature"}
            or signed["key_id"] != key_id
            or not re.fullmatch(r"[0-9a-f]{16,160}", signed["signature"])
        ):
            raise ValueError
        message = b"Wallet-MPC/WITNESS_QUERY_REPLY_V1\0" + _canonical(
            {"key_id": key_id, "value": signed["value"]}
        )
        if len(message) > 1024 * 1024:
            raise ValueError
        key.verify(bytes.fromhex(signed["signature"]), message, ec.ECDSA(hashes.SHA256()))
        value = signed["value"]
        root, mode = value["root"], value["root"]["financial_mode"]
        package, generation = root["public_key_package"], root["generation"]
        activation_id, command_id = UUID(mode["activation_id"]), UUID(mode["command_id"])
        if (
            value["query"] != _query(row)
            or root["original"] != row.root.statement
            or root["phase"] != "Active"
            or type(root["revision"]) is not int
            or root["revision"] <= 0
            or type(value["sequence"]) is not int
            or value["sequence"] <= 0
            or type(root["next_claim_index"]) is not int
            or root["next_claim_index"] != 0
            or value["claim"] is not None
            or value["execution"] is not None
            or value["abandoned"] is not False
            or value.get("claim_issuance") is not None
            or value.get("replacement") is not None
            or value.get("refresh") is not None
            or root.get("prepared") is not None
            or set(mode) != {"version", "activation_id", "command_id"}
            or type(mode["version"]) is not int
            or mode["version"] != 1
            or not activation_id.int
            or str(activation_id) != mode["activation_id"]
            or not command_id.int
            or str(command_id) != mode["command_id"]
            or row.activation_id != activation_id
            or row.command_id != command_id
            or set(root["node_keys"]) != {"signer-a", "signer-b", "signer-c"}
            or len(set(root["node_keys"].values())) != 3
            or any(not re.fullmatch(r"[0-9a-f]{64}", k) for k in root["node_keys"].values())
            or not isinstance(package, list)
            or not 1 <= len(package) <= 4096
            or any(type(b) is not int or not 0 <= b <= 255 for b in package)
            or set(generation) != {"epoch", "ceremony_id", "public_key_package_sha256"}
            or type(generation["epoch"]) is not int
            or not 0 <= generation["epoch"] < 2**64
            or not UUID(generation["ceremony_id"]).int
            or str(UUID(generation["ceremony_id"])) != generation["ceremony_id"]
            or hashlib.sha256(bytes(package)).hexdigest() != generation["public_key_package_sha256"]
        ):
            raise ValueError
        return activation_id
    except (KeyError, TypeError, ValueError, AttributeError, InvalidSignature):
        raise MpcBindingError(
            "original independently enabled clean financial Root proof required"
        ) from None


def complete_financial_mode(*, keyset_id, tenant_id, evidence, operator_ref, transport=None):
    _standalone()
    _runtime()
    keyset_id, tenant_id = _uuid(keyset_id), _uuid(tenant_id)
    operator_ref = _text(operator_ref, "operator audit reference")
    verify_solana_rpc_endpoints("SOL", transport or RequestsTransport())
    with transaction.atomic():
        root = _locked_root(keyset_id, tenant_id)
        row = MpcSolanaFinancialRoot.objects.select_for_update().get(root=root)
        row.root = root
        if row.status == "VERIFIED":
            verify_financial_mode(row)
            return row
        activation_id = verify_financial_mode(row, evidence)
        if (
            timezone.now() >= row.query_expires_at
            or root.next_index != 0
            or MpcSolanaClaim.objects.filter(root=root).exists()
        ):
            raise MpcBindingError("expired mode query or populated Root; retain original import")
        row.status, row.evidence, row.activation_id = "VERIFIED", evidence, activation_id
        row.save(update_fields=["status", "evidence", "activation_id"])
        _audit("SOLANA_FINANCIAL_ROOT_VERIFY", row, operator_ref)
        return row
