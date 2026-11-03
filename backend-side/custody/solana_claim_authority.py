"""Archival current-Claim public signatures, independent of mutable TLS pin rings.

Life's installed public pin authenticates the exact Prepare roster. Embedded
leaves supply only those named public keys. This verifier establishes neither
freshness nor registration: consumers must additionally verify their own fresh
W query and exact permanent registered evidence. W/private nodes validate the
FROST package against the original group key before accepting registration.
"""

import hashlib
import re
from pathlib import Path
from uuid import UUID

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .mpc_binding import PARTICIPANTS, MpcBindingError
from .solana_issuance import _canonical, _fingerprint
from .solana_witness_client import _message, _point_id, _require_role


def _exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        raise ValueError("exact public proof shape required")


def _uuid(value):
    if not isinstance(value, str):
        raise ValueError("canonical nonzero UUID required")
    parsed = UUID(value)
    if not parsed.int or str(parsed) != value:
        raise ValueError("canonical nonzero UUID required")
    return value


def _uint(value, *, positive=False):
    if type(value) is not int or not (int(positive) <= value <= 2**64 - 1):
        raise ValueError("bounded unsigned integer required")
    return value


def _hex(value, minimum=32, maximum=32):
    if not isinstance(value, str) or not 2 * minimum <= len(value) <= 2 * maximum:
        raise ValueError("bounded canonical hex required")
    if not re.fullmatch("[0-9a-f]+", value) or len(value) % 2:
        raise ValueError("canonical hex required")
    return bytes.fromhex(value)


def _key(certificate, role):
    _require_role(certificate, role)
    key = certificate.public_key()
    _point_id(key)
    return key


def _signed(domain, proof, key):
    _exact(proof, "key_id value signature")
    if proof["key_id"] != _point_id(key):
        raise ValueError("exact named public key required")
    key.verify(_hex(proof["signature"], 8, 80), _message(domain, proof), ec.ECDSA(hashes.SHA256()))


def _generation(value):
    _exact(value, "epoch ceremony_id public_key_package_sha256")
    _uint(value["epoch"])
    _uuid(value["ceremony_id"])
    _hex(value["public_key_package_sha256"])


def _authority(root, authority, lifecycle_certificate, witness_anchor_id):
    _exact(authority, "version prepare node_certificates_der_hex")
    if type(authority["version"]) is not int or authority["version"] != 1:
        raise ValueError("supported current Claim version required")
    lifecycle = _key(lifecycle_certificate, "lifecycle")
    prepare = authority["prepare"]
    _signed("WITNESS_COMMAND_V1", prepare, lifecycle)
    command = prepare["value"]
    _exact(command, "anchor_id root_identity request_id expected_revision expires_at action")
    if _uuid(command["anchor_id"]) != str(witness_anchor_id):
        raise ValueError("independently installed W anchor required")
    _uuid(command["request_id"])
    _uint(command["expected_revision"])
    _uint(command["expires_at"], positive=True)  # archival Prepare, no live expiry claim
    if command["root_identity"] != _fingerprint("SOLANA_SEEDED_ROOT_V1", root):
        raise ValueError("original Root required")
    action = command["action"]
    _exact(action, "kind ready node_keys")
    certificates = authority["node_certificates_der_hex"]
    if (
        action["kind"] != "Prepare"
        or not isinstance(action["ready"], list)
        or len(action["ready"]) != 3
        or not isinstance(action["node_keys"], dict)
        or set(action["node_keys"]) != set(PARTICIPANTS)
        or not isinstance(certificates, dict)
        or set(certificates) != set(PARTICIPANTS)
    ):
        raise ValueError("exact all-three prepared receipt roster required")
    keys, seen, common = {}, {_point_id(lifecycle)}, None
    for party, proof in zip(PARTICIPANTS, action["ready"], strict=True):
        der = _hex(certificates[party], 128, 16384)
        certificate = x509.load_der_x509_certificate(der)
        if certificate.public_bytes(serialization.Encoding.DER) != der:
            raise ValueError("canonical DER leaf required")
        key = _key(certificate, party)
        identity = _point_id(key)
        if identity in seen or identity != action["node_keys"][party]:
            raise ValueError("three distinct exact prepared receipt identities required")
        seen.add(identity)
        _signed("WITNESS_GENERATION_READY_V1", proof, key)
        ready = proof["value"]
        _exact(ready, "root_identity previous_generation generation public_key_package party_id")
        previous, generation = ready["previous_generation"], ready["generation"]
        _generation(previous)
        _generation(generation)
        package = ready["public_key_package"]
        if (
            not isinstance(package, list)
            or not 1 <= len(package) <= 4096
            or any(type(b) is not int or not 0 <= b <= 255 for b in package)
            or generation["epoch"] != previous["epoch"] + 1
            or generation["ceremony_id"]
            in {previous["ceremony_id"], root["dkg"]["execution_id"], root["dkg"]["session_id"]}
            or generation["public_key_package_sha256"] != hashlib.sha256(bytes(package)).hexdigest()
            or ready["root_identity"] != command["root_identity"]
            or ready["party_id"] != party
        ):
            raise ValueError("original Root and consistent next generation required")
        if previous["epoch"] == 0 and previous != dict(
            epoch=0,
            ceremony_id=root["dkg"]["execution_id"],
            public_key_package_sha256=hashlib.sha256(bytes(root["public_key_package"])).hexdigest(),
        ):
            raise ValueError("original DKG predecessor marker required")
        agreement = (previous, generation, package)
        if common is not None and agreement != common:
            raise ValueError("all-three exact generation agreement required")
        common, keys[party] = agreement, key
    return keys


def verify_current_claim(statement, evidence, *, lifecycle_certificate, witness_anchor_id):
    """Verify full archival evidence under an independently supplied Life PEM path."""
    try:
        if len(_canonical(evidence)) > 1024 * 1024:
            raise ValueError("bounded public evidence required")
        _exact(evidence, "statement participant_agreement authority")
        if evidence["statement"] != statement:
            raise ValueError("original Claim statement required")
        certificate = x509.load_pem_x509_certificate(Path(lifecycle_certificate).read_bytes())
        keys = _authority(statement["root"], evidence["authority"], certificate, witness_anchor_id)
        reports = evidence["participant_agreement"]
        if not isinstance(reports, list) or len(reports) != 3:
            raise ValueError("all-three current receipts required")
        for party, report in zip(PARTICIPANTS, reports, strict=True):
            _exact(report, "statement party_id durable signer_signature")
            if (
                report["statement"] != statement
                or report["party_id"] != party
                or report["durable"] is not True
            ):
                raise ValueError("exact durable current Claim receipt required")
            message = b"Wallet-MPC/SIGNER_SOLANA_CURRENT_CLAIM_V1\0" + _canonical(
                dict(
                    statement=statement,
                    authority=evidence["authority"],
                    party_id=party,
                    durable=True,
                )
            )
            keys[party].verify(
                _hex(report["signer_signature"], 8, 80), message, ec.ECDSA(hashes.SHA256())
            )
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        InvalidSignature,
        x509.ExtensionNotFound,
    ) as exc:
        raise MpcBindingError("unverifiable current Claim authority/receipts") from exc
