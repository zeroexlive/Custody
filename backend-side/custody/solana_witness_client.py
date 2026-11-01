"""Pinned courier transport: Custody read queries and authentic public results.

No Lifecycle/Policy key, command, private permit or nonce creation is available.
Transport verification is not freshness or ledger authority. Callers must first
commit their own query challenge/deadline and consume it under database locks.
"""

import hashlib
import http.client
import json
import re
import ssl
from pathlib import Path
from urllib.parse import urlsplit

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings

from .mpc_binding import MpcBindingError
from .solana_issuance import _canonical, _pin
from .solana_provisioning import _runtime


def _point_id(key):
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise MpcBindingError("P256 public authority required")
    return hashlib.sha256(
        key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    ).hexdigest()


def _message(domain, signed):
    return f"Wallet-MPC/{domain}\0".encode() + _canonical(
        {
            "key_id": signed["key_id"],
            "value": signed["value"],
        }
    )


def _require_role(certificate, role):
    try:
        identities = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
        if (
            identities != [f"spiffe://wallet-mpc/{role}"]
            or certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        ):
            raise ValueError
    except (x509.ExtensionNotFound, ValueError):
        raise MpcBindingError(f"exact {role} leaf identity required") from None


def _verify(domain, signed):
    _anchor, key_id, key = _pin()
    try:
        if (
            set(signed) != {"key_id", "value", "signature"}
            or signed["key_id"] != key_id
            or not re.fullmatch(r"[0-9a-f]{16,160}", signed["signature"])
        ):
            raise ValueError
        key.verify(
            bytes.fromhex(signed["signature"]), _message(domain, signed), ec.ECDSA(hashes.SHA256())
        )
    except (KeyError, TypeError, ValueError, InvalidSignature):
        raise MpcBindingError("independently pinned witness signature required") from None
    return signed["value"]


def _post(action, payload):
    _runtime()
    if action not in {"query", "record"}:
        raise MpcBindingError("only read query/public-result courier transport is available")
    url = urlsplit(settings.MPC_SOLANA_WITNESS_URL)
    if (
        url.scheme != "https"
        or url.hostname not in {"localhost", "127.0.0.1", "::1"}
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in ("", "/")
        or not 1 <= settings.MPC_SOLANA_WITNESS_TIMEOUT_SECONDS <= 5
    ):
        raise MpcBindingError(
            "explicit isolated HTTPS witness destination and bounded timeout required"
        )
    _, expected_key_id, _ = _pin()
    courier = x509.load_pem_x509_certificate(
        Path(settings.MPC_SOLANA_WITNESS_COURIER_CERT).read_bytes()
    )
    _require_role(courier, "courier")  # Reject Life/node credentials BEFORE reading their key.
    context = ssl.create_default_context(cafile=settings.MPC_SOLANA_WITNESS_CA_CERT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(
        settings.MPC_SOLANA_WITNESS_COURIER_CERT, settings.MPC_SOLANA_WITNESS_COURIER_KEY
    )
    body = _canonical(payload)
    if len(body) > 1024 * 1024:
        raise MpcBindingError("bounded public witness payload required")
    connection = http.client.HTTPSConnection(
        url.hostname,
        url.port or 443,
        context=context,
        timeout=settings.MPC_SOLANA_WITNESS_TIMEOUT_SECONDS,
    )
    try:
        connection.connect()
        certificate = x509.load_der_x509_certificate(connection.sock.getpeercert(binary_form=True))
        try:
            _require_role(certificate, "witness")
        except MpcBindingError:
            raise ssl.SSLCertVerificationError(
                "exact installed witness TLS identity required"
            ) from None
        if _point_id(certificate.public_key()) != expected_key_id:
            raise ssl.SSLCertVerificationError("exact installed witness TLS identity required")
        # The detached query or public share leaves only AFTER peer key pinning.
        connection.request(
            "POST",
            f"/v1/witness/{action}",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise requests.HTTPError(f"witness HTTP {response.status}; retain original operation")
        data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise MpcBindingError("witness response exceeds public size bound")
        return json.loads(data)
    finally:
        connection.close()


def query_witness(query):
    """Read with the already pinned class Custody signature, over courier TLS."""
    certificate = x509.load_pem_x509_certificate(Path(settings.MPC_CLIENT_CERT).read_bytes())
    _require_role(certificate, "custody")
    key = serialization.load_pem_private_key(Path(settings.MPC_CLIENT_KEY).read_bytes(), None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or _point_id(key.public_key()) != _point_id(
        certificate.public_key()
    ):
        raise MpcBindingError("original Custody identity key required for a read-only query")
    signed = {"key_id": _point_id(key.public_key()), "value": query}
    signed["signature"] = key.sign(
        _message("WITNESS_QUERY_V1", signed), ec.ECDSA(hashes.SHA256())
    ).hex()
    response = _post("query", signed)
    value = _verify("WITNESS_QUERY_REPLY_V1", response)
    anchor, _, _ = _pin()
    if value["query"] != query or query["anchor_id"] != str(anchor):
        raise MpcBindingError("exact original read-query echo/anchor required")
    return response


def publish_public_result(report):
    """Repeat only authentic original public delivery; never invoke Node.auto."""
    response = _post("record", report)
    value = _verify("WITNESS_ACK_V1", response)
    anchor, _, _ = _pin()
    if (
        value["anchor_id"] != str(anchor)
        or value["value_fingerprint"]
        != hashlib.sha256(_message("WITNESS_PUBLIC_ROUND_V1", report)).hexdigest()
        or type(value["sequence"]) is not int
        or value["sequence"] <= 0
    ):
        raise MpcBindingError("original public-result acknowledgement required")
    return response
