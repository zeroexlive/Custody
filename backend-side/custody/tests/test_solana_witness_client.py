"""Real TLS canaries: no signed query/public report to an unpinned authority.

Runtime selection is patched only to isolate transport; no MPC or ledger claim.
"""

import ssl
import threading
from datetime import datetime, timedelta, timezone
from socketserver import BaseRequestHandler, ThreadingTCPServer
from unittest.mock import patch
from uuid import uuid4

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from custody.solana_witness_client import publish_public_result, query_witness


def identity(root, role, issuer=None, *, key=None):
    root.mkdir(parents=True, mode=0o700)
    key = key or ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)])
    ca = issuer is None
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name if ca else issuer[1].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.UniformResourceIdentifier(f"spiffe://wallet-mpc/{role}"),
                ]
            ),
            False,
        ).add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            False,
        )
    certificate = builder.sign(key if ca else issuer[0], hashes.SHA256())
    (root / "tls.crt").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (root / "tls.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (root / "tls.key").chmod(0o600)
    return key, certificate


@pytest.mark.parametrize("fault", ["wrong_key", "wrong_role", "correct_pin"])
@pytest.mark.parametrize("action", ["query", "record"])
def test_wrong_authority_key_or_role_receives_zero_http_bytes(tmp_path, settings, fault, action):
    issuer = identity(tmp_path / "ca", "ca")
    expected = identity(tmp_path / "installed", "witness", issuer)
    identity(tmp_path / "courier", "courier", issuer)
    identity(tmp_path / "custody", "custody", issuer)
    identity(
        tmp_path / "canary",
        "coordinator" if fault == "wrong_role" else "witness",
        issuer,
        key=expected[0] if fault != "wrong_key" else None,
    )
    seen = bytearray()

    class Handler(BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                while True:
                    data = self.request.recv(4096)
                    if not data:
                        return
                    seen.extend(data)  # Every TLS application byte, including partial HTTP.
                    if b"\r\n\r\n" in seen:
                        header, body = seen.split(b"\r\n\r\n", 1)
                        length = next(
                            int(line.split(b":", 1)[1])
                            for line in header.split(b"\r\n")
                            if line.lower().startswith(b"content-length:")
                        )
                        if len(body) >= length:
                            break
                self.request.sendall(b"HTTP/1.1 500 Canary\r\nContent-Length: 0\r\n\r\n")
            except (OSError, StopIteration):
                return

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(tmp_path / "canary/tls.crt", tmp_path / "canary/tls.key")
    context.load_verify_locations(tmp_path / "ca/tls.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    settings.MPC_SOLANA_WITNESS_URL = f"https://localhost:{server.server_address[1]}"
    settings.MPC_SOLANA_WITNESS_ANCHOR_ID = str(uuid4())
    settings.MPC_SOLANA_WITNESS_CERTIFICATE = str(tmp_path / "installed/tls.crt")
    settings.MPC_SOLANA_WITNESS_CA_CERT = str(tmp_path / "ca/tls.crt")
    settings.MPC_SOLANA_WITNESS_COURIER_CERT = str(tmp_path / "courier/tls.crt")
    settings.MPC_SOLANA_WITNESS_COURIER_KEY = str(tmp_path / "courier/tls.key")
    settings.MPC_CLIENT_CERT = str(tmp_path / "custody/tls.crt")
    settings.MPC_CLIENT_KEY = str(tmp_path / "custody/tls.key")
    try:
        with patch("custody.solana_witness_client._runtime"):
            error = requests.HTTPError if fault == "correct_pin" else ssl.SSLCertVerificationError
            message = "witness HTTP 500" if fault == "correct_pin" else "exact installed witness"
            with pytest.raises(error, match=message):
                if action == "query":
                    query_witness(
                        {
                            "anchor_id": settings.MPC_SOLANA_WITNESS_ANCHOR_ID,
                            "root_identity": "11" * 32,
                            "challenge": "22" * 32,
                            "execution_id": None,
                        }
                    )
                else:
                    # Public delivery must be pinned even before remote
                    # validation of an eventual original node report.
                    publish_public_result({"key_id": "33" * 32, "value": {}, "signature": "00"})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    # Join all request threads before asserting: a late partial write must not
    # evade the negative. Correct-pin controls prove this canary detects HTTP.
    if fault == "correct_pin":
        assert f"POST /v1/witness/{action}".encode() in seen and len(seen) > 0
    else:
        assert len(seen) == 0


@pytest.mark.parametrize("role", ["lifecycle", "signer-a", "custody"])
def test_non_courier_credential_is_rejected_before_private_key_or_network(tmp_path, settings, role):
    from custody.mpc_binding import MpcBindingError

    issuer = identity(tmp_path / "ca", "ca")
    identity(tmp_path / "installed", "witness", issuer)
    identity(tmp_path / "wrong-client", role, issuer)
    settings.MPC_SOLANA_WITNESS_URL = "https://localhost:1"
    settings.MPC_SOLANA_WITNESS_ANCHOR_ID = str(uuid4())
    settings.MPC_SOLANA_WITNESS_CERTIFICATE = str(tmp_path / "installed/tls.crt")
    settings.MPC_SOLANA_WITNESS_COURIER_CERT = str(tmp_path / "wrong-client/tls.crt")
    settings.MPC_SOLANA_WITNESS_COURIER_KEY = str(tmp_path / "MUST-NOT-BE-READ")
    with patch("custody.solana_witness_client._runtime"):
        with pytest.raises(MpcBindingError, match="exact courier leaf"):
            publish_public_result({"key_id": "33" * 32, "value": {}, "signature": "00"})
