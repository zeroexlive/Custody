"""Real delayed TLS proves dispatch expiry is checked before any HTTP bytes."""

import ssl
import threading
import time
from datetime import timedelta
from socketserver import BaseRequestHandler, ThreadingTCPServer

import pytest
from django.utils import timezone

from custody.mpc_transport import coordinator_request
from custody.tests.test_solana_witness_client import identity


@pytest.mark.parametrize("expired", [True, False])
def test_delayed_tls_never_releases_expired_dispatch_payload(tmp_path, settings, expired):
    issuer = identity(tmp_path / "ca", "ca")
    identity(tmp_path / "server", "coordinator", issuer)
    identity(tmp_path / "client", "custody", issuer)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(tmp_path / "server/tls.crt", tmp_path / "server/tls.key")
    context.load_verify_locations(tmp_path / "ca/tls.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    seen = bytearray()
    handshakes = []

    class Server(ThreadingTCPServer):
        def get_request(self):
            sock, address = super().get_request()
            time.sleep(0.2)
            connected = context.wrap_socket(sock, server_side=True)
            handshakes.append(True)
            return connected, address

    class Handler(BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                while True:
                    data = self.request.recv(4096)
                    if not data:
                        return
                    seen.extend(data)
                    if b"\r\n\r\n" in seen:
                        header, body = seen.split(b"\r\n\r\n", 1)
                        length = next(
                            int(line.split(b":", 1)[1])
                            for line in header.split(b"\r\n")
                            if line.lower().startswith(b"content-length:")
                        )
                        if len(body) >= length:
                            break
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
            except OSError:
                return

    server = Server(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    settings.MPC_COORDINATOR_URL = f"https://localhost:{server.server_address[1]}"
    settings.MPC_CA_CERT = str(tmp_path / "ca/tls.crt")
    settings.MPC_CLIENT_CERT = str(tmp_path / "client/tls.crt")
    settings.MPC_CLIENT_KEY = str(tmp_path / "client/tls.key")
    settings.MPC_REQUEST_TIMEOUT_SECONDS = 2
    deadline = timezone.now() + timedelta(seconds=0.1 if expired else 2)
    try:
        if expired:
            with pytest.raises(ValueError, match="before HTTP payload"):
                coordinator_request(
                    "POST",
                    "/private-dispatch",
                    json_payload={"intent": "canary"},
                    dispatch_deadline=deadline,
                )
        else:
            assert (
                coordinator_request(
                    "POST",
                    "/private-dispatch",
                    json_payload={"intent": "canary"},
                    dispatch_deadline=deadline,
                )
                == {}
            )
    finally:
        server.shutdown()
        worker.join(timeout=3)
        server.server_close()  # Join all handlers before asserting zero application bytes.
    assert handshakes == [True]
    assert (len(seen) == 0) if expired else (len(seen) > 0)
