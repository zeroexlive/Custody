"""Explicit installed coordinator routes for original Solana keysets.

Binding is a trusted operator assertion of service identity, not proof learned
from signer receipts. HTTP/TLS credentials remain installed configuration. A
permanent binding never falls back to the mutable global coordinator.
"""

import hashlib
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.db import connection, transaction

from .identity_registry import _standalone, _text, _uuid
from .models import AdminActionLog, MpcKeyset, MpcSolanaCoordinatorBinding, MpcSolanaRoot
from .mpc_binding import MpcBindingError
from .mpc_transport import CoordinatorRoute, coordinator_request, coordinator_tls_context
from .signer_adapter import SelfHostedMpcAdapter

FIELDS = {"url", "coordinator_certificate", "ca_certificate", "client_certificate", "client_key"}


def _configured():
    mapping = settings.MPC_SOLANA_COORDINATOR_ROUTES
    try:
        if not isinstance(mapping, dict):
            raise ValueError
        for key, value in mapping.items():
            if (
                not isinstance(key, str)
                or str(UUID(key)) != key
                or not UUID(key).int
                or not isinstance(value, dict)
                or set(value) != FIELDS
                or any(not isinstance(v, str) or not v for v in value.values())
            ):
                raise ValueError
        return mapping
    except (TypeError, ValueError, AttributeError):
        raise MpcBindingError(
            "invalid independently installed Solana coordinator route map"
        ) from None


def _installed(keyset_id):
    from .solana_witness_client import _require_role

    try:
        config = _configured()[str(keyset_id)]
        url = urlsplit(config["url"])
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.path not in ("", "/")
            or url.query
            or url.fragment
            or len(config["url"]) > 512
            or any(char.isspace() for char in config["url"])
            or (url.port is not None and not 1 <= url.port <= 65535)
        ):
            raise ValueError
        raw = Path(config["coordinator_certificate"]).read_bytes()
        if len(raw) > 32768:
            raise ValueError
        certificate = x509.load_pem_x509_certificate(raw)
        _require_role(certificate, "coordinator")
        key = certificate.public_key()
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise ValueError
        identity = hashlib.sha256(
            key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()
        route = CoordinatorRoute(
            url=config["url"].rstrip("/"),
            coordinator_key_id=identity,
            ca_certificate=config["ca_certificate"],
            client_certificate=config["client_certificate"],
            client_key=config["client_key"],
        )
        client = x509.load_pem_x509_certificate(Path(route.client_certificate).read_bytes())
        _require_role(client, "custody")
        coordinator_tls_context(route)  # Validate installed credentials before any dispatch CAS.
        return route
    except (OSError, KeyError, TypeError, ValueError, x509.ExtensionNotFound):
        raise MpcBindingError("valid independently installed coordinator route required") from None


def resolve_route(keyset_id):
    keyset = MpcKeyset.objects.get(keyset_id=_uuid(keyset_id))
    if keyset.scope != "SOLANA":
        raise MpcBindingError("cohort routing is scoped to original Solana keysets")
    binding = MpcSolanaCoordinatorBinding.objects.filter(keyset=keyset).first()
    if binding is None:
        if keyset.solana_coordinator_required or str(keyset.keyset_id) in _configured():
            raise MpcBindingError("explicit original coordinator binding is required before RPC")
        return None
    if not keyset.solana_coordinator_required:
        raise MpcBindingError("coordinator binding and original admission marker disagree")
    route = _installed(keyset.keyset_id)
    if (route.url, route.coordinator_key_id) != (binding.url, binding.coordinator_key_id):
        raise MpcBindingError("original coordinator URL/public identity cannot change")
    return route


def preflight_route(keyset_id):
    route = resolve_route(keyset_id)
    coordinator_tls_context() if route is None else coordinator_tls_context(route)
    return route


def bind_coordinator(*, keyset_id, operator_ref, tenant_id=None):
    _standalone()
    if connection.vendor != "postgresql":
        raise MpcBindingError("permanent coordinator routing requires PostgreSQL")
    from .solana_provisioning import _runtime, _validate_root, _verify

    _runtime()
    keyset_id, operator_ref = _uuid(keyset_id), _text(operator_ref, "operator audit reference")
    tenant_id = None if tenant_id is None else _uuid(tenant_id)
    route = _installed(keyset_id)
    with transaction.atomic():
        keyset = MpcKeyset.objects.select_for_update().get(keyset_id=keyset_id)
        root = (
            MpcSolanaRoot.objects.select_for_update()
            .select_related("keyset")
            .filter(keyset=keyset)
            .first()
        )
        if root is not None:
            if root.tenant_id != tenant_id or root.status != "APPROVED":
                raise MpcBindingError(
                    "original approved Root and tenant required for legacy binding"
                )
            _validate_root(root)
            _verify("root", root.statement, root.evidence)
        elif tenant_id is not None:
            raise MpcBindingError("a new keyset route does not assign a tenant or create a Root")
        existing = MpcSolanaCoordinatorBinding.objects.filter(keyset=keyset).first()
        if existing:
            if (existing.url, existing.coordinator_key_id) != (route.url, route.coordinator_key_id):
                raise MpcBindingError("original coordinator binding cannot be replaced")
            if not keyset.solana_coordinator_required:
                raise MpcBindingError("original coordinator admission marker is missing")
            return existing
        with connection.cursor() as cursor:
            cursor.execute("SELECT custody_sol_coordinator_bindable(%s)", [keyset.pk])
            if not cursor.fetchone()[0]:
                raise MpcBindingError(
                    "bind before DKG import or recover all tracked legacy private work first"
                )
        row = MpcSolanaCoordinatorBinding.objects.create(
            keyset=keyset, url=route.url, coordinator_key_id=route.coordinator_key_id
        )
        keyset.solana_coordinator_required = True
        keyset.save(update_fields=["solana_coordinator_required"])
        AdminActionLog.objects.create(
            actor_id=operator_ref,
            action_type="SOLANA_COORDINATOR_BIND",
            entity_type="mpc_keyset",
            entity_id=str(keyset.keyset_id),
            metadata={"authority": "privileged_operator"},
        )
        return row


class ScopedSolanaAdapter(SelfHostedMpcAdapter):
    def __init__(self, keyset_id):
        self.keyset_id = str(_uuid(keyset_id))
        self.route = resolve_route(self.keyset_id)

    def _statement_scope(self, keyset_id, statement, *, claim):
        try:
            root = statement["root"] if claim else statement
            if (
                str(_uuid(keyset_id)) != self.keyset_id
                or root["dkg"]["keyset_id"] != self.keyset_id
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise MpcBindingError(
                "statement differs from original coordinator keyset scope"
            ) from None

    def _solana_provisioning(self, kind, keyset_id, statement):
        self._statement_scope(keyset_id, statement, claim=kind != "root")
        return super()._solana_provisioning(kind, keyset_id, statement)

    def approve_current_solana_claim(self, keyset_id, approval):
        try:
            statement = approval["statement"]
        except (KeyError, TypeError):
            raise MpcBindingError("original current Claim approval statement required") from None
        self._statement_scope(keyset_id, statement, claim=True)
        return super().approve_current_solana_claim(keyset_id, approval)

    def _request(self, method, path, **kwargs):
        prefix = "/v1/keysets/" + self.keyset_id
        allowed = {
            ("GET", prefix),
            ("POST", prefix + "/solana-seeded-root"),
            ("POST", prefix + "/solana-seeded-claims"),
            ("POST", prefix + "/solana-current-claims"),
        }
        if (method, path) not in allowed:
            raise MpcBindingError("request differs from original keyset coordinator scope")
        # Resolve again to detect an explicit legacy binding installed since this
        # public adapter was created. Never silently switch a captured route.
        if resolve_route(self.keyset_id) != self.route:
            raise MpcBindingError("coordinator binding changed; retain original IDs and retry")
        return coordinator_request(
            method,
            path,
            json_payload=kwargs.get("json"),
            params=kwargs.get("params"),
            route=self.route,
        )


def solana_adapter(keyset_id):
    return ScopedSolanaAdapter(keyset_id)
