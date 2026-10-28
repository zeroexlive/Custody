"""Standalone privileged-operator registry. No external caller authorization.

Opaque references use exact UTF-8 code points and case (C database collation).
No case folding, Unicode normalization, ownership backfill, ledger or wallet write.
"""

from uuid import UUID, uuid4

from django.db import connection, transaction

from .models import AdminActionLog, CustodyPrincipal, CustodyTenant


class RegistryError(ValueError):
    pass


def _text(value, name):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 64
        or value != value.strip(" \t\r\n\f\v")
        or "\0" in value
    ):
        raise RegistryError(f"invalid {name}")
    return value


def _standalone():
    if connection.vendor != "postgresql":
        raise RegistryError("identity registration requires PostgreSQL")
    if connection.in_atomic_block or not connection.get_autocommit():
        raise RegistryError("identity registration requires a standalone transaction")
    with connection.cursor() as cursor:
        cursor.execute("SHOW transaction_isolation")
        if cursor.fetchone()[0] != "read committed":
            raise RegistryError("identity registration requires READ COMMITTED")


def _uuid(value):
    try:
        result = UUID(str(value))
        if result.int == 0:
            raise ValueError
        return result
    except (ValueError, TypeError, AttributeError):
        raise RegistryError("invalid registry identity") from None


def register_tenant(*, reference, operator_ref):
    _standalone()
    reference = _text(reference, "tenant reference")
    operator_ref = _text(operator_ref, "operator audit reference")
    with transaction.atomic():
        tenant, created = CustodyTenant.objects.get_or_create(reference=reference)
        if created:
            # Mandatory atomic audit. The legacy helper is best-effort and has
            # optional external hooks; neither behavior belongs to this registry.
            AdminActionLog.objects.create(
                actor_id=operator_ref,
                action_type="TENANT_REGISTER",
                entity_type="custody_tenant",
                entity_id=str(tenant.pk),
                metadata={"reference": reference, "authority": "privileged_operator"},
            )
        return tenant


def register_principal(*, tenant_id, customer_ref, operator_ref):
    _standalone()
    customer_ref = _text(customer_ref, "customer reference")
    operator_ref = _text(operator_ref, "operator audit reference")
    tenant_id = _uuid(tenant_id)
    with transaction.atomic():
        try:
            tenant = CustodyTenant.objects.select_for_update().get(pk=tenant_id)
        except CustodyTenant.DoesNotExist:
            raise RegistryError("unknown tenant") from None
        principal, created = CustodyPrincipal.objects.get_or_create(
            tenant=tenant, customer_ref=customer_ref, defaults={"principal_id": uuid4()}
        )
        if created:
            AdminActionLog.objects.create(
                actor_id=operator_ref,
                action_type="PRINCIPAL_REGISTER",
                entity_type="custody_principal",
                entity_id=str(principal.pk),
                metadata={
                    "tenant_id": str(tenant.pk),
                    "customer_ref": customer_ref,
                    "ledger_owner_id": principal.ledger_owner_id,
                    "authority": "privileged_operator",
                },
            )
        return principal


def resolve_principal(*, tenant_id, principal_id):
    if connection.vendor != "postgresql":
        raise RegistryError("identity resolution requires PostgreSQL")
    tenant_id, principal_id = _uuid(tenant_id), _uuid(principal_id)
    try:
        return CustodyPrincipal.objects.select_related("tenant").get(
            tenant_id=tenant_id, pk=principal_id
        )
    except CustodyPrincipal.DoesNotExist:
        raise RegistryError("principal is unavailable in this tenant") from None
