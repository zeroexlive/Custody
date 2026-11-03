"""Explicit operator financial classification, not caller authentication.

Customer declaration preserves an existing generated owner and its history.
Treasury registration creates a fresh owner; it can never relabel a customer.
No role is inferred from a reference, wallet class or ledger balance.
"""

from django.db import transaction

from .identity_registry import RegistryError, _standalone, _text, _uuid
from .models import AdminActionLog, CustodyPrincipal, CustodyPrincipalRole, CustodyTenant


def register_financial_principal(*, tenant_id, reference, role, operator_ref):
    _standalone()
    tenant_id = _uuid(tenant_id)
    reference = _text(reference, "principal reference")
    operator_ref = _text(operator_ref, "operator audit reference")
    if role not in {"CUSTOMER", "TREASURY"}:
        raise RegistryError("explicit CUSTOMER or TREASURY role required")
    with transaction.atomic():
        try:
            tenant = CustodyTenant.objects.select_for_update().get(pk=tenant_id)
        except CustodyTenant.DoesNotExist:
            raise RegistryError("unknown tenant") from None
        principal = (
            CustodyPrincipal.objects.select_for_update()
            .filter(tenant=tenant, customer_ref=reference)
            .first()
        )
        if principal is not None:
            original = CustodyPrincipalRole.objects.filter(principal=principal).first()
            if original is not None:
                if original.role != role:
                    raise RegistryError("original financial principal role cannot change")
                return principal
            if role == "TREASURY":
                raise RegistryError("treasury registration requires a fresh principal reference")
        else:
            principal = CustodyPrincipal.objects.create(tenant=tenant, customer_ref=reference)
            AdminActionLog.objects.create(
                actor_id=operator_ref,
                action_type="PRINCIPAL_REGISTER",
                entity_type="custody_principal",
                entity_id=str(principal.pk),
                metadata={
                    "tenant_id": str(tenant.pk),
                    "customer_ref": reference,
                    "ledger_owner_id": principal.ledger_owner_id,
                    "authority": "privileged_operator",
                },
            )
        CustodyPrincipalRole.objects.create(principal=principal, role=role)
        AdminActionLog.objects.create(
            actor_id=operator_ref,
            action_type="PRINCIPAL_FINANCIAL_ROLE",
            entity_type="custody_principal",
            entity_id=str(principal.pk),
            metadata={
                "tenant_id": str(tenant.pk),
                "role": role,
                "authority": "privileged_operator",
            },
        )
        return principal
