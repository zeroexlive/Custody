"""Operator-only mapping; operator_ref is audit attribution, not authentication."""

import json

from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError

from custody.identity_registry import (
    RegistryError,
    register_principal,
    register_tenant,
    resolve_principal,
)


class Command(BaseCommand):
    help = "Register immutable tenant/customer mappings; does not issue wallets or authorize users"

    def add_arguments(self, parser):
        parser.add_argument("action", choices=["tenant", "principal", "resolve"])
        parser.add_argument("--tenant-reference")
        parser.add_argument("--tenant-id")
        parser.add_argument("--customer-ref")
        parser.add_argument("--principal-id")
        parser.add_argument("--operator-ref")

    def handle(self, *args, **options):
        try:
            if options["action"] == "tenant":
                row = register_tenant(
                    reference=options["tenant_reference"], operator_ref=options["operator_ref"]
                )
                result = {"tenant_id": str(row.pk), "reference": row.reference}
            else:
                if not options["tenant_id"]:
                    raise RegistryError("tenant ID is required")
                if options["action"] == "principal":
                    row = register_principal(
                        tenant_id=options["tenant_id"],
                        customer_ref=options["customer_ref"],
                        operator_ref=options["operator_ref"],
                    )
                else:
                    if not options["principal_id"]:
                        raise RegistryError("principal ID is required")
                    row = resolve_principal(
                        tenant_id=options["tenant_id"], principal_id=options["principal_id"]
                    )
                result = {
                    "tenant_id": str(row.tenant_id),
                    "principal_id": str(row.pk),
                    "ledger_owner_id": row.ledger_owner_id,
                    "customer_ref": row.customer_ref,
                }
        except (RegistryError, DatabaseError) as exc:
            raise CommandError(
                "identity registration rejected or busy; preserve the original references and retry"
            ) from exc
        self.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True))
