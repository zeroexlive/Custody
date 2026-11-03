"""Privileged operator coordinator identity binding; no remote effects or secrets."""

import json

from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError

from custody.solana_coordinator import bind_coordinator


class Command(BaseCommand):
    help = "Permanently bind an original Solana keyset to an installed coordinator identity"

    def add_arguments(self, parser):
        parser.add_argument("action", choices=["bind"])
        parser.add_argument("--keyset-id", required=True)
        parser.add_argument("--operator-ref", required=True)
        parser.add_argument("--tenant-id")

    def handle(self, *args, **options):
        try:
            row = bind_coordinator(
                **{k: options[k] for k in ("keyset_id", "tenant_id", "operator_ref")}
            )
        except (ValueError, RuntimeError, OSError, DatabaseError, ObjectDoesNotExist) as exc:
            raise CommandError(
                "Coordinator binding failed; preserve original IDs and configuration"
            ) from exc
        self.stdout.write(
            json.dumps(
                {
                    "keyset_id": str(row.keyset.keyset_id),
                    "coordinator_key_id": row.coordinator_key_id,
                    "private_work_performed": False,
                }
            )
        )
