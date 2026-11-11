"""Explicit local allocation fence; no witness or private-signing authority."""

import json

from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError

from custody.solana_allocation_pause import pause_allocation


class Command(BaseCommand):
    help = "Permanently pause local allocation on an original Solana source Root"

    def add_arguments(self, parser):
        for name in ("keyset-id", "tenant-id", "pause-id", "operator-ref"):
            parser.add_argument("--" + name, required=True)

    def handle(self, *args, **options):
        try:
            row = pause_allocation(
                **{k: options[k] for k in ("keyset_id", "tenant_id", "pause_id", "operator_ref")}
            )
        except (ValueError, RuntimeError, DatabaseError, ObjectDoesNotExist) as exc:
            raise CommandError("Allocation pause failed; preserve original IDs and holds") from exc
        self.stdout.write(
            json.dumps(
                {
                    "pause_id": str(row.pk),
                    "keyset_id": str(row.root.keyset.keyset_id),
                    "frontier": str(row.frontier),
                    "witness_freeze_performed": False,
                    "private_work_performed": False,
                }
            )
        )
