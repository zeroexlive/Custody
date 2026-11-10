"""Privileged public inventory handoff; no Life/Policy key or private transport."""

import json
from pathlib import Path

from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError

from custody.models import MpcSolanaRotationInventoryQuery
from custody.solana_rotation_inventory import (
    accept_query,
    begin_inventory,
    export_slice,
    request_query,
)


def public_json(path):
    if path is None:
        raise ValueError("original public input file required")
    data = Path(path).read_bytes()
    if len(data) > 1024 * 1024:
        raise ValueError("bounded public input required")
    return json.loads(data)


class Command(BaseCommand):
    help = "Capture and export a complete paused original-Root source inventory"

    def add_arguments(self, parser):
        parser.add_argument("action", choices=["begin", "query", "accept", "export"])
        for name in ("snapshot-id", "tenant-id", "operator-ref"):
            parser.add_argument("--" + name, required=True)
        parser.add_argument("--pause-id")
        parser.add_argument("--roles")
        parser.add_argument("--purpose", choices=["ROOT", "ENTRY", "SEAL"])
        parser.add_argument("--index", type=int)
        parser.add_argument("--challenge")
        parser.add_argument("--evidence")

    def handle(self, *args, **options):
        try:
            context = {k: options[k] for k in ("snapshot_id", "tenant_id", "operator_ref")}
            if options["action"] == "begin":
                row = begin_inventory(
                    **context,
                    pause_id=options["pause_id"],
                    legacy_roles={} if options["roles"] is None else public_json(options["roles"]),
                )
                result = dict(snapshot_id=str(row.pk), status=row.status)
            elif options["action"] == "query":
                result = request_query(
                    **context, purpose=options["purpose"], ordinal=options["index"]
                )
            elif options["action"] == "accept":
                # The operator-supplied snapshot and durable challenge must agree.
                MpcSolanaRotationInventoryQuery.objects.get(
                    pk=options["challenge"],
                    snapshot_id=options["snapshot_id"],
                    snapshot__pause__root__tenant_id=options["tenant_id"],
                )
                row = accept_query(
                    challenge=options["challenge"],
                    tenant_id=options["tenant_id"],
                    evidence=public_json(options["evidence"]),
                    operator_ref=options["operator_ref"],
                )
                result = dict(
                    snapshot_id=str(row.pk),
                    status=row.status,
                    inventory_fingerprint=row.inventory_fingerprint,
                )
            else:
                result = export_slice(
                    snapshot_id=options["snapshot_id"],
                    tenant_id=options["tenant_id"],
                    start_index=options["index"],
                )
        except (ValueError, RuntimeError, OSError, DatabaseError, ObjectDoesNotExist) as exc:
            raise CommandError(
                "Inventory handoff failed; preserve all original IDs and proofs"
            ) from exc
        self.stdout.write(json.dumps(result, sort_keys=True))
