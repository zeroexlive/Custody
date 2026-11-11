"""Privileged public control handoff, with no Life/Policy key or private route."""

import json

from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError

from custody.management.commands.solana_rotation_inventory import public_json
from custody.models import MpcSolanaRotationSourceQuery
from custody.solana_rotation_sources import (
    accept_source_query,
    request_source_query,
    source_control_archive,
)


class Command(BaseCommand):
    help = "Archive a sealed rotation source's public control proof without publishing it"

    def add_arguments(self, parser):
        parser.add_argument("action", choices=["query", "accept", "archive"])
        for name in ("snapshot-id", "tenant-id", "operator-ref"):
            parser.add_argument("--" + name, required=True)
        parser.add_argument("--rotation-id")
        parser.add_argument("--index", type=int)
        parser.add_argument("--challenge")
        parser.add_argument("--evidence")

    def handle(self, *args, **options):
        try:
            if options["action"] == "query":
                result = request_source_query(
                    snapshot_id=options["snapshot_id"],
                    tenant_id=options["tenant_id"],
                    ordinal=options["index"],
                    rotation_id=options["rotation_id"],
                    operator_ref=options["operator_ref"],
                )
            else:
                # A durable nonce is not permission to select another snapshot.
                MpcSolanaRotationSourceQuery.objects.get(
                    pk=options["challenge"],
                    entry__snapshot_id=options["snapshot_id"],
                    entry__snapshot__pause__root__tenant_id=options["tenant_id"],
                )
                if options["action"] == "accept":
                    row = accept_source_query(
                        challenge=options["challenge"],
                        tenant_id=options["tenant_id"],
                        evidence=public_json(options["evidence"]),
                        operator_ref=options["operator_ref"],
                    )
                    result = dict(challenge=row.pk, status=row.status)
                else:
                    result = source_control_archive(
                        challenge=options["challenge"],
                        tenant_id=options["tenant_id"],
                    )
        except (ValueError, RuntimeError, OSError, DatabaseError, ObjectDoesNotExist) as exc:
            raise CommandError(
                "Source handoff failed; preserve the original snapshot, IDs and proofs"
            ) from exc
        self.stdout.write(json.dumps(result, sort_keys=True))
