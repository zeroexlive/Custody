"""Privileged operator only. No external account issuance or signing endpoint."""

import json

import requests
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError

from custody.solana_provisioning import approve_claim, register_root, reserve_claim


class Command(BaseCommand):
    help = "Reserve/approve original Solana HOT/DEPOSIT records; does not issue wallets"

    def add_arguments(self, parser):
        actions = parser.add_subparsers(dest="action", required=True)
        for name in ("root", "reserve", "approve"):
            action = actions.add_parser(name)
            action.add_argument("--tenant-id", required=True)
            action.add_argument("--operator-ref", required=True)
            if name == "approve":
                action.add_argument("--reservation-id", required=True)
            else:
                action.add_argument("--keyset-id", required=True)
            if name == "reserve":
                action.add_argument("--principal-id", required=True)
                action.add_argument("--asset-key", required=True)
                action.add_argument("--idempotency-key", required=True)

    def handle(self, *args, **options):
        payload = {key: options[key] for key in ("tenant_id", "operator_ref")}
        action = options["action"]
        if action == "approve":
            payload["reservation_id"] = options["reservation_id"]
            function = approve_claim
        else:
            payload["keyset_id"] = options["keyset_id"]
            function = register_root
            if action == "reserve":
                payload.update(
                    {key: options[key] for key in ("principal_id", "asset_key", "idempotency_key")}
                )
                function = reserve_claim
        try:
            row = function(**payload)
        except (
            ValueError,
            RuntimeError,
            DatabaseError,
            ObjectDoesNotExist,
            requests.RequestException,
        ) as exc:
            raise CommandError(
                "Solana provisioning failed; preserve original IDs and retry after investigation"
            ) from exc
        result = {"id": str(row.pk), "status": row.status, "issued": False}
        if action != "root":
            result.update({"index": row.index, "address": row.address})
        self.stdout.write(json.dumps(result))
