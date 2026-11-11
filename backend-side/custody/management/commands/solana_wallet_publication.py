"""Privileged local operator entrypoint; audit labels are not API credentials."""

import json
from pathlib import Path

import requests
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError

from custody.solana_issuance import complete_publication, publication_request


class Command(BaseCommand):
    help = (
        "Publish an approved native seeded claim only after its independent witness issuance grant"
    )

    def add_arguments(self, parser):
        actions = parser.add_subparsers(dest="action", required=True)
        for name in ("request", "complete"):
            action = actions.add_parser(name)
            action.add_argument("--tenant-id", required=True)
            action.add_argument("--operator-ref", required=True)
            if name == "request":
                action.add_argument("--reservation-id", required=True)
            else:
                action.add_argument("--issuance-id", required=True)
                action.add_argument("--evidence", required=True)

    def handle(self, *args, **options):
        payload = {key: options[key] for key in ("tenant_id", "operator_ref")}
        try:
            if options["action"] == "request":
                result = publication_request(reservation_id=options["reservation_id"], **payload)
            else:
                path = Path(options["evidence"])
                if path.stat().st_size > 1024 * 1024:
                    raise ValueError("bounded public evidence required")
                wallet = complete_publication(
                    issuance_id=options["issuance_id"],
                    evidence=json.loads(path.read_bytes()),
                    **payload,
                )
                result = {
                    "wallet_id": wallet.pk,
                    "issuance_id": options["issuance_id"],
                    "reservation_id": str(wallet.solana_claim_id),
                    "address": wallet.deposit_address,
                    "status": wallet.status,
                    "issued": True,
                }
        except (
            OSError,
            ValueError,
            RuntimeError,
            DatabaseError,
            ObjectDoesNotExist,
            requests.RequestException,
        ) as exc:
            raise CommandError(
                "Native publication failed; preserve original issuance ID and investigate"
            ) from exc
        self.stdout.write(json.dumps(result))
