"""Privileged public handoff only; no Life/Policy key or private signing route."""

import json
from pathlib import Path

import requests
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError

from custody.solana_claim_registration import (
    begin_current_claim_approval,
    claim_query_request,
    collect_current_claim_evidence,
    complete_claim_registration,
    record_current_claim_evidence,
)


def public_json(path):
    raw = Path(path).read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("bounded public proof file required")
    return json.loads(raw)


class Command(BaseCommand):
    help = "Recover/register exact public Solana Claim evidence; no financial publication"

    def add_arguments(self, parser):
        actions = parser.add_subparsers(dest="action", required=True)
        for name in ("query", "begin", "collect", "record", "complete"):
            item = actions.add_parser(name)
            item.add_argument("--tenant-id", required=True)
            item.add_argument("--operator-ref", required=True)
            if name == "query":
                item.add_argument("--reservation-id", required=True)
                item.add_argument("--attempt-id")
            elif name in {"begin", "complete"}:
                item.add_argument("--challenge", required=True)
                item.add_argument("--evidence", required=True)
                if name == "begin":
                    item.add_argument("--node-certificates", required=True)
            else:
                item.add_argument("--attempt-id", required=True)
                if name == "record":
                    item.add_argument("--evidence", required=True)

    def handle(self, *args, **options):
        arguments = {key: options[key] for key in ("tenant_id", "operator_ref")}
        action = options["action"]
        try:
            if action == "query":
                result = claim_query_request(
                    **arguments,
                    reservation_id=options["reservation_id"],
                    attempt_id=options["attempt_id"],
                )
            else:
                if action in {"begin", "complete"}:
                    arguments.update(
                        challenge=options["challenge"], evidence=public_json(options["evidence"])
                    )
                else:
                    arguments["attempt_id"] = options["attempt_id"]
                    if action == "record":
                        arguments["evidence"] = public_json(options["evidence"])
                if action == "begin":
                    row = begin_current_claim_approval(
                        **arguments,
                        node_certificates_der_hex=public_json(options["node_certificates"]),
                    )
                else:
                    row = {
                        "collect": collect_current_claim_evidence,
                        "record": record_current_claim_evidence,
                        "complete": complete_claim_registration,
                    }[action](**arguments)
                result = {"claim_id": str(row.claim_id), "publication_performed": False}
                if action != "complete":
                    result.update(
                        attempt_id=str(row.pk),
                        status=row.status,
                        command_id=str(row.command_id),
                        approval=row.approval,
                    )
        except (
            OSError,
            ValueError,
            RuntimeError,
            DatabaseError,
            ObjectDoesNotExist,
            requests.RequestException,
        ) as exc:
            raise CommandError(
                "Current Claim handoff failed; retain original Claim/attempt/command IDs"
            ) from exc
        self.stdout.write(json.dumps(result, ensure_ascii=False))
