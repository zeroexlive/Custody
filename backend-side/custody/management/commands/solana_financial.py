"""Privileged local workflow; operator labels do not authenticate API callers.

Only public evidence and independent Policy signatures are read from files.
The backend never imports a Policy or Lifecycle private key.
"""

import json
from pathlib import Path

import requests
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError

from custody.financial_identity import register_financial_principal
from custody.solana_financial_deposits import (
    register_operator_funding_source,
    scan_financial_wallet,
)
from custody.solana_financial_outbound import broadcast_session, reconcile_finality
from custody.solana_financial_preparation import _snapshot, approve_session, prepare_session
from custody.solana_financial_root import complete_financial_mode, financial_mode_request
from custody.solana_financial_sessions import (
    allocate_session,
    allocate_sweep,
    allocate_withdrawal,
    complete_no_signature,
    request_query,
)
from custody.solana_financial_signing import execute_session, reconcile_session
from custody.solana_financial_wallet import complete_financial_wallet, financial_wallet_request
from custody.solana_token_provisioning import allocate_provision
from custody.solana_witness_client import query_witness


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate public evidence field")
        value[key] = item
    return value


def _public_file(path):
    # Bound the read itself, including a file replaced after stat().
    with Path(path).open("rb") as source:
        content = source.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024:
        raise ValueError("bounded public evidence required")
    value = json.loads(content, object_pairs_hook=_unique_object)
    if not isinstance(value, dict):
        raise ValueError("public evidence object required")
    return value


class Command(BaseCommand):
    help = (
        "Operate protected Solana financial workflows "
        "with explicit treasury and exact-wire approval"
    )

    def add_arguments(self, parser):
        actions = parser.add_subparsers(dest="action", required=True)
        fields = {
            "principal": ["reference", "role"],
            "funding-register": ["address", "reference"],
            "mode-request": ["keyset-id"],
            "mode-complete": ["keyset-id", "evidence"],
            "wallet-request": ["reservation-id"],
            "wallet-complete": ["reservation-id", "evidence"],
            "deposit-scan": ["user-wallet-id"],
            "withdrawal-allocate": ["withdrawal-id", "source-id", "fee-budget-lamports"],
            "sweep-allocate": ["sweep-id", "destination-id", "fee-budget-lamports"],
            "provision-allocate": [
                "reservation-id",
                "idempotency-key",
                "fee-budget-lamports",
                "rent-budget-lamports",
            ],
            "session-allocate": ["reservation-id", "selected-signers"],
            "query": ["session-id", "purpose"],
            "prepare": ["session-id"],
            "approve": ["session-id", "policy-authorization"],
            "execute": ["session-id"],
            "recover": ["session-id"],
            "broadcast": ["session-id"],
            "reconcile": ["session-id"],
            "no-signature": ["session-id"],
        }
        for name, names in fields.items():
            action = actions.add_parser(name)
            action.add_argument("--operator-ref", required=True)
            if name != "funding-register":
                action.add_argument("--tenant-id", required=True)
            for field in names:
                kwargs = {"required": True}
                if field == "role":
                    kwargs["choices"] = ["CUSTOMER", "TREASURY"]
                elif field == "purpose":
                    kwargs["choices"] = ["ADMISSION", "RECOVERY", "TERMINAL"]
                elif field == "selected-signers":
                    kwargs.update(nargs=2, choices=["signer-a", "signer-b", "signer-c"])
                elif field in {
                    "withdrawal-id",
                    "sweep-id",
                    "user-wallet-id",
                    "fee-budget-lamports",
                    "rent-budget-lamports",
                }:
                    kwargs["type"] = int
                action.add_argument("--" + field, **kwargs)
            if name == "withdrawal-allocate":
                action.add_argument("--rent-budget-lamports", type=int, default=0)

    def handle(self, *args, **options):
        try:
            result = self._run(options)
        except (
            OSError,
            ValueError,
            RuntimeError,
            DatabaseError,
            ObjectDoesNotExist,
            requests.RequestException,
        ) as exc:
            raise CommandError(
                "Solana financial action failed; preserve original business/session IDs "
                "and reconcile uncertain outcomes before retrying private execution"
            ) from exc
        self.stdout.write(json.dumps(result, sort_keys=True))

    def _run(self, options):
        action = options["action"]

        def values(*names):
            return {name: options[name] for name in names}

        common = values("operator_ref")
        if action == "funding-register":
            row = register_operator_funding_source(**values("address", "reference"), **common)
            return {"genesis_hash": row.genesis_hash, "address": row.address}
        common.update(values("tenant_id"))
        if action == "principal":
            row = register_financial_principal(**values("reference", "role"), **common)
            return {"principal_id": str(row.pk), "ledger_owner_id": row.ledger_owner_id}
        if action == "mode-request":
            return financial_mode_request(**values("keyset_id"), **common)
        if action == "mode-complete":
            row = complete_financial_mode(
                **values("keyset_id"), evidence=_public_file(options["evidence"]), **common
            )
            return {"keyset_id": str(row.pk), "status": row.status}
        if action == "wallet-request":
            return financial_wallet_request(**values("reservation_id"), **common)
        if action == "wallet-complete":
            row = complete_financial_wallet(
                **values("reservation_id"), evidence=_public_file(options["evidence"]), **common
            )
            return {
                "financial_wallet_id": str(row.pk),
                "status": row.status,
                "role": row.role,
                "address": row.claim.address,
                "user_wallet_id": row.user_wallet_id,
            }
        if action == "deposit-scan":
            result = scan_financial_wallet(**values("user_wallet_id"), **common)
            return {
                "scan_complete": result.scan_complete,
                "confirmed_balance": str(result.confirmed_balance),
                "cursor": result.scan_cursor,
            }
        if action in {"withdrawal-allocate", "sweep-allocate", "provision-allocate"}:
            if action == "withdrawal-allocate":
                row = allocate_withdrawal(
                    **values(
                        "withdrawal_id", "source_id", "fee_budget_lamports", "rent_budget_lamports"
                    ),
                    **common,
                )
            elif action == "sweep-allocate":
                row = allocate_sweep(
                    **values("sweep_id", "destination_id", "fee_budget_lamports"), **common
                )
            else:
                row = allocate_provision(
                    **values(
                        "reservation_id",
                        "idempotency_key",
                        "fee_budget_lamports",
                        "rent_budget_lamports",
                    ),
                    **common,
                )
            return {"reservation_id": str(row.pk), "status": row.status}
        if action == "session-allocate":
            row = allocate_session(**values("reservation_id", "selected_signers"), **common)
        else:
            common.update(values("session_id"))
            if action == "query":
                return request_query(purpose=options["purpose"], **common)
            if action in {"prepare", "approve", "execute", "no-signature"}:
                kwargs = {}
                if action == "approve":
                    kwargs["policy_authorization"] = _public_file(options["policy_authorization"])
                purpose = "TERMINAL" if action == "no-signature" else "ADMISSION"
                needs_query = True
                if action in {"execute", "no-signature"}:
                    snapshot = _snapshot(options["session_id"], options["tenant_id"])
                    needs_query = (
                        snapshot.status == "READY"
                        if action == "execute"
                        else snapshot.status != "NO_SIGNATURE"
                    )
                if needs_query:
                    lease = request_query(purpose=purpose, **common)
                    kwargs.update(
                        challenge=lease["query"]["challenge"],
                        evidence=query_witness(lease["query"]),
                    )
                else:
                    # The service still validates runtime/tenant and its own
                    # terminal state; retries create no query or private work.
                    kwargs.update(challenge=None, evidence={})
                service = {
                    "prepare": prepare_session,
                    "approve": approve_session,
                    "execute": execute_session,
                    "no-signature": complete_no_signature,
                }[action]
                row = service(**kwargs, **common)
            else:
                service = {
                    "recover": reconcile_session,
                    "broadcast": broadcast_session,
                    "reconcile": reconcile_finality,
                }[action]
                attempt = service(**common)
                if action != "recover":
                    return {"attempt_id": attempt.pk, "status": attempt.status}
                row = attempt
        result = {
            "session_id": str(row.pk),
            "crypto_execution_id": str(row.crypto_execution_id),
            "attempt_id": row.attempt_id,
            "status": row.status,
        }
        if action == "prepare":
            # Public immutable content for the independent Policy authority.
            result["policy_content"] = {
                "intent": row.intent,
                "payload_hex": bytes(row.payload).hex(),
            }
        return result
