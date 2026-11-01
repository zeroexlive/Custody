"""Disposable legacy demo smoke; synthetic ledger funding and no signing."""

import os
import sys
from decimal import Decimal
from pathlib import Path


def run(database_path):
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mpc_exchange.settings")
    from django.conf import settings

    # Current settings intentionally ignore a SQLite DATABASE_URL path. Replace
    # the engine/name before django.setup; never touch the user's demo database.
    settings.DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": str(Path(database_path).resolve()),
        }
    }
    import django

    django.setup()
    from django.core.management import call_command
    from django.db import transaction

    from custody.identity_registry import RegistryError
    from custody.ledger import (
        clearing_account,
        ensure_accounts,
        lock_user_accounts,
        post_transaction,
        release_withdrawal,
        reserve_withdrawal,
        settle_withdrawal,
        user_balances,
    )
    from custody.models import WithdrawalRequest
    from custody.solana_financial_sessions import allocate_session

    call_command("migrate", interactive=False, verbosity=0)
    owner = "legacy-sqlite-smoke"
    with transaction.atomic():
        ensure_accounts(owner, "SOL")
        accounts = lock_user_accounts(owner, "SOL")
        post_transaction(
            event_key="synthetic-smoke-funding",
            event_type="FIXTURE",
            asset_key="SOL",
            ref_type="Fixture",
            ref_id="not-a-real-deposit",
            postings=[(accounts["AVAILABLE"], Decimal(5)), (clearing_account("SOL"), Decimal(-5))],
        )
        for action in [release_withdrawal, settle_withdrawal]:
            req = WithdrawalRequest.objects.create(
                user_id=owner,
                chain_id="SOL",
                asset_key="SOL",
                to_address="legacy-sqlite-destination",
                amount=Decimal(1),
                status="APPROVED",
            )
            reserve_withdrawal(req)
            action(req)
    assert user_balances(owner, "SOL") == {
        "available": Decimal(4),
        "reserved": Decimal(0),
        "total": Decimal(4),
    }
    try:
        allocate_session(
            reservation_id="unused", tenant_id="unused", selected_signers=[], operator_ref="smoke"
        )
    except RegistryError as exc:
        assert "requires PostgreSQL" in str(exc)
    else:
        raise AssertionError("protected allocation accepted SQLite")
    print("SQLite migration, legacy reserve/release/settle, and PostgreSQL-only allocation: PASS")


if __name__ == "__main__":
    run(sys.argv[1])
