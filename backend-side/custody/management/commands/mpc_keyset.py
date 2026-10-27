"""Operate public MPC keyset metadata. This command never handles or prints shares."""

import uuid

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from custody.models import MpcKeyset


class Command(BaseCommand):
    help = "Create, inspect, activate, or retire public MPC keyset metadata"

    def add_arguments(self, parser):
        parser.add_argument(
            "action", choices=["create", "import-dkg", "inspect", "activate", "retire"]
        )
        parser.add_argument("--keyset-id")
        parser.add_argument("--algorithm", choices=["CGGMP24_ECDSA", "FROST_ED25519"])
        parser.add_argument("--scope", choices=["EVM", "TRON", "SOLANA", "TON"])
        parser.add_argument("--threshold", type=int, default=2)
        parser.add_argument("--parties", type=int, default=3)

    @transaction.atomic
    def handle(self, *args, **options):
        action = options["action"]
        if action == "create":
            if not options["algorithm"] or not options["scope"]:
                raise CommandError("--algorithm and --scope are required")
            keyset = MpcKeyset.objects.create(
                keyset_id=uuid.uuid4(),
                algorithm=options["algorithm"],
                scope=options["scope"],
                curve="secp256k1" if options["algorithm"] == "CGGMP24_ECDSA" else "ed25519",
                derivation_version=(
                    "frost_keyset_v1" if options["scope"] in {"SOLANA", "TON"} else "cggmp_hd_v1"
                ),
                threshold=options["threshold"],
                party_count=options["parties"],
            )
            self.stdout.write(str(keyset.keyset_id))
            return
        if not options["keyset_id"]:
            raise CommandError("--keyset-id is required")
        queryset = MpcKeyset.objects.all()
        if action != "inspect":
            queryset = queryset.select_for_update()
        keyset = queryset.get(keyset_id=options["keyset_id"])
        if keyset.status == "RETIRED" and action in {"import-dkg", "activate"}:
            raise CommandError("retired keysets cannot be reactivated or import new DKG evidence")
        if action == "inspect":
            self.stdout.write(
                f"{keyset.keyset_id} {keyset.algorithm} "
                f"{keyset.threshold}-of-{keyset.party_count} {keyset.status}"
            )
        elif action in {"import-dkg", "activate"}:
            if keyset.scope in {"EVM", "TRON", "SOLANA", "TON"}:
                from custody.mpc_binding import verify_coordinator_keyset
                from custody.signer_adapter import SelfHostedMpcAdapter

                metadata = SelfHostedMpcAdapter().get_keyset(str(keyset.keyset_id))
                if action == "import-dkg":
                    if keyset.status != "CREATING":
                        raise CommandError("only creating keysets can import DKG evidence")
                    if keyset.dkg_execution_id and (
                        str(keyset.dkg_execution_id) != metadata.get("execution_id")
                        or keyset.public_key != metadata.get("group_public_key")
                        or keyset.dkg_result_fingerprint != metadata.get("result_fingerprint")
                    ):
                        raise CommandError("import cannot replace original DKG identity")
                    keyset.public_key = metadata.get("group_public_key", "")
                    keyset.dkg_execution_id = metadata.get("execution_id")
                    keyset.dkg_result_fingerprint = metadata.get("result_fingerprint", "")
                    keyset.participant_identities = metadata.get("participants", [])
                verify_coordinator_keyset(keyset, metadata)
                if action == "import-dkg":
                    if keyset.scope in {"SOLANA", "TON"}:
                        keyset.dkg_public_evidence = metadata
                    keyset.save()
                    return
            elif action == "import-dkg":
                raise CommandError("only reviewed EVM/TRON CGGMP root keysets can import DKG")
            if not all(
                [
                    keyset.public_key,
                    keyset.dkg_execution_id,
                    keyset.dkg_result_fingerprint,
                    len(keyset.participant_identities) == keyset.party_count,
                ]
            ):
                raise CommandError(
                    "activation requires an imported, verified coordinator DKG result"
                )
            with transaction.atomic():
                MpcKeyset.objects.select_for_update().filter(
                    scope=keyset.scope, active_for_new_wallets=True
                ).update(active_for_new_wallets=False)
                keyset.status = "ACTIVE"
                keyset.active_for_new_wallets = False
                keyset.full_clean()
                keyset.save()
        else:
            if keyset.status == "RETIRED":
                return
            # No authenticated drain/rotation protocol exists yet. A zero observed
            # balance cannot prove safety (late deposits and uncertain broadcasts).
            # Only unused, never-imported metadata may be retired by this command.
            if (
                keyset.status != "CREATING"
                or keyset.active_for_new_wallets
                or keyset.public_key
                or keyset.dkg_execution_id
                or keyset.dkg_result_fingerprint
                or keyset.participant_identities
                or keyset.dkg_public_evidence
                or keyset.network_bindings
                or any(
                    relation.related_model._base_manager.filter(
                        **{relation.field.name: keyset}
                    ).exists()
                    for relation in MpcKeyset._meta.related_objects
                )
            ):
                raise CommandError(
                    "retirement requires a verified drain/rotation protocol; "
                    "only unused, never-imported keyset metadata can be retired"
                )
            keyset.status = "RETIRED"
            keyset.active_for_new_wallets = False
            keyset.retired_at = timezone.now()
            keyset.save()
