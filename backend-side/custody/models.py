"""Custody state and authoritative financial-ledger models.

Models
------
- UserWallet      : user_id -> network -> derivation_path -> deposit EOA address
- Deposit         : parsed on-chain deposit events (indexer-driven)
- WithdrawalRequest : user-initiated withdrawal, gated by admin approval
- HotWallet       : pre-determined custody hot wallet address per network
- SweepJob        : EOA -> hot wallet sweep state machine
- AdminActionLog  : immutable audit trail

Status enums are defined inline. Unique constraints enforce idempotency for
sweeps/withdrawals (see Meta). Indexes support fast lookups by address/user.
"""

from __future__ import annotations

import uuid

from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q


class RegistryIdentityQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("registry identity is immutable")

    def delete(self):
        raise ValueError("registry identity cannot be deleted")


class RegistryIdentity(models.Model):
    """Operator-managed identity only, not caller authentication or a balance."""

    created_at = models.DateTimeField(auto_now_add=True)
    objects = RegistryIdentityQuerySet.as_manager()

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("registry identity is immutable")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("registry identity cannot be deleted")


class CustodyTenant(RegistryIdentity):
    tenant_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # PostgreSQL's byte-exact C collation is installed by migration 0033.
    # Leave portable state unqualified so the legacy SQLite demo still migrates.
    reference = models.CharField(max_length=64, unique=True)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=~Q(reference=""), name="custody_tenant_ref_required"),
        ]


class CustodyPrincipal(RegistryIdentity):
    principal_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(CustodyTenant, on_delete=models.PROTECT)
    customer_ref = models.CharField(max_length=64)
    ledger_owner_id = models.CharField(max_length=64, unique=True, editable=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "customer_ref"], name="uq_tenant_customer_ref"
            ),
            models.CheckConstraint(
                condition=~Q(customer_ref=""), name="custody_principal_ref_required"
            ),
        ]

    def save(self, *args, **kwargs):
        expected = f"p1:{self.principal_id}"
        if self.ledger_owner_id and self.ledger_owner_id != expected:
            raise ValidationError("ledger owner must be generated from the original principal UUID")
        self.ledger_owner_id = expected
        return super().save(*args, **kwargs)


class CustodyPrincipalRole(RegistryIdentity):
    """Explicit immutable financial role; opaque references never imply a role."""

    principal = models.OneToOneField(CustodyPrincipal, on_delete=models.PROTECT, primary_key=True)
    role = models.CharField(
        max_length=16, choices=[("CUSTOMER", "CUSTOMER"), ("TREASURY", "TREASURY")]
    )

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(role__in=["CUSTOMER", "TREASURY"]),
                name="custody_principal_financial_role",
            ),
        ]


class Asset(models.Model):
    """Authoritative custody capability record for a reviewed asset.

    Token metadata alone does not provide custody support. Token capability
    flags remain disabled until a reviewed Phase 5 implementation exists.
    """

    asset_key = models.CharField(max_length=32, unique=True)  # "USDT-BSC"
    # PostgreSQL freezes this at first ledger-account creation. Display and
    # capability changes remain available; financial identity cannot be reused.
    financial_identity_locked = models.BooleanField(default=False, editable=False)
    chain_id = models.CharField(max_length=16, db_index=True)  # "BSC"
    symbol = models.CharField(max_length=16)
    decimals = models.PositiveIntegerField(default=18)
    is_native = models.BooleanField(default=False)
    contract_address = models.CharField(max_length=128, null=True, blank=True)
    TOKEN_STANDARDS = [(value, value) for value in ("ERC20", "TRC20", "SPL", "TEP74")]
    token_standard = models.CharField(max_length=8, choices=TOKEN_STANDARDS, null=True, blank=True)
    metadata_verified_at = models.DateTimeField(null=True, blank=True)
    metadata_fingerprint = models.CharField(max_length=64, blank=True, default="")
    deposit_threshold = models.DecimalField(max_digits=40, decimal_places=18, null=True, blank=True)
    enabled = models.BooleanField(default=True)
    deposit_supported = models.BooleanField(default=True)
    withdrawal_supported = models.BooleanField(default=True)
    sweep_supported = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=(
                    Q(is_native=True, token_standard__isnull=True)
                    | Q(is_native=False, token_standard__isnull=False)
                    | Q(
                        is_native=False,
                        token_standard__isnull=True,
                        deposit_supported=False,
                        withdrawal_supported=False,
                        sweep_supported=False,
                    )
                ),
                name="asset_native_token_standard_shape",
            ),
            models.CheckConstraint(
                condition=Q(is_native=False) | Q(contract_address__isnull=True),
                name="asset_native_has_no_contract",
            ),
            models.UniqueConstraint(
                fields=["chain_id", "contract_address", "token_standard"],
                condition=Q(is_native=False, enabled=True),
                name="uq_active_token_identity",
            ),
            models.UniqueConstraint(
                fields=["chain_id"], condition=Q(is_native=True), name="uq_native_asset_per_chain"
            ),
            models.UniqueConstraint(
                fields=["chain_id", "contract_address", "token_standard"],
                condition=Q(is_native=False, financial_identity_locked=True),
                name="uq_populated_token_identity",
            ),
        ]

    def clean(self):
        super().clean()
        if self.is_native:
            if self.token_standard or self.contract_address:
                raise ValidationError("native assets cannot have token metadata")
        elif not self.token_standard or not self.contract_address:
            raise ValidationError("tokens require a standard and contract/mint")

    def save(self, *args, **kwargs):
        if self.pk:
            old = (
                type(self)
                .objects.filter(pk=self.pk)
                .values("chain_id", "contract_address", "decimals", "token_standard")
                .first()
            )
            identity = (self.chain_id, self.contract_address, self.decimals, self.token_standard)
            if old and identity != tuple(old[key] for key in old):
                self.metadata_verified_at = None
                self.metadata_fingerprint = ""
                if kwargs.get("update_fields") is not None:
                    kwargs["update_fields"] = set(kwargs["update_fields"]) | {
                        "metadata_verified_at",
                        "metadata_fingerprint",
                    }
        return super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"Asset({self.asset_key},{self.symbol})"


class MpcKeyset(models.Model):
    """Public MPC metadata; signer shares must never be stored here."""

    ALGORITHMS = [("CGGMP24_ECDSA", "CGGMP24_ECDSA"), ("FROST_ED25519", "FROST_ED25519")]
    STATUSES = [("CREATING", "CREATING"), ("ACTIVE", "ACTIVE"), ("RETIRED", "RETIRED")]
    SCOPES = [(value, value) for value in ("EVM", "TRON", "SOLANA", "TON")]
    keyset_id = models.UUIDField(unique=True)
    algorithm = models.CharField(max_length=32, choices=ALGORITHMS)
    curve = models.CharField(max_length=16)
    scope = models.CharField(max_length=16, choices=SCOPES)
    threshold = models.PositiveSmallIntegerField(default=2)
    party_count = models.PositiveSmallIntegerField(default=3)
    public_key = models.TextField(blank=True)
    derivation_version = models.CharField(max_length=32)
    dkg_execution_id = models.UUIDField(null=True, blank=True, unique=True)
    dkg_result_fingerprint = models.CharField(max_length=64, blank=True, default="")
    participant_identities = models.JSONField(default=list, blank=True)
    dkg_public_evidence = models.JSONField(default=dict, blank=True)
    network_bindings = models.JSONField(default=dict, blank=True, editable=False)
    status = models.CharField(max_length=16, choices=STATUSES, default="CREATING")
    active_for_new_wallets = models.BooleanField(default=False)
    solana_coordinator_required = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(threshold__gte=2)
                & models.Q(party_count__gte=models.F("threshold")),
                name="mpc_keyset_valid_threshold",
            ),
            models.UniqueConstraint(
                fields=["scope"],
                condition=models.Q(active_for_new_wallets=True),
                name="uq_active_mpc_keyset_per_scope",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(
                        scope__in=["EVM", "TRON"],
                        algorithm="CGGMP24_ECDSA",
                        curve="secp256k1",
                        derivation_version="cggmp_hd_v1",
                    )
                    | models.Q(
                        scope__in=["SOLANA", "TON"],
                        algorithm="FROST_ED25519",
                        curve="ed25519",
                        derivation_version="frost_keyset_v1",
                    )
                ),
                name="mpc_keyset_scope_algorithm_shape",
            ),
            models.CheckConstraint(
                condition=~models.Q(scope="TON", active_for_new_wallets=True),
                name="ton_root_no_auto_provisioning",
            ),
            models.CheckConstraint(
                condition=~models.Q(scope="SOLANA", active_for_new_wallets=True),
                name="solana_root_no_auto_provisioning",
            ),
        ]

    def clean(self):
        super().clean()
        expected = {
            "EVM": ("CGGMP24_ECDSA", "secp256k1", "cggmp_hd_v1"),
            "TRON": ("CGGMP24_ECDSA", "secp256k1", "cggmp_hd_v1"),
            "SOLANA": ("FROST_ED25519", "ed25519", "frost_keyset_v1"),
            "TON": ("FROST_ED25519", "ed25519", "frost_keyset_v1"),
        }
        if self.scope and (self.algorithm, self.curve, self.derivation_version) != expected.get(
            self.scope
        ):
            raise ValidationError("algorithm, curve, and derivation version do not match scope")

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class MpcSolanaCoordinatorBinding(models.Model):
    """Permanent operator-selected coordinator identity for one original keyset."""

    keyset = models.OneToOneField(MpcKeyset, on_delete=models.PROTECT, primary_key=True)
    url = models.CharField(max_length=512)
    coordinator_key_id = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)


class MpcSolanaRoot(models.Model):
    """Durable original dedication intent. APPROVED is not a spending grant."""

    keyset = models.OneToOneField(MpcKeyset, on_delete=models.PROTECT, primary_key=True)
    tenant = models.ForeignKey(CustodyTenant, on_delete=models.PROTECT)
    statement = models.JSONField()
    network_identity = models.JSONField()
    dkg_public_evidence = models.JSONField()
    base_address = models.CharField(max_length=44, unique=True)
    status = models.CharField(max_length=16, default="PENDING")
    evidence = models.JSONField(default=dict)
    # Set only at original creation; the Root guard makes it immutable.
    receipt_pins_reserved = models.BooleanField(default=False)
    # Includes the exhausted sentinel 2**63 after the final signed-bigint index.
    next_index = models.DecimalField(max_digits=20, decimal_places=0, default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(next_index__gte=0, next_index__lte=9223372036854775808),
                name="sol_root_index_capacity",
            ),
            models.CheckConstraint(
                condition=Q(status="PENDING", evidence={})
                | (Q(status="APPROVED") & ~Q(evidence={})),
                name="sol_root_approval_shape",
            ),
        ]


class MpcSolanaAllocationPause(models.Model):
    """Permanent local allocator fence; not a witness freeze or migration grant."""

    pause_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    root = models.OneToOneField(MpcSolanaRoot, on_delete=models.PROTECT)
    frontier = models.DecimalField(max_digits=20, decimal_places=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(frontier__gte=0, frontier__lte=9223372036854775808),
                name="sol_pause_frontier_capacity",
            ),
        ]


class MpcSolanaReceiptPins(models.Model):
    """Immutable installed public identities for this original Root's receipts."""

    root = models.OneToOneField(MpcSolanaRoot, on_delete=models.PROTECT, primary_key=True)
    source = models.CharField(max_length=20)
    certificates_der_hex = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(source__in=["RESERVATION", "ARCHIVAL_IMPORT"]),
                name="sol_receipt_pin_source",
            ),
        ]


class MpcSolanaFinancialRoot(models.Model):
    """Durable clean-Root mode import; neither a wallet nor financial authority."""

    root = models.OneToOneField(MpcSolanaRoot, on_delete=models.PROTECT, primary_key=True)
    witness_anchor_id = models.UUIDField()
    witness_key_id = models.CharField(max_length=64)
    query_challenge = models.CharField(max_length=64)
    query_expires_at = models.DateTimeField()
    status = models.CharField(max_length=16, default="PENDING")
    activation_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    command_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    evidence = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(status="PENDING", evidence={})
                | (Q(status="VERIFIED") & ~Q(evidence={})),
                name="sol_financial_root_evidence_shape",
            ),
        ]


class MpcSolanaClaim(models.Model):
    """Immutable owner/asset/index reservation, never an issued UserWallet."""

    reservation_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    root = models.ForeignKey(MpcSolanaRoot, on_delete=models.PROTECT)
    principal = models.ForeignKey(CustodyPrincipal, on_delete=models.PROTECT)
    asset = models.ForeignKey(Asset, on_delete=models.PROTECT)
    asset_namespace = models.CharField(max_length=44)
    idempotency_key = models.CharField(max_length=128)
    index = models.PositiveBigIntegerField()
    statement = models.JSONField()
    address = models.CharField(max_length=44)
    status = models.CharField(max_length=16, default="PENDING")
    evidence = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["root", "index"], name="uq_sol_claim_index"),
            models.UniqueConstraint(fields=["root", "idempotency_key"], name="uq_sol_claim_retry"),
            models.UniqueConstraint(
                fields=["root", "principal", "asset_namespace"], name="uq_sol_claim_owner_asset"
            ),
            models.UniqueConstraint(fields=["root", "address"], name="uq_sol_claim_address"),
            models.CheckConstraint(
                condition=Q(index__lte=9223372036854775807), name="sol_claim_index_capacity"
            ),
            models.CheckConstraint(
                condition=Q(status="PENDING", evidence={})
                | (Q(status="APPROVED") & ~Q(evidence={})),
                name="sol_claim_approval_shape",
            ),
        ]


class MpcSolanaIssuance(models.Model):
    """Original publication intent; independent witness permission is mandatory."""

    issuance_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    claim = models.OneToOneField(MpcSolanaClaim, on_delete=models.PROTECT)
    witness_anchor_id = models.UUIDField()
    witness_key_id = models.CharField(max_length=64)
    query_challenge = models.CharField(max_length=64)
    query_expires_at = models.DateTimeField()
    status = models.CharField(max_length=16, default="PENDING")
    evidence = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(status="PENDING", evidence={})
                | (Q(status="WITNESSED") & ~Q(evidence={})),
                name="sol_issuance_evidence_shape",
            ),
        ]


class MpcSolanaFinancialWallet(models.Model):
    """Typed native publication membership, not a balance or signing grant."""

    claim = models.OneToOneField(MpcSolanaClaim, on_delete=models.PROTECT, primary_key=True)
    mode = models.ForeignKey(MpcSolanaFinancialRoot, on_delete=models.PROTECT)
    issuance = models.OneToOneField(MpcSolanaIssuance, on_delete=models.PROTECT)
    role = models.CharField(
        max_length=24,
        choices=[("CUSTOMER_DEPOSIT", "CUSTOMER_DEPOSIT"), ("TENANT_TREASURY", "TENANT_TREASURY")],
    )
    user_wallet = models.OneToOneField(
        "UserWallet",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="solana_financial_membership",
    )
    status = models.CharField(max_length=16, default="PENDING")
    evidence = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(status="PENDING", user_wallet__isnull=True, evidence={})
                | (
                    Q(status="ACTIVE")
                    & ~Q(evidence={})
                    & (
                        Q(role="CUSTOMER_DEPOSIT", user_wallet__isnull=False)
                        | Q(role="TENANT_TREASURY", user_wallet__isnull=True)
                    )
                ),
                name="sol_financial_wallet_state",
            ),
            models.CheckConstraint(
                condition=Q(role__in=["CUSTOMER_DEPOSIT", "TENANT_TREASURY"]),
                name="sol_financial_wallet_role",
            ),
        ]


class MpcProvisioningRoot(models.Model):
    """Immutable allocation namespace, not proof of HD capability or spendability.

    One original root has one network, ownership scope and deposit purpose.
    Warm/Cold namespaces await their independently enforceable signing workflows.
    """

    keyset = models.OneToOneField(MpcKeyset, on_delete=models.PROTECT, primary_key=True)
    ownership_scope = models.CharField(max_length=64)
    chain_id = models.CharField(max_length=16)
    purpose = models.CharField(max_length=16, default="DEPOSIT")
    wallet_class = models.CharField(max_length=8, default="HOT")
    derivation_version = models.CharField(max_length=48, default="cggmp_slip10_nonhardened_v1")
    root_identity = models.JSONField()
    dkg_public_evidence = models.JSONField()
    next_index = models.PositiveBigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(
                    purpose="DEPOSIT",
                    wallet_class="HOT",
                    derivation_version="cggmp_slip10_nonhardened_v1",
                ),
                name="mpc_provisioning_reviewed_shape",
            ),
            models.CheckConstraint(
                condition=Q(next_index__lte=2147483648),
                name="mpc_provisioning_index_capacity",
            ),
            models.CheckConstraint(
                condition=~Q(ownership_scope=""), name="mpc_provisioning_owner_required"
            ),
        ]


class MpcDerivationReservation(models.Model):
    """Immutable path assignment. Its custody account owns the issuance lifecycle."""

    reservation_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    root = models.ForeignKey(MpcProvisioningRoot, on_delete=models.PROTECT)
    customer_ref = models.CharField(max_length=64)
    idempotency_key = models.CharField(max_length=128)
    child_index = models.PositiveBigIntegerField()
    derivation_path = models.CharField(max_length=64)
    status = models.CharField(max_length=16, default="RESERVED")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["root", "child_index"], name="uq_mpc_reserved_index"),
            models.UniqueConstraint(
                fields=["root", "idempotency_key"], name="uq_mpc_reservation_retry"
            ),
            models.UniqueConstraint(
                fields=["root", "derivation_path"], name="uq_mpc_reserved_path"
            ),
            models.CheckConstraint(
                condition=Q(child_index__lte=2147483647), name="mpc_reserved_nonhardened"
            ),
            models.CheckConstraint(
                condition=Q(status="RESERVED"), name="mpc_reservation_not_issued"
            ),
            models.CheckConstraint(
                condition=~Q(customer_ref="") & ~Q(idempotency_key=""),
                name="mpc_reservation_owner_retry_required",
            ),
        ]


class MpcHdRootEvidence(models.Model):
    """Original three-store HD agreement; historical material is never backfilled."""

    root = models.OneToOneField(MpcProvisioningRoot, on_delete=models.PROTECT, primary_key=True)
    evidence = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        from .mpc_hd import verify_hd_evidence

        verify_hd_evidence(self.root, self.evidence)
        return super().save(*args, **kwargs)


class MpcCustodyAccount(models.Model):
    """Canonical beneficial ownership and recoverable child issuance claim.

    PROVISIONING is durable, but cannot enter indexing/signing. ISSUED identity
    is immutable. Asset views use the original authoritative financial ledger.
    """

    account_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reservation = models.OneToOneField(MpcDerivationReservation, on_delete=models.PROTECT)
    ownership_scope = models.CharField(max_length=64)
    customer_ref = models.CharField(max_length=64)
    chain_id = models.CharField(max_length=16)
    status = models.CharField(max_length=16, default="PROVISIONING")
    public_key = models.CharField(max_length=66, blank=True, default="")
    address = models.CharField(max_length=128, blank=True, default="")
    evidence = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if self.status == "ISSUED":
            from .mpc_hd import verify_child_evidence

            child = verify_child_evidence(
                self.reservation, self.reservation.root.mpchdrootevidence.evidence, self.evidence
            )
            if (self.public_key, self.address) != (child["public_key"], child["address"]):
                raise ValidationError("issued address must match authentic signer receipts")
        return super().save(*args, **kwargs)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["chain_id", "customer_ref"], name="uq_mpc_customer_account"
            ),
            models.UniqueConstraint(
                fields=["chain_id", "address"],
                condition=Q(status="ISSUED"),
                name="uq_mpc_issued_address",
            ),
            models.CheckConstraint(
                condition=Q(status="PROVISIONING", public_key="", address="", evidence={})
                | (Q(status="ISSUED") & ~Q(public_key="") & ~Q(address="") & ~Q(evidence={})),
                name="mpc_account_issuance_shape",
            ),
        ]


class UserWallet(models.Model):
    """A user's deposit address for a given (chain, asset).

    TON uses an independently verified standard wallet contract bound to an
    original FROST root. Root references do not support HD child derivation.
    """

    STATUS = [("ACTIVE", "ACTIVE"), ("RETIRED", "RETIRED")]

    user_id = models.CharField(max_length=64, db_index=True)
    chain_id = models.CharField(max_length=16, db_index=True)  # "ETH"/"BASE"
    asset_key = models.CharField(max_length=32, db_index=True)  # "ETH"/"USDT-BSC"
    # Unique within a user+chain+asset; guard against collisions across assets.
    derivation_path = models.CharField(max_length=64, db_index=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user_id", "chain_id", "asset_key", "derivation_path"],
                name="uq_user_chain_asset_derivation_path",
            ),
            models.UniqueConstraint(
                fields=["user_id", "chain_id", "asset_key", "address_index"],
                condition=Q(solana_claim__isnull=True),
                name="uq_user_chain_asset_addrindex",
            ),
            models.UniqueConstraint(
                fields=["deposit_address", "chain_id", "asset_key"],
                name="uq_deposit_address_chain_asset",
            ),
        ]
        indexes = [
            models.Index(fields=["user_id", "chain_id", "status"]),
        ]

    deposit_address = models.CharField(max_length=128, db_index=True)
    # TON memo attribution (optional). For TON this binds the user on-chain.
    memo = models.CharField(max_length=128, null=True, blank=True)
    address_index = models.PositiveBigIntegerField(default=0)
    status = models.CharField(max_length=16, choices=STATUS, default="ACTIVE")
    created_at = models.DateTimeField(auto_now_add=True)
    # Indexer scan metadata
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    last_scanned_block = models.BigIntegerField(null=True, blank=True)
    evm_scan_block_hash = models.CharField(max_length=66, null=True, blank=True)
    solana_scan_cursor = models.JSONField(default=dict, blank=True)
    ton_scan_cursor = models.JSONField(default=dict, blank=True)
    # SPL ATA. The signing authority remains deposit_address.
    asset_account_address = models.CharField(max_length=128, null=True, blank=True)
    mpc_keyset = models.ForeignKey(
        MpcKeyset, null=True, blank=True, on_delete=models.PROTECT, related_name="user_wallets"
    )
    derivation_version = models.CharField(max_length=32, default="legacy_local_v1")
    custody_account = models.ForeignKey(
        MpcCustodyAccount,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="asset_wallets",
    )
    solana_claim = models.OneToOneField(
        MpcSolanaClaim,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="issued_wallet",
    )

    def __str__(self) -> str:
        return f"UserWallet({self.user_id},{self.chain_id},{self.asset_key})"


class Deposit(models.Model):
    """A confirmed (or pending) on-chain deposit parsed by the indexer."""

    user_wallet = models.ForeignKey(UserWallet, on_delete=models.PROTECT, related_name="deposits")
    asset_key = models.CharField(max_length=32, db_index=True)
    tx_hash = models.CharField(max_length=128, db_index=True)
    amount = models.DecimalField(max_digits=40, decimal_places=18)
    block = models.BigIntegerField(null=True, blank=True)
    confirmations = models.PositiveIntegerField(default=0)
    event_index = models.CharField(max_length=64, default="native:0")
    block_hash = models.CharField(max_length=128, null=True, blank=True)
    parsed_at = models.DateTimeField(auto_now_add=True)
    # TON memo (echoed for attribution / reorg backfill).
    memo = models.CharField(max_length=128, null=True, blank=True)
    # Deposit status: PENDING (below confirmation threshold) -> CONFIRMED -> REVERTED (reorg)
    DEPOSIT_STATUS = [
        ("PENDING", "PENDING"),
        ("CONFIRMED", "CONFIRMED"),
        ("REVERTED", "REVERTED"),
    ]
    chain_evidence = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=16, choices=DEPOSIT_STATUS, default="PENDING")

    class Meta:
        constraints = [
            # Idempotency: do not double-count the same deposit tx for a wallet.
            models.UniqueConstraint(
                fields=["user_wallet", "tx_hash", "asset_key", "event_index"],
                name="uq_deposit_wallet_tx_asset_event",
            ),
        ]


class WithdrawalRequest(models.Model):
    """User withdrawal request. No broadcast until admin APPROVES."""

    STATUS = [
        ("PENDING_APPROVAL", "PENDING_APPROVAL"),
        ("APPROVED", "APPROVED"),
        ("PROCESSING", "PROCESSING"),
        ("RECONCILIATION_REQUIRED", "RECONCILIATION_REQUIRED"),
        ("DENIED", "DENIED"),
        ("BROADCASTED", "BROADCASTED"),
        ("CONFIRMED", "CONFIRMED"),
        ("FAILED", "FAILED"),
    ]

    user_id = models.CharField(max_length=64, db_index=True)
    chain_id = models.CharField(max_length=16, db_index=True)
    asset_key = models.CharField(max_length=32, db_index=True)
    to_address = models.CharField(max_length=128)
    amount = models.DecimalField(max_digits=40, decimal_places=18)
    status = models.CharField(max_length=32, choices=STATUS, default="PENDING_APPROVAL")
    admin_notes = models.TextField(null=True, blank=True)
    tx_hash = models.CharField(max_length=128, null=True, blank=True, db_index=True)
    # Idempotency key so retries of the same user request don't create dupes.
    idempotency_key = models.CharField(max_length=64, unique=True, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["user_id", "status"]),
            models.Index(fields=["status"]),
        ]


class HotWallet(models.Model):
    """Pre-determined custody hot wallet address per chain (MPC-controlled)."""

    chain_id = models.CharField(max_length=16, unique=True)
    address = models.CharField(max_length=128)
    # Opaque signer-owned identity.  Deliberately nullable for non-destructive
    # migration: legacy wallets must be repaired by an operator and fail closed.
    signing_key_ref = models.CharField(max_length=255, null=True, blank=True)
    mpc_keyset = models.ForeignKey(
        MpcKeyset, null=True, blank=True, on_delete=models.PROTECT, related_name="hot_wallets"
    )

    def __str__(self) -> str:
        return f"HotWallet({self.chain_id},{self.address})"


class SweepJob(models.Model):
    """EOA -> hot wallet sweep job (state machine).

    State machine:
      CREATED -> GAS_TOPUP_REQUIRED? -> SWEEP_BROADCASTED -> CONFIRMED / FAILED

    Idempotency strategy:
      - unique (user_wallet_id, sweep_round) prevents duplicate sweeps for the
        same balance-check round.
      - repeated "Check Balance" calls recompute but must not create a new
        SWEEP_BROADCASTED job if one already exists for this round.
    """

    STATUS = [
        ("CREATED", "CREATED"),
        ("GAS_TOPUP_REQUIRED", "GAS_TOPUP_REQUIRED"),
        ("GAS_TOPUP_BROADCASTED", "GAS_TOPUP_BROADCASTED"),
        ("GAS_TOPUP_CONFIRMED", "GAS_TOPUP_CONFIRMED"),
        ("SWEEP_PROCESSING", "SWEEP_PROCESSING"),
        ("SWEEP_BROADCASTED", "SWEEP_BROADCASTED"),
        ("RECONCILIATION_REQUIRED", "RECONCILIATION_REQUIRED"),
        ("CONFIRMED", "CONFIRMED"),
        ("FAILED", "FAILED"),
    ]

    user_wallet = models.ForeignKey(UserWallet, on_delete=models.PROTECT, related_name="sweeps")
    asset_key = models.CharField(max_length=32, db_index=True)
    sweep_round = models.PositiveIntegerField(default=1)
    balance_snapshot = models.DecimalField(max_digits=40, decimal_places=18, null=True, blank=True)
    deposit = models.ForeignKey(Deposit, null=True, blank=True, on_delete=models.SET_NULL)
    status = models.CharField(max_length=24, choices=STATUS, default="CREATED")
    tx_hash = models.CharField(max_length=128, null=True, blank=True, db_index=True)
    idempotency_key = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    gas_topup_intent = models.OneToOneField(
        "GasTopupIntent", null=True, blank=True, on_delete=models.PROTECT, related_name="sweep_job"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user_wallet", "asset_key", "sweep_round"],
                name="uq_sweep_wallet_asset_round",
            ),
        ]


class GasTopupIntent(models.Model):
    """Persisted idempotency and reconciliation state for gas transfers."""

    STATUS = [
        ("CREATED", "CREATED"),
        ("PROCESSING", "PROCESSING"),
        ("BROADCASTED", "BROADCASTED"),
        ("RECONCILIATION_REQUIRED", "RECONCILIATION_REQUIRED"),
        ("FAILED", "FAILED"),
        ("CONFIRMED", "CONFIRMED"),
    ]
    idempotency_key = models.CharField(max_length=64, unique=True)
    actor_id = models.CharField(max_length=64)
    chain_id = models.CharField(max_length=16)
    to_address = models.CharField(max_length=128)
    amount = models.DecimalField(max_digits=40, decimal_places=18)
    memo = models.CharField(max_length=128, null=True, blank=True)
    status = models.CharField(max_length=32, choices=STATUS, default="CREATED")
    tx_hash = models.CharField(max_length=128, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class TonWalletBinding(models.Model):
    """Public immutable V5R1 root identity. ACTIVE is never on-chain proof."""

    chain_id = models.CharField(max_length=16, default="TON")
    address = models.CharField(max_length=128)
    keyset = models.ForeignKey(MpcKeyset, on_delete=models.PROTECT)
    network_identity = models.JSONField()
    wallet_version = models.CharField(max_length=8, default="V5R1")
    code_hash = models.CharField(max_length=64)
    wallet_id = models.PositiveBigIntegerField()
    workchain = models.SmallIntegerField(default=0)
    state_init = models.TextField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["chain_id", "address"], name="uq_ton_root_contract"),
            models.UniqueConstraint(fields=["keyset"], name="uq_ton_keyset_network_binding"),
            models.CheckConstraint(
                condition=Q(workchain=0, wallet_version="V5R1"), name="ton_standard_wallet_shape"
            ),
        ]


class SourceAccountSequence(models.Model):
    """Durable allocator for account-chain sequence numbers (not a cache)."""

    chain_id = models.CharField(max_length=16)
    address = models.CharField(max_length=128)
    next_sequence = models.PositiveBigIntegerField(default=0)
    owner_attempt = models.OneToOneField(
        "OnchainTransactionAttempt",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="owned_sequence",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["chain_id", "address"], name="uq_source_account_sequence"
            )
        ]


class OnchainTransactionAttempt(models.Model):
    """One immutable-identity execution attempt for a logical custody operation."""

    OPERATION_TYPES = [
        ("WITHDRAWAL", "WITHDRAWAL"),
        ("SWEEP", "SWEEP"),
        ("GAS_TOPUP", "GAS_TOPUP"),
        ("PROVISION", "PROVISION"),
    ]
    STATUSES = [
        (value, value)
        for value in (
            "PREPARING",
            "PREPARED",
            "SIGNING",
            "SIGNED",
            "BROADCASTING",
            "BROADCASTED",
            "CONFIRMED",
            "FAILED",
            "RECONCILIATION_REQUIRED",
        )
    ]
    operation_type = models.CharField(max_length=16, choices=OPERATION_TYPES)
    operation_id = models.PositiveBigIntegerField()
    attempt_number = models.PositiveIntegerField(default=1)
    chain_id = models.CharField(max_length=16, db_index=True)
    asset_key = models.CharField(max_length=32)
    from_address = models.CharField(max_length=128)
    to_address = models.CharField(max_length=128)
    amount = models.DecimalField(max_digits=40, decimal_places=18)
    base_unit_amount = models.DecimalField(max_digits=78, decimal_places=0)
    status = models.CharField(max_length=32, choices=STATUSES, default="PREPARING")
    network_tx_id = models.CharField(max_length=128, null=True, blank=True, db_index=True)
    sequence = models.PositiveBigIntegerField(null=True, blank=True)
    prepared_metadata = models.JSONField(default=dict, blank=True)
    fee_metadata = models.JSONField(default=dict, blank=True)
    # Required to replay the *same* authorized bytes after an uncertain RPC.
    # Sensitive: never serialize this field through the public API or logs.
    signed_payload = models.TextField(blank=True, default="")
    expires_at = models.DateTimeField(null=True, blank=True)
    last_valid_block = models.PositiveBigIntegerField(null=True, blank=True)
    broadcast_started_at = models.DateTimeField(null=True, blank=True)
    broadcast_at = models.DateTimeField(null=True, blank=True)
    confirmation_metadata = models.JSONField(default=dict, blank=True)
    error_code = models.CharField(max_length=64, blank=True, default="")
    error_message = models.CharField(max_length=512, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["operation_type", "operation_id", "attempt_number"],
                name="uq_onchain_attempt_number",
            ),
            models.UniqueConstraint(
                fields=["chain_id", "network_tx_id"],
                condition=models.Q(chain_id="TRX", network_tx_id__isnull=False),
                name="uq_tron_attempt_txid",
            ),
            models.UniqueConstraint(
                fields=["chain_id", "from_address", "sequence"],
                condition=models.Q(sequence__isnull=False),
                name="uq_onchain_source_sequence",
            ),
            models.CheckConstraint(
                condition=(~Q(operation_type="PROVISION") & Q(amount__gt=0, base_unit_amount__gt=0))
                | Q(operation_type="PROVISION", chain_id="SOL", amount=0, base_unit_amount=0),
                name="onchain_attempt_positive_amount",
            ),
        ]
        indexes = [models.Index(fields=["status", "chain_id"])]


class MpcSolanaTokenProvision(models.Model):
    """One explicit initialization business; no token principal or USER liability.

    Failed finalized attempts retain history. A later explicit business may
    retry; an unresolved or successful original cannot be silently replaced.
    """

    claim = models.ForeignKey(MpcSolanaClaim, on_delete=models.PROTECT)
    idempotency_key = models.CharField(max_length=128)
    status = models.CharField(max_length=32, default="CREATED")
    tx_hash = models.CharField(max_length=128, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(
                    status__in=[
                        "CREATED",
                        "PROCESSING",
                        "BROADCASTED",
                        "RECONCILIATION_REQUIRED",
                        "CONFIRMED",
                        "FAILED",
                    ]
                ),
                name="sol_token_provision_state",
            ),
            models.UniqueConstraint(
                fields=["claim"],
                condition=~Q(status="FAILED"),
                name="sol_token_one_live_or_successful_init",
            ),
            models.UniqueConstraint(
                fields=["claim", "idempotency_key"], name="sol_token_provision_retry_identity"
            ),
        ]


class MpcSolanaTokenPublication(models.Model):
    """Immutable finalized initialization and actual account proof at publication."""

    claim = models.OneToOneField(MpcSolanaClaim, primary_key=True, on_delete=models.PROTECT)
    effect = models.OneToOneField("MpcSolanaFinancialEffect", on_delete=models.PROTECT)
    account_context_slot = models.PositiveBigIntegerField()
    account_evidence = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)


class MpcSolanaFinancialOperation(models.Model):
    """Immutable business/source identity; balances remain in the existing ledger."""

    reservation_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    withdrawal = models.OneToOneField("WithdrawalRequest", null=True, on_delete=models.PROTECT)
    sweep = models.OneToOneField("SweepJob", null=True, on_delete=models.PROTECT)
    provision = models.OneToOneField(MpcSolanaTokenProvision, null=True, on_delete=models.PROTECT)
    principal = models.ForeignKey(CustodyPrincipal, on_delete=models.PROTECT)
    source = models.ForeignKey(
        MpcSolanaFinancialWallet, on_delete=models.PROTECT, related_name="outgoing_operations"
    )
    treasury_destination = models.ForeignKey(
        MpcSolanaFinancialWallet,
        null=True,
        on_delete=models.PROTECT,
        related_name="incoming_sweep_operations",
    )
    approval_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    amount = models.DecimalField(max_digits=40, decimal_places=18)
    base_unit_amount = models.DecimalField(max_digits=78, decimal_places=0)
    destination_address = models.CharField(max_length=44)
    fee_budget_lamports = models.PositiveBigIntegerField()
    rent_budget_lamports = models.PositiveBigIntegerField(default=0)
    status = models.CharField(max_length=16, default="HELD")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(
                    withdrawal__isnull=False,
                    sweep__isnull=True,
                    provision__isnull=True,
                    treasury_destination__isnull=True,
                )
                | Q(
                    withdrawal__isnull=True,
                    sweep__isnull=False,
                    provision__isnull=True,
                    treasury_destination__isnull=False,
                )
                | Q(
                    withdrawal__isnull=True,
                    sweep__isnull=True,
                    provision__isnull=False,
                    treasury_destination__isnull=True,
                ),
                name="sol_fin_operation_business_shape",
            ),
            models.CheckConstraint(
                condition=Q(fee_budget_lamports__gt=0)
                & (
                    Q(
                        provision__isnull=True,
                        amount__gt=0,
                        base_unit_amount__gt=0,
                        base_unit_amount__lte=18446744073709551615,
                    )
                    | Q(
                        provision__isnull=False,
                        amount=0,
                        base_unit_amount=0,
                        rent_budget_lamports__gt=0,
                    )
                ),
                name="sol_fin_operation_amount_shape",
            ),
            models.CheckConstraint(
                condition=Q(status__in=["HELD", "SETTLED", "RELEASED"]),
                name="sol_fin_operation_state",
            ),
            models.UniqueConstraint(
                fields=["source"],
                condition=Q(sweep__isnull=False, status="HELD"),
                name="sol_fin_one_held_sweep_per_source",
            ),
        ]


class MpcSolanaFinancialSession(models.Model):
    """One exact protected crypto execution per immutable on-chain attempt."""

    session_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    crypto_execution_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    operation = models.ForeignKey(MpcSolanaFinancialOperation, on_delete=models.PROTECT)
    attempt = models.OneToOneField(OnchainTransactionAttempt, on_delete=models.PROTECT)
    selected_signers = models.JSONField()
    status = models.CharField(max_length=32, default="ALLOCATED")
    intent = models.JSONField(default=dict)
    payload = models.BinaryField(default=bytes)
    custody_authorization = models.JSONField(default=dict)
    policy_authorization = models.JSONField(default=dict)
    admission_evidence = models.JSONField(default=dict)
    no_signature_evidence = models.JSONField(default=dict)
    signature_hex = models.CharField(max_length=128, default="", blank=True)
    coordinator_evidence = models.JSONField(default=dict)
    error_code = models.CharField(max_length=64, default="", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(
                    status__in=[
                        "ALLOCATED",
                        "WAITING_POLICY",
                        "READY",
                        "IN_PROGRESS",
                        "COMPLETED",
                        "NO_SIGNATURE",
                        "RECONCILIATION_REQUIRED",
                    ]
                ),
                name="sol_fin_session_state",
            ),
            models.UniqueConstraint(
                fields=["operation"],
                condition=~Q(status="NO_SIGNATURE"),
                name="sol_fin_one_unresolved_session",
            ),
        ]


class MpcSolanaFinancialQuery(models.Model):
    """Append-only challenge lease; no refresh of an old nonce or deadline."""

    challenge = models.CharField(primary_key=True, max_length=64)
    session = models.ForeignKey(MpcSolanaFinancialSession, on_delete=models.PROTECT)
    purpose = models.CharField(max_length=16)
    witness_anchor_id = models.UUIDField()
    witness_key_id = models.CharField(max_length=64)
    query = models.JSONField()
    expires_at = models.DateTimeField()
    status = models.CharField(max_length=16, default="PENDING")
    evidence = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(purpose__in=["ADMISSION", "RECOVERY", "TERMINAL"]),
                name="sol_fin_query_purpose",
            ),
            models.CheckConstraint(
                condition=Q(status="PENDING", evidence={})
                | (Q(status="VERIFIED") & ~Q(evidence={})),
                name="sol_fin_query_evidence_shape",
            ),
        ]


class MpcSolanaMessageOwner(models.Model):
    """Permanent canonical (genesis,message) ownership, claimed before private work."""

    genesis_hash = models.CharField(max_length=44)
    message_fingerprint = models.CharField(max_length=64)
    operation = models.ForeignKey(MpcSolanaFinancialOperation, on_delete=models.PROTECT)
    first_session = models.ForeignKey(MpcSolanaFinancialSession, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["genesis_hash", "message_fingerprint"], name="uq_sol_fin_message_owner"
            )
        ]


class MpcSolanaSignatureOwner(models.Model):
    """Append-only verified signature ownership; never a settlement indicator."""

    genesis_hash = models.CharField(max_length=44)
    signature = models.CharField(max_length=88)
    message = models.ForeignKey(MpcSolanaMessageOwner, on_delete=models.PROTECT)
    session = models.OneToOneField(MpcSolanaFinancialSession, on_delete=models.PROTECT)
    evidence = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["genesis_hash", "signature"], name="uq_sol_fin_signature_owner"
            )
        ]


class MpcSolanaFinancialEffect(models.Model):
    """Immutable finalized original-wire observation, never a second balance ledger."""

    attempt = models.OneToOneField(
        OnchainTransactionAttempt, on_delete=models.PROTECT, primary_key=True
    )
    signature_owner = models.OneToOneField(MpcSolanaSignatureOwner, on_delete=models.PROTECT)
    slot = models.PositiveBigIntegerField()
    outcome = models.CharField(max_length=16)
    evidence = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(outcome__in=["CONFIRMED", "FAILED"], slot__gt=0) & ~Q(evidence={}),
                name="sol_fin_effect_shape",
            )
        ]


class MpcSolanaOperatorFundingSource(models.Model):
    """Permanent privileged source classification, never a customer balance."""

    genesis_hash = models.CharField(max_length=44)
    address = models.CharField(max_length=44)
    reference = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["genesis_hash", "address"], name="uq_sol_operator_source"
            ),
        ]


class MpcSolanaDepositProvenance(models.Model):
    """One finalized explicit instruction has exactly one original deposit owner."""

    deposit = models.OneToOneField("Deposit", on_delete=models.PROTECT)
    genesis_hash = models.CharField(max_length=44)
    signature = models.CharField(max_length=88)
    event_index = models.CharField(max_length=64)
    source_address = models.CharField(max_length=44)
    source_owner_address = models.CharField(max_length=44, null=True, blank=True)
    source_owner_history = models.JSONField(default=list)
    slot = models.PositiveBigIntegerField()
    block_hash = models.CharField(max_length=44)
    observation_sha256 = models.CharField(max_length=64)
    evidence = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["genesis_hash", "signature", "event_index"],
                name="uq_sol_deposit_instruction",
            ),
            models.CheckConstraint(
                condition=Q(slot__gt=0) & ~Q(evidence={}), name="sol_deposit_provenance_shape"
            ),
        ]


class MpcSigningSession(models.Model):
    """Durable, idempotent link between a prepared attempt and one MPC execution."""

    STATUSES = [
        (value, value)
        for value in (
            "CREATED",
            "STARTING",
            "IN_PROGRESS",
            "COMPLETED",
            "DEFINITIVE_NO_SIGNATURE_FAILURE",
            "RECONCILIATION_REQUIRED",
        )
    ]
    attempt = models.ForeignKey(
        OnchainTransactionAttempt, on_delete=models.PROTECT, related_name="mpc_sessions"
    )
    session_id = models.UUIDField(unique=True)
    session_number = models.PositiveIntegerField(default=1)
    keyset = models.ForeignKey(MpcKeyset, on_delete=models.PROTECT, related_name="signing_sessions")
    algorithm = models.CharField(max_length=32)
    message_fingerprint = models.CharField(max_length=64)
    payload_type = models.CharField(max_length=32)
    signing_payload = models.BinaryField()
    crypto_execution_id = models.UUIDField(null=True, blank=True, unique=True)
    selected_signers = models.JSONField(default=list, blank=True)
    signature_result = models.JSONField(default=dict, blank=True)
    transaction_identity = models.JSONField(default=dict, blank=True)
    custody_authorization = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=32, choices=STATUSES, default="CREATED")
    coordinator_request_id = models.CharField(max_length=128, blank=True, default="")
    error_code = models.CharField(max_length=64, blank=True, default="")
    error_message = models.CharField(max_length=512, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    signature_consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["attempt", "session_number"], name="uq_mpc_attempt_session_number"
            ),
            models.UniqueConstraint(
                fields=["attempt"],
                condition=models.Q(status__in=["CREATED", "STARTING", "IN_PROGRESS"]),
                name="uq_active_mpc_session_per_attempt",
            ),
        ]


class AdminActionLog(models.Model):
    """Append-style audit trail for all sensitive actions."""

    actor_id = models.CharField(max_length=64, db_index=True)
    action_type = models.CharField(max_length=32, db_index=True)
    entity_type = models.CharField(max_length=32)
    entity_id = models.CharField(max_length=128, db_index=True)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["actor_id", "created_at"]),
            models.Index(fields=["action_type", "created_at"]),
        ]


class ImmutableAccountQuerySet(models.QuerySet):
    """Allow account creation and locking, but never bulk mutation/deletion."""

    def update(self, **kwargs):
        raise ValueError("ledger account identity is immutable")

    def delete(self):
        raise ValueError("ledger accounts cannot be deleted")


class AppendOnlyQuerySet(models.QuerySet):
    """Block journal mutation through normal Django ORM queryset APIs."""

    def update(self, **kwargs):
        raise ValueError("ledger journal rows are append-only")

    def delete(self):
        raise ValueError("ledger journal rows are append-only")


class LedgerAccount(models.Model):
    """Stable account identity; balances are derived only from postings."""

    OWNER_TYPES = [("USER", "USER"), ("SYSTEM", "SYSTEM")]
    BUCKETS = [
        ("AVAILABLE", "AVAILABLE"),
        ("RESERVED", "RESERVED"),
        ("CUSTODY_CLEARING", "CUSTODY_CLEARING"),
        ("TREASURY_ASSET", "TREASURY_ASSET"),
        ("NETWORK_FEE_EXPENSE", "NETWORK_FEE_EXPENSE"),
        ("ATA_RENT_ASSET", "ATA_RENT_ASSET"),
        ("TOKEN_ACCOUNT_RENT_ASSET", "TOKEN_ACCOUNT_RENT_ASSET"),
        ("TOKEN_GAS_EXPENSE", "TOKEN_GAS_EXPENSE"),
    ]
    owner_type = models.CharField(max_length=16, choices=OWNER_TYPES)
    owner_id = models.CharField(max_length=64)
    asset_key = models.CharField(max_length=32, db_index=True)
    bucket = models.CharField(max_length=24, choices=BUCKETS)
    created_at = models.DateTimeField(auto_now_add=True)
    objects = ImmutableAccountQuerySet.as_manager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["owner_type", "owner_id", "asset_key", "bucket"],
                name="uq_ledger_account_identity",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(owner_type="USER", bucket__in=["AVAILABLE", "RESERVED"])
                    | models.Q(
                        owner_type="SYSTEM",
                        owner_id="custody",
                        bucket__in=[
                            "CUSTODY_CLEARING",
                            "TREASURY_ASSET",
                            "NETWORK_FEE_EXPENSE",
                            "ATA_RENT_ASSET",
                            "TOKEN_ACCOUNT_RENT_ASSET",
                            "TOKEN_GAS_EXPENSE",
                        ],
                    )
                ),
                name="ledger_account_valid_shape",
            ),
        ]

    def save(self, *args, **kwargs):
        if self.pk:
            original = type(self).objects.get(pk=self.pk)
            identity = (self.owner_type, self.owner_id, self.asset_key, self.bucket)
            original_identity = (
                original.owner_type,
                original.owner_id,
                original.asset_key,
                original.bucket,
            )
            if identity != original_identity:
                raise ValueError("ledger account identity is immutable")
        valid_user = self.owner_type == "USER" and self.bucket in {"AVAILABLE", "RESERVED"}
        valid_system = (
            self.owner_type == "SYSTEM"
            and self.owner_id == "custody"
            and self.bucket
            in {
                "CUSTODY_CLEARING",
                "TREASURY_ASSET",
                "NETWORK_FEE_EXPENSE",
                "ATA_RENT_ASSET",
                "TOKEN_ACCOUNT_RENT_ASSET",
                "TOKEN_GAS_EXPENSE",
            }
        )
        if not (valid_user or valid_system):
            raise ValidationError("invalid ledger account identity shape")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ledger accounts cannot be deleted")


class LedgerTransaction(models.Model):
    """Immutable journal header. Corrections are compensating transactions."""

    TYPES = [
        ("DEPOSIT_CREDIT", "DEPOSIT_CREDIT"),
        ("DEPOSIT_REVERSAL", "DEPOSIT_REVERSAL"),
        ("WITHDRAWAL_RESERVE", "WITHDRAWAL_RESERVE"),
        ("WITHDRAWAL_RELEASE", "WITHDRAWAL_RELEASE"),
        ("WITHDRAWAL_SETTLE", "WITHDRAWAL_SETTLE"),
        ("NETWORK_FEE", "NETWORK_FEE"),
        ("ATA_RENT", "ATA_RENT"),
        ("TOKEN_ACCOUNT_RENT", "TOKEN_ACCOUNT_RENT"),
        ("TOKEN_GAS", "TOKEN_GAS"),
    ]
    event_key = models.CharField(max_length=160, unique=True)
    event_type = models.CharField(max_length=32, choices=TYPES)
    asset_key = models.CharField(max_length=32, db_index=True)
    ref_type = models.CharField(max_length=32)
    ref_id = models.CharField(max_length=128)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    objects = AppendOnlyQuerySet.as_manager()

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValueError("ledger transactions are append-only")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ledger transactions are append-only")


class LedgerPosting(models.Model):
    """Signed journal line: positive adds to an account, negative removes."""

    transaction = models.ForeignKey(
        LedgerTransaction, on_delete=models.PROTECT, related_name="postings"
    )
    account = models.ForeignKey(LedgerAccount, on_delete=models.PROTECT, related_name="postings")
    amount = models.DecimalField(max_digits=40, decimal_places=18)
    created_at = models.DateTimeField(auto_now_add=True)
    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        constraints = [
            models.CheckConstraint(condition=~models.Q(amount=0), name="ledger_posting_nonzero")
        ]

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValueError("ledger postings are append-only")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("ledger postings are append-only")


class MpcSolanaClaimQuery(models.Model):
    """One immutable original challenge; public signatures are not freshness alone."""

    challenge = models.CharField(max_length=64, primary_key=True)
    claim = models.ForeignKey(MpcSolanaClaim, on_delete=models.PROTECT)
    witness_anchor_id = models.UUIDField()
    witness_key_id = models.CharField(max_length=64)
    attempt = models.ForeignKey(
        "MpcSolanaClaimApproval",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="registration_queries",
    )
    purpose = models.CharField(
        max_length=16, choices=[("DISCOVERY", "DISCOVERY"), ("REGISTRATION", "REGISTRATION")]
    )
    expires_at = models.DateTimeField()
    status = models.CharField(max_length=16, default="PENDING")
    evidence = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(purpose="DISCOVERY", attempt__isnull=True)
                | Q(purpose="REGISTRATION", attempt__isnull=False),
                name="sol_claim_query_purpose",
            ),
            models.CheckConstraint(
                condition=Q(status="PENDING", evidence={})
                | (Q(status="VERIFIED") & ~Q(evidence={})),
                name="sol_claim_query_shape",
            ),
        ]


class MpcSolanaClaimApproval(models.Model):
    """Durable public attempt; expiry never permits replacement of Claim identity."""

    attempt_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    claim = models.ForeignKey(MpcSolanaClaim, on_delete=models.PROTECT)
    discovery = models.OneToOneField(MpcSolanaClaimQuery, on_delete=models.PROTECT)
    authority_identity = models.CharField(max_length=64)
    approval = models.JSONField()
    command_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    status = models.CharField(max_length=16, default="PENDING")
    evidence = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(status="PENDING", evidence={})
                | (Q(status="REPORTED") & ~Q(evidence={})),
                name="sol_current_claim_attempt_shape",
            ),
        ]


class MpcSolanaClaimRegistration(models.Model):
    """Exact permanent W evidence; original Claim approval is immutable archival data."""

    claim = models.OneToOneField(MpcSolanaClaim, on_delete=models.PROTECT, primary_key=True)
    query = models.OneToOneField(MpcSolanaClaimQuery, on_delete=models.PROTECT)
    evidence = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
