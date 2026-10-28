> **Current supersession (2026-10-27):** Phase 6G-B is merged at verified fork main `3d32b763`. Earlier R1/R2-review-required and scc/Tokio-open descriptions below retain historical snapshots; current source facts and qualified final historical review dispositions are in [INITIAL_REPOSITORY_AUDIT.md](INITIAL_REPOSITORY_AUDIT.md). Phase 6G-C remains incomplete and no new production authorization is claimed.

# Target architecture and boundaries

**Status:** target/reference architecture; only a subset is implemented in main. See PROJECT_STATUS.md for actual implementation.

## Logical topology

External clients: Exchange Matching Engine / Order Book (independent), Payment Gateways / Merchants, Institutional Treasury, Admin/Operator, Auditors.
  -> Versioned Gateway/API / Tenant Authentication / RBAC / Idempotency / Quotas / Outbox
  -> Financial domain: immutable double-entry Ledger + Reservation + Trade Settlement + Fees
  -> Business domain: Merchant Invoice / Refund / Settlement; Internal Risk / Optional Withdrawal Blacklist; Policy and Human Approvals; Treasury
  -> Custody orchestrator: Address Provisioning, Indexing, Sweep, Gas, Withdrawal/Broadcast, Reconciliation
  -> Independent MPC authorization boundary / Coordinator / genuine 2-of-3 signer services (mTLS, isolated shares)
  -> independently reviewed EVM, TRON, Solana and currently limited isolated TON network adapters.

All components can share a modular backend initially; **logical ownership boundaries** must still be enforced. A microservice rewrite is not automatically required.

## Financial ownership and data flow

- LedgerAccount, LedgerTransaction and LedgerPosting are canonical for financial balances and liabilities. Every posting balances per asset; never use floats for financial amounts.
- Network events are authenticated inputs to a deterministic deposit/settlement state machine, not sufficient proof without chain-specific finality.
- Asset identity is chain/contract(or mint)/standard/decimals + immutable globally unique asset_key; same symbol across chains does not imply fungibility.
- Asset reservations lock available -> reserved, before any on-chain withdrawal or exchange obligation; unknown on-chain outcome retains reserved until authoritative reconciliation.
- Trade settlement is an *internal* atomic ledger movement of both traded assets and fees. No chain signature, RPC or wallet movement on each trade.
- Customer liabilities, operator treasury balances, network fees, merchant balances and clearing/suspense must be separately attributable by tenant/legal ownership.
- The existing ledger is **not yet tenant-aware for exchange trade settlements**; add tenant boundaries and models deliberately without replacing or retroactively changing established journals.
- Snapshot/reporting/analytics are derived projections, not independent sources of truth.

## Tenant isolation and trust boundaries

The unmerged operator identity registry persists immutable CustodyTenant and
CustodyPrincipal mappings with generated globally unique ledger owner IDs, exact
tenant-scoped references, atomic audit and PostgreSQL collision/immutability guards.
Operator-only Solana root/claim reservations now bind these mappings to original
DKG/network/asset evidence and independently verified three-store approvals.
They do not authorize external callers, issue wallets, grant spending or post
financial journals. Existing ledger/wallet identities are preserved;
there is no automatic adoption/backfill. See [scope](PHASE6GC_IDENTITY_REGISTRY.md).
The [Solana reservation boundary](PHASE6GC_SOLANA_REGISTRY.md) documents pending
recovery, shared index allocation, legacy fences and migration0034.

Design Tenant/Organization and principals; customer identity is scoped to tenant. Each API credential has explicit tenant/service/role/scopes; never trust caller-supplied user_id as an authorization boundary. Developer/merchant/ops capabilities are separated from signer policy authority. Prevent cross-tenant transaction IDs, account lookups, webhook delivery, wallet/address reuse and funding. Support distinct custody keyset policy and wallet class by tenant as needed, without promising one root per tenant by default.

## Transaction state machine

Persist: request -> policy/risk check -> financial reservation -> required approvals -> independent signer authorization -> original approved payload -> MPC signing -> persist immutable signed bytes -> broadcast -> network-specific authoritative confirmation -> settle ledger + costs. Rejected/denied request may release; ambiguous signed/broadcast result must retain reservation. Retries use original signed identity whenever possible and cannot create a duplicate payout. Pre- and post-restart reconciliation is explicit.

## Signer security

Coordinator stores public/session metadata; signer nodes retain encrypted private shares and nonce/execution tombstones. FROST or CGGMP creates threshold signatures; no complete custody private key is assembled in the backend. Human approval is not signer quorum. Independent signer-side authorization must resist a compromised Django app minting arbitrary transactions; see SECURITY_MODEL.md. Never imply one PostgreSQL DB, one network operator or current CI fixture provides a production trust boundary.

## Chain-specific adapters

Each network has canonical registry, genesis/chain identity, token verification, fee/finality, tx assembly, RPC and scanner recovery policy. Block confirmations alone do not fully model Solana/TON finality. Reorg and consensus evidence must be understood per family. Release gates are per network, not a single global feature flag.

## Lifecycle / throughput constraints

Phase 6G-A's immutable canonical `m/0/index` reservation remains the allocation
identity. Phase 6G-B adds original chain code and extended root agreement from
all three independently validated signer stores. The coordinator and every signer
use pinned upstream SLIP-10; Django independently verifies public derivation.
A durable `MpcCustodyAccount` claim precedes external RPC and becomes ISSUED only
after three signer approvals. A reservation alone stays RESERVED and unissuable.
The account's immutable owner/address/key/path/network is authoritative; nullable
`UserWallet.custody_account` supplies asset views sharing that same owner/address.
Existing customer IDs are global ledger principals, not a new tenant namespace.
There is no journal backfill or second ledger. Child authorization is committed
in original transaction, signing request and execution; the original 2-of-3 shares
sign with upstream `set_derivation_path`, and verification uses the child key.
The custody machine signs the entire original child request with its existing
P-256 TLS identity. Each signer verifies that grant across the coordinator hop
against the private CA before nonce work. Migration 0031 persists it once with
the original session; coordinator child substitution invalidates the signature.
This is machine authentication, with independent policy authority still Phase 7.
See [PHASE6GB.md](../PHASE6GB.md) for failure/recovery and throughput limits.

Phase 6G should use reviewed chain/algorithm-specific scalable provisioning rather than heavy fresh DKG for every deposit address. EVM/TRON secp256k1 derivation and Ed25519 FROST derivation must not be assumed interchangeable. Root bindings are immutable; resharing/rotation/recovery require versioned, auditable transitions. Hot/warm/cold are separate security classes; cold signing cannot reuse the hot environment's routine authorization.

## Scalability, events, and operability

Introduce reliable transactional outbox/inbox, monotonic event IDs, idempotent consumers, backpressure, bounded retries and DLQs for API webhooks and internal financial events. Use queue-based withdrawal and payout execution; database transaction isolation and lock order must be explicit. Instrument lag, missing chain history, signer availability, reconciliation debt, treasury runway, asset-liability gaps and security policy denials. Backup/restore tests must include both ledger and independently held signing material; avoid confidential leakage to logs/artifacts.

## Compatibility rules

Do not claim old Phase 1–5 docs describe current complete state; those files describe dated baselines. Do not invent production integrations just because DTO/routes or dashboard placeholders exist. Keep migrations additive, auditable and reversal-safe. Never change a settled financial journal to compensate for new behaviors.

New child approvals include a domain-separated original custody machine proof.
All three signer CAs and P-256 credential profiles are verified before issuance;
identity readiness is established with the original share/HD approval rather than
first discovered during spending. This public approval does not consume an MPC
nonce or alter immutable child identity. Signing uses its separately persisted
original grant.


## 2026-10-23 independent review remediation (PR #37)

The prior mTLS report design was insufficient against a compromised coordinator.
R1 now requires detached, domain-separated ECDSA/SHA-256 receipts from all three
signers, verified by Django against separately installed signer public identities
(`MPC_HD_SIGNER_CERTIFICATES`), never coordinator-provided trust anchors. Receipt
bytes and original ownership remain immutable across retries. Migration 0032 checks
signature presence/shape; application writes and every use verify cryptography.
SQL is not an ECDSA verifier; database writers and independent trust enrollment
remain protected authorities. Old unsigned records remain immutable and quarantined;
use the read-only `audit_mpc_hd_evidence` procedure in PHASE6GB before upgrade.

R2 requires a domain-separated original custody dedication proof checked by every
signer before role/namespace mutation, plus durable historical root-use reservation
before nonce work. Signers seed use from original retained execution records and
reject used/conflicting roots. Authorized dedication of a fresh eligible root is
irreversible; no root-only fallback. Dedicated role and original proof persist
across restart. Unverified old signer HD stores fail startup for offline audit.
These are machine-authentication corrections, not Phase 7 policy/RBAC or lifecycle
completion. R1/R2 require independent re-review and fresh final-head gates; prior
normal-path CI is insufficient. scc/RUSTSEC-2026-0205 remains P1 OPEN.


## Continuation boundaries — 2026-10-27

Phase 6G-B is implemented on verified main 3d32b763; 6G-C remains incomplete. Immutable FROST epochs, authenticated generation commits/old-share fencing and independent Warm/Cold workflows are required before claiming lifecycle completion. If the standard seeded-account candidate is selected, SOL/SPL source/rent/authority bindings and genuine spendability acceptance are also required. Phase 7B adds only a default-disabled manual withdrawal blacklist with authoritative versioned checks at request/execution/signer boundaries. It must not become a deposit-processing dependency. No external AML/KYT integration is part of the approved target.


## Seeded Solana primitive boundary — 2026-10-27

Subsequent signer-local enrollment/claim records reopen each original encrypted
FROST DKG and authenticate domain-separated custody statements. A shared role
lock serializes dedication against legacy nonce reservation; dedicated roots
cannot use the legacy signing API. Index-first immutable files recover partial
aliases and protect global reservation UUIDs across roots. These are operator-
scoped records, still unconnected to tenant identity, custody issuance or seeded
spending. Genesis is the original custody pin, not signer-side chain attestation;
epochs, an independent rollback witness and identity-key rollover remain pending.

Custody-mTLS coordinator routes now collect and pin all three original receipts;
partial commits remain recoverable and completed public evidence can be reread
offline. Custody verifies distinct Solana domains with independently configured
archival HOT signer pins; transport/coordinator metadata cannot replace these
checks. This adds no Django financial wallet, tenant authorization or spending
grant. HTTP409 cannot establish that a partial operation never committed.

Subsequent coordinated enrollment checks all signing-session history and all-party
readonly eligibility before mutation. A durable pending-root fence and the signing
reservation share the coordinator data lock, preserving historical unused-first
quorum and partial-write fencing. Bounded RPCs hold that lock during the ceremony;
future scalability and independent witness/policy isolation are still required.
Direct local APIs do not constitute a global Byzantine eligibility lease.

Standard seeded System/native and classic SPL account primitives now have exact
SDK/Rust wire checks and genuine all-pair FROST spendability acceptance, described
in [PHASE6GC_SOLANA_SEEDED.md](PHASE6GC_SOLANA_SEEDED.md). They do not yet issue
accounts or enter product signing/ledger flows. A seeded financial source differs
from the original FROST authority/fee payer; settlement must bind and verify each
separately. Custody integration of signer-local ownership/index/mint claims and
enrollment, generation grants and ledger integration remain required. There is no
Ed25519 child-private-key derivation or new local signing fallback.
