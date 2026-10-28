# Authoritative Solana reservations — Phase 6G-C development checkpoint

This operator-only layer connects original FROST seeded root/claim approvals to
the immutable tenant/principal registry. It does not issue customer wallets,
initialize seeded SPL accounts, authorize spending or post financial journals.
It is included in the owner-authorized PR #1 development checkpoint; complete
phase acceptance and production gates are open. See the [dated decision](DECISIONS.md)
and [current status](PROJECT_STATUS.md) for merge evidence and remaining work.

## Original identity and durability

`MpcSolanaRoot` has one original keyset and tenant, unique base address, original
DKG evidence/package, isolated network/genesis/artifact identity and HOT/DEPOSIT
statement. Its ownership scope is the registered tenant UUID, not an arbitrary
caller-provided label. Generation0 remains the original DKG marker, not proof of
the current signing generation. Existing keyset algorithm/derivation metadata is
preserved. Automatic SOL root-wallet issuance remains disabled.

`MpcSolanaClaim` binds that exact original root to a registered principal in the
same tenant, its generated `p1:<UUID>` ledger owner, reviewed native/classic SPL
asset, immutable server-generated reservation UUID, retry key, shared monotonic
index and standard seeded address. Native SOL and different token mints consume
the same counter; decimals cannot create another namespace for an existing mint.
One original owner/mint reservation is allowed per root. A different retry key
cannot silently replace it. The counter uses numeric(20,0) to represent the exact
exhausted sentinel2**63 after allocating the final signed-bigint index.

The original PENDING record and mandatory audit commit before any mutating signer
RPC. A timeout, malformed response, partial quorum or unavailable audit after the
remote commit leaves that same pending identity for recovery. Retries preserve
the original signer signatures. Earlier pending claims must be recovered before
later indices can be approved; a higher reservation never skips a missing signer
index. Three genuine independently pinned archival HOT P256 receipts are required
for APPROVED, with distinct custody/signature domains for roots and claims.

APPROVED is public provisioning evidence, not ISSUED and not a signing grant. No
UserWallet, ledger account, balance, deposit, sweep, withdrawal or new execution is
created. The token mint must already have current classic SPL metadata verification
on the pinned isolated network. Token approval does not prove the seeded account
exists or is initialized. Finalized atomic create+initialize evidence remains
required before publication. Seeded addresses are not Ed25519 child public keys.

## Database and legacy compatibility

Migration0034 atomically adds only the two new tables, explicit PostgreSQL C
collations for exact addresses/mint namespaces/retry keys, constraints and guards.
It adds no historical backfill and rewrites no financial identity or journal.
The portable migration state still supports SQLite demo migration; protected
operations refuse SQLite and caller-owned/older-snapshot transactions.

The root INSERT locks the original keyset and all three legacy wallet/hot-wallet/
signing-session relations with SHARE ROW EXCLUSIVE NOWAIT before scanning any
history. Existing references, including an unbound SOL base address, reject
dedication. An active writer causes a retryable transaction failure; a later
writer waits for this short ceremony transaction and then rejects a dedicated
root. SOL legacy reference writes require READ COMMITTED so an older transaction
snapshot cannot miss a committed dedication. Pending dedication is already fenced.
Coordinator all-party history probes and signer-local role guards remain required;
the database cannot infer undisclosed remote signing history by itself.

Claim INSERT locks keyset, root and asset, checks original owner/tenant/asset/
statement/counter and advances the counter inside that same transaction. Root
and claim identity cannot be mutated or deleted; completed evidence cannot be
replaced. Original dedicated keyset metadata and reserved asset identity are
frozen. Display/capability changes remain separate from immutable identity.
Populated downgrade is refused even if no wallet has been published, because
off-database signer commitments may already exist. Admin is view-only.

SQL enforces receipt shape, not cryptographic validity. Privileged application
code and database owners remain trusted; disabling triggers, TRUNCATE and coherent
backup rollback are outside this boundary. Services independently verify pinned
signatures, and every future consumer must do so. A receipt-shaped SQL row is
insufficient authority. Database/file records are not an anti-rollback witness.
Archival signer-key rollover remains an explicitly reviewed future operation.

## Operator interface

Privileged operator filesystem/database and custody-machine credentials are the
authority. `operator-ref` is audit attribution, not authenticated human identity.
There is no tenant HTTP issuance endpoint or external IAM/RBAC implementation.

```sh
python manage.py solana_provisioning root --keyset-id <uuid> --tenant-id <uuid> --operator-ref <ticket>
python manage.py solana_provisioning reserve --keyset-id <uuid> --tenant-id <uuid> --principal-id <uuid> --asset-key SOL --idempotency-key <original-retry> --operator-ref <ticket>
python manage.py solana_provisioning approve --reservation-id <original-uuid> --tenant-id <uuid> --operator-ref <ticket>
```

The root action verifies original coordinator DKG metadata and freezes the
independently configured isolated network before committing the intent. Mutating
RPCs also verify endpoint genesis. Cached complete evidence can be recovered with
all signer services offline under the same configured policy and archival pins.
Never delete a failed/unknown pending intent or reuse its root/index for another
owner. Investigate and retry the original IDs. No production flag is relaxed.

## Acceptance and limits

All48 new PostgreSQL cases pass within the fresh758-case backend run in103.75s.
Separate review reran the initial46 in13.45s and the genuine scenario in31.46s,
independently checked all nine signer signatures and both SDK-derived addresses,
and found no P0/P1 in this bounded layer. Local PostgreSQL coverage includes both actual writer race orders with blocking
PID evidence, exact concurrent retries, cross-tenant/owner/asset substitutions,
raw SQL mutation/deletion/insert negatives, stale isolation, capacity sentinel,
audit rollback before/after remote effects, partial/lost responses and restart.
Synthetic public test receipts are explicitly separate from genuine MPC evidence.
The genuine integration scenario uses real FROST DKG/three encrypted signer stores,
Python custody authorization, all three pinned signer receipts, pinned Agave genesis
and verified on-chain classic mint, partial commits and service/DB restart recovery.
Only the specifically named public report is eligible for CI upload.

Remaining phase work includes authenticated external identity, actual issuance,
finalized SPL provisioning, signer-side original typed spending intent/decoding,
source-vs-base authority and fee/rent accounting, deposit/sweep/withdrawal integration,
real1000-issued-wallet benchmark, active epochs/witness/refresh/repair, rotation/drain/
late-deposit rescue and enforceable Hot/Warm/Cold boundaries. NOWAIT ceremony
contention, relation scans and signer index population cost remain unbenchmarked.
TON remains isolated/deferred with its independent artifact-audit blocker open.
