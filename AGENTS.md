# Wallet-MPC — standing instructions for AI coding agents and contributors

This file defines the mandatory read-before-code workflow. It is guidance for work in the repository, not a bypass of human approvals or security gates.

## Required orientation (every new chat/session/feature branch)

Read README.md, docs/PRODUCT_VISION.md, docs/PROJECT_STATUS.md, docs/ROADMAP.md, docs/DECISIONS.md, docs/ARCHITECTURE.md and docs/SECURITY_MODEL.md. Consult docs/PRODUCT_REQUIREMENTS.md and docs/API_CONTRACTS.md for relevant interfaces. Inspect implementation and existing phase evidence. **Verify current main SHA, active PRs and tests; this file's snapshot is historical.**

If the user's newest explicit decision conflicts with documentation, do not silently rewrite the product. Record the change proposal and seek owner approval when it changes scope/security; respect approved user direction for the task. If a historical document says an earlier phase feature is absent, check newer merged code before inferring present absence.

## Product invariant

Build a self-hosted enterprise custody + **financial core**, not merely an MPC wallet demo. Customer segments: exchanges, payment gateways, payment facilitators, merchants and institutional operators. External order book and matching engine; wallet platform is authoritative for balances, reserves, settlement, fees, on-chain custody and events. No second ledger.

## Security and financial invariants

- Never reconstruct a customer custody private key or substitute local-key signing for genuine MPC acceptance.
- Cryptographic signer quorum is independent of human transaction approval and independent policy enforcement.
- Bind every cryptographic authorization to tenant, keyset, network/genesis, asset, exact signed intent, recipient, amount, fee policy, nonce/sequence, policy version, expiry and operation ID as applicable.
- Preserve ledger double-entry conservation, immutable financial identity, Decimal/base-unit exactness, atomic settlement and idempotency. Never credit from mere wallet balance changes.
- An ambiguous broadcast/signing outcome stays reserved and requires authoritative reconciliation. Never assume timeout means failure.
- Fail closed on uncertain network identity, incomplete history, insufficient confirmations/finality, policy or signer quorum.
- No cross-tenant access, shared authorization scope or silent mutation of populated asset identities.
- Production activation per chain is independently gated. Never infer readiness from green testnet/isolated CI.
- No mainnet/customer funds until the applicable security/operations gates have been independently accepted.

## Scope and sequence

Latest merged development checkpoint: PR #1 at
`587e0969a216102879d17cadb6ffeee8dfb8b6c6` (2026-10-28). Its tree exactly matches
reviewed head `78394fc`; final-head Fast/full passed14jobs/228calls/zero skips,
and automatic main Fast passed. Continue remaining 6G-C from this merged base.
Draft PR #2 continues from this base with a typed intent, independent public
witness and required-profile protected Solana signer. Local genuine original-
generation signing, courier, restart, backup/partial and corruption cases pass;
see docs/PHASE6GC_SOLANA_SPENDING.md. Subsequent original-identity distributed
same-key refresh and encrypted generation loading pass genuine Gen1 all-pair,
COLD, interrupted/Gen2 and independently rerun private-peer/storage-fault cases;
see docs/PHASE6GC_SOLANA_REFRESH.md. Terminal R2 NoRelease now requires original
signed requests, separate lifecycle approval, durable local cancellation and
Frozen witness proof from every actual grantee. Any durable partial or missing
evidence remains unresolved; see docs/PHASE6GC_NO_RELEASE.md. Genuine restart,
write-failure, late-permission, race, COLD and refresh/retry cases pass, including
independent review/reruns. Narrow same-identity profile migration and one-share
repair now have bounded genuine development evidence; finalized SPL wallets,
financial integration and whole-phase acceptance remain incomplete. Unmerged
native Claim-linked wallet publication now requires a separate permanent witness
grant; expanded genuine three-wallet tests pass. After an initial timeout, the
retry actually published1000 wallets in627.149s and finalized all-pair transfers
from issued indices0/500/999 (complete case737.59s). See docs/PHASE6GC_NATIVE_ISSUANCE.md.
The public replacement reservation/abandonment and original witness-store replay
boundary now has independent17-unit and actual-runtime upgrade/tampering evidence;
see docs/PHASE6GC_RECOVERY.md. Explicit LC=None source fencing, verified successor
history import and HOT/COLD migrated signing now pass bounded local cases.
Further unmerged private upstream one-share RTS, fresh recipient provenance and
all-three replacement refresh now have genuine HOT/COLD, restart and storage/TLS/
expiry fault evidence plus bounded independent review. Existing original Claims
only; repaired staging cannot sign. New durable ordinary-refresh reservation
permanently binds both IDs before private work, with forward-only rules2 and old
signed-history replay. Genuine restart/abandonment and historical-ID recovery pass;
whole-phase recovery, current-identity Claim progression after replacement and
fresh-DKG drain/retirement remain unfinished. See docs/PHASE6GC_RECOVERY.md and
PHASE6GC_SOLANA_REFRESH.md. Current development source still needs its exact-head
CI and final whole-phase review.
Further financial-contract foundations add class-pinned read-only queries over
existing courier TLS and explicit clean irreversible Root financial mode. Typed
reservation/source-owner identity has bounded actual crypto/maintenance evidence;
its references are synthetic in these cases. A typed HOT public-state coordinator
now has9 genuine local fault/recovery cases and3 independent reruns, with
signature-only completion and current-source CI pending. Separate clean-Root mode
import has54 PG cases and a genuine Rust W roundtrip; it activates no wallet/ledger.
Direct seeded credit remains closed. Subsequent uncommitted immutable principal
roles have bounded source/49-targeted/genuine-import evidence plus840 backend tests
and independent49-case/genuine reruns; current-source CI remains pending.
Separate0038 native customer/treasury membership now has39 PG and genuine
publication/independent evidence plus879 backend tests. Treasury creates no
UserWallet; ACTIVE is membership only. Protected financial sessions, seeded
credit/provenance and actual ledger integration remain unfinished; current-source
CI is required.
Optional backend query/record courier transport has9 actual TLS and genuine W
query/publication evidence, independently rerun with stable hashes. It has no
Life/Policy key or private-permission route; caller durable freshness/financial
validation remains required. Positive authentic result redelivery is still an
upcoming financial recovery gate. See PHASE6GC_FINANCIAL_INTEGRATION.md.
See docs/PHASE6GC_FINANCIAL_INTEGRATION.md. No phase completion is implied.
Courier2077eea exactFast41357648627 passed. New0039 unprepared allocation commits
business/approval/source, then both MPC UUIDs and OnchainAttempt before query or
lifecycle export. Only fresh pinned W permanent abandonment permits a new crypto
attempt; the original hold remains.59 PG/SQLite cases and actual Rust W case pass,
independently59 cases57.528s/genuine7.989s with stable hashes and no remaining
bounded P0/P1. Review caught/fixed old-snapshot and late ledger-release races;
generic paths remain fenced. Prepared/private signing, broadcast, settlement and
seeded credit remain closed; full backend/current-source CI are still required.

Phase 6G-B is merged as **development** at `3d32b763ff777347f77eae7a8a7936d85dc2d770`. Phase 6G-C (Solana provisioning, key lifecycle/rotation/recovery and Hot/Warm/Cold foundations) remains incomplete. On 2026-10-28 the owner explicitly authorized merging the verified bounded development checkpoint in PR #1 and continuing the next implementation step. See the dated decision in docs/DECISIONS.md: this supersedes keeping all remaining 6G-C work in that one Draft PR; it does not complete 6G-C or authorize Phase 7 or production. Keep original Phase 7A/7B/7C, 8A/8B/8C/8D and 9. TON public network, arbitrary shards and real USDT work are **deferred**; preserve existing TON code and open audit blocker, do not activate or widen it unless owner explicitly changes scope. Bitcoin, bridging, swaps, exchange matching engine and trading order book are out of current scope.

A proposed feature is not an implemented feature. A merged implementation is not production-approved. Label every status accordingly.

## Change workflow / evidence

1. Confirm clean baseline, base/head SHAs and exact scope. Use isolated feature branch, smallest reviewable PR.
2. Review data migration/backfill and compatibility before changing ledger, ownership or on-chain identity.
3. Define acceptance and negative tests, concurrency/restart/failure/unauthorized scenarios and audit trail.
4. Run targeted Fast CI; for MPC/chain/financial-impacting changes run the required final-SHA cryptographic gate. Do not weaken expensive checks to gain speed.
5. Update docs/PROJECT_STATUS.md, docs/DEVELOPMENT_HISTORY.md and affected requirements/decisions **in the same PR** when facts change. Never mark production-readiness from development tests.
6. Supply changed files, commit SHA, CI links, migrations, residual P0/P1/P2 risks, and proof of no production flag relaxation.
7. Obtain genuine independent review for cryptographic, authorization and sensitive financial changes. The owner’s adopted Master Development Directive v2.0 authorizes development merges only after acceptance, exact-final-SHA CI, required reviews and repository rules all pass, with no blocking P0/P1. Never bypass protections or fabricate approvals. Complete and merge the current phase before advancing. Production/customer-fund activation remains separately authorized.

Latest99a055e allocation checkpoint passed Fast41361207460 and selected Solana
41361259277:59 selected/called,0skips,verified inventory276 and57 public files;
not ALL and before subsequent execution changes. Committed c233a04/0040–0042
add native exact-wire approval, protected signing/public recovery, original-wire
broadcast/finality and existing-ledger settlement.124 focused cases146.21s and
three genuine FROST/PG/Agave sweep cases141.72s pass (success,lostACK,auditrollback).
Final independent129 cases150.692s and3genuine141.350s/stable22source+3bins pass;
no remaining identified bounded P0/P1. ExactFast41425030949 and full local backend
1017 cases538.917s pass at c233a04. Synthetic
sweep funding/snapshot are not deposit/customer-liability acceptance. NoSignature
permits another crypto attempt under the same hold; it cannot release a business
hold from local history alone. Subsequent committed55e245e/0043–0044 add native finalized
deposit provenance, actual legacy/v0/PDA source attribution and pre-allocation
financial private-routing/legacy-history gates. Seeded credit remains default-off;
live finalized scanning and explicit permanent operator-funding classification
are required. Ordinary shared-hot-wallet signing cannot service an enrolled
financial customer. Independent209 cases206.063s and3 genuine legacy/v0/PDA full
flows332.263s pass with stable54-source/3-binary hashes and no remaining bounded
P0/P1. Root80 component cases58.966s, Django checks/drift and lint pass. Exact
Fast41445276955 passes four jobs including1097 backend tests521.11s; it excludes
subsequent uncommitted SPL primitives. Final whole-phase ALL/compatibility, SPL,
repaired-identity new Claims, fresh-DKG retirement and final phase gates remain
unfinished. See PHASE6GC_FINANCIAL_INTEGRATION.md.

Subsequent default-off classic SPL financial source now reuses original operation/
session/ownership and ledger records for initialization, publication, seeded
treasury sweep, external withdrawal and instruction-attributed deposit credit.
Root103 targeted cases130.43s and independent313 cases302.898s pass; current
independent genuine SPL176.216s/Native3 331.088s pass with stable82-path hashes.
Exact136d995 Fast41499260859 passes4 jobs/1201 backend tests705.55s. An accepted
public-query-only lease retry helper is included in7ff1e56 Fast41536746241,
which passed4 jobs/1201 backend tests485.46s. Read PHASE6GC_SPL_FINANCIAL.md;
no whole-phase completion follows.

Next current-identity public Claim boundary has independent85 contracts and7
genuine cases533.394s/zero failures/errors/skips, with112 source/binary hashes
stable. Original Root/Claim receipt domains and old signed event replay remain
unchanged. Node approvals cover actual HOT/COLD refresh/replacement, restart,
historical context use, share-only restore and explicit old rules2 recipient pin
promotion; read PHASE6GC_CURRENT_CLAIMS.md. Backend registration/effective-evidence
consumption and financial publication after replacement remain unfinished, as do
fresh-DKG drain/retirement/rescue and final whole-phase/CI gates.

Subsequent node cleanup e1664ed Fast41594758324 passes4 jobs/1228 backend cases
670.51s. The0046 checkpoint adds default-off immutable current Claim registration,
archival original/effective evidence separation and public operator handoff.
Independent527 contracts/backend cases and actual repaired financial flow157.113s
pass. A final narrow raw-SQL deadline fix changes only0046/test; independent1-case
fresh-DB regression4.105s passes, with116 other source/bin hashes unchanged.
Earlier527/runtime evidence carries forward qualified, not rerun after that fix.
Root55 current cases38.37s pass. No remaining identified bounded P0/P1 or concrete
P2 gap. Exact f58d219 Fast41624031631 passes4 jobs/1283 backend cases785.63s;
full-crypto jobs were unselected. See PHASE6GC_CURRENT_CLAIMS.md.
Fresh-DKG migration/retirement/rescue and final whole-phase gates remain open.
Preserve original proofs and all held/allocated IDs; reject prepared/consumed/
uncertain proof migration. No Life/Policy private key or balance mutation is
introduced by registration.

## Latest owner-approved Phase 7B scope

Optional, default-disabled, administrator-managed manual withdrawal address blacklist only. Audit changes, recheck before execution and at independent signer authorization, fail closed for unavailable enabled policy, and preserve reservations/history. No deposit screening, deposit holds, external AML/KYT services or automatic address feeds. Preserve unrelated financial/finality/security controls. This is a planned feature, not existing enforcement.

## API-first design guard

Separate API identities and permissions for tenant/customer, exchange engine, merchant, operator, compliance, and signer. Matching-engine credentials only access narrow order-reserve/settlement authority, never generic balance mutation or arbitrary signing. Signed, durable, replayable outgoing event delivery is required. Stable schemas and backwards-compatible versioning are part of acceptance.

See docs/DOCUMENTATION_GOVERNANCE.md for conflict resolution and required documentation updates.

Uncommitted0047 per-Root receipt archives preserve old/new independent cohorts;
initial pins come only from operator files, never coordinator-provided trust.
Original Root/Claim validation resolves exactRoot archives; currentSome authority
is separate. NewRoot immutable reservation flag/deferred snapshot commit, explicit
approved legacy import, final Claim-lock reverify and populated downgrade guard
have40 new/149 affected legacy PG cases and one actual two-cohort case8.44s with
124 unchanged source/bin hashes. Independent189 backend cases135.216s and2
genuine cases158.945s pass with unchanged124 hashes; no remaining identified
bounded P0/P1 or concrete P2 gap. Exact f9f4445 Fast41696076316 passes4 jobs/1323
backend cases798.12s, predating0048; full-crypto jobs unselected. No whole-phase
acceptance follows. See PHASE6GC_RECEIPT_PINS.md. Preserve no-row-only
legacy fallback; malformed/required-missing snapshots must fail before remote work.

The0048 coordinator-routing prerequisite has bounded independent338 unique PG/
transport cases across qualified runs, plus3 genuine cases278.711s. The original
313PASS/one historicalGBfixture failure is retained; historical0031ORM-only setup
correction passed final48 cases62.767s. Production130paths stayed unchanged across
allruntime cases; correctedtest gives131finalstablepaths. No identified bounded
P0/P1 remains. Exact143dfb5 Fast41702205647 passes4 jobs/1364 backend cases815.43s
(fullcrypto unselected). URL/SPKIbinding/forwardkeysetmarker
must commit before backend import, with no alternate coordinator after ambiguity.
Typed private dispatch preflights localTLS beforeREADY CAS; public W-onlyrecovery
can proceed withoutcoor config, preservingallcryptographicproofs. Genericstartup/
legacyflows retain their existingglobaltransport requirements. SharedCustodybody
credentials remainrequired; noactivationflagrelaxation. Read
PHASE6GC_COORDINATOR_ROUTING.md beforechangingthesecontracts. Actualfundmigration,
retirement/rescue andfinalwholephase gates remainunfinished.

2026-11-04 rotation-data draft: solana_rotation is a PURE contract layer, no W/
private/ledger authority. SourceMembership distinguishes unpublished/control-only/
financial PENDING or ACTIVE; never synthesize financial activation or ownership.
Stable business fingerprints exclude fresh authorization/gen/TTL but include all
Roots/inventory/targets/budgets. Fee caps are per movement AND cumulative; renewal
cannot replenish. All namespace/generation/target-currentness/actual-control and
inflight-budget checks remain mandatory in W before future permits. Independent26
protocol cases75.66s and workspaceClippy10.27s pass with136 paths unchanged; no
bounded P0/P1/concreteP2. Do not present this as runtime rotation acceptance.
Read PHASE6GC_ROTATION_CONTRACT.md before integrating it. Existing original signed
messages and encrypted-store compatibility must remain unchanged.


2026-11-09 witness rotation staging draft: read PHASE6GC_ROTATION_INVENTORY.md.
Rules4 changes only fresh admission; preserve exact old signed replay. Staged source
maintenance remains fenced; every new ordinary R1/R2 requires known recipient Roots
Active. Mode-off issuance stays exact archival LegacyControl, never synthetic
financial membership. Migrating currently grants NO movement. Before adding private
migration, strengthen abandonment against possible signatures and implement actual
original-wire finality, in-flight fee budgets and existing financial parent/effect/
ledger integration. Root49 W tests and Clippy pass; independent28 protocol/49 W cases and6 genuine cases pass across qualified
runs with159 stable paths; exact-source CI remains pending. No whole-phase completion, merge or production follows.


2026-11-09 public finality draft: read PHASE6GC_PUBLIC_FINALITY.md. All3 CURRENT
SOURCE nodes only; exact old W SignedPending signature/binding/package, Frozen and
resolved maintenance, own initial/post-observation W proof under original15s lease.
Runtime MUST verify all embedded Life/node/W P256 signatures; content validation
alone is not authority. Separate immutable facts never rewrite SignedPending,
release holds, replenish fees or allow a signed logical retry. Rules5 preserves
old0–4 signed messages. Exact-revision ACKs currently process serially. Public
observation uses only enrollment/provenance/public package, not an old missing
share. Independent39 protocol/55 W cases, Clippy and9 genuine strict-source cases
356.041s pass with167 stable paths and no concrete bounded P0/P1. Serial ACK
availability remains documented. Exact-head/whole-phase gates are pending. No movement/retirement/phase completion.


2026-11-10 local pause draft: read docs/PHASE6GC_ALLOCATION_PAUSE.md. Immutable0049
Root/frontier fence is separate from W freeze and inventory completeness. New
operation births lock all source/known-destination keysets then Roots in order;
HELD incoming work blocks target pause, supporting source-only private checks.
NoSignature does not remove the original hold. Public retries/recovery remain
separate; no release/reset or ledger authority exists. Root35 PG cases51.90s and
one pre-lock-hardening two-cohort case15.00s pass. Final independent618 backend
cases948.157s and4 genuine cases307.541s pass with174 unchanged paths and no
bounded P0/P1. Exact-source CI remains pending. Parent473d86a Fast42704314910 passes4 jobs/1364 backend cases807.77s;
not ALL or whole-phase acceptance. Do not enable production or merge partial phase.


2026-11-10 backend inventory checkpoint: read docs/PHASE6GC_BACKEND_INVENTORY.md.
0050 is source data only over an immutable0049 pause, never private/ledger grant.
Own ROOT/ENTRY/SEAL15s leases, exact Frozen context, complete registered prefix/
aliases, principal role-birth locks and archival native/SPL provenance protect the
handoff. PENDING and mode-off issuance never become synthetic financial ACTIVE.
Normal private validation retains its original enabled-asset path. Independent168
backend cases381.863s and2 genuine cases354.981s pass, zero failures/errors/skips.
Final180-path baseline (176source/helper/test/workflow/manifests+4bins) is stable;
only an earlier helper-format delta is qualified/AST-equivalent. No bounded P0/P1.
Root32 cases52.94s and1000/Repaired actual runs157.82s/176.38s retain their original
qualifications. Exact-source CI is pending. BEFORE any movement/retirement add W
coverage of ALL retained same-Root candidates/prior staged frontiers, evenabandoned
history, under new forward rules preserving exact original0–5 replay. Local DB
frontier/registered W frontier alone cannot prove restored-history completeness.
Do not merge partial phase or activate production. Parent87b8abf Fast42761045014
passes4 jobs/1399 backend cases844.20s; not ALL.


2026-11-10 retained-inventory INTERIM quarantine draft: read
docs/PHASE6GC_RETAINED_INVENTORY.md. Rules6 fences shrunken known/prior declared
frontiers, requires exact historical full-FP prefixes at seal, and blocks new
ownership/ordinary activation/private permits across unresolved commitments.
Original0–5 replay stays unchanged. Root64 W cases1.97s and4 genuine cases116.20s pass. Independent64 W cases1.38s,
final Clippy2.38s and4 genuine cases120.085s pass with180 unchanged paths. The only post-runtime delta is three reviewed test-only negatives; production
source and runtime binaries stayed unchanged. This deliberately blocks legitimate
metadata evolution; full historical materialization and explicit provisional
poison reconciliation remain mandatory before movement/retirement. No new
MIGRATION/RESCUE, financial or phase authority follows.
