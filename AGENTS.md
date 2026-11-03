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
P2 gap; exact-source CI remains required. See PHASE6GC_CURRENT_CLAIMS.md.
Fresh-DKG migration/retirement/rescue and final whole-phase gates remain open.
Preserve original proofs and all held/allocated IDs; reject prepared/consumed/
uncertain proof migration. No Life/Policy private key or balance mutation is
introduced by registration.

## Latest owner-approved Phase 7B scope

Optional, default-disabled, administrator-managed manual withdrawal address blacklist only. Audit changes, recheck before execution and at independent signer authorization, fail closed for unavailable enabled policy, and preserve reservations/history. No deposit screening, deposit holds, external AML/KYT services or automatic address feeds. Preserve unrelated financial/finality/security controls. This is a planned feature, not existing enforcement.

## API-first design guard

Separate API identities and permissions for tenant/customer, exchange engine, merchant, operator, compliance, and signer. Matching-engine credentials only access narrow order-reserve/settlement authority, never generic balance mutation or arbitrary signing. Signed, durable, replayable outgoing event delivery is required. Stable schemas and backwards-compatible versioning are part of acceptance.

See docs/DOCUMENTATION_GOVERNANCE.md for conflict resolution and required documentation updates.
