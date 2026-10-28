## 2026-10-28 — PR #1 merged and next 6G-C intent contract started

GitHub confirms PR #1 MERGED as `587e0969a216102879d17cadb6ffeee8dfb8b6c6`, with
parents3d32b763 and final reviewed head78394fc. Its tree
`affecb334af959a462fd747b0fdf49a3a731f182` exactly matches that final head.
Fast40683968092 and ALL40683962776 passed:14 full jobs,228 actual calls/zero skips,
all seven exact-head artifacts and original-store compatibility665.205s independently
verified. Automatic main Fast40716836844 passed all four executed jobs. This is
the owner-authorized development checkpoint, not completion of Phase 6G-C.

Local post-merge checks/migration drift passed and all48 PostgreSQL provisioning
cases passed53.73s after restarting existing development services stopped during
environment idle. The initial attempt failed on connection-refused setup errors;
no code regression or database reset was involved. Live/ready return200 with
databaseOK and unchanged optional Redis degradation.

The next branch `codex/phase6gc-seeded-spending` starts directly from merged main.
It promotes a pure public typed intent/wire/domain constructor, nine Rust tests,
twelve SDK/Python-canonical goldens and a reproducible no-RPC generator. No route,
nonce, witness freshness, business authority, wallet issuance or financial flow
is enabled. See [implemented and pending boundary](PHASE6GC_SOLANA_SPENDING.md).
Independent promoted-source review reran final9 tests in0.29s and regenerated all12
goldens with DB connections forbidden, including the Unicode case. No blocking
P0/P1 was identified within the unconnected library. New exact-head CI remains required.

## 2026-10-28 — verified checkpoint and explicit development merge request

At `1d4737ecf53d3e445c83c89f382f71b9ddbd8c57`, Fast40675308341 and full40675302192
passed all required checks:14 full jobs,228 actual calls and zero skips. Separate
review independently fetched all seven remote artifacts, verified exact SHA,
selected/called inventories and original-store compatibility652.422s against fixed
main3d32b763, all six compatibility cases and distinct original/candidate binaries.
No blocking P0/P1 was identified in the bounded implemented checkpoint.

The owner then explicitly requested merging correct verified work and proceeding
to the next step. The [dated decision](DECISIONS.md) records this delivery-granularity
change: PR #1 may merge as a development checkpoint after its final-head gates,
while 6G-C remains incomplete and subsequent work stays within that phase.
This documentation update records preparation, not a future successful merge.
Actual merge SHA/main verification must be recorded after GitHub confirms it.
No production/mainnet/customer-fund gate or deferred TON scope is changed.

## 2026-10-28 — authoritative operator Solana reservations (unmerged)

Migration0034 adds original tenant-bound Solana roots and principal/asset/index/
retry reservations. PENDING records and mandatory audit commit before mutating
RPCs; APPROVED requires all three independently pinned archival signer receipts.
The database freezes original DKG/network/asset/ownership identity, allocates one
shared monotonic signed-bigint index space with an exact exhausted sentinel,
fences existing and later legacy financial/signing references, and refuses
populated downgrade. No historical owner/journal backfill, wallet issuance,
seeded SPL initialization, spending grant or financial posting is introduced.

The initial46 PostgreSQL cases passed13.00s; a separate reviewer reran46 in13.45s.
Real FROST/Agave/PostgreSQL acceptance passed30.16s and independently31.46s,
including partial/lost responses, service/DB restart and all-signers-offline
receipt recovery with original encrypted shares unchanged. Independent public
verification checked all nine signer signatures and both SDK-derived addresses;
bounded source review found no P0/P1. A subsequent isolation hardening covers
cross-chain legacy aliases pointing to SOLANA keysets and invisible keysets.
Final expanded fresh backend suite passes758 cases in103.75s, including all48 new
cases. Exact-head Fast/full remain required before this checkpoint is accepted.
SQLite full migration through0034 and protected-operation refusal pass.
See [scope, residual trust and remaining work](PHASE6GC_SOLANA_REGISTRY.md).

Separately, exact prior checkpointa28da6d passed Fast40626197327 and
ALL40626191763: all14 full jobs,227 actual calls and zero skips. Independent
remote artifact review verified exactSHA and original encrypted-store compatibility
413.05s against fixed main3d32b763. These results do not transfer to later source.
Whole6G-C remains Draft/unmerged; no phase advance or production activation.

## 2026-10-28 — operator-only tenant/principal identity registry (unmerged)

Migration 0033 adds immutable CustodyTenant/CustodyPrincipal mappings, generated
`p1:<UUID>` owner IDs, exact scoped references and PostgreSQL identity guards.
Standalone READ COMMITTED registration takes five-table NOWAIT locks before any
legacy ownership scan, rejects prior ledger/wallet/withdrawal/MPC account or orphan
reservation IDs, and writes mandatory audit atomically. Admin cannot mutate even
unused rows. A populated registry blocks downgrade; no legacy row/backfill or
financial account is created. PostgreSQL-only C collations preserve exact identity
while portable SQLite demo migrations remain usable; protected registry operations
require PostgreSQL. All 47 new cases passed in 18.48s; separate review independently
reran 47 in 15.44s and found no P0/P1 in the operator-only boundary. SQLite fresh
migration/registration-refusal smoke passed. See [scope](PHASE6GC_IDENTITY_REGISTRY.md).
External auth, root/claim linkage, financial consumers, scalability and full phase
acceptance remain incomplete. New source needs new CI; no funds/production flags.
The complete backend suite passed710 cases in149.78s. A strengthened migration
case additionally preserves a nonzero balanced journal, all original accounts/
postings and7.25-unit balance (1passed,2.14s).

## 2026-10-28 — bounded historical-quorum checkpoint verified (unmerged)

At exact `e5b82faa0e552662243e2d04defa5b5d16ae4404`,
[Fast 40579867138](https://github.com/zeroexlive/Custody/actions/runs/40579867138)
and [full 40579857716](https://github.com/zeroexlive/Custody/actions/runs/40579857716)
passed. Full has all 14 jobs successful, actual 227 selected/called scenarios and
zero skips (EVM45/TRON5/SOL10/TON3/network162/aux1/integrated1). Original-store
upgrade passed in 425.729s against fixed original main 3d32b763. A separate reviewer
independently fetched all seven remote artifact ZIPs and verified exact SHA, all
calls/skips and the original-store gate. This accepts the bounded quorum/fence
checkpoint, not all 6G-C, production activation or subsequent registry changes.

## 2026-10-27 — preserve unused-first historical signer quorum (unmerged)

Independent review reproduced a valid-authority edge missed by earlier tests:
historical b/c use let a dedicate first before b rejected. The coordinator now
rejects all historical signing intent and probes every original store before
mutation, including when its own signing history is restored older. It durably
pins a pending intent while holding the same data mutex as new signing-session
reservation; pending/complete roots reject new generic signing. Exact prior
session recovery remains available. Seven genuine cases passed in20.36s, including
all legacy pairs after rejection, create/enroll competition and missing-complete-
cache recovery with the fence retained. Inventory227; fresh-head CI remains required.
Direct local APIs, malicious-coordinator races and coherent rollback are not a
global distributed lease; fresh unreferenced-root selection and later witness/
policy enforcement remain mandatory. No issuance/funds activation is introduced.
The reviewer independently reran the new regression (1passed,6.38s), with no
remaining P0/P1 in the declared single-coordinator flow. All48 legacy FROST
process cases passed in73.55s. New final-head gates remain mandatory.

Separate review verified checkpoint94a0216 Fast40573881921 and full40573875580:
all14 jobs passed, all225 scenarios called with zero skips, original-store
compatibility315.32s. That checkpoint precedes coordinator aggregation and this
later compatibility fix; it is not acceptance of the unfinished whole phase.

## 2026-10-27 — three-store seeded agreement and independent receipt checks (unmerged)

Custody-mTLS coordinator routes relay original detached provisioning proofs,
verify original completed DKG context and collect all three ordered matching
signer receipts. Only complete agreements are pinned; partial commits recover
their exact original signatures after restart. Complete public retries work with
all signers offline, without granting a new operation. Custody's pinned receipt
verifier adds separate Solana root/claim domains and rejects coordinator-key
forgeries, domain substitutions, reordered/partial/duplicate statements. Six
genuine store/agreement cases passed in14.27s; 38 existing EVM/TRON backend
issuance/provisioning cases passed in17.38s. Independent source review found no
concrete P0/P1 in this bounded layer. Inventory226; fresh-head CI remains required.
There is no Django wallet issuance, new financial journal, tenant login or seeded
spend permission. Epoch/rollback/class and full-phase gates remain open.

Checkpoint94a0216 Fast40573881921 passed all four jobs; local56 distinct
Solana/FROST cases passed, including2 actual PostgreSQL custody/recovery cases
in365.32s after starting the restored database container. Its full40573875580 is
separate from subsequent coordinator work; do not transfer a checkpoint gate.

## 2026-10-27 — authenticated signer-local seeded root/claim records (unmerged)

Original custody P-256 proofs now authorize immutable initial HOT/DEPOSIT FROST
root dedication and owner/mint/index/retry claims on each signer. Each party
reopens its encrypted original DKG and signs its own durable public receipt.
Historical use fences dedication; dedication fences the legacy arbitrary-message
API under one lock. Immutable index-first writes retain partial claims across
restart and protect aliases, including global reservation UUIDs across roots.
Independent review found interrupted-temp handling and a cross-root partial-alias
collision; both were corrected with genuine process regressions. Five new cases
passed in 11.31s; the reviewer independently reran the strengthened approvals case
(1 passed, 3.63s), finding no remaining concrete P0/P1 in this bounded diff.
No customer issuance, tenant identity, seeded spend authorization, chain attestation,
epoch/antirollback, identity-key rotation or complete-phase acceptance is claimed.
The new full crypto inventory is 225. See [boundaries](PHASE6GC_SOLANA_SEEDED.md).

Previous exact head `a1b6ae99` passed Fast40531484471 and selected Solana40531473864;
downloaded public evidence confirms all three selected scenarios executed with
zero skips and seven finalized primitive transactions. This was a selected gate,
not all-chain acceptance or validation of the new signer-local records.

## 2026-10-27 — independently verified seeded Solana wire/spend primitives

The unmerged 6G-C branch adds Rust-side exact standard message/address checking,
one regression case covering 15 independent SDK fixtures plus coordinated
substitution/malformed negatives, and a reproducible genuine Solana regression.
Actual repository acceptance passed **one case in 150.23s** (four existing
warnings): seven finalized transactions, all three FROST pairs for native and SPL
transfers, atomic seeded SPL creation, independently verified original signed
bytes, both transfer legs, base fees, initialized token identity and ATA rent.
The final pair repeats idempotent creation of an existing ATA with zero added rent.
Public evidence is generated inline; no private stores/PKI are uploaded.
Separate source review found no P0/P1 within this unconnected primitive scope.
This does not implement customer issuance, independent seeded grants, tenant/epoch
proofs or ledger integration. See [scope](PHASE6GC_SOLANA_SEEDED.md). The complete
crypto inventory now contains 220 scenarios; new final-head CI is still required.

## 2026-10-27 — dependency migration regression gate passed (unmerged)

At `ea4bb4edfd646b34a58e00170a734e57674b1825`,
[Fast 40521504904](https://github.com/zeroexlive/Custody/actions/runs/40521504904)
and [full 40521510401](https://github.com/zeroexlive/Custody/actions/runs/40521510401)
passed; full has all 14 jobs successful. All seven public scenario manifests show
219 selected/called scenarios and zero skips. Fixed-original-main encrypted-store
acceptance passed in 518.46s. A separate review agent independently verified
remote run/manifest artifacts as well as source/provenance and compatibility.
This accepts the bounded version remediation in Draft PR #1; main is unchanged
and whole Phase 6G-C remains incomplete. Later commits need new final-head gates.

## 2026-10-27 — owner-authorized RustCrypto backend remediation (unmerged)

The owner explicitly approved the maintained-backend integration investigation
and migration with independent review after the incompatible resolver result.
The owned generic-ec-curves adapter ports only the selected secp256k1 integration
to k256/elliptic-curve 0.14 and patched crypto-bigint 0.7.10; original CGGMP,
HD/key-share and separate FROST protocols remain unchanged. Public golden vectors
match the original backend exactly; bounded real-process old-store FROST, root
and original-child all-pair signing have passed. The full network gate gains a
reproducible fixed-main historical-store acceptance step. See
[dependency report](PHASE6GC_DEPENDENCY_GATE.md) and vendor provenance/delta for
scope, exact evidence and pending final-head checks. This is unfinished Phase
6G-C on Draft PR #1, not a phase merge, external audit or production approval.

# Verified development history and evidence

**Source policy:** timeline below is extracted from merged pull requests / main history, not an assertion that every historical attempted PR merged. The repository had 34 PRs as of 2026-10-11; several earlier attempts were closed **without merge** (e.g. PRs #4–7, #9–13, #15–24). Do not include unmerged proposals in delivered capability counts.

## Mainline implementation chronology (UTC)

| Date | PR | Delivered development milestone |
| --- | --- | --- |
| 2026-10-03 | [#1](https://github.com/hassan-anari/Wallet-MPC/pull/1) | Stabilization, fail-closed signer/demo boundaries, sweep/gas/idempotency regressions |
| 2026-10-03 | [#2](https://github.com/hassan-anari/Wallet-MPC/pull/2) | Phase 2 authoritative double-entry custody ledger |
| 2026-10-03 | [#3](https://github.com/hassan-anari/Wallet-MPC/pull/3) | Phase 3 DB-backed chain registry and adapter/indexer resolution |
| 2026-10-04 | [#8](https://github.com/hassan-anari/Wallet-MPC/pull/8) | Phase 4 durable native transaction execution/reconciliation |
| 2026-10-05 | [#14](https://github.com/hassan-anari/Wallet-MPC/pull/14) | Phase 5 reviewed fungible-token custody foundation |
| 2026-10-08 | [#25](https://github.com/hassan-anari/Wallet-MPC/pull/25) | Phase 6A self-hosted MPC baseline, disabled outside development |
| 2026-10-08 | [#26](https://github.com/hassan-anari/Wallet-MPC/pull/26) | Phase 6B TLS 1.3 mutual-authenticated transport |
| 2026-10-08 | [#27](https://github.com/hassan-anari/Wallet-MPC/pull/27) | Phase 6C.1 genuine distributed FROST DKG / signer-local stores |
| 2026-10-08 | [#28](https://github.com/hassan-anari/Wallet-MPC/pull/28) | Phase 6C.2 FROST distributed signing and durable nonce safety |
| 2026-10-09 | [#29](https://github.com/hassan-anari/Wallet-MPC/pull/29) | Phase 6D genuine CGGMP24 ECDSA |
| 2026-10-09 | [#30](https://github.com/hassan-anari/Wallet-MPC/pull/30) | Phase 6E root-keyset EVM MPC integration |
| 2026-10-09 | [#31](https://github.com/hassan-anari/Wallet-MPC/pull/31) | Phase 6F-A isolated TRON / TRC-20 |
| 2026-10-10 | [#32](https://github.com/hassan-anari/Wallet-MPC/pull/32) | Phase 6F-B isolated Solana / classic SPL |
| 2026-10-10 | [#33](https://github.com/hassan-anari/Wallet-MPC/pull/33) | Phase 6F-C isolated TON V5R1 / TEP-74; exact audit OPEN |
| 2026-10-11 | [#34](https://github.com/hassan-anari/Wallet-MPC/pull/34) | Phase 6F-D four-chain integrated development acceptance and financial identity/EVM history hardening |

Historical Phase 6F-D merge SHA: **4488016a668283868633eb1a7fa2f64187a93b56**. PR #34 final reviewed feature SHA: **04bb9c621a3aba5a6313bff0c6f5028b4fc803b3**. Different SHAs are expected for merge commits.

## Subsequent orientation and active development (not merged capability)

- 2026-10-11: [PR #35](https://github.com/hassan-anari/Wallet-MPC/pull/35) established
  the authoritative enterprise product/engineering documents; verified main
  `99d005e23f1463ebb245fc451552af944a1fdd1f`.
- [Phase 6G Draft PR #36](https://github.com/hassan-anari/Wallet-MPC/pull/36),
  branch `phase6g-provisioning-foundation`, based on that exact main:
  pinned-source crypto feasibility audit, original-root namespace registration
  and durable non-hardened path reservations with migrations 0027/0028. Unmerged,
  for independent review. Local 10,000-row PostgreSQL benchmark: 46.1376s,
  216.743 reservations/s, 3,579,904 table/index bytes. These are **not issued
  spendable addresses**. See [PHASE6G.md](../PHASE6G.md); exact final head/CI
  links and genuine-service evidence are provided in the Draft PR handoff.
  Initial local evidence: 570 backend tests and genuine CGGMP/mTLS registration
  plus coordinator/DB restart passed (338.10s). GitHub jobs failed before runner
  assignment; final-head Fast/full CI acceptance remains blocked, not waived.
  Supporting code head 09653ef subsequently passed 571 PostgreSQL tests and a
  fresh genuine CGGMP registration/restart case (857.41s). Cargo audit exited 0
  with atomic-polyfill maintenance and pinned scc 2.4.0 unsoundness warnings;
  scc comes through existing everscale-types, uses HashSet in inspected source,
  and requires separate dependency/reachability review. Final documentation
  records this finding without changing crypto dependencies or tested code.

## Significant discovered/fixed failure classes (development)

- Phase 6A–D: move from demo/local signing primitives to genuine independently running DKG/signers, authenticated transport, robust execution identity and nonce safety.
- Phase 6E–F: reviewed network/genesis identity, chain-specific signing/broadcast/finality and token-code matching.
- Phase 6F-D: immutable populated asset financial identity, preventing native/token aliases and root rebinding; safe EVM genesis pins and completion-gated settlement; native network-fee posting; signed recipient serialization fix.
- Phase 6F-D follow-ups: native EVM scanner previously reported false head after partial read and last-64-only scanning; repaired with 64-block verified historical chunks, height/hash checkpoint, atomic deposit-credit/cursor and migration **0025**.
- Phase 6F-D final: ERC-20 formerly used 1,000-block initial lookback and could accept missing/false-empty logs; repaired with genesis backfill, receipt-trie/root corroboration, overlap, fail-closed errors, atomic journals/checkpoints and migration **0026**. Original financial-identity trigger migration **0024** stays.
- PR #34 final [full-gate](https://github.com/hassan-anari/Wallet-MPC/actions/runs/38129567244) 14/14 successful, 814 test executions. Real isolated recovery scenario older than 1,000 blocks accepted exactly once; unknown broadcast outcomes remain reserved.

## Scope decisions made during design discussions (NOT historical implemented code)

- Approved target broadened to self-hosted **Custody + Ledger + Exchange APIs + Merchant Payments + Treasury + Governance + Operations + UI**.
- Crypto 2-of-3 signer quorum and multi-human approval policy are explicitly independent. Example rule above USD 500 requires three humans only if configured in future Phase 7; **not active now**.
- Matching engine/order book developed separately, connected by narrow financial API; ledger exclusively owns balances and trade settlement.
- Configurable per-network/per-asset deposit finality, Hot/Warm/Cold, gas station optimization, batch payments, invoice/refund, audit/monitoring are binding target features, not claims of completed implementation.
- TON remains frozen at successful isolated foundation; public Mainnet/sharding/actual TON USDT work deferred. Deferral **does not** imply production approval or waiver of audit P1.
- No new numbered phase, no Bitcoin or bridge by default.

## How to maintain this timeline

On every milestone merge, append date, exact PR/merge SHA, capabilities with implementation-level evidence, tests/CI links, discovered risks, migrations, and changed scope/architecture decisions. Do not overwrite chronology with a guessed percent complete. Use PROJECT_STATUS.md as a separately refreshed current-state view.

## Phase 6G-A merge correction and 6G-B active branch

PR #36 is merged as `24eed19e6e280083793c69c3901f5f746dd0a2fe`.
Its final head `4e0ef58d08196a42a3e308b65b6e67a2459626d7` passed all fourteen
jobs on [full CI run 38142219480, attempt 2](https://github.com/hassan-anari/Base/actions/runs/38142219480/attempts/2),
including the four Fast jobs and genuine four-chain suites. Earlier runner failures
and Fast run 38142190057 remain historical failure evidence; they were not erased.
The successful rerun supersedes the earlier unresolved runner-block status.

Phase 6G-B is based on that exact merge, on `phase6g-b-child-wallets`.
Original-share HD attestation, canonical child derivation, genuine threshold child
signing and additive canonical account/asset associations are implemented in this
single branch. Migrations 0029/0030/0031 leave historical wallet/ledger rows intact.
Final validator, throughput and exact-head CI evidence belongs in
[PHASE6GB.md](../PHASE6GB.md) and the draft review handoff. Unmerged capability
is not counted as shipped. Earlier failed harness/CI attempts remain evidence.
Final Phase 6G-C owns Solana provisioning, lifecycle, rotation/recovery and wallet
security-class foundations; no additional implementation PR split is authorized.

Security assessment found a P1 EVM liability-inflation path: native scanning could
credit operator MPC gas funding as a customer deposit when native/token views
shared an address. This branch excludes only an exact known GAS_TOPUP transaction
with recovered persisted signed bytes, original source/destination/native amount/
chain, and consumed completed signing intent. Missing or altered provenance aborts
history; another payment from the same sender is still a deposit. Genuine live
acceptance caught the issue; dedicated negative contracts and final validator
checks cover the repair. Existing append-only historical journals are not rewritten;
any preexisting affected deployment needs a separate evidence-led investigation.
Independent review is required before considering this P1 repair accepted.

The coordinator substitution review also identified an authorization gap: approving
a child in each store did not authenticate which approved child the custody
service originally requested. This branch commits the full child signing request
with a once-persisted ECDSA/SHA-256 signature under the existing custody P-256 TLS
identity. Signers independently validate private-CA client authentication, current
certificate validity, exact custody URI and signature before nonce work and in the
worker. Substitution of another valid approved child, digest or session fails
closed. Dedicated DEPOSIT roots also reject dropping child authorization.
Migration 0031 freezes the original grant and prevents retrospective minting for
already-started executions. Original completed public signature recovery remains
possible; uncertain funds are never released on credential expiry or RPC timeout.
This does not make a compromised custody authority trustworthy; independent policy
authority remains Phase 7. Independent review must verify canonical serialization,
identity-key isolation, credential validity and immutable session/replay controls.
Transport adds the existing pinned ring 0.17.14 dependency edge; no Rust package or
cryptographic version is upgraded and the scc P1 remains open.

The first full-population restart benchmark issued all 1,000 real accounts, then
failed on a PostgreSQL deadlock during concurrent idempotent replay. Django's
joined FOR UPDATE implicitly locked account/reservation/root/keyset rows in query
plan order, conflicting with issuance's keyset-first order. Asset attachment now
explicitly locks keyset -> provisioning root -> account -> asset; the joined
account query locks only `self`. Deterministic first-view and existing-view tests
wait for a demonstrably blocked PostgreSQL backend and assert the account lock
remains available until its keyset lock is acquired. No deadlock is hidden by
retrying or claiming a passing benchmark. Initial-stage public benchmark evidence
is persisted before recovery so failed stages remain attributable. The full
recovery/validator run must pass on the final head.

Child issuance additionally verifies the current spending credential at all three
signers. The coordinator forwards an envelope containing the original ChildRequest
and a custody P-256 signature under `Wallet-MPC/CUSTODY_CHILD_APPROVAL_V1`. Each
signer validates private-CA client authentication, validity, exact custody URI and
public-request signature before reading/pinning child approval. Unsupported keys
or a custody CA trusted only by the coordinator cannot publish a new spendable
account. This public proof is domain-separated from signing grants, consumes no
CGGMP nonce and is not part of immutable child identity; public retries retain
original receipt identity. Private signing still requires its once-persisted
original operation grant. No human/policy approval authority is added.
## Phase 6G-B continuation — 2026-10-12

Draft PR #37 remains the only Phase 6G-B PR. Full run 38181533803 at head
`2c22c8b66954444f47f3868ca5df2538c4183764` failed EVM after successful genuine
child native/token custody and full-population recovery; the final gate correctly
failed. Twelve other primary jobs passed. Retained-store replay confirmed HTTP
400 `{"error":"Invalid"}`: the module root had been durably attested for DEPOSIT
children, so the coordinator correctly refused subsequent root-only signing.
Child acceptance now uses a fresh dedicated original DKG/auxiliary root, leaving
the historical module root intact. Trusted custody-mTLS root signing and rejected
untrusted/wrong-role credentials are tested, including directly after issuance.
No production authorization/signature checks, original receipts, ledger history,
TON scope or production flags change. New exact-head gates remain required;
previous 1.67 local / 1.6008 CI accounts/s measurements remain supporting results.
The fresh genuine focused fixture passed two cases in 212.00s; PostgreSQL backend
passed all 600 cases in 153.01s, with zero system-check issues/migration drift.
The scc / RUSTSEC-2026-0205 P1 stays OPEN pending independent review.

The corrected implementation `3670893bdfa6b21e2a99887e1238de5a979658cb` passed
Fast 38262366737 and all fourteen jobs in full run 38262414457. Backend 600;
preflight 8; integration 218 (EVM 44/TRON 5/Solana 2/TON 3/network 162/persistence
1/integrated 1), zero required skips. Actual child native/token movements pass.
CI complete issuance: 1,000 customers/eight workers, 653.488s, 1.5302 accounts/s;
full original-UUID recovery 56.182s with zero new derivation approvals. Corrected
local EVM passed all 44 cases in 1391.85s and measured 1.5736 accounts/s with
56.666s recovery. These do not erase earlier 1.67/s supporting measurements.
Intermediate run 38261875338 at 1a00466 retained a stale fixture keyset ID in
direct hostile child requests and failed EVM; the correction binds those requests
to the actual dedicated root. Failed runs remain evidence, not accepted gates.
Public evidence and the full security report are published in this same draft;
the documentation head receives a fresh final-SHA Fast/full gate recorded in
PR #37 before handoff. Independent review and all open findings remain mandatory.


## 2026-10-23 — Phase 6G-B independent P1 remediation, same Draft PR #37

Independent review 5628227149 against ebe9dd7 reproduced R1 false issuance from
fabricated coordinator reports and R2 permanent root-role denial from coordinator-
only attestation. Prior fourteen-job passes did not exercise either attack.
The continuation adds independently pinned signer-origin receipts, custody-signed
root dedication, durable non-retrospective root-use state, migration 0032 and
read-only pre-fix evidence audit/quarantine. Both unchanged-baseline reproductions
were rerun successfully; corrected exact-head acceptance and independent re-review
remain mandatory. See PHASE6GB_SECURITY_REVIEW and PR #37 for final hashes/evidence.
No additional PR/phase, merge, TON expansion or production activation.


The fresh continuation audit (39965525267, job 120454268053) failed on five TLS
advisories published after the prior acceptance. A scoped minimum patch updates
only rustls/webpki; this failure remains visible, and new final-head gates are
required. R1/R2 reproduction work is complete; subsequent work uses ordinary
engineering regression/CI validation only, as directed by the owner.


2026-10-23 validation update: published R1/R2 corrections and TLS patch head
`ac476accfae4ed91bfe31fc0bfce1499831b9a42` passed Fast CI. Full run 39966475502
had twelve successful jobs; EVM child spending and the 1,000-account issuance/restart
benchmark passed, followed by a legacy TLS fixture failure (44 passed / 1 failed).
The aggregate correctly failed. The lifecycle test now uses an independent genuine
root-only fixture, preserving rejection of HD stores without their receipt identity.
[Detailed evidence and measurements](acceptance/phase6gb/r1-r2-validation.md)
record the original failure, public signer proofs and 1.57922 complete accounts/s.
A fresh exact-final-head Fast/full run and independent R1/R2 re-review are required;
PR #37 remains Draft and unmerged, with scc P1 open.


The unsuppressed audit in final-candidate Fast/full runs 40000063620 /
40000095316 additionally reported **tokio 1.47.1 / RUSTSEC-2026-0386 OPEN**
(informational `unsound`, published 2026-10-13), alongside scc and atomic-polyfill.
The canonical advisory identifies `tokio::io::unix::AsyncFd::{new,with_interest,
try_new,try_with_interest}` accepting non-owning/invalid descriptors, with potential
I/O-safety violation and use-after-free. Scoped searches found no application
AsyncFd/raw-descriptor manipulation and no AsyncFd caller in the downloaded
application dependency sources outside Tokio's own implementation/tests/BSD AIO.
This is source/configuration evidence, not complete dynamic reachability or
independent exploitability clearance. The runtime is directly depended on by
coordinator, signer and transport; no broad exemption is asserted. Advisory fixes
start in 1.51.6 / 1.53.3; Tokio stays pinned pending a separately reviewed compatible
runtime assessment. Audit output is not suppressed. Record this additional open
finding in independent dependency review; scc P1 remains unchanged and open.
See https://rustsec.org/advisories/RUSTSEC-2026-0386 . No attack reproduction was
performed. A new exact-head gate remains necessary after this documentation update.


## 2026-10-23 focused dependency remediation disposition

The subsequent owner-authorized remediation pass upgrades Tokio **1.47.1 →
1.53.3** (RUSTSEC-2026-0386: REMEDIATED) and removes **scc 2.4.0 / sdd 3.0.10**
from the entire lockfile by using everscale-types 0.1.2's existing upstream local
Rc implementation (RUSTSEC-2026-0205: REMEDIATED, independent acceptance pending).
TON cells never cross the synchronous verifier's thread/await boundary; no unsafe
bridge or cell/hash algorithm change is introduced. Historical P1 evidence remains.

**atomic-polyfill 1.0.3 / RUSTSEC-2023-0089: BLOCKED.** Latest compatible
FROST 3.0.0/Postcard 1.1.3 force Heapless ^0.7.0; Cargo concretely rejects
maintained Heapless 0.8.0. A reviewed upstream serialization-feature/dependency
change is needed; a direct downstream override cannot subtract enabled features.
The full warning remains visible, with host/all-target distinction and explicit
independent assessment requirements. No blanket risk acceptance or crypto fork.

See [focused dependency report](PHASE6GB_DEPENDENCY_REMEDIATION.md) for exact
versions, source/feature review, resolver failure and required assessment. New
final-SHA Fast/full CI must pass; the PR report records its exact SHA and results
after commit. Previous a7c92c8 fourteen-job pass remains supporting history.
PR #37 stays Draft/unmerged; no activation or Phase 6G-C work.


## 2026-10-27 — fork continuation, initial audit and unmerged lifecycle safety work

Verified zeroexlive/Custody live main as `3d32b763ff777347f77eae7a8a7936d85dc2d770`, the Phase 6G-B (#37) squash merge, with no subsequent commits. Historical MPC-2 export records final premerge head `a92d00ca8c4228cc81154f303039ce3668e93a33`, R1/R2 fixed, Tokio/scc remediated and atomic-polyfill accepted as development-only P2 debt. Historical review/CI URLs are not freshly verified because the proxy blocks api.github.com. Earlier reports above retain their original evidence and are not current-state declarations.

Adopted owner directive v2.0: conditional automatic development merge after all gates, optional withdrawal-only manual blacklist, no external AML/KYT or deposit screening. Created codex/phase-6gc-key-lifecycle from fetched main. Initial code correction blocks the keyset command from retiring active/imported/referenced keys without a drain protocol, serializes mutation commands, preserves retired timestamp on retries and rejects reopening retired metadata. This is not completion of 6G-C or system-wide lifecycle enforcement. No migration, ledger mutation, crypto dependency change or production enablement.

See INITIAL_REPOSITORY_AUDIT.md for validation and remaining acceptance. No fork PR number, CI pass, review approval vote or merge is claimed. Full final-SHA cryptographic gates and independent review remain mandatory before phase merge; next phase remains blocked until 6G-C completes.


## 2026-10-27 — API restored, Draft PR #1 and keyset admin safety

After the owner updated Internet access, GitHub API confirmed the fork parent and main SHA. Initial PR listings/rulesets were empty; main reports protected=false. Created Draft PR https://github.com/zeroexlive/Custody/pull/1 for the same unfinished Phase 6G-C. Actions workflows/runs report zero; dispatch ci.yml is 404 and reading/enabling Actions settings is integration-permission 403. This is a CI activation/permission prerequisite, not an Internet failure or permission to waive gates.

The Django keyset admin is now view-only: superusers can inspect metadata but cannot create/edit/delete it through generic model forms or bulk deletion. Explicit guarded commands remain the supported mutation path. Three real HTTP regressions failed before the change; all 15 focused lifecycle cases passed after it. Direct model/raw SQL remains a trusted boundary. No migrations, balances, production flags, crypto primitives or dependencies change. Phase 6G-C remains IN PROGRESS, Draft and unmerged.

Direct API follow-up also verified upstream PR #37’s merged state and a92d00ca premerge head, final COMMENT review records 5633820156 / 5633830492, Fast run 40009083421 and all 14 successful jobs in full run 40009129783. This verifies historical upstream evidence; it does not satisfy fork PR #1 final-SHA gates or constitute production authorization.

Post-admin-change local validation: 622 PostgreSQL backend tests passed (135.27s, four existing deprecation warnings); all 15 focused lifecycle/admin cases passed, including independent rerun; Django checks/migration drift and changed-file Ruff checks passed. Rust/frontend implementation is unchanged from the preceding 32-test Rust and two-contract/two-build validation. No new fork CI execution or phase completion is asserted.


## 2026-10-27 — Actions running, new dependency gate, seeded wire primitives

Activated the existing fork CI workflow after the owner enabled Actions. Full dispatch 40470890805 at 3db8c01 executed backend/frontend/rust-check successfully. Unsuppressed rust-audit failed on newly published RUSTSEC-2026-0387 in crypto-bigint0.5.5; cryptographic jobs were skipped and aggregate failed. This is recorded without suppression or a crypto dependency upgrade. Official metadata, upstream main and scratch Cargo resolution confirm no compatible published fixed backend path. Independent review qualifies impact and confirms no exploited-key-recovery claim. See PHASE6GC_DEPENDENCY_GATE.md for the concrete proposed security decision and mandatory migration acceptance.

Added unconnected standard Solana seeded-address and native/SPL wire builders/typed validators, with 41 independent SDK/public-encoding cases and a separate 41-case review rerun. Included the source in existing Ruff CI checks. No issuance endpoint, signer authorization, on-chain activation, deposit/ledger change or dependency/lockfile change. These helpers do not complete 6G-C; all authenticated persistence, signer, validator, attribution and recovery gates remain outstanding in the same Draft PR #1.

Seeded-wire checkpoint local validation completed: 663 PostgreSQL/backend tests passed (158.33s, four existing deprecation warnings), including 41 new wire/address tests; Django/migration/Ruff checks passed. The independent reviewer also passed all 41 helper tests, verified single-base-signer standard messages and reported no P0/P1 in that unconnected builder scope. This does not close the cryptographic dependency gate or establish account issuance, chain spending, financial attribution or complete 6G-C acceptance.
