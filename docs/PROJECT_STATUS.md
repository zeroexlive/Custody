# Current project status — 2026-11-09

Verified `zeroexlive/Custody` main is **`587e0969a216102879d17cadb6ffeee8dfb8b6c6`**,
merged [PR #1](https://github.com/zeroexlive/Custody/pull/1). Its parents are the
previous Phase 6G-B main3d32b763 and final reviewed head78394fc. GitHub merge state,
main ref and exact tree identity were independently confirmed.

**Phase 6G-C remains IN PROGRESS.** The owner's [2026-10-28 decision](DECISIONS.md)
authorized this bounded development checkpoint merge and continuation within6G-C.
It supersedes retaining the entire unfinished phase in one Draft PR. Phase7–9
remain planned; production/mainnet/customer-fund activation remains unauthorized.

Earlier Draft PR #2 allocation checkpoint `99a055e` passed exact
[Fast41361207460](https://github.com/zeroexlive/Custody/actions/runs/41361207460)
and [selected Solana41361259277](https://github.com/zeroexlive/Custody/actions/runs/41361259277).
Downloaded artifacts verify59 unique selected/called scenarios, zero skips,
inventory276/shared hash and57 allowlisted Solana files. This is not ALL and
does not cover subsequent uncommitted execution work. See
[bounded CI evidence](evidence/phase6gc-financial-allocation-ci-99a055e.json).

Earlier committed Draft PR #2 checkpoint `c233a04` passed
[Fast41425030949](https://github.com/zeroexlive/Custody/actions/runs/41425030949)
and the full local backend suite,1017 cases538.917s, zero failures/errors/skips.
Its native financial execution adds exact-wire Custody and
independent HOT Policy approval, one-shot protected dispatch, authenticated
public recovery and permanent signature ownership before broadcast. Finalized
original-wire effects separate Claim principal from Root-paid fees and settle
through the existing ledger.124 focused PG/SQLite/TLS cases pass146.21s; three
actual FROST/PG/Agave sweep cases pass141.72s, including lost broadcast ACK and
settlement-audit rollback/recovery. Sweep funding/snapshot are synthetic and do
not establish deposit credit or customer liability acceptance. Independent129 focused cases150.692s and3genuine cases141.350s pass with
stable22-source/3-binary hashes and no remaining identified bounded P0/P1.
These results cover c233a04, not the subsequent incoming/routing source.

Committed55e245e/0043–0044 implement finalized native deposit provenance and
pre-allocation financial routing. Credit uses actual canonical legacy/v0 wire,
finalized status/block membership, explicit transfer instructions and original
Claim/owner identity. Known custody and registered operator sources create no
customer liability; balance changes alone never credit. Actual System CPI may
attribute PDA sources. The feature remains default-disabled, with live indexing
and explicit funding-source configuration required. Generic shared-hot-wallet
private fallback is fenced before allocation; unresolved legacy history blocks
enrollment, and existing holds retain their original release/settlement gates.
Current-source independent209 cases206.063s and3 genuine legacy/v0/PDA full native
flows332.263s pass with54-source/3-binary hashes unchanged and no remaining
identified bounded P0/P1. Root component80 cases58.966s also passes. Exact
[Fast41445276955](https://github.com/zeroexlive/Custody/actions/runs/41445276955)
passes all four executed jobs, including1097 backend tests521.11s. This is Fast
only and excludes subsequent SPL changes. SPL, repaired-identity new Claims, fresh-DKG drain/retirement and
final whole-phase gates remain unfinished. No whole-phase completion is claimed.

The next Draft PR #2 boundary implements default-off classic SPL initialization,
publication, seeded treasury sweeps, external ATA withdrawals and incoming token
provenance through the existing ledger. Root103 focused cases130.43s pass, and
one complete genuine FROST/PG/Agave flow passed166.60s before the subsequent
owner-history race correction. Independent source review found/fixed atomic
forwarding availability and historical-owner classification races; revised
independent313 cases302.898s, genuine SPL176.216s and Native3 cases331.088s now pass.
Exact136d995 Fast41499260859 passes4 jobs/1201 backend tests705.55s. Subsequent
7ff1e56 Fast41536746241 also passes4 jobs/1201 backend tests485.46s and includes
the accepted public-query-only helper correction. The interrupted broad run
reported617 passes218.64s and is not full-suite acceptance. See
[SPL scope and evidence](PHASE6GC_SPL_FINANCIAL.md). Repaired-identity new Claims,
fresh-DKG migration/drain/retirement, old-address rescue and final whole-phase
ALL/original-store compatibility/merge gates remain unfinished.

Subsequent current-identity public Claim approvals now have independently accepted
bounded node evidence:85 contracts and7 genuine cases533.394s, zero failures/
errors/skips, with112 source/binary hashes stable. The actual cases include HOT/
COLD refresh and physical replacement, exact receipt recovery, Gen2 historical
Claim spending, share-only restore and explicit fixed7ff rules2 repaired-store
profile promotion. Original Root/Claim bytes and original DKG ciphertexts remain
unchanged. Backend registration/effective-evidence consumption and financial
publication after replacement were not yet implemented at that checkpoint.
Subsequent e1664ed Fast41594758324 passes4 jobs/1228 backend tests670.51s, after
reviewed equivalent Clippy cleanup. Final whole-phase gates remain pending;
see [current Claim boundary](PHASE6GC_CURRENT_CLAIMS.md).

The0046 current-Claim backend checkpoint now has independent bounded acceptance:
527 contracts/backend cases, genuine repaired-node native/SPL financial execution
157.113s and an additional final raw-SQL commit-expiry regression4.105s all pass.
The expiry correction changed only0046 and its test; prior527/runtime evidence
carries forward qualified, with the other116 source/binary paths unchanged.
Root's final current suite passes55 cases38.37s. Registration remains default-off,
retains original approval/issuer/hold/session identities and uses no Life/Policy
private key. See [scope and evidence](PHASE6GC_CURRENT_CLAIMS.md). Exact f58d219 Fast41624031631 passes all4 executed jobs, including1283 backend
cases785.63s; full-crypto jobs were unselected. Fresh-DKG fund migration, retirement,
late-deposit rescue and final whole-phase gates remain required.

Final reviewed head `78394fc2e5ae585cd265c195f1d02557cb062e21` passed
[Fast40683968092](https://github.com/zeroexlive/Custody/actions/runs/40683968092)
and [ALL40683962776](https://github.com/zeroexlive/Custody/actions/runs/40683962776):
all14 full jobs, **228 actual selected/called scenarios, zero skips**
(EVM45/TRON5/SOL11/TON3/network162/aux1/integrated1). Seven remote artifacts and
mandatory original encrypted-store compatibility665.205s against fixed baseline
3d32b763, all six cases and distinct old/new binaries were independently verified.
Merged tree `affecb334af959a462fd747b0fdf49a3a731f182` exactly matches that head.
Automatic [main Fast40716836844](https://github.com/zeroexlive/Custody/actions/runs/40716836844)
passed all four executed jobs; its skipped crypto jobs are not another full gate.

Post-merge checks/migration drift and48 PostgreSQL provisioning cases passed53.73s.
Existing development services were restarted after environment idle; the first
local attempt had connection-refused setup errors, not a source assertion failure.
No database reset or source workaround was needed. Live/ready return200 with
DBOK and unchanged optional Redis degradation.

The merged checkpoint includes the owner-approved owned RustCrypto integration
removing crypto-bigint0.5.5 without scanner exceptions or protocol replacement;
original share/encoding/HD receipt/nonce recovery compatibility; standard Solana
seeded wire primitives and seven finalized all-pair FROST/Agave transactions;
signer-local original custody proofs, all-three receipt collection, independent
archival pins and historical-quorum fences; immutable operator tenant/principal
IDs; and durable original root/owner/network/asset/index reservations before
mutating RPC. These are development foundations, not issued customer wallets or
new seeded spending grants. Existing generic signing remains fenced for dedicated
roots. Full backend758 cases passed before merge, including48 new provisioning
cases; genuine approvals and independent source review are recorded in the
[reservation report](PHASE6GC_SOLANA_REGISTRY.md). The unchanged atomic-polyfill
warning remains visible development-only P2 debt. See [dependency evidence](PHASE6GC_DEPENDENCY_GATE.md).

Draft PR #2, `codex/phase6gc-seeded-spending`, adds the typed intent, independent
public witness authority and a separate protected signer/profile/journal. Local
genuine three-party FROST/Agave tests now cover native all-pair spending, manual
COLD courier, old private-backup restore, lost R1 nonces, withheld actual R2
results, corruption/exclusive-writer rejection and read-only recovery after freeze.
Independent live RPC checks separate source funds from base fee/rent funds.
The witness independently preserves original claim ownership through all three
pre-claim backup restores and binds each exact wire to one logical operation.
Thirteen new HTTP scenarios cover these boundaries and full-queue R2 drain;
twelve witness unit tests passed independently, with no ignored cases.
The actual Rust witness client rejects a same-CA/wrong-key server before HTTP
transmission. Independent review found and the implementation fixed a queued
expiry race; post-lock/final-private-work expiry regressions pass. These remain
isolated, unmerged development additions requiring final-head CI/review.
See [implemented boundary and evidence](PHASE6GC_SOLANA_SPENDING.md).

Subsequent ordinary distributed refresh and encrypted generation loading now pass
genuine Gen1 all-pair/restart and Gen2/COLD/interrupted-ceremony cases. Original
root/claim identity and original DKG ciphertext stay unchanged; missing refreshed
material fails closed. Further fault acceptance and exact-head gates remain open.
See [refresh authority and limitations](PHASE6GC_SOLANA_REFRESH.md).
Further [terminal R2 cancellation](PHASE6GC_NO_RELEASE.md) now requires original
signed requests, separate lifecycle approval and durable node cancellation before
returning certificates. Frozen witness closure derives every actual R2 grantee
from its own history; a durable partial or missing evidence keeps uncertainty.
Five genuine scenarios cover one/two grantees, subsequent real refresh/retry,
apply/cancel races, withheld partial refusal and COLD/manual flow. Expanded
write-failure/late-grant cases and13 unit tests pass with independent review.
Unmerged [native wallet publication](PHASE6GC_NATIVE_ISSUANCE.md) now adds
original Claim-linked wallets only after a separate permanent witness issuance
grant. Migration0035 preserves identity/history, blocks legacy adoption and
retirement, and requires PostgreSQL serialization. Expanded genuine three-wallet
restart/retry/collision/history-fault acceptance passed111.00s with all-pair
finalized transfers. The first genuine1000 run timed out after more than300;
an exact-byte signer verification cache retains full inventory checks and its
retry passed737.59s, actually publishing1000 wallets in627.149s and finalizing
all-pair transfers from indices0/500/999. Independent PostgreSQL tests
passed80 cases in97.01s and the independent genuine three-wallet rerun passed
113.42s. Native checkpoint6e2bcee passed exact Fast40851236750; complete local
backend rerun passed790 cases in431.17s. Selected Solana40851260306 passed34
actual calls/zero scenario skips with independently verified exact-head public
artifacts and actual1000 issuance evidence. This is no whole-phase or financial-
settlement gate; ALL/original-store compatibility remains required.

A further unmerged [replacement authorization boundary](PHASE6GC_RECOVERY.md)
now reserves one exact new identity/profile/anchor under Frozen authority, retains
permanent failed-plan history and preserves old signed journal semantics while
requiring strict rules for new admissions. Independent17-unit and actual public
store upgrade/restart/tampering reruns pass. Public checkpointa278953 passed exact
Fast40857133396 and selectedSolana40857374994:35 actual calls/zero scenario skips,
independently verified exact-head artifacts and original public-history evidence.
Subsequent unmerged private recovery now uses upstream direct helper Delta/Sigma,
one-share encrypted staging and a fresh immutable recipient profile, then requires
all-three refresh/activation before signing existing original Claims. HOT all-pair
finalized signing/restart, COLD/manual and storage/TLS/expiry/interruption cases
pass bounded genuine runs. After environment restoration, all37 Rust library tests
passed and independent current-source staging/provenance rerun passed76.81s,
including all-pair finalized transfers. Independent review found no demonstrated
P0/P1 in this layer. Complete current-source genuine run passed5 cases297.72s,
with2 ordinary-refresh regression cases138.78s and all-target Clippy; exact-head
CI at private checkpoint4a4e6ff subsequently passed exact Fast40908695597 and
selectedSolana40908696183:40 actual calls/zero skips and independently verified
exact-SHA public artifact/inventory. Fixed-baseline/ALL remains mandatory; these
passes do not cover subsequent profile-migration source changes.
Explicit old-profile migration, new Claim receipt identity rollover and complete
recovery remain unfinished.
Remaining6G-C includes explicit profile migration,
rotation/drain/late-deposit rescue, issued
wallet and finalized SPL initialization records, financial ledger integration,
and final whole-phase acceptance. Manual COLD relay is not physical airgap
or production acceptance. Canonical tenant strings do not replace registry and
financial authorization during backend integration.
Each subsequent checkpoint requires its own independent review,
applicable exact-head gates and normal repository merge rules. Do not advance7.
TON stays isolated/deferred with its external artifact-audit gate open. Phase7B
stays optional default-disabled manual withdrawal-only restrictions, with no
deposit screening or external AML/KYT integration.

## Historical snapshots below


Earlier Draft/unmerged, scc/Tokio-open and atomic-polyfill-blocked wording records the state at those historical checkpoints. It is superseded by the qualified current evidence above; historical CI is not current fork CI.

# Project status — verified snapshot

**Repository:** hassan-anari/Base. **Verified baseline:** `24eed19e6e280083793c69c3901f5f746dd0a2fe`.
**Active branch:** [Phase 6G-B Draft PR #37](https://github.com/hassan-anari/Base/pull/37), unmerged development work.


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

Historical remediation and acceptance snapshots below:

**2026-10-23: independent review requires changes.** Two newly reproduced P1s
block this draft: R1 coordinator-fabricated HD/child evidence can publish unspendable
addresses; R2 coordinator-only dedication can disable historical root signing.
Repairs add independently pinned signer-origin signatures, custody-authorized
signer-local dedication/use state, migration 0032 and pre-fix evidence quarantine.
Acceptance and independent re-review are required on the new final head. Previous
CI passes below remain historical evidence, not clearance of these findings.
See [current remediation report](PHASE6GB_SECURITY_REVIEW.md). Existing scc P1 stays OPEN.

Verified implementation acceptance at `3670893bdfa6b21e2a99887e1238de5a979658cb`:
[Fast 38262366737](https://github.com/hassan-anari/Base/actions/runs/38262366737)
and [full 38262414457](https://github.com/hassan-anari/Base/actions/runs/38262414457)
passed, all fourteen jobs successful. 600 backend cases and 218 integration
scenarios passed (EVM 44, TRON 5, Solana 2, TON 3, network 162, persistence 1,
integrated 1), with zero required skips; Rust includes genuine child all-pair signing.
Actual 1,000-account issuance measured 1.5302/s, with all original identities
recovered after four-service restart/DB reconnect and no new approvals.
The [security/implementation report](PHASE6GB_SECURITY_REVIEW.md) supplies public
transaction evidence, migrations, benchmark hardware and remaining findings.
Its publication is revalidated on the final draft head; exact final SHA and
Fast/full links are recorded in PR #37. P1 scc remains OPEN. No independent
security acceptance, mainnet activation or merge is claimed.

2026-10-12 verification update: full run
[38181533803](https://github.com/hassan-anari/Base/actions/runs/38181533803),
head `2c22c8b66954444f47f3868ca5df2538c4183764`, failed EVM and its final gate.
The other twelve primary jobs passed, including 600 PostgreSQL backend tests and
TRON/Solana/TON/integrated regressions. Child EVM native/token acceptance and the
1,000-account benchmark passed before a legacy root test failed. Investigation
confirmed permanent DEPOSIT attestation of a shared module root; the root-only
rejection is legitimate, not a missing child grant or production contract defect.
The fixture now uses a fresh dedicated DKG root, retaining original authenticated
legacy signing. A targeted positive/negative credential regression is added;
The fresh focused genuine fixture passed two cases in 212.00s and all 600 backend
cases passed in 153.01s, with no migration drift. New final-SHA Fast and fourteen-job
acceptance were required and are recorded above. Details and exact
final evidence are recorded in [PHASE6GB.md](../PHASE6GB.md) and the existing PR.

PR #36 is merged as `24eed19e6e280083793c69c3901f5f746dd0a2fe`.
Its final head `4e0ef58d08196a42a3e308b65b6e67a2459626d7` passed all fourteen
jobs on [full CI run 38142219480, attempt 2](https://github.com/hassan-anari/Base/actions/runs/38142219480/attempts/2),
including the four Fast jobs and genuine four-chain suites. Earlier runner failures
and Fast run 38142190057 remain historical failure evidence; they were not erased.
The successful rerun supersedes the earlier unresolved runner-block status.

This branch implements genuine original-share HD agreement, upstream SLIP-10
public derivation and CGGMP24 child threshold signing for EVM/TRON, plus immutable
canonical custody accounts and asset views, and end-to-end original machine
request authentication (migrations 0029/0030/0031). It preserves
root-only wallets and the original ledger. See [PHASE6GB.md](../PHASE6GB.md) for
reviewable boundaries and current test evidence. This is not independent audit
acceptance, production permission or completion of Phase 6G-C.

## Shipped into main as development implementation

- One PostgreSQL-backed Django custody/ledger application; append-only double-entry journal and asset-key-based separation. Native/token deposit, withdrawal reservation and settlement flows and four-chain integrated consistency checks.
- Chain registry and controlled RPC source registry; exact token verification and scoped chain policies.
- Self-hosted 2-of-3 independent networked MPC signers: genuine FROST Ed25519 DKG/signing and CGGMP24 threshold ECDSA; durable authenticated coordinator/execution evidence and nonce/recovery discipline.
- EVM native/ERC-20, TRON TRX/TRC-20, Solana SOL/classic SPL, TON native/V5R1/reference TEP-74 *in reviewed isolated-development execution*.
- Phase 6F-D immutable financial asset identity and network-root bindings, integrated cross-family tests, settlement/fee ledger fixes and EVM native/ERC-20 resumable finalized historical scanners.
- Admin/operator-oriented Vue panels for overview/deposits/withdrawals/basic approval/chain-token settings/gas/node/ops; some existing operator API endpoints. **Not** a finished multi-tenant merchant/exchange UI.

## Most recent acceptance evidence

PR [#34](https://github.com/hassan-anari/Wallet-MPC/pull/34) final implementation head 04bb9c621a3aba5a6313bff0c6f5028b4fc803b3, merged as commit 4488016a. Final-SHA [Fast CI](https://github.com/hassan-anari/Wallet-MPC/actions/runs/38129528658) passed four required jobs; [full cryptographic gate](https://github.com/hassan-anari/Wallet-MPC/actions/runs/38129567244) passed all fourteen, 814 executions (779 pytest, 33 Rust, 2 frontend). One integrated multi-stage isolated scenario reported 8 independently generated roots, 8 deposit credits, 32 confirmed and 4 reconciliation-required attempts, 92 journals/184 postings and genuine native/ERC-20 backfill recovery including >1,000-block token history. This **does not prove production mainnet trust, audits or operator security**.

## Not yet implemented / do not claim otherwise

- Arbitrarily large provisioning throughput, Solana scalable provisioning, production root/child lifecycle, rotation/resharing/recovery and independent Hot/Warm/Cold management. EVM/TRON child provisioning is implemented on this unmerged branch, with measured development acceptance required.
- Human multi-person approval quorum, configurable transaction USD thresholds, governance-controlled policy changes, signer-side independently issued approvals.
- Multi-tenant external exchange financial service APIs (Reserve/Release/Adjust/Trade Settlement/Internal Transfer), merchant invoices/refunds/settlement and signed webhooks.
- Per-asset configurable finality override and broad operational on-chain reconciliation/dispute tooling.
- Complete batch-payments/treasury automation, active production-grade signer separation, independently verified live-network release per chain, merchant/developer UX.
- Independently verified production TON V5R1 external audit mapping; TON public sharding/real USDT/mainnet parity.

## Existing implementation distinctions

- /api/... endpoints currently include /wallet/address, /wallet/create, /wallet/balance/check, /withdrawals/request and admin ledger balances. They do **not** constitute externally authorized, tenant-scoped reserve/trade settlement APIs.
- Withdrawal currently has a basic admin approve/deny step; there is no configurable quorum of independent human approvers.
- UserWallet DB rows and demo derivation do not prove economically scalable issuance of independently spendable MPC addresses.
- ops.Chain.min_confirmations exists; per-asset and risk-based overrides are future features; Solana/TON require chain-native finality rules.
- HotWallet and gas topup/sweep primitives exist; a categorized ops cold_wallet observation does not implement true Cold Storage.
- Production public network routing is deliberately restricted; EVM test/development and isolated TRON/Solana/TON acceptance != operational mainnet.

## Open risks and release exclusions

**P1 OPEN:** independent TON V5R1 exact-artifact audit correspondence; broader chain-specific public-network trust and production security review. TON owner decision: freeze current isolated scope; defer mainnet/sharding/real USDT without blocking other chain families.

**Operational/P2:** EVM archival RPC/backfill capacity, historic diagnostic codes, dependency advisory triage, security of IdP/roles, independently authorized signer infrastructure, multi-tenant financial models, comprehensive production control reviews. Record newly discovered issues by evidence, do not assume absence of hidden vulnerabilities from passing CI.

**Prohibited in this snapshot:** customer funds, production withdrawals, automatic mainnet enablement, fake local signer fallback and unauthorized changes to approved protocol/network identity.

## Entry checkpoint for a future new chat

Read README -> AGENTS -> PRODUCT_VISION -> PROJECT_STATUS -> ROADMAP -> DECISIONS -> SECURITY_MODEL. Fetch latest main and current phase PR. Start Phase 6G only when instructed; no silent TON scope expansion. Aim toward complete exchange/payment API-first product, not signer-only roadmap.


Fresh 2026-10-23 CI additionally identified five post-baseline RustSec advisories in
rustls 0.23.45/webpki 0.103.15, blocking audit and dependent crypto jobs. The scoped
minimum patch correction is rustls 0.23.46/webpki 0.103.16; full final-head revalidation
is mandatory. No audit suppression or MPC protocol upgrade. scc P1 remains OPEN.


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


# Historical continuation checkpoint before migration verification — 2026-10-27

Repository: `zeroexlive/Custody`. Live main verified as `3d32b763ff777347f77eae7a8a7936d85dc2d770` by Git fetch/ls-remote; this is the Phase 6G-B squash merge (#37), not an unmerged B branch. No post-checkpoint main commits. **Phase 6G-C: IN PROGRESS locally; not merged or complete.** Phase 7–9 remain planned. Current source/audit evidence and dependency security gate are recorded in [INITIAL_REPOSITORY_AUDIT.md](INITIAL_REPOSITORY_AUDIT.md).

Draft PR [#1](https://github.com/zeroexlive/Custody/pull/1) tracks this unfinished phase. Actions is now enabled and the main CI workflow was activated successfully. [Full run 40470890805](https://github.com/zeroexlive/Custody/actions/runs/40470890805) at `3db8c01` passed backend, frontend and rust-check, but failed rust-audit on new `crypto-bigint 0.5.5 / RUSTSEC-2026-0387`; crypto-preflight/dependent jobs were skipped and the aggregate correctly failed. This is an OPEN security gate, not an Actions/network blocker or passing full acceptance. See [dependency investigation and remediation decision](PHASE6GC_DEPENDENCY_GATE.md). main remains unprotected; all directive gates remain mandatory.

Standard seeded SOL / classic SPL wire helpers and 41 independent SDK/encoding tests are now implemented locally, without connecting them to issuance, signing authorization, financial credit or broadcast. This is a building block, not scalable issued-wallet acceptance.

The first local correction restricts the keyset command to retiring only unused, never-imported metadata and prevents retired-key reactivation. The continuation also makes the Django keyset admin view-only, denying add/edit/delete even to superusers. These are not a complete drain/rotation/recovery protocol, a database-wide lifecycle guarantee or production permission. No migrations or balances change.

Current lockfile has Tokio 1.53.3 and no scc/sdd. The exported final review reports R1/R2 fixed and atomic-polyfill accepted as development-only P2 debt; Upstream PR #37 merge, the exact-head final technical COMMENT reviews and all 14 successful full-gate jobs are now verified directly through GitHub API. These historical upstream results are not current fork PR checks. TON audit/public-network exclusions remain. New Phase 7B target is an optional withdrawal-only manual blacklist, with deposits unaffected and no external AML integration.


## Previous continuation snapshot — superseded

# Current project status — 2026-10-27

Repository: `zeroexlive/Custody`. Verified main:
`3d32b763ff777347f77eae7a8a7936d85dc2d770`, the historical Phase 6G-B squash
merge (#37). **6G-A/B are implemented as development; 6G-C is IN PROGRESS and
unmerged in Draft [PR #1](https://github.com/zeroexlive/Custody/pull/1).** Phase
7–9 remain planned. Main is unprotected in the inspected repository API; all
owner-directed acceptance/review/merge gates remain mandatory.

The branch restricts command retirement to unused, never-imported metadata,
rejects retired-key reactivation and makes keyset admin view-only. These are
bounded safeguards, not complete drain/rotation/recovery or a database-wide
lifecycle guarantee. Direct privileged model/SQL access remains trusted.

The explicitly authorized owned RustCrypto integration port removes
crypto-bigint 0.5.5 from the branch graph. Exact checkpoint `ea4bb4ed` passed
[Fast CI](https://github.com/zeroexlive/Custody/actions/runs/40521504904) and
[all 14 full-gate jobs](https://github.com/zeroexlive/Custody/actions/runs/40521510401),
with 219 scenario calls and zero skips. Original-store upgrade acceptance passed
in 518.46s. A separate review agent verified source, compatibility and remote
artifacts. See [dependency disposition](PHASE6GC_DEPENDENCY_GATE.md). Main still
carries the old graph until the phase is completed and merged.

Latest source work adds independent Rust verification of standard seeded SOL and
classic SPL messages, one 15-fixture SDK/negative wire matrix and a genuine
seven-transaction all-pair FROST/Agave regression. Actual repository acceptance
passed in 150.23s, including destination effects, fees/rent and repeated existing
ATA creation with zero added rent. These remain unconnected to product issuance,
signer-side seeded grants, ownership/tenant enforcement and the financial ledger.
See [implemented/pending scope](PHASE6GC_SOLANA_SEEDED.md). The crypto inventory
at that checkpoint was 220 scenarios. Exact `a1b6ae99` Fast and selected Solana
[40531473864](https://github.com/zeroexlive/Custody/actions/runs/40531473864) passed;
the downloaded Solana manifest has three selected/called and zero skips. Other
suites were unselected, so this is not a new full all-chain gate.

Subsequent signer-local work implements original custody-authorized FROST root
dedication and immutable monotonic owner/asset/index/retry approvals with separately
signed per-party receipts. Dedication fences the legacy arbitrary-message API;
historical roots cannot be dedicated. Five genuine process cases passed in 11.31s,
including concurrent/damaged/partial-store and two-root reservation-conflict cases.
Independent review found two recovery defects, both fixed; its strengthened case
rerun passed in 3.63s with no remaining concrete P0/P1 in this bounded diff. These
are deployment-scoped records, not tenant authentication, on-chain initialization,
issued customer accounts, seeded spending grants, epoch/rollback protection or
class isolation. Identity-key rollover and scalability remain unaccepted. The
complete crypto inventory is now 225 scenarios; new full-head CI remains required.

Subsequent coordinator routes collect the original proof and all three ordered
signer receipts, persist only complete evidence, and recover exact partial commits
or completed public retries with signers offline. The custody verifier now checks
separate Solana domains against its configured independent archival HOT signer
pins; coordinator-key forgeries and partial/reordered/duplicate receipts fail.
All six record/agreement cases passed in 14.27s, and 38 existing backend EVM/TRON
issuance/provisioning cases passed in 17.38s. Independent source review found no
concrete P0/P1 in this bounded layer. This is subsequent to94a0216; inventory226
and fresh final-head CI are required. No issued wallet or spending grant is added.

Further review reproduced unused-first-participant dedication reducing an existing
b/c historical quorum. The subsequent fix checks coordinator signing history and
all three stores before mutation, and pins a pending intent under the same data
lock used by new signing-session reservations. Seven genuine cases passed in20.36s,
including restored coordinator history, all legacy pairs, concurrent intent and
pending-fence cache recovery. Inventory227; fresh-head gates are required. This
bounded coordinated-API fence is not a Byzantine lease or rollback witness.
The separate reviewer independently reran the new case (1passed,6.38s), finding no
remaining P0/P1 within that boundary; all48 legacy FROST cases passed in73.55s.

Remaining 6G-C scope: authoritative custody integration of the new Solana records,
tenant ownership and independently pinned all-party evidence; actual issued-wallet/scanner/sweep/withdrawal integration and benchmark;
immutable epochs, authorized refresh/repair and rollback protection; controlled
rotation/drain/late-deposit rescue, backup and compromise procedures; enforceable
Hot/Warm/Cold boundaries; complete genuine negative/restart/concurrency acceptance,
independent review and final-head full CI before the one final major phase merge.
No database migration or balances change in the current primitives.

The unchanged atomic-polyfill warning remains visible development-only P2 debt
per the historical review, with production assessment outstanding. TON remains
isolated/deferred with its external artifact-audit gate open. No production,
mainnet or customer-fund activation is authorized. Phase 7B remains optional,
default-disabled manual withdrawal-only restrictions; no deposit screening or
external AML/KYT integration is introduced.

Earlier local snapshot (superseded by Nov1 evidence below): explicit LC=None terminal source fencing and
verified successor history import have bounded genuine old4a/independent evidence;
new runtime retains the original journal flock and enforces the approved cohort
and exact witness profile pin. Expanded genuine migrated HOT/COLD signing and
exact-head CI are still pending. See PHASE6GC_RECOVERY.md. Whole-phase financial,
SPL publication, fresh-DKG drain/retirement and recovery acceptance remain open.

2026-11-01 continuation: original-profile migration HOT/COLD and bounded independent
HOT runtime now have actual finalized evidence. Subsequent ordinary-refresh ID
allocation required explicit durable witness reservation, rather than a racy
preflight. New rules2 reservation/abandonment has22 state-test and independent
passes; current genuine runtime gates are in progress. Draft PR2 remains unmerged;
whole-phase work and exact-final-head ALL acceptance are still incomplete.

Current bounded local gates now pass5 migration/witness-upgrade and3 ordinary
refresh cases with zero skips, plus final successor preflight and genuine old4a
historical-ID recovery. Independent enhanced HOT passed72.276s; historical-ID
rerun passed72.366s with unchanged binaries; exact-checkpoint CI remains pending. No merged phase completion follows.

39ad4f5 passed exactFast41269720532 and selectedSolana41269752763:45actualcalls,
zero skips, independently matched public artifacts. Fixed3d32 compatibility and
other chains were unselected, not ALL. Subsequent uncommitted financial-mode/query
boundaries have bounded local and independent evidence only; protected coordinator,
ledger integration, treasury roles, finalized SPL and whole-phase recovery remain
incomplete. See PHASE6GC_FINANCIAL_INTEGRATION.md.

Subsequent unmerged typed HOT coordinator now passes9 genuine local cases362.45s
with all-pair finalized transfers, durable original R1/first R2 package, isolated
public store, original signature recovery and actual response/write/restart faults.
Created records intent; Completed verifies only the aggregate, with public witness
redelivery/reconciliation still required before backend financial consumption.
Independent coordinator3-case runtime passed157.614s with stable binaries and no
bounded P0/P1 finding. Current-source CI is pending. Financial references are
synthetic; DB treasury/customer roles, protected financial sessions, actual ledger
integration, SPL and lifecycle completion remain unfinished. See
PHASE6GC_FINANCIAL_INTEGRATION.md. This does not complete the phase or merge gate.

Backend migration0036 now commits immutable expected mode/command IDs and a15s
query before importing a clean Root's independent financial mode.54 PG cases
passed74.51s and genuine PG/original protected nodes/Rust W import passed6.25s;
mode import itself activates no wallet or ledger. Direct seeded deposit ingestion
and credit stay closed until financial wallet activation/provenance is implemented.
Independent54 PG cases passed76.12s and genuine import8.39s/stable binaries, with
no bounded P0/P1 finding. Broader backend/current-head CI remain pending; whole-phase acceptance
and Draft PR2 merge remain incomplete.

The stored-wallet precision correction600fcfe passed Fast41330106726, including
812 backend tests245.64s. Selected Solana41330272112 is running. Subsequent
uncommitted0037 explicit CUSTOMER/TREASURY roles preserve existing customer IDs,
require fresh treasury creation and block treasury references in customer wallet,
USER liability, withdrawal and HD paths.49 targeted cases54.37s and actual Rust W/
PG customer-declared mode import6.02s pass. Full backend840 tests291.17s pass;
independent49 PG cases53.586s and genuine import5.912s/stable binaries passed,
with no bounded P0/P1 finding. Current-source CI remains pending. Dedicated treasury
publication, financial-wallet activation and actual
protected ledger integration remain unfinished.

Role checkpointd5ab520 passed exactFast41331691016. Subsequent uncommitted0038
native financial membership atomically links original Root mode, Claim role and
W issuance; treasury never becomes a customer UserWallet.39 PG cases70.55s and
genuine customer+treasury publication6.68s pass; independent39 cases71.763s and
actual publication7.283s/stable binaries found no bounded P0/P1. Full backend879
tests360.44s pass. ACTIVE membership enables no credit/signing/settlement; seeded
credit stays closed. Protected financial sessions/ledger integration, SPL and
whole-phase lifecycle acceptance remain unfinished. Current-source CI is pending.

2026-11-02: membership checkpointa4e8d5b passed exactFast41337021996, all four
executed jobs. Subsequent optional query/record courier client checks actual W
TLS identity before HTTP and reads only correctly typed courier/Custody keys.
Local9 raw TLS cases1.26s and actual Rust W query/publication6.92s pass, independently
9 cases1.29s/genuine6.99s with stable source/binaries and no bounded P0/P1. Caller
durable freshness/ledger checks and positive authentic report-delivery acceptance
remain required. Protected financial sessions/settlement still remain unfinished.

2026-11-02: courier2077eea passed exactFast41357648627. Earlier selected
Solana41330272112 at600fcfe was downloaded/verified:57 selected=called/zero skips,
XML3288.062s, shared274-scenario inventory/hash and51 allowlisted public files.
It predates later roles/membership/courier/allocation and is not ALL; fixed3d32
network compatibility was unselected.

New0039 unprepared financial-session allocation commits original business/source/
approval plus MPC/session/OnchainAttempt IDs before query/lifecycle export. Original
withdrawal journals are reused; sweep HELD adds no USER reserve. Append-only15s
leases and a fresh pinned W permanent-abandonment proof permit a new crypto
attempt while retaining the business hold. Generic signing/reconciliation/ledger
paths stay fenced. Independent review found and corrected stale-snapshot and late
ledger-release races;54 PG cases52.06s and actual Rust W case8.69s pass, independently
59 final cases57.528s/genuine7.989s with unchanged source/binaries and no remaining
identified bounded P0/P1. Full backend/current-source CI remain pending. Prepared
signing, broadcast, settlement/release, seeded credit, SPL and whole-phase lifecycle
acceptance remain unfinished. See PHASE6GC_FINANCIAL_INTEGRATION.md.

Full backend946 cases428.52s passed after SQL alias correction. Subsequent minimal
SQLite vendor guard preserves legacy demo ledger flows while retaining PG-only
protected allocation; final59 local cases57.56s and independent59 cases57.528s/
genuine7.989s pass with stable11-source/3-binary hashes. The946-case run predates
that non-PG-only correction; final committed-source CI remains required.

The next0047 per-Root receipt-pin prerequisite has40 new PG/P256 cases19.96s,
149 affected legacy cases117.48s and one actual two-cohort FROST DKG/Root/Claim
archive case8.44s passing. All124 source/bin hashes stayed unchanged during the
actual case. Explicit old archive import and new reservation preserve original
receipts and all six encrypted shares. Independent189 backend cases135.216s and2 genuine cases158.945s pass with all124
hashes unchanged and no remaining identified bounded P0/P1 or concrete P2 gap.
This prerequisite has bounded development acceptance. Exact f9f4445
Fast41696076316 passes4 executed jobs/1323 backend cases798.12s; ten full-crypto
jobs were unselected. It predates routing0048. Coordinator routing, actual fund migration,
retirement/rescue and whole-phase gates remain open. See PHASE6GC_RECEIPT_PINS.md.

The0048 Root-bound coordinator routing checkpoint has independent bounded
development acceptance:338 unique PG/transport cases across explicitly qualified
runs and3 genuine cases278.711s pass. The initial historical-fixture failure is
resolved through0031 historical ORM setup; all assertions and production source
remain unchanged. The final131-path manifest is stable. Exact143dfb5
Fast41702205647 passes4 jobs/1364 backend cases815.43s; full-crypto jobs were
unselected. Root routing creates no fund migration or retirement feature; those,
late-deposit rescue and final whole-phase gates remain unfinished. See
PHASE6GC_COORDINATOR_ROUTING.md.

As of2026-11-04, a separate uncommitted migration-contract draft adds exact source/
owner/membership inventory, distinct approval and business identities, destination
asset coverage, cumulative fee budgets and bounded manifest chunks. Independent26 protocol cases75.66s and workspace/all-targets Clippy10.27s pass
with136 frozen paths unchanged. This is bounded data-contract validation only. No witness
rotation command, transfer, retirement, late-rescue API or activation follows from
this unconnected data layer. Phase6G-C remains incomplete.


The next witness manifest-staging implementation now authenticates current
Custody/Policy plus separate Life commands, preserves exact original W evidence/
issuance, accepts contiguous bounded chunks and fences normal source maintenance.
Rules4 adds locked incoming-recipient gates on every new ordinary R1/R2, preserving
old signed replay. Root49 W tests and workspace Clippy pass; independent28 protocol/49 witness cases, Clippy and6 genuine cases across qualified
runs pass with159 stable source/binary hashes. Exact-source CI remains pending. `Migrating` grants no private movement. Every
source SignedPending/known uncertain inbound execution still blocks entry pending
future original-wire finality attestation. No retirement, rescue or phase completion
follows. See [exact scope and remaining work](PHASE6GC_ROTATION_INVENTORY.md).
Parent0c24faf Fast41730430453 passed4 jobs/1364 backend cases830.90s; crypto jobs
were unselected and that run predates this W implementation.


The next public finality development checkpoint has bounded independent validation. All3 current source
nodes observe an exact original signed wire under Frozen, with own initial/end
W queries and unchanged15s lease. Separate immutable W facts preserve SignedPending,
original signatures and all held logical aliases; no financial settlement or hold
release follows. Root55 W tests pass; initial actual HOT/Gen1/native/SPL and COLD
courier cases pass2/124.57s, plus actual failed-wire/no-new-attempt case77.74s.
Final strict-source independent39 protocol/55 W cases, Clippy and9 genuine cases
356.041s pass with167 unchanged source/binary paths. No bounded P0/P1 was identified;
serial revision-bound ACK availability remains documented. Read [scope and limitations](PHASE6GC_PUBLIC_FINALITY.md).
Exact parent8a9c796 Fast42651565984 passes4 jobs/1364 backend cases774.17s; not ALL.


The durable local allocation pause is implemented under default-disabled operator
entry. Migration0049 freezes the allocator frontier and fences new ordinary source
and known incoming work under ordered PG locks. Tracked HELD work, including SPL
initializers and retained NoSignature holds, must reconcile before pause birth.
Exact Claim retries and already-reserved public approval remain possible. Root35
PG cases51.90s and one pre-lock-hardening two-cohort case15.00s pass. Final
independent618 backend cases948.157s and4 genuine cases307.541s pass with174
unchanged source/bin paths and no bounded P0/P1. Read [scope](PHASE6GC_ALLOCATION_PAUSE.md). Parent473d86a Fast42704314910
passes4 jobs/1364 backend cases807.77s; not ALL. Actual MIGRATION/RESCUE execution,
fee accounting, retirement and final whole-phase gates remain unfinished.
