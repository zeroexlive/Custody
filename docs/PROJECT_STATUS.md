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
