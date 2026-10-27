# CUSTODY — INITIAL REPOSITORY AUDIT

Date: 2026-10-27. Status: **IN PROGRESS; GitHub API restored; fork Actions execution blocked**.
This is an implementation/source audit, not an external security audit or production approval.

## Repository and evidence

- Repository: `zeroexlive/Custody`, origin `https://github.com/zeroexlive/Custody.git`.
- Current live `main`: `3d32b763ff777347f77eae7a8a7936d85dc2d770` (read-only `git ls-remote`, then `git fetch origin main`).
- Historical upstream: `hassan-anari/Base`, per owner directive and exported history. GitHub API now independently confirms that exact fork parent.
- Historical checkpoint verified: local HEAD is exactly the supplied Phase 6G-B squash merge, subject `Phase 6G-B: genuine CGGMP child custody for EVM and TRON (#37)`. Its parent is Phase 6G-A `24eed19e6e280083793c69c3901f5f746dd0a2fe`. No post-checkpoint changes on live main.
- Historical premerge head `a92d00ca8c4228cc81154f303039ce3668e93a33` is cited in MPC-2.md but is not present in the local object database. A squash merge does not independently prove every former review or CI result.
- GitHub API access was restored after the owner updated Internet access. The repository is an unarchived, enabled fork of `hassan-anari/Base`. Initial open/all/closed PR listings were empty; [Draft PR #1](https://github.com/zeroexlive/Custody/pull/1) now tracks this phase. Ruleset listing is empty; the branch endpoint explicitly reports `protected=false`, protection disabled and no required checks for main. Detailed protection settings still return integration-permission 403, which does not contradict the branch summary. Repository response reports admin/push permissions, but this does not establish permission for every Actions API.
- Actions workflows and runs both report `total_count=0`, despite tracked `.github/workflows/ci.yml` and `crypto-suite.yml`. Dispatch of `ci.yml` returns 404. Reading Actions settings and the attempted additive `enabled=true` update both return `Resource not accessible by integration` / HTTP 403. No workflow execution or passing check is claimed. The owner must activate/allow fork Actions and ensure the installed integration has the required Actions permissions; inspect the resulting API/dispatch behavior before concluding this is resolved.
- The earlier network draft added only `api.github.com`; the owner subsequently updated Internet access and live API connectivity now works. No further network change or new secret requirement was added.
- Development branch: `codex/phase-6gc-key-lifecycle`, from freshly fetched main; no worktrees or changes to historical upstream.

## Current verified phase

Phase 6G-B is **IMPLEMENTED (DEV)** in the verified main tree. Phase 6G-C is the next unfinished milestone. Phase 7–9 remain planned. Current docs contain historical branch snapshots; they cannot override this Git evidence.

## Completed implementation

- Django/Ninja backend, PostgreSQL migrations through custody 0032, double-entry financial ledger and reservation/reconciliation infrastructure.
- Real 2-of-3 FROST Ed25519 and CGGMP24 services, mTLS transport, encrypted create-once stores, signing executions and nonce/replay state.
- EVM/TRON child account issuance with original three-signer signed receipts, fixed non-hardened paths, original custody-machine grants and child threshold signing.
- Existing isolated EVM/TRON/Solana/TON adapters and native/token integration tests. These are development capabilities; production chain activation remains gated.
- Vue operator app and simulator with real endpoint clients and frontend withdrawal-idempotency contract tests.

## Partial and missing functionality

- Solana currently uses original FROST roots and exact single-signer normal SOL/ATA transfer messages; it has no scalable seeded-account provisioning. `solana_wire.py`, `solana_policy.py` and `PHASE6G.md` establish this boundary.
- FROST upstream provides distributed refresh and repair, but signer files are keyed by one immutable keyset identity and compared against original DKG packages. There is no authenticated generation/epoch commit protocol or stale-generation fencing.
- Pinned CGGMP `key_refresh.rs` exposes auxiliary generation, not arbitrary core-share resharing. Fresh DKG plus explicit asset migration is a possible rotation strategy; auxiliary regeneration is not resharing.
- Warm/Cold labels cannot supply separate authorization or signer infrastructure. Those workflows are absent.
- Tenant-aware external financial APIs, MFA/multi-human governance, independent policy grants, merchant/invoice/webhook platform, full operational deployment/backup/restore and final UIs remain unfinished.
- Existing `ops.Blocklist` API/UI is not the new optional withdrawal-only module: its descriptions claim deposit screening/external AML and no global default-disabled enforcement setting is implemented. Searches found no custody deposit/withdrawal enforcement call to this model. Do not treat its UI as proof of enforcement or implement Phase 7B before 6G-C/7A.

## Security findings

**P0:** No new P0 established by this bounded source review. This is not proof of absence.

**P1 / existing lifecycle limitation at baseline `3d32b763`:** `management/commands/mpc_keyset.py` unconditionally retires keysets, while `mpc_binding.py` rejects non-ACTIVE roots. An operator can disable application access to a funded root without an authenticated drain/rotation workflow. Previously documented in PHASE6G.md. The local unmerged correction now rejects command retirement of active/imported/referenced metadata and reopening retired metadata, serializing mutations under a row lock. This is a command-boundary mitigation, not a system-wide lifecycle fix: direct model/raw SQL mutation remains a trusted bypass. The continuation also makes the Django keyset admin view-only; admin-form creation, lifecycle/identity editing and deletion are now denied even to superusers. Full retirement requires safe lifecycle evidence; no irreversible deletion or silent re-enabling of compromised keys is authorized.

**P1 / production exclusions:** Independent signer policy authority, real Warm/Cold isolation, recovery epoch safety and per-chain production assessments remain absent. Existing TON exact-artifact audit correspondence remains open and TON public scope stays deferred.

**Historical corrected findings:** R1/R2 code and migration 0032 exist. MPC-2.md's final review records them fixed and accepted for development merge; the upstream final technical COMMENT reviews have now been checked through GitHub API (not represented as another account’s formal approval vote). Preserve historical attack evidence; do not announce a fresh independent audit.

**P2 / dependency:** Cargo.lock pins Tokio 1.53.3 and removes scc/sdd. `atomic-polyfill` 1.0.3 remains through FROST/Postcard/Heapless on `cargo tree --target all`, absent from the selected Linux host graph. Historical final review accepts it only as development-stage P2 maintenance debt; remediation and production assessment remain outstanding. No scanner suppression or dependency change is authorized by that historical acceptance.

## Financial correctness and infrastructure

Existing immutable asset identity, original gas-grant provenance, deterministic issuance locks and ledger tests are implemented. No balances or historical journals are rewritten by this continuation. Root retirement safety needs correction; database and signer administrators remain trusted authorities. Local same-host fixtures do not establish independent production failure domains.

The prepared environment provides Python 3.11, PostgreSQL 16, Rust 1.90.0, Node/npm and locked frontend dependencies. Redis is optional for synchronous development. Full validators, genuine multi-chain acceptance and production signer credentials are not supplied by the basic environment setup.

## CI status and local evidence

The workflows retain backend/PostgreSQL, frontend, Rust Fast/audit, cryptographic preflight and full protocol/network/four-chain gates. Live fork Actions listing contains no workflows or runs, and PR #1 reports no checks. main is reported unprotected, but the directive still requires all existing Fast/full gates and independent review; lack of branch enforcement does not waive them. Local Fast results are recorded below after execution; they never substitute for exact-final-SHA GitHub gates.

Historical MPC-2.md reports 14/14 jobs, 607 backend, 219 integration and 32 distinct Rust cases at the former premerge head. These are historical reported results, not fresh executions or verified fork CI results.

## Documentation inconsistencies

README/AGENTS name 6F-D as current; status/requirements/phase reports still call 6G-B Draft/unmerged. Some latest-looking paragraphs retain remediated Tokio/scc warnings or call the atomic maintenance decision blocked. Preserve these as dated history with explicit current supersession. Existing requirements still demand AML/KYT plugins and frontend describes deposit screening; the newly adopted directive supersedes these product requirements.

## Next required phase, implementation scope and acceptance

**6G-C, one final major Phase 6G PR.** First address unsafe lifecycle transitions. Then implement standard chain-native seeded SOL and separately attributed classic SPL accounts controlled by original FROST authority; never invent Ed25519 HD. Add authenticated immutable ownership/network/base/seed/rent/fee identities, scanner/sweep accounting and signer-side exact-message verification. Implement immutable FROST generation state, authenticated refresh/repair, stale-epoch fencing, backup rollback controls and explicit root-migration rotation for unsupported CGGMP operations. Build enforceable Hot/Warm/Cold boundaries, not labels alone.

Require genuine all-pair threshold signing/spending, native/SPL validators, attribution and liability accounting, unauthorized/cross-owner/network/replay/mixed-epoch tests, partial signer loss, restart/crash-at-commit recovery, concurrent issuance and measured storage/rent/throughput. Existing multi-chain regressions, PostgreSQL migrations, exact-final-SHA CI and independent review must pass before merge. Do not move to Phase 7 while this PR is incomplete.

## Blocking dependencies

Internet/API access is restored and Draft PR #1 exists. The remaining external prerequisite is fork GitHub Actions activation and adequate Actions integration permissions: workflow/run listings are empty, dispatch is 404, and both reading and enabling Actions settings via the integration are 403. Owner action in the fork’s Actions/settings and integration configuration is required. Do not request token values in chat, weaken workflows or bypass merge requirements. After the setting/permission changes, retry workflow discovery/dispatch, inspect actual runs and complete exact-final-SHA gates before merging. Complete the remaining 6G-C implementation and acceptance in this same draft PR; no later phase may start yet.

## Initial correction and independent source review

The first ten regression cases all failed against the baseline command before the correction. After correction, 71 relevant keyset/Solana/lifecycle cases passed. The final focused suite adds referenced-metadata protection and a real PostgreSQL concurrent row-lock wait: 12 passed. A separate review agent independently inspected the command and tests and reran those 12 cases (1.78s), finding no P0/P1 blocker within that bounded correction. This is independent source review, not an external cryptographic audit, final-SHA GitHub approval or acceptance of complete Phase 6G-C. No wallet/key/generation lifecycle endpoint or production flag is enabled.

Limitations remain: imported-root drain/rotation is not implemented; direct model/raw SQL status changes remain trusted; the admin-form bypass is removed by the continuation; no epoch/refresh/repair protocol or signer-side state revocation was added. Coordinator requests now occur while a keyset row lock is held; adapter timeouts bound this correctness-oriented command serialization, which can delay concurrent administration.

## Executed validation — initial unmerged correction

| Check | Actual outcome |
| --- | --- |
| Unchanged baseline PostgreSQL backend | 607 passed, 4 existing deprecation warnings, 134.07s |
| Post-correction PostgreSQL backend | 619 passed, 4 existing deprecation warnings, 140.47s |
| Focused final lifecycle tests | 12 passed, including real concurrent lock wait and reference guard |
| Independent reviewer focused rerun | 12 passed, 1.78s; bounded source review only |
| Full Rust workspace (no exclusion) | 32 passed, zero failed/ignored/filtered; includes genuine FROST and CGGMP all-pair signing, protocol suite 88.75s |
| Frontend contract | 2 passed |
| Both frontend builds | Passed with BUILD_TARGET=django |
| Django checks and migration drift | Passed; no migration changes |
| Changed Python Ruff format/lint | Passed |
| Cargo fmt / all-target Clippy with warnings denied | Passed |
| Git whitespace / local Markdown target links | Passed |
| Fresh Cargo advisory scanner / full multi-chain validator acceptance / fork CI | Not executed; no result claimed |

These runs validate the local code working tree and unchanged dependency locks. They do not prove exact-final-SHA GitHub CI or complete 6G-C acceptance. The network draft is persisted, not applied/published by the save tool. API access is now applied and Draft PR #1 exists. Once fork Actions execution is available, resume real workflow execution while completing all remaining 6G-C implementation and genuine acceptance, obtain required final reviews/checks, then merge only if every mandatory gate passes.

## Continuation after Internet update — direct GitHub verification

The API now confirms upstream PR #37 is closed/merged, its premerge head is `a92d00ca8c4228cc81154f303039ce3668e93a33`, and merge commit is exactly `3d32b763ff777347f77eae7a8a7936d85dc2d770`. Reviews 5633820156 and 5633830492 exist at that head and record R1/R2 fixed, Tokio/scc remediated, and atomic-polyfill acceptable for development merge under documented restrictions. They are technical COMMENT reviews, not a fabricated approving-account vote or a production audit. The clarification states the benchmark compares all 1,000 account UUIDs and independently revalidates receipt-bound identities; it does not directly snapshot/compare every complete identity tuple.

Upstream Fast run [40009083421](https://github.com/hassan-anari/Base/actions/runs/40009083421) and full run [40009129783](https://github.com/hassan-anari/Base/actions/runs/40009129783) both report success at that exact historical head. The full run’s job listing confirms 14 completed/success jobs, with none skipped. These are newly verified historical upstream workflow outcomes, not current fork PR CI or an execution of new 6G-C changes.

The keyset admin continuation denies creation, mutation and deletion while retaining authorized view access. Three HTTP regression cases fail before the change and all 15 focused cases pass after it. The independent reviewer reran the 15 cases (2.50s), inspected denied mutation permissions and confirmed the registered admin offers no bulk actions even to superusers. No P0/P1 blocker was found within this bounded change. Direct model/raw SQL and privileged code remain trusted; the whole lifecycle milestone is still incomplete.

Continuation validation: the complete PostgreSQL backend suite passed **622 tests**, with four existing deprecation warnings, in 135.27s. Django system checks, migration-drift check and changed-file Ruff format/lint passed. There are no migrations or dependency changes. Rust/frontend outcomes above belong to the preceding checkpoint with identical Rust/frontend code; they were not rerun for this Python-admin-only change. Current fork CI still has zero runs/checks and remains an unmet mandatory gate.
