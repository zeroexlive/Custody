# Phase 6G-C — RUSTSEC-2026-0387 security gate

Current supersession (2026-10-28): the implemented source checkpoint `1d4737e`
passed Fast40675308341 and all14 full-gate jobs40675302192,228 actual calls/zero
skips and original-store compatibility652.422s, independently verified. The owner
explicitly authorized merging this bounded development checkpoint; see the
[dated decision](DECISIONS.md) and [live status](PROJECT_STATUS.md). The older
unmerged/no-checkpoint-merge wording below is historical. Phase completion and
production/mainnet/customer-fund authorization remain separate, unfinished gates.

Status (2026-10-27): **bounded remediation VERIFIED in unmerged development
checkpoint `ea4bb4edfd646b34a58e00170a734e57674b1825`**. Main `3d32b763` still
contains the older affected graph. Phase 6G-C is incomplete and no phase merge or
real-fund authorization follows. Subsequent source changes need their own final
SHA gates. This is not an exploitation claim or scanner exception.

## Executed CI evidence

The owner enabled fork Actions. The main `CI` workflow initially reported
`disabled_fork`; enabling that existing workflow and dispatching it succeeded.
[Run 40470890805](https://github.com/zeroexlive/Custody/actions/runs/40470890805)
executed against `3db8c01a7df5bdcd9b3116c0d6d2f7e2182d6f55`:

- backend, frontend and rust-check: **passed**;
- rust-audit: **failed**, one vulnerability plus the existing atomic-polyfill warning;
- crypto-preflight and eight dependent cryptographic jobs: **skipped**, not passed;
- full-crypto-gate: **failed**, correctly refusing incomplete acceptance.

The failure is `crypto-bigint 0.5.5 / RUSTSEC-2026-0387`, published 2026-10-23.
The unchanged main lockfile already contains this dependency; the command/admin
correction and unconnected Solana helpers did not introduce it.

## Authoritative source and impact

[RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0387) and its
[canonical advisory record](https://github.com/RustSec/advisory-db/blob/main/crates/crypto-bigint/RUSTSEC-2026-0387.md)
classify multiple timing-variability issues as `crypto-failure`. Operations
intended to be constant-time may execute secret-dependent branches depending
on compiler and target: subtraction, zero counting, division and Montgomery
multiplication. Newer API issues also include equality and inversion.

[RustCrypto release PR #1365](https://github.com/RustCrypto/crypto-bigint/pull/1365)
merged as `c34044b8a1479ef32bec0a9030cf2f07b06506d9` and documents the 0.7.6
fixes and constant-time regression work. The advisory marks `>=0.7.6` patched.
Registry metadata currently marks 0.7.6 yanked; non-yanked patched 0.7.10 exists.
No checksum, package-signature or TLS verification was disabled.

The selected Linux dependency graph includes private-arithmetic consumers:

```text
CGGMP24 0.7.0-alpha.3
  -> generic-ec 0.4.5 -> generic-ec-curves 0.2.4
  -> k256 0.13.4 / elliptic-curve 0.13.8
  -> crypto-bigint 0.5.5
```

The signer selects CGGMP Secp256k1; generic-ec's scalar subtraction delegates to
k256's `Scalar::sub`, which uses `Uint::sub_mod`; k256 wide scalar reduction also
uses `U256::sbb`. Thus a blanket public-verification-only exemption is unsupported.
However, exact timing leakage or key recovery has **not** been reproduced here.
Some newer APIs named by the advisory do not exist in 0.5.5, and its `Limb::sbb`
implementation differs from the newer `borrowing_sub` implementation fixed in
PR #1358. Source reachability alone is neither compiler-level timing analysis nor
proof of exploitability/absence. Keep this as a P1 security gate pending proper
assessment/remediation; do not hide it behind the older development P2 warning.

## Pre-migration compatibility investigation and concrete resolver result

Read-only crates.io index checks establish:

| Current/published component | Dependency constraint |
| --- | --- |
| elliptic-curve 0.13.8 (latest 0.13) | crypto-bigint ^0.5 |
| k256 0.13.4 (latest 0.13) | elliptic-curve ^0.13.8 |
| generic-ec-curves 0.2.4 | k256 ^0.13 / elliptic-curve ^0.13 |
| latest generic-ec-curves 0.3.0 | still k256 ^0.13 / elliptic-curve ^0.13 |
| latest generic-ec 0.5.2 | generic-ec-curves ^0.3.0 |
| latest cggmp24 0.7.0-alpha.3 | generic-ec ^0.4.1 |
| maintained k256 0.14.0 / elliptic-curve 0.14.3 | elliptic-curve ^0.14.1 / crypto-bigint ^0.7.8 |

The current official generic-ec main-branch manifest also retains k256 and
elliptic-curve 0.13; inspected open PRs do not supply the missing backend migration.
There is no published compatible patched crypto-bigint 0.5.x release. Updating
only the direct k256 dependency would leave the old CGGMP dependency instance.
Updating published generic-ec alone also does not remove the affected backend.

Resolution was tested in `/tmp/custody-crypto-resolution`, a source/manifest copy
outside the checkout, without changing repository manifests or the lockfile:

```text
cargo update --manifest-path /tmp/custody-crypto-resolution/Cargo.toml \
  -p crypto-bigint --precise 0.7.10
error: failed to select a version for the requirement `crypto-bigint = "^0.5"`
candidate versions found which didn't match: 0.7.10
required by package `elliptic-curve v0.13.8`
... required by package `k256 v0.13.4`
```

No cryptographic dependency or arithmetic source was changed. No audit ignore,
advisory-date rollback, dependency relabeling or alternate scanner gate was added.
A separate source reviewer independently confirmed the registry/constraint
finding and its impact qualifications. This is not an external cryptographic audit.

## Remediation decision and explicit owner authorization

1. Obtain an official maintained compatible backport or CGGMP/backend release,
   pin the reviewed release/commit with normal integrity verification, and rerun
   the complete gates. No such compatible release was found at this checkpoint.
2. Explicitly authorize investigation/implementation of a maintained integration
   change for generic-ec's RustCrypto backend and Custody's direct k256 use to
   the fixed 0.14 / crypto-bigint >=0.7.8 line. This may require an explicitly
   owned/reviewed integration patch until upstream publishes it. Preserve the
   approved CGGMP protocol; do not invent or locally rewrite constant-time
   arithmetic or threshold cryptography, and do not silently introduce a fork.

The second choice is a security-critical dependency/backend change, rather than
a compatible lockfile refresh. The adopted Prompt.md section 29 requires owner
input when "A security-critical architectural change requires explicit approval."
After reading this concrete proposal, the owner explicitly answered
"تأیید بررسی و مهاجرت با بازبینی مستقل" (approve investigation and migration with
independent review). That authorization covers the bounded maintained-backend
integration described in choice 2. It does not authorize algorithm changes,
scanner exceptions, gate bypasses, phase completion or production activation.

Before adopting any migration, require independent review plus serialization
compatibility of existing core/aux shares, extended public material, HD child
paths/public keys, signature/recovery encoding, original receipt/grant identity,
nonce tombstones and completed/pending execution recovery. Preserve original
stores. Run genuine all-pair DKG/signing/HD-spend tests, negative authorization,
crash/restart/partial-quorum cases, historical-store compatibility, unsuppressed
advisory scan and all existing chain/full-final-SHA gates. Independent upstream
constant-time fixes must remain authoritative; functional tests alone do not
establish constant-time behavior.

In the meantime, continue only independent source work and public/disposable
validation. The standard Solana wire helpers are not connected to issuance,
production signing, deposit credit or broadcasts, and do not close this gate.
No phase merge or next-phase work is authorized while the mandatory gate fails.


## Authorized implementation and compatibility evidence

The branch now includes an explicit owned integration port at
`mpc-side/vendor/generic-ec-curves`, version `0.2.4+custody.rustcrypto014`,
selected with `[patch.crates-io]`; it is not a disguised registry release.
`CUSTODY_PATCH.md` identifies the upstream commit, verified original crate checksum,
licenses, maintained dependency versions, unsupported-feature boundaries and
maintenance/removal conditions. `UPSTREAM_DELTA.patch` records the exact manifest
and retained-source delta. Upstream arithmetic and protocol implementations remain
authoritative. No local secret-arithmetic implementation or scanner suppression
is introduced.

The lockfile selects k256 0.14.0 / elliptic-curve 0.14.3 / crypto-bigint 0.7.10.
The old 0.13 / 0.5.5 instances are removed, including from all-target resolution.
CGGMP24, keygen, generic-ec/core, key-share, HD, FROST and Postcard remain pinned to
their original versions. The mechanical port adapts ScalarValue/SEC1 API names,
borrowed reductions and hybrid-array byte storage. Original curve names and
serialized byte slices are preserved. Direct ecdsa integration continues rejecting
high-S; it never silently normalizes untrusted input into an accepted signature.

Executed public compatibility evidence: the original-backend generator was
recreated after the environment restart, and matched the previously persisted
original fingerprint exactly:
`c1ba561d0384ecbc1b7cc97ed17b99cfa521bd79cd63cf38b9bb15017da3d8a9`.
The migrated generator produced the identical complete JSON and fingerprint.
Committed regression fixtures contain public known inputs/results only, including
arbitrary-length scalar reduction, scalar/point serialization, compressed and
uncompressed points, identity/malformed decoding, original HD children and chain
codes, scalar-order/endian boundaries, coordinate round trips, and an original
recoverable low-S signature plus high-S/invalid/wrong-digest rejection.

A disposable real-process upgrade exercise has passed against preserved binaries
from the unchanged pre-migration Rust implementation:

- FROST original encrypted shares, original completed signature recovery, pending
  nonce rejection after restart, and new signatures with all three signer pairs;
- CGGMP original encrypted core/auxiliary shares, exact completed result recovery,
  prepared-execution fencing and all three root signing pairs;
- original signer-signed HD root/child receipts recovered byte-for-byte, then
  genuine child signing with all three pairs, independently verified/recovered
  with libsecp256k1, rejecting verification against the root key;
- encrypted original core/aux/share files, HD identities, completed records and
  already-completed nonce tombstones remained unchanged. Pending statuses are
  allowed only to transition to the existing reconciliation-required state.

`mpc-side/integration/backend_compatibility.py` makes this acceptance reproducible,
with private fixtures in a fresh local-only directory and candidate services
operating on separate copies of original stores. Its stronger combined run also
checks a CGGMP consumed execution created before upgrade. The mandatory full
network CI job builds fixed original main `3d32b763...` with its own original
lockfile, then runs the current candidate against those historical stores.
Only the allowlisted public summary (binary hashes, case names, duration/status)
may be uploaded; never upload signer stores, PKI, shares, wrapping keys or nonce
material. A failing compatibility step fails the existing mandatory network job.

A genuinely separate review agent independently inspected the reconstructed
adapter, direct verifier port and selected dependency versions and found no
concrete P0/P1 in that bounded source diff. This is not an external cryptographic
audit or final phase acceptance. The original pre-acceptance requirements remain
visible above;
exact-head CI and independent review of the final patch/test/workflow diff remain
required before closing this gate. Executed follow-up checks are recorded below.


### Executed migration checks (before final GitHub full gate)

- Full Rust workspace: **35 passed**, no ignored/failed tests, including genuine
  CGGMP all-pair signing (the protocol group completed in 119.04s).
- All-target workspace Clippy with `-D warnings`: **passed**; Cargo formatting
  and changed Python Ruff checks passed.
- Unsuppressed `cargo audit 0.22.0`, live RustSec database (1,380 advisories),
  current 263-package lockfile: **exit 0**. RUSTSEC-2026-0387 is absent after
  remediation; the unchanged atomic-polyfill RUSTSEC-2023-0089 unmaintained
  warning remains visible. This is no scanner exception or production clearance.
- All-target inverse dependency tree selects only crypto-bigint 0.7.10.
- The stronger combined portable upgrade exercise **passed in 361.556s** with
  fresh genuine legacy FROST and two CGGMP DKG/auxiliary ceremonies. A Python
  tuple/list mismatch in its initial exact consumed
  record assertion was corrected to an explicit signer list; no product source
  change or cryptographic assertion relaxation was used. The final harness also
  submits the valid original FROST package for replay rejection and checks original
  owner/index/role files and coordinator reconciliation identity. All three final
  assertion groups were rerun on fresh copies of the preserved original stores
  and **passed**, including same-execution coordinator reconciliation with no
  signature and repeated execute/reconcile rejection. Original source stores
  passed a complete final hash recheck.
- The same three committed public compatibility tests also **passed against the
  unchanged old backend**, independently checking historical fixture provenance.
- Explicit owned-adapter Clippy with `-D warnings` and rustfmt: **passed**.

Exact final-SHA GitHub Fast/full results must replace pending gate claims with
actual links/results; no local result above is a GitHub gate pass.


## Exact-head regression disposition

Checkpoint `ea4bb4edfd646b34a58e00170a734e57674b1825` passed
[Fast CI 40521504904](https://github.com/zeroexlive/Custody/actions/runs/40521504904)
(all four Fast jobs) and
[full CI 40521510401](https://github.com/zeroexlive/Custody/actions/runs/40521510401)
(**14/14 jobs successful, zero skipped jobs**). The seven remote public manifests
were downloaded and independently checked for exact workflow/head SHA, identical
selected/called sets and zero skipped scenarios: EVM 45, TRON 5, Solana 2, TON 3,
network 162, auxiliary-persistence 1, integrated 1 — **219 total executions**.
The separate original-main encrypted-store migration step passed in **518.46s**.

A genuinely separate review agent independently verified the remote GitHub run/job
state and all seven remote public ZIP artifacts, plus the earlier source/provenance
and local compatibility checks. No unresolved P0/P1 was found in this bounded
migration. The technical version-remediation/regression gate is satisfied at this
checkpoint; the older failed CI remains historical evidence. This is neither a
whole-phase review nor an external constant-time/production assessment.

Draft PR #1 remains unmerged and main remains `3d32b763`. Scalable issued Solana
accounts, authenticated epochs/lifecycle/recovery, wallet classes, complete
financial/on-chain acceptance and final whole-phase review still require work.
No later commit inherits an exact-SHA CI pass from this checkpoint.
