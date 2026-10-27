# Phase 6G-C — RUSTSEC-2026-0387 security gate

Status (2026-10-27): **OPEN / merge blocked**. This finding is not an exploitation
claim, a scanner exception, or permission to activate real-fund signing.

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

## Compatibility investigation and concrete resolver result

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

## Concrete remediation choices requiring a security decision

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
This document makes the proposed scope reviewable; no such migration is approved
or implemented merely by preparing this report.

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
