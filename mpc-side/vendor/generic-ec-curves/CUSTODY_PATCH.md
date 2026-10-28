# Owned RustCrypto integration patch

This is an explicit Custody-maintained port of upstream `generic-ec-curves 0.2.4`
(the CGGMP24-compatible API) to maintained RustCrypto. It is not a new MPC protocol
or an independently audited cryptographic implementation. The owner explicitly
authorized investigation and migration with independent review on 2026-10-27.

Upstream repository: <https://github.com/LFDT-Lockness/generic-ec>.
Crate source commit: `b105806fb6efa258266e150b91906378b95cd0db`, path
`generic-ec-curves`. Crates.io archive SHA-256:
`4c7c6d23001a5eb60eec2b785a63d2ca965fdfbaf3314b3b46df047398369e28`.
The cached original archive was verified against the original Cargo.lock checksum.
LICENSE-MIT and LICENSE-APACHE are from that exact upstream commit's repository
root, retaining the upstream licensing and copyright. `Cargo.toml.orig`, registry
marker files, benches and performance assets are omitted; the replacement manifest
and retained source are explicit in Git. `UPSTREAM_DELTA.patch` records the exact
retained-source/manifest delta against the verified published crate.

## Bounds of the port

- Keep generic-ec-core 0.2.3, generic-ec 0.4.5, CGGMP24/keygen 0.7.0-alpha.3,
  key-share/HD, and separate FROST Ed25519 unchanged.
- Use k256 0.14.0, elliptic-curve 0.14.3, hash2curve 0.14.0 and sha2 0.11.1.
  The reviewed lockfile selects crypto-bigint 0.7.10 (patched for
  RUSTSEC-2026-0387) and ctutils 0.4.6. Normal Cargo integrity checks remain enabled.
- Port upstream API names: ScalarPrimitive -> ScalarValue; EncodedPoint/SEC1 traits
  -> Sec1Point equivalents; Reduce takes a borrowed upstream integer.
- `WireBytes` bridges new hybrid-array storage to old generic-ec-core's ByteArray
  trait. It forwards the original byte slices. The curve name `secp256k1`, widths,
  endianness, JSON point/scalar shapes and zero encoding remain unchanged.
- Preserve upstream scalar arithmetic, inversion, conditional selection, sampling
  and arbitrary-length reduction. No local constant-time arithmetic fix exists.
- Support only Custody's selected secp256k1 adapter. Ed25519, secp256r1 and Stark
  feature requests explicitly fail compilation; they have not been migrated.
  Custody's FROST Ed25519 uses its separate unchanged upstream implementation.
- Custody's direct ecdsa 0.17 integration keeps rejecting high-S signatures:
  `normalize_s() == signature` replaces the old Option-returning API check.

The application tests contain original-backend public golden vectors, scalar
order boundaries, coordinate round trips and low/high-S recovery cases. The full
network gate additionally builds fixed original main and exercises original
private encrypted core/aux stores, signed root/child receipts, completed results,
pending/consumed nonce fences and genuine all-pair root/child/FROST signatures.
Private fixtures and wrapping keys are never CI artifacts.

Functional compatibility does not establish constant-time behavior. Upstream
RustCrypto fixes and independent security assessment remain authoritative. Keep
this patch small and review it with every RustCrypto/generic-ec/CGGMP update;
replace it with a compatible maintained upstream release when one exists. Never
remove the historical-store gate or change stored identity to ease an upgrade.
