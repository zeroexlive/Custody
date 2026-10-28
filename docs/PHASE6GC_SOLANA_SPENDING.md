# Seeded Solana intent contract — Phase 6G-C in progress

The next branch starts from merged PR #1, main
`587e0969a216102879d17cadb6ffeee8dfb8b6c6`. This adds a public typed intent and pure
wire/message construction checks. No signer/coordinator route consumes the new
contract. Dedicated roots retain their existing generic FROST signing fence.
There is no new signing permission, nonce creation, issued wallet, transaction
broadcast, database migration, financial posting or production flag change.

## Implemented public contract

`protocol::solana_intent::Intent` commits the original claim and its root/network/
owner/asset/index, a separate active-generation reference, operation/attempt IDs,
logical session and crypto-execution UUIDs, asset label, customer financial source,
base fee payer, explicit optional rent payer, native/token/create action, exact
blockhash and message fingerprint, validity height, policy version, fee/rent
assertions and wall-clock lifetime. Generation0 in the original Root remains an
immutable DKG marker; it is not rewritten to represent future active generations.

`validate_shape_and_wire` checks canonical UUID tenant and `p1:` owner reference
formats, derived source versus base signing/fee authority, original claim asset
versus action/mint/decimals, package/group/hash consistency, trusted local policy
bounds and time window, then delegates to the independently implemented standard
Solana legacy wire decoder. It rejects extraneous instructions/accounts/permissions,
wrong source, mint, amount, rent, index, payer or blockhash. Native/token transfers
can represent SWEEP or WITHDRAWAL; token account creation requires PROVISION.

`custody_message` constructs the exact canonical public bytes for the separate
`Wallet-MPC/CUSTODY_SOLANA_SEEDED_INTENT_V1` domain plus NUL, containing the entire
typed intent and canonical bounded payload hex. It neither signs nor verifies a
signature. These bytes must not be substituted for an authorization check.

The supplied `ValidationPolicy` is not deserializable from a request. A future
signer must obtain it from trusted configuration/independent policy. The helper
does not establish that the caller supplied an authentic policy or active package.

## Explicit remaining authorization boundary

Canonical tenant/principal references do not prove registry membership or caller
authority. A generation number and package fingerprint do not prove freshness;
the epoch99 positive test deliberately demonstrates that this pure reference
check is insufficient. Fee/rent/height values remain assertions and caps until
independent live network checks exist. Wall-clock expiry does not prove current
blockhash validity, current rent, fee quotation or non-inclusion of an old payout.

Before integration can create a nonce, each actual signer must authenticate the
original custody proof, reopen its own original root/claim approval and compare
the exact identity, enforce trusted network/business/class policy, obtain a fresh
independent generation/operation/party/round-bound witness permit, and preserve
execution tombstones and unknown financial reservations. Protected require-witness
deployment policy must live outside restored share backups; restoring an older
store without enrollment metadata cannot reopen generic signing. A saved signed
epoch certificate is replayable and cannot replace that online boundary.

Original completed-result recovery may return existing evidence without creating
a fresh nonce. Partial/unknown signing and broadcast outcomes remain reserved.
Witness/refresh/repair/rotation/drain/late-deposit rescue, source-versus-base fee/rent
settlement, finalized SPL initialization, actual issuance and deposit/sweep/
withdrawal integration remain unfinished. No Phase 7 policy platform is implied.

## Evidence and fixture provenance

Nine Rust contract tests pass on the promoted workspace source; a separate review
agent independently reran the final nine in0.29s with no ignored/filtered cases and
found no blocking P0/P1 within this unconnected foundation. The generator was also
independently rerun with database connections explicitly forbidden. Twelve public
Solders SDK fixtures cover native transfer, classic token creation and classic
transfer with/without idempotent ATA creation at indices0,1 and2**63-1, including a
Unicode asset label in the canonical message. They also
provide independently generated Python canonical domain-message hashes. Negative
coverage includes source/authority substitution, changed wire even with an updated
hash, index/mint/policy/time/rent/package/ceremony mismatch, unknown fields and
noncanonical/oversized payload. WITHDRAWAL and provisioning role semantics are
tested separately. These are contract cases, not twelve genuine executions.

The shared public FROST package was extracted from local genuine isolated registry
acceptance supporting checkpoint1d4737e. Claim/intent fixture values are synthetic
format/wire inputs; they are not signer-approved spending grants. No private key,
share, receipt-signing key or authority credential is included. The Python generator
uses public data and SDK constructors only, with no RPC or database queries.

```sh
cargo test --locked --manifest-path mpc-side/Cargo.toml -p wallet-mpc-protocol --test solana_seeded_intent
python mpc-side/protocol/tests/fixtures/generate_solana_intent.py --fixture mpc-side/protocol/tests/fixtures/solana-seeded-intent-sdk.json --check
```

Run the generator in the configured development Python environment. Backend CI
checks its formatting/lint and regenerates every public SDK/canonical golden.
Workspace Clippy passes; Cargo.lock and the dependency graph remain unchanged.
No new dependency or cryptographic arithmetic implementation is added.
New final-head CI remains required; previous PR #1 gates do not transfer to it.
This review accepts the limited library boundary, not operational seeded signing.
