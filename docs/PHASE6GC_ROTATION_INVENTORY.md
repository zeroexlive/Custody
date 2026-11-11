# Governed rotation manifest staging — unmerged development

This checkpoint authenticates and durably stages the finite rotation inventory
in the independent witness. It grants no migration private round, transfer,
financial publication, ledger mutation, chain-finality assertion, retirement or
late-deposit rescue. Phase6G-C remains incomplete. The existing native/SPL
financial paths and original Root/Claim domains retain their separate gates.

Custody and the current independent class Policy sign the identical bounded
RotationPlan under `WITNESS_SOLANA_ROTATION_PLAN_V1`; the separately pinned
Lifecycle authority signs each existing witness command. Live verification checks
both CA chains, roles and exact current public-key pins. The locked admission
clock checks both plan and command expiry after acquiring the journal mutex.
The backend receives no Life or Policy private key.

`StageRotationInventory` requires the exact enrolled original source Root already
Frozen and unprepared, its current generation/roster, no pending maintenance or
source Open execution, and an exact Active financial-mode target. Both complete
source and target signing-identity histories must be disjoint on every admission,
including renewal after target maintenance. Target Claims must match original
registered evidence and permanent issuance. Treasury role and ACTIVE publication
remain explicit Custody/Policy declarations: W does not attest a live DB row,
beneficial-owner registry, actual chain balances or target all-pair control.

The source manifest covers indices0..N-1, including declared unpublished entries.
W compares every known Claim and evidence fingerprint and requires its registered
frontier not exceed N. Custody/Policy must independently attest the backend's
allocated frontier; a signed digest alone cannot discover unknown allocations.
Chunks are contiguous, at most32 entries/128KiB. Exact retries cannot append twice;
changed chunks, gaps, overlap and cross-chunk reservation/owner/retry aliases fail.
The last chunk must match the full original inventory fingerprint. An empty Root
uses one explicit empty chunk with high-water0. Every original W Claim is mandatory.

A W issuance is not itself financial membership. Financial-mode issued sources
require an explicit matching Financial PENDING/ACTIVE declaration; inconsistent
DB history must be reconciled, never manufactured. Mode-off native issuance stays
`LegacyControl` with its exact optional archival issuance, original evidence and
unchanged mode. `Unpublished` cannot hide an existing W grant. New unregistered
entries cannot reuse rotation, authorization or already reserved lifecycle IDs.
Their exact Claim tuple is also permanently bound as a non-spending allocation
candidate. Other Roots cannot reuse its reservation ID; its index/owner/mint/retry
cannot be reassigned after abandonment. Registration and candidate availability
recheck these bindings. Exact later registration may consume its own candidate,
but no registered frontier, Evidence, issuance or membership advances at staging.
No membership row is created or activated by this protocol. This W layer does
not pause the backend allocator: durable local allocation pause and final DB
frontier/hold rechecks are required before future migration/retirement admission.

The witness retains original plans, authorization attempts, entries, chunk hashes
and abandonment tombstones. Fresh approval may change the current generation,
roster and TTL, but cannot change the original business, destination, inventory or
fee budgets. These are approved budget declarations only; actual in-flight fee
reservation and failed-attempt accounting are still required before movement.
A staged source cannot use ordinary lifecycle changes, including profile migration
through another cohort Root, to escape its pause.

`BeginRotation` accepts only a sealed inventory under fresh approvals and moves
the source to `Migrating`. This checkpoint still grants no private work. Every
source SignedPending execution and every known non-NoSignature incoming execution
blocks entry: a signature, backend settlement or timeout is not a witness finality
proof. Thus a used Root, including a classic-token initializer, needs the future
original-wire finality-attestation path before it can enter migration.
`AbandonRotationInventory` preserves all identities/history and leaves the source
Frozen. In this staging-only layer it may abandon a Migrating reservation because
no movement permit exists. Before implementing movement, this boundary must reject
any attempt with a possible signature until authoritative resolution. Abandonment
never clears an original execution or releases any backend hold.

New journal writes use forward-only rules4. Old signed rules0–3 events retain their
original replay behavior and bytes. Rotation progress is an optional signed RootView
field omitted when absent. A public recipient index rebuilds from the journal's
Root enrollment, Claim registration and admitted unpublished inventory. Under the
same mutex, every new ordinary R1/R2 rejects known inactive recipient Roots for
native transfers, classic owner transfers and cross-Root seeded token transfers.
The index is genesis-scoped and grants no ownership. Old public results remain
recoverable after Freeze; already uncertain inbound wires remain migration blockers.
External deposits cannot be prevented and still require future monitoring/rescue.

## Validation status

Root49 witness tests pass, covering original signed archive replay, current Claim/
maintenance regressions, strict staging, fresh-context renewal, queued expiry,
public incoming fences on both private rounds, source/target history, UUID/alias
collisions, preservation of issuance and conservative SignedPending handling.
Workspace/all-targets Clippy passes with warnings denied. Independent execution passes28 protocol cases77.39s,49 witness cases0.63s and
workspace Clippy0.15s. Six unique genuine cases pass across qualified runs:
new2 calls63.675s and old4 calls7.168s, not a single six-case pass run. All155
source/fixture/manifest/workflow/helper paths plus4 runtime binaries remain stable.
Review found no remaining identified bounded P0/P1 or actionable P2. See
[evidence and qualifications](evidence/phase6gc-rotation-inventory-local.json).
Exact-source CI and whole-phase gates remain pending.

The genuine development case uses two fresh three-party FROST DKG cohorts and
separate signer TLS/wrapping identities, actual Root/Claim receipts and authentic
Custody/Policy/Life/W signatures. Mode-off33 and financial-mode1000-entry manifests
exercise bounded chunking/restart; only source index0 has real registered receipts.
The remaining indices are explicitly unpublished allocation fixtures, not1000
backend wallet publications. Target ACTIVE is a signed declaration in this case,
not DB financial membership acceptance. Private permits and ledger effects are zero.
The case also exercises head-publication failure/poison/recovery, lost-head replay,
exact retry, forbidden normal source work and authenticated rules downgrade.

Retained earlier failures include an incorrect Life transport in a permit-negative
fixture and separate10-second startup/rejected-start helper limits exceeded by the
1000-entry debug replay. Startup waits are now explicitly bounded at60seconds for
these tests; no authorization TTL or production transport deadline is extended.
A test-only Clippy needless-borrow issue was corrected without suppressions.
Independent failures also remain retained: one candidate query omitted its required
Claim ID; an older helper expected new rules2 events rather than current rules4.
Both corrections affect tests only. Historical bytes/signature/downgrade assertions
remain intact. Final1000-entry debug replay took13.324s.

Parent0c24faf Fast41730430453 passed4 executed jobs, including1364 backend cases
830.90seconds. Full-crypto jobs were unselected. That run predates this witness
implementation. This checkpoint is not whole-phase ALL or original3d32 encrypted-
store compatibility acceptance, and does not authorize merge or production.

Remaining: authenticated original-wire finality, explicit MIGRATION/RESCUE source
and private authority with fee exposure, original operation/effect/ledger/finality
integration, actual native/SPL movement of customer and treasury sources, retirement
readiness, continued address watching and late-deposit rescue. Final exact-SHA
Fast/ALL/fixed3d32 compatibility, independent whole-phase review and conditional
merge/main verification remain mandatory. Same-key repair cannot cryptographically
revoke a compromised old threshold.
