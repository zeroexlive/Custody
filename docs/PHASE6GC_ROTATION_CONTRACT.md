# Rotation data contract — implemented draft, no rotation authority

The protocol library now defines a bounded, strict data layer for governed fresh-
DKG migration. It exposes no witness command, signer/private route, transfer,
wallet activation, ledger mutation, retirement or rescue permission. Phase6G-C
remains incomplete. The following validations establish data consistency only.

`MigrationSource` preserves the exact original Claim, tenant/owner, asset, role,
prior membership and optional W-evidence fingerprint. It includes unpublished
entries rather than silently skipping them. An absent fingerprint cannot be a
movement source; a supplied fingerprint still needs authoritative W comparison.
LegacyControl means a canonical registered tenant/principal namespace without
ordinary financial membership. It does not automatically adopt an opaque legacy
namespace or rewrite an old beneficial owner.

Financial membership distinguishes PENDING from ACTIVE publication. It retains
original issuance/command/initialization IDs and does not change stored membership
or Root liveness. A retired Root may retain its old ACTIVE membership record;
that is not ordinary spending authority. Only a previously issued ACTIVE target
treasury is eligible as a destination declaration. W/DB checks must independently
verify those facts before future admission.

The finite inventory covers every allocated index0..N-1, with exact Root, unique
original reservation, owner/asset and retry aliases. Its canonical fingerprint
includes classification and original evidence identity. Bounded chunks carry at
most32 entries and128KiB. A complete-plan comparison also requires an exact target
for every asset key/mint/decimals; labels alone cannot select another asset.

A RotationPlan binds distinct original source/target group keys and DKG identities,
current generation references, separate three-party rosters, exact tenant/genesis/
class, complete inventory and governed treasury destinations. Epoch-zero markers
must match original DKG; later generation IDs cannot reuse known plan/Root/context
identities. Live state must additionally check current generations, all historical
source identities, target control/liveness, cycles and incoming uncertain work.

The stable rotation/business identity is separate from each fresh authorization
ID, generation context and approval expiry. Renewed approval cannot change the
original Root, inventory, destination or budget. `max_fee_per_movement_lamports`
is a per-execution cap; `total_fee_budget_lamports` is cumulative, including failed
finalized attempts. Renewal does not replenish either budget. Future W admission
must reserve possible in-flight fees before granting concurrent work and retain
unknown exposures until authoritative resolution. Explicit budget replanning must
preserve every old movement/hold/session, rather than clearing them.

Custody and independent Policy sign the same exact plan under a separate domain;
Lifecycle authorization remains separate. Detached-approval shape checks require
bounded canonical signatures/chains and distinct identities, but do not verify
signatures or establish chain trust. Plans are capped at256KiB so two approval
copies, bounded chains and an inventory chunk fit the unchanged1MiB service/event
ceiling. Signed-message verification is required in the future witness layer.

## Evidence and next implementation

Root12 contract tests pass0.18s and protocol/all-targets Clippy passes3.93s. Expanded
negative coverage caught that an internally tagged unit enum ignored extra fields
despite its strict annotation. Empty struct variants now reject those fields while
preserving valid JSON shape; the failed8-pass/one-failure result remains retained.
The new public Root fixture contains only original statements and node public-key
IDs from disposable genuine DKG cohorts; it supplies no authorization/private key.

Independent full protocol tests pass26 cases75.66s (12 new contracts and14 existing
cases), zero failures/ignored. Workspace/all-targets Clippy passes10.27s with warnings
denied. All136 frozen source/fixture/manifests/binary paths stayed unchanged. No
identified bounded P0/P1 or concrete P2 remains in this pure data layer. This is
not independent fund-migration, retirement or runtime authority acceptance.

Next: authenticate and durably stage/seal the finite manifest in W; bind current
source/target state under one authority lock; add explicit MIGRATION/RESCUE business
and private permission; integrate original operation/effect/ledger/finality paths;
then retirement readiness, monitoring and late-address rescue. Unknown work must
remain held, and same-key repair never cryptographically revokes an old threshold.
Final exact-SHA Fast/ALL/original3d32 compatibility and whole-phase review/merge
remain required. Parent143dfb5 Fast41702205647 passed4 jobs/1364 backend cases815.43s;
it predates this data layer and selected no full-crypto jobs.
