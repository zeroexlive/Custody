# Readonly rotation Claim registration — implementation draft

This unmerged rules8 draft adds public control evidence for originally
unregistered entries of an exact sealed rotation. It grants no issuance,
financial publication, private movement, ledger posting or retirement authority.
Root genuine Gen1 HOT/COLD frozen-receipt cases pass143.880s. Corrected independent validation passes six cases323.592s with182 unchanged
source/runtime paths; no phase or private-movement acceptance is implied.

`RegisterRotationClaim` requires a fresh Life command/CAS, fresh independent
Custody/Policy approval of the unchanged rotation business, a resolved Sealed
inventory and its exact Frozen source/current generation. All three authentic
original/current Claim receipts must agree with the original sealed tuple.
Registration advances only the original contiguous `next_claim_index`; an
arbitrary funded high index cannot bypass earlier original reservations.

The original inventory remains unchanged, including absent registered-evidence
fingerprint and Unpublished/control-only membership. A separate immutable
(rotation, Claim) record binds the original command, source-entry fingerprint and
full registered Evidence. Only that original rotation can use this precise
post-seal provenance exception; the generic entry validator and other rotations
must capture ordinary positive Evidence. Claim issuance and original financial
membership remain separate authorities. Renewed approval IDs stay reserved and
cannot rewrite the accepted receipt or replenish any future budget.

Optional query `rotation_id` plus the original Claim selector returns signed
`rotation_claim_registration` provenance with original rotation/command/Claim IDs,
source fingerprint and Evidence fingerprint. It remains readable after abandonment
and restart. Cross-Root selection fails; ordinary queries omit both optional
fields and retain their original encodings. Backend consumption is not implemented.

Current-generation public approvals gain optional `rotation` context with a
distinct Custody authorization domain. Source nodes separately verify the pinned
Custody and class Policy plan signatures plus original Life/Prepare authority.
Frozen is permitted only for the exact Sealed W rotation and its unchanged current
roster/package; ordinary approvals still require Active. Every node retains its
own original15-second query lease, and both approval and C/P plan expiry apply.
C/P freshness also holds at the original approval issue time so archival recovery
can verify the original accepted context after expiry. The Claim receipt domain
and original Evidence authority encoding remain unchanged. No FROST nonce or
private movement is created by these public reports.

Original signed rules0–7 retain their replay semantics. Old approval/query fields
omit absent optional context. Root75 witness state cases1.87s, seven public shape contracts0.14s and
workspace/all-target Clippy2.19s pass; these are synthetic state/shape tests, not genuine signature
acceptance. The initial new backdate negative used a120-second test assumption;
the existing rotation-plan bound is300 seconds. Its fixture was corrected to
exercise that actual boundary without changing production limits.

Root genuine all-three Gen1 HOT/COLD receipts, Policy/Custody/Prepare/current-
generation negatives, delayed own-lease expiry, original report recovery after
expiry and signed provenance recovery pass in the two-case143.880s run. Corrected independent75 witness cases1.64s,39 protocol cases82.17s,17 related
contracts and workspace/all-target Clippy0.53s pass. Six process cases323.592s
pass together, with no failures/errors/skips/reviewer retries and182 unchanged
paths (178 source/helper/fixture/workflow/manifests plus4 binaries). No remaining
bounded P0/P1 or new P2 blocker was found. Exact-source Fast CI is pending. Actual MIGRATION/RESCUE execution, cumulative
fee exposure, retirement/watch/rescue and final whole-phase gates remain open.

The four original-generation process cases pass on a fresh fixture in187.57s.
An earlier run retained two failures (1000-entry60s startup and a later baseline
DKG failure); the exact saved journal subsequently starts in44.286s CPU44.170s
without code/deadline changes. The fresh four-case run also passes unchanged.
The initial Gen1 HOT case passes74.48s. Initial COLD33.95s fails in target
enrollment because its fixture changed a HOT DKG's Root label to COLD. The fixture
now creates the target DKG with COLD from inception; the production class binding
was preserved. The final class-pair run passes both cases and includes wrong Policy pin and
stale-generation contexts. One later cross-Root helper assertion and one state
case are the only test deltas; production/binaries remain unchanged. Independent
validation will rerun all six process cases on that final source. All failed logs remain available, and no single combined six-case run is
claimed from these qualified root runs.

Independent review then reproduced a live Gen0 provenance gap: the inherited
archival verifier accepted any retained class receipt key, including another
cohort's three valid signatures over the exact approved source Claim. The original
C/P/Life and ownership checks still applied, but this did not prove control by the
stated source cohort. The negative returned200 before correction (7.97s).

Fresh Gen0 rotation registration now verifies each receipt against the exact
source Root's designated per-party key. The generic archival verifier is unchanged.
On reopen, rules8 None registrations are checked against the source roster at
that event; invalid unreviewed draft8 provenance is quarantined rather than
silently reused. Original signed rules0–7 retain their original semantics. The
same corrected33-entry case passes15.44s, and the copied invalid draft journal is
rejected on reopen16.503s. No event, owner, issuer or ledger record is rewritten.
Root75 tests1.67s and Clippy3.07s pass after this narrow correction. The corrected frozen182-path independent rerun passes; earlier passing runs
remain qualified to their pre-correction source. The independent bad-draft copy
also rejects1.520s without modifying the original fixture.
