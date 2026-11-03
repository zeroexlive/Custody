# Phase6G-C current-identity Claim approvals — development in progress

This unmerged boundary adds public Claim receipts under the current signer
identities after actual same-key refresh or physical replacement. It does not
complete Phase6G-C. Backend registration, effective-evidence consumption and
financial publication after replacement remain unfinished; no production flag
is enabled.

## Authority and compatibility

Root, Claim, original receipt messages, original DKG ciphertexts and native/token
address derivation remain unchanged. Optional Claim Evidence `authority` holds
the exact original Life-signed Prepare, its three GenerationReady statements and
public DER leaves for precisely those three named keys. Embedded leaves are key
material authorized by the pinned Lifecycle identity, never uploaded CA anchors.
Root Evidence still rejects authority. Absent optional fields preserve old
serialized bytes and signed journal replay.

The separate `CUSTODY_SOLANA_CURRENT_CLAIM_V1` and
`SIGNER_SOLANA_CURRENT_CLAIM_V1` domains commit the unchanged Claim and complete
authority. New Custody requests have explicit bounded lifetimes; old Prepare
expiry does not invalidate archival receipts. Verification of public signatures
alone establishes no current generation, registration or permission to spend.

W returns its exact original signed Prepare from verified durable history and
read-only candidate alias occupancy. New rules3 writes require current authority
at a post-maintenance Claim frontier and bind the full permanently registered
Evidence on private permits. Older rules0/1/2 retain original replay semantics.
Already registered original or current Evidence never changes with later refresh.

## Public node controls

Only profiles with an explicit Lifecycle pin expose
`/internal/v1/solana/current-claim/{query,approve,recover}`. HOT/WARM require the
coordinator transport role; COLD requires courier and explicit manual query
exchange. A node durably commits its own 15-second challenge before contacting W.
Before a new report it checks current Active generation/roster, unused original
aliases/frontier, exact committed encrypted generation, immutable loaded profile
and original source/replacement provenance. Staging is insufficient. Custody
authorization and freshness are rechecked after locking and before publication.
Only a public P256 report is produced; this API consumes no FROST nonce or private
transaction signature.

Reports are durable before release; recovery returns their exact original bytes.
All old/current Claim, index, owner and retry aliases remain permanent. Another
authority attempt may approve the same unchanged Claim after maintenance races;
W determines which context can register. It never assigns another Claim those
aliases. Historical current receipts remain usable after another refresh without
requiring their receipt roster to equal today's private signing roster.

The original approval store has a signed forward marker. Its observed marker
cannot silently disappear or change while live. Protected startup reconciles the
fence from independently replayed external CurrentClaimReport history after a
share-only backup restore, creating no original enrollment or Claim receipt.
An uncertain report write may leave a conservative forward fence; it cannot
release an undurable receipt.

The online coordinator adds `/v1/keysets/{id}/solana-current-claims`, collecting
only public node reports under a previously enrolled original Root. It preserves
the original Claim cache and separately caches by Claim/context. The backend must
independently verify these signatures and exact W registration. COLD stays on
explicit courier controls.

## Historical repaired-store upgrade

New rules3 replacement activations install the exact recipient profile pin from
the Life-reserved replacement plan. Older accepted rules2 events intentionally
retain their previous missing-pin state on replay. They require an explicit new
Life command `PinReplacementProfile {replacement_command_id}` before new current
receipts can be issued.

Promotion derives every field from the original accepted ReserveReplacement;
there are no supplied profile, key or anchor overrides. The same Root must be
Frozen, drained of Open executions, without pending maintenance or preparation;
the recipient key must still be current and its original next epoch reached.
A different existing pin cannot be replaced. The normal immutable command and
idempotency history applies. An ordinary all-three refresh then provides fresh
readiness before new receipts. Existing old signed event files are not rewritten.

## Validation and open work

Local ordinary HOT and COLD runs passed real refresh, all-three current receipts,
W registration, node restart, new-address FROST spending and original/current
Claim spending after Gen2. Replacement HOT/COLD and public storage/maintenance
fault cases passed three cases225.94s before the restore correction. The expanded
restore case passed32.33s, including live marker disappearance and restoring the
entire pre-current share directory while preserving the external journal.
A genuine fixed7ff1e56 rules2 repaired-store upgrade passed101.39s before the
subsequent online collector and baseline-canary additions. These results are
bounded intermediate evidence, not acceptance of those later source changes.

Witness27 and Python27 public P256 contracts pass; Python readiness fixtures are
synthetic. The standalone Python verifier intentionally does not parse upstream
FROST packages or activate backend registration. Genuine private/W verification
and exact fresh registered proof remain mandatory.

The final frozen-source independent rerun passed7 genuine cases533.394s, zero
failures/errors/skips, plus85 contracts. The112-path manifest (108 source/fixture/
workflow files and4 binaries) is unchanged before/after genuine execution. The
permitted unit-test build temporarily changed W's binary; its exact frozen v7
artifact was restored before the genuine run, with that intermediate delta
retained separately. No remaining bounded P0/P1 was identified. See
[public evidence](evidence/phase6gc-current-claims-local.json).
Exact-head CI and all whole-phase gates remain required.

Backend completion must retain immutable original Claim approval while storing
the exact W-registered effective Evidence separately. It must handle a legacy
approved/unregistered Claim with a pending public issuance intent without changing
its IDs, aliases, roles or financial history. Fresh-DKG rotation, actual fund
migration, drain/retirement, old-address rescue and final ALL/original-store
compatibility gates remain open.
