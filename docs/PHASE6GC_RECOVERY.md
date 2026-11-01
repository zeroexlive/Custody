# Phase6G-C explicit replacement recovery — in progress

The current unmerged continuation implements public replacement authorization and
journal upgrade, plus direct upstream single-share RTS repair into a fresh
required-profile recipient and subsequent all-three refresh. Private-path runtime
and fault evidence below remains bounded development evidence under review.
Explicit old-profile migration acceptance, root rotation and complete recovery remain open.
Do not infer phase completion or production readiness from these foundations.

## Public replacement reservation

`ReplacementPlan` binds the exact original Root, current generation/public package,
old three-key roster, exactly one fresh replacement key with both helper keys
unchanged, new recipient journal anchor and immutable profile SHA256, distinct
repair session/ceremony and subsequent refresh session/ceremony, next epoch and
expiry. The profile hash is a pinned configuration assertion, not remote runtime
attestation against a malicious holder of that node key.

A separate Lifecycle `ReserveReplacement` command requires the exact current
Frozen Root, no prepared generation, no existing replacement and no unresolved
Open private execution. All new roster keys must have independently installed
witness certificate pins. The witness captures the original all-three Root
receipt evidence directly from its immutable enrollment; a recipient must verify
these archival receipts and cannot substitute newly re-signed history.

The signed query's optional replacement value records the original command and
plan. Each private participant verifies its own fresh query, both
Lifecycle/witness signatures and original receipt pins. A prior acknowledgement
alone does not prove the reservation is still pending. `ReplacementStart` is a
separate envelope; ordinary `RefreshStart` retains its strict original-roster
check.

Permanent command history fences reserved repair/refresh/anchor UUIDs, keys and
anchors across completion or abandonment. Later signing executions/sessions,
original DKG identities, ordinary refresh ceremonies and lifecycle command IDs
cannot consume those reserved identifiers. Signed node journals also permanently
fence those IDs against local signing and ordinary refresh, in both admission
directions. The witness cannot know an ordinary private refresh session that it
has never observed.

Preparation of a changed roster now requires the exact reserved next refresh
ceremony/epoch/roster and all three matching signed GenerationReady records.
Activation preserves original Root/Claim/operation/history and clears only the
pending reservation. Current generation remains Frozen until the complete new
agreement is prepared and activated. A repaired share alone will not be a new
generation or a private signing grant.

`AbandonReplacement` requires the exact Frozen, unprepared repair ceremony. It
removes pending authority while retaining every original reservation tombstone.
A fresh identity, anchor and session/ceremony IDs are required for a new attempt.
Replaying the original reservation command only returns its original idempotent
acknowledgement; it cannot recreate a reservation after abandonment. Abandonment
is not proof that an old permission or private packet never existed.

## Private upstream repair and fresh recipient

An existing protected deployment must already have its immutable lifecycle pin.
There is no automatic None-to-Some profile upgrade. A recipient starts with a new
TLS identity, wrapping key, empty private storage and fresh external public anchor.
Its immutable `replacement_bootstrap` binds exactly one original Root and anchor;
the Life-signed reservation binds the actual loaded profile fingerprint, including
public certificate file contents. This hash is configuration provenance, not
remote attestation. Original helper profiles/certificates are never overwritten.

Every node verifies the separate Life plan, exact Frozen witness reservation,
original all-three Root enrollment receipts and its own random witness challenge
(15 seconds). HOT/WARM use the real pinned Rust witness client; COLD has no such
client and requires explicit fresh courier exchange for repair and again for
refresh. A durable signed RepairStart consumes all private IDs before upstream
randomness. The two unchanged helpers load their actual current-generation share.
Upstream `repair_share_part1` creates Delta, sent only helper-to-helper over the
exact newly authorized TLS roster; `part2` emits Sigma only to the fresh recipient;
`part3` creates one participant KeyPackage. No full-key reconstruction or local-key
substitute is used. Controllers never carry private packets.

The recipient checks the scalar-derived verifying share against the exact
current public package, identifier, threshold and group key. Upstream part3 alone
does not perform that public-share check. One repaired share is persisted in
immutable AEAD staging bound to the complete plan, Root, epoch, party and IDs.
It never overwrites original DKG or an active generation. Separate signed
RepairReady proves staging only and cannot authorize signing or activation.
The recipient exposes no original DKG/provisioning router and cannot sign epoch0.
This boundary supports existing original, all-three-approved Claims; it does not
enable new Claim approval using a retired original receipt identity.

All three parties then take a new own Frozen witness query and run the upstream
distributed refresh under a separate replacement protocol/session/ceremony.
Each encrypted new-generation share precedes its GenerationReady; only exact
all-three readiness permits witness Prepare/Activate. The group key and original
Root/Claim receipts remain unchanged. Restart reloads recipient provenance from
original signed RepairStart and independently verifies archival Root receipts.

Secret Delta/Sigma and refresh ephemeral state remain RAM-only. Interrupted private
ceremonies never regenerate on restart; public report may recover only a durable
exact staging/generation artifact. Missing, corrupt or transplanted material fails
closed. Failure between private-artifact persistence and public Ready publication
is recovered from the same ciphertext after verified journal replay. Uncertain
public writes fence private work until restart; they are never discarded to retry.
Explicit abandonment retains old IDs/keys/anchors and requires a fresh recipient.

Private TLS key pins are checked before HTTP. A short release mutex orders journal
appends and synchronous HTTP enqueue; deadline/uncertainty checks occur after TLS
and after acquiring that mutex. The guard drops before awaiting the response, so
two peers can exchange concurrently. A message already enqueued remains in flight;
later Freeze/abandonment cannot prove it was never sent. Disk/fsync and synchronous
lock waits can outlast the async network timeout; there is no hard five-second
availability guarantee under blocked disk. Serialized owned buffers are zeroized,
but upstream Copy scalar intermediates/HTTP implementation copies do not justify
a claim of complete memory scrubbing. Independent external assessment remains due.

## Original signed-journal compatibility

Old witness events omitted the rules field and could accept a Lifecycle-approved
roster change without the new replacement reservation. These already authenticated
historical events must retain their original meaning. `Event.rules` is optional
and omitted when absent, preserving original signed bytes/canonical message
hashes. New live admissions and new events use rules1. Only verified historical
None events select legacy replay; no HTTP parameter selects that path. After the
first rules1 event, replay permanently rejects a downgrade to None, including an
otherwise correctly signed/chained orphan event. An old binary cannot interpret
the new event format and must not be used as a writer after upgrade.

The committed public archive fixture contains four genuine original witness
signed events, the original signed head and public certificates, from an
independently executed original-DKG/Claim rollback-fence case. It contains two
Roots and one Claim. No private historical identity key or MPC share is included.
Independent verification compared every archived event/head to the original
persisted files and checked all witness/Lifecycle signatures, all nine detached
Root/Claim receipts, the complete hash chain and canonical message hashes.

## Bounded evidence and remaining work

Witness state/unit tests passed17 cases, including real original signed-event
verification, signature tampering, monotonic rules, exact reservation, drained
execution requirements, safe abandonment, permanent reverse identifier fences
and old-ACK non-resurrection. Three replacement shape cases and the original Frozen golden pass (four
focused cases). A pending replacement also stops ordinary refresh before private
work. At an earlier public snapshot the independent full protocol library run
passed9 cases including its genuine CGGMP all-pair test.
Independent witness17-case and actual-runtime public upgrade reruns passed.

The actual runtime test loads the original public store through archived pins,
preserves its original event bytes, reserves/abandons/retries a fresh identity,
restarts and refuses old key/anchor reuse. It rejects stripping rules while
retaining the original signature, and rejects a newly signed/chained None-rule
orphan after upgrade with the explicit downgrade error. Initial case passed1.18s,
independent rerun0.98s; the addition proving that the reservation contains the
exact original Root receipts passed1.11s. The final raw historical-byte case
passed0.97s and independently1.21s, with imported bytes matched exactly to the
original historical files. These are public authority/compatibility
tests, not actual share repair or new-generation signing.

Pushed public checkpoint `a27895390ac24df8aac6a5a0345114ba65ee5774`
passed Fast40857133396 (four executed jobs) and selected
Solana40857374994. Independent verification matched exact SHA, preflight
artifact12890253162 and Solana artifact12892037614:35 unique selected/actual
calls, zero scenario skips, JUnit1861.812s, inventory252 with SHA256
`5183ccc7a7806e27ae24fc7a22783e3afe7bd4f3808fca6ebaa3c5c60241d7f6`.
All16 artifact files match the explicit public allowlist. Public replacement
runtime passed0.526s. Other chains and fixed-baseline original-store compatibility
were unselected, so these are not ALL or whole-phase/merge gates. They do not
validate subsequent private-repair source changes.

The only removed test artifact is the deliberately injected invalid-rule orphan
which was never admitted by the running authority. Actual uncertain committed
journal events still replay conservatively; no recovery procedure discards them.

Private development evidence before the final release-ordering refinement:
HOT genuine one-share repair, all-three refresh/restart and all-pair finalized
transfers passed84.85s. The first run reached signing but used a destination amount
below the validator's rent minimum; the test amount was corrected without changing
protocol or validator rules. Actual staging-publication failure/restart, missing/
corrupt/transplanted/symlink staging, altered profile anchor and COLD/manual cases
passed together165.03s. Actual wrong-peer Delta and delayed correct-TLS expiry
tests observed zero HTTP bytes, proved interrupted restart refusal and successful
fresh-recipient retry after explicit abandonment (two cases73.86s).
The upstream-DKG storage unit proves correct one-share RTS and rejects canonical
forged zero Sigmas, wrong participant and transplanted plan; it passed0.02s.
Three deterministic tests of the actual production dispatch helper prove enqueue
ordering, poison-wins refusal and expiry while waiting for the append lock.
After environment restoration the complete current-source private run passed
all5 actual cases/zero skips in297.72s (35 unrelated cases deselected); old ordinary
refresh all-pair/restart and interrupted/missing/Gen2 regressions passed2 cases
in138.78s. All37 signer/storage/transport/witness library tests passed; workspace
all-target Clippy passed5.69s, formatting/Ruff/diff checks passed. Independent
current-source genuine staging/provenance case passed76.81s, with independent
production-dispatch3 and forged-Sigma store1 reruns. Independent bounded review
found no demonstrated P0/P1 remaining after the enqueue/write ordering correction.
See [public local evidence](evidence/phase6gc-private-repair-local.json).
The pre-disconnection partial final-run output is not counted. This local test
selection is not a complete selected-Solana/ALL gate; exact-checkpoint CI remains
required and these passes do not implement profile migration or financial flows.

Private checkpoint `4a4e6ffca0d7107d53e742144f52838a3473f32e`, tree
`16b25bca416dd7ce3c4cdbd41827bb64f0312460`, subsequently passed exact
[Fast40908695597](https://github.com/zeroexlive/Custody/actions/runs/40908695597)
and [selectedSolana40908696183](https://github.com/zeroexlive/Custody/actions/runs/40908696183).
Independent verification matched artifact12916845138 to that SHA:40 unique
selected/actual calls, zero scenario skips, XML2237.562s; inventory257 with hash
`9946094195659c13238ae4fb8703d39a416fcfd6009b6c735d28a1a1ef813b7e`
matches preflight12913152351. All22 files match the exact public allowlist. The
five actual private cases passed70.561/70.878/69.549/29.477/32.573s remotely.
The independent bounded review is tied to this exact tree. Fixed-baseline
original-store compatibility and other chains were skipped/unselected: these
passes are not ALL, phase completion or merge acceptance, and do not validate
subsequent profile-migration working-tree changes.

Remaining migration acceptance: expanded genuine private runtime/failure coverage,
current-revision exact-head gates and independent review. Current-identity Claim
receipt rollover after physical replacement, fresh-DKG rotation and complete
recovery remain implementation work. New identities cannot
attest NoRelease for old execution keys or erase unresolved old R2 outcomes.
Same-key repair/refresh cannot revoke a compromised threshold: fresh-DKG rotation,
actual fund migration, drain/retirement and old-address rescue remain required.

Final exact-head gates, independent private-recovery review and whole-phase
acceptance remain open. No generic signing or LocalKey fallback is introduced.

## Explicit original-profile migration — current working implementation

A dedicated offline `wallet-mpc-profile-migration` command now handles original
`lifecycle_certificate=None` deployments. A successor changes only the independent
Life pin, external public anchor and explicit migration bootstrap; original TLS,
private storage/wrapping key, policy/receipt trust and network/class stay exact.
Original Custody AND Policy approvals, validated through their current original
CA/role validators and key pins, plus the independently pinned Life key authorize
one exact source head, successor fingerprint/anchor and ordered Root cohort.

The source receives one terminal signed event containing the exact original raw
signed pre-head, both original approvals, Life approval and own fresh signed
Frozen witness queries. Earlier signed events are never rewritten. Old binaries
reject the unknown terminal event; current normal old-profile startup also fails.
Source paths and output destinations are checked before this irreversible fence.
The offline command loads no MPC share or nonce and never receives a Life private
key. COLD migration uses explicit end-to-end signed courier exchanges.

The witness's FIRST global migration reservation checks approval freshness at its
own locked clock, current original CA/role proofs and every cohort Root's Frozen
identity/generation/roster. A local signed timestamp cannot establish timely
admission. If independent registration misses expiry, a fresh OLD Custody+Policy
renewal plus Life must bind the same immutable fence/target/UUID. A timely durable
reservation permits exact subsequent cohort recovery after original expiry.
Permanent source/profile/anchor/renewal IDs survive completion. Partial cohort
registration fences lifecycle activation; no old R2 outcome is reclassified.

Offline successor import requires a separate set of own fresh signed queries
showing the exact installed profile pin for EVERY cohort Root. It fully replays
all original raw signed records under their OLD profile context, imports every
request/consume/result/ceremony/cancellation/repair map, then records a new signed
genesis linked to the exact final original signed head. Source-stage proofs or
an uninstalled profile cannot initialize it. Interrupted genesis recovery uses
the same durable signed event and preserves accepted artifacts. Normal
`--initialize` cannot reset either journal.

Runtime startup replays the complete original predecessor and successor, retaining
the predecessor flock throughout service lifetime. New private work is limited to
the approved Root cohort and requires an explicit exact witness profile pin,
including source fence, anchor and migration UUID. Public historical results and
original-request NoRelease recovery retain their original signatures and keys.
New DKG routes are closed; provisioning is limited to the approved cohort. This
same-identity migration does not replace historical receipt identities or revoke
a compromised threshold.

Bounded local evidence: original4a terminal-fence/path/raw-head case passed44.373s;
offline successor import passed51.717s. Independent terminal/import rerun passed
46.094s with identical before/after binary hashes. These genuine cases preserve
2 original None-profile requests, 2 consumed None-profile permits and 2 public
results, reject corrupt predecessor history, and recover the same orphan genesis.
The current protocol/signer/witness library selection passed12/12/20 tests;
workspace all-target Clippy passed7.34s. Independent bounded source review found no
remaining P0/P1 in the terminal/import layer. At that initial snapshot genuine
migrated private runtime and expanded failure acceptance were pending; completed
local results below supersede that runtime status. Exact-head CI remains separate. The initial runtime fixture reused one financial operation ID across two
Roots; the witness correctly refused the second use. That failed run is not
acceptance. The corrected expanded HOT case passed277.789s, with terminal/import
passing50.418s in the same selection (2 completed calls; selection stopped before
COLD, not a complete three-case pass). The runtime case uses three genuine old
Roots: two migrate as the explicit cohort; the third retains exact public
historical recovery but rejects new signing/provisioning/refresh. All three
original nodes migrate, all9 original DKG ciphertexts remain unchanged, and old
None-profile R2 requests remain Open until both actual grantees attest NoRelease.
Both cohort Roots then refresh, restart and finalize all3 signer pairs (6 actual
transactions). Freshly re-signed missing/wrong profile requests are refused while
Roots are Active, independently of the old grant's expiry. The predecessor flock
remains held; corrupt predecessor bytes fence successor restart. COLD and the
independent HOT rerun were pending at that initial snapshot; Nov1 results below
supersede that status. The first independent HOT attempt stopped
at initial validator funding before migration under simultaneous local validator
load; it is not acceptance evidence.

CI now builds genuine original-profile services from the fixed unmodified
`4a4e6ffca0d7107d53e742144f52838a3473f32e` source in a separate target directory,
records actual binary hashes, and includes terminal/import and HOT/COLD runtime
cases in the selected Solana inventory. This is ADDITIONAL compatibility coverage;
the original fixed `3d32b763ff777347f77eae7a8a7936d85dc2d770` six-case store gate
remains unchanged. Only explicit named public reports may be uploaded. No current
working-tree CI pass or complete Phase6G-C acceptance is claimed here.

2026-11-01 (Asia/Tehran): the previously pending standalone COLD migrated runtime
passed274.23s, and independent expanded HOT rerun passed228.004s with stable binary
hashes (14 exact historical results,9 original ciphertexts,6 finalized transfers).
Those binaries predate the subsequent durable ordinary-refresh reservation and
rules2 boundary. Review identified that local refresh could otherwise consume a
W-reserved renewal/session identity; preflight cannot solve its cross-Root race.
New explicit Life `ReserveRefresh`/`AbandonRefresh`, permanent global IDs and exact
own-query proofs now close that allocation gap in the working implementation.
Original absent/1 events retain historical meaning; all new witness events use2
and cannot downgrade. See PHASE6GC_SOLANA_REFRESH.md for semantics and current
evidence limits. Fresh genuine gates were then in progress; completed local
results follow below.

Rules2 local migration/witness-upgrade5 completed cases passed525.47s; ordinary
refresh3 passed177.44s, independently enhanced HOT72.276s. Final successor-import
preflight passed45.06s and refuses a known pending refresh until explicit abandon
and fresh proof, without resetting source history. Subsequent local historical
cross-field ID tightening preserves old None-start replay and passed a genuine
original4a old-writer/new-reader recovery case72.77s. Independent historical rerun
passed72.366s with unchanged binaries. Exact-head CI remained separate. See the explicit scope/delta notes in
[public local evidence](evidence/phase6gc-profile-migration-local.json).

Checkpoint39ad4f51872303371cbd4ad65a64f9255a3037be, tree
00e55be4b25584c9abfb00b92d61170f9fce64f9, passed exact
[Fast41269720532](https://github.com/zeroexlive/Custody/actions/runs/41269720532)
and [selectedSolana41269752763](https://github.com/zeroexlive/Custody/actions/runs/41269752763).
Independent artifact13070282539/preflight13068897326 verification matched45 unique
selected/actualcalls,0errors/failures/skips, XML2768.421s; inventory262 with hash
0f7198209d9d43874b425f7905e8f90cc84ab281f267e6b8e0ff009cb7474cc7.
All35 files match the exact public allowlist. Actual fixed4a original-profile
services built and ran; fixed3d32 original-store gate and other chains were
unselected. This is not ALL or phase completion and does not validate subsequent
financial-mode working changes. DraftPR2 remains unmerged.
