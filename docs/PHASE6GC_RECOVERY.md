# Phase6G-C explicit replacement recovery — in progress

The current unmerged continuation implements the public authorization and journal
upgrade boundary. It does not yet implement private single-share repair, new
profile provenance loading, subsequent refresh, root rotation or complete recovery.
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
plan. Each private participant must eventually verify its own fresh query, both
Lifecycle/witness signatures and original receipt pins. A prior acknowledgement
alone does not prove the reservation is still pending. `ReplacementStart` is a
separate envelope; ordinary `RefreshStart` retains its strict original-roster
check. The actual private start/repair path remains unfinished.

Permanent command history fences reserved repair/refresh/anchor UUIDs, keys and
anchors across completion or abandonment. Later signing executions/sessions,
original DKG identities, ordinary refresh ceremonies and lifecycle command IDs
cannot consume those reserved identifiers. Local private-session history still
needs enforcement when the repair service is connected; the witness cannot know
an ordinary private refresh session that it has never observed.

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

The only removed test artifact is the deliberately injected invalid-rule orphan
which was never admitted by the running authority. Actual uncertain committed
journal events still replay conservatively; no recovery procedure discards them.

Remaining implementation: explicit narrow profile migration preserving every
original signed node record and all Roots sharing that profile; fresh replacement
profile/credential/provenance loading; direct pinned helper-to-helper Delta and
helper-to-recipient Sigma exchanges using upstream FROST RTS; immutable encrypted
one-share staging; all-three refresh and current-roster activation; interrupted,
corrupt, wrong-key, old-generation and COLD/manual cases. New identities cannot
attest NoRelease for old execution keys or erase unresolved old R2 outcomes.
Same-key repair/refresh cannot revoke a compromised threshold: fresh-DKG rotation,
actual fund migration, drain/retirement and old-address rescue remain required.

Final exact-head gates, independent private-recovery review and whole-phase
acceptance remain open. No generic signing or LocalKey fallback is introduced.
