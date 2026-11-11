# Historical inventory materialization (unmerged development)

The rules6 checkpoint `00e49a4` deliberately quarantines unresolved old full
inventory commitments. Forward rules7 adds public data recovery against those
original commitments, and allows fresh plans to update publication metadata while
preserving exact original Claim, asset-key and approved-role bindings. Original
signed rules0–6 retain their replay semantics.

## Authority and immutable records

`MaterializeRotationInventory {rotation_id, materialization_id, chunk}` references
an already admitted rotation, including an abandoned partial upload. The original
Custody/Policy plan supplies the whole-vector fingerprint and allocation frontier.
The caller supplies no replacement approvals or fingerprint. A separate fresh Life
command, original Root, CAS revision and command expiry authorize data transport.
The Root must be Frozen and unprepared. Old plan expiry, old target liveness and
old source generation do not become fresh authority: archive validation uses
original shape and the exact whole hash, independent of current metadata.

Each attempt has a permanently reserved UUID and immutable contiguous chunks,
bounded at32 entries/128KiB under the original plan. An incorrect partial upload
cannot be edited; a new attempt UUID can transport the correct original data while
retaining the failed attempt. Whole-hash mismatch rejects the final chunk atomically.
No partial proposal establishes an owner or changes registered Claim evidence,
issuance, financial publication, private permission or ledger records.

A complete matching vector is recorded as `Verified` only when its Claim/asset-key/
role bindings agree with retained candidates, registered/consumed identities and
other proved commitments. A proved but conflicting vector is retained as `Conflict`
with its reason. It promotes no aliases and permanently keeps quarantine closed;
this change supplies no reconciliation override. In particular, contradictory
rules4–6 provisional candidates are preserved and require explicit recovery.

Life-authenticated query may select `materialization_id`; the signed optional
`inventory_materialization` reply returns the exact attempt/rotation IDs, progress,
original fingerprint and Collecting/Verified/Conflict status. Cross-Root selection
fails. Ordinary requests/replies omit the new optional fields, preserving their
original signed bytes. A successful command ACK means durable data acceptance;
it does not imply Verified status. Operators must inspect signed progress.

## New staging and current metadata

Before a fresh rotation is admitted, every prior admitted commitment must have
complete proved data, including tuples whose chunks never originally reached W.
The new frontier covers every retained candidate and prior declared high-water.
At seal, exact Claim, asset key and role must match all original proved prefixes.
Fresh metadata separately passes current W Claim/evidence/issuance checks and
fresh Custody/Policy/Life plan authorization. No role change is inferred from
publication or data recovery.

New rules7 staging chunks remain provisional until their complete vector matches
the signed plan hash. Only then are all candidate aliases promoted. Proposed UUIDs
remain tombstones against reuse as commands, ceremonies, sessions or other domain
identities, and their addresses remain watched. A Life-submitted wrong partial
owner can therefore be recovered against the original C/P commitment without
rewriting that partial upload or treating it as authenticated ownership.

Unresolved or conflicting sources still cannot register/issue new Claims, activate
ordinary private use, obtain private R1/R2 permits or escape through another Root's
profile migration. Public data recovery and original-wire reconciliation remain
available. No MIGRATION/RESCUE private round or retirement authority is added.

## Validation status

Root71 witness cases pass1.69s and workspace/all-target Clippy passes2.06s.
New state cases exercise missing-data recovery and metadata evolution, new partial
owner proposals, preserved conflicting legacy candidates, wrong hashes and immutable
attempts, expired old-plan archive recovery with a Frozen target, immutable role/
asset/owner checks, exact Root/CAS/UUID/frozen/rules guards and exact retry.
Root4 process cases pass161.712s, zero failures/errors/skips. The1000-entry case
takes146.079s and its final replay29.723s, within the original60-second startup
limit; ordinary permit rejection also meets the original5-second HTTP limit.
Final independent71 witness cases1.55s,39 protocol library cases82.53s,14
related contracts and Clippy0.32s pass. Four independent process cases175.174s
pass with no failures/errors/skips or candidate retries; all181 paths (177 source/
helper/fixture/workflow plus4 binaries) stayed unchanged. Final independent1000
replay34.708s fits the unchanged60s limit. No bounded P0/P1 or new P2 blocker
was found. Exact-source CI is pending. The two-cohort
helper exercises33/1000 entries; only one source has registered receipts and the
remaining entries are explicit unpublished allocation fixtures. Publication ACTIVE
in that helper is a C/P declaration, not backend financial publication acceptance.

Parent `00e49a4` Fast42848404456 passed4 jobs/1431 backend tests1001.70s,
full crypto unselected; it predates this source. Whole-phase
Fast+ALL, original3d32 six-case encrypted-store compatibility, actual movement/fees,
retirement/watch/rescue and final independent phase review remain required.

The initial process run retained two helper failures: plain activation of a Frozen
target correctly required a prepared generation. The helper was corrected without
changing the guard. The next1000-entry run measured an existing5-second HTTP timeout
on ordinary permit rejection because old verified vectors were fully revalidated
on each request. Exact complete proofs already established by committed Stage/
Materialize transitions now have direct lookups; indexed immutable alias checks
replace repeated Claim shape validation. Longer-prefix commitments still require
their own hash check, and journal replay verifies complete hashes before installing
these proofs. Approval/HTTP/startup deadlines are unchanged. The corrected root runtime passes; independent final reruns also pass.
Failed logs are retained.

The subsequent1000-entry run passed the permit deadline but exceeded60 seconds
on restart: unfinished new publication metadata repeatedly triggered hashes of an
equal-length old vector whose different whole fingerprint was already known.
Those known-different complete vectors are now skipped; longer-prefix proof
validation is retained. The new two-chunk metadata test confirms old data cannot
prove the unfinished new fingerprint. Final root runtime passes4 cases161.712s; independent4 cases175.174s also pass with181 unchanged paths.
