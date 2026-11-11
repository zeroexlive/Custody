# Backend rotation source proofs — unmerged development

The backend now records its own public witness query over an original sealed
inventory entry. This is a prerequisite for migration of unpublished sources.
It does not publish the Claim, change financial membership, allocate a private
execution, post a ledger journal or establish retirement readiness.

Migration0051 adds only `MpcSolanaRotationSourceQuery`. Every query commits its
original entry, rotation UUID, random nonce and15-second deadline before the
operator transports it. The original inventory, original Claim status/evidence,
issuer and wallet records remain unchanged. New queries use the existing
default-disabled inventory feature; accepting an already requested response and
reading accepted historical proofs remain possible when that entry switch is off.

Acceptance verifies the independently installed W signature, exact original
query/Root, sealed rotation ID and full inventory fingerprint/high-water, original
source generation/roster/package, contiguous registered prefix, exact allocation
aliases and original publication grant. Unregistered-at-capture sources need the
exact signed rotation/command/Claim/source-fingerprint/evidence-fingerprint
provenance. Their new original/current three-party receipts must match the actual
source roster or accepted Life Prepare. Current receipt signatures and embedded
Prepare signatures are verified independently; W-signed JSON alone is insufficient.

An originally registered source retains its exact positive Evidence fingerprint.
Its receipt authority remains archival across later refreshes and replacements;
requiring those immutable old signatures to become current signatures would make
valid historical Claims unusable. Fresh W context is checked separately. Neither
that old receipt nor this public archive is a future private movement permission.
The movement boundary must independently check current source control, exact
source-cohort receipt pins, current target and plan, possible fees and all holds.

PostgreSQL guards preserve the query subject/deadline and permit only
PENDING→VERIFIED with a bounded structurally matching reply. They reject deletion,
replacement and pre-verified birth; a deferred trigger checks expiry again at
commit. An audit failure rolls back acceptance, retaining the original pending
nonce. A response that was accepted before expiry can be redelivered after expiry;
an unresolved expired response requires a new nonce and retains its old row.
Populated rollback cannot remove these guards. SQL does not verify P256 signatures
or canonical JSON fingerprints; every application use re-verifies them.

Privileged operator handoff:

```text
python manage.py solana_rotation_source query --snapshot-id UUID --tenant-id UUID \
  --operator-ref OPERATOR --rotation-id UUID --index INTEGER
python manage.py solana_rotation_source accept --snapshot-id UUID --tenant-id UUID \
  --operator-ref OPERATOR --challenge HEX --evidence PUBLIC_REPLY.json
python manage.py solana_rotation_source archive --snapshot-id UUID --tenant-id UUID \
  --operator-ref OPERATOR --challenge HEX
```

The operator supplies only public signed responses. The backend stores no Life or
Policy private key and exposes no automatic command/private route. The archive
command returns historical data, including after W abandonment/restart. A new
acceptance after abandonment fails; an archive read grants no liveness or role
absence guarantee to a later transaction. A movement consumer must lock and
recheck its own current context.

Root190 PostgreSQL/P256 contracts pass221.04s:63 new source contracts,
32 inventory,55 Claim-registration and40 receipt-pin cases. The earlier53-case
run57.21s predates final guard strengthening. The initial migration syntax
error, receipt fixture lacking required BasicConstraints, and final concurrency
fixture missing its application-name argument were corrected without weakening
production checks. The intermediate run is47PASS/1FAIL67.30s.

The genuine Gen1/33-allocation case passes23.291s. Its Gen0/1000 companion reaches
post-seal audit/restart recovery, then fails the helper's original10-second
readiness bound191.091s; the combined run is1PASS/1FAIL214.87s. The final helper
uses the existing scale-test60-second startup bound and obtains one new public
own-nonce response after restart, retaining the original pending nonce and all
entry/rotation/registration IDs. No authorization TTL is extended. Independent190-case regression passes360.446s XML/360.46s wall, zero failures,
errors or skips. Final independent runtime validation remains pending on that
helper. Its first independent pair was interrupted after Gen1 passed and before
1000-case completion; no combined pass is claimed. All187 source/runtime hashes
remained unchanged after the interruption.

Earlier actual failures are retained:22.54s and14.14s rejected an empty inventory
fingerprint because the test callback passed a stale collecting object; the helper
now passes the completed sealed object. Another17.94s failure rejected current
receipts because the test omitted the independently installed backend Life public
certificate; the fixture now supplies the correct pin. No production check changed
for these failures. A prior interrupted run has no completion report and is not
accepted evidence. [Machine-readable qualifications](evidence/phase6gc-backend-rotation-sources-local.json).

The preceding witness checkpoint `fff0acc` passed exact
[Fast42917404514](https://github.com/zeroexlive/Custody/actions/runs/42917404514):
four executed jobs,1431 backend tests590.12s, full crypto unselected. A duplicate
manual run42917403637 was cancelled; it is not acceptance evidence. That Fast
result predates0051. Actual movement/fees/retirement/rescue and whole-phase final
Fast+ALL/original3d32 compatibility/review/merge remain unfinished.
