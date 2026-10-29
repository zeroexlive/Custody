# Phase 6G-C distributed same-key FROST refresh — development

This unmerged part of Draft PR #2 refreshes three independently held Ed25519
shares with upstream FROST 3.0.0. It preserves the original group public key,
Root/DKG receipts, claim ownership, seeded addresses and encrypted original DKG
files. It does not rotate the custody root or revoke a compromised old threshold.
Phase 6G-C remains incomplete; no production or customer-fund activation follows.

## Authority and private work

Ordinary refresh requires a separately pinned lifecycle certificate in the
protected profile. A signed `RefreshPlan` binds the original root, witness anchor,
current generation and package, exact current three-party identity roster,
logical session, new ceremony UUID, next epoch and expiry (at most300 seconds).
Each participant issues its own random query and verifies the signed witness
reply within15 seconds. The reply must identify the same current lifecycle key
and Frozen root/generation/package/roster. COLD has no automatic witness client;
its original query and response are explicitly relayed through the courier.

Before generating any upstream refresh polynomial, each node durably reserves
the original signed plan and frozen query response in its independent public
execution journal, outside private-share backups. Ceremony and session UUIDs
cannot be reused. Restart never repeats an interrupted private ceremony; an
operator must explicitly authorize a different ceremony. An abort only discards
volatile state and is allowed after the original plan expires. Expired pending
queries are pruned before enforcing the32-query limit. At most eight active
private refresh ceremonies are retained; abandoning them still requires abort
or restart, rather than an automatic epoch change.

All three nodes run upstream `refresh_dkg_part1`, `refresh_dkg_part2` and
`refresh_dkg_shares`. Canonical public round-one packages establish a complete
three-party view before private round-two packages are accepted. Private packets
travel directly between signer processes, with exact protocol/session/ceremony/
root-keyset/party/round binding and replay guards. Both incoming authenticated
peer keys and outgoing TLS peer keys must match the lifecycle plan. Outgoing
pin verification occurs before any HTTP request body is sent. The coordinator
receives public status and signed readiness records only.

## Persistence, activation and recovery

Each new private share is stored as an immutable encrypted generation file under
`solana-generations/`. Existing AEAD wrapping binds original root identity,
epoch, ceremony and owning party. Loading verifies original group key, party,
threshold2, public-package hash and private/public verification-share agreement.
Original DKG files are never overwritten. Plaintext serialized private buffers
use the existing zeroizing storage interfaces.

The independent node journal records a signed `GenerationReady` only after the
encrypted file is durable. A crash between these operations may recover Ready
from the same completed encrypted artifact through the public report/recovery
action, appending missing Ready history without repeating private work. If Ready
exists but its exact
private artifact is missing, corrupt or belongs to another party, report/signing
fail closed. There is no original-share fallback for a later generation.

Witness Prepare requires all three matching signed readiness records, a changed
public package with the same group key, the exact next epoch and a never-used
ceremony UUID. Original DKG/session UUIDs cannot be reused as new ceremonies.
Prepare/Activate cannot erase or bypass unresolved private executions. Existing
potentially signed R2 outcomes remain blockers; timeout, missing shares or a
declared lost node cannot prove that no signature exists. Original public result
recovery remains available. `SignedPending` drains cryptography only and never
establishes financial settlement or releases a reservation.

## Evidence and limits

Local genuine-process acceptance includes Gen1 all-pair finalized transfers and
restart (89.04s), COLD manual-query refresh/restart, and interrupted-ceremony,
missing-Gen1 fail-closed, explicit restoration and Gen2 finalized signing (the
latter two cases passed together in146.02s). Original DKG ciphertext hashes,
root identity and claim identity were checked unchanged. The expanded interrupted
case then passed61.81s and independently62.59s: a real private R2 sent zero HTTP
bytes to a same-CA/same-role wrong-key server; missing/corrupt/transplanted Gen1
files were rejected; an occupied immutable Ready-event path caused a real write
failure after encrypted Gen2 persistence. Restart recovered exactly one Ready
event from the unchanged ciphertext and finalized Gen2 signing. The independent
review reran12 witness unit cases with zero ignored and found no demonstrated
P0/P1 in this bounded ordinary-refresh source. Clippy/all-target checks and
protocol/transport/witness tests passed locally. Complete exact-final-head gates
remain mandatory.

Two environment interruptions ended earlier HOT runs without a result. An initial
Ready fault test used parent-directory permissions, which the existing atomic
writer correctly restores; that attempt failed and proved no publication fault.
The corrected occupied-path case above supplies the evidence. No production
storage semantics or timeouts were weakened.

The earlier `5abbaaa` spending checkpoint independently passed
[Fast40774829095](https://github.com/zeroexlive/Custody/actions/runs/40774829095)
and [selected Solana40774940853](https://github.com/zeroexlive/Custody/actions/runs/40774940853),
with24 actual selected/called Solana cases and zero scenario skips. That selected
run did not execute the ALL gate or original-store compatibility suite. Those
results do not validate this later refresh source.

Enabling `lifecycle_certificate` changes the immutable protected-profile
fingerprint. An already initialized profile without it cannot silently enable
refresh or rotate its TLS identity. Explicit profile/provenance migration and
replacement-node repair remain unfinished. Ordinary refresh deliberately requires
the current roster; it is not an implicit replacement authorization.

Old encrypted generations are retained for auditable recovery/compatibility.
Two old shares can still represent the old threshold. Runtime witness generation
fences assume the independent profiles, credentials, public journals and protected
binary remain authoritative; coherent rollback/substitution of that entire
authority is outside the share-restore claim. A compromised threshold requires
fresh-key rotation and migration, not merely same-key refresh.

Remaining phase work includes explicit new-identity provenance, supported masked
single-share repair followed by all-three refresh, root rotation/compromise and
drain/retirement, old-address late-deposit rescue, issued-wallet and finalized SPL
initialization records, single-ledger deposit/sweep/withdrawal integration,
1000 actually issued wallets, independent final review and exact-final-SHA gates.

## Verified ordinary-refresh checkpoint

Commit `cc55cc606c5665fe311fe600f2caa05cfae13d1b` independently passed
[Fast40805529721](https://github.com/zeroexlive/Custody/actions/runs/40805529721)
and [selected Solana40805525701](https://github.com/zeroexlive/Custody/actions/runs/40805525701).
The selected artifact12868533578 contains27 unique selected/called scenarios,
zero scenario skips,27 JUnit passes in1190.729s and ten explicitly public files.
Independent remote verification checked the exact head, job conclusions,
inventory/JUnit equality and absence of private artifact markers. Other chain
jobs were intentionally unselected. These are bounded checkpoint results;
ALL and original-store compatibility still require the final whole-phase SHA.
