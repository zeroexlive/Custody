# Phase 6G-C terminal R2 cancellation — unmerged development

An issued round-two permission normally remains potentially signed, even after
expiry, restart, response loss or private-share loss. This extension adds one
narrow alternative: every actual R2 grantee permanently cancels its own original
request before any durable R2 result exists. No timeout or missing-history
inference is introduced. Phase6G-C remains incomplete and PR #2 remains Draft.

## Node terminal cancellation

`/internal/v1/solana/protected/cancel` accepts the original strict R2 control plus
an independently pinned lifecycle-signed `Cancellation`. The approval binds the
witness anchor, original root, execution, binding and original signed request
fingerprints, with at most300 seconds of life. The original signed R2 request
must already exist in the intact protected journal; absence is not evidence.

Cancellation and signing share the same node mutex. Any durable R2 result,
including an actual partial withheld from the coordinator or witness, prevents
cancellation. Otherwise a signed terminal `NoRelease` event is fsynced before
its certificate is returned and the remaining local nonce is discarded.
All Request/Consume/Result transitions and private entrypoints reject the old
execution after cancellation. Cached original R2 recovery also rejects it.
An original R1 public report may still be read; that cannot create a partial.

Write uncertainty poisons the journal and prevents private work. Restart replays
an already committed terminal event and recovers the same immutable certificate.
No lost cancellation response permits renewed private work. A later-issued,
otherwise live witness permit for that original request is also locally terminal.

Local cancellation deliberately does not obtain a fresh witness query or require
a Frozen root: it grants no private work and only removes authority. Its separate
lifecycle approval and original request are mandatory. Final witness closure
requires Frozen state and current lifecycle authority. A stale local lifecycle
configuration can cause an availability problem but cannot close the operation
at the current witness; explicit profile/provenance migration remains required.

## Independent witness closure

The new lifecycle command `CloseUnreleased` requires an original Open execution
and Frozen root. Under the same durable mutex/CAS as grants and public results,
the witness derives the complete, nonempty R2-grantee set from its own permanent
grant history. The caller cannot choose a smaller set. Exactly one valid terminal
certificate from each actual grantee is required. Every certificate must use
that execution's original node pin, original signed request, original binding,
anchor, generation and first immutable signing package. Node and lifecycle
signatures are verified separately. Missing/duplicate/relabelled/foreign-key
proofs and any contradictory stored R2 result are rejected.

Only then does the witness durably mark `NoSignature`. Late original R2 reports
and new permissions cannot revive the closed execution. Existing operation,
attempt, claim, owner and wire aliases remain permanent. The old zero-R2-only
`CloseNoSignature` rule is unchanged; a bare request cannot close any R2 grant.
After separate genuine refresh/activation, a new explicitly authorized attempt
may retain the same business identity. This is not chain settlement or a command
to release financial reservations.

Under the existing at-most-one-Byzantine-node assumption, if the sole R2 grantee
is honest, its truthful terminal certificate excludes its share. If that sole
grantee is Byzantine, the other participant is honest and had no R2 grant.
If both participants were granted, both certificates are required, so an honest
grantee permanently withholds at least one necessary partial. This relies on the
existing protected-runtime rule that a partial never leaves an honest node before
its durable Result event. It does not protect a compromised old threshold.

Coherent rollback of the entire independent protected journal to a pre-Result
state remains outside this claim. A fresh witness query cannot distinguish that
rollback from a real crash before Result. Missing/corrupt history fails closed;
replacement identities cannot attest on behalf of an original execution key.
Loss of required original evidence or any durable partial leaves the existing
unknown outcome reserved and blocks drain until authoritative reconciliation.

## Evidence and remaining work

The initial four genuine-process cases passed165.76s: one/two actual R2 grantees,
lost cancellation response/restart, actual subsequent all-three refresh and
same-business finalized retry, apply-versus-cancel exclusivity, and refusal to
cancel a genuine durable partial withheld from the witness. A separate state
test uses actual upstream commitments/partial verification with explicitly
synthetic detached receipts to check exact grantee sets and late-result fencing.
Expanded positives passed97.98s, independently96.04s: valid-but-expired lifecycle
approval and missing original-request denial; terminal local cancellation before
a later witness grant; actual durable Cancel-event/head-publication failure and
recovery of the same certificate; valid wrong-node/request rejection; and a fresh
still-live request after closure. The independent apply/cancel race passed30.40s;
all13 witness units passed independently with zero ignored. COLD courier/manual
refresh and finalized retry additionally passed51.64s. Independent review found
no demonstrated P0/P1 in this bounded component under the explicit assumptions.
These results do not establish exact-final-head or whole-phase acceptance.

No key or cryptographic algorithm was replaced; no financial journal or reserve
was modified. R1-only nonce cleanup still requires restart or a future separately
verified disposal action. Replacement/provenance, supported share repair, root
rotation/drain/retirement, issued wallets and finalized SPL initialization,
single-ledger deposit/sweep/withdrawal integration and actual1000-wallet issuance
remain unfinished. Final Fast/ALL and original-store compatibility gates remain
mandatory, along with independent review and no blocking P0/P1.

## Verified terminal-cancellation checkpoint

Commit `fe67ee9a59aa16c0902d188ae8e32d7668d4fdbc` independently passed
[Fast40807326269](https://github.com/zeroexlive/Custody/actions/runs/40807326269)
and [selected Solana40807346419](https://github.com/zeroexlive/Custody/actions/runs/40807346419).
Selected artifact12870505005 contains32 unique selected/called scenarios,
zero scenario skips,32 JUnit passes in1379.875s and ten explicitly public files.
All five cancellation scenarios, including manual COLD, actually executed.
Independent verification checked exact SHA, public inventory/JUnit equality,
job conclusions and private-marker absence. This does not cover later native
issuance source or satisfy final ALL/original-store/whole-phase acceptance.
