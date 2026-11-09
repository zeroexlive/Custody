# Public original-wire finality — unmerged development

This adds an independently observed terminal-chain fact alongside an existing
witness SignedPending execution. It grants no private round, transfer, financial
publication, ledger settlement, hold release, retirement or rescue. Phase6G-C
remains incomplete. A signature alone and a local settlement record cannot replace
actual finalized chain evidence.

## Source authority and public handoff

The separately pinned Lifecycle authority signs a fresh FinalityPlan binding the
original Root/execution/binding fingerprint/signature and the source's CURRENT
observing generation, three-party roster and exact Frozen revision. All three
current source identities must observe the old wire. No other Root or arbitrary
pinned observer cohort can substitute. Existing repair and same-key refresh may
restore current source identities before observation: those existing operations
reject Open uncertainty but allow an already complete SignedPending signature.
Pending replacement, refresh, preparation or global profile-cohort migration blocks
witness acceptance. Old signing and current observing generations remain distinct.

Protected nodes expose public `finality/query`, `observe`, `complete`, `recover`
under `/internal/v1/solana/`. Capability requires an explicitly installed Life pin;
HOT/WARM use the coordinator transport role and COLD requires its explicit courier.
The backend receives no Life/Policy private key. Existing private signing and
original/current Claim authorization paths retain their original checks.

Query persists the node's own nonce-bound15-second lease. Observe authenticates
that exact signed W response and the original signed binding, queries the node's
own pinned RPC, then durably records its public observation and a different own
post-observation query. Complete authenticates the fresh second W response and
unchanged current Frozen context before signing the Ready report. The ORIGINAL
lease still expires after15seconds; RPC or courier delays cannot renew it. Exact
recovery returns the original signed report without another private round.

Public observation checks signed original enrollment or replacement provenance;
it does not require loading an old missing DKG share for the public operation.
Ordinary daemon startup still verifies its complete original DKG store; this
checkpoint does not relax that integrity gate. Original DKG/private/Claim
validation is unchanged. The original Root/group signature and accepted public
signing package are verified independently. Archive content is checked at its own
original admission interval solely for structural/wire consistency, never as a
fresh private authorization. Actual W acceptance of the exact binding/signature
and all live P256 authorities remains mandatory; old intent/CA expiry cannot by
itself invalidate observation of an already signed wire.

## RPC and witness boundary

The unchanged loopback-only, genesis-pinned RPC boundary gains only two read
methods: getSignatureStatuses/searchTransactionHistory and finalized getTransaction
with base64 encoding. Genesis must match before and after observation. Missing,
null, non-finalized, wrong genesis/slot/error/signature/wire/fee or malformed metadata
remains unresolved. Canonical decoded bytes must be the original single-signature
legacy transaction, including its verified FROST/Ed25519 signature and exact message.
Balance arrays must match its original account table and contain bounded unsigned
integers. Native principal/payer fee deltas must match the exact signed instruction;
a failed transaction rolls back principal/rent except its original payer fee.

This is the existing trusted-RPC model, not SPV or a consensus proof. The normalized
metadata fingerprint records observed chain metadata. It does not replace the
existing complete native/SPL financial-effect validators or ledger settlement.
Different observers' RPC context slots are retained separately; they need not be
one bank. Requests and Ready reports are bounded so three reports fit the unchanged
1MiB witness event ceiling.

Life submits `AcknowledgeFinality` with all three reports. Under its journal mutex,
W independently verifies the Life plan, both node-signed queries, both pinned W
responses and each outer current-party Ready signature. It rechecks source revision,
current generation/roster/profile and all pending-maintenance fences, then matches
the exact original SignedPending execution, signature, binding and public package.
No Open/partial/unsigned execution can become a terminal wire fact by presenting an
arbitrary valid group signature or RPC transaction ID.

An immutable public receipt is included as optional signed `execution.finality`;
None remains absent from old signed JSON. Original status stays SignedPending and
its original signature, session, wire, attempt and logical-operation ownership stay
unchanged. Even a finalized failure is never NoSignature. Acknowledgement cannot
replenish budgets, release DB holds or open another signed logical attempt. Only
this authenticated fact removes a SignedPending blocker from manifest Begin and
known incoming-work checks. Ordinary incoming private fences remain unchanged.

New writes use forward-only rules5, preserving exact signed rules0–4 replay. A
head-publication failure poisons the live writer; verified restart replays its
immutable fact rather than discarding an unacknowledged event. Old history and
original encrypted key material are retained.

## Development validation and limitations

Independent final strict-source validation passes39 protocol cases99.68s,
55 witness cases1.30s, workspace/all-targets Clippy0.35s and9 genuine cases356.041s,
zero failures/errors/skips. All163 reviewed source/fixture/manifest/workflow/helper
files and4 runtime binaries stayed unchanged. Review found no concrete bounded
P0/P1. See [evidence](evidence/phase6gc-public-finality-local.json). The serial-ACK
availability limitation below remains visible.

Earlier root actual HOT/COLD cases passed2/124.57s: native and SPL initialization
were genuinely MPC-signed/finalized; source HOT underwent real upstream same-key
Gen1 before all3 current nodes observed its original expired Gen0 wires. COLD used
explicit courier handoff. Node restart, forged embedded W proof under an actual
observer signature, insufficient quorum and witness head-write failure/recovery
were exercised. Original signatures/statuses and encrypted DKG ciphertexts persisted;
public observation added no private Request/Consume/Result records.

A separate genuine failed-wire case passed77.74s. Two real legacy-control wires
competed for a source; the captured first wire actually finalized with failure.
All3 observers verified the rollback/fee. Its signed ownership still rejected a
new attempt after genuine refresh and operator test refunding. This is not a DB
hold or ledger-settlement test.

Those earlier runtime results predate final stricter metadata/envelope checks;
the independent9-case strict-source run above supersedes them. It additionally
made all3 original DKG share files unavailable during public native observation
after Gen1, restored identical ciphertexts, and tested SPL observation/node restart.
Ordinary daemon startup integrity remains unchanged. One earlier harness
failure read the outer signed journal object instead of `value.change`; the failed
73.60s result is retained and only that test helper was corrected. Early static
review also caught randomized account ordering in a synthetic public unit fixture;
it now canonically reorders the key table AND all instruction indices. No production
canonical verifier was relaxed. The synthetic public fixture and dealer-only unit
tests do not claim genuine DKG, P256 authority, RPC or financial acceptance.

Revision-bound acknowledgements are deliberately serial: an ACK advances the Root
revision, invalidating other observations collected against its old revision. The
1000-entry manifest benchmark does not establish1000 finality ACK throughput.
Missing chain history, unavailable current source quorum, an unfinalized wire or
Open/partial uncertainty remains held. No local timeout or absent RPC result can
create NoSignature or an expiry/nonexecution fact. Migration maintenance/recovery
must retain these constraints before any private movement is added.

Parent8a9c796 [Fast42651565984](https://github.com/zeroexlive/Custody/actions/runs/42651565984)
passes4 executed jobs/1364 backend cases774.17s. Full-crypto jobs were unselected,
and it predates this finality implementation. Whole-phase Fast/ALL/fixed original
3d32 six-case encrypted-store compatibility and independent final review remain
required before conditional merge. Actual fresh-DKG movement, retirement, continued
watching and late-address rescue remain unfinished. No production/mainnet/customer
funds or Phase7 activation follows.
