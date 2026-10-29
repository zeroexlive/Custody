# Protected seeded Solana signing — Phase 6G-C in progress

Draft PR #2 starts from merged main `587e0969a216102879d17cadb6ffeee8dfb8b6c6`.
It now contains a typed intent, an independent witness and a separate protected
signer entrypoint. These are isolated development implementations. Subsequent
[native issuance](PHASE6GC_NATIVE_ISSUANCE.md) actually publishes Claim-linked
wallets after independent witness grants, including local1000 acceptance.
Phase6G-C, finalized SPL issuance and financial integration remain unfinished.
No production/mainnet/customer-fund activation flag changes.

## Exact intent and original approvals

`protocol::solana_intent::Intent` commits the original claim/root, tenant/principal,
network, asset/index, separate signing generation, operation/attempt/session and
crypto execution IDs, financial source, base fee payer, optional rent payer,
action, recent blockhash/validity height, policy version, fee/rent limits and
wall-clock expiry. Canonical UUID/`p1:` strings establish format; backend registry
membership and financial reservation checks remain required during integration.

Rust independently decodes the standard Solana legacy message and checks every
instruction/account/permission against native TransferWithSeed or classic SPL
CreateAccountWithSeed + InitializeAccount3 / TransferChecked, with optional
idempotent ATA creation. Ed25519 private child derivation is never assumed.
Twelve public Solders/Python canonical fixtures and nine Rust contract tests cover
indices 0, 1 and 2**63-1, Unicode labels and negative wire/identity/policy inputs.
Their public package came from genuine isolated registry acceptance at 1d4737e;
the synthetic claim/intent values are encoding fixtures, not spending grants.

The actual protected signer reopens its own signed original root and all claim
aliases. It independently verifies all three original claim signatures, the exact
live custody proof and a separate exact-intent operator/policy proof. The latter
uses `Wallet-MPC/OPERATOR_SEEDED_SPEND_V1` plus NUL; custody uses
`Wallet-MPC/CUSTODY_SOLANA_SEEDED_INTENT_V1` plus NUL. Separate configured issuers,
current public-key pins and class roles prevent one proof from substituting for
the other. Distinct approval keys/roles are enforced; separate CA issuers are
deployment configuration used by the genuine fixtures, not an issuer-key
inequality check. Full human multi-approver governance remains Phase 7 work.

## Independent witness

`wallet-mpc-witness` requires an explicit isolated configuration and initialization.
It handles public permissions/results only, never an MPC private share or nonce.
Its lifecycle issuer is separate from custody and business-policy issuers. Root
registration requires all three independently pinned original root receipts.
Lifecycle-authorized claim registration then atomically preserves the exact
original Claim, root/index shared across native/token assets, owner/asset slot,
retry slot and globally unique reservation UUID. Its root counter is monotonic,
including the exhausted 2**63 sentinel. Every private permission requires that
exact registration, including requests for an existing execution. Refresh,
backup restore and execution closure never release ownership aliases. Issuance
must wait for this durable witness ACK; an authenticated fresh query can recover
the original public registration after response loss.
Each private-round permission binds the exact intent, pair, generation, party,
round, signer-origin random challenge, original signing package and a maximum
15-second lifetime. Both witness and signer verify time after acquiring their
locks; the signer checks again after awaited RPC work and durable consumption,
immediately before the synchronous upstream private operation.

The authority serializes permits, lifecycle CAS, freeze and closure through one
exclusive writer and fsynced signed hash-chain journal/head. Startup rejects
missing initialization, gaps, tail deletion, corruption and a second writer.
An immutable event left after an interrupted head publication is conservatively
replayed and retained. Uncertain writes poison the service until recovery.

The global logical-operation fence is tenant + operation type + operation ID,
independent of root, epoch, attempt, session and execution UUID. Business identity
also freezes the original root, claim reservation, owner, source, asset and action.
Neither a fresh UUID/blockhash nor a generation change silently reopens a payout.
Each `(execution, party, round)` is one-use even with a fresh challenge. An absent
execution can be closed only by writing a permanent global UUID tombstone.
The first R1 also permanently assigns `(genesis, exact message fingerprint)` to
that logical operation. Agave deduplicates an identical message even when another
FROST signature is produced; a different financial operation therefore requires a
different wire/blockhash. A zero-R2 closure does not release this alias to another
operation. Same-operation retries remain subject to the original NoSignature
rules. Ledger reconciliation must still bind the exact signed intent and chain
execution to one reserved financial operation.

Zero-R2 closure is atomic against every R2 permission and permanently fences the
old execution. Any R2 permission is conservatively potentially signed, including
a lost response or an apparently inactive party. The witness verifies each
original signed R2 share with upstream FROST against the first immutable signing
package. Only both valid original public shares permit aggregation/verification
and transition to `SignedPending`. This drains cryptography; it never establishes
financial settlement or permits another attempt. Financial reconciliation is
still pending integration. No timeout, old backup or missing result proves
non-inclusion or absence of a signature.

The subsequent [terminal cancellation extension](PHASE6GC_NO_RELEASE.md) adds a
separate Frozen-only closure requiring durable original-key NoRelease certificates
from every actual R2 grantee, with no contradictory R2 result. The zero-R2 rule
above is unchanged; timeout, absent history or a lost key never supplies proof.

Freeze stops new private-round permissions. Prepare/activate contracts require a
genuine changed public package with the same group key and all three matching
signed generation-ready records. Original Root/DKG identity remains immutable.
The state-machine tests exercise upstream three-participant refresh and roster
replacement. Subsequent distributed ordinary refresh and encrypted generation
loading now have genuine-process Gen1 all-pair and Gen2/COLD/restart evidence.
Ordinary refresh requires the exact frozen current roster; explicit replacement
provenance and share repair remain unfinished. See [refresh scope and limits](PHASE6GC_SOLANA_REFRESH.md).

Node detached permission keys use explicit configured pins plus the exact active
root roster. Certificate expiry alone does not revoke such a detached key when
relayed through a valid courier; lifecycle freeze/roster replacement is required.
Archival receipt pins never become current business/custody approval authority.

## Protected runtime and class boundaries

`wallet-mpc-protected-signer` requires `MPC_PROTECTED_PROFILE`; it has no insecure
mode or generic signing router. The legacy entrypoint refuses startup if that
variable is present. Protected profiles, credentials and a separate public
execution journal live outside private-share backups. Request reservation and
witness-permit consumption are durable before private work. Nonces remain only in
the owning process; restart never regenerates them. Original signed public result
recovery is read-only and may complete a previously unresolved witness result.

Optional DKG `custody_class` is immutable birth metadata for protected SOLANA
keysets. Historical None serialization is unchanged and can only describe HOT
roots; WARM/COLD require their original matching class. Generic signing rejects
all classified requests. Separate deployment/class credentials and exact-intent
policy pins enforce class boundaries. The existing CGGMP and TON paths retain
their original scope; this does not enable their WARM/COLD financial workflows.

HOT/WARM use the actual Rust witness client. It verifies TLS chain/hostname/role
and the active witness public-key pin before sending any HTTP body, including
public signature shares. Signed witness responses are verified independently.
COLD creates no witness network client: an authenticated courier explicitly
relays each signer-origin signed challenge, exact witness reply and public result.
This tested local relay plus isolated RPC is a custody-class foundation, not
physical airgap or production cold-storage acceptance.

Before each private round, the signer independently checks a pinned loopback
Solana endpoint: configured artifact-derived genesis, live finalized block height
and blockhash validity, exact fee quote, System base/source shape and funds,
classic mint/account owner/data/decimals/authority/state, token funds and actual
rent/ATA requirements. Source amount and base fee/rent funds remain distinct.
All calls are bounded to five seconds; no production network endpoint is enabled.

The share-restore claim assumes these external execution/witness journals,
credentials, mandatory profile and protected binary remain authoritative.
Coherent rollback or substitution of that entire independent deployment is
outside this development claim. Journal corruption fails closed; complete lost
history is never reconstructed as an unused operation.

Current correctness scaffolding clones the complete public snapshot under a
global mutex and replays the complete journal at startup. This has not established
large-customer-count throughput. It must be measured and addressed as needed
during the required actual1000-issued-wallet acceptance, before scalability claims.
Closed zero-R2 nonces currently occupy local active capacity until process restart;
this is P2 development availability debt, not permission to reopen the old execution.
The limit applies to new R1 work; R2 must remain able to drain a full queue.

## Evidence and outstanding acceptance

Local evidence before final-head CI:

- Original public contract: nine Rust tests, twelve reproducible SDK/canonical goldens.
- Witness core: twelve state/admission tests pass, including genuine upstream DKG,
  per-share verification/aggregation, refresh-package agreement and three queued
  expiry regressions. These are state tests with explicitly synthetic detached
  receipts; they are not distributed refresh acceptance.
- Independent reviewer reran all twelve witness cases (zero ignored) and
  inspected the durable/private-work/class boundaries without finding a
  demonstrated P0/P1 in this bounded scope. Newly added cases still require final review.
- Two real TLS witness authorization/restart/corruption/concurrency cases passed
  5.29s with actual three-party original DKG/root/claim signatures.
- Actual Rust TLS canary passed 0.31s: the pinned server receives the canary; a
  same-CA/same-role server with another key receives no HTTP request.
- Protected native all-pair finalized transfers and COLD manual courier passed
  131.35s; source amount and base fee debits were independently checked.
- Pre-enrollment private-backup restore, lost R1 nonces and safe closed retry
  passed 49.94s. Actual withheld R2 result/restart, protected journal corruption,
  freeze and public recovery/finalized broadcast passed 50.62s.
- Delayed real RPC responses cumulatively crossed a permit lifetime while each
  stayed below the unchanged five-second timeout; no private result was emitted,
  restart did not reopen it, and the R2 outcome remained reserved (53.74s).
- Genuine atomic classic SPL creation/initialization and all-pair protected token
  transfers passed114.24s, with exact source/base rent and fee checks. Separate
  WARM signing with authentic unrelated HOT custody/policy/lifecycle rejection
  passed44.44s. These preceded the final claim-registration integration rerun.
- Three genuine restored pre-claim stores produced conflicting authentic receipts
  for a registered, never-spent address; witness registration and private
  permission rejected them. A genuine second root also could not reuse the global
  reservation UUID. Registration response-loss/restart recovery passed3.60s.
- Expired CURRENT detached node pin via valid courier succeeds; a configured but
  nonactive key fails (11.97s). Live custody/operator certificate checks are retained.
- After claim registration was enforced, the twelve HTTP cases above completed:
  six before an environment restart, five resumed in293.11s, and the separately
  collected detached-pin case in11.97s. Strengthened native replay checks also
  reject an actual newly finalized blockhash/wire with a fresh execution UUID
  for the same completed logical operation (80.64s).
- A saturated32-execution queue drained a genuine R2 signature, finalized a
  transaction and admitted another R1 without restarting (59.18s). After the
  permanent wire fence was added, the test used distinct exact amounts/wires for
  all concurrent operations and passed with the extended authorization case
  in71.48s. The signature/expiry/replay fences remain in force.

An earlier delay-test attempt hit the individual RPC timeout and did not prove
expiry; its corrected cumulative-delay case supplies the evidence above. The
TLS probe was initially invoked before its binary finished building and was then
rerun after the dependency was available. These failed attempts are not counted
as acceptance. New exact-final-SHA Fast/full cryptographic CI remains mandatory.
An OpenSSL peer-close BrokenPipe in the wrong-key canary branch was diagnosed;
the test retains every received byte and still requires the exact Rust pin error
and zero HTTP bytes. An environment restart interrupted the combined run after
six completed cases; the remaining five are rerun separately. An earlier missing
validator-path environment variable was corrected without changing source gates.

Remaining 6G-C: final distributed-refresh fault acceptance, explicit replacement
provenance and share repair/recovery;
rotation, compromise response, obligation drain/retirement and late-deposit rescue;
backend issued-wallet identity and finalized SPL initialization records; financial
source/base fee/rent accounting with deposit/sweep/withdrawal integration;
1000 genuinely issued Solana wallets; final independent review and required
exact-head full gates. No Phase 7 or production acceptance is implied.
