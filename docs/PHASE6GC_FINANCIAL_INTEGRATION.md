# Phase6G-C protected financial integration — in progress

The first implementation boundary adds a versioned financial identity and an
explicit irreversible witness Root mode. A subsequent typed HOT coordinator has
bounded genuine fault/recovery evidence. Native membership and explicit principal
roles have separate bounded evidence below. Protected PostgreSQL operation/session
bindings and existing ledger integration are still unfinished.
No financial wallet activation or production/customer-fund approval follows from
these cryptographic development cases.

## Read-only authority query

The existing authenticated courier channel may carry a `WITNESS_QUERY_V1` signed
by the already pinned Custody key for the queried Root's class. The witness checks
that exact key and domain. No TLS role, CA trust store, lifecycle issuer or private
permit authority is added. Wrong keys/domains fail; a Custody signature cannot
issue a private permit or lifecycle command. The query changes no journal state.
Backend use still requires its own durable random challenge, one-use consumption
and deadline checked after response verification and database locks. The response
is not tenant login authority or a statement about live ledger contents.

## Financial identity and irreversible activation

Optional `Intent.financial` binds version, immutable reservation UUID, tenant,
reservation owner, source owner, explicit source role, business operation/ID,
business approval UUID and asset. Reservation owner is distinct from the tenant's
treasury-source owner for a withdrawal. Source owner must equal the original
Claim owner; non-withdrawal operations cannot silently substitute another owner.
Every supplied financial object is validated even on a mode-off Root. Its value
enters the stable business digest; crypto session/execution, blockhash and epoch
changes do not change the business identity. Per-wire signatures may change while
the original business approval UUID stays fixed. An absent financial object
preserves the EXACT old canonical object and digest, without a new null key.

`EnableFinancialMode` requires current original Custody AND independent Policy
approvals plus the separate Lifecycle command. Current CA/role validators and
key pins authenticate the approvals. The exact Active Root/generation/roster must
have no Claims, issuance progression, private signing history, prepared/pending
maintenance or partial cohort migration. Existing published/manual Roots are not
automatically adopted: this clean-Root policy intentionally requires a fresh Root
for subsequent financial activation. Completed maintenance is compatible; it does
not imply a private signing history. The activation UUID remains globally reserved.

There is no disable/re-enable command. Original enable command, approvals and
Root-mode identity survive witness replay; mode persists across refresh/activation
and is included in signed query and private-permission metadata. Every new R1/R2
on a mode-enabled Root requires the financial object, including existing-execution
requests. One financial reservation UUID cannot back different business operations.
Signer private apply validates a financial-mode permission's typed identity before
new private work. Cached original public outcomes remain read-only recovery.

Mode and bindings do not certify an actual ledger reserve, a principal's registry
membership, treasury designation, finality or settlement. Those must be proved by
the dedicated backend contract, database invariants and actual chain evidence.
Synthetic reservation references in the present crypto acceptance are explicitly
labelled; no PostgreSQL financial activation is executed in those cases.

## Typed protected coordinator (unmerged development)

`MPC_SOLANA_PROTECTED_COORDINATOR_PROFILE` explicitly enables separate typed routes;
without it they are absent. Authenticated Custody TLS, a loopback listener and all
three loopback destinations are required. Existing generic sessions/schema remain
separate. The coordinator has no Lifecycle/Policy key, private MPC storage,
broadcast capability or automatic Unknown retry. HOT only; COLD stays manual.

An immutable public record claims the exact business reservation, operation,
attempt, crypto session/execution, original package/roster and supplied W proof
before dispatch. Operation/reservation aliases preserve the stable business digest;
one attempt cannot own multiple crypto sessions. This does not authorize a fresh
attempt: backend authoritative NoSignature reconciliation and retained financial
hold remain required, and W independently enforces prior execution closure.

`CREATED` means durable intent. The supplied signed W view has no timestamp, so it
does not establish freshness or independent Custody/Policy verification here.
Backend must commit/consume its own random query and deadline; protected nodes/W
independently verify exact approvals and live permission before each private round.
Even an old signed Active view cannot bypass a now-Frozen W private gate.

CAS plus an owned worker prevents concurrent execute or HTTP disconnection from
starting another private round. Original node-signed R1 reports and the exact first
R2 package are fsynced before any R2 dispatch. Original P256 identity, canonical
share/package and upstream `verify_signature_share` are verified before accepting
each R2. Aggregation and final signature verification use upstream FROST; no custom
cryptography or key reconstruction. This is not a separate Ed25519 implementation.

Write uncertainty poisons the process and blocks later private enqueue. Restart
verifies every stored report/package/result and converts InProgress to
ReconciliationRequired. Unknown recovery calls original-node public `recover`
only; an incomplete result stays Unknown with its original IDs. Completed/GET
recovery uses the captured original generation and remains available after Freeze.
History/pins must be retained; coherent all-authority rollback is not solved here.

`COMPLETED` verifies the original aggregate only. A node may have durably produced
R2 before W received its public report. In that case public coordinator recovery
can complete while W remains Open. Existing courier redelivery of authentic
reports, a new backend-owned query, matching W execution and immutable DB message
and signature ownership are still mandatory before financial consumption. Neither
Completed nor W SignedPending means settlement, finality or reserve release.

Final local source passed9 genuine scenarios362.45s, zero failures/skips: all three
pairs with finalized transfers, exact completed restart recovery, conflicting
operation/attempt rejection, Frozen denial with stale supplied view, last/first
R2 and R1 response loss, actual R2 before W record, HTTP disconnect/concurrent
execute, mid-round process restart, actual public write failure, and a canonical
zero invalid share re-signed by the fixture's genuine original node identity.
Invalid data is rejected before persistence; later public recovery returns the
authentic result. Missing/incomplete outcomes never trigger new private work.
Reports use synthetic financial references and no ledger entries. All-target
Clippy/build passed. Independent all-pair, invalid-share and before-W-record reruns
passed3 cases157.614s with unchanged binaries; bounded source/runtime review found
no demonstrated P0/P1. Exact-head CI and whole-phase gates remain pending.
See [public evidence](evidence/phase6gc-protected-coordinator-local.json).

## Backend clean-Root mode import (unmerged development)

Migration0036 adds a separate immutable Root-mode import record. Before querying
or enabling W mode, the standalone operator service commits expected activation
and Lifecycle-command UUIDs plus exact W anchor/key and a random15s query lease.
The backend has no Lifecycle/Policy key and cannot send EnableFinancialMode.
Independent authorities enable that exact mode; a relayed read-only Custody-signed
query over existing courier TLS retrieves its public proof.

Only a clean approved HOT Root can begin or complete import: no DB Claim/counter
history and an authenticated W next-Claim index of zero. Pending import blocks
new Claims; both orderings serialize on the existing keyset/root locks. Completion
verifies the exact original all-three Root receipts, current installed W signature,
mode UUIDs, query echo, original Root, package/hash/generation and roster shape.
It rechecks expiry after row locks and consumes the original lease. A renewed
nonce retains both original mode UUIDs and rejects delayed replies. Mode proof
and mandatory audit commit atomically; VERIFIED history cannot mutate or downgrade.
Every new Claim service admission re-verifies the original mode proof. Structural
SQL checks do not authenticate signatures by themselves.

Verified proof remains historical after Claims are added; it is not today's
generation/phase authorization. Current W identity rotation needs an explicit
archival-pin/import extension; this implementation fails closed on a changed pin.
Neither Root-mode import nor original native wallet publication enables financial
wallets. Both direct event ingestion and dedicated deposit credit now inspect
the stored wallet identity and reject seeded wallets until financial activation
and provenance are implemented. Compensation of original postings is preserved.
Generic trusted financial posting/SQL is not claimed to be a new cryptographic gate.

Local54 PostgreSQL cases passed74.51s, including both real lock race orders,
post-lock expiry, audit failure, nonce renewal, immutable IDs and populated downgrade
refusal with leaf restoration. Genuine PG/three original protected nodes/Rust W
import passed6.25s: committed IDs, mode-off and pre-import Claim denial, actual
canonical no-Claim query, independently enabled mode, original Claim after import,
W restart and retained proof/Root receipts. No wallet or ledger activation occurred.
Independent source review caught an optional-null canonicalization bug; it was
fixed and the genuine Rust roundtrip now covers it. Independent54 PG cases passed
76.12s and actual Rust/PG import passed8.39s with unchanged binaries; bounded
source/runtime review found no demonstrated P0/P1. Broader backend/current-head CI
and whole-phase gates remain separate. See
[public evidence](evidence/phase6gc-financial-root-import-local.json).

Checkpoint `9d93320` Fast41329232311 and selected dispatch41329251940 failed the
broader backend gate: an existing TON precision test used a synthetic object with
no stored-wallet FK. Its crypto preflight/suites did not execute. The subsequent
fix uses real stored UserWallet/Deposit fixtures while preserving the original
full-precision assertion, and the credit service reads the stored owner/asset.
Targeted precision plus seeded-credit denial passed2 cases3.88s. New exact-head
broader backend/crypto gates remain required; this failure is not a green gate.

The correction `600fcfe` subsequently passed Fast41330106726, all four executed
jobs including812 backend tests245.64s. Selected Solana41330272112 is running;
no current ALL gate is claimed. Later principal-role source is separate.

## Explicit principal roles (subsequent uncommitted development)

Migration0037 adds immutable, mutually exclusive CUSTOMER/TREASURY classification
on the existing tenant-scoped principal. A standalone operator service always
requires the explicit role. An audited CUSTOMER declaration may preserve an
existing registered principal and its multichain history; owner IDs, wallet
ownership, assets, balances and original receipts do not change. Treasury
registration creates a fresh principal/reference and cannot relabel an existing
reference, even an empty one. Matching original-role retries are reads. Identity
and role/audit creation are atomic; role references are not caller authentication.

SQL Treasury birth locks the stable principal and scans all customer ownership,
USER-account, withdrawal, HD account/reservation and Solana Claim history while
holding NOWAIT table locks. Future customer writers take compatible KEY SHARE
locks on that same principal; these conflict with role birth's UPDATE lock.
Customer wallet/USER-account/withdrawal/HD customer references cannot use treasury
principals, across chains. Isolation is checked before role/absence lookups so a
stale transaction cannot miss a newly committed role. Unrelated legacy reference
strings retain their prior semantics. Treasury and customer classifications
cannot change or be deleted, including through SQL; populated downgrade fails.

Financial-Root Claims require a declared role; treasury Claims require a verified
financial Root. Root/Claim ownership and the separate original W issuance grant
remain unchanged. Existing customer publication rejects a treasury Claim before
reserving an issuance intent; SQL independently blocks a treasury UserWallet.
Dedicated treasury publication uses the separate membership contract below.
No synthetic `FinancialBinding.source_role` assertion substitutes for this DB role.

Current targeted49 cases passed54.37s, with existing-owner balance preservation,
immutable roles, five future-writer paths across ETH/SOL, both actual database lock
race orders for wallet and USER account birth, stale-isolation denial, Root-mode
and treasury-Claim gates, and audit rollback. Genuine Rust W/PG import with explicit
customer declaration passed6.02s. Independent49 PG cases passed53.586s and genuine
import5.912s with unchanged binaries; bounded source/runtime review found no P0/P1.
Full backend passed840 tests291.17s, zero failures/skips. Current-source CI remains
required; the earlier600fcfe selected run does not cover this role layer.
No financial wallet or ledger activation follows from these classification tests.
See [bounded evidence](evidence/phase6gc-financial-principal-roles-local.json).

## Native customer and treasury membership (subsequent development)

Migration0038 adds one financial publication record per original Claim, with exact
verified Root mode, derived owner role and original native issuance UUID. Begin
atomically commits both intents and a15s query before exporting any grant action.
Existing wallet/address/issuer history cannot be adopted; forward preflight and
reverse guards refuse populated incompatible history. Mode-off native foundation
wallets remain nonfinancial. Legacy customer APIs reject every financial Root
before allocating an issuance intent.

Completion authenticates the current nonce, original W signature/issuance grant,
irreversible mode IDs and all-three archival Root/Claim proofs under existing
locks. Issuer WITNESSED, optional new customer UserWallet, ACTIVE membership and
mandatory audit commit together. Deferred constraints reject partial commits.
Customer linkage preserves the exact original owner/source/asset; treasury creates
no UserWallet. Source role and identity cannot change. HotWallet reference races
serialize through NOWAIT table locks; no legacy HotWallet adoption or fallback.
Multiple tenant/asset treasuries remain possible for later root rotation; actual
operations must choose an explicit immutable same-tenant/asset source/destination.

Previously granted publication may complete after Freeze/Prepare or a generation
advance. Historical validation reloads DB rows and re-verifies original proofs,
allowing a retired keyset in read-only identity checks. This is not unconditional
archival availability across policy/key rotation: current asset/deposit policy and
installed W pin still apply. Original ledger reversals do not call this validator.
ACTIVE is publication membership only. Both seeded ingestion and dedicated credit
remain closed until verified indexing and protected financial-session integration
are implemented. No new crypto grant, customer liability or ledger balance follows.

Local39 PostgreSQL cases passed70.55s, including real post-lock expiry, expired
query renewal, no adoption, SQL forward/reverse guards, deferred issuer/customer
partial commits, atomic audit rollback, immutable identity and both HotWallet race
orders. Genuine PG/three original nodes/Rust W customer+treasury publication passed
6.68s: original grants recovered after W restart, completion while Frozen, actual
DB failure after remote grant then exact-ID retry, no treasury UserWallet, no
ledger journals and unchanged three DKG ciphertexts. Initial genuine ACK comparison
incorrectly expected identical signatures/sequence; W intentionally re-signs ACKs
at its current sequence. The corrected check verifies the original command digest,
authentic signature and no journal advance. No authority source change was needed.

Independent39 PG cases passed71.763s and genuine publication7.283s with unchanged
binaries, with no bounded source/runtime P0/P1 finding. Full backend passed879
tests360.44s, zero failures/skips. Current-source CI and whole-phase gates remain
required. See [public evidence](evidence/phase6gc-financial-wallet-local.json).

## Local evidence and remaining implementation

Current protocol8 and witness23 tests pass, independently rerun. Tests preserve
old signed fixtures/digests and cover owner separation, stable business identity,
parent-field mismatch, clean/irreversible activation, stale generation/roster,
expiry/pending-maintenance denial and reservation reuse. All-target Clippy passed
2.59s after the final test-only additions; no new dependency or algorithm is used.

Genuine independent processes and pinned Agave passed the read-only query case
29.43s. The query+initial-mode batch passed2 cases71.98s. The expanded mode case
passed58.04s, independently57.613s with unchanged binaries: actual activation and
witness restart/ACK recovery, legacy intent denial before W grant, typed financial
identity, reservation reuse denial, original-gen AB transfer, all-three upstream
refresh/activation/restart retaining mode, and refreshed-gen AC transfer. Both
transfers finalized. These tests use synthetic reservation references, not ledger
entries. Named public reports contain no private shares/keys.

Remaining work includes current-source CI/review, immutable backend session/attempt
and business reservation identity, independent Policy approval for each exact wire,
explicit tenant/asset treasury selection separate from customer deposit sources, and
canonical message AND signature ownership bound before broadcast. Preserve Unknown
and existing reserves; signature completion alone is not settlement. Source amount
and base-paid fee/rent need separate verified effects and exactly-once accounting.
Known custody/internal withdrawal destinations require explicit rejection or a
same-ledger transfer/reconciliation path. Deposits require actual indexed provenance
and exclude operator/base/internal transfers, including registered unpublished
Claims; no balance-difference credits. SPL finality/publication and fresh-DKG
drain/retirement/late-address rescue remain whole-phase requirements.

Public local evidence is recorded in
[evidence/phase6gc-financial-mode-local.json](evidence/phase6gc-financial-mode-local.json).

The earlier financial crypto checkpoint `4971fd7` passed exact
[Fast41290861686](https://github.com/zeroexlive/Custody/actions/runs/41290861686)
and [selected Solana41290881147](https://github.com/zeroexlive/Custody/actions/runs/41290881147):
6 executed jobs successful,8 unselected jobs skipped;47 selected=called scenarios,
zero scenario skips, XML2812.070s. Preflight/inventory264 hash and exact SHA match;
artifact13078274703 contains39 allowlisted public files including materialized
pytest current aliases. Fixed3d32 original-store compatibility and other suites
were unselected: this is not ALL and does not cover later coordinator/backend code.
