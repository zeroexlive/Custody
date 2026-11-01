# Phase6G-C protected financial integration — in progress

The first implementation boundary adds a versioned financial identity and an
explicit irreversible witness Root mode. The protected coordinator, PostgreSQL
operation/session bindings and existing ledger integration are still unfinished.
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

Remaining work includes a durable typed protected coordinator, original R1 reports
and first R2 package committed before R2 dispatch, immutable backend session/attempt
and business reservation identity, independent Policy approval for each exact wire,
tenant/asset treasury publication separate from customer deposit wallets, and
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
