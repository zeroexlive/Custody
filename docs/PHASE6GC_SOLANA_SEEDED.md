# Phase 6G-C — seeded Solana primitive boundary

Status: **implemented primitives and signer-local approvals / incomplete custody integration**. No issued
customer wallet, new signing permission, production flag, ledger behavior or phase
completion is implied. The separately reviewed dependency checkpoint `ea4bb4ed`
passed all 14 full-gate jobs; subsequent seeded changes need their own final gates.

## Mechanism

A standard System `TransferWithSeed` spends native lamports from a base+seed+owner
address using the original FROST base authority. This address is not an Ed25519
child verification key. Classic SPL uses a separately allocated seeded account,
atomically created with `CreateAccountWithSeed` + `InitializeAccount3`; the Token
program owns its 165 bytes and the base is its spending authority. `TransferChecked`
spends that account, optionally creating the recipient's ATA idempotently.

Native/token seeds are fixed 32-byte ASCII strings, with a signed-bigint allocated
index and distinct prefixes. Token indices must be unique across mints; never
hash/truncate customer or mint into an index. Persistent namespace/ownership/index
allocation is not supplied by these primitives.

The original base signs and pays fees/rent, while the financial source is the
seeded account. Existing settlement assumptions that fee payer, source and token
authority are identical cannot be reused for issued seeded custody.

## Implemented boundaries

- Python SDK-based message/address builders remain unconnected to product flows.
- Rust `protocol::solana_seeded` independently checks standard address hashes,
  classic ATA derivation, bounded canonical legacy encoding, payer/signature and
  account flags, the exact complete account set and SDK ordering, blockhash,
  program IDs, instruction accounts/data and absence of extra instructions/bytes.
- Direct curve25519-dalek 4.1.3 is the already pinned FROST dependency. Its public
  Edwards decompression is used for Solana PDA/on-curve checks, with no new version,
  feature selection, private scalar operation or Ed25519 derivation protocol.
- One Rust regression case covers 15 independent SDK fixtures (native transfers
  including sweep-to-base, token creation, transfers with/without ATA creation,
  indices 0/7/i64-max), truncation/every-byte mutation, coordinated same-permission
  account-table/index permutations, malformed/overflow shortvecs, invalid bases,
  capacity, blockhash and operation-amount mismatch.
- `seeded_message_check` is a public-message acceptance helper. It does not sign,
  read a share, issue a wallet or authenticate caller-supplied intent.

## Genuine primitive acceptance

The Solana suite adds `test_phase6gc_seeded_wire_primitive_spendability`. It creates
three independent mTLS FROST services and a fresh genuine DKG, pins an isolated
Agave 2.1.21 genesis from local ledger artifacts, then finalizes three native seeded
transfers, one atomic seeded SPL creation and three checked token transfers. Both
transfer families use every signer pair with the third offline; no complete custody
key is reconstructed. Ordinary disposable faucet/mint keys bootstrap the isolated
chain only.

The test independently verifies FROST signatures and exact returned chain bytes.
It checks native source/destination/base fee effects, classic token owner/mint/
165-byte initialized state, creation rent/base cost, token source/recipient amounts
and transfer/ATA rent effects. Only explicit public evidence (original messages,
signatures, operation/session IDs, network identity and on-chain deltas) is eligible
for upload; signer stores, PKI, wrapping keys and private protocol state remain local.

**Scope:** client-side typed validation precedes the existing root signing API,
whose `expected_source` is the FROST base. This does not implement signer-side
seeded enrollment/authorization or financial source binding. It is evidence of
primitive spendability, not complete end-to-end custody acceptance.

## Signer-local authenticated enrollment and claims

Three internal signer routes accept only the coordinator's mTLS transport plus
an original detached P-256 custody-machine authorization. Separate domain-separated
canonical statements prevent a root proof from becoming a claim proof. These
routes remain internal to signer services:

- `POST /internal/v1/solana/seeded/enroll`: immutable original FROST DKG request,
  group key and complete public package, authenticated deployment ownership scope,
  `SOL` genesis, `HOT/DEPOSIT`, `solana_seeded_v1`, initial generation zero.
- `POST /internal/v1/solana/seeded/approve`: original root, reservation UUID,
  operator-supplied ledger owner reference, retry identity, monotonic index and
  native/classic-token identity (mint and decimals for tokens).
- `POST /internal/v1/solana/seeded/probe`: read-only original-root eligibility,
  requiring the same original custody proof, own encrypted DKG and usable receipt
  identity. Its transport response is not a signed dedication receipt or lease.

Each party reopens its own encrypted original DKG and compares the complete public
evidence before signing a durable receipt with its separately held identity key.
A root dedication and first legacy nonce reservation share one lock: historical
use prevents dedication; dedication prevents the generic root-signing API. Startup
imports historical prepared/consumed/completed records conservatively, preserving
legacy signatures and rejecting a conflicting dedication. It does not infer that
a historical root was unused. Newly enrolled roots have **no spending API yet**.

An authoritative immutable index commits before owner/reservation/retry aliases.
Exact retries repair incomplete aliases and return the original randomized
receipt. Allocation checks all committed indices, including global reservation
UUID conflicts across roots when aliases are missing. Owner/mint and retry slots
remain root-scoped; indices are shared across native and all token mints, never
recycled or chosen out of order. Startup checks contiguous allocation and exact
alias consistency, verifies own signatures, rejects corrupted/orphaned records,
and retains actual `tmp-UUID` atomic-write leftovers as uncommitted evidence.

Five genuine process cases passed in **11.31s**: credential/domain/identity
negatives, exact retries, concurrent requests/index competition, partial enrollment,
missing aliases, interrupted temporaries, two-root reservation collisions, historical
signing, dedication/nonce race and three corruption/restart cases. A separate review
agent identified two recovery defects, then independently reran the strengthened
approvals case (**1 passed in 3.63s**) after both fixes. No remaining concrete P0/P1
was identified in this bounded change. Fresh full regressions are required because
signer startup and legacy signing paths changed.

**Trust and limits:** custody is the trusted deployment-level machine authority;
the root genesis is its signed pin, not a signer-side RPC/light-client attestation.
`owner_ref` is not yet resolved to a custody DB principal and does not establish
an external tenant/customer principal. A token claim
does not prove an existing valid mint/account or on-chain initialization. Receipts
do not grant spending or create a financial wallet. Current identity keys must be
retained: transparent TLS identity-key replacement is unsupported pending archival
rotation. Allocation scans committed records and has not passed the required 1000
complete-wallet benchmark. These records do not prevent coherent store or approved
binary rollback; an independent generation witness and protected deployment policy
remain mandatory. One configured process exclusively owns each signer store;
privileged filesystem/configuration access remains trusted. No database migration,
UserWallet attachment, balance posting or production flag change is introduced.

## Three-store coordinator agreement and custody receipt verification

The coordinator now also exposes custody-machine-only mTLS POST routes
`/v1/keysets/{id}/solana-seeded-root` and `/v1/keysets/{id}/solana-seeded-claims`.
They relay the original detached custody proof, preserve the exact original DKG
and namespace, collect all three independently authenticated signer responses,
and persist one immutable complete agreement. The response contains `statement`
and ordered `participant_agreement` (signer-a/b/c); every receipt includes the
same statement, party ID, durable flag and detached signature. Two receipts cannot
create completed evidence. Partial responses stay in the original signer stores.
An HTTP409 does not prove that no signer committed: retain the original request,
reservation/index and retry identity. Recovery completes that exact request.

Completed agreements can be returned after coordinator restart with all signers
offline. These are public evidence reads under custody mTLS, not new transitions;
they do not renew a signing grant or require fresh detached proof validation at
every signer. New writes require the original proof at each signer. Conflicting
root/claim identity cannot replace the original cached agreement.

Custody's receipt verifier adds separate `solana_root` and `solana_claim` domains,
using the existing operator-configured `MPC_HD_SIGNER_CERTIFICATES` archival HOT
signer pins. It requires three distinct P-256 identity keys in the fixed party
order. No coordinator-supplied trust key is accepted. This verification is mandatory
before a future issuance service may consume the agreement; the new routes alone
do not establish its financial/customer identity or create a wallet.

A genuine partial-enrollment/partial-claim/restart/offline-retry case verifies both
all-party receipt collection and independent custody verification, including a
coordinator-key forgery, wrong domain and missing/duplicate/reordered receipts.
All six store/agreement cases passed in **14.27s**; **38** existing backend
EVM/TRON issuance/provisioning tests passed in **17.38s** after the receipt-domain
extension. Separate source review found no concrete P0/P1 in this bounded layer.
It is subsequent to checkpoint94a0216 and needs its own final-head CI. Whole-phase
acceptance remains open; crypto inventory is now226.

## Historical-quorum preservation and coordinator intent fence

Further independent review reproduced a conditional compatibility gap: a root
previously used only by signer-b/c could still look unused at signer-a. An
authorized dedication collected in party order could change a before b rejected,
reducing historical quorum availability. Earlier green gates did not cover it.

The coordinator now rejects any existing signing-session history for that root,
including never-executed intent, before changing a party. It probes all three
original stores without mutation before committing a new immutable `.pending`
root intent. The same durable-data mutex serializes this sequence against new
`create_sign` reservations, which reject pending or complete dedication markers.
Partial/uncertain dedication retains its original fence. Exact existing signing
session/result recovery is preserved. A missing completed coordinator cache can
be rebuilt from the original party receipts without reopening generic signing.

Seven genuine store/agreement cases passed in **20.36s**. The new case verifies
b/c-only historical use leaves all three roles unchanged, including after restoring
coordinator metadata without that signing history; all three legacy signer pairs
remain usable. It also covers concurrent enrollment/signing intent and recovery
with the pending fence retained after complete-cache loss. New inventory: **227**.
The independent reviewer reran this strengthened case (**1 passed in6.38s**) and
found no remaining P0/P1 in the declared single-coordinator flow. All **48** legacy
FROST process cases also passed in73.55s; new final-head CI remains required.

The coordinator holds its data mutex across bounded signer RPCs for this rare
operator ceremony; unrelated metadata requests may wait. This is not accepted
population scalability or a distributed Byzantine lease. Direct internal enrollment
still checks local history: custody must authorize only fresh, unreferenced roots.
Readonly probes do not stop a malicious coordinator bypassing the coordinated API
from racing separate local actions. Independent policy/generation fencing, protected
deployment configuration and the rollback witness remain required before issuance.
No global safety claim is made against coherent infrastructure rollback.

## Still required before customer issuance

Connect the new signer-local records to authoritative custody root/owner/network
registration and durable issuance, verify all three independently pinned receipts,
and implement generation continuity and authenticated signing intent across the coordinator;
mandatory signer-side decoding before nonce work; fee/rent policy and actual account
validation; source-vs-authority settlement and operator-cost attribution; ledger,
indexer/sweep/withdrawal integration; partial/restart/unauthorized/network/mint/replay
negatives; and a benchmark of actual complete issuance, not public hash generation.

Deployment ownership scopes are not tenant authorization. Bind real supported
ownership identities and keep external issuance unavailable until its authorization
boundary exists. Preserve historical addresses, balances and uncertain reservations.
Authenticated epochs, recovery, class isolation and full-phase acceptance remain
required. TON scope is unchanged. No mainnet/customer-fund activation is authorized.
