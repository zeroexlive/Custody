# Phase 6G-C native seeded wallet publication — development

Draft PR #2 adds a privileged operator flow that actually publishes native SOL
wallets from the original durable reservations. This is unmerged development;
SPL publication, protected financial sessions, lifecycle replacement/repair and
whole-phase acceptance remain unfinished. No production activation follows.

## Identity and independent authority

The original tenant/principal registry, completed genuine DKG, three original
Root receipts and three original Claim receipts remain mandatory. Classified
HOT DKG receipts retain their explicit `custody_class` in the exact original
request; absent legacy fields remain absent. Backend import does not enable
WARM/COLD or another algorithm by relabelling those receipts.

The backend first commits one immutable `MpcSolanaIssuance` UUID, its Claim FK,
independently installed witness key/anchor and a random15-second query. The local
operator exports the public action/query to the separate lifecycle authority.
The backend has no lifecycle private key or automatic issuance approval. An
actual witness `IssueNativeClaim` command requires an already registered native
Claim and an Active Root. Its issuance UUID is globally unique and permanent.
An issuance acknowledgement alone never creates a backend wallet.

Completion verifies the current pinned P-256 witness signature, the exact durable
challenge/anchor/Root/Claim/issuance identity and all original detached signer
receipts. It independently checks RPC network identity. Freshness is checked
again after I/O, cryptographic verification and database locks. An expired query
can be renewed only for the same original issuance UUID; delayed old replies
cannot answer its replacement challenge. A grant committed while Active may be
recovered after Freeze; Freeze does not erase already granted publication.
Retirement/drain must account for all registered/issued witness Claims, including
a grant whose database publication response was lost.

Wallet creation, WITNESSED evidence and mandatory audit commit atomically. A
failed audit rolls back their transaction without erasing the external witness
grant. Exact retries return the original wallet after re-verifying its retained
proof. Issuance never creates a financial journal or credits a balance.

## Persistence and ownership

Migration0035 adds the issuance record and a nullable unique Claim link on
`UserWallet`; it performs no adoption or ownership backfill. Seeded wallets use
the Claim's individual source address, immutable `p1` ledger owner and index,
and a Root-specific derivation path. The shared FROST base is fee authority,
not the published deposit address. Distinct Roots can use index0 without
collapsing their owners. Existing unlinked HD uniqueness remains conditional
on the absence of the seeded Claim link; the index becomes positive64-bit.

PostgreSQL triggers enforce the exact native owner/asset/network/Root/Claim
identity, original WITNESSED issuance and append-only history. Allocation and
publication require READ COMMITTED; a stale REPEATABLE READ/SERIALIZABLE view
cannot adopt a concurrently committed legacy address owner. Seeded claim and
legacy source/token-account writes share address advisory locks. Keyset locks
precede those address locks. SQL checks signature structure; the application
must still verify cryptography at each authoritative consumption boundary.

Seeded wallet ownership cannot be edited, deleted, reassigned or adopted from
an old wallet. Generic admin forms are read-only for these rows. Status changes
are blocked until drain, continued old-address scanning and late-deposit rescue
are implemented. Dedicated Roots still cannot enter generic signing or
HotWallet paths. SQLite can install the schema for compatibility but privileged
publication refuses its missing PostgreSQL guarantees. Downgrade refuses populated
issuance history, seeded wallets or indexes outside the old range.

## Actual issuance and performance evidence

The genuine acceptance flow uses PostgreSQL, an isolated pinned Agave validator,
a real classified HOT DKG and three independent protected signer processes.
Every counted wallet has its own actual reservation, all three signed Claim
approvals, witness registration and issuance grant, and published database wallet.
No count comes from address derivation or hashes alone. Three distinct issued
sources are then spent by each possible signer pair and finalized on Agave.

The initial three-wallet flow passed105.98s. Expanded acceptance passed111.00s:
registered-but-unissued publication refused; cross-Claim issuance UUID reuse
refused; a lost witness acknowledgement recovered across an actual witness
restart; exact backend retry returned the same wallet; altered and missing old
index receipts were rejected while the signer cache was warm; all three signers
restarted from original durable records before finalized all-pair spending.

The first actual1,000-wallet attempt failed after more than300 issuances with a
backend HTTP read timeout at771.42s. It is not a passed benchmark. Each new
signer approval was repeatedly deserializing, verifying signatures and deriving
namespaces for the entire prior inventory. An in-memory exact-byte verification
cache now avoids repeating those calculations. Every approval still enumerates
and reads all committed indices, rejects changed/disappeared cached records,
checks all global reservation/owner/retry collisions and monotonic allocation,
and confirms directory durability. New or uncertain committed records are fully
verified before entering the cache. Startup reconstructs it from the fully
verified original store. Spending continues to read and verify its original
four aliases. No persistent encoding, timeout or scanner exception changes.
The retry **actually issued1,000 wallets in627.149s** and passed the complete
case in737.59s. Exactly1,000 WITNESSED issuance records and Claim-linked wallets
were checked, with zero issuance ledger journals and unchanged original DKG
ciphertexts. Each signer pair finalized a transfer from indices0/500/999; each
fee was5000 lamports paid by the separate base. The
[public benchmark record](evidence/phase6gc-native-1000-local.json) and separate
[three-wallet fault/restart record](evidence/phase6gc-native-recovery-local.json)
retain their distinct scopes. This is local genuine acceptance, not remote CI,
financial settlement or whole-phase completion.

Public CI artifacts are restricted to the explicitly named
`solana-native-issuance-public-evidence.json`, JUnit and scenario inventory.
Private stores, wrapping keys, identity keys, nonce material and service logs
remain local. Public reports state the primitive-spending scope explicitly;
these transactions do not establish backend ledger settlement. Existing generic
root signing and root deposit validation reject seeded derivation references.
Protected backend financial integration must explicitly verify original issuance
and source identity before enabling those consumers; no local-key fallback is
added by publication.

## Operator interface and remaining gates

`solana_wallet_publication request --tenant-id … --reservation-id … --operator-ref …`
exports the durable issuance identity and public query/action.
`solana_wallet_publication complete --tenant-id … --issuance-id … --evidence … --operator-ref …`
consumes bounded signed public witness evidence. Operator audit labels are not
API credentials; no external customer/IAM permission is granted by this CLI.
The witness pin/anchor settings default empty and publication then fails closed.

An independent fresh PostgreSQL run passed all80 native issuance and prior
provisioning cases in97.01s, including real query expiry/refresh, concurrent
single-identity/audit publication, Frozen grant recovery and pending/published
downgrade refusal. These unit tests use synthetic public evidence and are not
genuine MPC acceptance. The original public RefreshPlan/Frozen canonical hashes
were independently recomputed and unchanged after the optional issuance field.
Protocol/witness tests (including actual upstream crypto cases), signer/storage
unit tests, Clippy, formatting, Django checks and migration drift passed locally.
Independent source review found no demonstrated P0/P1 in this bounded layer;
full inventory reads and all-time cache memory remain O(N) scalability debt.
The independent expanded genuine three-wallet rerun passed113.42s, verifying the
same issuance/restart/fault/all-pair path with a separate original fixture. Final
native checkpoint CI,
full final-phase ALL/original-store compatibility, supported recovery/rotation,
finalized SPL issuance and single-ledger integration remain
required before phase completion and merge.


The first complete backend run had787 passes and three legacy migration-test
failures (548.49s). The failures were exact expected new-nullable-field defaults
and a current-model query after a partly completed refused downgrade. Narrow
compatibility corrections preserve every old wallet/account/journal field and
the original balance assertions. All three corrected cases passed12.55s;
the complete backend rerun passed all790 cases in431.17s. The development database, with no issuance
intents/seeded wallets/expanded indexes, also successfully reversed empty0035 and
reapplied the current guards without resetting legacy data.


Native checkpoint `6e2bcee111fd8cb72d5747aec2e599f21b10127f` passed
[Fast40851236750](https://github.com/zeroexlive/Custody/actions/runs/40851236750)
(all four executed jobs; expected crypto skips). Its
[selected Solana40851260306](https://github.com/zeroexlive/Custody/actions/runs/40851260306)
passed at that exact SHA. Independent verification of artifact12889217392
confirmed34 unique selected/called scenarios, zero scenario skips and34 JUnit
passes in1856.780s. Its inventory251/hash
`c765bb1558a9b73cec5b5eec01f55ac08ca6fc54e36f24613be9fbad803293b1`
matched preflight. Fourteen allowlisted public files include pytest current-path
duplicates; no private key/store markers were present. Actual remote native3 took
96.202s and native1000 took402.073s, with307.076s actual1000 issuance. All counted
wallet/issuance rows, unchanged original ciphertexts, zero issuance journals and
all-pair finalized transfers were verified. The selected run explicitly skipped
original-store compatibility and other chains, so it does not satisfy final
ALL/original-store or whole-phase acceptance.
