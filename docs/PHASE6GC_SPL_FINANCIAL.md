# Phase6G-C classic SPL financial workflows — in progress

This development boundary extends the existing financial core to classic SPL
seeded accounts. It introduces no new ledger or cryptographic algorithm.
`MPC_SOLANA_SEEDED_SPL_ENABLED` and seeded deposit credit remain default-disabled.
Whole-phase acceptance, final-SHA CI, merge and production authorization are
separate gates; none follows from the component results below.

## Initialization and publication

An explicit `TokenProvision` parent uses the existing financial operation,
session, query, message owner, signature owner and finality effect records.
`PROVISION` alone has exactly zero principal, positive Root-paid fee/rent budgets
and no customer balance reservation. Ordinary spending retains positive amounts.
Original business IDs precede private execution. An unresolved initializer cannot
be replaced. Authoritative NoSignature permits another crypto attempt under the
same hold; an actual finalized failed transaction permits a new explicit business
ID after recording its actual fee. A signature is never silently retried.

Membership stays pending and creates no UserWallet until the original owned MPC
initializer has finalized successfully. Standard CreateAccountWithSeed followed
by InitializeAccount3 must create one fresh zero-token account with exact rent.
A separate Lifecycle `IssueClassicClaim` command permanently binds the original
Claim and its original financial `SignedPending` initialization execution. This
witness grant certifies signing identity, not chain finality. The backend also
requires fresh finalized account evidence: classic Token Program, binary165,
exact mint/Root authority, initialized state, no delegate, wrapper or close
authority, and current rent exemption. A nonzero balance at publication does not
itself create customer credit; original history must be attributed separately.

Publication, proof, optional customer UserWallet and mandatory audit commit
atomically. Treasury membership creates no UserWallet. Both customer address
fields identify the unique seeded token account; signing authority remains the
Root base. Native issuance retains its previous three-key canonical witness
grant; the initializer field is omitted for native claims.

## Transfers, deposits and accounting

`ClassicSeededTransfer` is an explicit sweep-only standard TransferChecked action
to an already initialized treasury Claim's exact base/index-derived account.
Existing native and classic wire fixtures remain unchanged; three additive SDK
intent cases cover the new action. Each protected node independently validates
current source/destination account identities and state.

Financial external withdrawals always authorize an idempotent ATA creation
instruction and reserve its full possible current rent, including when the ATA
already exists. An external account closure between observation and execution
cannot turn an authorized zero-rent operation into an unreserved spend. Finality
posts actual rent only. Root lamports for fees/rent are separate from token units;
all held operations contribute their fee and rent budgets to Root liquidity.

The dedicated incoming parser accepts actual successful classic Transfer and
TransferChecked instructions, including delegates, multisigs and runtime CPI.
It does not require an external ATA or treat a fee sponsor as the token owner.
Executed InitializeAccount(1/2/3), AccountOwner changes and Close/reinitialization
are traversed in transaction execution order. Source account and every observed
source owner are checked against historical custody and permanent operator
funding classifications. Ownership through an internal owner stays excluded for
the whole transaction. Missing or contradictory ownership fails closed.

Gross transfer instructions establish amounts under the existing independently
pinned trusted-finalized-RPC boundary. Destination aggregate token change must
corroborate incoming instructions. A source's net decrease is deliberately not
required: a valid atomic route may receive and forward the same tokens. The
Classic digest binds normalized token amounts, mint, owner, program, decimals and
indices together with original signed wire, finalized block membership, native
effects and executed inner trace. Native digest material is unchanged.

Credit uses the existing Deposit and balanced customer/clearing journal, with
immutable global instruction provenance and complete source-owner history. The
locked credit step rechecks that entire history against current classifications;
later funding classification also checks every persisted historical owner.
Replay cannot credit
twice or recredit a reversed deposit. Every asset's credit serializes with
operator funding classification through the common SOL asset lock. A source
account or owner already credited as external cannot be reclassified silently.
The funding registry must be operationally complete; nonempty is not proof of
completeness. It is technical ownership classification, not deposit screening.

Actual fees and initialization rent post balanced immutable SYSTEM journals.
Initialization rent uses `TOKEN_ACCOUNT_RENT_ASSET`; external ATA rent preserves
the existing bucket. Neither initialization nor sweeping creates USER liability.

## Migration and operational limits

Migration0045 preserves prior native functions while extending explicit subtype,
publication, cost and deposit invariants. It refuses to reinterpret preexisting
generic `PROVISION` attempts, and refuses downgrade after classic financial
history exists. SQL publication checks raw mint/authority bytes and required rent
fields in addition to service validation. Structural SQL checks do not replace
cryptographic verification or prove that RPC metadata is true.

A predictable `c1t` address can be prefunded with SOL before initialization.
CreateAccountWithSeed then fails closed; arbitrary existing accounts are never
adopted. Resolving such a reservation requires governed fresh-Root recovery or a
separately reviewed standard AllocateWithSeed/AssignWithSeed implementation.
External ATA prefunding and uncertain/pruned history also fail closed. No
automatic private resend, production/mainnet activation or customer-fund use is
authorized by these development tests.

## Validation checkpoint — 2026-11-03

Root103 focused cases passed130.43s. Independent combined313 cases passed302.898s;
one genuine complete SPL flow passed176.216s, and three genuine native legacy/
v0/PDA regressions passed331.088s. All have zero failures/errors/skips. Independent
before/after82-path hashes, including3 runtime binaries, match freeze3. The79
source/fixture/workflow files are independently tied to committed7ff1e56,
including the single accepted helper correction; saved runtime binaries match
the independent final manifest.

The actual SPL acceptance finalized2 original MPC initializers, permanent
issuance/publication, actual A→B→customer with observed Bpre/post0,10m deposited
units, seeded treasury sweep, two approved withdrawals totaling3m units,7m remaining
liability backed by7m treasury units,25k Root fees and3 rent-funded accounts.
Thirteen existing-ledger journals balance; treasury creates no UserWallet.
Restart preserves all original3 DKG ciphertexts. The independently rerun primitive
boundary also passed protocol9, wire1, account negative1 and a genuine protected
SPL sweep case; current independent DB-free units passed protocol10, witness24,
account negative1 and parser/effects29 before the later history correction.

Exact [Fast41499260859](https://github.com/zeroexlive/Custody/actions/runs/41499260859)
at136d995 passed4 executed jobs, including1201 backend tests705.55s. Ten full-crypto
jobs were unselected. Subsequent exact
[Fast41536746241](https://github.com/zeroexlive/Custody/actions/runs/41536746241)
at7ff1e56 also passed4 jobs, including1201 backend tests485.46s, and includes the
accepted public-only lease retry helper. Ten full-crypto jobs were unselected;
whole-phase ALL and original-store compatibility remain required. The intentionally interrupted local
broad run at617 passes218.64s is partial evidence only.

Both independent initial failures remain recorded. One setup attempt stopped15
passes/1NOWAIT error; a fresh disposable DB rerun passed313 without weakening the
lock guard. The first genuine SPL attempt failed67.05s at the unchanged publication
query-expiry guard. The corrected harness requests a fresh public query only after
actual expiry, up to3 attempts under the same Claim/issuance/initializer/grant.
It never repeats private execution or the Lifecycle command and extends no deadline.
The subsequent actual full SPL rerun passed176.216s.

Independent review corrected two blockers: redundant source net-debit validation
rejected valid atomic forwarding, and owner-at-transfer alone lost earlier owner
history between observation and locked credit. Complete immutable history and
locked classification rechecks passed both timing orders. Witness mode/binding
and SQL raw-mint/rent consistency checks were also tightened. No remaining
identified bounded P0/P1 follows from source/runtime review; this is not an external
audit, whole-phase acceptance or production approval. See the machine-readable
[evidence record](evidence/phase6gc-spl-financial-local.json).
