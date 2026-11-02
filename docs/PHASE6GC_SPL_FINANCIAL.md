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

## Validation checkpoint

The independently rerun primitive boundary passed protocol9, wire1, account
negative1 and one genuine protected SPL case (138.924s), with stable16-source and
three-binary hashes. This predates the financial backend changes and does not
review or accept them.

Root backend initialization/publication plus native deposit regression passed69
cases in81.71s. Dedicated deposit/pure attribution passed24 cases in21.92s;
expanded pure ownership/order coverage passed21 in0.19s. Witness24 unit tests
passed in0.10s, including unchanged native serialization and rejection of classic
issuance without financial mode or financial initializer binding. Further
concurrency, SQL mutation, complete genuine SPL financial execution, independent
runtime, native regression and exact-source CI gates are still in progress.

The latest root combined batch passes103 cases in130.43s with no failures/errors/
skips, including concurrent initializer/publication, direct SQL rent mutation and
downgrade refusal, failed initialization followed by a fresh business, expiry
after locking, raw mint/rent proof checks and both historical-owner race orders.
One genuine full financial SPL flow passed166.60s: two MPC initializers, permanent
issuance grants, actual atomic external forwarding/deposit, seeded treasury sweep,
two approved withdrawals,13 balanced journals, actual first-ATA rent/second-ATA
zero rent, restart and unchanged original DKG ciphertexts. That run predates the
subsequent historical-owner correction and added explicit intermediary metadata
assertions; independent rerun is required. Broad backend run v1 was intentionally
interrupted after617 passes218.64s for the race fix and is not full-suite evidence.

Independent source review found and corrected an availability blocker: requiring
a source's whole-transaction net debit rejected valid atomic forwarding and could
stall scanning. Review of the revised bounded source found no additional concrete
P0/P1; this is source review, not runtime acceptance or an external audit.

A second review finding identified a classification race between observation and
locked credit: owner-at-transfer alone lost an earlier owner after SetAuthority.
The corrected immutable history field and locked/full-history rechecks passed
both controlled timing orders. Source re-review found no remaining concrete
P0/P1 in that correction; revised independent runtime is pending.
