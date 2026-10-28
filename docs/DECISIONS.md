## 2026-10-28 — owner-authorized verified development checkpoint merge

The owner explicitly instructed: «چرا مرج نکردی؟ اگر صحیح است و همه چیز درست هست
مرج کن و برو گام بعدی» (merge the current work if it is correct and proceed to the
next step). This authorizes merging the independently reviewed bounded development
checkpoint in PR #1 once its required final-head gates and repository rules pass.
It supersedes the earlier instruction to retain all remaining 6G-C work in one
Draft PR. Keep the original nine-phase numbering and continue the remaining 6G-C
implementation in subsequent reviewed PRs; do not advance to Phase 7 yet.

Scope accepted for this checkpoint: the owned RustCrypto integration and original
store compatibility, standard seeded Solana primitives, original custody/signer
approvals and historical-quorum fences, immutable operator tenant/principal
registry, and durable owner/network/asset/index root/claim reservations. These
are development foundations. Customer issuance, seeded spending, financial
integration, active generation/witness, refresh/repair/rotation/drain/late-deposit
rescue and class isolation remain unfinished. No feature acceptance is inferred
from a merge, and production/mainnet/customer-fund restrictions remain unchanged.

All required Fast/full checks must validate the actual final PR head. Preserve
genuine independent review, no blocking P0/P1, normal repository merge rules,
post-merge verification and truthful remaining-work status. This exception changes
the delivery granularity, not any cryptographic, financial or activation gate.

## 2026-10-27 — authorized maintained RustCrypto integration remediation

After the incompatible RUSTSEC-2026-0387 resolver investigation, the owner
explicitly approved investigation/migration with independent review. Maintain a
small, explicitly owned generic-ec-curves 0.2.4 integration port to maintained
RustCrypto 0.14 / patched crypto-bigint 0.7, preserving original CGGMP, HD and FROST
protocols, original serialized identities/stores and nonce/replay controls. Record
upstream integrity/licensing and the complete local patch delta. Unsupported
adapter curves fail closed. Replace the patch with a compatible maintained
upstream release when available; do not suppress scanners or rewrite local
constant-time arithmetic. Require genuine original-store compatibility,
independent review and exact-head full gates before acceptance. See
[scope and evidence](PHASE6GC_DEPENDENCY_GATE.md). No production/phase merge is
implied by dependency remediation.

# Architecture and product decisions (ADRs in compact form)

**Authority:** owner-approved choices, backed by explicit user discussions and implementation evidence. The entries below are durable decisions; newly suggested extras remain proposals until approved. Each material change should append a dated supersession, not quietly rewrite history.

## Accepted — 2026-10-11

| ID | Decision | Consequence |
| --- | --- | --- |
| D-001 | Wallet-MPC is self-hosted API-first enterprise custody **and financial operations** platform. | Signer-only implementation does not satisfy product completion. |
| D-002 | One authoritative append-only double-entry ledger; on-chain data is evidence. | No second wallet/merchant/trade balance source of truth. |
| D-003 | Exchange order book and matching engine are external services. | Narrow authenticated exchange reserve/settlement/event API; no embedded matching. |
| D-004 | Human multi-approver, business policy engine and MPC signer quorum are independent. | Require authorization separation and eventual signer-side checks. |
| D-005 | Support EVM, TRON, Solana as independently activatable families; keep TON isolated scope for now. | TON public Mainnet/sharding/USDT deferred; do not allow this to delay the other production readiness streams. |
| D-006 | Preserve original nine-phase plan, with 7A/7B/7C and 8A/8B/8C/8D subpackages. | Next is 6G; no invented 6F-E phase. |
| D-007 | Prefer broad safe operational customizability. | Expose per-chain/asset/risk finality policy, treasury/gas/batch rules, approvals; never weaken security floor via UI. |
| D-008 | Multi-tenant exchange/merchant use is a binding target. | Per-tenant ledger ownership, API credentials, policy and reporting boundaries need dedicated design. |
| D-009 | Keep Bitcoin, bridge/cross-chain swap, staking, advanced conversion and matching infrastructure outside required release scope. | Optional proposals only, separate authorization. |
| D-010 | Merge of successful isolated acceptance is development completion, not production acceptance. | Independent per-chain production gates and audit remain mandatory. |

## Explicit current deferral: TON

Phase 6F-C/6F-D previously documented eventual public TON parity as a mandatory production deliverable. The owner subsequently decided **not to let TON public-network work delay the remaining roadmap**. Accordingly, TON V5R1/native/reference Jetton isolated integration and tests remain in main; the public-network work, real TON USDT and dynamic shard support are **deferred, requiring renewed explicit authorization**, and TON must not be marketed as production-ready. This is an explicit change of schedule/priority, not evidence that previous safety blockers are solved. Retain external audit correspondence P1 OPEN.

## Proposed, not yet approved as mandatory launch scope

Staking/earn, cross-chain/bridge/swap, high-frequency market-data integrations, cross-venue collateral/liquidity routing, OTC special flows, third-party exchange connectivity, auto-conversion, hosted white-label branding and public proof-of-reserves. These are design opportunities, not roadmap commitments.

## Decision change procedure

Phase 6G first-slice engineering choices are submitted for independent review in
[PHASE6G.md](../PHASE6G.md): dedicated root/network/deployment-owner/DEPOSIT
namespace, monotonic non-hardened `m/0/index` reservations and no address issuance
before genuine child attestation/signing acceptance. These are branch-level
implementation choices within the authorized Phase 6G, not new product phases
or production approvals. Solana seeded accounts, persistent derivation and full
key lifecycle remain alternatives/requirements for subsequent reviewed slices.

Record ID/date/requester/reason, alternatives considered, scope impact, security and migration impact, work package, approved-by and evidence. If a new request affects established goals, update PRODUCT_VISION, PRODUCT_REQUIREMENTS, ROADMAP and PROJECT_STATUS together, then review in a separate PR where feasible.

## Authorized Phase 6G-B implementation decisions

The owner's current direction supersedes historical small-slice suggestions:
exactly 6G-A (#36 merged), 6G-B complete EVM/TRON child custody, and final 6G-C.
Use original CGGMP24 HD material and pinned upstream SLIP-10/set_derivation_path;
never fill historical chain-code gaps. All three original stores approve a child;
two of three sign. Separate immutable custody accounts from asset-specific legacy
wallet rows, with no balance reconstruction. Namespace remains a trusted deployment
boundary; existing global customer ledger principals are preserved. Account claims
commit before external work and can recover only their original reservation.
Independent production review and Phase 7 policy authority remain separate.


## 2026-10-27 owner directive v2.0 — superseding workflow and risk scope

- **D-011:** The owner explicitly adopted the supplied Custody Master Development Directive v2.0. Conditional autonomous development merges replace the prior manual-merge-only workflow. All required acceptance, exact-final-SHA CI, independent reviews, migration assessment and repository rules remain mandatory; no admin bypass. A phase must be merged and validated before the next starts. Production activation and real-fund operation remain separately controlled.
- **D-012:** Phase 7B is an optional default-disabled, manually managed withdrawal-only address blacklist. No deposit screening/blacklist holds, external AML/KYT integrations or address feeds. Preserve unrelated freezes/holds/limits and financial correctness. Enforce before signing/execution and at independent signer authority with policy-version/race controls. This supersedes external AML plugin requirements, not existing financial-security controls.
- **Proposed implementation direction (not a new owner-selected architecture; review pending):** Phase 6G-C uses existing standard Solana seeded System-account and separately attributed classic SPL-account primitives under genuine FROST authority as its provisioning candidate. This is not Ed25519 HD or a new cryptographic protocol. Public allocation requires complete genuine validator/attribution/economic acceptance; the candidate is not implemented yet. FROST refresh/repair needs authenticated immutable epochs and rollback protection. Unsupported CGGMP core-share resharing remains explicit; fresh-root migration must not be mislabeled resharing.

Historical final review dispositions and upstream workflow outcomes are now verified through GitHub API and qualified in INITIAL_REPOSITORY_AUDIT.md. Fork Actions execution is now restored; new crypto-bigint RUSTSEC-2026-0387 blocks the security gate. A crypto-backend integration migration is only proposed and awaits explicit owner input; no dependency patch is adopted. See PHASE6GC_DEPENDENCY_GATE.md. No external cryptographic audit or production approval is implied.
