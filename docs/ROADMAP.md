> **Verified dependency update (2026-10-27):** The controlled RustCrypto migration
> passed exact-head Fast/full CI at `ea4bb4ed` (14/14 jobs; 219 scenario calls, no
> skips), with independent evidence review. The earlier failing dependency state
> below is historical. Phase 6G-C remains IN PROGRESS; later work requires
> final-head gates and complete phase acceptance.

# Approved nine-phase roadmap and product work packages

The owner explicitly authorized merging the verified bounded PR #1 development
checkpoint and continuing remaining 6G-C work; see the [2026-10-28 decision](DECISIONS.md).
The earlier single-Draft-PR restriction is superseded for delivery granularity.
No Phase 7 advance, phase completion or production activation is authorized.

Checkpoint `1d4737e` passed exact-head Fast/full (14 jobs, 228 calls, zero skips)
with independent artifact review; whole 6G-C remains incomplete. Operator
tenant/principal registry work has 47 passing PostgreSQL cases and independent
review, preserving legacy identity and SQLite demo migration compatibility. It
does not complete external authorization, wallet issuance or financial linkage;
new source needs its own gates. Subsequent authoritative Solana root/claim records
bind tenant/principal/network/asset/index before genuine three-store approvals;
48 PostgreSQL cases and one real FROST/Agave integration pass (758 full backend
cases). They create no
issued wallet or spending grant. See [scope](PHASE6GC_SOLANA_REGISTRY.md).

Unmerged 6G-C now includes signer-local authenticated initial FROST root dedication
and monotonic owner/mint/index/retry approvals, with exact receipt recovery and
legacy-signing fencing. Five genuine positive/negative/restart/concurrency cases
and a separately rerun approvals case pass. See [bounded evidence and remaining
scope](PHASE6GC_SOLANA_SEEDED.md). Customer issuance, tenant identity, seeded
spending grants, chain validation, epochs/rollback protection and class isolation
remain incomplete; no subsequent roadmap phase or production activation begins.

The coordinator now collects all three original enrollment/claim receipts and
custody verifies separate Solana receipt domains against archival HOT signer
pins. Six genuine store/agreement cases and38 existing backend provisioning cases
passed with independent source review; final-head gates remain required. This
does not complete customer issuance, epochs/lifecycle or the whole6G-C scope.

Further review added historical-quorum preflight and durable pending-root fencing
against concurrent generic signing. Seven genuine cases pass, including b/c-only
history with unused a and older coordinator metadata. Inventory227 and new-head
gates are required; this coordinated-API correction does not implement a global
Byzantine lease, witness, customer issuance or phase completion.

**Historical pre-merge anchor (2026-10-27):** `zeroexlive/Custody` main `3d32b763ff777347f77eae7a8a7936d85dc2d770` contains Phase 6G-B. A and B are IMPLEMENTED (DEV); C is IN PROGRESS on an unmerged branch, with complete acceptance still outstanding. Phase 7A/B/C, 8A/B/C/D and 9 are PLANNED. TON public scope remains DEFERRED; explicit non-goals remain OUT OF SCOPE. See INITIAL_REPOSITORY_AUDIT.md. Draft PR #1 exists and GitHub API connectivity is restored. Fork Actions executes; the original RUSTSEC-2026-0387 failure was remediated by the explicitly authorized owned backend port at checkpoint ea4bb4ed, with exact-head Fast and all14 full-gate jobs passed. Later signer changes require fresh gates. Merge remains blocked on unfinished whole-phase acceptance; see PHASE6GC_DEPENDENCY_GATE.md. Branch summary reports main unprotected and rulesets empty; required gates remain mandatory. No phase merge is claimed.

## Phases already delivered in development

| Milestone | Primary merged evidence | Status |
| --- | --- | --- |
| 1 Stability | PR #1 | Development baseline |
| 2 Authoritative ledger | PR #2 | Development implementation |
| 3 Chain registry/adapters | PR #3 | Development implementation |
| 4 Native outbound lifecycle | PR #8 | Development implementation |
| 5 Fungible token foundation | PR #14 | Development implementation |
| 6A MPC foundation | PR #25 | Development implementation |
| 6B mTLS transport | PR #26 | Development implementation |
| 6C.1 FROST DKG | PR #27 | Development implementation |
| 6C.2 FROST signing | PR #28 | Development implementation |
| 6D CGGMP ECDSA | PR #29 | Development implementation |
| 6E EVM integration | PR #30 | Isolated/testnet acceptance |
| 6F-A TRON/TRC-20 | PR #31 | Isolated acceptance |
| 6F-B Solana/classic SPL | PR #32 | Isolated acceptance |
| 6F-C TON V5R1/reference TEP-74 | PR #33 | Isolated acceptance only |
| 6F-D four-chain integrated custody | PR #34 | Isolated integrated acceptance |

## Remaining order — do not renumber

### Phase 6G — Scalable wallet provisioning and key lifecycle (IN PROGRESS)

Chain-specific **genuine** distributed address provisioning/derivation, keyset scopes and account bindings, Hot/Warm/Cold foundations, signer node/key lifecycle, new root and child lifecycle, auditable rotation, resharing/recovery and tested failure behavior. Explicitly evaluate performance and key security per algorithm, do not infer FROST and ECDSA can use identical HD derivation. Add schema and tenancy extension points, but do not implement all merchant/trade product APIs early.

Authorized delivery is exactly three major PRs: **6G-A PR #36 merged** for root
registration/reservations; **6G-B (#37 merged at the current anchor)** for genuine EVM/TRON HD issuance and
child signing; **6G-C final** for Solana scalable provisioning, lifecycle,
rotation/recovery and Hot/Warm/Cold foundations. Do not split B into additional
PRs or add roadmap phases. Phase 7/8 exclusions remain.

Gate: no private-key reconstruction, measurable high-volume provisioning, durable identities, no cross-root replay/rebinding, key-loss and restart acceptance, final-SHA CI.

### Phase 7A — Governance and human authorization

RBAC/MFA, multi-person transaction and policy approvals, immutable approval records, policy precedence and USD value freshness; request/approver separation and account/tenant scoping. Implement API/backend then UI in Phase 9. Human quorum distinct from MPC quorum.

### Phase 7B — Risk controls and optional withdrawal blacklist

Optional default-disabled, manually administered withdrawal-destination restrictions, network-aware canonicalization, audited configuration/entry changes and request/execution/independent-signer enforcement. Enabled policy lookup failures fail closed for new signing; disabling preserves entries, audits and reservations. Incoming deposits, sender handling, indexing, confirmation and crediting remain unaffected. No external AML/KYT providers, address feeds or automatic scoring. Preserve unrelated account freezes, limits, financial holds and security controls. This module is not regulatory compliance certification; it remains unimplemented.

### Phase 7C — Signer-side authorization and security evaluation

Independent signing authorization rooted outside a compromised backend's unilateral power; canonical intent/policy-bound tickets, signer verification, security audit and targeted penetration testing. Security findings are tracked to closure or explicitly accepted under the release governance process, never hidden behind CI.

### Phase 8A — Production infrastructure and chain activation

Independently hosted signer security domains, PKI/rotation, backup/restore/disaster recovery drills, secrets, network egress, high availability, forensic logging, production RPC provenance, archive capacity, safe deployments and independent *per-chain* mainnet enablement gates. EVM/TRON/Solana must be independently activatable. **TON public-network work is deferred at owner direction**; do not require TON Mainnet to release other supported chains. Do not treat isolated tests as mainnet proof.

### Phase 8B — Treasury, Gas, Batch

Hot/Warm/Cold liquidity policies, automatic sweeps/refills, fee/cost optimization, independently authorized cold release, batch payouts with partial outcome reconciliation, operational budgets and economic benchmarks.

### Phase 8C — Exchange and merchant financial platform

All ten Exchange Financial API families in API_CONTRACTS.md, tenant-scoped ledger/reservations/trade settlement, merchant onboarding/payment invoices/late/partial/excess/unknown payment cases, refunds/fees/merchant settlements and durable events/webhooks. API backend and contract tests in this phase; advanced UI in Phase 9.

### Phase 8D — Reporting, reconciliation and incident operations

Three-way chain-wallet-ledger reconciliations, asset-vs-liability snapshots, daily close, missing deposits, payout ambiguity, confirmed finance reporting, suspense handling, immutable audit exports, operational cases, alerting and incident response.

### Phase 9 — Product UIs, DX and complete end-to-end validation

Operator/Security/Treasury/Compliance/Merchant/Developer panels, API portal/SDK/documentation, policy editing and simulation UX, monitoring dashboards, E2E exchanges and payment-gateway workflows, load/chaos/restart and production-readiness evidence. UI/API features must already have backend acceptance, not be mere placeholders.

## Deferred and dependency policy

TON Mainnet global -239, validator transitions, dynamic shard split/merge, deployed real Jettons incl independently verified USDT and broad archival trust are **not part of upcoming 6G/7/8 default execution** unless explicit owner approval. Maintain P1 TON audit blocker and never enable public funds. No Phase 6F-E. No Bitcoin, matching engine, bridge or swap by default. Optional innovation must not displace required financial controls.

Each work package can span reviewable PRs; no big-bang implementation. A milestone is DONE only after code/docs/test evidence is merged; PRODUCTION APPROVED requires the separate per-chain and organization gate.
