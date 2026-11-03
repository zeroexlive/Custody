# Wallet-MPC

**Self-hosted, API-first digital-asset custody and financial platform** for cryptocurrency exchanges, payment gateways, payment facilitators, merchants, and institutional operators.

**Status (2026-10-28):** Phase 6G-C remains incomplete. [PR #1](https://github.com/zeroexlive/Custody/pull/1) merged its verified development foundations as `587e0969a216102879d17cadb6ffeee8dfb8b6c6`; final-head Fast/full and main Fast passed. Remaining 6G-C implementation continues from that merged base; see [current evidence/status](docs/PROJECT_STATUS.md) and the [dated merge decision](docs/DECISIONS.md). Existing EVM, TRON, Solana and TON integrations have genuine isolated-development acceptance, **not production/mainnet authorization**. TON stays at its currently accepted isolated scope until explicitly reprioritized. No customer funds or production withdrawal activation is authorized by these documents.

This is more than an MPC signing service. The target system combines a single authoritative double-entry ledger, a transaction/custody engine, independent MPC signers, human authorization, treasury operations, exchange settlement APIs, merchant payments, risk controls, and operator/developer interfaces. External exchange matching engines and order books remain separate systems.

## Source of truth: reading order

1. [AGENTS.md](AGENTS.md) — mandatory instructions for contributors and coding agents.
2. [Product vision](docs/PRODUCT_VISION.md) — binding scope, customers, commitments and non-goals.
3. [Product requirements](docs/PRODUCT_REQUIREMENTS.md) — capabilities, priority, states and acceptance.
4. [Architecture](docs/ARCHITECTURE.md) — trust boundaries and subsystem ownership.
5. [Roadmap](docs/ROADMAP.md) — original nine phases and work packages.
6. [Project status](docs/PROJECT_STATUS.md) — current merge anchor, blockers and next work.
7. [Development history](docs/DEVELOPMENT_HISTORY.md) — evidence-linked milestones and PR history.
8. [API contracts](docs/API_CONTRACTS.md) — **target** integration contracts, not implemented endpoints.
9. [Security model](docs/SECURITY_MODEL.md) — signing vs human approvals, authorization and gates.
10. [Decisions](docs/DECISIONS.md) — accepted decisions vs proposals and deferrals.
11. [Documentation governance](docs/DOCUMENTATION_GOVERNANCE.md) — update rules, evidence and conflict resolution.

## Existing implementation evidence

- [Operator identity registry](docs/PHASE6GC_IDENTITY_REGISTRY.md) — immutable tenant/customer mapping with PostgreSQL and audit guards; external authorization and financial integration remain incomplete.
- [Authoritative Solana reservations](docs/PHASE6GC_SOLANA_REGISTRY.md) — durable tenant/owner/asset allocation and three-store approvals; wallet issuance and spending integration remain incomplete.
- [Seeded Solana intent contract](docs/PHASE6GC_SOLANA_SPENDING.md) — the next development branch's public structure/wire checks; authenticated nonce/signing integration remains incomplete.

- [Phase 6G-C seeded Solana foundations](docs/PHASE6GC_SOLANA_SEEDED.md) — wire/spendability primitives, authenticated root/claim records and three-store receipt collection; customer issuance and lifecycle remain incomplete.
- [Authoritative ledger](LEDGER.md), [chain adapters](CHAIN_ADAPTERS.md), [token custody](TOKEN_CUSTODY.md), [native transaction lifecycle](NATIVE_TX_LIFECYCLE.md).
- [Self-hosted MPC](SELF_HOSTED_MPC.md) and the [Rust-side protocol docs](mpc-side/).
- [EVM](PHASE6E.md), [TRON](PHASE6F-A.md), [Solana](PHASE6F-B.md), [TON](PHASE6F-C.md), and [integrated four-chain acceptance](PHASE6F-D.md).
- [PR #34](https://github.com/hassan-anari/Wallet-MPC/pull/34) and [its final cryptographic gate](https://github.com/hassan-anari/Wallet-MPC/actions/runs/38129567244).

Historical phase documents describe their own implementation dates and may contain **superseded forward-looking claims**. Read the status/decision documents for present-day scope, then verify actual behavior in code. Documentation approval is not deployment authorization.
