# Wallet-MPC — standing instructions for AI coding agents and contributors

This file defines the mandatory read-before-code workflow. It is guidance for work in the repository, not a bypass of human approvals or security gates.

## Required orientation (every new chat/session/feature branch)

Read README.md, docs/PRODUCT_VISION.md, docs/PROJECT_STATUS.md, docs/ROADMAP.md, docs/DECISIONS.md, docs/ARCHITECTURE.md and docs/SECURITY_MODEL.md. Consult docs/PRODUCT_REQUIREMENTS.md and docs/API_CONTRACTS.md for relevant interfaces. Inspect implementation and existing phase evidence. **Verify current main SHA, active PRs and tests; this file's snapshot is historical.**

If the user's newest explicit decision conflicts with documentation, do not silently rewrite the product. Record the change proposal and seek owner approval when it changes scope/security; respect approved user direction for the task. If a historical document says an earlier phase feature is absent, check newer merged code before inferring present absence.

## Product invariant

Build a self-hosted enterprise custody + **financial core**, not merely an MPC wallet demo. Customer segments: exchanges, payment gateways, payment facilitators, merchants and institutional operators. External order book and matching engine; wallet platform is authoritative for balances, reserves, settlement, fees, on-chain custody and events. No second ledger.

## Security and financial invariants

- Never reconstruct a customer custody private key or substitute local-key signing for genuine MPC acceptance.
- Cryptographic signer quorum is independent of human transaction approval and independent policy enforcement.
- Bind every cryptographic authorization to tenant, keyset, network/genesis, asset, exact signed intent, recipient, amount, fee policy, nonce/sequence, policy version, expiry and operation ID as applicable.
- Preserve ledger double-entry conservation, immutable financial identity, Decimal/base-unit exactness, atomic settlement and idempotency. Never credit from mere wallet balance changes.
- An ambiguous broadcast/signing outcome stays reserved and requires authoritative reconciliation. Never assume timeout means failure.
- Fail closed on uncertain network identity, incomplete history, insufficient confirmations/finality, policy or signer quorum.
- No cross-tenant access, shared authorization scope or silent mutation of populated asset identities.
- Production activation per chain is independently gated. Never infer readiness from green testnet/isolated CI.
- No mainnet/customer funds until the applicable security/operations gates have been independently accepted.

## Scope and sequence

Latest merged development checkpoint: PR #1 at
`587e0969a216102879d17cadb6ffeee8dfb8b6c6` (2026-10-28). Its tree exactly matches
reviewed head `78394fc`; final-head Fast/full passed14jobs/228calls/zero skips,
and automatic main Fast passed. Continue remaining 6G-C from this merged base.
Draft PR #2 continues from this base with a typed intent, independent public
witness and required-profile protected Solana signer. Local genuine original-
generation signing, courier, restart, backup/partial and corruption cases pass;
see docs/PHASE6GC_SOLANA_SPENDING.md. Subsequent original-identity distributed
same-key refresh and encrypted generation loading pass genuine Gen1 all-pair,
COLD, interrupted/Gen2 and independently rerun private-peer/storage-fault cases;
see docs/PHASE6GC_SOLANA_REFRESH.md. Terminal R2 NoRelease now requires original
signed requests, separate lifecycle approval, durable local cancellation and
Frozen witness proof from every actual grantee. Any durable partial or missing
evidence remains unresolved; see docs/PHASE6GC_NO_RELEASE.md. Genuine restart,
write-failure, late-permission, race, COLD and refresh/retry cases pass, including
independent review/reruns. Explicit identity/provenance migration and
share repair, issued wallets,
financial integration and whole-phase acceptance remain incomplete. Current
development source still needs its exact-final-head CI and final review.

Phase 6G-B is merged as **development** at `3d32b763ff777347f77eae7a8a7936d85dc2d770`. Phase 6G-C (Solana provisioning, key lifecycle/rotation/recovery and Hot/Warm/Cold foundations) remains incomplete. On 2026-10-28 the owner explicitly authorized merging the verified bounded development checkpoint in PR #1 and continuing the next implementation step. See the dated decision in docs/DECISIONS.md: this supersedes keeping all remaining 6G-C work in that one Draft PR; it does not complete 6G-C or authorize Phase 7 or production. Keep original Phase 7A/7B/7C, 8A/8B/8C/8D and 9. TON public network, arbitrary shards and real USDT work are **deferred**; preserve existing TON code and open audit blocker, do not activate or widen it unless owner explicitly changes scope. Bitcoin, bridging, swaps, exchange matching engine and trading order book are out of current scope.

A proposed feature is not an implemented feature. A merged implementation is not production-approved. Label every status accordingly.

## Change workflow / evidence

1. Confirm clean baseline, base/head SHAs and exact scope. Use isolated feature branch, smallest reviewable PR.
2. Review data migration/backfill and compatibility before changing ledger, ownership or on-chain identity.
3. Define acceptance and negative tests, concurrency/restart/failure/unauthorized scenarios and audit trail.
4. Run targeted Fast CI; for MPC/chain/financial-impacting changes run the required final-SHA cryptographic gate. Do not weaken expensive checks to gain speed.
5. Update docs/PROJECT_STATUS.md, docs/DEVELOPMENT_HISTORY.md and affected requirements/decisions **in the same PR** when facts change. Never mark production-readiness from development tests.
6. Supply changed files, commit SHA, CI links, migrations, residual P0/P1/P2 risks, and proof of no production flag relaxation.
7. Obtain genuine independent review for cryptographic, authorization and sensitive financial changes. The owner’s adopted Master Development Directive v2.0 authorizes development merges only after acceptance, exact-final-SHA CI, required reviews and repository rules all pass, with no blocking P0/P1. Never bypass protections or fabricate approvals. Complete and merge the current phase before advancing. Production/customer-fund activation remains separately authorized.

## Latest owner-approved Phase 7B scope

Optional, default-disabled, administrator-managed manual withdrawal address blacklist only. Audit changes, recheck before execution and at independent signer authorization, fail closed for unavailable enabled policy, and preserve reservations/history. No deposit screening, deposit holds, external AML/KYT services or automatic address feeds. Preserve unrelated financial/finality/security controls. This is a planned feature, not existing enforcement.

## API-first design guard

Separate API identities and permissions for tenant/customer, exchange engine, merchant, operator, compliance, and signer. Matching-engine credentials only access narrow order-reserve/settlement authority, never generic balance mutation or arbitrary signing. Signed, durable, replayable outgoing event delivery is required. Stable schemas and backwards-compatible versioning are part of acceptance.

See docs/DOCUMENTATION_GOVERNANCE.md for conflict resolution and required documentation updates.
