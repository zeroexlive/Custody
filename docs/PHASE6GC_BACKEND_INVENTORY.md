# Paused backend source inventory — unmerged development

This handoff accounts for every original reserved index under an immutable0049
pause. Migration0050 stores a source snapshot, one entry per original Claim and
separate immutable witness query leases. It exports data for independent rotation
approval. It issues no Life command, private permission, financial membership,
transaction, credit or ledger posting. Movement and retirement remain unfinished.

New snapshots require explicit `MPC_SOLANA_ROTATION_INVENTORY_ENABLED=true`
(default false), PostgreSQL and the existing isolated Solana runtime gates.
Disabling entry preserves existing snapshots and their public completion paths.
Original Root/Claim receipts, statuses, owners, aliases, publication/initialization
IDs and ledger records are retained. No local reset or populated downgrade exists.

The snapshot captures local state before observing W. PENDING and ACTIVE are
historical publication records, not liveness. Each W result is authenticated
separately; DB APPROVED does not imply W registration, and a W grant does not
promote a local PENDING wallet to ACTIVE. Mode-off grants remain LegacyControl;
unissued addresses remain Unpublished, including pending local financial wallets.

Known customer/treasury roles are preserved. Unclassified legacy principals need
explicit read-only role declarations; these do not create principal financial
roles or wallet membership. Capture uses0037's principal KEY SHARE lock to
serialize role absence with classification birth. Entry acceptance and sealing
recheck known roles. A conflicting later classification requires a new snapshot,
preserving the earlier record. Future movement must recheck current role/liveness.

ROOT, ENTRY and SEAL queries each commit a new nonce and original15-second
deadline before transport. No nonce or deadline is renewed. A header requires
the exact original Root in Frozen with no prepared generation. All entries and
the final seal must observe that same RootView, including revision, generation,
package, roster and financial mode. A registered source needs its exact original
alias occupants, index below W's frontier, independently verified Claim evidence
and canonical evidence fingerprint. A missing grant cannot hide prior publication.

Captured positive issuance/publication proofs are reverified, including original
customer-wallet identity and owned SPL initialization/publication provenance.
Read-only historical validation permits disabled deposit/token capabilities;
ordinary validation and the native chain/runtime/network guards remain strict.
Pending recovery never fabricates a positive publication proof.

SQL mirrors captured records, protects their identity and validates query/subject
atomicity and commit-time expiry. Source keyset/Root locks precede snapshot/entry/
query locks. SQL uses NOWAIT for conflicting Root ownership to avoid raw UPDATE
lock inversion; callers retry without changing original IDs. Source principal
locks are shared with compatible customer readers. Original partial snapshots,
expired challenges and accepted replies remain durable.

Export revalidates archival proofs and returns contiguous source slices capped at
32 entries and128KiB, reducing the count when needed. Sealing computes the complete
inventory fingerprint using the existing Rust canonical domain; export revalidates
its page proofs and retains that immutable complete fingerprint. These slices are
not W commands: exact current source/target context, complete-plan approval,
destination membership, budgets and actual private admission remain W/Policy
and later movement responsibilities. No stable chain balance is asserted.

Privileged `solana_rotation_inventory` provides `begin`, `query`, `accept` and
`export`, with explicit snapshot/tenant/operator IDs. `begin` also takes pause ID
and optional public role-declaration file. `query` selects ROOT/ENTRY/SEAL and an
entry index when applicable. `accept` requires the original challenge and bounded
signed public evidence file. `export` selects the next original source index.
The operator relays public queries through the independently pinned W workflow.
No Life/Policy private key is loaded by this command.

Root final focused evidence:164 cases456.19s pass, including28 inventory,
33 issuance,39 wallet and64 SPL initialization cases. Earlier117/25-case results
remain qualified to their earlier snapshots. One genuine1000-entry case passes157.82s:
one registered source retains pending financial publication,999 actual backend
allocations remain unpublished, connection/W restart succeeds, and original
shares/receipts/ledger stay unchanged. This is not1000 wallet publication or
movement acceptance. Final root32 inventory cases pass52.94s after environment resume; a lost zero-output
run is not counted. Repaired ACTIVE native/SPL runtime passes176.38s. Its initial
203.04s failure was a helper-only Group.root lookup after the financial flow; it
now uses the immutable original wallet Root FK. Full307-case crypto collection
passes (not execution). Final independent168 cases381.863s and2 genuine cases354.981s pass, with no
failures/errors/skips. Actual1000 backend case185.009s exports32 slices;
repaired ACTIVE native/SPL case169.632s covers5 Claims. All180 final-baseline
paths (176 source/test/helper/workflow/manifests and4 binaries) remain unchanged.
A coordinated helper-only formatting fix after the first format check is retained
as an exact, independently reconstructed AST-equivalent delta; all other179 paths
stayed unchanged and the final180-path runtime baseline is stable. No concrete
bounded P0/P1 or blocking P2 was identified. See
[public evidence](evidence/phase6gc-backend-inventory-local.json).
Exact-source CI remains pending after commit; no whole-phase approval follows.

Parent87b8abf Fast42761045014 passes4 jobs/1399 backend tests844.20s. It predates
0050 and selected no full crypto. Whole-phase final-SHA Fast/ALL, fixed original
encrypted-store compatibility and independent phase review/merge remain open.

Before movement/retirement, W admission must additionally prove coverage of all
retained same-Root staged candidates and prior staged frontiers, including
abandoned plans. The current backend snapshot proves its durable local frontier;
a database restored before an old allocation cannot establish global completeness
from W's registered frontier alone. Permanent alias fences prevent reassignment,
but do not themselves prevent omission. Strengthen forward W staging/sealing and
reconcile such restored history before adding private movement or retirement;
preserve the exact original signed old-rule replay. Current staging grants no
movement, and0050 exports data only, so this remains an explicit next-step gate.
