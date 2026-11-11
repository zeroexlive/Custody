# Durable local allocation pause — Phase6G-C development

Migration0049 records an immutable original Root, caller-owned pause UUID and
exact allocator frontier. This is a backend fence before inventory export, not
a W freeze, complete inventory, stable balance, movement or retirement proof.
Original ownership, indices, aliases, receipts and financial membership persist.

## Operator action

New pauses require PostgreSQL, the existing isolated runtime gates and
`MPC_SOLANA_ALLOCATION_PAUSE_ENABLED=true` (default false):

```bash
python manage.py solana_allocation_pause \
  --keyset-id <original-keyset-uuid> --tenant-id <original-tenant-uuid> \
  --pause-id <durable-pause-uuid> --operator-ref <audit-reference>
```

The privileged local action verifies the original approved Root and receipt
authority, and commits pause plus audit atomically. It makes no remote request
and owns no Life/Policy key. Exact retries survive entry disable; conflicting
IDs fail. Root APPROVED and wallet ACTIVE/PENDING keep their historical meanings.
No release/delete action exists. A future reviewed forward lifecycle must verify
W state and preserve history before introducing release. Populated downgrade fails.

## Concurrency and recovery

Pause birth locks keyset then Root under READ COMMITTED and checks the frontier.
Tracked HELD source/incoming work, including zero-principal SPL fee/rent work and
retained NoSignature holds, blocks admission. Unresolved sessions, completed
sessions without matching immutable final effects and generic source-keyset
signing history also block. This checks backend history, not all work known to W.

The operation-birth trigger precedes existing source-only locks. It locks all
involved keysets in order, then Roots in order, and checks persisted pauses.
Incoming classification includes treasury Claim FK, exact known Claim addresses
and Root bases. Pause admission uses the same classifier. A HELD incoming
operation prevents destination pause for its entire lifetime, allowing subsequent
session/private guards to retain source-only locks. Pause scans take no subordinate
row locks, avoiding inversion with raw UPDATE session/attempt locks. Before its
absence scan, pause admission also takes a NOWAIT SHARE ROW EXCLUSIVE lock on the
operation table. This excludes invisible writers whose destination alias became
known after their initial classification. A reproduced two-transaction regression
failed before this fix6.18s and passes after5.91s; logs are retained. The final35-case
run includes the fix. This rare operator action may require retry even during an
unrelated Root's financial operation write. Only the pause transaction fails;
the existing writer is preserved.

SQL fences new Claims, operations, sessions, preparation, policy acceptance,
dispatch and counter advances. VOLATILE statements see preceding writers after
lock waits; stale isolation fails. Entry disable cannot remove persisted fences.
Exact Claim retries preserve indices. Already-reserved public approvals can finish
under their separate W gates. Public recovery and original settlement keep their
own proof/hold rules. External deposits remain possible. There is no second ledger.

## Bounded evidence

Root35 actual PG cases pass51.90s, covering both allocation race orders, invisible
old snapshots, raw writes, retained holds, SPL initializers, immutability, audit
rollback and downgrade. Initial4 failures attempted an immutable WithdrawalRequest
fixture mutation; a new separately reserved parent fixes setup without relaxing rules.
One root genuine two-cohort case, before only the NOWAIT hardening, passes15.00s, using actual three-party FROST DKG and
authentic Root/Claim receipts. Old allocation stays fenced across connection
replacement/entry disable; exact retry works and the fresh cohort still allocates.
All six encrypted shares, original receipts and ledger count remain unchanged.
It performs no migration. Independent19-module backend coverage passes618 cases
948.22s, zero failures/errors/skips; lint/format/diff checks pass. Four genuine
cases pass307.541s: new pause13.207s, original cohorts6.208s, routed native
financial/W-only recovery125.549s and repaired native/SPL financial162.233s.
All174 paths (170 source/test/helper/workflow/manifests and4 binaries) remain
unchanged. No concrete bounded P0/P1 or blocking P2 was identified. Independent
runs had no failures/retries. See [public evidence](evidence/phase6gc-allocation-pause-local.json).
Exact-source CI remains pending after commit; this is not whole-phase acceptance.

Parent473d86a Fast[42704314910](https://github.com/zeroexlive/Custody/actions/runs/42704314910)
passes4 jobs/1364 backend cases807.77s, predating0049; not ALL. Actual migration,
fee accounting, retirement/rescue and final whole-phase gates remain unfinished.
