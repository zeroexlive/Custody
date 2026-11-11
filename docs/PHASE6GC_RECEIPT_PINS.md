# Per-Root original receipt pins — Phase6G-C development prerequisite

This is the receipt-trust prerequisite for fresh-DKG cohorts. Fund migration,
protected rotation, retirement and late-deposit rescue are not implemented by
this change. All production and customer-fund activation gates remain closed.

## Trust and compatibility

Original Solana Root and original Claim receipts previously always used the
single installed `MPC_HD_SIGNER_CERTIFICATES` map. A different signer cohort
cannot replace that map without losing verification of the old receipts.

Migration0047 adds immutable one-to-one `MpcSolanaReceiptPins` public DER archives.
Every original Root/Claim verifier selects the exact stored original Root/keyset
statement before using its archive. No-row legacy validation retains its original
global pin behavior. A malformed archive fails closed; a Root that reserved pins
at creation also fails closed if its archive is missing. Existing pending Root
retries validate reserved pins before any enrollment RPC.

Initial trust comes only from independently installed operator public certificate
files. Each snapshot requires exactly three distinct P256 keys, canonical bounded
DER leaves, exact signer role URIs and explicit non-CA BasicConstraints. Embedded
coordinator evidence never establishes new trust. Receipt verification remains
archival: transport certificate expiry does not expire existing signatures. Live
TLS authentication continues to enforce its own validity and trust checks.

Original statements, signature domains, receipt bytes, DKG identity and encrypted
shares stay unchanged. Historical current-identity Claims continue to use their
separate Lifecycle-authorized Prepare context; these original pins do not replace
or rebind that authority. ECDSA/HD and TON receipt behavior remains unchanged.

## Operator workflow

The default-empty `MPC_SOLANA_ROOT_SIGNER_CERTIFICATES` configuration maps canonical
original keyset UUIDs to the three installed signer certificate paths:

```json
{
  "<original-keyset-uuid>": {
    "signer-a": "/operator/public/cohort-B/signer-a.crt",
    "signer-b": "/operator/public/cohort-B/signer-b.crt",
    "signer-c": "/operator/public/cohort-B/signer-c.crt"
  }
}
```

For a new Root with an explicit map entry, reservation captures those public
identities before remote enrollment. The original Root records an immutable
`receipt_pins_reserved` flag. A deferred SQL constraint requires the snapshot and
Root to commit together. An old pending Root cannot enable that flag, even after
a no-op UPDATE; a new flagged Root cannot commit without its snapshot. Subsequent
configuration changes do not change its receipt authority.

An existing APPROVED Root requires an explicit archival import before global pins
are changed. The operator may configure that keyset's entry or use its still-valid
original global map, then run:

```bash
python manage.py solana_provisioning archive-pins \
  --keyset-id <original-keyset-uuid> \
  --tenant-id <original-tenant-uuid> \
  --operator-ref <audit-reference>
```

Import independently verifies the original Root and all approved original-domain
Claims under the installed identities. It locks keyset, Root and Claims, then
commits the archive and audit atomically. Claim approval re-verifies returned
receipts under its final Claim lock, so import and approval cannot cross their
verification/commit boundary. An invalid Claim or audit failure rolls back import.
An existing identical archive is idempotent and needs no installed file paths.

Unknown legacy PENDING enrollment cannot adopt new pins. Recover its original
operation and identities first; do not delete, reassign or synthesize approval.
Archives cannot update/delete, and populated0047 downgrade is refused. The command
is a privileged local operator workflow, not an external IAM or customer API.
It issues no wallet, releases no reservation and posts no ledger transaction.

## Validation and remaining work

Root validation passed40 new PostgreSQL/P256 cases19.96s and149 affected legacy
cases117.48s, zero failures/errors/skips. Both import/approval lock orders, parallel
idempotent import, malformed/missing pins, old pending adoption, nested savepoint,
SQL immutability, downgrade and audit failure are exercised. P256 service fixtures
are synthetic and establish no MPC acceptance by themselves.

One genuine two-cohort test passed8.44s, with two independent three-node FROST DKGs,
distinct group/DKG identities, TLS and wrapping keys. It imports the old original
Root/Claim archive, reserves new-cohort pins before actual enrollment, verifies
both archives without global/config pin paths, rejects cross-Root evidence and
preserves all six original encrypted shares and the ledger. All124 source/binary
hashes remained unchanged before/after. This case establishes original-receipt
trust, not protected spending, fund migration or retirement.

Independent frozen-source validation passed189 PostgreSQL/backend cases135.216s
and2 genuine cases158.945s, zero failures/errors/skips. The two-cohort case passed
7.888s; the repaired-node current-Claim native/SPL financial flow passed150.858s,
verifying that the original archive lookup preserves the separate current authority.
All124 hashes (120 source/fixture/workflow files and4 binaries) stayed unchanged
before/after. No remaining identified bounded P0/P1 or concrete P2 gap was found.
Exact f9f4445 Fast41696076316 passes4 executed jobs, including1323 backend
cases798.12s; ten full-crypto jobs were unselected. This predates routing0048. The prior0046 checkpoint f58d219 Fast41624031631 passed4 executed
jobs/1283 backend tests785.63s; ten full-crypto jobs were unselected. Whole-phase
Fast/ALL/original3d32 compatibility, independent acceptance, conditional merge and
main verification remain open. Root-bound coordinator routing is the next
prerequisite; the single global coordinator URL has not been replaced here.
