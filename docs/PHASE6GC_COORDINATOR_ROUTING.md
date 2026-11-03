# Original-keyset coordinator routing — Phase6G-C development

This change is a prerequisite for old and fresh MPC cohorts to coexist. It does
not implement custody-fund migration, retirement or late-deposit rescue. Those
features and final whole-phase acceptance remain unfinished.

## Permanent service identity

Migration0048 adds an immutable one-to-one `MpcSolanaCoordinatorBinding` recording
the original keyset's HTTPS URL and SHA256 of the coordinator's P256 public SPKI.
An independently installed operator certificate establishes this identity; signer
Root receipts do not prove coordinator identity or storage provenance. In
particular, binding an existing Root is an explicit trusted operator assertion
of its original coordinator, not automatic discovery from remote evidence.

The forward-only `MpcKeyset.solana_coordinator_required` marker and binding must
commit together. Once admitted, the keyset cannot return to global transport,
change its routing identity or lose its row silently. Update/delete and populated
downgrade are refused. The marker is established before DKG metadata import,
including before a Root exists. A required missing binding or missing/changed
runtime configuration fails closed.

Unbound legacy keysets retain their original behavior until explicitly bound.
A configured per-keyset entry without a binding is rejected before RPC. Binding
new CREATING metadata requires original SOLANA2of3 parameters and no imported DKG,
network or signing history. Existing approved Roots require archived original
receipt pins, the original tenant and no tracked unresolved business/private work.
Common keyset/Root/operation/session/attempt locks serialize binding with allocation.
No hold is released, no private request is repeated and no ledger entry is posted.

## Installed configuration and operator action

`MPC_SOLANA_COORDINATOR_ROUTES` defaults to an empty map. Each canonical keyset UUID
selects installed files, never uploaded credentials or coordinator-supplied trust:

```json
{
  "<original-keyset-uuid>": {
    "url": "https://coordinator-a.internal:8443",
    "coordinator_certificate": "/operator/public/coordinator-a.crt",
    "ca_certificate": "/operator/public/coordinator-a-ca.crt",
    "client_certificate": "/operator/identity/custody.crt",
    "client_key": "/operator/identity/custody.key"
  }
}
```

The database stores no private key or credential file contents. The configured
coordinator leaf must be non-CA P256 with the exact coordinator role. Client
transport credentials require the Custody role. TLS credentials and CA material
are checked locally before binding/private-dispatch admission. Runtime server
certificates may renew with the same pinned identity; a different URL or public
identity cannot silently replace the binding.

For a new CREATING keyset, install its route and bind before `mpc_keyset import-dkg`:

```bash
python manage.py solana_coordinator bind \
  --keyset-id <original-keyset-uuid> --operator-ref <audit-reference>
```

For an existing APPROVED Root, first import its original receipt archive, resolve
all tracked outstanding work under the original coordinator, then bind with the
additional `--tenant-id <original-tenant-uuid>` argument. Do not install an entry
that requires a binding while unresolved work still requires legacy transport;
recover through the original configuration or independently pinned W public
recovery first. A timeout does not establish definitive failure or permit rebinding.

This is a privileged local operator workflow. It creates no tenant assignment,
customer endpoint, wallet publication, private permission or financial settlement.

## Request and recovery boundary

Root, original Claim and current-Claim collection use a keyset-scoped adapter.
Different keyset paths, different Root statements and generic private-session
paths are rejected; incorrect statements fail before signing a Custody approval.
Bound DKG import/activation fetches metadata outside the SQL transaction, then
rechecks the original route under the keyset lock. Legacy import also rechecks
admission after locking, preventing a concurrent binding from being bypassed by
a previously selected global request.

Protected financial Create and Execute capture one permanent route. Local
configuration/TLS preparation occurs before READY transitions to IN_PROGRESS and
is rechecked under the normal Root locks. The actual connection verifies TLS1.3,
CA, validity, hostname, server EKU and exact coordinator URI, then the bound public
key before any HTTP byte. Dispatch expiry remains checked after the handshake;
redirects and oversized responses remain rejected. Post-dispatch uncertainty keeps
the original IDs and hold; there is no alternate-cohort retry.

Public reconciliation selects the same Root's binding. If its route/configuration
is unavailable, it may recover from independently pinned W truth without any
coordinator request. Original-node reports, generation, binding, signature and
message ownership checks still apply. A missing coordinator response never proves
NoSignature and cannot release a reservation.

Typed Solana runtime checks retain PostgreSQL, live mode/indexing, network and
isolated development/testnet gates. Each actual coordinator/W request validates
its own transport. Generic runtime calls retain their original global transport
checks; Django startup and generic entrypoints still require a valid shared legacy
configuration. Shared Custody body-authorization credentials remain independently
required. Root-aware routing does not remove those application-wide requirements.
No production activation flag is relaxed.

## Validation status

Root local final55 focused cases39.61s pass, including39 routing cases and16
financial signing cases. Tests exercise permanent marker/row coupling, old pending
and imported-keyset rejection, unresolved holds, both metadata-import and financial
allocation lock orders, pre-CAS failure retaining READY, wrong statement/keyset
scope, and authentic synthetic W recovery without coordinator calls. Eight actual
TLS canaries count every application byte: wrong key/role/CA, expired server and
expired dispatch receive zero HTTP bytes; correct identity, redirect and response
size controls exercise the response path. These fixtures establish no MPC claim.

An intermediate genuine run passed2 cases126.826s before the final additional
statement-scope checks: two real DKG cohorts use their bound coordinator while the
global default points at the other cohort; an actual native deposit/sweep/withdrawal
flow uses the original wire and ledger, and a separate genuine signature case
recovers through W after coordinator cache/route configuration loss. Its initial
attempt failed because the test driver omitted an operator reference; that result
is retained and excluded from acceptance.

Independent validation passed338 unique PG/transport cases across qualified runs.
The first run recorded313 passes and one historical-fixture failure: the0031
migration test used today's keyset ORM against its older schema. The test-only
correction uses0031 historical Root/reservation models and their actual SQL
triggers, preserving every quarantine/history assertion. The final48-case run
passed62.767s: all24 GB cases plus22 financial-Root and2 dispatch-deadline cases.
The290 unchanged non-GB passes carry forward; this is not one338-case execution.
The original failed result remains preserved.

All3 genuine independent cases passed278.711s, zero failures/errors/skips: two
cohorts8.692s, routed native finances and witness-only recovery119.219s, and repaired
current-Claim native/SPL finances150.581s. All130 source/binary hashes remained
unchanged throughout these executions. The final manifest adds the corrected
historical test as path131; all131 hashes stayed unchanged during final48. No
production correction was made for the fixture; the genuine evidence carries
forward with that qualification. No remaining identified bounded P0/P1 was found.

Exact committed-source CI and all whole-phase gates remain required. Parent
f9f4445 Fast41696076316 passes4 executed jobs/1323 backend cases798.12s, with full
crypto unselected; it predates0048. Root-bound transport is a development
prerequisite, not fund migration, retirement or whole-phase acceptance.
