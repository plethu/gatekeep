# User-to-user blocking and timed restrictions

This synthetic platform example applies a directed “Alice blocks Bob” relation,
checks both directions before a new user interaction, and gives an individual
account restriction its own deadline. Keepsake lifecycle state, Gatekeep policy
evaluation, application records and Dovecote events share one PostgreSQL transaction.
It uses local source dependencies across the three sibling checkouts. Use the
sibling revisions pinned in `.github/workflows/ci.yml` to match its lockfile.

Use a **dedicated disposable database**, with the schema owned by the fixture
role. Setup installs schemas and adds a fresh synthetic tenant on every run;
it does not delete existing records. From this directory:

```sh
DATABASE_URL=postgres://USER:PASSWORD@localhost:PORT/DATABASE cargo run --locked
DATABASE_URL=postgres://USER:PASSWORD@localhost:PORT/DATABASE cargo test --locked -- --ignored
cargo clippy --all-targets -- -D warnings
```

From the Gatekeep repository root, the named lane includes formatting, strict
Clippy, test compilation and advisory/license checks:

```sh
mise exec -- just check-relation-consumer
DATABASE_URL=postgres://USER:PASSWORD@localhost:PORT/DATABASE mise exec -- just test-relation-consumer
```

`GATEKEEP_RELATION_CONSUMER=1` includes the source check in the canonical gate.
The `relation-consumer` dispatch workflow accepts matching committed sibling
revisions for the same check and live PostgreSQL test. Pull-request and main
CI run that check with the reviewed sibling commits pinned in the workflow.

The executable asserts outer rollback, a successful commit with three distinct
events, lost-commit-response recovery, conflicting command reuse, revoked
application authority before receipt lookup, stale observations after reapply,
exact-deadline expiry without reconciliation, and typed time unavailability.
It also checks delayed durable expiry with its audit and notification intent,
a mandatory intent failure, a block racing an absent observation,
storage failure, and restart with delivered immutable history. Each run retains
its fixture rows for inspection. The PostgreSQL connection must use
`READ COMMITTED`.

`store.rs` owns the application transaction sequence. Authentication is a
synthetic, pre-authenticated account identity plus a locked current authority
record; production authentication belongs at the application's ingress. The
operator fixture may apply relations. Admission policy denies a new operation
when either directed block or the account restriction is effectively present.
No lifecycle operation updates an existing `application_sessions` row.

`application_actions` is the application's business action and retry receipt,
not another audit or lifecycle store. Keepsake's complete lifecycle occurrence
and Gatekeep's complete decision occurrence remain immutable Dovecote events.
The third event is the application's required notification intent.
Reconciliation returns the IDs transitioned in that attempt;
this fixture verifies that a repeated batch creates no new events. Applications
that must recover the exact batch result after an unknown commit also store a
stable batch receipt with those IDs in the same transaction. The caller
rolls back the entire transaction on every error or cancellation. A denial may
commit its specified decision audit alone; it creates no session or relation.

The pair encoding is application-owned and injective: the UTF-8 byte length of
the first account ID precedes both account IDs. Direction is preserved. Production
applications must keep that mapping stable, respect identifier byte limits and
choose their own self-block and operation-scope policies.

## Platform integration

Keepsake owns the relation lifecycle. Your platform maps user identities and
chooses which operations a block or restriction prevents: for example, a new
contact request, invitation or conversation admission. The example's session
rows represent already-admitted interactions; denying a later admission leaves
those rows unchanged.

Keep reports, evidence, cases, appeals, staff policy, notification wording and
business receipts in the application. Use a fixed block relation definition with
a directed pair subject, and per-assignment expiry for timed account restrictions.
Authenticate current authority, lock all policy-relevant relation scopes, evaluate
Gatekeep, then write business state and required events before one commit. The
[transaction contract](../../docs/relation-lifecycle-contract.md) explains time,
evidence and concurrency obligations.

Effective expiry stops a timed restriction at its deadline but does not release
persisted uniqueness. To renew while reconciliation is delayed, authenticate
current authority and reconcile (or revoke) the old assignment before applying
a fresh command in the same caller-owned transaction. A plain apply against the
still-persisted `Applied` row reports `duplicate_prevented` and retains its old
identity; it is not a renewal. The consumer's reconciliation scenario verifies
that distinction, atomic rollback/commit of expiry plus reapplication, fresh
assignment evidence, and no repeated terminal events.
