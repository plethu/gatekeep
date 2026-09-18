# A small record service

This example uses synthetic data and SQLite. It is a case study, not a copy of
Send and not a production identity service. URL-selected people are local test
fixtures. Bind it only to the loopback address used by the example.

```sh
cargo run -p gatekeep-example-record-service
curl http://127.0.0.1:3000/people/parent/records/one
```

Try `owner`, `participant`, `parent`, `admin`, `emergency`, `expired` and
`disabled`. Owners receive full records, participants shared notes, and parents
released summaries. Administrators have no standing content access. Emergency
access is a fallback; it does not upgrade an existing ordinary shared permit.
Denied and nonexistent access both return an empty 404 response.

The handler starts a SQLite `BEGIN IMMEDIATE` transaction, resolves permission
metadata, creates a checked pending decision, writes its Dovecote event,
projects only permitted columns, and commits before responding. Denials commit
their event before returning 404. This write fence serializes permission changes
with the protected read; it is intentionally conservative for a small example.
The database lives in memory and disappears on shutdown.

The batch test uses one metadata query for several contexts, compares the
results with individual checks and verifies that equal record IDs in different
tenants cannot share observations. Other tests inspect actual returned JSON,
audit persistence and rollback. Run them with:

```sh
cargo test -p gatekeep-example-record-service
```

A recorded decision is not proof of HTTP delivery. Audit a business mutation in
its owning transaction; use a separate event when the application needs to
record that a response was assembled or sent. Store only the necessary resource
references and disclosure tiers. Retention and access to history belong to the
application.

For Postgres, the executable companion is
`permission_guard_fences_mutation_and_audit_against_revocation` in the SQLx live
suite. It locks an application guard row with `FOR UPDATE`, reads permission,
prepares the checked decision, performs the write and appends its event in the
same transaction. A second connection's revocation cannot acquire that guard
until the operation commits. Run `mise exec -- just test-db-postgres`.

Every permission-changing path must lock the same guard, including lifecycle
changes that would otherwise insert a previously absent relation. A row lock on
a missing relation alone does not fence insertion. The guard is an application
contract, not a property inferred by an HTTP extractor.

`GET /people/parent/records` exercises SQL lowering against actual rows. It
applies the tenant and authorization filter before counting and pagination,
projects the permitted fields, and commits a separate application disclosure
event containing the returned row references and tiers. That event records
response assembly and the policy anchor; it does not pretend SQL produced
point-check traces or that the client received the response.
