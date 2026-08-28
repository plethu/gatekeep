# Durable Audit

Durable audit records let a service explain an authorization decision after the
request is gone. Gatekeep keeps the typed decision in one complete JSON
Dovecote event; Dovecote owns its durable event and delivery lifecycle.

## Setup

Enable the SQLx backend feature and run the matching migration:

```toml
[dependencies]
gatekeep-sqlx = { version = "2.0", features = ["postgres"] }
```

The compile-checked [`axum-durable-audit`](../../examples/axum-durable-audit/src/main.rs)
example is the canonical setup: it imports `gatekeep_axum::Gatekeeper`, uses an
application-owned `FactResolver`, checks the Dovecote schema, and attaches
`PgDovecoteAudit` with `Gatekeeper::new(resolver).with_audit_sink(audit)`. The
workspace builds this example as part of its checks.

The sink implements `gatekeep::AuditSink`. For an existing application
transaction, call the backend-specific
`record_decision_audit_in_transaction` method. The caller owns commit and
rollback; this is atomic with other writes in that transaction, not with
arbitrary business-state writes made elsewhere.

## Stored Data

The Dovecote schema stores:

- one immutable event containing the complete typed decision JSON
- the selected tenant, principal, locale, request id, and named subjects
- one mutable pending delivery
- event identity `gatekeep-audit-<decision_audit_id>`
- configured absolute source, `gatekeep-audit` stream, and
  `gatekeep.decision_audit_recorded` type

Use Dovecote live or snapshot paging for history and decode its JSON payload
into `AuditEntry`. Do not add Gatekeep-owned child tables or a second outbox.

## Failure Handling

The Axum adapter awaits audit persistence before returning permit or deny. That
gives the application a clear choice: return a successful authorization result
only when the audit sink accepted the record, or surface the adapter error.

Use `NoopAuditSink` only for applications where durable authorization audit is
out of scope.

## Installation and migration

For a new 2.0 installation, install the application's domain schema and the
selected Dovecote schema, call `check_schema`, configure the source, and use
the ordinary sink. No Gatekeep audit migration is required.

For a v1 upgrade, retain the historical `gatekeep-sqlx` audit tables as
read-only migration sources through the rollback window. Install Dovecote and
import the complete history, including delivered decisions, with the Dovecote
migration importer. Never drop the old tables automatically. The shipped v1
SQL files are release artifacts and must remain byte-identical.
