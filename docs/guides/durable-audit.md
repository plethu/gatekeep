# Durable Audit

Durable audit lets a service explain an authorization decision after the
request is gone. Gatekeep writes the typed decision as one complete JSON event;
[Dovecote](https://github.com/plethu/dovecote) stores it and tracks delivery.

## Setup

Enable the SQLx backend feature and run the matching migration:

```toml
[dependencies]
gatekeep-sqlx = { version = "4.0", features = ["postgres"] }
```

The compile-checked
[`axum-durable-audit`](../../examples/axum-durable-audit/src/main.rs) example
shows the complete Postgres setup: an application-owned `FactResolver`, the
Dovecote schema check, and `PgDovecoteAudit` attached through
`Gatekeeper::new(resolver, audit)`. The workspace builds it as part of its
checks.

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

Use Dovecote live or snapshot paging for history and decode each complete
`PagedEvent` with `gatekeep_sqlx::decode_decision_audit`; the decoder checks the
storage-row tenant against the payload tenant and validates current schema,
policy-hash version, portable occurrence, binding, and fact evidence before
returning `AuditEntry`. Missing or unknown schema/hash versions are rejected.
It does not silently import legacy-shaped payloads. Use
`gatekeep_sqlx::decode_legacy_decision_audit` and
`LegacyAuditEntry::into_current` from an explicit migration importer instead.
Do not add Gatekeep-owned child tables or a second outbox.

## Failure Handling

The Axum adapter awaits audit persistence before returning permit or deny. That
gives the application a clear choice: return a successful authorization result
only when the audit sink accepted the record, or surface the adapter error.

Use `Gatekeeper::unaudited(resolver)` only when durable authorization audit is
explicitly out of scope. The production constructor requires an audit sink.

## Installation and migration

For a new 4.0 installation, install the application's domain schema and the
selected Dovecote schema, call `check_schema`, configure the source, and use
the ordinary sink. No Gatekeep audit migration is required.

For a v1 upgrade, retain the historical `gatekeep-sqlx` audit tables as
read-only migration sources through the rollback window. Install Dovecote and
import the complete history, including delivered decisions, with the Dovecote
migration importer. Never drop the old tables automatically. The shipped v1
SQL files are release artifacts and must remain byte-identical.
