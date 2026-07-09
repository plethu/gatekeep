# Durable Audit

Durable audit records let a service explain an authorization decision after the
request is gone. `gatekeep-sqlx` stores decision rows, structured child rows,
and an outbox row for each recorded decision.

## Setup

Enable the SQLx backend feature and run the matching migration:

```toml
[dependencies]
gatekeep-sqlx = { version = "0.4", features = ["postgres"] }
```

```rust
use gatekeep_axum::Gatekeeper;
use gatekeep_sqlx::PgDecisionAuditRepository;

let audit = PgDecisionAuditRepository::new(pool.clone());
let gatekeeper = Gatekeeper::new(policy).with_audit_sink(audit);
```

The repository implements `gatekeep::AuditSink`. It can also query stored
records for review and support tooling.

## Stored Data

The schema stores:

- one decision row with request, policy, effect, and trace data
- consulted fact rows
- obligation rows
- request subject rows
- denial reason parameter rows
- one `gatekeep_audit_outbox` row

Use structured rows for search and reporting. Use the serialized audit payload
when an export worker needs the full decision envelope.

## Failure Handling

The Axum adapter awaits audit persistence before returning permit or deny. That
gives the application a clear choice: return a successful authorization result
only when the audit sink accepted the record, or surface the adapter error.

Use `NoopAuditSink` only for applications where durable authorization audit is
out of scope.
