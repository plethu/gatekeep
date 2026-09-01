# SQLx Adapter

`gatekeep-sqlx` has two jobs:

- lower residual policies into trusted SQL fragments
- serialize typed decisions into Dovecote events and deliveries

## Query Lowering

Use partial evaluation before lowering. The application supplies
`SqlxFactPredicates` so each unknown fact has a trusted SQL predicate. The
adapter renders a backend-aware fragment for a `sqlx::QueryBuilder`.

Keep schema knowledge in the application. Fact predicates should be static or
constructed from trusted code paths, with user values passed as SQLx binds.
Construct `TenantColumn` from separate validated table and column identifiers;
the lowerer automatically guards both the `WHERE` filter and grade projection
with a typed tenant bind.

## Dovecote Audit Sink

The Dovecote audit sinks serialize one complete `AuditEntry` and enqueue it in
the selected Dovecote schema. History is read through Dovecote paging, not a
Gatekeep-owned query repository.

| Sink | Backend |
| --- | --- |
| `PgDovecoteAudit` | Postgres |
| `SqliteDovecoteAudit` | SQLite |
| `MySqlDovecoteAudit` | MySQL and MariaDB |

Each sink implements `gatekeep::AuditSink`, so it can be passed to
`gatekeep_axum::Gatekeeper::new(resolver, audit)`. The constructor requires an
application-owned absolute event source. The default stream is
`gatekeep-audit`, the event type is `gatekeep.decision_audit_recorded`, and the
content type is `application/json`.

For an existing application transaction, call the backend-specific
`record_decision_audit_in_transaction` method. The caller owns commit and
rollback; the event is atomic with other writes in that transaction, not with
arbitrary business-state writes made elsewhere.

## Migrations

Install Dovecote's migration for the enabled backend. The old Gatekeep
migration files remain only for v1 upgrade and reconciliation and are not part
of the 4.0 runtime schema.
