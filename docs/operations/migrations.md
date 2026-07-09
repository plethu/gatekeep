# Migrations

SQL lowering does not require Gatekeep tables. Durable decision audit does.

Run the migration for the database backend enabled in `gatekeep-sqlx`:

| Backend | Migration |
| --- | --- |
| Postgres | `crates/gatekeep-sqlx/migrations/postgres/0001_audit.sql` |
| SQLite | `crates/gatekeep-sqlx/migrations/sqlite/0001_audit.sql` |
| MySQL | `crates/gatekeep-sqlx/migrations/mysql/0001_audit.sql` |

The migration creates:

- `gatekeep_audit_decisions`
- `gatekeep_audit_consulted_facts`
- `gatekeep_audit_obligations`
- `gatekeep_audit_request_subjects`
- `gatekeep_audit_reason_params`
- `gatekeep_audit_outbox`

Apply the migration with the same migration tool used by the application. Keep
Gatekeep migrations in the service's normal database rollout so audit writes are
available before the adapter is enabled.
