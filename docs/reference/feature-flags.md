# Feature Flags

Gatekeep keeps the core crate small and puts integrations in adapter crates.

## `gatekeep`

| Feature | Use |
| --- | --- |
| `test` | exposes `InMemoryAuditSink` for tests |

## `gatekeep-sqlx`

| Feature | Use |
| --- | --- |
| `postgres` | Postgres lowering and Dovecote audit sink |
| `sqlite` | SQLite lowering and Dovecote audit sink |
| `mysql` | MySQL/MariaDB lowering and Dovecote audit sink |
| `postgres-tests` | ignored Postgres integration tests |
| `mysql-tests` | ignored MySQL integration tests |

Enable one database feature in applications. Test features are for the
workspace's database-backed gates. Each Dovecote adapter feature also enables
the matching Dovecote SQLx adapter; feature selection does not install or
apply a migration.

## Other Adapters

`gatekeep-axum`, `gatekeep-fluent`, and `gatekeep-keepsake` use their crate
dependencies directly. Add only the adapter crates needed by the service.
