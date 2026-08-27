# Feature Flags

Gatekeep keeps the core crate small and puts integrations in adapter crates.

## `gatekeep`

| Feature | Use |
| --- | --- |
| `test` | exposes `InMemoryAuditSink` for tests |

## `gatekeep-sqlx`

| Feature | Use |
| --- | --- |
| `postgres` | Postgres lowering and durable audit repository |
| `sqlite` | SQLite durable audit repository and lowering support |
| `mysql` | MySQL durable audit repository and lowering support |
| `dovecote-postgres` | Opt-in Postgres dual-write and complete-history Dovecote bridge |
| `dovecote-sqlite` | Opt-in SQLite dual-write and complete-history Dovecote bridge |
| `dovecote-mysql` | Opt-in MySQL dual-write and complete-history Dovecote bridge |
| `dovecote` | Enables all three Dovecote bridge backend features |
| `postgres-tests` | ignored Postgres integration tests |
| `mysql-tests` | ignored MySQL integration tests |

Enable one database feature in applications. Test features are for the
workspace's database-backed gates.

## Other Adapters

`gatekeep-axum`, `gatekeep-fluent`, and `gatekeep-keepsake` use their crate
dependencies directly. Add only the adapter crates needed by the service.
