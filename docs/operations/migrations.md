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

## Dovecote bridge (1.1.0)

The bridge is additive and opt-in. Apply the Dovecote adapter's schema first,
then the Gatekeep `0001_audit.sql` migration, then the backend's
`0002_dovecote_bridge.sql`:

Dovecote's MySQL/MariaDB schema creates validation triggers. The migration
account needs trigger DDL authority; with MySQL binary logging enabled, an
administrator may also need to enable `log_bin_trust_function_creators` for
schema installation. Ordinary Gatekeep and bridge operations do not require
that server setting after the schema is installed.

| Backend | Bridge migration |
| --- | --- |
| Postgres | `crates/gatekeep-sqlx/migrations/postgres/0002_dovecote_bridge.sql` |
| SQLite | `crates/gatekeep-sqlx/migrations/sqlite/0002_dovecote_bridge.sql` |
| MySQL | `crates/gatekeep-sqlx/migrations/mysql/0002_dovecote_bridge.sql` |

The bridge migration adds a single fenced importer state row and immutable
identity ledgers for legacy outbox rows and normalized decision rows without an
outbox. It does not alter or delete the historical audit tables. See the
[Dovecote bridge guide](../guides/dovecote-bridge.md) for rollout, import, and
publisher ownership rules.

The ledgers store payload bytes together with provenance, the
`gatekeep-audit-json-v1` codec name, and a SHA-256 digest. This makes the
canonical JSON reconstruction of pre-bridge JSON/JSONB rows explicit, while
dual-write rows and SQLite text rows retain their original bridge/export bytes.
The importer walks normalized decision IDs, so a decision row without an
outbox is still migrated: it receives a `gatekeep-audit-legacy-<decision id>`
identity in the separate `gatekeep_dovecote_bridge_audit` migration ledger and
remains pending. That ledger has no publisher claim columns and is not a second
delivery queue.

Apply the migration with the same migration tool used by the application. Keep
Gatekeep migrations in the service's normal database rollout so audit writes are
available before the adapter is enabled.
