# Migrations

SQL lowering does not require Gatekeep tables. Durable decision audit is owned
by Dovecote in 2.0.

## New 2.0 installation

Install the application's domain-state schema and the selected Dovecote schema.
Call the Dovecote adapter's `check_schema` before enabling authorization audit.
Do not apply a Gatekeep audit migration: clean 2.0 has no Gatekeep-owned audit
tables.

Dovecote's MySQL/MariaDB schema creates validation triggers. The migration
account needs trigger DDL authority; with MySQL binary logging enabled, an
administrator may also need to enable `log_bin_trust_function_creators` for
schema installation. Ordinary Gatekeep operations do not require that server
setting after the schema is installed.

## v1 upgrade

Keep the published Gatekeep audit migrations and source rows intact through the
rollback and reconciliation window. Install Dovecote additively, fence or
complete active legacy claims, and import the complete typed audit history with
Dovecote's migration importer. Delivered rows import as delivered and are
never publishable. Reconcile counts, identities, types, exact payloads where
original bytes exist, and delivery state before switching publication to
Dovecote. Old tables are not dropped automatically.

The following files are historical v1 upgrade artifacts only:

| Backend | Migration |
| --- | --- |
| Postgres | `crates/gatekeep-sqlx/migrations/postgres/0001_audit.sql` |
| SQLite | `crates/gatekeep-sqlx/migrations/sqlite/0001_audit.sql` |
| MySQL | `crates/gatekeep-sqlx/migrations/mysql/0001_audit.sql` |

Do not use these files for a clean 2.0 installation, and do not rewrite them.
