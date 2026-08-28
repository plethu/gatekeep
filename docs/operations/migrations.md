# Migrations

SQL lowering does not require Gatekeep tables. Durable decision audit is owned
by Dovecote in 3.0.

## New 3.0 installation

Install the application's domain-state schema and the selected Dovecote schema.
Call the Dovecote adapter's `check_schema` before enabling authorization audit.
Do not apply a Gatekeep audit migration: clean 3.0 has no Gatekeep-owned audit
tables.

Dovecote's MySQL/MariaDB schema creates validation triggers. The migration
account needs trigger DDL authority; with MySQL binary logging enabled, an
administrator may also need to enable `log_bin_trust_function_creators` for
schema installation. Ordinary Gatekeep operations do not require that server
setting after the schema is installed.

When applying the MySQL/MariaDB artifact through SQLx, send its complete
`sql()` value with `sqlx::raw_sql`. Do not split the artifact on semicolons:
trigger bodies contain semicolons and must reach the server as one raw,
unprepared multi-statement request.

## 2.x to 3.0 upgrade

Gatekeep 3.0 is a coordinated breaking release. First update the Dovecote
crates and tenant-aware schema to 0.2. Then update the Keepsake dependency and
bridge to 3.0. Finally update all Gatekeep crates to 3.0 together. Existing rows need an
explicit, reviewable tenant mapping; never assign a guessed tenant default.
Run the binding, resolver, SQL lowering, audit retry, and wrong-scope tests
against the deployed feature set before switching traffic.

Gatekeep 3.0 has no runtime reader for an old Gatekeep-owned audit table. Keep
the published 2.x audit migrations and source rows intact for rollback and
reconciliation until the service has verified Dovecote history and delivery
state. The old schema is not a substitute for the tenant-aware Dovecote 0.2
schema.

The current Dovecote decoder accepts only a tenant-scoped `PagedEvent` whose
payload contains a current binding and fact evidence. It does not reinterpret
`legacy-` identities or missing binding fields. Historical data therefore
requires an explicit, versioned migration importer with a reviewable tenant
mapping before it can become a current Gatekeep entry.

## Historical v1 upgrade

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

Do not use these files for a clean 3.0 installation, and do not rewrite them.
