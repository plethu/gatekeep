# Installation

Add the core crate first. Add adapters only where the application needs them.

```toml
[dependencies]
gatekeep = "3.0"
```

For an Axum request boundary:

```toml
[dependencies]
gatekeep = "3.0"
gatekeep-axum = "3.0"
```

For SQLx list filtering or
[Dovecote](https://github.com/plethu/dovecote)-backed durable decision audit,
choose the database feature used by the service:

```toml
[dependencies]
gatekeep = "3.0"
gatekeep-sqlx = { version = "3.0", features = ["postgres"] }
```

For localized denial messages:

```toml
[dependencies]
gatekeep = "3.0"
gatekeep-fluent = "3.0"
```

For entitlements or relation-backed facts stored in
[Keepsake](https://github.com/plethu/keepsake):

```toml
[dependencies]
gatekeep = "3.0"
gatekeep-keepsake = "3.0"
keepsake = "3.0"
```

## Workspace Use

Applications usually keep policy definitions in one module or crate and import
them from HTTP handlers, SQL query builders, workers, and tests. That avoids
parallel request-only and list-only policy implementations.

## Database Setup

Install the selected Dovecote migration for durable audit. SQL lowering itself
does not require Gatekeep tables, and a clean 3.0 installation requires no
Gatekeep audit DDL. The historical files under
`crates/gatekeep-sqlx/migrations/{postgres,sqlite,mysql}/0001_audit.sql` remain
available only as immutable v1 upgrade sources; do not apply them to a clean
3.0 database.
