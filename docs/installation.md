# Installation

Add the core crate first. Add adapters only where the application needs them.

```toml
[dependencies]
gatekeep = "0.4"
```

For an Axum request boundary:

```toml
[dependencies]
gatekeep = "0.4"
gatekeep-axum = "0.4"
```

For SQLx list filtering or durable decision audit, choose the database feature
used by the service:

```toml
[dependencies]
gatekeep = "0.4"
gatekeep-sqlx = { version = "0.4", features = ["postgres"] }
```

For localized denial messages:

```toml
[dependencies]
gatekeep = "0.4"
gatekeep-fluent = "0.4"
```

For entitlements or relation-backed facts stored in Keepsake:

```toml
[dependencies]
gatekeep = "0.4"
gatekeep-keepsake = "0.4"
keepsake = "0.6"
```

## Workspace Use

Applications usually keep policy definitions in one module or crate and import
them from HTTP handlers, SQL query builders, workers, and tests. That avoids
parallel request-only and list-only policy implementations.

## Database Setup

`gatekeep-sqlx` includes migrations for durable decision audit:

- `crates/gatekeep-sqlx/migrations/postgres/0001_audit.sql`
- `crates/gatekeep-sqlx/migrations/sqlite/0001_audit.sql`
- `crates/gatekeep-sqlx/migrations/mysql/0001_audit.sql`

Run the migration for the backend you enable. SQL lowering itself does not
require Gatekeep tables. Durable audit does.
