# Installation

Add the core crate first. Add adapters only where the application needs them.

```toml
[dependencies]
gatekeep = "5.0"
```

For an Axum request boundary:

```toml
[dependencies]
gatekeep = "5.0"
gatekeep-axum = "5.0"
```

For SQLx list filtering or
[Dovecote](https://github.com/plethu/dovecote)-backed durable decision audit,
choose the database feature used by the service:

```toml
[dependencies]
gatekeep = "5.0"
gatekeep-sqlx = { version = "5.0", features = ["postgres"] }
```

For localized denial messages:

```toml
[dependencies]
gatekeep = "5.0"
gatekeep-fluent = "5.0"
```

For entitlements or relation-backed facts stored in
[Keepsake](https://github.com/plethu/keepsake):

```toml
[dependencies]
gatekeep = "5.0"
gatekeep-keepsake = "6.0"
keepsake = "6.0"
```

These versioned examples use crates.io dependencies. They require
no sibling checkouts or source overrides. For an existing Gatekeep 4 application,
follow [the migration notes](operations/improvement-migration.md).

## First gate

This example works with the registry dependency above:

```rust
use gatekeep::{Fact, StaticFactId, KnownFacts, condition, policy, evaluate};
struct Owner;
impl Fact for Owner { const ID: StaticFactId = StaticFactId::new("record.owner"); }
let gate = policy::grant_clause((), condition::has::<Owner>()).into_policy();
let facts = KnownFacts::new().with_present::<Owner>();
assert!(evaluate(&gate, &facts).is_permit());
```

The [published Axum API](https://docs.rs/gatekeep-axum/5.0.0/gatekeep_axum/)
and [SQLx audit API](https://docs.rs/gatekeep-sqlx/5.0.0/gatekeep_sqlx/)
use the same required sink boundary. The runnable record service requires this
repository, but no sibling project checkout.

## Workspace Use

Applications usually keep policy definitions in one module or crate and import
them from HTTP handlers, SQL query builders, workers, and tests. That avoids
parallel request-only and list-only policy implementations.

## Database Setup

Install the selected Dovecote migration for durable audit. SQL lowering itself
does not require Gatekeep tables, and a clean installation requires no
Gatekeep audit DDL. The historical files under
`crates/gatekeep-sqlx/migrations/{postgres,sqlite,mysql}/0001_audit.sql` remain
available only as immutable v1 upgrade sources; do not apply them to a clean
database.
