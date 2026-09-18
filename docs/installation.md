# Installation

Add the core crate first. Add adapters only where the application needs them.

```toml
[dependencies]
gatekeep = "4.0.1"
```

For an Axum request boundary:

```toml
[dependencies]
gatekeep = "4.0.1"
gatekeep-axum = "4.0"
```

For SQLx list filtering or
[Dovecote](https://github.com/plethu/dovecote)-backed durable decision audit,
choose the database feature used by the service:

```toml
[dependencies]
gatekeep = "4.0.1"
gatekeep-sqlx = { version = "4.0.1", features = ["postgres"] }
```

For localized denial messages:

```toml
[dependencies]
gatekeep = "4.0.1"
gatekeep-fluent = "4.0"
```

For entitlements or relation-backed facts stored in
[Keepsake](https://github.com/plethu/keepsake):

```toml
[dependencies]
gatekeep = "4.0.1"
gatekeep-keepsake = "5.0"
keepsake = "6.0"
```

These versioned examples use crates.io dependencies. They require
no sibling checkouts or source overrides. The checked authoring/evidence APIs in
this checkout are unreleased and will require a coordinated major upgrade; see
[the migration notes](operations/improvement-migration.md).

## First gate on the published version

This example works with the registry dependency above:

```rust
use gatekeep::{Fact, StaticFactId, KnownFacts, condition, policy, evaluate};
struct Owner;
impl Fact for Owner { const ID: StaticFactId = StaticFactId::new("record.owner"); }
let gate = policy::grant_clause((), condition::has::<Owner>()).into_policy();
let facts = KnownFacts::new().with_present::<Owner>();
assert!(evaluate(&gate, &facts).is_permit());
```

The [published Axum API](https://docs.rs/gatekeep-axum/4.0.0/gatekeep_axum/)
and [SQLx audit API](https://docs.rs/gatekeep-sqlx/4.0.1/gatekeep_sqlx/)
use the same required sink boundary. The new `with_bool`, `PreparedPolicy` and
resource-policy examples need the unreleased checkout until its packages are
published. The runnable record service requires this repository, but no sibling
project checkout.

## Workspace Use

Applications usually keep policy definitions in one module or crate and import
them from HTTP handlers, SQL query builders, workers, and tests. That avoids
parallel request-only and list-only policy implementations.

## Database Setup

Install the selected Dovecote migration for durable audit. SQL lowering itself
does not require Gatekeep tables, and a clean 4.0 installation requires no
Gatekeep audit DDL. The historical files under
`crates/gatekeep-sqlx/migrations/{postgres,sqlite,mysql}/0001_audit.sql` remain
available only as immutable v1 upgrade sources; do not apply them to a clean
4.0 database.
