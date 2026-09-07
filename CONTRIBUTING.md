# Contributing

Gatekeep is stable infrastructure for in-process authorization. The core crate
stays pure and synchronous; adapters handle Axum, SQLx, Fluent, and Keepsake
integration at the application boundary.

## Before you open a PR

Install the pinned project tools once:

```sh
mise install
```

Run the local gates:

```sh
mise run check
```

When a change touches SQLx, migrations, or database queries, also run:

```sh
mise run test-db
```

Dependency changes must also pass the RustSec-backed cargo-deny checks:

```sh
just supply-chain
```

The structural Rust checks are documented in
[`tools/ast-grep/README.md`](tools/ast-grep/README.md). Run them on their own
with `mise run lint-structure`.

Run `mise run fmt` to format Rust and TOML across the workspace and standalone consumer and `mise tasks` to list the
available project commands.

The canonical gate includes selected all-target and production Clippy restrictions,
Taplo, typos, reviewed dependency ownership through cargo-machete, strict rustdoc,
cargo-deny, structural checks, and the established Cargo test/doctest lane.
[`docs/maintainability.md`](docs/maintainability.md) records their exact scope and
the remaining published compatibility exception.

CI runs `mise run check` on pull requests via GitHub Actions. The same command
is the local release gate.

## Stability

From 1.0 onward, public API and audit schema changes follow semver. Open an
issue before proposing breaking changes.

## Docs

Human guides live in [`docs/README.md`](docs/README.md). API detail belongs in
rustdoc and on docs.rs. Update both when you change public behaviour.

## Issues and pull requests

Contributions are welcome, including bug reports, documentation improvements,
and changes to the code. Open an issue before spending substantial time on a
pull request so we can agree on the shape of the work before you implement it.

Tools, including generative AI, may help you write code, tests, or
documentation. You remain responsible for understanding and checking everything
you submit. Interpersonal communication must be your own work: please write
issue reports, pull request descriptions, review replies, and other comments
yourself rather than generating them or pasting generated prose.

A contribution is a conversation, not a drop-off. Please be willing to respond
to questions, consider review feedback, and revise the work with the
maintainers. A pull request does not need to arrive perfect; it does need
someone present on the other side of it.

## Relation source integration

The standalone `examples/relation-lifecycle` consumer composes local Gatekeep,
Keepsake 6 and Dovecote sources. Keep the checkouts side-by-side as `gatekeep-rs`,
`keepsake-rs` and `carrier`. From the Gatekeep repository, run:

```sh
mise exec -- just check-relation-consumer
GATEKEEP_RELATION_CONSUMER=1 mise run check
```

The first command checks formatting, strict Clippy, test compilation and the
consumer's dependency graph against the root cargo-deny policy. The second adds
those checks to the canonical root gate. The default gate explicitly reports
that this source-integration lane is skipped.

Until Keepsake 6 is available from the registry, the root gate also needs a
local dependency override. Merge this into `.cargo/config.toml` without replacing
any existing configuration, and keep the override uncommitted:

```toml
[patch.crates-io]
keepsake = { path = "../keepsake-rs/crates/keepsake" }
```

The standalone consumer already declares its local overrides and does not need
this additional root configuration.

For the live transaction proof, set `DATABASE_URL` to a dedicated disposable
PostgreSQL database and run `mise exec -- just test-relation-consumer`. The check
fails immediately if that variable is absent; it does not start or reset an
application database or print the connection string.

The local canonical gate keeps source integration opt-in because it requires
sibling checkouts. Pull-request and main-branch CI always run the separate
`relation-consumer` job, which calls the reusable `relation consumer` workflow
with full reviewed Keepsake and Dovecote commit IDs recorded in
`.github/workflows/ci.yml`. That job checks out the matching siblings and runs
the same check owner against PostgreSQL 17.11. The workflow also supports manual
dispatch with explicit sibling commits. Update those pins deliberately when the
source integration changes; a green source job and the ordinary canonical/
database job are both required release evidence.

Dovecote 0.2.1 remains the consumer's compatible published dependency minimum.
The current local source lock records Dovecote 0.2.2, so the source workflow
requires matching committed sibling revisions explicitly and invents no pending
tag. A published-baseline package check is distinct from this local source lane.

Current candidate versions, registry prerequisites and publication order are in
[Versioning](docs/operations/versioning.md#coordinated-release-checks). A green
source consumer job does not replace the ordinary canonical/database CI job or
registry-only package checks after dependencies are published.
