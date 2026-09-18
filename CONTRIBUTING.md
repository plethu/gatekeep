# Contributing

Gatekeep keeps deterministic evaluation in core and application integration in
its adapters. Public APIs, examples and durable record formats are part of the
library contract.

## Checks

Install the pinned tools and run the shared local/CI check:

```sh
mise install
mise run check
```

`check` runs formatting, spelling, dependency checks, Clippy,
workspace tests and doctests, strict rustdoc, isolated consumer builds and docs
links. Its implementation lives in `scripts/check-project-gates.sh`. Run
`mise run fmt` to format Rust and TOML, or `mise tasks` to list commands.

Run a focused test with `mise exec -- just test <filter> -- --nocapture`.
For SQLx, migration or database-query changes, also run `mise run test-db`.
The pinned toolchain checks the minimum Rust version declared in `Cargo.toml`;
raising that minimum is a deliberate compatibility decision.

Production-only lint restrictions exclude test harnesses, where assertions and
fixture arithmetic are expected. `unreachable_pub` also conflicts with Clippy's
private test-module visibility advice. The existing `AuditEntry::new` argument
count exception preserves its published signature; prefer `from_decision` for
new callers. Cargo-deny checks dependency policy even where upstream libraries
require multiple versions of a crate.

## Documentation and API changes

`mise exec -- just check-public-api` compares default, no-default, and all-feature
APIs against the published baselines in `scripts/check-public-api.sh`. SQLx
requires a backend, so its no-default check selects SQLite explicitly. CI uses
major-release mode for the planned breaking release; that mode permits breaks.
After publication, update the baselines and restore minor-release enforcement.
See [versioning](docs/operations/versioning.md) for durable-format compatibility.

[Human guides](docs/README.md) live in `docs`; API detail belongs in rustdoc.
Update examples when changing public behavior. `mise exec -- just docs-site`
builds the searchable book in `target/book` from those same Markdown files.

The book build applies checked compatibility transforms for keyboard sidebar
activation, search input and focus. Review them when updating mdBook. Exercise
keyboard navigation, search, reduced motion, narrow layouts and screen-reader
use when changing the documentation theme.

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

The standalone `examples/relation-lifecycle` consumer requires sibling checkouts
named `gatekeep-rs`, `keepsake-rs` and `carrier`. Use the revisions pinned in
`.github/workflows/ci.yml` to match its lockfile.

```sh
mise exec -- just check-relation-consumer
GATEKEEP_RELATION_CONSUMER=1 mise run check
```

The first command checks formatting, strict Clippy, test compilation and dependency
policy. The second includes those checks in the root gate. For the live test,
set `DATABASE_URL` to a dedicated disposable PostgreSQL database and run
`mise exec -- just test-relation-consumer`. See the
[example README](examples/relation-lifecycle/README.md) for setup and transaction
semantics. CI runs this source integration separately from registry consumers.

## Package archives and performance

To check the actual archive contents before a coordinated release:

```sh
mise exec -- cargo package --allow-dirty --no-verify \
  -p gatekeep -p gatekeep-axum -p gatekeep-fluent \
  -p gatekeep-keepsake -p gatekeep-sqlx
mise exec -- python3 scripts/check-consumers.py --packaged
```

The consumer check extracts the archives and builds them with registry
dependencies. This supports unpublished coordinated versions without requiring
sibling sources; verify registry-only resolution after publication as well.

Run `cargo bench -p gatekeep --bench authorization` for evaluator, trace, hash
and preparation timings. Run `cargo bench -p gatekeep-example-record-service
--bench data_access` for separate single/bulk metadata reads and SQL construction.
Use `cargo build --timings` and `cargo tree -p gatekeep -e normal` to inspect
build and dependency cost. Local in-memory timings are not network throughput
measurements.
