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

The structural Rust checks are documented in
[`tools/ast-grep/README.md`](tools/ast-grep/README.md). Run them on their own
with `mise run lint-structure`.

Run `mise run fmt` to format the workspace and `mise tasks` to list the
available project commands.

CI runs `mise run check` on pull requests via Codeberg-hosted Forgejo Actions
when runners are available. The same command is the local release gate.

## Stability

From 1.0 onward, public API and audit schema changes follow semver. Open an
issue before proposing breaking changes.

## Docs

Human guides live in [`docs/README.md`](docs/README.md). API detail belongs in
rustdoc and on docs.rs. Update both when you change public behaviour.

## Issues and pull requests

Issues are welcome for bugs, doc gaps, and operational problems.

Open an issue before spending time on a pull request so scope is clear before
you implement it.
