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
