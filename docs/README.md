# Gatekeep

Gatekeep is a code-first authorization engine for Rust. Policies are ordinary
Rust values, evaluation is pure and deterministic, and every decision carries
the reasons that produced it.

[Keepsake](https://github.com/plethu/keepsake) stores relation lifecycles;
Gatekeep decides what those facts permit. They work together, but neither
requires the other.

The core API is on [docs.rs](https://docs.rs/gatekeep); each adapter links its
own API from its manifest.

## Start here

1. [Overview](overview.md)
2. [Installation](installation.md)
3. [Quickstart](quickstart.md)

Read [Combining permit outcomes](concepts/lattice-outcomes.md) before designing
graded access such as redacted/full records or scope unions.

## Concepts

- [Authorization model](concepts/authorization-model.md)
- [Combining permit outcomes](concepts/lattice-outcomes.md)
- [Facts and context](concepts/facts-and-context.md)
- [Decisions and audit](concepts/decisions-and-audit.md)

## Guides

- [Axum authorization](guides/axum-authorization.md)
- [SQLx list filtering](guides/sqlx-list-filtering.md)
- [Durable audit](guides/durable-audit.md)
- [Keepsake entitlements](guides/keepsake-entitlements.md)

## Reference

- [Policy combinators](reference/policy-combinators.md)
- [Feature flags](reference/feature-flags.md)
- [SQLx adapter](reference/sqlx-adapter.md)
- [Reason catalogs](reference/reason-catalogs.md)

## Operations

- [Audit export](operations/audit-export.md)
- [Migrations](operations/migrations.md)
- [Versioning](operations/versioning.md)
- [Threat model](threat-model.md)
