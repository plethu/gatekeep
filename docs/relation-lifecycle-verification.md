# Relation lifecycle verification

This records the pre-release implementation and audit phase. Registry limitations
below describe that phase; release checks and publication are recorded separately.

Executed 2026-09-07 against local Keepsake 6 sources. No publication was performed.
A temporary Cargo patch configuration was removed after verification.

## Initial feature verification

These results precede the broader maintainability alignment. Its final Gatekeep
results are recorded separately below; sibling final verification has its own
acceptance record.

- Canonical `mise exec -- scripts/check-project-gates.sh`: passed. Includes fmt,
  structural rules, workspace/all-target/all-feature Clippy, advisory/license/
  source/ban checks, workspace tests, examples and documentation tests.
- PostgreSQL: all six explicitly ignored backend tests passed, including complete
  immutable audit replay/conflict and caller-transaction rollback.
- MySQL: all four explicitly ignored backend tests passed, including audit replay,
  conflict and caller-transaction rollback.
- SQLite audit tests run as part of the all-feature workspace suite.
- Core Keepsake tests: 54 passed after command-envelope and missing-fulfillment evidence validation.
- Focused Gatekeep adapter tests and Clippy passed after binding fulfillment
  evidence to tenant and assignment incarnation, including rejected substitutions.
- Post-audit `GATEKEEP_RELATION_CONSUMER=1` canonical gate passed, including
  the standalone consumer's format, strict Clippy, test compilation and
  advisory/license checks. Its `--live` lane also passed the PostgreSQL regression.
- Supplemental strict workspace rustdoc passed. Cargo-machete 0.9.2 passed on
  crates/examples after removing two unused private-example dependencies.
  The documentation test package uses dependencies through included Markdown;
  its textual-scan findings were checked and dismissed without ignore entries.
- Targeted `cargo package` checks assembled and verified all five public Gatekeep
  library archives with a local Keepsake 6 override. This is source integration
  evidence; Cargo used its temporary local registry for staged sibling archives.
- The same package check without an override fails resolving unpublished Keepsake
  6. This is not registry/package publication readiness.
- Workspace packaging reaches an existing unpublished
  `gatekeep-example-authorized-list-support` dependency. The public libraries
  were therefore packaged explicitly; no example publication
  configuration was changed.

Backend commands used `--test postgres --features postgres-tests` and
`--test mysql --features mysql-tests`, followed by
`-- --ignored --test-threads=1`, against separate `gatekeep_fixture` databases.
The disposable fixtures ran PostgreSQL 17.11 and MySQL 8.4.11. The repository
Compose pins PostgreSQL 17.6 and MySQL 9.5; the latter exact image was not verified.
No application databases or access controls were changed.

The standalone consumer's live PostgreSQL pass is separate from the Gatekeep
adapter suites. Reproduce it with `mise exec -- just test-relation-consumer`,
setting `DATABASE_URL` to a dedicated disposable database. Run
`GATEKEEP_RELATION_CONSUMER=1 mise exec -- just check` for the canonical gate
including its source checks, with the root workspace's dependency overridden as
described in [Contributing](../CONTRIBUTING.md#relation-source-integration).
The [consumer README](../examples/relation-lifecycle/README.md)
records the sibling-source setup, business assertions and application obligations.
These runs establish local source integration, not registry resolution or a
remote workflow result.

## Maintainer alignment verification

After the broader alignment and patch-version changes, the strengthened
canonical gate passed again with the standalone source lane enabled: 134 tests
and doctests passed, with ten live tests checked separately. PostgreSQL's six
and MySQL's four live tests passed, and the complete source consumer passed its
live PostgreSQL regression including atomic reconciliation plus reapplication.
Separate production Clippy selections passed for all three SQL backends and
runtime-free core. All five public archives were rebuilt and verified using
local source overrides; a fresh online registry-only package attempt still
fails on unpublished Keepsake 6. See the complete criterion/evidence map and
specific deviations in [Maintainability](maintainability.md).

A later independent-review correction restricts unsupported URL diagnostics to
unambiguous hierarchical schemes. All 17 SQL-lowering tests, SQLx strict
all-target/all-feature Clippy, and a refreshed gatekeep-sqlx 4.0.1 package
verification passed after that correction.
