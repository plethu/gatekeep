# Relation lifecycle implementation handoff

Keepsake owns assignment history, application, revocation, effective expiry and
durable reconciliation. Gatekeep evaluates scoped effective facts. Dovecote owns
the immutable audit/notification events and mutable delivery lifecycle. The application
retains its identity mapping, workflows and affected business records.

The [executable consumer](../examples/relation-lifecycle/README.md) contains the
application transaction sequence for user blocking and timed restrictions. Its
PostgreSQL assertions cover rollback, one committed set of effects, exact retry,
conflicting reuse, current authority before receipt disclosure, both block
directions, stale observations, exact-deadline expiry, reconciliation intent,
missing time, storage failure and immutable delivered history across reconnect.

The [fighting-game integration notes](fighting-game-integration.md) describe that
particular consumer's migration separately from the reusable platform example.

## Public contracts and constraints

- [Keepsake transaction contract](https://github.com/plethu/keepsake/blob/main/docs/reference/transactional-lifecycle.md):
  caller-owned apply/revoke/reconciliation and fulfillment reads; conditional
  observations; typed committed receipts; backend isolation and lock order.
- [Gatekeep effective facts](relation-lifecycle-contract.md): scoped absence and
  presence, supplied authoritative time, unavailable evidence and cache limits.
- A PostgreSQL protected transaction requires READ COMMITTED and takes coarse
  relation-definition/assignment table locks. This serializes these operations
  across tenants. MySQL uses definition/assignment locks under the documented
  REPEATABLE READ session contract; SQLite reserves its writer. These are
  explicit contention costs, not a high-throughput service claim.
- Observation comparison retains complete assignment history. Do not prune or
  rewrite that history while observations or receipts can be reused. A new
  archival scheme would need its own versioned invalidation contract.
- Any transaction-operation error or cancellation requires whole-transaction
  rollback. A commit error leaves the outcome unknown: authenticate again and
  recover a stable receipt before repeating business effects. Apply/revoke have
  library command receipts. For a reconciliation batch, persist an application
  batch receipt with its returned IDs when exact batch-result recovery is needed.
- Time freshness, high-water persistence and fulfillment completeness are
  application assertions. Unknown evidence is an unavailable operation, not
  permission or a restriction denial. A known deadline is evaluated separately
  from delayed reconciliation.

## Versions and migrations

Registry inspection confirmed Keepsake 5.0.0, Gatekeep 4.0.0 and Dovecote 0.2.1
already published. The coordinated release versions are Keepsake and keepsake-sqlx
6.0.0 and gatekeep-keepsake 5.0.0. The subsequent maintainability work stages
Gatekeep core and gatekeep-sqlx 4.0.1, plus Dovecote's compatible 0.2.2 patches.
Gatekeep's Axum and Fluent adapters remain 4.0.0. Compatible dependency lower
bounds are retained where no newly introduced API is required.

The new command/receipt fields and adapter behavior warrant these public major
versions. Domain schema and audit schema remain version 4. Optional complete
command evidence is additive to the audit payload; historical bytes remain
readable. An old occurrence without this evidence cannot establish exact replay
and returns `ReceiptEvidenceUnavailable`. Existing application receipts remain
application-owned and must still be protected by current authentication.

Existing valid schema-4 deployments need no DDL change. Earlier tenant-activated
schemas use the supported `upgrade_identifier_contract()` step in the
[Keepsake migration guide](https://github.com/plethu/keepsake/blob/main/docs/operations/migrations.md).
That method uses the existing published identifier migration and validates its
receipt; it does not invent a baseline or copy history into new pending events.
Quiesce affected writers and retain a verified backup for the documented upgrade,
particularly MySQL's non-transactional DDL recovery path.

All 51 tracked historical SQL migration artifacts were compared byte-for-byte
with each checkout's starting HEAD and remain unchanged. The aggregate below is
SHA-256 of sorted `path + space + artifact SHA-256 + newline` records per repo:

| Repository | Artifacts | Aggregate SHA-256 |
| --- | ---: | --- |
| keepsake-rs | 34 | b6198914285bc77afd9735d266186795e2f0752f39b8d7a47a039b076e0db671 |
| gatekeep-rs | 3 | 8e261a21440ea21d24f841eb439dd95c5bcbaf80360a220a9149cb34b1987bf9 |
| carrier | 14 | b50d9841bc47ee9e40c94b5f2390f2207c876d9caf8a135dd7227ecd2ef5fb96 |

## Verification boundaries

[Gatekeep verification](relation-lifecycle-verification.md) records the canonical
checks, real server tests and local package checks. The standalone consumer's
manifest explicitly patches local sibling sources. Its strict Clippy and live
PostgreSQL assertions pass; that is source integration evidence.

The stricter maintainability verification is recorded separately from the
initial feature-verification pass:

- [Keepsake verification](https://github.com/plethu/keepsake/blob/main/docs/operations/relation-lifecycle-verification.md)
  has completed its final canonical gate, core 56 and SQL suite 28 tests,
  PostgreSQL 48, MySQL 33 and SQLite 36 tests, and both package archives.
  MySQL Innovation 26.7.0 and MariaDB 11.8.6 each passed two focused transaction
  tests and one prior-version upgrade test. These results cover the later
  maintainability refactors as well as the relation contracts.
- Gatekeep's [maintainability verification](maintainability.md#verification-performed)
  has completed: the strengthened canonical gate passed 134 tests and doctests,
  PostgreSQL's six and MySQL's four live tests passed, and the updated source
  consumer and all five public package archives passed. After the independent
  review's URL-diagnostic correction, all 17 SQL-lowering tests, strict SQLx
  Clippy and the refreshed SQLx archive also passed. The consumer proves the
  current local sibling-source composition; archive checks use the documented
  local override rather than establishing registry-only Keepsake 6 resolution.
- Dovecote's final canonical gate, strict documentation/checks and four package
  archives passed, with adapter package verification against the actual
  published core 0.2.1. Its PostgreSQL suite reported 44 passing tests, but live
  RLS role checks were unconfigured and are not claimed as exercised. MySQL 25,
  SQLite 37, import 11 and finalization five tests passed. The final
  complete-history matrix passed SQLite, PostgreSQL 17.11, MySQL 8.4.11 and
  26.7.0, and MariaDB's retained-data 10.3.17 to 11.8.6 upgrade. All three
  MySQL-family targets also passed 25 current conformance tests and the
  separately enabled tenant-activation upgrade test each. Core minimum-feature
  compilation and the SQLite delivery example passed.

The [initial post-feature quality audit](relation-lifecycle-quality.md) records
its bounded findings and review before the broader alignment. The subsequent
work includes Dovecote runtime changes: shared stored-event validation, clearer
claim ownership, catalog normalization, error/rollback documentation and typed
migration-fixture modes. It is not limited to fixture manifests or lockfiles.
Its existing public API and immutable/delivery-history contracts are retained;
package versions advance to 0.2.2. No historical migration bytes are rewritten.

The optional high-cardinality stress lane and live RLS role/grant exercise are
not established by these results. CDC evidence is a reference-fixture check,
not a live connector result. Fresh independent source review
is clean after fixes and re-review, including the shell URL diagnostic correction.
Dovecote's canonical gate also passed on Rust 1.96.0 stable, alongside its 1.94.0
baseline; its [maintainability report](https://github.com/plethu/dovecote/blob/main/docs/maintainability.md)
records the complete evidence and limits.

The generic PostgreSQL consumer was executed again against all three final local
sources after the maintenance fixes. Its transaction, retry, expiry and admission
assertions passed, including unchanged already-admitted sessions.

During pre-release verification, Keepsake 6 was unavailable in the registry, so
dependent package checks used explicit source overrides. Release preparation
repeats those checks against published dependencies before uploading adapters.
The implementation/audit phase ended without commits, tags or publication;
the subsequent release is recorded by its CI runs and release notes. The
fighting-game checkout was not modified.
