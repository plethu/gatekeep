# Changelog

All notable changes to this project are documented here.

## Unreleased

### Documentation

- Added an Astro Starlight docs site covering the authorization model, lattice
  outcomes, facts and context, decisions and audit, Axum integration, SQLx list
  filtering, durable audit, and Keepsake-backed entitlements.

### `gatekeep`

- Changed `AuditSink::record` to async so durable audit sinks can perform IO
  without hiding persistence behind a synchronous trait.
- Expanded `AuditEntry` with request id, request subjects, consulted facts,
  decisive clause, and structured denial reason data.

### `gatekeep-axum`

- Await audit persistence before returning permit or deny decisions.

### `gatekeep-sqlx`

- Added `SqlxDecisionAuditRepository` and backend aliases for durable,
  queryable decision audit storage.
- Added SQL migrations for decision audit rows, consulted facts, obligations,
  request subjects, reason params, and outbox rows.

## [0.4.0] — 2026-06-23

### `gatekeep-sqlx`

- Deduplicated shared SQLx bind dispatch across Postgres, SQLite, and MySQL
  backend markers while keeping dialect-specific placeholders and grade
  functions explicit.

### `gatekeep-keepsake`

- Updated the keepsake dependency to `0.6.0`.
- Added `KeepsakeRelationTarget` and target resolver helpers so lifecycle writes
  can reuse the same subject/relation mapping as authorization reads.
- Re-exported keepsake's `DynActiveRelationSource` for application composition
  boundaries while keeping `KeepsakeResolver<S>` generic over
  `ActiveRelationSource`.

## [0.2.0] — 2026-06-20

### `gatekeep-sqlx`

- Added backend-aware SQLx lowering for Postgres, SQLite, and MySQL.
- Kept the existing Postgres `Pg*` API as the default backend surface while
  adding generic `Sqlx*` lowerer, fragment, value, and predicate types.
- Added compile-time and runtime safeguards for SQLx backend feature selection
  and database URL validation.
- Added in-memory SQLite execution coverage and Docker-backed MySQL differential
  coverage alongside the existing Postgres tests.

### `gatekeep-keepsake`

- Updated the keepsake dependency to `0.5.1`.

## [0.1.0] — 2026-06-20

Initial release of all five crates.

### `gatekeep`

- Core policy model: `Policy`, `Condition`, `Lattice`, `Fact`, `FactId`
- Synchronous full evaluation (`evaluate`) and partial evaluation (`partial_evaluate`, `evaluate_residual`)
- Decision tracing: every outcome carries `DecisionTrace` with `DecisiveClause`, denial reasons, and unsatisfied facts
- Residual policy types for query lowering: `Residual`, `ResidualPolicy`, `ResidualPolicyNode`
- Adapter traits: `FactResolver`, `AuditSink`, `PolicyObserver`, `QueryLowering`, `ReasonCatalog`
- Stable identity types: `PolicyId`, `PolicyHash`, `ReasonCode`, `FactId`, `TenantId`, `RequestId`
- `KnownFacts` and `PartialFacts` for full and partial fact sets
- `InMemoryAuditSink` behind the `test` feature flag

### `gatekeep-axum`

- `Gatekeeper` extractor: resolves facts, evaluates a policy, rejects with `GatekeepRejection`
- `Authorized<T>` wrapper carrying the permitted effect grade through to the handler
- `DenialResponse` and `DenialResponseConfig` for structured JSON denial bodies
- `test_support` module for handler unit tests without a running server

### `gatekeep-sqlx`

- `QueryLowering` implementation for Postgres via `sqlx::QueryBuilder`
- Lowers residual fact conditions to trusted SQL predicates and appends a grade projection
- `FragmentSet` for registering fact-to-SQL-fragment mappings

### `gatekeep-fluent`

- `FluentCatalog` implementing `ReasonCatalog` over Project Fluent `.ftl` resources
- Per-locale bundle loading with configurable fallback locale
- Configurable hidden-denial message (avoids leaking resource existence)

### `gatekeep-keepsake`

- `KeepsakeResolver` implementing `FactResolver` against a keepsake `ActiveRelationSource`
- `FactBinding` mapping `FactId`s to keepsake relation ids
- `QueryPresence` for marking selected facts unknown during partial evaluation
- `SubjectMapper` trait with `PrincipalSubjectMapper` and `TenantScopedSubjectMapper` built in
- `in-memory` feature flag for test-time `InMemoryActiveRelations` seeds

[0.4.0]: https://codeberg.org/plethu/gatekeep/releases/tag/v0.4.0
[0.2.0]: https://codeberg.org/plethu/gatekeep/releases/tag/v0.2.0
[0.1.0]: https://codeberg.org/plethu/gatekeep/releases/tag/v0.1.0
