# Changelog

All notable changes to this project are documented here.

## [4.0.0] - 2026-09-01

Gatekeep 4.0 is a coordinated breaking release for the public audit API and
durable event contract.

### `gatekeep`

- Made `AuditEntry` a current-only type with private fields, validated
  constructors, and accessors. Current construction requires a validated
  `DecisionAuditOccurrence`, tenant binding, and fact-resolution evidence.
- Made `DecisionAuditOccurrence` opaque and validating on deserialization so
  callers cannot bypass its identity, range, UTC, or microsecond invariants.
- Validated and canonicalized occurrences while decoding current audit JSON;
  unsupported portable times and reserved legacy identities fail closed.
- Added explicit `AUDIT_ENTRY_SCHEMA_VERSION` payloads and
  `policy_hash_version` fields to current policy anchors.
- Added `LegacyAuditEntry` and `LegacyPolicyAnchor` for explicit migration
  decoding and import; legacy records cannot be silently treated as current.

### `gatekeep-sqlx`

- Added `decode_legacy_decision_audit` for separately reviewed historical
  imports. `decode_decision_audit` accepts only the current versioned shape.
- Kept the historical v1 SQL migration artifacts byte-identical.

### `gatekeep-keepsake`

- Updated the relation bridge to the published Keepsake 4 identity and time
  contracts.

### Migration

Update all five Gatekeep crates together. Decode 3.x events with the explicit
legacy decoder, establish the tenant and policy-hash mapping, and use
`LegacyAuditEntry::into_current` with a new validated occurrence before
emitting 4.0 events. Do not apply the historical Gatekeep SQL migrations to a
clean installation.

## [3.0.1] - 2026-09-01

### Correctness

- Added semantic validation for durable audit entries so duplicated effect,
  decisive-clause, consulted-fact, obligation, denial-reason, and trace fields
  cannot contradict one another at a current audit boundary.
- Made the authorized-list example perform the same pre-resolution and
  receipt-time binding and resolver-freshness checks as point authorization.
- Declared policy-hash format 1 as the durable Postcard-plus-BLAKE3 contract
  and froze it with a golden vector.
- Aligned tenant validation with Keepsake and Dovecote by rejecting
  whitespace-only identities.

### Documentation and packaging

- Added Rustdoc compilation coverage for every Rust code block in the README
  and hand-written guides, and repaired the incomplete examples it exposed.
- Removed sibling-checkout paths from external Dovecote and Keepsake
  dependencies so a standalone Gatekeep clone resolves them from crates.io.
- Retained compatibility with the published Dovecote 0.2 and Keepsake 3.0
  series while resolving both dependencies from crates.io.

## [3.0.0] - 2026-08-28

### `gatekeep`

- Made tenant binding explicit in `Context`, including bounded application
  verification evidence and freshness checks before and after fact resolution.
- Replaced separate resolver metadata callbacks with one atomic
  `FactResolution` envelope carrying source observation time, structurally
  validating freshness, and always recording a deterministic fact-set digest;
  future observations and expired results fail closed at the decision
  boundary.
- Changed `FactResolver` methods to receive the application-owned `Clock` used
  by the authorization boundary, keeping resolver observations coherent with
  replay, freshness validation, and audit timestamps.
- Added bounded resolver revision, observation, freshness, and fact-set digest
  evidence to durable `AuditEntry` values without claiming individual-fact
  provenance or obligation execution.
- Made unaudited Axum construction explicit instead of using it as the normal
  `Gatekeeper::new` path.

### `gatekeep-sqlx`

- Validated tenant table and column identifiers and applied typed tenant
  predicates to both filters and grade projections.
- Updated Dovecote audit sinks to the tenant-scoped 0.2 adapter API.
- Made the current history decoder require a tenant-scoped `PagedEvent` and
  current binding/evidence; legacy-shaped payloads require an explicit,
  versioned migration importer.

### `gatekeep-keepsake`

- Updated the bridge to Keepsake 3's explicit tenant provider operations.
- Retained tenant identity on lifecycle targets and commands so equal subject
  ids cannot cross tenant boundaries through the bridge.

### Migration

Apply the tenant-aware Dovecote 0.2 schema and crates first, then the Keepsake 3
dependency and bridge, and finally update all Gatekeep crates together. See
[`docs/operations/migrations.md`](docs/operations/migrations.md).

## [2.0.1] - 2026-08-28

Patch release for the 2.0 durable-audit integration and documentation.

### Documentation

- Corrected every durable-audit setup example to construct
  `gatekeep_axum::Gatekeeper` with an application-owned `FactResolver` and a
  Dovecote-backed `PgDovecoteAudit`.
- Added a compile-checked Axum setup example so the documented composition is
  exercised by the workspace build.

### `gatekeep-axum`

- Documented that the default occurrence clock is internal to the adapter.
  Callers needing retry-stable time continue to supply a
  `DecisionAuditOccurrence` in `Context`.

### Packaging

- Bumped all publishable workspace crates to 2.0.1 and raised the sibling
  Dovecote and Keepsake caret requirements to 0.1.1 and 2.1.0.

## [2.0.0] - 2026-08-27

Gatekeep 2.0 is a breaking release. Durable SQL decision audit now uses
Dovecote as its sole maintained event and delivery model.

### `gatekeep`

- Added typed `DecisionAuditId` values, generated before persistence and
  reusable across retries.
- Added authoritative decision occurrence time to `AuditEntry`.

### `gatekeep-axum`

- Captures occurrence time once after evaluation at the authorization boundary.
- The default occurrence clock is internal to the adapter; callers can supply a
  `DecisionAuditOccurrence` in `Context` when retry stability is required.

### `gatekeep-sqlx`

- Replaced Gatekeep-owned audit repositories and child/outbox tables with
  Dovecote-backed `PgDovecoteAudit`, `SqliteDovecoteAudit`, and
  `MySqlDovecoteAudit` sinks.
- Added concrete caller-owned transaction methods and preserved typed Dovecote
  validation, idempotency, and transient errors through adapter errors.
- Retained the v1 audit migrations as immutable upgrade artifacts only.

## [1.1.0] - 2026-08-27

### `gatekeep-sqlx`

- Added an opt-in Dovecote migration bridge for Postgres, SQLite, and MySQL.
  Existing audit constructors and default `AuditSink` behavior remain
  legacy-only.
- Added one-transaction legacy normalized audit plus pending Dovecote
  dual-write APIs, persisted publisher identity mappings, and bounded,
  resumable complete-history import with delivered-state preservation and
  claim fencing.
- Added additive `0002_dovecote_bridge.sql` migrations. Historical `0001`
  migration bytes remain unchanged.

See [the Dovecote bridge guide](https://github.com/plethu/gatekeep/blob/v1.1.0/docs/guides/dovecote-bridge.md)
for feature selection and rollout semantics.

## [1.0.1] - 2026-07-12

### Reliability

- Fixed MySQL durable audit writes by quoting the reserved reason-parameter
  `key` column.
- Added Docker-backed Postgres and MySQL audit round-trip tests to CI.
- Resolved `keepsake` from crates.io so a standalone checkout can build without
  a sibling repository.

### Documentation

- Documented public `Result` failure contracts and made missing `# Errors`
  sections a denied workspace lint.

## 1.0.0 - 2026-07-09

First stable release. Semver applies to the public Rust API and to audit schema
expectations in `gatekeep-sqlx` from this version onward.

### Documentation

- Moved human documentation from the Astro docs site into [`docs/`](docs/README.md).
- Added a lattice rationale in [Lattice outcomes](docs/concepts/lattice-outcomes.md).

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

- CI runs on pull requests via GitHub Actions.
- Depends on `keepsake` 1.0.

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

[2.0.1]: https://github.com/plethu/gatekeep/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/plethu/gatekeep/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/plethu/gatekeep/compare/v1.0.1...v1.1.0

[1.0.1]: https://github.com/plethu/gatekeep/releases/tag/v1.0.1
[0.4.0]: https://github.com/plethu/gatekeep/releases/tag/v0.4.0
[0.2.0]: https://github.com/plethu/gatekeep/releases/tag/v0.2.0
[0.1.0]: https://github.com/plethu/gatekeep/releases/tag/v0.1.0
