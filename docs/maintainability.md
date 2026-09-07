# Maintainability contract

Gatekeep owns deterministic authorization and auditable decision records.
Applications own authenticated identities, current facts, transactions and the
business operation. Maintained adapters use SQLx, Dovecote, Axum and Fluent at
those boundaries. This document records the repository's alignment criteria and
the specific compatibility decisions that constrain changes.

| Criterion | Owner and enforcement | Deliberate boundary |
| --- | --- | --- |
| Setup and familiar commands | Pinned mise tools; `just fmt`, `clippy`, `test`, `check`, `supply-chain`, explicit database recipes | `check` owns acceptance; database startup is explicit |
| One gate owner | `scripts/check-project-gates.sh`, called by mise/just/CI | Local source checks are opt-in; PR/main CI has a separate mandatory job with reviewed sibling commit pins |
| Actual lint coverage | Root members inherit workspace lints; standalone consumer declares the same selected policy | No file-name exemptions or size-baseline increases |
| Unsafe and unfinished work | Unsafe forbidden; panic/unwrap/expect/todo/unimplemented/dbg/exit/unreachable denied | Normal assertion-based tests remain tests, not error-handling code |
| Bounds and conversions | Selected bounds, slicing, conversion and time lints | Indexed test assertions have a narrow Clippy test setting; production remains checked |
| Import readability | `absolute_paths` with a two-segment threshold | Qualified names remain where trait/type disambiguation requires them |
| Exception hygiene | Reasons required for existing allow attributes; unfulfilled expectations denied | One published audit constructor retains a compatibility exception described below |
| Public types | Private invariant fields, validating constructors and serde wire conversions | Opaque application identity and authoritative-time mapping remain application-owned |
| Errors and diagnostics | Typed domain/adapter errors; HTTP responses redact backend detail | Synthetic executable aggregates application errors and avoids printing credentials |
| Effects and cancellation | Pure evaluator; async only at I/O boundaries; caller-owned transactions explicit | Snapshot facts do not prove a concurrent write is fenced |
| Durable contracts | Stable policy hash/typed audit occurrences; current and historical decoders separate | No historical migration rewrite, dual writer or second outbox |
| Module ownership | Context, resolution, output hooks, query lowering and durable audit have distinct modules | Public root reexports preserve the published API |
| Commodity infrastructure | Serde/Postcard/BLAKE3, SQLx, Dovecote, Fluent and time | Const identity checks validate forbidden UTF-8 sequences without a second general decoder |
| Observable determinism | Ordered facts/trace collections, explicit clock and stable occurrence IDs | Source authority and checklist completeness cannot be inferred by a library |
| Database behavior | PostgreSQL/MySQL live lanes and SQLite tests | Backend isolation/locking promises belong to the owning lifecycle adapter |
| Dependency and package evidence | cargo-deny and package verification; inspectable local overrides for source integration | Source overrides and registry resolution are separate evidence |
| Public prose and examples | README one adoption example; compile-tested documentation; named transaction consumer | Game-specific migration instructions remain a separate integration document |

## Published compatibility exception

`AuditEntry::new` is a published Gatekeep 4 constructor with fifteen semantic
arguments. Removing that signature merely to satisfy an argument-count rule
would force an unrelated major release on callers. Its existing
`too_many_arguments` exception remains, with an explicit compatibility reason.
The constructor validates the actual tenant, occurrence, fact evidence and
trace relationships. An obsolete exception on the five-argument historical
conversion was removed. Any future public replacement must model a real audit
occurrence/context boundary and migrate callers deliberately; an anonymous
parameter bag is not the acceptance criterion.

The remaining `multiple_crate_versions` Cargo lint setting reflects the shared
SQLx/HTTP/dependency graph, not permission to ignore advisories: cargo-deny
continues to inspect and report duplicate versions under repository policy. The
current graph includes digest 0.10/0.11 and sha2 0.10/0.11 through SQLx
authentication dependencies, and rand 0.9/0.10 plus getrandom 0.3/0.4 through
the runtime/test ecosystem. Forcing one transitive version would require changing
upstream contracts; the public library does not own those interfaces.
The redundant blanket `module_name_repetitions` override was removed rather than
copied into newly maintained surfaces.

## Verification scope

The maintained source-integration command is
`mise exec -- just check-relation-consumer`; add its live PostgreSQL proof with
`mise exec -- just test-relation-consumer` and an explicitly supplied disposable
`DATABASE_URL`. `CONTRIBUTING.md` describes reproducible sibling revisions and
the mandatory PR/main source job and its reviewed sibling commit pins. Static
source validation and workflow wiring are not evidence that remote CI passed.

## Selected restriction scope

The canonical gate additionally applies `arithmetic_side_effects` and
`panic_in_result_fn` and `unreachable_pub` to workspace libraries and binaries without compiling test
harnesses. Existing tests use normal assertions and authored timestamp arithmetic;
the all-target pass still forbids direct panic, unwrap and expect calls. The
standalone transaction consumer is an executable regression harness, so it uses
the all-target policy and mandatory live assertions rather than pretending its
assertion functions are production request handlers. Its bounds, conversion,
path and exception checks are the same selected all-target policy.

`cargo machete crates examples` checks implementation manifests, including the
standalone consumer. The repository documentation package's dependencies are
used in Markdown included through `include_str!`; machete does not expand those
external code blocks. Mandatory Cargo doctests and strict rustdoc verify that
specific harness instead. No ignored-dependency annotations are installed.

Taplo formats maintained TOML without sorting authored keys; typos checks the
tracked source/documentation surface. Both tools are pinned and required by the
canonical gate. Cargo's established test runner remains appropriate here: it
executes property, integration and documentation tests without introducing a
second runner or splitting the default acceptance path.

## Ownership review

The former adapter module mixed five distinct public responsibilities in one
1,424-line owner. Context construction, fact resolution, output hooks, query
lowering and audit entries now have separate private modules and unchanged root
reexports. SQL fragments similarly separate backend binding, validated tenant
columns and driver configuration. The recursive evaluator and residualizer
remain cohesive owners: their exhaustive matches describe the policy algebra,
not a generic workflow. A private `Permit` keeps the outcome, obligations and
decisive trace together while lattice branches combine, replacing nested tuples.

The audit module remains a single durable-contract owner: current validation,
explicit historical import and shared trace consistency must agree. The identity
module owns generated opaque identifiers and validated audit occurrence identity;
it has no I/O or general-purpose parser. Neither is split solely to meet a line
count. Published audit encoding uses Serde/Postcard, policy identity uses the
existing versioned canonical representation and BLAKE3, and SQL rendering owns
only authorization predicates passed to SQLx bind APIs. Changing those durable
bytes or adopting a general query framework would add migration and abstraction
cost without retiring an unowned commodity subsystem.

The const tenant validator now rejects C1 controls consistently with owned
identities and traverses valid UTF-8 byte slices without an independent Unicode
decoder. Existing authored policy-hash vectors, current/legacy audit tests,
property tests and live SQL differential tests remain the behavior checks for
these internal refactors.

`unreachable_pub` is enforced on production library/binary targets. Applying it
also to private integration-test namespaces conflicts with nursery's
`redundant_pub_crate`: one demands narrower item visibility while the other
rejects that same visibility inside private modules. Test/helper visibility and
public library contracts are preserved; no suppression is introduced for either
lint. The standalone regression binary has no exported library API.

Static identity validation also rejects Unicode-only whitespace consistently
with owned identity validation, including all 25 Unicode White_Space scalars.
The public const API requires a finite UTF-8 prefix check because the pinned
compiler does not support const `str::trim` or `str::chars`; regression cases
compare the static boundary with the standard-library-based owned constructor.

The quality fixes stage `gatekeep` and `gatekeep-sqlx` 4.0.1 patches. Their
compatible dependency lower bounds remain unchanged. The effective-relation
adapter uses the 5.0.0 major for Keepsake 6.0.0. Source integration
uses the current Dovecote 0.2.2 checkout while its compatible published dependency
minimum remains 0.2.1; matching reviewed sibling commits are required inputs to
the source workflow. The required PR/main caller records full reviewed sibling
commits explicitly.

## Verification performed

The final alignment was verified on the pinned Rust 1.96 toolchain with local
Keepsake 6 sources. These local alignment checks performed no commit,
publication or remote workflow execution; subsequent release preparation and
remote CI are separate evidence.

| Check | Evidence |
| --- | --- |
| Canonical gate with standalone opt-in | Passed formatting, structural rule tests/scan, all-target/all-feature Clippy, production restrictions, Taplo, typos, machete, cargo-deny, strict rustdoc, and 134 unit/integration/doc tests; ten live database tests were explicitly ignored in this lane |
| PostgreSQL 17.11 | All six ignored backend tests passed, including live SQL differential and immutable audit rollback/replay |
| MySQL 8.4.11 | All four ignored backend tests passed, including live SQL differential and immutable audit rollback/replay |
| Standalone source consumer | Strict checks and complete live PostgreSQL proof passed, including persisted-expiry renewal, rollback of all six events, fresh assignment identity, and no terminal event repetition |
| Feature selection | Production Clippy passed separately for PostgreSQL, SQLite and MySQL with default features disabled; runtime-free core passed without default features |
| Unsupported backend selection | No-backend build failed with the documented requirement to select PostgreSQL, SQLite or MySQL |
| Public package archives | All five public packages assembled and verified using the local Keepsake override and Cargo's staged package registry |
| Registry-only package check | At the pre-release audit, the registry did not yet contain Keepsake 6; repeat against published dependencies before release |
| Hygiene | Temporary Cargo configuration removed; ShellCheck and Git whitespace checks passed |

The inherited RSA advisory exception in `deny.toml` remains narrowly scoped to
SQLx's MySQL public-key password encryption path, confirmed in the resolved SQLx
implementation. Its existing review deadline and removal conditions remain;
no advisory exception or lint suppression was added. The PostgreSQL-only
consumer reports that exception as unused because it shares the root deny
policy without selecting MySQL.

The pinned compiler lists `excessive_nesting` in `clippy::all`, so it was already
enforced by the prior strict gate. The actual alignment change is lowering the
threshold from five to four; the explicit individual deny records intent rather
than fixing a previously inactive check. Likewise, the prior nursery warning
level was already fatal under `-D warnings` in the canonical gate.

Live fixtures used PostgreSQL 17.11 and MySQL 8.4.11. The repository's exact
Compose images (PostgreSQL 17.6 and MySQL 9.5) were not repeated in this pass;
source/backend evidence is not a claim to have executed those image versions.

A follow-up review tightened unsupported driver diagnostics further: parseable
`prefix:value` text can still be a raw username/password pair. Only a validated
explicit `scheme://` shape retains an unsupported scheme; ambiguous prefixes
produce `None`. Regression cases include scheme-shaped private usernames, and
supported PostgreSQL/MySQL/SQLite aliases retain their prior detection paths.

After that review fix, all 17 SQL-lowering tests passed with every backend
feature enabled, SQLx all-target/all-feature strict Clippy passed, and the
current gatekeep-sqlx 4.0.1 archive was rebuilt and verified. No database path
changed in this diagnostic-only correction.
