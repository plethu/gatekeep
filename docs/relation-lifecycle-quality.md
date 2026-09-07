# Initial post-feature quality audit

This records the bounded audit after feature implementation and before the
subsequently authorized stricter maintainability alignment. It covers Keepsake,
Gatekeep and Dovecote at that earlier stage. Current scope and final verification
status are recorded in the [handoff](relation-lifecycle-handoff.md) and Gatekeep's
[maintainability contract](maintainability.md). The findings below remain an
account of that initial audit, not an inventory of all subsequent changes.

| Project | Finding | Correction |
| --- | --- | --- |
| Keepsake | Both PostgreSQL examples installed Dovecote before the fresh Keepsake migration, which rejects an unmarked nonempty schema. | Install Keepsake first, then Dovecote, then check the combined schema. |
| Keepsake | Revoking an unknown assignment could bypass transaction schema/isolation validation. | Check the caller transaction before lookup on all three backends; add wrong-track and wrong-isolation regressions. |
| Keepsake | The established SQL adapter guide described exact retries as active duplicate prevention. | Explain original committed receipts, conflicting reuse, current authority and caller rollback; index the new transaction guide. |
| Gatekeep | The standalone consumer was outside the named executable verification lanes. | Add a dedicated source-consumer check and database lane, with explicit sibling-source prerequisites. |
| Gatekeep | Two private examples retained unused `time` dependencies; the standalone consumer lacked version bounds on five local dependencies. | Remove the unused declarations and add the appropriate public major versions to the local dependency declarations. |
| Dovecote | The unpublished migration fixture directly depended on UUID without using it. | Remove that dependency and let Cargo prune its now-unused lockfile entries. Public packages were unchanged at that stage. |

The consumer uses unpublished Keepsake 6 sources. Ordinary Gatekeep package/PR
checks cannot establish that cross-repository contract. Its explicit lane must
run against matching sibling revisions; local runs are source evidence, not
registry verification or a remotely executed CI result. No publication or remote
workflow execution was performed for this audit.

## Scope and evidence

The audit traced just/mise commands through their scripts and CI callers, checked
effective member and standalone lint coverage, and inspected representative core,
authorization, transaction, migration, error, delivery and documentation paths.
Signal searches were followed by contextual reads. Canonical gates and real
backend evidence are recorded in the [handoff](relation-lifecycle-handoff.md).
The audit reused those current-run results rather than launching competing
database suites. Cargo-machete also checked Dovecote's standalone migration
fixture and confirmed the removed dependency was unused.

At this initial stage, Keepsake and Gatekeep members inherited their existing
lint policies; Dovecote used its established default Clippy policy and structural
rules. The consumer copied Gatekeep's then-existing policy, including two group
overrides. The later alignment strengthens selected restrictions and tooling and
removes the redundant module-name override; the remaining exceptions and exact
scope are documented in each current maintainability report. No gate was
weakened and no size baseline was raised.

## Strengths and dismissed signals

The core evaluator remains independent of storage and runtime. SQLx owns
transactions and migration receipts; the adapters state their actual locking
differences. Dovecote still has one immutable event store and separate mutable
delivery state. Backend tests exercise stale claim tokens, lock waits, conflicts,
rollback and complete delivered history, rather than only successful calls.

Backend SQL duplication reflects real locking and catalog differences. Existing
audit constructor argument counts do not justify breaking validated durable
types merely to shorten signatures. Complete assignment history has an explicit
query/memory cost. Dovecote uses established URI, MIME, JSON, Base64 and entropy
libraries; its ordered projection is a tested durable-byte contract, not a reason
to replace Serde. SQLite's small native transaction-state inspection retains the
SQLx handle lock while calling the read-only C API. Test assertions and validated
constant conversions were not reported as production panic defects.

This was a bounded repository audit, not proof that every path or deployment is
defect-free. Live RLS, optional high-cardinality stress, live CDC and remote CI
were outside this run's evidence. Published-package readiness remains a separate
gate once the new core package is available from the registry.

## Independent review

A fresh GPT-5.6-Sol review at medium reasoning covered the feature changes
and executable consumer after this initial audit. It found no material source defect and
one contradictory verification sentence. That sentence was corrected; re-review
reported no unresolved findings. The review checked transaction ownership,
receipt/replay semantics, absent-state fencing, effective expiry, scoped evidence,
immutable delivery history and prior-version migration behavior. This records a
source review, not an additional database run or a publication approval.

That initial review does not cover the subsequent broader maintainability
alignment. A fresh review and final sibling verification are tracked separately
in the current handoff.
