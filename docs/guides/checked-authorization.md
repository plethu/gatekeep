# Checked authorization and audit

`PreparedPolicy::new` stores an immutable policy, its existing versioned hash
and its sorted required-fact identities. Prepare once during application setup.
The policy hash format has not changed.

Freshness is checked at the decision boundary. Awaiting audit does not freeze
the clock or source state; a protected write needs the application's transaction
or revision contract. A delayed operation must reauthorize. Explicitly unaudited
construction creates no durable record, even though it returns the same typed
decision shape.

`Authorizer` owns the shared boundary used by workers and Axum: context
validation, fact resolution, receipt-time validation, evaluation, evidence,
required persistence, then observation. `Gatekeeper::authorize_prepared` adds
HTTP presentation. `authorize_policy` and the older Axum `authorize` retain the
published omission-as-absence behavior for existing callers.

Every required fact in the checked path must be explicitly true or false.
Omitted results fail before evaluation. Query-deferred unknowns belong to
`PartialFacts`; source failures are typed errors. Do not turn an unavailable
backend into a negative observation with `unwrap_or(false)`.

Point checks need only `FactResolver::resolve_for_decision`. Implement the optional
`QueryFactResolver` trait on the same resolver when you also need partial facts
for SQL list filtering; there is no default query resolution.

## Evidence

Set-level source, revision, observation time and digest remain valid evidence.
When a provider can establish individual observations, construct bounded
`FactObservation` values and attach them with `with_observations`. Their boolean
values must agree with the explicit facts. Duplicate identities are rejected;
accepted observations are sorted. Each observation's expiry is checked at the
decision boundary, even if the set has no expiry.

The limit is 256 selected observations per record, with bounded identities and
source metadata. Select references and authorization metadata rather than case
content. There is no automatic Debug capture. A source label is an application
assertion, and a digest is neither encryption nor proof that a source was honest.

Audit schema 2 carries selected observations. Schema 1 remains readable and
retains its schema marker and set-only meaning. See the
[migration notes](../operations/improvement-migration.md).

## Failures and retry

Use `prepare` to freeze a checked decision when an audit write may need retry.
It returns `PendingDecision`, which is not permission to act. Persist that same
value with `persist_pending`; on success, inspect the decision before disclosure.
The retry preserves the entire event, including observation times and identity.
A successful retry records an old decision; it does not refresh its authority
for a later write. Reauthorization creates a new occurrence.

Dovecote's concrete record methods distinguish a newly enqueued event from an
identical already-enqueued event and reject a changed payload under the same
identity. A database/commit error can be uncertain. Retain the frozen event and
reconcile or retry it; do not assume failure means no write happened.

`authorize_recording_attempts` additionally requires an `AttemptAuditSink` for
failures before a complete decision can be recorded. Attempts have a separate
event type and no invented deny trace. If both authorization and attempt
persistence fail, the returned `Persistence` variant retains both failures and
the frozen attempt. Invalid or expired context returns `Unscoped`: the app must
use its authentication audit boundary, not fabricate a tenant for Gatekeep.

A denied operation needs a committed audit transaction. Rolling back an event
with the operation does not leave a durable denial record. The
[record service](record-service.md) commits denials explicitly and fences permit
resolution, projection and audit with SQLite's write transaction.

## Batches and obligations

`BatchFactResolver` is a real provider bulk-load contract, without a default
single-item loop. `authorize_batch` enforces an explicit size limit and exact
output cardinality, retains input order, and revalidates each item's freshness.
`into_strict` returns all completed decisions or the whole failed batch with its
evidence. A denial is a completed decision, not a source failure.

Persistence is per item. Strict response handling does not make multiple writes
atomic. Dropping the future cancels remaining work; earlier events may already
be durable and the in-flight write may be uncertain. No background tasks or
cross-request permission caches are created.

Obligations remain attached to decisions. The application must satisfy any
prerequisites before disclosing data. Neither an obligation value nor a SQL
projection proves that the obligation was executed.
