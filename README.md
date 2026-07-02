# gatekeep

> The soul selects her own society,
> Then shuts the door;
>
> — Emily Dickinson, "Exclusion" (1890)

`gatekeep` is a code-first authorization engine for Rust. Policies are ordinary
Rust values, a pure deterministic core evaluates them, and every decision
carries the reasons that produced it.

It is the sibling of [`keepsake`](../keepsake-rs): keepsake keeps relation
lifecycle state — entitlements, holds, sanctions, risk flags, gates — and
gatekeep decides what those facts permit. The two compose but stay independent crates.

## Where it fits

Use gatekeep for an in-process authorization boundary authored in Rust, by the
team that owns the application. Policies are composable combinators over a
frozen set of facts, evaluated synchronously with no IO, so a decision replays
exactly from its inputs.

It is not a policy DSL, an authentication or session layer, or a network policy
service; those stay with the application or with crates built for them. Because
each policy is reified as inspectable data, gatekeep can serialize, hash, diff,
and explain a decision. It can also answer "which resources can this principal
reach?", not just "may this principal reach this one?".

## Usage

```rust
use gatekeep::{
    condition, evaluate, policy, DecisiveClause, Effect, Fact, GatekeepResult, KnownFacts,
    Lattice, ReasonCode, StaticFactId,
};

// Outcome grade: how much of a record the caller may read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
enum ReadAccess {
    Redacted,
    Full,
}

impl Lattice for ReadAccess {
    fn meet(&self, other: &Self) -> Self { (*self).min(*other) }
    fn join(&self, other: &Self) -> Self { (*self).max(*other) }
    fn top() -> Self { Self::Full }
    fn bottom() -> Self { Self::Redacted }
}

// A fact the application resolves before evaluation.
struct CaseOwner;

impl Fact for CaseOwner {
    const ID: StaticFactId = StaticFactId::new("case_owner");
}

fn read_access() -> GatekeepResult<()> {
    // "The case owner may read the full record."
    let owner_full_read = policy::grant(ReadAccess::Full, condition::has::<CaseOwner>())
        .try_labeled("owner_full_read")?
        .try_reason("not_case_owner")?;

    // The owner is permitted, with the granted grade carried on the effect.
    let permitted = evaluate(&owner_full_read, &KnownFacts::new().with_present::<CaseOwner>());
    assert_eq!(permitted.effect, Effect::Permit(ReadAccess::Full));

    // A non-owner is denied, and the decision explains itself instead of
    // returning a bare "no": the facts that were missing and a stable reason
    // code your UI or audit log can map to a message.
    let denied = evaluate(&owner_full_read, &KnownFacts::new());
    assert_eq!(denied.effect, Effect::Deny);
    if let DecisiveClause::Deny { reason, unsatisfied, .. } = &denied.trace.decisive {
        assert_eq!(reason.as_ref().map(ReasonCode::as_str), Some("not_case_owner"));
        assert_eq!(unsatisfied.len(), 1); // the missing case_owner fact
    }

    Ok(())
}
```

Partial evaluation reuses the same policy value with `PartialFacts`: mark
request-known facts as present or absent, leave resource-level facts unknown,
then lower the residual policy in an application-owned adapter. For SQL-backed
list queries, `gatekeep-sqlx` maps residual facts to trusted row predicates and
appends a lowered filter and grade projection to a `sqlx::QueryBuilder`.
Postgres is the default backend; SQLite and MySQL are available behind feature
flags.

For durable decision audit, configure an async `AuditSink`. `gatekeep-sqlx`
provides `SqlxDecisionAuditRepository` plus Postgres, SQLite, and MySQL aliases.
Run the audit migration for your backend, pass the repository to
`Gatekeeper::with_audit_sink`, and the Axum adapter will await the audit write
before returning permit or deny. The SQL schema stores the decision row, consulted
facts, obligations, request subjects, reason parameters, and an outbox row for
export workers.

```rust
use gatekeep::Gatekeeper;
use gatekeep_sqlx::PgDecisionAuditRepository;

let audit = PgDecisionAuditRepository::new(pg_pool.clone());
let gatekeeper = Gatekeeper::new(policy).with_audit_sink(audit);
```

Use the matching migration under `gatekeep-sqlx/migrations/{postgres,sqlite,mysql}`.
Export workers can page `gatekeep_audit_outbox` by id and transform the stored
`AuditEntry` payload for Kafka, Restate, S3, or warehouse ingestion.

For the lowering walkthrough, see the `gatekeep-sqlx` docs on
[docs.rs](https://docs.rs/gatekeep-sqlx) and the
[`axum-authorized-list`](examples/axum-authorized-list) and
[`axum-keepsake-authorized-list`](examples/axum-keepsake-authorized-list)
examples, which resolve request facts in-process and from keepsake.

`gatekeep-keepsake` resolves gatekeep facts from active keepsake relations. The
default resolver maps the request principal to a keepsake subject, and bindings
can target additional request-scoped subjects through `SubjectSlot` values in
`Context::subjects`. Use that for facts attached to something other than the
principal, such as a skill version, repository, account, or source identity. A
missing subject slot is reported as `ResolveError::MissingSubject`, distinct
from an unbound or unproducible fact.

The resolver can also expose the same `(SubjectRef, RelationId)` target it uses
for reads through `target_for_fact` and `targets_for_facts`. Lifecycle code can
turn that target into a keepsake `RevokeBySubject` command without taking on a
SQLx dependency. `KeepsakeResolver<S>` intentionally stays generic over
`S: ActiveRelationSource`; use keepsake's `DynActiveRelationSource` at
application composition boundaries when runtime erasure is needed.

## Why it exists

The Rust authz ecosystem leans on external DSLs. A policy DSL is worth its
overhead across many services and for non-engineer authors; for a single Rust
service it mostly adds cost: a second language, the domain re-encoded as entities
and attributes, and typos that fail at runtime instead of compile time. gatekeep
keeps policies in Rust and reifies them as data, so they stay analyzable.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license

at your option.
