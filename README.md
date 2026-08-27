# gatekeep

> The soul selects her own society,
> Then shuts the door;
>
> — Emily Dickinson, "Exclusion" (1890)

`gatekeep` is a code-first authorization engine for Rust. Policies are ordinary
Rust values, a pure deterministic core evaluates them, and every decision
carries the reasons that produced it.

The project keeps policy in Rust. A policy is an ordinary, typed value that can
be composed, tested, serialized, and hashed alongside application code. An
external policy language can be the right shared contract across services or
teams; gatekeep targets the case where Rust owns the model and the policy
should remain visible to the compiler and ordinary tests.

## Documentation

- [docs/](docs/README.md) — guides and reference for integrators
- [docs.rs/gatekeep](https://docs.rs/gatekeep) — core crate API
- Adapter crates: [gatekeep-axum](https://docs.rs/gatekeep-axum),
  [gatekeep-fluent](https://docs.rs/gatekeep-fluent),
  [gatekeep-keepsake](https://docs.rs/gatekeep-keepsake),
  [gatekeep-sqlx](https://docs.rs/gatekeep-sqlx)

Read [Combining permit outcomes](docs/concepts/lattice-outcomes.md) before designing
graded access such as redacted/full records or scope unions.

## A policy

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

The application resolves facts before evaluation. Gatekeep is an in-process
authorization boundary; it does not authenticate requests, manage sessions or
tenancy, provide a network policy service, or define a separate policy DSL.
Those concerns remain with application code or a crate built for them.

Each policy is inspectable data. Gatekeep can serialize and hash it, explain a
decision, and answer "which resources can this principal reach?", not just "may
this principal reach this one?".

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

For an explicit migration to Dovecote, enable the matching opt-in Dovecote
feature (`dovecote-postgres`, `dovecote-sqlite`, or `dovecote-mysql`; `dovecote`
enables all three) and follow the [Dovecote migration bridge guide](docs/guides/dovecote-bridge.md).
The existing audit path and legacy outbox publisher remain unchanged until the
application chooses to cut over.

For the lowering walkthrough, see the `gatekeep-sqlx` docs on
[docs.rs](https://docs.rs/gatekeep-sqlx) and the
[`axum-authorized-list`](examples/axum-authorized-list) example.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license

at your option.
