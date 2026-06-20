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
and explain a decision, and answer "which resources can this principal reach?"
rather than only "may this principal reach this one?".

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
then lower the returned residual policy in an application-owned adapter. For
Postgres list queries, `gatekeep-sqlx` maps live residual facts to trusted row
predicates and appends a lowered filter and grade projection to a
`sqlx::QueryBuilder`. See [`docs/SPEC.md`](docs/SPEC.md) and the `gatekeep-sqlx`
docs for the lowering example, or
[`examples/axum-authorized-list`](examples/axum-authorized-list) for an axum
flow with in-process request facts. The
[`examples/axum-keepsake-authorized-list`](examples/axum-keepsake-authorized-list)
variant resolves request facts from keepsake before lowering resource facts into
SQL.

For point authorization, resolve every required fact into `KnownFacts` and call
`evaluate` or `Gatekeeper::authorize`. For authorized list queries, resolve
request/session facts, leave row-scoped facts as `Unknown` in `PartialFacts`, and
lower only the residual resource predicates. Keep data-boundary predicates such
as tenant id, soft-delete state, or jurisdiction outside the lowered
authorization expression; compose them as ordinary application query scope before
or around the gatekeep filter.

## Why it exists

The Rust authz ecosystem leans on external DSLs. A policy language earns its
keep across many services and non-engineer authors, but for a single Rust
service those benefits mostly disappear and the costs stay: a second language,
the domain serialized into entities and attributes, and typos that fail at
runtime instead of compile time. gatekeep keeps policies in Rust and takes one
lesson from the DSL world, reifying them as data so they stay analyzable.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license

at your option.
