# gatekeep

> The soul selects her own society,
> Then shuts the door;
>
> — Emily Dickinson, "Exclusion" (1890)

`gatekeep` is a code-first authorization engine for Rust. Policies are ordinary
typed values, so the compiler and your tests can see the same rules that run in
production. Evaluation is deterministic, and every decision includes the facts
and policy clause that produced it.

It fits applications where Rust owns the authorization model. If policy needs
to live outside the codebase or cross service and language boundaries, use a
shared policy system instead.

## A policy

```rust
use gatekeep::{condition, evaluate, policy, Effect, Fact, GatekeepResult, KnownFacts, StaticFactId};

struct CaseOwner;

impl Fact for CaseOwner {
    const ID: StaticFactId = StaticFactId::new("case_owner");
}

fn main() -> GatekeepResult<()> {
    let may_read = policy::grant((), condition::has::<CaseOwner>())
        .try_reason("not_case_owner")?;

    let facts = KnownFacts::new().with_present::<CaseOwner>();
    let decision = evaluate(&may_read, &facts);
    assert_eq!(decision.effect, Effect::Permit(()));

    Ok(())
}
```

Your application authenticates the request and supplies the facts. Gatekeep
evaluates them. The same policy can authorize one request, become a SQL filter
through `gatekeep-sqlx`, and leave a decision trace for audit.

For durable audit, `gatekeep-sqlx` writes complete decision events through
[Dovecote](https://github.com/plethu/dovecote). The
[`gatekeep-keepsake`](https://docs.rs/gatekeep-keepsake) adapter reads relation
state from [Keepsake](https://github.com/plethu/keepsake).

## Install

```sh
cargo add gatekeep@3
```

Add only the adapters you need:
[`gatekeep-axum`](https://docs.rs/gatekeep-axum),
[`gatekeep-fluent`](https://docs.rs/gatekeep-fluent),
[`gatekeep-keepsake`](https://docs.rs/gatekeep-keepsake), and
[`gatekeep-sqlx`](https://docs.rs/gatekeep-sqlx).

Start with the [quickstart](docs/quickstart.md), read about
[graded outcomes](docs/concepts/lattice-outcomes.md), or browse the full
[documentation](docs/README.md). The core API is on
[docs.rs](https://docs.rs/gatekeep).

Licensed under `MIT OR Apache-2.0`.
