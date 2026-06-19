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
gatekeep decides what those facts permit. The two compose, but they are
independent crates; keepsake's charter excludes authorization, so this is a
separate project rather than a keepsake module.

## Status

Early implementation. The `gatekeep` crate ships the pure policy model,
evaluation, partial evaluation, traces, denial reasons, and adapter traits.
[`docs/SPEC.md`](docs/SPEC.md) remains the design contract while the public API
settles.

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
    condition, evaluate, policy, Effect, Fact, KnownFacts, Lattice, StaticFactId,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
enum ReadTier {
    Released,
    Full,
}

impl Lattice for ReadTier {
    fn meet(&self, other: &Self) -> Self {
        if *self == Self::Released || *other == Self::Released {
            Self::Released
        } else {
            Self::Full
        }
    }

    fn join(&self, other: &Self) -> Self {
        if *self == Self::Full || *other == Self::Full {
            Self::Full
        } else {
            Self::Released
        }
    }

    fn top() -> Self {
        Self::Full
    }

    fn bottom() -> Self {
        Self::Released
    }
}

struct Staff;

impl Fact for Staff {
    const ID: StaticFactId = StaticFactId::new("staff");
}

let policy = policy::grant(ReadTier::Full, condition::has::<Staff>());
let facts = KnownFacts::new().with_present::<Staff>();
let decision = evaluate(&policy, &facts);

assert_eq!(decision.effect, Effect::Permit(ReadTier::Full));
```

Partial evaluation uses the same policy value with `PartialFacts`: mark
request-known facts as present or absent, mark resource-level facts as unknown,
then lower the returned residual policy in an application-owned adapter.

## Why it exists

The Rust authz ecosystem leans on external DSLs. A policy language earns its
keep across many services and non-engineer authors, but for a single Rust
service those benefits mostly disappear and the costs stay: a second language,
the domain serialized into entities and attributes, and typos that fail at
runtime instead of compile time. gatekeep keeps policies in Rust and takes one
lesson from the DSL world, reifying them as data so they stay analyzable.

It is the authorization half of the story keepsake tells. Keepsake records what
is true of a subject; gatekeep decides what that permits.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license

at your option.
