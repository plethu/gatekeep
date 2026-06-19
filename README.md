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

Design stage. [`docs/SPEC.md`](docs/SPEC.md) is the contract, and no code ships
with it yet. The spec defines the model, the two-layer algebra, and the decision
procedure; this README grows an install and usage section once the crates land.

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
