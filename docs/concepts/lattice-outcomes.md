# Lattice Outcomes

A Gatekeep permit carries an outcome. The outcome can be a simple enum such as
`ReadAccess::Full`, or a richer type such as a set of allowed operations. The
`Lattice` trait defines how Gatekeep combines those outcomes when policies are
composed with `all` and `any`.

## Why a lattice

Many authorization checks stop at allow or deny. Gatekeep permits also carry a
grade: how much access the caller gets, not just whether the call succeeds.

Once policies compose, that grade has to combine somewhere. `all([owner, not_suspended])`
might permit `Full` and `Redacted` on the same request. `any([owner, support])`
might permit `Full` and `Redacted` through different paths. The application
still needs one answer it can apply to the response, the SQL projection, and the
audit record.

A lattice names that combination rule in one place. `meet` is the outcome you
get when every child policy has to hold at once. `join` is the outcome you get
when any child policy may grant access. For ordered tiers such as
`Redacted < Full`, `meet` is the stricter value and `join` is the broader one.

That buys three things:

1. **Composition matches policy shape.** `policy::all` always narrows with
   `meet`. `policy::any` always broadens with `join`. You write clauses for
   individual facts; the combinator applies the same rule every time.

2. **The result is deterministic.** Given the same facts, the same policy tree
   returns the same outcome. Partial evaluation and SQL lowering reuse the same
   policy value because the combination rule is fixed, not reimplemented in each
   adapter.

3. **The model stays typed.** You choose the outcome type and implement four
   methods. Gatekeep keeps permits, traces, and residual policies generic over
   that type. Boolean allow/deny is the special case `Lattice for ()`.

You do not need the full vocabulary of order theory to use this. Pick an outcome
type that matches how your service talks about access, then make `meet` and
`join` read like the policy rules your team already uses.

## The four operations

| Method | Role in composition |
| --- | --- |
| `top()` | broadest access the service models |
| `bottom()` | narrowest access the service models |
| `meet(a, b)` | combined outcome when every child in `all` permits |
| `join(a, b)` | combined outcome when several children in `any` permit |

For ordered access levels, `meet` is usually `min` and `join` is usually `max`.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
enum ReadAccess {
    None,
    Redacted,
    Full,
}

impl gatekeep::Lattice for ReadAccess {
    fn meet(&self, other: &Self) -> Self { (*self).min(*other) }
    fn join(&self, other: &Self) -> Self { (*self).max(*other) }
    fn top() -> Self { Self::Full }
    fn bottom() -> Self { Self::None }
}
```

## `all` uses `meet`

`policy::all` requires every child policy to allow the request. When several
children permit with different outcomes, the result is their `meet`.

That fits caps and overlapping requirements. One clause may grant full access to
owners while another caps access to redacted during an incident hold. The
combined permit returns the stricter grade.

## `any` uses `join`

`policy::any` allows the request when any child policy permits. When several
children permit, the result is their `join`.

That fits alternative paths to the same resource. A case owner and a support
auditor may reach the record through different clauses. If both apply, the
broader outcome wins.

## Non-total outcomes

Ordered enums are the easy case. Some access models are not a straight line. A
scope might be `Left`, `Right`, `Both`, or `None`, where left and right do not
compare as "less than" or "greater than" but still have a defined meet and join.

Implement `Lattice` with explicit match arms and test the combinations your
service relies on. Gatekeep evaluates `all` and `any` the same way whether the
outcome is a chain or a custom algebra.

## Keep the order obvious

Use enums for simple tiers. Put the lowest value first and derive `Ord` when the
order is obvious to the team.

Use a custom `Lattice` for sets, scopes, bitflags, or records. The methods should
read like policy rules, with tests for the combinations that matter:

- combining two requirements narrows access
- combining two alternatives broadens access
- `top` and `bottom` match the service's permit model

If the outcome type feels hard to explain, split the policy. A clear outcome
model matters more than fitting every authorization detail into one enum.
