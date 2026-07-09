# Combining Permit Outcomes

Gatekeep permits carry an outcome: how much access the caller gets. That can be
a simple enum like `ReadAccess::Full`, or a richer type such as a set of allowed
operations. The `Lattice` trait defines how Gatekeep combines those outcomes
when policies are composed with `all` and `any`.

## Why a lattice

Many authorization checks stop at allow or deny. Gatekeep permits also carry a
grade. Once policies compose, that grade has to combine somewhere.
`all([owner, not_suspended])` might permit `Full` and `Redacted` on the same
request. `any([owner, support])` might permit `Full` and `Redacted` through
different paths. The application still needs one answer it can apply to the
response, the SQL projection, and the audit record.

A lattice names that combination rule in one place. `meet` is the outcome you
get when every child policy has to hold at once. `join` is the outcome you get
when any child policy may grant access. For ordered tiers such as
`Redacted < Full`, `meet` is the stricter value and `join` is the broader one.

Three consequences:

1. `policy::all` always narrows with `meet`; `policy::any` always broadens with
   `join`. Write clauses for individual facts; the combinator applies the same
   rule every time.
2. Given the same facts, the same policy tree returns the same outcome. Partial
   evaluation and SQL lowering reuse the same policy value because the
   combination rule is fixed in one place.
3. You choose the outcome type and implement four methods. Gatekeep keeps
   permits, traces, and residual policies generic over that type. Boolean
   allow/deny is just `Lattice for ()`.

Order-theory names are optional. Pick an outcome type that matches how your
service talks about access, then make `meet` and `join` match the rules your
team already uses.

## The four operations

| Method | Role in composition |
| --- | --- |
| `top()` | broadest access the service models |
| `bottom()` | narrowest access the service models |
| `meet(a, b)` | combined outcome when every child in `all` permits |
| `join(a, b)` | combined outcome when several children in `any` permit |

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

## How `all` and `any` combine outcomes

`policy::all` requires every child to permit. When children disagree on grade,
the result is their `meet`, the stricter value. One clause may grant owners
`Full` access; another caps everyone to `Redacted` during an incident hold. The
combined permit is `Redacted`.

`policy::any` permits when any child does. When several children permit, the
result is their `join`, the broader value. A case owner and a support auditor
may reach the record through different clauses. If both apply, the combined
permit is the broader of the two grades.

## Non-total outcomes

Ordered enums are the easy case. Some access models are not a straight line. A
scope might be `Left`, `Right`, `Both`, or `None`, where left and right do not
compare as "less than" or "greater than" but still have a defined meet and join.

Implement `Lattice` with explicit match arms and test the combinations your
service relies on. Gatekeep evaluates `all` and `any` the same way whether the
outcome is a chain or a custom algebra.

## Choosing an outcome type

Use ordered enums for simple tiers. Put the lowest value first and derive `Ord`
when the order is obvious to the team.

Use a custom `Lattice` for sets, scopes, bitflags, or records. Make the four
methods read like your policy rules and test the combinations your service
relies on.

If the outcome type is hard to explain, split the policy. A clear outcome model
beats a single enum that carries every authorization detail.
