# Authorization Model

Gatekeep treats authorization as a pure decision over known facts. The policy
does not read the database or inspect HTTP state. The application does that work
first, then passes typed facts to evaluation.

## Policies Are Data

A policy is a Rust value made from combinators such as `grant`, `deny_when`,
`all`, `any`, and `or_else`. Because the policy is data, adapters can evaluate
it, partially evaluate it, inspect required facts, hash it, and record the
decisive clause.

```rust
let owner = policy::grant(ReadAccess::Full, condition::has::<CaseOwner>())
    .try_labeled("owner_full_read")?
    .try_reason("not_case_owner")?;

let not_suspended = policy::deny_when(
    condition::has::<SuspendedAccount>(),
    "account_suspended",
);

let read_policy = policy::all([not_suspended, owner]);
```

`all` combines requirements. `any` combines alternatives. `or_else` supplies a
fallback policy when the primary path does not permit.

## Facts Are Boundary Values

Facts are stable identifiers for things the application already knows or can
resolve. A fact can come from a request, a row, a cache, Keepsake, or a service
call. Gatekeep only sees whether the fact is present, absent, or unknown during
partial evaluation.

Keep facts small and specific. `case_owner` is easier to test, audit, and lower
than a broad `can_read_case` fact. The policy should express the authorization
rule; the resolver should only provide inputs.

## Outcomes Carry Access

A permit can carry more than yes. The outcome might be a role, a redaction
level, a permission set, or a data-scope grade. See [Lattice outcomes](../concepts/lattice-outcomes.md)
for why Gatekeep models that combination as a lattice and how `all` and `any`
use `meet` and `join`.

Use `Effect::Deny` for failure. Use typed permit outcomes for the access level
the application may apply after the decision.

## Evaluation Is Replayable

Evaluation returns:

- `Effect::Permit(outcome)` or `Effect::Deny`
- obligations attached to the decisive permit path
- a trace of consulted facts
- the clause that fixed the result
- denial reason data when a grant fails

The audit layer stores that envelope so the service can answer the later
question: "what did this request know, and which policy clause mattered?"
