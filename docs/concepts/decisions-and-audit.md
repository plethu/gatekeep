# Decisions And Audit

A Gatekeep decision is more than a boolean. It records the effect, obligations,
facts consulted by evaluation, and the clause that fixed the result.

## Decision Shape

`Decision<O>` contains:

- `effect`: `Permit(O)` or `Deny`
- `obligations`: follow-up work attached to a permit path
- `trace.consulted`: facts read during evaluation
- `trace.decisive`: the permit or deny clause that decided the result

The outcome type `O` remains typed during evaluation. Use `Decision::to_trace`
when a durable sink needs a non-generic serialized trace.

## Denial Reasons

Grant clauses can carry reason codes. A denial reason gives UI, API, and audit
layers a stable code plus structured parameters.

```rust
let policy = policy::grant(ReadAccess::Full, condition::has::<CaseOwner>())
    .try_labeled("owner_full_read")?
    .try_reason("not_case_owner")?;
```

The reason code should be stable enough to translate and search. Human wording
belongs in a reason catalog such as `gatekeep-fluent`, not in the policy value.

## Audit Entries

`AuditEntry` stores the decision envelope:

- request id and subjects
- policy anchor
- effect
- obligations
- consulted facts
- decisive clause and trace data
- denial reason parameters

The core `AuditSink` trait is async because durable audit usually performs IO.
`NoopAuditSink` is available for applications that do not record decisions, and
the test feature exposes `InMemoryAuditSink` for assertions.

`gatekeep-sqlx` provides a queryable SQL audit repository. The Axum adapter
awaits the audit sink before returning the authorization result.
