# Quickstart

This example defines one fact, one graded outcome, and one policy. The policy
says that a case owner may read the full case.

```rust
use gatekeep::{
    condition, evaluate, policy, DecisiveClause, Effect, Fact, GatekeepResult,
    KnownFacts, Lattice, ReasonCode, StaticFactId,
};

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

struct CaseOwner;

impl Fact for CaseOwner {
    const ID: StaticFactId = StaticFactId::new("case_owner");
}

fn main() -> GatekeepResult<()> {
    let policy = policy::grant(ReadAccess::Full, condition::has::<CaseOwner>())
        .try_labeled("owner_full_read")?
        .try_reason("not_case_owner")?;

    let permitted = evaluate(&policy, &KnownFacts::new().with_present::<CaseOwner>());
    assert_eq!(permitted.effect, Effect::Permit(ReadAccess::Full));

    let denied = evaluate(&policy, &KnownFacts::new());
    assert_eq!(denied.effect, Effect::Deny);

    if let DecisiveClause::Deny { reason, unsatisfied, .. } = &denied.trace.decisive {
        assert_eq!(reason.as_ref().map(ReasonCode::as_str), Some("not_case_owner"));
        assert_eq!(unsatisfied.len(), 1);
    }

    Ok(())
}
```

The outcome type belongs to the application. Gatekeep only requires the
`Lattice` implementation so composed policies can combine outcomes.

The fact type also belongs to the application. A request handler, resolver, or
test decides whether `CaseOwner` is present. Gatekeep records that the policy
consulted `case_owner` and returns the reason code from the denied grant.

## Next Steps

Read `Lattice Outcomes` before adding roles, tiers, scopes, or redaction levels.
Then wire the same policy into an adapter:

- `Axum Authorization` for request boundaries
- `SQLx List Filtering` for list endpoints
- `Durable Audit` for stored decision records
