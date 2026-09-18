# Your first gate

These examples use Gatekeep 5.
For the published 4.x API, start with [installation](installation.md).

An ownership check needs one named fact and a permit/deny policy. The check is
ordinary Rust; its stable name is what appears in a decision trace.

```rust
use gatekeep::{condition, evaluate, policy, Fact, KnownFacts, StaticFactId};

struct Owner;
impl Fact for Owner {
    const ID: StaticFactId = StaticFactId::new("record.owner");
}

let may_read = policy::grant_clause((), condition::has::<Owner>()).into_policy();

let actor_id = "alex";
let owner_id = "alex";
let facts = KnownFacts::new().with_bool::<Owner>(actor_id == owner_id);
let decision = evaluate(&may_read, &facts);
assert!(decision.is_permit());
assert_eq!(facts.observed::<Owner>(), Some(true));
```

`()` is the outcome for an ordinary gate. You can add
[disclosure tiers](concepts/lattice-outcomes.md) when the application needs them.
A false observation is recorded explicitly. The pure evaluator still treats an
omitted fact as absent; the checked authorizer rejects omissions instead.

`evaluate` is a pure function. It does not authenticate anyone, read a database,
or persist its trace. Use it in policy tests and capability previews. A preview
is not authorization for a later operation.

For a request boundary, prepare the policy once and use `Authorizer::authorize`
or Axum's `Gatekeeper::authorize_prepared`. Those paths validate the context,
resolve every required check, check freshness, and await the configured audit
sink. A source failure remains an error, including under negated conditions.

Continue with [resource policies](guides/resource-policies.md),
[required audit and retries](guides/checked-authorization.md), or the
[runnable record service](guides/record-service.md). The advanced paths are
[SQL list filtering](guides/sqlx-list-filtering.md) and
[relation lifecycle](relation-lifecycle-contract.md).
