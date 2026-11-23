# Layered precedence

Applications often describe access as layers: a developer override, then a
feature flag, then roles, restrictions and a subscription tier. Gatekeep has no
separate layer or priority setting. The shape of the policy tree is the
precedence, built from three combinators with fixed meanings:

| Layer behavior | Combinator | Result |
| --- | --- | --- |
| Overrides everything below | `or_else(override, rest)` | If `override` permits, `rest` is not evaluated. Otherwise `rest` decides. |
| Gate or veto | `all([deny_when(..), ..])` | Any denial wins. Permits narrow with `meet`. |
| Alternative paths | `any([..])` | Any permit wins. Permits broaden with `join`. |

A tier is a ceiling inside `all`: its permitted outcome meets the role's, so the
narrower value wins.

## A layered policy

```rust
use gatekeep::{condition, policy, Fact, GatekeepResult, Policy, ReasonCode, StaticFactId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    None,
    Read,
    Edit,
    Full,
}

gatekeep::ordered_lattice!(Access: None < Read < Edit < Full);

# macro_rules! facts {
#     ($($name:ident = $id:literal),* $(,)?) => {
#         $(struct $name;
#         impl Fact for $name { const ID: StaticFactId = StaticFactId::new($id); })*
#     };
# }
# facts!(
#     DevTools = "dev_tools_session", FeatureOn = "feature.reports",
#     Suspended = "account.suspended", Admin = "role.admin",
#     Editor = "role.editor", Member = "role.member", ProPlan = "plan.pro",
# );
fn reports_policy() -> GatekeepResult<Policy<Access>> {
    Ok(policy::or_else(
        // 1. A developer override bypasses every layer below.
        policy::grant_clause(Access::Full, condition::has::<DevTools>())
            .try_labeled("dev_tools")?
            .into_policy(),
        policy::all([
            // 2. The feature flag gates everyone else.
            policy::deny_when(
                condition::not(condition::has::<FeatureOn>()),
                ReasonCode::new("feature_disabled")?,
            ),
            // 3. Restrictions veto roles, except where a role is exempt.
            policy::deny_when(
                condition::all([
                    condition::has::<Suspended>(),
                    condition::not(condition::has::<Admin>()),
                ]),
                ReasonCode::new("account_restricted")?,
            ),
            // 4. Roles are alternative paths to a grade.
            policy::any([
                policy::grant_clause(Access::Full, condition::has::<Admin>())
                    .try_labeled("role.admin")?
                    .try_reason("no_role")?
                    .into_policy(),
                policy::grant_clause(Access::Edit, condition::has::<Editor>())
                    .try_labeled("role.editor")?
                    .into_policy(),
                policy::grant_clause(Access::Read, condition::has::<Member>())
                    .try_labeled("role.member")?
                    .into_policy(),
            ]),
            // 5. The subscription tier caps the role's grade.
            policy::any([
                policy::grant_clause(Access::Edit, condition::has::<ProPlan>())
                    .try_labeled("tier.pro")?
                    .into_policy(),
                policy::grant_clause(Access::Read, condition::always())
                    .try_labeled("tier.free")?
                    .into_policy(),
            ]),
        ]),
    ))
}
# fn main() -> GatekeepResult<()> { reports_policy().map(drop) }
```

`ordered_lattice!` implements `Lattice` from the listed order, narrowest first.
A missing variant is a compile error. Use a hand-written `Lattice` for sets and
other outcomes that are not a single chain; see
[combining outcomes](../concepts/lattice-outcomes.md).

## What decides, and what it reports

- **Order inside `all` changes the reported denial, not the result.** The first
  denying child stops evaluation and becomes the decision's reason. A
  restriction vetoes a role wherever it is listed. To let a role override a
  restriction, write the exemption into the guard's condition as above, or wrap
  that part in its own `or_else`.
- **A denied `any` reports its first child.** When no role permits, the decision
  carries the first role clause's label and reason, not the last. Put the
  reason you want users to see on the first branch.
- **A permit reports the clause that bound the grade.** Within `all`, the
  narrowest permit decides: the tier clause when it caps the role, the role
  clause when the role is already at or below the tier. A grade produced by
  combining several clauses, rather than taken from one, has no label.
- **`or_else` hides the override's denial.** When the override does not apply,
  the decision comes entirely from the fallback.

Flags and developer overrides are ordinary facts your application supplies.
Resolve an override from an authoritative source, never a request header, and
treat it like [emergency access](recipes.md): label it, expire it and audit it.

## Pin precedence in tests

Precedence lives in the tree, so a refactor can reorder or flatten layers
without changing any single clause. With the core `test` feature,
`testing::check_deciders` evaluates named scenarios and checks the effect,
outcome, deciding label and reason code of each:

```rust
# use gatekeep::{condition, policy, Fact, GatekeepResult, KnownFacts, Policy, ReasonCode, StaticFactId};
use gatekeep::testing::{check_deciders, Decider};
# #[derive(Clone, Copy, Debug, PartialEq, Eq)]
# enum Access { None, Read, Edit, Full }
# gatekeep::ordered_lattice!(Access: None < Read < Edit < Full);
# struct DevTools;
# impl Fact for DevTools { const ID: StaticFactId = StaticFactId::new("dev_tools_session"); }
# struct FeatureOn;
# impl Fact for FeatureOn { const ID: StaticFactId = StaticFactId::new("feature.reports"); }
# struct Admin;
# impl Fact for Admin { const ID: StaticFactId = StaticFactId::new("role.admin"); }
# struct ProPlan;
# impl Fact for ProPlan { const ID: StaticFactId = StaticFactId::new("plan.pro"); }
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let policy = policy::or_else(
#     policy::grant_clause(Access::Full, condition::has::<DevTools>()).try_labeled("dev_tools")?.into_policy(),
#     policy::all([
#         policy::deny_when(condition::not(condition::has::<FeatureOn>()), ReasonCode::new("feature_disabled")?),
#         policy::grant_clause(Access::Full, condition::has::<Admin>()).try_labeled("role.admin")?.into_policy(),
#         policy::any([
#             policy::grant_clause(Access::Edit, condition::has::<ProPlan>()).try_labeled("tier.pro")?.into_policy(),
#             policy::grant_clause(Access::Read, condition::always()).try_labeled("tier.free")?.into_policy(),
#         ]),
#     ]),
# );
let admin = || {
    KnownFacts::new()
        .with_bool::<DevTools>(false)
        .with_bool::<FeatureOn>(true)
        .with_bool::<Admin>(true)
        .with_bool::<ProPlan>(true)
};

check_deciders(&policy, [
    ("dev tools bypass the flag",
     admin().with_bool::<DevTools>(true).with_bool::<FeatureOn>(false),
     Decider::permit(Access::Full).try_labeled("dev_tools")?),
    ("flag gates admins",
     admin().with_bool::<FeatureOn>(false),
     Decider::deny().try_reason("feature_disabled")?),
    ("pro tier caps admins",
     admin(),
     Decider::permit(Access::Edit).try_labeled("tier.pro")?),
])?;
# Ok(())
# }
```

All scenarios are evaluated and every mismatch is reported together, naming
the scenario and the expected and actual labels and reason codes. Outcomes are
not copied into the failure. Like `compare_scenario`, the check covers only the
scenarios you supply; write one per layer boundary you care about.
