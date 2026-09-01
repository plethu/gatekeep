# Reason Catalogs

Gatekeep policies carry stable reason codes. Presentation layers turn those
codes into user-facing messages.

## Reason Codes

Reason codes should be stable, searchable, and product-neutral:

```rust
# use gatekeep::{condition, policy, Fact, GatekeepResult, Lattice, StaticFactId};
# #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
# enum ReadAccess { Redacted, Full }
# impl Lattice for ReadAccess {
#     fn meet(&self, other: &Self) -> Self { (*self).min(*other) }
#     fn join(&self, other: &Self) -> Self { (*self).max(*other) }
#     fn top() -> Self { Self::Full }
#     fn bottom() -> Self { Self::Redacted }
# }
# struct CaseOwner;
# impl Fact for CaseOwner { const ID: StaticFactId = StaticFactId::new("case_owner"); }
# fn main() -> GatekeepResult<()> {
let policy = policy::grant(ReadAccess::Full, condition::has::<CaseOwner>())
    .try_reason("not_case_owner")?;
# Ok(())
# }
```

Use one code for one denial meaning. Put variable data in reason parameters,
not in the code string.

## Fluent

`gatekeep-fluent` implements `ReasonCatalog` with Fluent message bundles. That
lets services keep policy decisions stable while changing wording by locale.

Audit records should store the code and parameters. Render human text at the UI,
API, or support-tool boundary.

## Disclosure Shape

`DenyShape::Forbidden` means the service may disclose that the protected object
exists. `DenyShape::Hidden` supports "act as missing" responses for sensitive
resources.

Choose the shape in policy code so audit, HTTP responses, and localized messages
agree.
