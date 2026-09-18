use crate::{Emergency, Enabled, Owner, Released, Shared};
use gatekeep::{Fact, GatekeepError, Lattice, Policy, StaticFactId, condition, policy};
use serde::Serialize;

impl Fact for Owner {
    const ID: StaticFactId = StaticFactId::new("record.owner");
}
impl Fact for Shared {
    const ID: StaticFactId = StaticFactId::new("record.shared");
}
impl Fact for Released {
    const ID: StaticFactId = StaticFactId::new("record.released");
}
impl Fact for Emergency {
    const ID: StaticFactId = StaticFactId::new("record.emergency");
}
impl Fact for Enabled {
    const ID: StaticFactId = StaticFactId::new("person.enabled");
}

/// Fields the application may disclose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// Published summary only.
    Released,
    /// Summary and shared notes.
    Shared,
    /// Full synthetic record.
    Full,
}
impl Lattice for Access {
    fn meet(&self, other: &Self) -> Self {
        (*self).min(*other)
    }
    fn join(&self, other: &Self) -> Self {
        (*self).max(*other)
    }
    fn top() -> Self {
        Self::Full
    }
    fn bottom() -> Self {
        Self::Released
    }
}

/// Normal access takes precedence over emergency fallback, even at a lower tier.
///
/// # Errors
/// Returns invalid static policy-identity errors.
pub fn read_policy() -> Result<Policy<Access>, GatekeepError> {
    let ordinary = policy::any([
        policy::grant_clause(Access::Full, condition::has::<Owner>())
            .try_labeled("owner")?
            .hidden()
            .into_policy(),
        policy::grant_clause(Access::Shared, condition::has::<Shared>())
            .try_labeled("participant")?
            .hidden()
            .into_policy(),
        policy::grant_clause(Access::Released, condition::has::<Released>())
            .try_labeled("parent")?
            .hidden()
            .into_policy(),
    ]);
    let emergency = policy::grant_clause(Access::Full, condition::has::<Emergency>())
        .try_labeled("emergency-read")?
        .hidden()
        .into_policy();
    Ok(policy::all([
        policy::grant_clause(Access::Full, condition::has::<Enabled>())
            .hidden()
            .into_policy(),
        policy::or_else(ordinary, emergency),
    ]))
}
