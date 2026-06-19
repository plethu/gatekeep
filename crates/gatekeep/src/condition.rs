use crate::{Condition, Fact};

/// Builds a condition that always succeeds.
#[must_use]
pub const fn always() -> Condition {
    Condition::Always
}

/// Builds a condition that always fails.
#[must_use]
pub const fn never() -> Condition {
    Condition::Never
}

/// Builds a condition requiring a typed fact.
#[must_use]
pub fn has<F: Fact>() -> Condition {
    Condition::Has(crate::FactId::from_trusted(F::ID.as_str()))
}

/// Builds a condition requiring a runtime fact identifier.
#[must_use]
pub const fn has_id(fact: crate::FactId) -> Condition {
    Condition::Has(fact)
}

/// Builds a negated condition.
#[must_use]
pub fn not(condition: Condition) -> Condition {
    Condition::Not(Box::new(condition))
}

/// Builds a conjunction. Empty input fails closed.
#[must_use]
pub fn all(conditions: impl IntoIterator<Item = Condition>) -> Condition {
    let conditions = conditions.into_iter().collect::<Vec<_>>();
    if conditions.is_empty() {
        Condition::Never
    } else {
        Condition::All(conditions)
    }
}

/// Builds a disjunction. Empty input fails closed.
#[must_use]
pub fn any(conditions: impl IntoIterator<Item = Condition>) -> Condition {
    let conditions = conditions.into_iter().collect::<Vec<_>>();
    if conditions.is_empty() {
        Condition::Never
    } else {
        Condition::Any(conditions)
    }
}
