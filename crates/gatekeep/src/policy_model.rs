use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::{ClauseLabel, DenyShape, FactId, ObligationId, ReasonCode};

/// Outcome ordering used when policies combine permissions.
pub trait Lattice: Clone + Eq + Debug {
    /// Computes the common permission for `all` policy composition.
    #[must_use]
    fn meet(&self, other: &Self) -> Self;
    /// Computes the least upper permission for `any` policy composition.
    #[must_use]
    fn join(&self, other: &Self) -> Self;
    /// Returns the most permissive outcome.
    #[must_use]
    fn top() -> Self;
    /// Returns the least permissive outcome.
    #[must_use]
    fn bottom() -> Self;
}

impl Lattice for () {
    fn meet(&self, _other: &Self) -> Self {}
    fn join(&self, _other: &Self) -> Self {}
    fn top() -> Self {}
    fn bottom() -> Self {}
}

/// Boolean predicate over known or deferred facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Condition {
    /// Predicate that always succeeds.
    Always,
    /// Predicate that always fails.
    Never,
    /// Predicate requiring the fact to be present.
    Has(crate::FactId),
    /// Negated predicate.
    Not(Box<Self>),
    /// Conjunction of predicates.
    All(Vec<Self>),
    /// Disjunction of predicates.
    Any(Vec<Self>),
}

/// Reified authorization policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Policy<O> {
    /// Unconditional permit with an outcome.
    Permit(O),
    /// Unconditional denial.
    Deny,
    /// Constant permit that preserves decisive trace metadata.
    PermitWithTrace {
        /// Granted outcome.
        outcome: O,
        /// Obligations attached to the permit.
        obligations: Vec<ObligationId>,
        /// Facts that satisfied the original condition.
        satisfied: Vec<FactId>,
        /// Optional stable clause label.
        label: Option<ClauseLabel>,
    },
    /// Constant denial that preserves decisive trace metadata.
    DenyWithTrace {
        /// Outcome requested by the denied grant, when one exists.
        denied: Option<O>,
        /// Facts that caused the original condition to fail.
        unsatisfied: Vec<FactId>,
        /// Optional stable clause label.
        label: Option<ClauseLabel>,
        /// Optional stable reason code.
        reason: Option<ReasonCode>,
        /// Disclosure shape for presentation.
        shape: DenyShape,
    },
    /// Conditional permit with denial metadata.
    Grant {
        /// Outcome granted when the condition succeeds.
        outcome: O,
        /// Predicate that guards the grant.
        condition: Condition,
        /// Optional trace label for this clause.
        label: Option<ClauseLabel>,
        /// Shape exposed when the grant condition fails.
        deny_shape: DenyShape,
        /// Obligations attached to a successful grant.
        obligations: Vec<ObligationId>,
        /// Reason code attached to a failed grant.
        reason: Option<ReasonCode>,
    },
    /// Meet composition across child policies.
    All(Vec<Self>),
    /// Join composition across child policies.
    Any(Vec<Self>),
    /// Fallback policy used only when the primary denies.
    OrElse {
        /// Primary policy.
        primary: Box<Self>,
        /// Fallback policy.
        fallback: Box<Self>,
    },
}
