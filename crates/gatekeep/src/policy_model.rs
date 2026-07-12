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

/// Residual policy produced by partial evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResidualPolicy<O> {
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
    /// Meet composition across child residual policies.
    All(Vec<Self>),
    /// Join composition across child residual policies.
    Any(Vec<Self>),
    /// Fallback residual used only when the primary denies.
    OrElse {
        /// Primary residual.
        primary: Box<Self>,
        /// Fallback residual.
        fallback: Box<Self>,
    },
}

/// Fold node exposed by [`ResidualPolicy::try_fold`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResidualPolicyNode<'a, O, T> {
    /// Unconditional permit with an outcome.
    Permit(&'a O),
    /// Unconditional denial.
    Deny,
    /// Constant permit that preserves decisive trace metadata.
    PermitWithTrace {
        /// Granted outcome.
        outcome: &'a O,
        /// Obligations attached to the permit.
        obligations: &'a [ObligationId],
        /// Facts that satisfied the original condition.
        satisfied: &'a [FactId],
        /// Optional stable clause label.
        label: Option<&'a ClauseLabel>,
    },
    /// Constant denial that preserves decisive trace metadata.
    DenyWithTrace {
        /// Outcome requested by the denied grant, when one exists.
        denied: Option<&'a O>,
        /// Facts that caused the original condition to fail.
        unsatisfied: &'a [FactId],
        /// Optional stable clause label.
        label: Option<&'a ClauseLabel>,
        /// Optional stable reason code.
        reason: Option<&'a ReasonCode>,
        /// Disclosure shape for presentation.
        shape: DenyShape,
    },
    /// Conditional permit with denial metadata.
    Grant {
        /// Outcome granted when the condition succeeds.
        outcome: &'a O,
        /// Predicate that guards the grant.
        condition: &'a Condition,
        /// Optional trace label for this clause.
        label: Option<&'a ClauseLabel>,
        /// Shape exposed when the grant condition fails.
        deny_shape: DenyShape,
        /// Obligations attached to a successful grant.
        obligations: &'a [ObligationId],
        /// Reason code attached to a failed grant.
        reason: Option<&'a ReasonCode>,
    },
    /// Meet composition with already-folded child outputs.
    All {
        /// Source child policies.
        policies: &'a [ResidualPolicy<O>],
        /// Folded child outputs in source order.
        arms: Vec<T>,
    },
    /// Join composition with already-folded child outputs.
    Any {
        /// Source child policies.
        policies: &'a [ResidualPolicy<O>],
        /// Folded child outputs in source order.
        arms: Vec<T>,
    },
    /// Fallback composition with already-folded child outputs.
    OrElse {
        /// Source primary residual.
        primary_policy: &'a ResidualPolicy<O>,
        /// Source fallback residual.
        fallback_policy: &'a ResidualPolicy<O>,
        /// Folded primary output.
        primary: T,
        /// Folded fallback output, unless a pruned fold skipped it.
        fallback: Option<T>,
    },
}

/// Child branch considered by [`ResidualPolicy::try_fold_pruned`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidualPolicyBranch<'a, O> {
    /// `OrElse` fallback branch.
    OrElseFallback {
        /// Primary residual for the `OrElse`.
        primary: &'a ResidualPolicy<O>,
        /// Fallback residual for the `OrElse`.
        fallback: &'a ResidualPolicy<O>,
    },
}

impl<O> ResidualPolicy<O> {
    /// Returns true for unconditional permit nodes.
    #[must_use]
    pub const fn is_permit_constant(&self) -> bool {
        matches!(self, Self::Permit(_) | Self::PermitWithTrace { .. })
    }

    /// Returns true for unconditional denial nodes.
    #[must_use]
    pub const fn is_deny_constant(&self) -> bool {
        matches!(self, Self::Deny | Self::DenyWithTrace { .. })
    }

    /// Returns true for unconditional permit or denial nodes.
    #[must_use]
    pub const fn is_constant(&self) -> bool {
        self.is_permit_constant() || self.is_deny_constant()
    }

    /// Returns true when any possible permit carries an obligation.
    #[must_use]
    pub fn carries_obligation(&self) -> bool {
        self.fold(&mut |node| match node {
            ResidualPolicyNode::PermitWithTrace { obligations, .. }
            | ResidualPolicyNode::Grant { obligations, .. } => !obligations.is_empty(),
            ResidualPolicyNode::Permit(_)
            | ResidualPolicyNode::Deny
            | ResidualPolicyNode::DenyWithTrace { .. } => false,
            ResidualPolicyNode::All { arms, .. } | ResidualPolicyNode::Any { arms, .. } => {
                arms.into_iter().any(std::convert::identity)
            }
            ResidualPolicyNode::OrElse {
                primary, fallback, ..
            } => primary || fallback.unwrap_or(false),
        })
    }

    /// Folds a residual policy bottom-up.
    #[must_use]
    pub fn fold<T>(&self, visitor: &mut impl FnMut(ResidualPolicyNode<'_, O, T>) -> T) -> T {
        match self {
            Self::Permit(outcome) => visitor(ResidualPolicyNode::Permit(outcome)),
            Self::Deny => visitor(ResidualPolicyNode::Deny),
            Self::PermitWithTrace {
                outcome,
                obligations,
                satisfied,
                label,
            } => visitor(ResidualPolicyNode::PermitWithTrace {
                outcome,
                obligations,
                satisfied,
                label: label.as_ref(),
            }),
            Self::DenyWithTrace {
                denied,
                unsatisfied,
                label,
                reason,
                shape,
            } => visitor(ResidualPolicyNode::DenyWithTrace {
                denied: denied.as_ref(),
                unsatisfied,
                label: label.as_ref(),
                reason: reason.as_ref(),
                shape: *shape,
            }),
            Self::Grant {
                outcome,
                condition,
                label,
                deny_shape,
                obligations,
                reason,
            } => visitor(ResidualPolicyNode::Grant {
                outcome,
                condition,
                label: label.as_ref(),
                deny_shape: *deny_shape,
                obligations,
                reason: reason.as_ref(),
            }),
            Self::All(policies) => {
                let arms = policies.iter().map(|policy| policy.fold(visitor)).collect();
                visitor(ResidualPolicyNode::All { policies, arms })
            }
            Self::Any(policies) => {
                let arms = policies.iter().map(|policy| policy.fold(visitor)).collect();
                visitor(ResidualPolicyNode::Any { policies, arms })
            }
            Self::OrElse { primary, fallback } => {
                let primary_output = primary.fold(visitor);
                let fallback_output = fallback.fold(visitor);
                visitor(ResidualPolicyNode::OrElse {
                    primary_policy: primary,
                    fallback_policy: fallback,
                    primary: primary_output,
                    fallback: Some(fallback_output),
                })
            }
        }
    }

    /// Fallibly folds a residual policy bottom-up.
    ///
    /// # Errors
    ///
    /// Returns the first error produced by `visitor`.
    pub fn try_fold<T, E>(
        &self,
        visitor: &mut impl FnMut(ResidualPolicyNode<'_, O, T>) -> Result<T, E>,
    ) -> Result<T, E> {
        match self {
            Self::Permit(outcome) => visitor(ResidualPolicyNode::Permit(outcome)),
            Self::Deny => visitor(ResidualPolicyNode::Deny),
            Self::PermitWithTrace {
                outcome,
                obligations,
                satisfied,
                label,
            } => visitor(ResidualPolicyNode::PermitWithTrace {
                outcome,
                obligations,
                satisfied,
                label: label.as_ref(),
            }),
            Self::DenyWithTrace {
                denied,
                unsatisfied,
                label,
                reason,
                shape,
            } => visitor(ResidualPolicyNode::DenyWithTrace {
                denied: denied.as_ref(),
                unsatisfied,
                label: label.as_ref(),
                reason: reason.as_ref(),
                shape: *shape,
            }),
            Self::Grant {
                outcome,
                condition,
                label,
                deny_shape,
                obligations,
                reason,
            } => visitor(ResidualPolicyNode::Grant {
                outcome,
                condition,
                label: label.as_ref(),
                deny_shape: *deny_shape,
                obligations,
                reason: reason.as_ref(),
            }),
            Self::All(policies) => {
                let arms = policies
                    .iter()
                    .map(|policy| policy.try_fold(visitor))
                    .collect::<Result<Vec<_>, _>>()?;
                visitor(ResidualPolicyNode::All { policies, arms })
            }
            Self::Any(policies) => {
                let arms = policies
                    .iter()
                    .map(|policy| policy.try_fold(visitor))
                    .collect::<Result<Vec<_>, _>>()?;
                visitor(ResidualPolicyNode::Any { policies, arms })
            }
            Self::OrElse { primary, fallback } => {
                let primary_output = primary.try_fold(visitor)?;
                let fallback_output = fallback.try_fold(visitor)?;
                visitor(ResidualPolicyNode::OrElse {
                    primary_policy: primary,
                    fallback_policy: fallback,
                    primary: primary_output,
                    fallback: Some(fallback_output),
                })
            }
        }
    }

    /// Fallibly folds a residual policy bottom-up, allowing selected branches to
    /// be skipped before they are visited.
    ///
    /// # Errors
    ///
    /// Returns the first error produced by `visitor`.
    pub fn try_fold_pruned<T, E>(
        &self,
        should_descend: &mut impl FnMut(&ResidualPolicyBranch<'_, O>) -> bool,
        visitor: &mut impl FnMut(ResidualPolicyNode<'_, O, T>) -> Result<T, E>,
    ) -> Result<T, E> {
        match self {
            Self::Permit(outcome) => visitor(ResidualPolicyNode::Permit(outcome)),
            Self::Deny => visitor(ResidualPolicyNode::Deny),
            Self::PermitWithTrace {
                outcome,
                obligations,
                satisfied,
                label,
            } => visitor(ResidualPolicyNode::PermitWithTrace {
                outcome,
                obligations,
                satisfied,
                label: label.as_ref(),
            }),
            Self::DenyWithTrace {
                denied,
                unsatisfied,
                label,
                reason,
                shape,
            } => visitor(ResidualPolicyNode::DenyWithTrace {
                denied: denied.as_ref(),
                unsatisfied,
                label: label.as_ref(),
                reason: reason.as_ref(),
                shape: *shape,
            }),
            Self::Grant {
                outcome,
                condition,
                label,
                deny_shape,
                obligations,
                reason,
            } => visitor(ResidualPolicyNode::Grant {
                outcome,
                condition,
                label: label.as_ref(),
                deny_shape: *deny_shape,
                obligations,
                reason: reason.as_ref(),
            }),
            Self::All(policies) => {
                let arms = policies
                    .iter()
                    .map(|policy| policy.try_fold_pruned(should_descend, visitor))
                    .collect::<Result<Vec<_>, _>>()?;
                visitor(ResidualPolicyNode::All { policies, arms })
            }
            Self::Any(policies) => {
                let arms = policies
                    .iter()
                    .map(|policy| policy.try_fold_pruned(should_descend, visitor))
                    .collect::<Result<Vec<_>, _>>()?;
                visitor(ResidualPolicyNode::Any { policies, arms })
            }
            Self::OrElse { primary, fallback } => {
                let primary_output = primary.try_fold_pruned(should_descend, visitor)?;
                let fallback_branch = ResidualPolicyBranch::OrElseFallback { primary, fallback };
                let fallback_output = if should_descend(&fallback_branch) {
                    Some(fallback.try_fold_pruned(should_descend, visitor)?)
                } else {
                    None
                };
                visitor(ResidualPolicyNode::OrElse {
                    primary_policy: primary,
                    fallback_policy: fallback,
                    primary: primary_output,
                    fallback: fallback_output,
                })
            }
        }
    }
}
