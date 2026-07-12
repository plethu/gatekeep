use std::collections::BTreeSet;

use serde::Serialize;

use crate::{
    ClauseLabel, Condition, Decision, DecisionTrace, DecisiveClause, DenyShape, Effect, FactId,
    KnownFacts, Lattice, ObligationId, Policy, PolicyHash, Presence, ReasonCode, ResidualPolicy,
};

#[must_use]
/// Evaluates a policy against known facts.
pub fn evaluate<O: Lattice>(policy: &Policy<O>, facts: &KnownFacts) -> Decision<O> {
    let mut consulted = Consulted::default();
    let result = eval_policy(policy, facts, &mut consulted);
    Decision {
        effect: result.effect,
        obligations: result.obligations,
        trace: DecisionTrace {
            consulted: consulted.into_vec(),
            decisive: result.decisive,
        },
    }
}

#[must_use]
/// Evaluates a residual policy against known facts.
pub fn evaluate_residual<O: Lattice>(
    policy: &ResidualPolicy<O>,
    facts: &KnownFacts,
) -> Decision<O> {
    let mut consulted = Consulted::default();
    let result = eval_residual_policy(policy, facts, &mut consulted);
    Decision {
        effect: result.effect,
        obligations: result.obligations,
        trace: DecisionTrace {
            consulted: consulted.into_vec(),
            decisive: result.decisive,
        },
    }
}

#[must_use]
/// Returns every fact that may be consulted by a policy.
pub fn required_facts<O>(policy: &Policy<O>) -> BTreeSet<FactId> {
    let mut facts = BTreeSet::new();
    collect_policy_facts(policy, &mut facts);
    facts
}

#[must_use]
/// Returns every fact that may be consulted by a residual policy.
pub fn required_residual_facts<O>(policy: &ResidualPolicy<O>) -> BTreeSet<FactId> {
    let mut facts = BTreeSet::new();
    collect_residual_policy_facts(policy, &mut facts);
    facts
}

impl<O: Serialize> Policy<O> {
    /// Computes a stable hash of the serialized policy value.
    ///
    /// # Errors
    ///
    /// Returns a [`postcard::Error`] when the policy cannot be serialized.
    pub fn hash(&self) -> Result<PolicyHash, postcard::Error> {
        let bytes = postcard::to_allocvec(self)?;
        Ok(PolicyHash::from_trusted(
            blake3::hash(&bytes).to_hex().to_string(),
        ))
    }
}

#[derive(Default)]
struct Consulted(Vec<(FactId, Presence)>);

impl Consulted {
    fn record(&mut self, fact: &FactId, presence: Presence) {
        if !self.0.iter().any(|(existing, _presence)| existing == fact) {
            self.0.push((fact.clone(), presence));
        }
    }

    fn into_vec(self) -> Vec<(FactId, Presence)> {
        self.0
    }
}

#[derive(Clone)]
struct EvalResult<O> {
    effect: Effect<O>,
    obligations: Vec<ObligationId>,
    decisive: DecisiveClause<O>,
}

#[derive(Clone)]
struct ConditionEval {
    satisfied: bool,
    decisive_facts: Vec<FactId>,
}

fn eval_policy<O: Lattice>(
    policy: &Policy<O>,
    facts: &KnownFacts,
    consulted: &mut Consulted,
) -> EvalResult<O> {
    match policy {
        Policy::Permit(outcome) => EvalResult {
            effect: Effect::Permit(outcome.clone()),
            obligations: Vec::new(),
            decisive: DecisiveClause::Permit {
                granted: outcome.clone(),
                satisfied: Vec::new(),
                label: None,
            },
        },
        Policy::Deny => generic_deny(),
        Policy::Grant {
            outcome,
            condition,
            label,
            deny_shape,
            obligations,
            reason,
        } => eval_grant(
            &GrantRef {
                outcome,
                condition,
                label,
                deny_shape: *deny_shape,
                obligations,
                reason,
            },
            facts,
            consulted,
        ),
        Policy::All(policies) => eval_all_by(policies, facts, consulted, eval_policy::<O>),
        Policy::Any(policies) => eval_any_by(policies, facts, consulted, eval_policy::<O>),
        Policy::OrElse { primary, fallback } => {
            let primary = eval_policy(primary, facts, consulted);
            if matches!(primary.effect, Effect::Permit(_)) {
                primary
            } else {
                eval_policy(fallback, facts, consulted)
            }
        }
    }
}

fn eval_residual_policy<O: Lattice>(
    policy: &ResidualPolicy<O>,
    facts: &KnownFacts,
    consulted: &mut Consulted,
) -> EvalResult<O> {
    match policy {
        ResidualPolicy::Permit(outcome) => EvalResult {
            effect: Effect::Permit(outcome.clone()),
            obligations: Vec::new(),
            decisive: DecisiveClause::Permit {
                granted: outcome.clone(),
                satisfied: Vec::new(),
                label: None,
            },
        },
        ResidualPolicy::Deny => generic_deny(),
        ResidualPolicy::PermitWithTrace {
            outcome,
            obligations,
            satisfied,
            label,
        } => EvalResult {
            effect: Effect::Permit(outcome.clone()),
            obligations: obligations.clone(),
            decisive: DecisiveClause::Permit {
                granted: outcome.clone(),
                satisfied: satisfied.clone(),
                label: label.clone(),
            },
        },
        ResidualPolicy::DenyWithTrace {
            denied,
            unsatisfied,
            label,
            reason,
            shape,
        } => EvalResult {
            effect: Effect::Deny,
            obligations: Vec::new(),
            decisive: DecisiveClause::Deny {
                denied: denied.clone(),
                unsatisfied: unsatisfied.clone(),
                label: label.clone(),
                reason: reason.clone(),
                shape: *shape,
            },
        },
        ResidualPolicy::Grant {
            outcome,
            condition,
            label,
            deny_shape,
            obligations,
            reason,
        } => eval_grant(
            &GrantRef {
                outcome,
                condition,
                label,
                deny_shape: *deny_shape,
                obligations,
                reason,
            },
            facts,
            consulted,
        ),
        ResidualPolicy::All(policies) => {
            eval_all_by(policies, facts, consulted, eval_residual_policy::<O>)
        }
        ResidualPolicy::Any(policies) => {
            eval_any_by(policies, facts, consulted, eval_residual_policy::<O>)
        }
        ResidualPolicy::OrElse { primary, fallback } => {
            let primary = eval_residual_policy(primary, facts, consulted);
            if matches!(primary.effect, Effect::Permit(_)) {
                primary
            } else {
                eval_residual_policy(fallback, facts, consulted)
            }
        }
    }
}

fn eval_grant<O: Lattice>(
    grant: &GrantRef<'_, O>,
    facts: &KnownFacts,
    consulted: &mut Consulted,
) -> EvalResult<O> {
    let condition = eval_condition(grant.condition, facts, consulted);
    if condition.satisfied {
        EvalResult {
            effect: Effect::Permit(grant.outcome.clone()),
            obligations: grant.obligations.to_vec(),
            decisive: DecisiveClause::Permit {
                granted: grant.outcome.clone(),
                satisfied: condition.decisive_facts,
                label: grant.label.clone(),
            },
        }
    } else {
        EvalResult {
            effect: Effect::Deny,
            obligations: Vec::new(),
            decisive: DecisiveClause::Deny {
                denied: Some(grant.outcome.clone()),
                unsatisfied: condition.decisive_facts,
                label: grant.label.clone(),
                reason: grant.reason.clone(),
                shape: grant.deny_shape,
            },
        }
    }
}

struct GrantRef<'a, O> {
    outcome: &'a O,
    condition: &'a Condition,
    label: &'a Option<ClauseLabel>,
    deny_shape: DenyShape,
    obligations: &'a [ObligationId],
    reason: &'a Option<ReasonCode>,
}

fn eval_all_by<O: Lattice, P>(
    policies: &[P],
    facts: &KnownFacts,
    consulted: &mut Consulted,
    mut eval_arm: impl FnMut(&P, &KnownFacts, &mut Consulted) -> EvalResult<O>,
) -> EvalResult<O> {
    if policies.is_empty() {
        return generic_deny();
    }

    let mut permit: Option<(O, Vec<ObligationId>, DecisiveClause<O>)> = None;
    for policy in policies {
        let arm = eval_arm(policy, facts, consulted);
        match arm.effect {
            Effect::Deny => return arm,
            Effect::Permit(outcome) => {
                permit = Some(match permit {
                    None => (outcome, arm.obligations, arm.decisive),
                    Some((current, current_obligations, decisive)) => {
                        let met = current.meet(&outcome);
                        if met == outcome && met != current {
                            (met, arm.obligations, arm.decisive)
                        } else if met != current {
                            (
                                met.clone(),
                                Vec::new(),
                                DecisiveClause::Permit {
                                    granted: met,
                                    satisfied: Vec::new(),
                                    label: None,
                                },
                            )
                        } else {
                            (met, current_obligations, decisive)
                        }
                    }
                });
            }
        }
    }

    let Some((outcome, obligations, decisive)) = permit else {
        return generic_deny();
    };
    EvalResult {
        effect: Effect::Permit(outcome),
        obligations,
        decisive,
    }
}

fn eval_any_by<O: Lattice, P>(
    policies: &[P],
    facts: &KnownFacts,
    consulted: &mut Consulted,
    mut eval_arm: impl FnMut(&P, &KnownFacts, &mut Consulted) -> EvalResult<O>,
) -> EvalResult<O> {
    if policies.is_empty() {
        return generic_deny();
    }

    let mut winning: Option<(O, DecisiveClause<O>)> = None;
    let mut winning_obligations = Vec::<ObligationId>::new();
    let mut first_deny = None;

    for policy in policies {
        let arm = eval_arm(policy, facts, consulted);
        match arm.effect {
            Effect::Deny => {
                if first_deny.is_none() {
                    first_deny = Some(arm.decisive);
                }
            }
            Effect::Permit(outcome) => match &mut winning {
                None => {
                    winning = Some((outcome, arm.decisive));
                    winning_obligations = arm.obligations;
                }
                Some((current, _decisive)) => {
                    let joined = current.join(&outcome);
                    if joined == *current && joined == outcome {
                        union_obligations(&mut winning_obligations, arm.obligations);
                    } else if joined == outcome {
                        *current = joined;
                        winning_obligations = arm.obligations;
                        if let Some((_, decisive)) = &mut winning {
                            *decisive = arm.decisive;
                        }
                    } else if joined != *current {
                        *current = joined.clone();
                        union_obligations(&mut winning_obligations, arm.obligations);
                        if let Some((_, decisive)) = &mut winning {
                            *decisive = DecisiveClause::Permit {
                                granted: joined,
                                satisfied: Vec::new(),
                                label: None,
                            };
                        }
                    }
                }
            },
        }
    }

    if let Some((outcome, decisive)) = winning {
        EvalResult {
            effect: Effect::Permit(outcome),
            obligations: winning_obligations,
            decisive,
        }
    } else {
        EvalResult {
            effect: Effect::Deny,
            obligations: Vec::new(),
            decisive: first_deny.unwrap_or_else(|| generic_deny::<O>().decisive),
        }
    }
}

fn eval_condition(
    condition: &Condition,
    facts: &KnownFacts,
    consulted: &mut Consulted,
) -> ConditionEval {
    match condition {
        Condition::Always => ConditionEval {
            satisfied: true,
            decisive_facts: Vec::new(),
        },
        Condition::Never => ConditionEval {
            satisfied: false,
            decisive_facts: Vec::new(),
        },
        Condition::Has(fact) => {
            let presence = facts.presence(fact);
            consulted.record(fact, presence);
            ConditionEval {
                satisfied: presence == Presence::Present,
                decisive_facts: vec![fact.clone()],
            }
        }
        Condition::Not(inner) => {
            let inner = eval_condition(inner, facts, consulted);
            ConditionEval {
                satisfied: !inner.satisfied,
                decisive_facts: inner.decisive_facts,
            }
        }
        Condition::All(conditions) => eval_condition_all(conditions, facts, consulted),
        Condition::Any(conditions) => eval_condition_any(conditions, facts, consulted),
    }
}

fn eval_condition_all(
    conditions: &[Condition],
    facts: &KnownFacts,
    consulted: &mut Consulted,
) -> ConditionEval {
    if conditions.is_empty() {
        return ConditionEval {
            satisfied: false,
            decisive_facts: Vec::new(),
        };
    }

    let mut satisfied_facts = Vec::new();
    for condition in conditions {
        let arm = eval_condition(condition, facts, consulted);
        if !arm.satisfied {
            return ConditionEval {
                satisfied: false,
                decisive_facts: arm.decisive_facts,
            };
        }
        satisfied_facts.extend(arm.decisive_facts);
    }
    ConditionEval {
        satisfied: true,
        decisive_facts: satisfied_facts,
    }
}

fn eval_condition_any(
    conditions: &[Condition],
    facts: &KnownFacts,
    consulted: &mut Consulted,
) -> ConditionEval {
    if conditions.is_empty() {
        return ConditionEval {
            satisfied: false,
            decisive_facts: Vec::new(),
        };
    }

    let mut missing = Vec::new();
    for condition in conditions {
        let arm = eval_condition(condition, facts, consulted);
        if arm.satisfied {
            return ConditionEval {
                satisfied: true,
                decisive_facts: arm.decisive_facts,
            };
        }
        missing.extend(arm.decisive_facts);
    }
    ConditionEval {
        satisfied: false,
        decisive_facts: missing,
    }
}

const fn generic_deny<O>() -> EvalResult<O> {
    EvalResult {
        effect: Effect::Deny,
        obligations: Vec::new(),
        decisive: DecisiveClause::Deny {
            denied: None,
            unsatisfied: Vec::new(),
            label: None,
            reason: None,
            shape: DenyShape::Forbidden,
        },
    }
}

fn union_obligations(target: &mut Vec<ObligationId>, source: Vec<ObligationId>) {
    for obligation in source {
        if !target.contains(&obligation) {
            target.push(obligation);
        }
    }
}

fn collect_policy_facts<O>(policy: &Policy<O>, facts: &mut BTreeSet<FactId>) {
    match policy {
        Policy::Permit(_) | Policy::Deny => {}
        Policy::Grant { condition, .. } => collect_condition_facts(condition, facts),
        Policy::All(policies) | Policy::Any(policies) => {
            for policy in policies {
                collect_policy_facts(policy, facts);
            }
        }
        Policy::OrElse { primary, fallback } => {
            collect_policy_facts(primary, facts);
            collect_policy_facts(fallback, facts);
        }
    }
}

fn collect_residual_policy_facts<O>(policy: &ResidualPolicy<O>, facts: &mut BTreeSet<FactId>) {
    match policy {
        ResidualPolicy::Permit(_)
        | ResidualPolicy::Deny
        | ResidualPolicy::PermitWithTrace { .. }
        | ResidualPolicy::DenyWithTrace { .. } => {}
        ResidualPolicy::Grant { condition, .. } => collect_condition_facts(condition, facts),
        ResidualPolicy::All(policies) | ResidualPolicy::Any(policies) => {
            for policy in policies {
                collect_residual_policy_facts(policy, facts);
            }
        }
        ResidualPolicy::OrElse { primary, fallback } => {
            collect_residual_policy_facts(primary, facts);
            collect_residual_policy_facts(fallback, facts);
        }
    }
}

fn collect_condition_facts(condition: &Condition, facts: &mut BTreeSet<FactId>) {
    match condition {
        Condition::Always | Condition::Never => {}
        Condition::Has(fact) => {
            facts.insert(fact.clone());
        }
        Condition::Not(condition) => collect_condition_facts(condition, facts),
        Condition::All(conditions) | Condition::Any(conditions) => {
            for condition in conditions {
                collect_condition_facts(condition, facts);
            }
        }
    }
}
