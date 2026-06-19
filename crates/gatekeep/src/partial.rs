use crate::{
    Condition, Decision, Effect, FactId, KnownFacts, Lattice, PartialFacts, Policy, Presence,
    ResidualPolicy, evaluate, evaluate_residual,
};

/// Result of partial evaluation with possibly unknown facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Residual<O> {
    /// The policy was fully resolved with the supplied facts.
    Resolved(Decision<O>),
    /// Evaluation needs more facts and produced a smaller residual policy.
    Pending {
        /// Remaining policy to evaluate after unknown facts are resolved.
        residual: ResidualPolicy<O>,
        /// Facts consulted while reducing the policy.
        consulted: Vec<(FactId, Presence)>,
    },
}

#[must_use]
/// Partially evaluates a policy against present, absent, and unknown facts.
pub fn partial_evaluate<O: Lattice>(policy: &Policy<O>, facts: &PartialFacts) -> Residual<O> {
    let reduced = reduce_policy(policy, facts);
    match reduced {
        ReducedPolicy::Resolved(decision) => Residual::Resolved(decision),
        ReducedPolicy::Pending {
            residual,
            consulted,
        } => Residual::Pending {
            residual,
            consulted: consulted.into_vec(),
        },
    }
}

#[must_use]
/// Completes a partial-evaluation result against known facts.
pub fn complete_residual<O: Lattice>(residual: &Residual<O>, facts: &KnownFacts) -> Decision<O> {
    match residual {
        Residual::Resolved(decision) => decision.clone(),
        Residual::Pending {
            residual,
            consulted,
        } => {
            let decision = evaluate_residual(residual, facts);
            with_prior_consulted(decision, consulted)
        }
    }
}

#[derive(Clone)]
enum ReducedPolicy<O> {
    Resolved(Decision<O>),
    Pending {
        residual: ResidualPolicy<O>,
        consulted: ConsultedList,
    },
}

#[derive(Clone, Default)]
struct ConsultedList(Vec<(FactId, Presence)>);

impl ConsultedList {
    fn record(&mut self, fact: &FactId, presence: Presence) {
        if !self.0.iter().any(|(existing, _presence)| existing == fact) {
            self.0.push((fact.clone(), presence));
        }
    }

    fn extend(&mut self, other: Self) {
        for (fact, presence) in other.0 {
            self.record(&fact, presence);
        }
    }

    fn into_vec(self) -> Vec<(FactId, Presence)> {
        self.0
    }
}

#[derive(Clone)]
enum ReducedCondition {
    Known {
        satisfied: bool,
        consulted: ConsultedList,
    },
    Pending {
        residual: Condition,
        consulted: ConsultedList,
    },
}

fn reduce_policy<O: Lattice>(policy: &Policy<O>, facts: &PartialFacts) -> ReducedPolicy<O> {
    match policy {
        Policy::Permit(_) | Policy::Deny => {
            let known = partial_to_known(facts);
            ReducedPolicy::Resolved(evaluate(policy, &known))
        }
        Policy::Grant {
            outcome,
            condition: grant_condition,
            label,
            deny_shape,
            obligations,
            reason,
        } => match reduce_condition(grant_condition, facts) {
            ReducedCondition::Known {
                satisfied: _,
                consulted,
            } => {
                let residual = Policy::Grant {
                    outcome: outcome.clone(),
                    condition: grant_condition.clone(),
                    label: label.clone(),
                    deny_shape: *deny_shape,
                    obligations: obligations.clone(),
                    reason: reason.clone(),
                };
                let known = partial_to_known(facts);
                let decision = evaluate(&residual, &known);
                let decision = Decision {
                    trace: crate::DecisionTrace {
                        consulted: consulted.into_vec(),
                        decisive: decision.trace.decisive,
                    },
                    ..decision
                };
                ReducedPolicy::Resolved(decision)
            }
            ReducedCondition::Pending {
                residual,
                consulted,
            } => ReducedPolicy::Pending {
                residual: ResidualPolicy::Grant {
                    outcome: outcome.clone(),
                    condition: residual,
                    label: label.clone(),
                    deny_shape: *deny_shape,
                    obligations: obligations.clone(),
                    reason: reason.clone(),
                },
                consulted,
            },
        },
        Policy::All(policies) => reduce_all(policies, facts),
        Policy::Any(policies) => reduce_any(policies, facts),
        Policy::OrElse { primary, fallback } => reduce_or_else(primary, fallback, facts),
    }
}

fn reduce_all<O: Lattice>(policies: &[Policy<O>], facts: &PartialFacts) -> ReducedPolicy<O> {
    if policies.is_empty() {
        let known = partial_to_known(facts);
        return ReducedPolicy::Resolved(evaluate(&Policy::Deny, &known));
    }

    let mut consulted = ConsultedList::default();
    let mut pending = Vec::new();
    let mut resolved_permits = Vec::new();

    for policy in policies {
        match reduce_policy(policy, facts) {
            ReducedPolicy::Resolved(decision) => {
                consulted.extend(ConsultedList(decision.trace.consulted.clone()));
                match decision.effect {
                    Effect::Deny => {
                        return ReducedPolicy::Resolved(Decision {
                            trace: crate::DecisionTrace {
                                consulted: consulted.into_vec(),
                                decisive: decision.trace.decisive,
                            },
                            ..decision
                        });
                    }
                    Effect::Permit(_) => resolved_permits.push(policy_from_decision(decision)),
                }
            }
            ReducedPolicy::Pending {
                residual,
                consulted: arm_consulted,
            } => {
                consulted.extend(arm_consulted);
                pending.push(residual);
            }
        }
    }

    if pending.is_empty() {
        let known = partial_to_known(facts);
        let decision = evaluate_residual(&ResidualPolicy::All(resolved_permits), &known);
        return ReducedPolicy::Resolved(with_consulted(decision, consulted));
    }

    let mut residual = resolved_permits;
    residual.extend(pending);
    ReducedPolicy::Pending {
        residual: ResidualPolicy::All(residual),
        consulted,
    }
}

fn reduce_any<O: Lattice>(policies: &[Policy<O>], facts: &PartialFacts) -> ReducedPolicy<O> {
    if policies.is_empty() {
        let known = partial_to_known(facts);
        return ReducedPolicy::Resolved(evaluate(&Policy::Deny, &known));
    }

    let mut consulted = ConsultedList::default();
    let mut pending = Vec::new();
    let mut resolved_permits = Vec::new();
    let mut first_resolved_deny = None;

    for policy in policies {
        match reduce_policy(policy, facts) {
            ReducedPolicy::Resolved(decision) => {
                consulted.extend(ConsultedList(decision.trace.consulted.clone()));
                match decision.effect {
                    Effect::Permit(_) => resolved_permits.push(policy_from_decision(decision)),
                    Effect::Deny => {
                        if first_resolved_deny.is_none() {
                            first_resolved_deny = Some(decision);
                        }
                    }
                }
            }
            ReducedPolicy::Pending {
                residual,
                consulted: arm_consulted,
            } => {
                consulted.extend(arm_consulted);
                pending.push(residual);
            }
        }
    }

    if pending.is_empty() {
        if resolved_permits.is_empty()
            && let Some(decision) = first_resolved_deny
        {
            return ReducedPolicy::Resolved(with_consulted(decision, consulted));
        }
        let known = partial_to_known(facts);
        let decision = evaluate_residual(&ResidualPolicy::Any(resolved_permits), &known);
        return ReducedPolicy::Resolved(with_consulted(decision, consulted));
    }

    let mut residual = resolved_permits;
    if residual.is_empty()
        && let Some(decision) = first_resolved_deny
    {
        residual.push(policy_from_decision(decision));
    }
    residual.extend(pending);
    ReducedPolicy::Pending {
        residual: ResidualPolicy::Any(residual),
        consulted,
    }
}

fn reduce_or_else<O: Lattice>(
    primary: &Policy<O>,
    fallback: &Policy<O>,
    facts: &PartialFacts,
) -> ReducedPolicy<O> {
    match reduce_policy(primary, facts) {
        ReducedPolicy::Resolved(decision) => match decision.effect {
            Effect::Permit(_) => ReducedPolicy::Resolved(decision),
            Effect::Deny => {
                let mut consulted = ConsultedList(decision.trace.consulted);
                match reduce_policy(fallback, facts) {
                    ReducedPolicy::Resolved(fallback_decision) => {
                        consulted.extend(ConsultedList(fallback_decision.trace.consulted.clone()));
                        ReducedPolicy::Resolved(with_consulted(fallback_decision, consulted))
                    }
                    ReducedPolicy::Pending {
                        residual,
                        consulted: fallback_consulted,
                    } => {
                        consulted.extend(fallback_consulted);
                        ReducedPolicy::Pending {
                            residual,
                            consulted,
                        }
                    }
                }
            }
        },
        ReducedPolicy::Pending {
            residual: primary_residual,
            mut consulted,
        } => match reduce_policy(fallback, facts) {
            ReducedPolicy::Resolved(decision) => {
                consulted.extend(ConsultedList(decision.trace.consulted.clone()));
                ReducedPolicy::Pending {
                    residual: ResidualPolicy::OrElse {
                        primary: Box::new(primary_residual),
                        fallback: Box::new(policy_from_decision(decision)),
                    },
                    consulted,
                }
            }
            ReducedPolicy::Pending {
                residual: fallback_residual,
                consulted: fallback_consulted,
            } => {
                consulted.extend(fallback_consulted);
                ReducedPolicy::Pending {
                    residual: ResidualPolicy::OrElse {
                        primary: Box::new(primary_residual),
                        fallback: Box::new(fallback_residual),
                    },
                    consulted,
                }
            }
        },
    }
}

fn reduce_condition(condition: &Condition, facts: &PartialFacts) -> ReducedCondition {
    match condition {
        Condition::Always => ReducedCondition::Known {
            satisfied: true,
            consulted: ConsultedList::default(),
        },
        Condition::Never => ReducedCondition::Known {
            satisfied: false,
            consulted: ConsultedList::default(),
        },
        Condition::Has(fact) => match facts.presence(fact) {
            Presence::Present => {
                let mut consulted = ConsultedList::default();
                consulted.record(fact, Presence::Present);
                ReducedCondition::Known {
                    satisfied: true,
                    consulted,
                }
            }
            Presence::Absent => {
                let mut consulted = ConsultedList::default();
                consulted.record(fact, Presence::Absent);
                ReducedCondition::Known {
                    satisfied: false,
                    consulted,
                }
            }
            Presence::Unknown => ReducedCondition::Pending {
                residual: Condition::Has(fact.clone()),
                consulted: ConsultedList::default(),
            },
        },
        Condition::Not(inner) => match reduce_condition(inner, facts) {
            ReducedCondition::Known {
                satisfied,
                consulted,
            } => ReducedCondition::Known {
                satisfied: !satisfied,
                consulted,
            },
            ReducedCondition::Pending {
                residual,
                consulted,
            } => ReducedCondition::Pending {
                residual: Condition::Not(Box::new(residual)),
                consulted,
            },
        },
        Condition::All(conditions) => reduce_condition_all(conditions, facts),
        Condition::Any(conditions) => reduce_condition_any(conditions, facts),
    }
}

fn reduce_condition_all(conditions: &[Condition], facts: &PartialFacts) -> ReducedCondition {
    if conditions.is_empty() {
        return ReducedCondition::Known {
            satisfied: false,
            consulted: ConsultedList::default(),
        };
    }

    let mut consulted = ConsultedList::default();
    let mut pending = Vec::new();
    for condition in conditions {
        match reduce_condition(condition, facts) {
            ReducedCondition::Known {
                satisfied: false,
                consulted: arm_consulted,
            } => {
                consulted.extend(arm_consulted);
                return ReducedCondition::Known {
                    satisfied: false,
                    consulted,
                };
            }
            ReducedCondition::Known {
                satisfied: true,
                consulted: arm_consulted,
            } => consulted.extend(arm_consulted),
            ReducedCondition::Pending {
                residual,
                consulted: arm_consulted,
            } => {
                consulted.extend(arm_consulted);
                pending.push(residual);
            }
        }
    }

    if pending.is_empty() {
        ReducedCondition::Known {
            satisfied: true,
            consulted,
        }
    } else if pending.len() == 1 {
        let mut pending = pending.into_iter();
        let Some(residual) = pending.next() else {
            return ReducedCondition::Pending {
                residual: Condition::Never,
                consulted,
            };
        };
        ReducedCondition::Pending {
            residual,
            consulted,
        }
    } else {
        ReducedCondition::Pending {
            residual: Condition::All(pending),
            consulted,
        }
    }
}

fn reduce_condition_any(conditions: &[Condition], facts: &PartialFacts) -> ReducedCondition {
    if conditions.is_empty() {
        return ReducedCondition::Known {
            satisfied: false,
            consulted: ConsultedList::default(),
        };
    }

    let mut consulted = ConsultedList::default();
    let mut pending = Vec::new();
    for condition in conditions {
        match reduce_condition(condition, facts) {
            ReducedCondition::Known {
                satisfied: true,
                consulted: arm_consulted,
            } => {
                consulted.extend(arm_consulted);
                return ReducedCondition::Known {
                    satisfied: true,
                    consulted,
                };
            }
            ReducedCondition::Known {
                satisfied: false,
                consulted: arm_consulted,
            } => consulted.extend(arm_consulted),
            ReducedCondition::Pending {
                residual,
                consulted: arm_consulted,
            } => {
                consulted.extend(arm_consulted);
                pending.push(residual);
            }
        }
    }

    if pending.is_empty() {
        ReducedCondition::Known {
            satisfied: false,
            consulted,
        }
    } else if pending.len() == 1 {
        let mut pending = pending.into_iter();
        let Some(residual) = pending.next() else {
            return ReducedCondition::Pending {
                residual: Condition::Never,
                consulted,
            };
        };
        ReducedCondition::Pending {
            residual,
            consulted,
        }
    } else {
        ReducedCondition::Pending {
            residual: Condition::Any(pending),
            consulted,
        }
    }
}

fn policy_from_decision<O: Lattice>(decision: Decision<O>) -> ResidualPolicy<O> {
    match decision.effect {
        Effect::Permit(outcome) => match decision.trace.decisive {
            crate::DecisiveClause::Permit {
                satisfied, label, ..
            } => ResidualPolicy::PermitWithTrace {
                outcome,
                obligations: decision.obligations,
                satisfied,
                label,
            },
            crate::DecisiveClause::Deny { .. } => ResidualPolicy::Permit(outcome),
        },
        Effect::Deny => match decision.trace.decisive {
            crate::DecisiveClause::Deny {
                denied,
                unsatisfied,
                label,
                reason,
                shape,
                ..
            } => ResidualPolicy::DenyWithTrace {
                denied,
                unsatisfied,
                label,
                reason,
                shape,
            },
            crate::DecisiveClause::Permit { .. } => ResidualPolicy::Deny,
        },
    }
}

fn with_consulted<O>(decision: Decision<O>, consulted: ConsultedList) -> Decision<O> {
    Decision {
        trace: crate::DecisionTrace {
            consulted: consulted.into_vec(),
            decisive: decision.trace.decisive,
        },
        ..decision
    }
}

fn with_prior_consulted<O>(
    mut decision: Decision<O>,
    consulted: &[(FactId, Presence)],
) -> Decision<O> {
    let mut merged = ConsultedList::default();
    for (fact, presence) in consulted {
        merged.record(fact, *presence);
    }
    merged.extend(ConsultedList(decision.trace.consulted));
    decision.trace.consulted = merged.into_vec();
    decision
}

fn partial_to_known(facts: &PartialFacts) -> crate::KnownFacts {
    crate::KnownFacts::from_known_entries(
        facts
            .known_entries()
            .map(|(fact, presence)| (fact.clone(), presence)),
    )
}
