use crate::{ClauseLabel, ObligationId, Policy, PreparedPolicy};
use std::collections::BTreeSet;

/// Advisory authoring issue; it does not change evaluation or invalidate a policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyAdvice<'a> {
    /// A grant has no stable label for explanations.
    UnlabeledGrant,
    /// More than one grant uses this label.
    DuplicateLabel(&'a ClauseLabel),
    /// A grant has neither a reason nor a label usable as a fallback reason.
    MissingReason,
}

/// Borrowed metadata inventory for tooling and reason-catalog checks.
#[derive(Clone, Debug)]
pub struct PolicyInspection<'a> {
    /// Grant labels in deterministic order.
    pub labels: BTreeSet<&'a ClauseLabel>,
    /// Explicit reason codes and label fallbacks, in deterministic order.
    pub reasons: BTreeSet<&'a str>,
    /// Required application obligations.
    pub obligations: BTreeSet<&'a ObligationId>,
    /// Advisory findings in policy traversal order.
    pub advice: Vec<PolicyAdvice<'a>>,
}

impl<O> PreparedPolicy<O> {
    /// Inventories metadata without evaluating checks or exposing application context.
    #[must_use]
    pub fn inspect(&self) -> PolicyInspection<'_> {
        let mut inspection = PolicyInspection {
            labels: BTreeSet::new(),
            reasons: BTreeSet::new(),
            obligations: BTreeSet::new(),
            advice: Vec::new(),
        };
        let mut pending = vec![self.policy()];
        while let Some(policy) = pending.pop() {
            match policy {
                Policy::Grant {
                    label,
                    reason,
                    obligations,
                    ..
                } => inspection.grant(
                    label.as_ref(),
                    reason.as_ref().map(crate::ReasonCode::as_str),
                    obligations,
                ),
                Policy::All(children) | Policy::Any(children) => {
                    pending.extend(children.iter().rev());
                }
                Policy::OrElse { primary, fallback } => {
                    pending.push(fallback);
                    pending.push(primary);
                }
                Policy::Permit(_) | Policy::Deny => {}
            }
        }
        inspection
    }
}

impl<'a> PolicyInspection<'a> {
    fn grant(
        &mut self,
        label: Option<&'a ClauseLabel>,
        reason: Option<&'a str>,
        obligations: &'a [ObligationId],
    ) {
        match label {
            None => self.advice.push(PolicyAdvice::UnlabeledGrant),
            Some(label) if !self.labels.insert(label) => {
                self.advice.push(PolicyAdvice::DuplicateLabel(label));
            }
            Some(_) => {}
        }

        match reason.or_else(|| label.map(ClauseLabel::as_str)) {
            Some(reason) => {
                self.reasons.insert(reason);
            }
            None => self.advice.push(PolicyAdvice::MissingReason),
        }

        self.obligations.extend(obligations);
    }
}
