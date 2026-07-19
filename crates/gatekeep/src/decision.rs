use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ClauseLabel, FactId, ObligationId, ParamKey, Presence, ReasonCode, TraceValue};

/// Disclosure shape for a denied grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyShape {
    /// The denial may disclose that the protected resource exists.
    Forbidden,
    /// The denial should be presented as if the protected resource does not exist.
    Hidden,
}

/// Permit or deny effect produced by evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect<O> {
    /// Policy permitted with an outcome grade.
    Permit(O),
    /// Policy denied.
    Deny,
}

/// Structured policy decision with obligations and a typed trace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision<O> {
    /// Permit or deny effect.
    pub effect: Effect<O>,
    /// Obligations attached to the decisive permit path.
    pub obligations: Vec<ObligationId>,
    /// Typed trace returned by pure evaluation.
    pub trace: DecisionTrace<O>,
}

impl<O> Decision<O> {
    /// Returns true when the decision is a permit.
    #[must_use]
    pub const fn is_permit(&self) -> bool {
        matches!(self.effect, Effect::Permit(_))
    }
}

impl<O: Serialize + Clone> Decision<O> {
    /// Converts the typed trace into a durable, non-generic trace.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError::Outcome`] when an outcome cannot be represented
    /// as JSON.
    pub fn to_trace(&self) -> Result<Trace, TraceError> {
        let decisive = match &self.trace.decisive {
            DecisiveClause::Permit {
                granted,
                satisfied,
                label,
            } => TraceClause::Permit {
                granted: serde_json::to_value(granted).map_err(TraceError::Outcome)?,
                satisfied: satisfied.clone(),
                label: label.clone(),
            },
            DecisiveClause::Deny {
                denied,
                unsatisfied,
                label,
                reason,
                shape,
            } => TraceClause::Deny {
                denied: denied
                    .as_ref()
                    .map(serde_json::to_value)
                    .transpose()
                    .map_err(TraceError::Outcome)?,
                unsatisfied: unsatisfied.clone(),
                label: label.clone(),
                reason: reason.clone(),
                shape: *shape,
            },
        };
        Ok(Trace {
            consulted: self.trace.consulted.clone(),
            decisive,
        })
    }

    /// Builds a stable denial reason for a denied grant.
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] when an outcome cannot be serialized or a
    /// generated reason identifier fails validation.
    pub fn denial_reason(&self) -> Result<Option<DenialReason>, TraceError> {
        if !matches!(self.effect, Effect::Deny) {
            return Ok(None);
        }

        let DecisiveClause::Deny {
            denied,
            unsatisfied,
            label,
            reason,
            shape,
        } = &self.trace.decisive
        else {
            return Ok(None);
        };

        let code = match (reason, label) {
            (Some(reason), _) => reason.clone(),
            (None, Some(label)) => ReasonCode::new(label.as_str()).map_err(TraceError::Identity)?,
            (None, None) => return Ok(None),
        };

        let mut params = BTreeMap::new();
        for (index, fact) in unsatisfied.iter().enumerate() {
            let key = if index == 0 {
                ParamKey::new("missing_fact").map_err(TraceError::Identity)?
            } else {
                ParamKey::new(format!("missing_fact_{index}")).map_err(TraceError::Identity)?
            };
            params.insert(key, ReasonValue::Fact(fact.clone()));
        }

        if let Some(outcome) = denied {
            params.insert(
                ParamKey::new("denied_outcome").map_err(TraceError::Identity)?,
                ReasonValue::Outcome(serde_json::to_value(outcome).map_err(TraceError::Outcome)?),
            );
        }

        Ok(Some(DenialReason {
            code,
            params,
            shape: *shape,
        }))
    }
}

/// Typed trace produced by pure evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionTrace<O> {
    /// Facts read by the evaluator in first-read order.
    pub consulted: Vec<(FactId, Presence)>,
    /// Clause that fixed the decision effect.
    pub decisive: DecisiveClause<O>,
}

/// Typed decisive clause.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisiveClause<O> {
    /// Permit clause that fixed the decision.
    Permit {
        /// Granted outcome.
        granted: O,
        /// Facts that satisfied the deciding condition.
        satisfied: Vec<FactId>,
        /// Optional stable clause label.
        label: Option<ClauseLabel>,
    },
    /// Deny clause that fixed the decision.
    Deny {
        /// Outcome requested by the denied grant, when one exists.
        denied: Option<O>,
        /// Facts that caused the deciding condition to fail.
        unsatisfied: Vec<FactId>,
        /// Optional stable clause label.
        label: Option<ClauseLabel>,
        /// Optional stable reason code.
        reason: Option<ReasonCode>,
        /// Disclosure shape for presentation.
        shape: DenyShape,
    },
}

/// Durable, non-generic decision trace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trace {
    /// Facts read by the evaluator in first-read order.
    pub consulted: Vec<(FactId, Presence)>,
    /// Serialized decisive clause.
    pub decisive: TraceClause,
}

/// Serialized decisive clause.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceClause {
    /// Permit clause with a serialized outcome.
    Permit {
        /// Serialized granted outcome.
        granted: TraceValue,
        /// Facts that satisfied the deciding condition.
        satisfied: Vec<FactId>,
        /// Optional stable clause label.
        label: Option<ClauseLabel>,
    },
    /// Deny clause with an optional serialized requested outcome.
    Deny {
        /// Serialized denied outcome, when one exists.
        denied: Option<TraceValue>,
        /// Facts that caused the deciding condition to fail.
        unsatisfied: Vec<FactId>,
        /// Optional stable clause label.
        label: Option<ClauseLabel>,
        /// Optional stable reason code.
        reason: Option<ReasonCode>,
        /// Disclosure shape for presentation.
        shape: DenyShape,
    },
}

/// Stable denial reason emitted by the core.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenialReason {
    /// Stable translation key.
    pub code: ReasonCode,
    /// Structured parameters for presentation.
    pub params: BTreeMap<ParamKey, ReasonValue>,
    /// Disclosure shape for presentation.
    pub shape: DenyShape,
}

/// Structured denial-reason parameter value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReasonValue {
    /// String parameter.
    Str(String),
    /// Integer parameter.
    Int(i64),
    /// Fact identity parameter.
    Fact(FactId),
    /// Serialized outcome parameter.
    Outcome(TraceValue),
}

/// Error produced while serializing trace or reason values.
#[derive(Debug, Error)]
pub enum TraceError {
    /// Outcome serialization failed.
    #[error("failed to serialize outcome for trace")]
    Outcome(#[source] serde_json::Error),
    /// Stable identity validation failed while building a reason.
    #[error(transparent)]
    Identity(#[from] crate::GatekeepError),
}
