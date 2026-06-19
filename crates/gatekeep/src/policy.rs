use crate::{ClauseLabel, Condition, GatekeepResult, ObligationSpec, Policy, ReasonCode};

/// Builds an unconditional permit policy.
#[must_use]
pub const fn permit<O>(outcome: O) -> Policy<O> {
    Policy::Permit(outcome)
}

/// Builds an unconditional denial policy.
#[must_use]
pub const fn deny<O>() -> Policy<O> {
    Policy::Deny
}

/// Builds a conditional grant policy.
#[must_use]
pub const fn grant<O>(outcome: O, condition: Condition) -> Policy<O> {
    Policy::Grant {
        outcome,
        condition,
        label: None,
        deny_shape: crate::DenyShape::Forbidden,
        obligations: Vec::new(),
        reason: None,
    }
}

/// Builds a meet composition. Empty input fails closed.
#[must_use]
pub fn all<O>(policies: impl IntoIterator<Item = Policy<O>>) -> Policy<O> {
    let policies = policies.into_iter().collect::<Vec<_>>();
    if policies.is_empty() {
        Policy::Deny
    } else {
        Policy::All(policies)
    }
}

/// Builds a join composition. Empty input fails closed.
#[must_use]
pub fn any<O>(policies: impl IntoIterator<Item = Policy<O>>) -> Policy<O> {
    let policies = policies.into_iter().collect::<Vec<_>>();
    if policies.is_empty() {
        Policy::Deny
    } else {
        Policy::Any(policies)
    }
}

/// Builds a fallback policy.
#[must_use]
pub fn or_else<O>(primary: Policy<O>, fallback: Policy<O>) -> Policy<O> {
    Policy::OrElse {
        primary: Box::new(primary),
        fallback: Box::new(fallback),
    }
}

impl<O> Policy<O> {
    /// Adds a label to grant policies.
    #[must_use]
    pub fn labeled(mut self, label: impl IntoLabel) -> Self {
        if let Self::Grant {
            label: grant_label, ..
        } = &mut self
        {
            *grant_label = Some(label.into_label());
        }
        self
    }

    /// Tries to add a validated label to grant policies.
    pub fn try_labeled(self, label: impl Into<String>) -> GatekeepResult<Self> {
        Ok(self.labeled(ClauseLabel::new(label)?))
    }

    /// Marks grant denial as hidden.
    #[must_use]
    pub const fn hidden(mut self) -> Self {
        if let Self::Grant { deny_shape, .. } = &mut self {
            *deny_shape = crate::DenyShape::Hidden;
        }
        self
    }

    /// Adds a reason code to grant denials.
    #[must_use]
    pub fn reason(mut self, reason: impl IntoReasonCode) -> Self {
        if let Self::Grant {
            reason: grant_reason,
            ..
        } = &mut self
        {
            *grant_reason = Some(reason.into_reason_code());
        }
        self
    }

    /// Tries to add a validated reason code to grant denials.
    pub fn try_reason(self, reason: impl Into<String>) -> GatekeepResult<Self> {
        Ok(self.reason(ReasonCode::new(reason)?))
    }

    /// Adds a typed obligation to grant permits.
    #[must_use]
    pub fn with_obligation<S: ObligationSpec>(mut self) -> Self {
        if let Self::Grant { obligations, .. } = &mut self {
            obligations.push(crate::ObligationId::from_trusted(S::ID.as_str()));
        }
        self
    }
}

/// Conversion into a validated clause label.
pub trait IntoLabel {
    /// Converts the value into a label.
    fn into_label(self) -> ClauseLabel;
}

impl IntoLabel for ClauseLabel {
    fn into_label(self) -> ClauseLabel {
        self
    }
}

/// Conversion into a validated reason code.
pub trait IntoReasonCode {
    /// Converts the value into a reason code.
    fn into_reason_code(self) -> ReasonCode;
}

impl IntoReasonCode for ReasonCode {
    fn into_reason_code(self) -> ReasonCode {
        self
    }
}
