use crate::{
    ClauseLabel, Condition, DenyShape, GatekeepResult, ObligationId, ObligationSpec, Policy,
    ReasonCode,
};

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

/// Builds a conditional denial guard.
///
/// The returned policy permits when `condition` is false and denies with
/// `reason` when `condition` is true. Place these guards in `policy::all` before
/// positive grant clauses to get ordered fail-closed precedence.
#[must_use]
pub fn deny_when<O: crate::Lattice>(
    condition: Condition,
    reason: impl IntoReasonCode,
) -> Policy<O> {
    grant(O::top(), crate::condition::not(condition)).reason(reason)
}

/// Builds a conditional grant policy.
#[must_use]
pub const fn grant<O>(outcome: O, condition: Condition) -> Policy<O> {
    Policy::Grant {
        outcome,
        condition,
        label: None,
        deny_shape: DenyShape::Forbidden,
        obligations: Vec::new(),
        reason: None,
    }
}

/// Builds a grant-only policy builder.
///
/// Unlike [`Policy::labeled`], [`Policy::hidden`], [`Policy::reason`], and
/// [`Policy::with_obligation`], these methods are only available on grant
/// clauses and cannot silently no-op on other policy variants.
#[must_use]
pub const fn grant_clause<O>(outcome: O, condition: Condition) -> GrantPolicy<O> {
    GrantPolicy {
        outcome,
        condition,
        label: None,
        deny_shape: DenyShape::Forbidden,
        obligations: Vec::new(),
        reason: None,
    }
}

/// Grant-only policy builder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantPolicy<O> {
    outcome: O,
    condition: Condition,
    label: Option<ClauseLabel>,
    deny_shape: DenyShape,
    obligations: Vec<ObligationId>,
    reason: Option<ReasonCode>,
}

impl<O> GrantPolicy<O> {
    /// Converts this grant builder into a policy.
    #[must_use]
    pub fn into_policy(self) -> Policy<O> {
        Policy::Grant {
            outcome: self.outcome,
            condition: self.condition,
            label: self.label,
            deny_shape: self.deny_shape,
            obligations: self.obligations,
            reason: self.reason,
        }
    }

    /// Adds a label to this grant.
    #[must_use]
    pub fn labeled(mut self, label: impl IntoLabel) -> Self {
        self.label = Some(label.into_label());
        self
    }

    /// Tries to add a validated label to this grant.
    ///
    /// # Errors
    ///
    /// Returns [`crate::GatekeepError::EmptyIdentifier`] when `label` is empty
    /// or contains only whitespace.
    pub fn try_labeled(self, label: impl Into<String>) -> GatekeepResult<Self> {
        Ok(self.labeled(ClauseLabel::new(label)?))
    }

    /// Marks this grant's denial as hidden.
    #[must_use]
    pub const fn hidden(mut self) -> Self {
        self.deny_shape = DenyShape::Hidden;
        self
    }

    /// Adds a reason code to this grant's denial.
    #[must_use]
    pub fn reason(mut self, reason: impl IntoReasonCode) -> Self {
        self.reason = Some(reason.into_reason_code());
        self
    }

    /// Tries to add a validated reason code to this grant's denial.
    ///
    /// # Errors
    ///
    /// Returns [`crate::GatekeepError::EmptyIdentifier`] when `reason` is empty
    /// or contains only whitespace.
    pub fn try_reason(self, reason: impl Into<String>) -> GatekeepResult<Self> {
        Ok(self.reason(ReasonCode::new(reason)?))
    }

    /// Adds a typed obligation to this grant's permit result.
    #[must_use]
    pub fn with_obligation<S: ObligationSpec>(mut self) -> Self {
        self.obligations
            .push(ObligationId::from_trusted(S::ID.as_str()));
        self
    }
}

impl<O> From<GrantPolicy<O>> for Policy<O> {
    fn from(grant: GrantPolicy<O>) -> Self {
        grant.into_policy()
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
    ///
    /// # Errors
    ///
    /// Returns [`crate::GatekeepError::EmptyIdentifier`] when `label` is empty
    /// or contains only whitespace.
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
    ///
    /// # Errors
    ///
    /// Returns [`crate::GatekeepError::EmptyIdentifier`] when `reason` is empty
    /// or contains only whitespace.
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
