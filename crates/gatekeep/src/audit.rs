use crate::{
    Decision, DecisionAuditId, DecisionAuditOccurrence, DecisionAuditOccurrenceError, DenialReason,
    FactId, FactResolutionError, FactResolutionEvidence, Locale, ObligationId, PolicyHash,
    PolicyId, Presence, ReasonValue, RequestId, SubjectRef, SubjectSlot, TenantBinding, TenantId,
    Trace, TraceClause,
};
use serde::{Deserialize, Serialize, de::Error as DeError};
use std::collections::BTreeMap;
use thiserror::Error;

/// Current durable representation version for decision audit entries.
pub const AUDIT_ENTRY_SCHEMA_VERSION: u16 = 1;

/// Stable policy identity recorded with summaries and audit entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyAnchor {
    /// Author-assigned stable policy id.
    #[serde(rename = "policy_id")]
    id: PolicyId,
    /// Derived content hash of the policy AST.
    #[serde(rename = "policy_hash")]
    hash: PolicyHash,
    /// Format version used to derive `policy_hash`.
    #[serde(rename = "policy_hash_version")]
    hash_version: u16,
}

#[derive(Deserialize)]
struct PolicyAnchorWire {
    #[serde(rename = "policy_id")]
    id: PolicyId,
    #[serde(rename = "policy_hash")]
    hash: PolicyHash,
    #[serde(rename = "policy_hash_version")]
    hash_version: u16,
}

impl<'de> Deserialize<'de> for PolicyAnchor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = PolicyAnchorWire::deserialize(deserializer)?;
        if wire.hash_version != crate::POLICY_HASH_FORMAT_VERSION {
            return Err(D::Error::custom(format!(
                "unsupported policy hash format version {}; expected {}",
                wire.hash_version,
                crate::POLICY_HASH_FORMAT_VERSION
            )));
        }
        Ok(Self {
            id: wire.id,
            hash: wire.hash,
            hash_version: wire.hash_version,
        })
    }
}

impl PolicyAnchor {
    /// Constructs an anchor for the current policy-hash format.
    #[must_use]
    pub const fn new(policy_id: PolicyId, policy_hash: PolicyHash) -> Self {
        Self {
            id: policy_id,
            hash: policy_hash,
            hash_version: crate::POLICY_HASH_FORMAT_VERSION,
        }
    }

    /// Returns the author-assigned policy id.
    #[must_use]
    pub const fn policy_id(&self) -> &PolicyId {
        &self.id
    }

    /// Returns the derived policy hash.
    #[must_use]
    pub const fn policy_hash(&self) -> &PolicyHash {
        &self.hash
    }

    /// Returns the format version used to derive the policy hash.
    #[must_use]
    pub const fn policy_hash_version(&self) -> u16 {
        self.hash_version
    }

    const fn validate_current(&self) -> Result<(), AuditEntryError> {
        if self.hash_version != crate::POLICY_HASH_FORMAT_VERSION {
            return Err(AuditEntryError::UnsupportedPolicyHashVersion {
                expected: crate::POLICY_HASH_FORMAT_VERSION,
                actual: self.hash_version,
            });
        }
        Ok(())
    }
}

/// Policy anchor shape retained for explicit migration of pre-4.0 audit data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyPolicyAnchor {
    /// Author-assigned stable policy id.
    pub policy_id: PolicyId,
    /// Hash recorded by the historical audit representation.
    pub policy_hash: PolicyHash,
}

/// Permit/deny effect without the generic outcome value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectKind {
    /// Decision permitted.
    Permit,
    /// Decision denied.
    Deny,
}

impl<O> From<&Decision<O>> for EffectKind {
    fn from(decision: &Decision<O>) -> Self {
        match decision.effect {
            crate::Effect::Permit(_) => Self::Permit,
            crate::Effect::Deny => Self::Deny,
        }
    }
}

/// Monomorphic observer payload for a decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionSummary {
    /// Policy version that produced the decision.
    pub anchor: PolicyAnchor,
    /// Permit/deny effect.
    pub effect: EffectKind,
    /// Obligations attached to the decision.
    pub obligations: Vec<ObligationId>,
    /// Facts read by the evaluator.
    pub consulted: Vec<(FactId, Presence)>,
}

/// Durable audit payload for a decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditEntry {
    /// Current durable audit representation version.
    schema_version: u16,
    /// Stable identity of this decision occurrence, independent of storage
    /// cursors and database-generated row ids.
    decision_audit_id: DecisionAuditId,
    /// Authoritative time at which the decision occurred.
    occurred_at: time::OffsetDateTime,
    /// Request identifier supplied by the application boundary.
    request_id: Option<RequestId>,
    /// Policy version that produced the decision.
    anchor: PolicyAnchor,
    /// Permit/deny effect.
    effect: EffectKind,
    /// Obligations attached to the decision.
    obligations: Vec<ObligationId>,
    /// Facts read by the evaluator in first-read order.
    consulted: Vec<(FactId, Presence)>,
    /// Clause that fixed the decision effect.
    decisive: TraceClause,
    /// Structured denial reason for deny decisions.
    denial_reason: Option<DenialReason>,
    /// Durable, non-generic decision trace.
    trace: Trace,
    /// Tenant binding used for this decision.
    binding: TenantBinding,
    /// Bounded evidence for the complete fact set.
    fact_resolution: FactResolutionEvidence,
    /// Tenant selected by the application before resolution.
    tenant: TenantId,
    /// Principal selected by the application before resolution.
    principal: SubjectRef,
    /// Named request subjects selected by the application before resolution.
    subjects: BTreeMap<SubjectSlot, SubjectRef>,
    /// Locale carried by the request context for a complete decision record.
    locale: Locale,
}

#[derive(Deserialize)]
struct AuditEntryWire {
    schema_version: u16,
    decision_audit_id: DecisionAuditId,
    occurred_at: time::OffsetDateTime,
    request_id: Option<RequestId>,
    anchor: PolicyAnchor,
    effect: EffectKind,
    obligations: Vec<ObligationId>,
    consulted: Vec<(FactId, Presence)>,
    decisive: TraceClause,
    denial_reason: Option<DenialReason>,
    trace: Trace,
    binding: TenantBinding,
    fact_resolution: FactResolutionEvidence,
    tenant: TenantId,
    principal: SubjectRef,
    #[serde(default)]
    subjects: BTreeMap<SubjectSlot, SubjectRef>,
    locale: Locale,
}

impl<'de> Deserialize<'de> for AuditEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AuditEntryWire::deserialize(deserializer)?;
        if wire.schema_version != AUDIT_ENTRY_SCHEMA_VERSION {
            return Err(D::Error::custom(format!(
                "unsupported audit entry schema version {}; expected {}",
                wire.schema_version, AUDIT_ENTRY_SCHEMA_VERSION
            )));
        }

        let occurrence = DecisionAuditOccurrence::new(wire.decision_audit_id, wire.occurred_at)
            .map_err(D::Error::custom)?;
        Self::new(
            occurrence,
            wire.request_id,
            wire.anchor,
            wire.effect,
            wire.obligations,
            wire.consulted,
            wire.decisive,
            wire.denial_reason,
            wire.trace,
            wire.binding,
            wire.fact_resolution,
            wire.tenant,
            wire.principal,
            wire.subjects,
            wire.locale,
        )
        .map_err(D::Error::custom)
    }
}

/// Historical audit shape used only by an explicit migration decoder.
///
/// This type is intentionally not accepted by [`crate::AuditSink`] and cannot be
/// passed to current audit APIs. Its optional binding and fact evidence mirror
/// pre-4.0 payloads so migration code can inspect and map them deliberately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyAuditEntry {
    /// Historical decision identity as it appeared in the source record.
    pub decision_audit_id: String,
    /// Historical decision occurrence time.
    pub occurred_at: time::OffsetDateTime,
    /// Request identifier supplied by the historical application boundary.
    pub request_id: Option<RequestId>,
    /// Historical policy anchor without a hash-format marker.
    pub anchor: LegacyPolicyAnchor,
    /// Permit/deny effect.
    pub effect: EffectKind,
    /// Obligations attached to the decision.
    pub obligations: Vec<ObligationId>,
    /// Facts read by the evaluator.
    pub consulted: Vec<(FactId, Presence)>,
    /// Clause that fixed the decision effect.
    pub decisive: TraceClause,
    /// Structured denial reason for deny decisions.
    pub denial_reason: Option<DenialReason>,
    /// Durable decision trace.
    pub trace: Trace,
    /// Historical tenant binding, when the source contained one.
    #[serde(default)]
    pub binding: Option<TenantBinding>,
    /// Historical fact-set evidence, when the source contained one.
    #[serde(default)]
    pub fact_resolution: Option<FactResolutionEvidence>,
    /// Tenant selected by the historical application.
    pub tenant: TenantId,
    /// Principal selected by the historical application.
    pub principal: SubjectRef,
    /// Named request subjects selected by the historical application.
    #[serde(default)]
    pub subjects: BTreeMap<SubjectSlot, SubjectRef>,
    /// Locale carried by the historical request context.
    pub locale: Locale,
}

impl LegacyAuditEntry {
    /// Validates only the semantic fields retained by the historical shape.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEntryError`] when duplicated decision fields disagree.
    pub fn validate_semantics(&self) -> Result<(), AuditEntryError> {
        validate_audit_semantics(
            self.effect,
            &self.obligations,
            &self.consulted,
            &self.decisive,
            self.denial_reason.as_ref(),
            &self.trace,
        )
    }

    /// Imports this historical record after the caller supplies current
    /// binding, evidence, occurrence, and the known historical hash format.
    ///
    /// The supplied occurrence deliberately determines the new current
    /// identity; historical identities remain migration provenance and are
    /// never accepted as ordinary current identities.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEntryError`] when the historical semantics, supplied
    /// anchor version, or current entry invariants are invalid.
    pub fn into_current(
        self,
        occurrence: DecisionAuditOccurrence,
        policy_hash_version: u16,
        binding: TenantBinding,
        fact_resolution: FactResolutionEvidence,
    ) -> Result<AuditEntry, AuditEntryError> {
        self.validate_semantics()?;
        if policy_hash_version != crate::POLICY_HASH_FORMAT_VERSION {
            return Err(AuditEntryError::UnsupportedPolicyHashVersion {
                expected: crate::POLICY_HASH_FORMAT_VERSION,
                actual: policy_hash_version,
            });
        }
        AuditEntry::new(
            occurrence,
            self.request_id,
            PolicyAnchor::new(self.anchor.policy_id, self.anchor.policy_hash),
            self.effect,
            self.obligations,
            self.consulted,
            self.decisive,
            self.denial_reason,
            self.trace,
            binding,
            fact_resolution,
            self.tenant,
            self.principal,
            self.subjects,
            self.locale,
        )
    }
}

/// Validation failure for a current durable audit entry.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditEntryError {
    /// The entry uses a schema version this crate does not understand.
    #[error("unsupported audit entry schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion {
        /// Schema version required by this release.
        expected: u16,
        /// Schema version found in the entry.
        actual: u16,
    },
    /// The policy hash uses a format version this crate does not understand.
    #[error("unsupported policy hash format version {actual}; expected {expected}")]
    UnsupportedPolicyHashVersion {
        /// Hash format required by this release.
        expected: u16,
        /// Hash format found in the anchor.
        actual: u16,
    },
    /// The entry tenant differs from the tenant carried by its binding.
    #[error("audit entry tenant does not match its binding")]
    BindingTenantMismatch,
    /// The decision occurrence does not satisfy the current durable contract.
    #[error("audit entry carries an invalid decision occurrence")]
    InvalidDecisionOccurrence(#[source] DecisionAuditOccurrenceError),
    /// Fact-resolution evidence has an impossible freshness window.
    #[error("audit entry carries invalid fact-resolution evidence")]
    InvalidFactResolutionEvidence(#[source] FactResolutionError),
    /// The duplicated decisive clause disagrees with the complete trace.
    #[error("audit entry decisive clause does not match its trace")]
    DecisiveTraceMismatch,
    /// The duplicated consulted-fact list disagrees with the complete trace.
    #[error("audit entry consulted facts do not match its trace")]
    ConsultedTraceMismatch,
    /// The effect disagrees with the decisive trace clause.
    #[error("audit entry effect does not match its decisive trace clause")]
    EffectTraceMismatch,
    /// Permit decisions cannot carry a denial reason.
    #[error("permit audit entry carries a denial reason")]
    PermitWithDenialReason,
    /// Deny decisions cannot carry permit-path obligations.
    #[error("deny audit entry carries obligations")]
    DenyWithObligations,
    /// The materialized denial reason disagrees with the decisive trace.
    #[error("audit entry denial reason does not match its decisive trace clause")]
    DenialReasonMismatch,
}

impl AuditEntry {
    /// Constructs a current audit entry with a validated occurrence, binding,
    /// and fact-resolution evidence.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEntryError`] when the binding does not cover the entry
    /// tenant or when required current evidence is absent.
    #[allow(
        clippy::too_many_arguments,
        reason = "Published Gatekeep 4 constructor; retain its signature until a justified major API migration"
    )]
    pub fn new(
        occurrence: DecisionAuditOccurrence,
        request_id: Option<RequestId>,
        anchor: PolicyAnchor,
        effect: EffectKind,
        obligations: Vec<ObligationId>,
        consulted: Vec<(FactId, Presence)>,
        decisive: TraceClause,
        denial_reason: Option<DenialReason>,
        trace: Trace,
        binding: TenantBinding,
        fact_resolution: FactResolutionEvidence,
        tenant: TenantId,
        principal: SubjectRef,
        subjects: BTreeMap<SubjectSlot, SubjectRef>,
        locale: Locale,
    ) -> Result<Self, AuditEntryError> {
        occurrence
            .validate()
            .map_err(AuditEntryError::InvalidDecisionOccurrence)?;
        let (decision_audit_id, occurred_at) = occurrence.into_parts();
        let entry = Self {
            schema_version: AUDIT_ENTRY_SCHEMA_VERSION,
            decision_audit_id,
            occurred_at,
            request_id,
            anchor,
            effect,
            obligations,
            consulted,
            decisive,
            denial_reason,
            trace,
            binding,
            fact_resolution,
            tenant,
            principal,
            subjects,
            locale,
        };
        entry.validate_current()?;
        Ok(entry)
    }

    /// Returns the current durable audit schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the stable identity and occurrence time as one validated value.
    #[must_use]
    pub fn occurrence(&self) -> DecisionAuditOccurrence {
        DecisionAuditOccurrence::from_validated_parts(
            self.decision_audit_id.clone(),
            self.occurred_at,
        )
    }

    /// Returns the stable decision identity.
    #[must_use]
    pub const fn decision_audit_id(&self) -> &DecisionAuditId {
        &self.decision_audit_id
    }

    /// Returns the authoritative decision occurrence time.
    #[must_use]
    pub const fn occurred_at(&self) -> time::OffsetDateTime {
        self.occurred_at
    }

    /// Returns the optional request identifier.
    #[must_use]
    pub const fn request_id(&self) -> Option<&RequestId> {
        self.request_id.as_ref()
    }

    /// Returns the policy anchor.
    #[must_use]
    pub const fn anchor(&self) -> &PolicyAnchor {
        &self.anchor
    }

    /// Returns the permit or deny effect.
    #[must_use]
    pub const fn effect(&self) -> EffectKind {
        self.effect
    }

    /// Returns obligations attached to the selected policy path.
    #[must_use]
    pub fn obligations(&self) -> &[ObligationId] {
        &self.obligations
    }

    /// Returns facts consulted by evaluation.
    #[must_use]
    pub fn consulted(&self) -> &[(FactId, Presence)] {
        &self.consulted
    }

    /// Returns the decisive trace clause.
    #[must_use]
    pub const fn decisive(&self) -> &TraceClause {
        &self.decisive
    }

    /// Returns the structured denial reason, when present.
    #[must_use]
    pub const fn denial_reason(&self) -> Option<&DenialReason> {
        self.denial_reason.as_ref()
    }

    /// Returns the complete durable decision trace.
    #[must_use]
    pub const fn trace(&self) -> &Trace {
        &self.trace
    }

    /// Returns the validated tenant binding used by the decision.
    #[must_use]
    pub const fn binding(&self) -> &TenantBinding {
        &self.binding
    }

    /// Returns bounded evidence for the complete resolved fact set.
    #[must_use]
    pub const fn fact_resolution(&self) -> &FactResolutionEvidence {
        &self.fact_resolution
    }

    /// Returns the tenant selected by the application.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Returns the principal selected by the application.
    #[must_use]
    pub const fn principal(&self) -> &SubjectRef {
        &self.principal
    }

    /// Returns named request subjects.
    #[must_use]
    pub const fn subjects(&self) -> &BTreeMap<SubjectSlot, SubjectRef> {
        &self.subjects
    }

    /// Returns the request presentation locale.
    #[must_use]
    pub const fn locale(&self) -> &Locale {
        &self.locale
    }

    /// Validates that this entry is safe to persist as a current decision.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEntryError`] when the schema or policy hash version is
    /// unsupported, the binding names another tenant, evidence is invalid, or
    /// denormalized decision fields contradict one another.
    pub fn validate_current(&self) -> Result<(), AuditEntryError> {
        if self.schema_version != AUDIT_ENTRY_SCHEMA_VERSION {
            return Err(AuditEntryError::UnsupportedSchemaVersion {
                expected: AUDIT_ENTRY_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        DecisionAuditOccurrence::from_validated_parts(
            self.decision_audit_id.clone(),
            self.occurred_at,
        )
        .validate()
        .map_err(AuditEntryError::InvalidDecisionOccurrence)?;
        self.anchor.validate_current()?;
        if self.binding.tenant() != &self.tenant {
            return Err(AuditEntryError::BindingTenantMismatch);
        }

        self.fact_resolution
            .validate()
            .map_err(AuditEntryError::InvalidFactResolutionEvidence)?;
        self.validate_semantics()
    }

    /// Validates consistency between the denormalized decision fields.
    ///
    /// This check applies to both current entries and decoded legacy history;
    /// it does not require current tenant-binding or fact-resolution evidence.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEntryError`] when effect, trace, consulted facts,
    /// obligations, or denial reason contradict one another.
    pub fn validate_semantics(&self) -> Result<(), AuditEntryError> {
        validate_audit_semantics(
            self.effect,
            &self.obligations,
            &self.consulted,
            &self.decisive,
            self.denial_reason.as_ref(),
            &self.trace,
        )
    }
}

fn validate_audit_semantics(
    effect: EffectKind,
    obligations: &[ObligationId],
    consulted: &[(FactId, Presence)],
    decisive: &TraceClause,
    denial_reason: Option<&DenialReason>,
    trace: &Trace,
) -> Result<(), AuditEntryError> {
    if decisive != &trace.decisive {
        return Err(AuditEntryError::DecisiveTraceMismatch);
    }

    if consulted != trace.consulted.as_slice() {
        return Err(AuditEntryError::ConsultedTraceMismatch);
    }

    match (effect, decisive) {
        (EffectKind::Permit, TraceClause::Permit { .. }) => {
            if denial_reason.is_some() {
                return Err(AuditEntryError::PermitWithDenialReason);
            }
        }
        (EffectKind::Deny, TraceClause::Deny { .. }) => {
            if !obligations.is_empty() {
                return Err(AuditEntryError::DenyWithObligations);
            }

            if !denial_reason_matches_trace(denial_reason, decisive) {
                return Err(AuditEntryError::DenialReasonMismatch);
            }
        }
        _ => return Err(AuditEntryError::EffectTraceMismatch),
    }

    Ok(())
}

fn denial_reason_matches_trace(reason: Option<&DenialReason>, decisive: &TraceClause) -> bool {
    let TraceClause::Deny {
        denied,
        unsatisfied,
        label,
        reason: reason_code,
        shape,
    } = decisive
    else {
        return reason.is_none();
    };

    let expected_code = reason_code
        .as_ref()
        .map(crate::ReasonCode::as_str)
        .or_else(|| label.as_ref().map(crate::ClauseLabel::as_str));
    let Some(expected_code) = expected_code else {
        return reason.is_none();
    };

    let Some(reason) = reason else {
        return false;
    };

    if reason.code.as_str() != expected_code || reason.shape != *shape {
        return false;
    }

    let actual = reason
        .params
        .iter()
        .map(|(key, value)| (key.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    if Some(actual.len()) != unsatisfied.len().checked_add(usize::from(denied.is_some())) {
        return false;
    }

    for (index, fact) in unsatisfied.iter().enumerate() {
        let key = if index == 0 {
            "missing_fact".to_owned()
        } else {
            format!("missing_fact_{index}")
        };

        if actual.get(key.as_str()) != Some(&&ReasonValue::Fact(fact.clone())) {
            return false;
        }
    }

    denied.as_ref().is_none_or(|value| {
        actual.get("denied_outcome") == Some(&&ReasonValue::Outcome(value.clone()))
    })
}
