use std::collections::BTreeMap;

use gatekeep::{
    AuditEntry, DenialReason, DenyShape, EffectKind, FactId, FactResolution,
    FactResolutionEvidence, GatekeepError, ParamKey, PolicyAnchor, PolicyHash, PolicyId, Presence,
    ReasonCode, ReasonValue, RequestId, SubjectRef, SubjectSlot, TenantBinding, TenantId, Trace,
    TraceClause, TrustedServiceBinding,
};
use time::OffsetDateTime;

pub fn audit_entry() -> Result<AuditEntry, GatekeepError> {
    let missing = FactId::new("owner")?;
    let mut params = BTreeMap::new();
    params.insert(
        ParamKey::new("missing_fact")?,
        ReasonValue::Fact(missing.clone()),
    );
    let reason = DenialReason {
        code: ReasonCode::new("not_owner")?,
        params,
        shape: DenyShape::Forbidden,
    };
    let decisive = TraceClause::Deny {
        denied: None,
        unsatisfied: vec![missing.clone()],
        label: None,
        reason: Some(reason.code.clone()),
        shape: DenyShape::Forbidden,
    };
    let tenant = TenantId::new("tenant-1")?;
    let trace = Trace {
        consulted: vec![(missing, Presence::Absent)],
        decisive,
    };
    let binding = TenantBinding::TrustedService(
        TrustedServiceBinding::new(tenant.clone(), "gatekeep-sqlx-tests").map_err(|_| {
            GatekeepError::InvalidPolicyRecord {
                reason: "test binding construction",
            }
        })?,
    );
    let fact_resolution = FactResolutionEvidence::from_resolution(
        &FactResolution::new(
            gatekeep::KnownFacts::new(),
            None,
            OffsetDateTime::UNIX_EPOCH,
        )
        .map_err(|_| GatekeepError::InvalidPolicyRecord {
            reason: "test fact resolution freshness",
        })?,
    )
    .map_err(|_| GatekeepError::InvalidPolicyRecord {
        reason: "test fact evidence serialization",
    })?;
    AuditEntry::new(
        gatekeep::DecisionAuditOccurrence::new(
            gatekeep::DecisionAuditId::new("decision-1")?,
            OffsetDateTime::UNIX_EPOCH,
        )
        .map_err(|_| GatekeepError::InvalidPolicyRecord {
            reason: "test decision occurrence",
        })?,
        Some(RequestId::new("request-1")?),
        PolicyAnchor::new(PolicyId::new("case-read")?, PolicyHash::new("hash")?),
        EffectKind::Deny,
        Vec::new(),
        trace.consulted.clone(),
        trace.decisive.clone(),
        Some(reason),
        trace,
        binding,
        fact_resolution,
        tenant,
        SubjectRef::new("user", "mari")?,
        BTreeMap::from([(SubjectSlot::new("case")?, SubjectRef::new("case", "123")?)]),
        gatekeep::Locale::new("en-US")?,
    )
    .map_err(|_| GatekeepError::InvalidPolicyRecord {
        reason: "test audit entry",
    })
}
