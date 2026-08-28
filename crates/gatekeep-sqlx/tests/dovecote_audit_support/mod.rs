use std::collections::BTreeMap;

use gatekeep::{
    AuditEntry, DenialReason, DenyShape, EffectKind, FactId, FactResolution,
    FactResolutionEvidence, GatekeepError, ObligationId, ParamKey, PolicyAnchor, PolicyHash,
    PolicyId, Presence, ReasonCode, ReasonValue, RequestId, SubjectRef, SubjectSlot, TenantBinding,
    TenantId, Trace, TraceClause, TrustedServiceBinding,
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
    Ok(AuditEntry {
        decision_audit_id: gatekeep::DecisionAuditId::new("decision-1")?,
        occurred_at: OffsetDateTime::UNIX_EPOCH,
        request_id: Some(RequestId::new("request-1")?),
        anchor: PolicyAnchor {
            policy_id: PolicyId::new("case-read")?,
            policy_hash: PolicyHash::new("hash")?,
        },
        effect: EffectKind::Deny,
        obligations: vec![ObligationId::new("record-denial")?],
        consulted: vec![(missing.clone(), Presence::Absent)],
        decisive: decisive.clone(),
        denial_reason: Some(reason),
        trace: Trace {
            consulted: vec![(missing, Presence::Absent)],
            decisive,
        },
        binding: Some(TenantBinding::TrustedService(
            TrustedServiceBinding::new(TenantId::new("tenant-1")?, "gatekeep-sqlx-tests").map_err(
                |_| GatekeepError::InvalidPolicyRecord {
                    reason: "test binding construction",
                },
            )?,
        )),
        fact_resolution: Some(
            FactResolutionEvidence::from_resolution(
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
            })?,
        ),
        tenant: TenantId::new("tenant-1")?,
        principal: SubjectRef::new("user", "mari")?,
        subjects: BTreeMap::from([(SubjectSlot::new("case")?, SubjectRef::new("case", "123")?)]),
        locale: gatekeep::Locale::new("en-US")?,
    })
}
