use std::collections::BTreeMap;

use gatekeep::{
    AuditEntry, DenialReason, DenyShape, EffectKind, FactId, GatekeepError, ObligationId, ParamKey,
    PolicyAnchor, PolicyHash, PolicyId, Presence, ReasonCode, ReasonValue, RequestId, SubjectRef,
    SubjectSlot, TenantId, Trace, TraceClause,
};

pub fn audit_entry() -> Result<AuditEntry, GatekeepError> {
    let missing = FactId::new("case_owner")?;
    let mut params = BTreeMap::new();
    params.insert(
        ParamKey::new("missing_fact")?,
        ReasonValue::Fact(missing.clone()),
    );
    params.insert(
        ParamKey::new("case_id")?,
        ReasonValue::Str("case-123".to_owned()),
    );
    let denial_reason = DenialReason {
        code: ReasonCode::new("case-read-denied")?,
        params,
        shape: DenyShape::Forbidden,
    };

    let decisive = TraceClause::Deny {
        denied: None,
        unsatisfied: vec![missing.clone()],
        label: None,
        reason: Some(denial_reason.code.clone()),
        shape: DenyShape::Forbidden,
    };
    Ok(AuditEntry {
        request_id: Some(RequestId::new("req-1")?),
        anchor: PolicyAnchor {
            policy_id: PolicyId::new("case_read")?,
            policy_hash: PolicyHash::new("hash")?,
        },
        effect: EffectKind::Deny,
        obligations: vec![ObligationId::new("redact")?],
        consulted: vec![
            (FactId::new("staff")?, Presence::Present),
            (missing, Presence::Absent),
        ],
        decisive: decisive.clone(),
        denial_reason: Some(denial_reason),
        trace: Trace {
            consulted: vec![
                (FactId::new("staff")?, Presence::Present),
                (FactId::new("case_owner")?, Presence::Absent),
            ],
            decisive,
        },
        tenant: Some(TenantId::new("tenant-a")?),
        principal: Some(SubjectRef::new("user", "mari")?),
        subjects: BTreeMap::from([(
            SubjectSlot::new("case")?,
            SubjectRef::new("case", "case-123")?,
        )]),
    })
}
