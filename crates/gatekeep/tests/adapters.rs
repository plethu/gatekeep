//! Adapter-boundary tests.

#![cfg(feature = "test")]

use std::collections::BTreeMap;

use gatekeep::{
    AuditEntry, AuditSink, Context, EffectKind, InMemoryAuditSink, KnownFacts, Locale,
    PolicyAnchor, PolicyHash, PolicyId, SubjectRef, SubjectSlot, TenantId, condition, evaluate,
    policy,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
enum Access {
    Denied,
    Full,
}

impl gatekeep::Lattice for Access {
    fn meet(&self, other: &Self) -> Self {
        std::cmp::min(*self, *other)
    }

    fn join(&self, other: &Self) -> Self {
        std::cmp::max(*self, *other)
    }

    fn top() -> Self {
        Self::Full
    }

    fn bottom() -> Self {
        Self::Denied
    }
}

#[tokio::test]
async fn in_memory_audit_sink_records_cloned_entries() -> Result<(), TestError> {
    let sink = InMemoryAuditSink::default();
    let decision = evaluate(
        &policy::grant(Access::Full, condition::always()),
        &KnownFacts::new(),
    );
    let entry = AuditEntry {
        request_id: None,
        anchor: PolicyAnchor {
            policy_id: PolicyId::new("case_read")?,
            policy_hash: PolicyHash::new("hash")?,
        },
        effect: EffectKind::from(&decision),
        obligations: decision.obligations.clone(),
        consulted: decision.trace.consulted.clone(),
        decisive: decision.to_trace()?.decisive,
        denial_reason: decision.denial_reason()?,
        trace: decision.to_trace()?,
        tenant: Some(TenantId::new("tenant_a")?),
        principal: Some(SubjectRef::new("user", "mari")?),
        subjects: BTreeMap::new(),
    };

    sink.record(&entry).await?;
    let entries = sink.entries()?;

    assert_eq!(entries, vec![entry]);
    Ok(())
}

#[test]
fn context_subject_slots_round_trip() -> Result<(), TestError> {
    let context = Context {
        tenant: TenantId::new("tenant_a")?,
        principal: SubjectRef::new("user", "mari")?,
        subjects: BTreeMap::from([(
            SubjectSlot::new("skill-version")?,
            SubjectRef::new("skill", "std/core@0.1.0")?,
        )]),
        locale: Locale::new("en-US")?,
        request_id: None,
    };

    let encoded = serde_json::to_string(&context)?;
    let decoded = serde_json::from_str::<Context>(&encoded)?;

    assert_eq!(decoded, context);
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Gatekeep(#[from] gatekeep::GatekeepError),
    #[error(transparent)]
    Trace(#[from] gatekeep::TraceError),
    #[error(transparent)]
    Audit(#[from] gatekeep::InMemoryAuditError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
