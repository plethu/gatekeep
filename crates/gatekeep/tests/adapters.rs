//! Adapter-boundary tests.

#![cfg(feature = "test")]

use gatekeep::{
    AuditEntry, AuditSink, EffectKind, InMemoryAuditSink, KnownFacts, PolicyAnchor, PolicyHash,
    PolicyId, SubjectRef, TenantId, condition, evaluate, policy,
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

#[test]
fn in_memory_audit_sink_records_cloned_entries() -> Result<(), TestError> {
    let sink = InMemoryAuditSink::default();
    let decision = evaluate(
        &policy::grant(Access::Full, condition::always()),
        &KnownFacts::new(),
    );
    let entry = AuditEntry {
        anchor: PolicyAnchor {
            policy_id: PolicyId::new("case_read")?,
            policy_hash: PolicyHash::new("hash")?,
        },
        trace: decision.to_trace()?,
        effect: EffectKind::from(&decision),
        obligations: decision.obligations,
        tenant: Some(TenantId::new("tenant_a")?),
        principal: Some(SubjectRef::new("user", "mari")?),
    };

    sink.record(&entry)?;
    let entries = sink.entries()?;

    assert_eq!(entries, vec![entry]);
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
}
