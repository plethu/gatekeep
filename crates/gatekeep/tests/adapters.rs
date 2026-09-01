//! Adapter-boundary tests.

#![cfg(feature = "test")]

use std::collections::BTreeMap;

use gatekeep::{
    ApplicationVerifiedTenantBinding, AuditEntry, AuditSink, BindingAuthority, BindingProvenance,
    Context, EffectKind, EvidenceDigest, FactResolution, FactResolutionEvidence, InMemoryAuditSink,
    KnownFacts, Locale, PolicyAnchor, PolicyHash, PolicyId, SubjectRef, SubjectSlot, TenantBinding,
    TenantBindingEvidence, TenantId, TrustedServiceBinding, condition, evaluate, policy,
};

#[test]
fn fact_resolution_rejects_invalid_or_expired_freshness() -> Result<(), TestError> {
    let observed_at = time::OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2);
    let fresh_until = observed_at - time::Duration::hours(1);
    let source = BindingProvenance::new("test.facts")?;
    let metadata = gatekeep::FactResolutionMetadata::new(source, None, Some(fresh_until));

    assert!(matches!(
        FactResolution::new(KnownFacts::new(), Some(metadata), observed_at),
        Err(gatekeep::FactResolutionError::InvalidFreshnessWindow { .. })
    ));

    let fresh_until = observed_at + time::Duration::hours(1);
    let metadata = gatekeep::FactResolutionMetadata::new(
        BindingProvenance::new("test.facts")?,
        None,
        Some(fresh_until),
    );
    let resolution = FactResolution::new(KnownFacts::new(), Some(metadata), observed_at)?;
    assert!(matches!(
        resolution.validate_at(fresh_until),
        Err(gatekeep::FactResolutionError::Expired { .. })
    ));

    let observed_at = time::OffsetDateTime::UNIX_EPOCH + time::Duration::hours(3);
    let received_at = observed_at - time::Duration::minutes(1);
    let resolution = FactResolution::new(KnownFacts::new(), None, observed_at)?;
    assert!(matches!(
        resolution.validate_at(received_at),
        Err(gatekeep::FactResolutionError::ObservedInFuture { .. })
    ));
    Ok(())
}

#[test]
fn fact_resolution_serde_rejects_invalid_freshness() -> Result<(), TestError> {
    let observed_at = time::OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2);
    let source = BindingProvenance::new("test.facts")?;
    let mut value = serde_json::to_value(FactResolution::new(
        KnownFacts::new(),
        Some(gatekeep::FactResolutionMetadata::new(source, None, None)),
        observed_at,
    )?)?;
    value["metadata"]["fresh_until"] =
        serde_json::to_value(observed_at - time::Duration::hours(1))?;
    assert!(serde_json::from_value::<FactResolution<KnownFacts>>(value).is_err());
    Ok(())
}

#[test]
fn fact_resolution_evidence_serde_rejects_invalid_freshness() -> Result<(), TestError> {
    let observed_at = time::OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2);
    let source = BindingProvenance::new("test.facts")?;
    let resolution = FactResolution::new(
        KnownFacts::new(),
        Some(gatekeep::FactResolutionMetadata::new(
            source,
            None,
            Some(observed_at + time::Duration::hours(1)),
        )),
        observed_at,
    )?;
    let mut value = serde_json::to_value(FactResolutionEvidence::from_resolution(&resolution)?)?;
    value["fresh_until"] = serde_json::to_value(observed_at - time::Duration::hours(1))?;

    assert!(serde_json::from_value::<FactResolutionEvidence>(value).is_err());
    Ok(())
}

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
    let mut entry = AuditEntry {
        decision_audit_id: gatekeep::DecisionAuditId::new("decision-1")?,
        occurred_at: time::OffsetDateTime::UNIX_EPOCH,
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
        binding: Some(TenantBinding::ApplicationVerified(
            ApplicationVerifiedTenantBinding::new(
                TenantId::new("tenant_a")?,
                TenantBindingEvidence::new(
                    BindingAuthority::Issuer {
                        issuer: BindingProvenance::new("test")?,
                        key_id: None,
                    },
                    time::OffsetDateTime::UNIX_EPOCH,
                    EvidenceDigest::new([0; 32]),
                ),
                time::OffsetDateTime::UNIX_EPOCH,
                time::OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
            )?,
        )),
        fact_resolution: Some(FactResolutionEvidence::from_resolution(
            &FactResolution::new(KnownFacts::new(), None, time::OffsetDateTime::UNIX_EPOCH)?,
        )?),
        tenant: TenantId::new("tenant_a")?,
        principal: SubjectRef::new("user", "mari")?,
        subjects: BTreeMap::new(),
        locale: Locale::new("en-US")?,
    };

    sink.record(&entry).await?;
    let entries = sink.entries()?;

    assert_eq!(entries, vec![entry.clone()]);

    entry.effect = EffectKind::Deny;
    assert!(matches!(
        entry.validate_current(),
        Err(gatekeep::AuditEntryError::EffectTraceMismatch)
    ));
    Ok(())
}

#[tokio::test]
async fn in_memory_audit_sink_rejects_legacy_entry_representation() -> Result<(), TestError> {
    let sink = InMemoryAuditSink::default();
    let decision = evaluate(
        &policy::grant(Access::Full, condition::always()),
        &KnownFacts::new(),
    );
    let mut entry = AuditEntry {
        decision_audit_id: gatekeep::DecisionAuditId::new("decision-legacy-check")?,
        occurred_at: time::OffsetDateTime::UNIX_EPOCH,
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
        binding: Some(TenantBinding::TrustedService(TrustedServiceBinding::new(
            TenantId::new("tenant_a")?,
            "test",
        )?)),
        fact_resolution: Some(FactResolutionEvidence::from_resolution(
            &FactResolution::new(KnownFacts::new(), None, time::OffsetDateTime::UNIX_EPOCH)?,
        )?),
        tenant: TenantId::new("tenant_a")?,
        principal: SubjectRef::new("user", "mari")?,
        subjects: BTreeMap::new(),
        locale: Locale::new("en-US")?,
    };
    entry.binding = None;

    assert!(matches!(
        sink.record(&entry).await,
        Err(gatekeep::InMemoryAuditError::InvalidEntry(
            gatekeep::AuditEntryError::MissingBinding
        ))
    ));
    entry.binding = Some(TenantBinding::TrustedService(TrustedServiceBinding::new(
        TenantId::new("tenant_b")?,
        "test",
    )?));
    assert!(matches!(
        sink.record(&entry).await,
        Err(gatekeep::InMemoryAuditError::InvalidEntry(
            gatekeep::AuditEntryError::BindingTenantMismatch
        ))
    ));
    Ok(())
}

#[test]
fn context_subject_slots_round_trip() -> Result<(), TestError> {
    let now = time::OffsetDateTime::UNIX_EPOCH;
    let binding = ApplicationVerifiedTenantBinding::new(
        TenantId::new("tenant_a")?,
        TenantBindingEvidence::new(
            BindingAuthority::Issuer {
                issuer: BindingProvenance::new("test")?,
                key_id: None,
            },
            now - time::Duration::hours(1),
            EvidenceDigest::new([0; 32]),
        ),
        now,
        now + time::Duration::hours(1),
    )?;
    let context = Context::new_at(
        TenantId::new("tenant_a")?,
        TenantBinding::ApplicationVerified(binding),
        SubjectRef::new("user", "mari")?,
        Locale::new("en-US")?,
        now,
    )?
    .with_subject(
        SubjectSlot::new("skill-version")?,
        SubjectRef::new("skill", "std/core@0.1.0")?,
    );

    let encoded = serde_json::to_string(&context)?;
    assert!(encoded.contains("tenant_a"));
    assert!(encoded.contains("skill-version"));
    Ok(())
}

#[test]
fn context_rejects_mismatched_tenant_binding() -> Result<(), TestError> {
    let now = time::OffsetDateTime::UNIX_EPOCH;
    let binding = ApplicationVerifiedTenantBinding::new(
        TenantId::new("tenant_a")?,
        TenantBindingEvidence::new(
            BindingAuthority::Issuer {
                issuer: BindingProvenance::new("test")?,
                key_id: None,
            },
            now,
            EvidenceDigest::new([0; 32]),
        ),
        now,
        now + time::Duration::hours(1),
    )?;

    let result = Context::new_at(
        TenantId::new("tenant_b")?,
        TenantBinding::ApplicationVerified(binding),
        SubjectRef::new("user", "mari")?,
        Locale::new("en-US")?,
        now,
    );

    assert!(matches!(
        result,
        Err(gatekeep::ContextError::TenantMismatch { .. })
    ));
    Ok(())
}

#[test]
fn application_binding_rejects_not_yet_valid_and_stale_windows() -> Result<(), TestError> {
    let now = time::OffsetDateTime::UNIX_EPOCH;
    let future = ApplicationVerifiedTenantBinding::new(
        TenantId::new("tenant_a")?,
        TenantBindingEvidence::new(
            BindingAuthority::Issuer {
                issuer: BindingProvenance::new("test")?,
                key_id: None,
            },
            now,
            EvidenceDigest::new([0; 32]),
        ),
        now + time::Duration::minutes(1),
        now + time::Duration::minutes(2),
    )?;
    let stale = ApplicationVerifiedTenantBinding::new(
        TenantId::new("tenant_a")?,
        TenantBindingEvidence::new(
            BindingAuthority::Issuer {
                issuer: BindingProvenance::new("test")?,
                key_id: None,
            },
            now - time::Duration::minutes(2),
            EvidenceDigest::new([0; 32]),
        ),
        now - time::Duration::minutes(2),
        now - time::Duration::minutes(1),
    )?;

    assert!(matches!(
        future.validate_at(now),
        Err(gatekeep::TenantBindingError::NotYetValid { .. })
    ));
    assert!(matches!(
        stale.validate_at(now),
        Err(gatekeep::TenantBindingError::Stale { .. })
    ));

    let future_auth = ApplicationVerifiedTenantBinding::new(
        TenantId::new("tenant_a")?,
        TenantBindingEvidence::new(
            BindingAuthority::Issuer {
                issuer: BindingProvenance::new("test")?,
                key_id: None,
            },
            now + time::Duration::minutes(1),
            EvidenceDigest::new([0; 32]),
        ),
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    )?;
    assert!(matches!(
        future_auth.validate_at(now),
        Err(gatekeep::TenantBindingError::AuthenticatedInFuture { .. })
    ));
    Ok(())
}

#[test]
fn trusted_service_binding_is_explicitly_named() -> Result<(), TestError> {
    let binding = TrustedServiceBinding::new(TenantId::new("tenant_a")?, "billing-worker")?;
    let context = Context::from_trusted_service(
        binding,
        SubjectRef::new("service", "billing-worker")?,
        Locale::new("en-US")?,
    )?;

    assert!(matches!(
        context.binding(),
        TenantBinding::TrustedService(_)
    ));
    Ok(())
}

#[test]
fn tenant_id_uses_dovecote_string_contract() {
    assert!(matches!(
        TenantId::new(""),
        Err(gatekeep::GatekeepError::EmptyIdentifier { field: "tenant_id" })
    ));
    assert!(matches!(
        TenantId::new("   "),
        Err(gatekeep::GatekeepError::EmptyIdentifier { field: "tenant_id" })
    ));
    assert!(matches!(
        TenantId::new("x".repeat(gatekeep::MAX_TENANT_ID_BYTES + 1)),
        Err(gatekeep::GatekeepError::TenantIdTooLong { .. })
    ));
    assert!(TenantId::new("é".repeat(127)).is_ok());
    assert!(matches!(
        TenantId::new("é".repeat(128)),
        Err(gatekeep::GatekeepError::TenantIdTooLong { .. })
    ));
    assert!(matches!(
        TenantId::new("line\nbreak"),
        Err(gatekeep::GatekeepError::TenantIdControlCharacter { .. })
    ));
    assert!(matches!(
        TenantId::new("noncharacter\u{FDD0}"),
        Err(gatekeep::GatekeepError::TenantIdNoncharacter { .. })
    ));
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Gatekeep(#[from] gatekeep::GatekeepError),
    #[error(transparent)]
    Context(#[from] gatekeep::ContextError),
    #[error(transparent)]
    Binding(#[from] gatekeep::TenantBindingError),
    #[error(transparent)]
    Trace(#[from] gatekeep::TraceError),
    #[error(transparent)]
    FactResolutionEvidence(#[from] gatekeep::FactResolutionEvidenceError),
    #[error(transparent)]
    FactResolution(#[from] gatekeep::FactResolutionError),
    #[error(transparent)]
    Audit(#[from] gatekeep::InMemoryAuditError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
