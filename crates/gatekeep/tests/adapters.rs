//! Adapter-boundary tests.

#![cfg(feature = "test")]

use std::collections::BTreeMap;

use gatekeep::{
    ApplicationVerifiedTenantBinding, AuditEntry, AuditSink, BindingAuthority, BindingProvenance,
    Context, DecisionAuditOccurrence, EffectKind, EvidenceDigest, FactResolution,
    FactResolutionEvidence, InMemoryAuditSink, KnownFacts, LegacyAuditEntry, LegacyPolicyAnchor,
    Locale, PolicyAnchor, PolicyHash, PolicyId, SubjectRef, SubjectSlot, TenantBinding,
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
    let entry = current_entry("decision-1", &decision)?;

    sink.record(&entry).await?;
    let entries = sink.entries()?;

    assert_eq!(entries, vec![entry.clone()]);

    let mut invalid = serde_json::to_value(&entry)?;
    invalid["effect"] = serde_json::Value::String("Deny".to_owned());
    assert!(serde_json::from_value::<AuditEntry>(invalid).is_err());
    Ok(())
}

#[tokio::test]
async fn in_memory_audit_sink_rejects_legacy_entry_representation() -> Result<(), TestError> {
    let decision = evaluate(
        &policy::grant(Access::Full, condition::always()),
        &KnownFacts::new(),
    );
    let current = current_entry("decision-legacy-check", &decision)?;
    let value = serde_json::to_value(&current)?;
    let legacy = LegacyAuditEntry {
        decision_audit_id: "legacy-outbox-42".to_owned(),
        occurred_at: time::OffsetDateTime::UNIX_EPOCH,
        request_id: None,
        anchor: LegacyPolicyAnchor {
            policy_id: PolicyId::new("case_read")?,
            policy_hash: PolicyHash::new("hash")?,
        },
        effect: current.effect(),
        obligations: current.obligations().to_vec(),
        consulted: current.consulted().to_vec(),
        decisive: current.decisive().clone(),
        denial_reason: current.denial_reason().cloned(),
        trace: current.trace().clone(),
        binding: None,
        fact_resolution: None,
        tenant: TenantId::new("tenant_a")?,
        principal: SubjectRef::new("user", "mari")?,
        subjects: BTreeMap::new(),
        locale: Locale::new("en-US")?,
    };
    assert!(serde_json::from_value::<AuditEntry>(serde_json::to_value(legacy)?).is_err());
    assert!(value.get("schema_version").is_some());
    Ok(())
}

#[test]
fn current_audit_schema_and_policy_hash_versions_are_required() -> Result<(), TestError> {
    let decision = evaluate(
        &policy::grant(Access::Full, condition::always()),
        &KnownFacts::new(),
    );
    let entry = current_entry("decision-versioned", &decision)?;

    let mut missing_schema = serde_json::to_value(&entry)?;
    missing_schema
        .as_object_mut()
        .ok_or(TestError::ExpectedObject)?
        .remove("schema_version");
    assert!(serde_json::from_value::<AuditEntry>(missing_schema).is_err());

    let mut unknown_schema = serde_json::to_value(&entry)?;
    unknown_schema["schema_version"] = serde_json::json!(99);
    assert!(serde_json::from_value::<AuditEntry>(unknown_schema).is_err());

    let mut unknown_hash = serde_json::to_value(&entry)?;
    unknown_hash["anchor"]["policy_hash_version"] = serde_json::json!(99);
    assert!(serde_json::from_value::<AuditEntry>(unknown_hash).is_err());

    let mut missing_hash = serde_json::to_value(&entry)?;
    missing_hash["anchor"]
        .as_object_mut()
        .ok_or(TestError::ExpectedObject)?
        .remove("policy_hash_version");
    assert!(serde_json::from_value::<AuditEntry>(missing_hash).is_err());

    assert_eq!(
        serde_json::to_string(entry.anchor())?,
        r#"{"policy_id":"case_read","policy_hash":"hash","policy_hash_version":1}"#
    );
    Ok(())
}

#[test]
fn current_audit_occurrence_is_validated_during_deserialization() -> Result<(), TestError> {
    let decision = evaluate(
        &policy::grant(Access::Full, condition::always()),
        &KnownFacts::new(),
    );
    let entry = current_entry("decision-occurrence-validation", &decision)?;

    let mut submicrosecond = serde_json::to_value(&entry)?;
    let submicrosecond_at = time::OffsetDateTime::UNIX_EPOCH + time::Duration::nanoseconds(1_234);
    submicrosecond["occurred_at"] = serde_json::to_value(submicrosecond_at)?;
    let normalized: AuditEntry = serde_json::from_value(submicrosecond)?;
    assert_eq!(
        normalized.occurred_at(),
        time::OffsetDateTime::UNIX_EPOCH + time::Duration::nanoseconds(1_000)
    );
    assert_eq!(normalized.occurred_at().nanosecond() % 1_000, 0);

    let mut malformed = serde_json::to_value(&entry)?;
    malformed["occurred_at"] = serde_json::json!("not-an-offset-date-time");
    assert!(serde_json::from_value::<AuditEntry>(malformed).is_err());

    let mut out_of_range = serde_json::to_value(&entry)?;
    let before_epoch = time::OffsetDateTime::UNIX_EPOCH - time::Duration::seconds(1);
    out_of_range["occurred_at"] = serde_json::to_value(before_epoch)?;
    assert!(serde_json::from_value::<AuditEntry>(out_of_range).is_err());

    let mut contradictory = serde_json::to_value(&entry)?;
    contradictory["effect"] = serde_json::json!("deny");
    assert!(serde_json::from_value::<AuditEntry>(contradictory).is_err());
    Ok(())
}

#[test]
fn legacy_audit_requires_explicit_import() -> Result<(), TestError> {
    let decision = evaluate(
        &policy::grant(Access::Full, condition::always()),
        &KnownFacts::new(),
    );
    let entry = current_entry("decision-legacy-import", &decision)?;
    let mut payload = serde_json::to_value(&entry)?;
    payload
        .as_object_mut()
        .ok_or(TestError::ExpectedObject)?
        .remove("schema_version");
    payload["anchor"]
        .as_object_mut()
        .ok_or(TestError::ExpectedObject)?
        .remove("policy_hash_version");
    payload["binding"] = serde_json::Value::Null;
    payload["fact_resolution"] = serde_json::Value::Null;
    let legacy: LegacyAuditEntry = serde_json::from_value(payload)?;
    assert!(serde_json::from_value::<AuditEntry>(serde_json::to_value(&legacy)?).is_err());

    let imported = legacy.into_current(
        entry.occurrence(),
        gatekeep::POLICY_HASH_FORMAT_VERSION,
        entry.binding().clone(),
        entry.fact_resolution().clone(),
    )?;
    assert_eq!(
        imported.schema_version(),
        gatekeep::AUDIT_ENTRY_SCHEMA_VERSION
    );
    assert_eq!(imported.decision_audit_id(), entry.decision_audit_id());
    Ok(())
}

fn current_entry(
    decision_id: &str,
    decision: &gatekeep::Decision<Access>,
) -> Result<AuditEntry, TestError> {
    let now = time::OffsetDateTime::UNIX_EPOCH;
    let binding = TenantBinding::ApplicationVerified(ApplicationVerifiedTenantBinding::new(
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
    )?);
    let occurrence =
        DecisionAuditOccurrence::new(gatekeep::DecisionAuditId::new(decision_id)?, now)?;
    let trace = decision.to_trace()?;
    Ok(AuditEntry::new(
        occurrence,
        None,
        PolicyAnchor::new(PolicyId::new("case_read")?, PolicyHash::new("hash")?),
        EffectKind::from(decision),
        decision.obligations.clone(),
        trace.consulted.clone(),
        trace.decisive.clone(),
        decision.denial_reason()?,
        trace,
        binding,
        FactResolutionEvidence::from_resolution(&FactResolution::new(
            KnownFacts::new(),
            None,
            now,
        )?)?,
        TenantId::new("tenant_a")?,
        SubjectRef::new("user", "mari")?,
        BTreeMap::new(),
        Locale::new("en-US")?,
    )?)
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
    AuditEntry(#[from] gatekeep::AuditEntryError),
    #[error(transparent)]
    Occurrence(#[from] gatekeep::DecisionAuditOccurrenceError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("expected a JSON object")]
    ExpectedObject,
}
