//! Effective facts share Keepsake's policy and explicit observation time.
use gatekeep::{FactId, Presence};
use gatekeep_keepsake::{EffectiveFactError, KeepsakeRelationTarget};
use keepsake::{
    ActiveRelation, ActorRef, ApplyKeepsake, CommandContext, EffectiveRelationError, ExpiryPolicy,
    Keepsake, ObservationTime, RelationDefinition, RelationKey, SubjectRef, TenantId,
};
use std::error::Error as StdError;
use std::{collections::BTreeMap, slice};
use time::OffsetDateTime;

type TestResult = Result<(), Box<dyn StdError>>;

#[test]
fn deadline_and_each_scope_are_enforced() -> TestResult {
    let at = OffsetDateTime::UNIX_EPOCH;
    let definition = RelationDefinition::new(
        TenantId::new("tenant")?,
        keepsake::RelationId::nil(),
        RelationKey::new("block", "social")?,
        true,
        ExpiryPolicy::ManualOnly,
    )?;
    let command = ApplyKeepsake::new(
        definition.tenant_id.clone(),
        SubjectRef::new("directed-pair", "1:a1:b")?,
        definition.id,
        at,
        CommandContext::new(ActorRef::new("account", "a")?),
    )
    .with_expiry(ExpiryPolicy::At {
        timestamp: at + time::Duration::hours(1),
    });
    let active = ActiveRelation::new(Keepsake::from_apply(&command, &definition)?, definition)?;
    let target = KeepsakeRelationTarget {
        tenant_id: command.tenant_id.clone(),
        fact: FactId::new("blocked")?,
        subject: command.subject,
        relation_id: command.relation_id,
        subject_slot: None,
    };
    let snapshot = keepsake::RelationSnapshot::new(
        target.tenant_id.clone(),
        target.subject.clone(),
        target.relation_id,
        Some(active),
    )?;
    let absent = keepsake::RelationSnapshot::new(
        target.tenant_id.clone(),
        target.subject.clone(),
        target.relation_id,
        None,
    )?;
    assert_eq!(
        target.effective_presence(ObservationTime::Authoritative(at), &snapshot, None)?,
        Presence::Present
    );
    assert_eq!(
        target.effective_presence(
            ObservationTime::Authoritative(at + time::Duration::hours(1)),
            &snapshot,
            None
        )?,
        Presence::Absent
    );
    assert_eq!(
        target.effective_presence(ObservationTime::Stale, &absent, None),
        Err(EffectiveFactError::Evidence(
            EffectiveRelationError::StaleTime
        ))
    );
    let mut other = target.clone();
    other.tenant_id = TenantId::new("other")?;
    assert_eq!(
        other.effective_presence(ObservationTime::Authoritative(at), &snapshot, None),
        Err(EffectiveFactError::ScopeMismatch)
    );
    assert_eq!(
        other.effective_presence(ObservationTime::Authoritative(at), &absent, None),
        Err(EffectiveFactError::ScopeMismatch)
    );
    other = target.clone();
    other.subject = SubjectRef::new("directed-pair", "1:b1:a")?;
    assert_eq!(
        other.effective_presence(ObservationTime::Authoritative(at), &snapshot, None),
        Err(EffectiveFactError::ScopeMismatch)
    );
    other = target;
    other.relation_id = keepsake::RelationId::from_u128(1);
    assert_eq!(
        other.effective_presence(ObservationTime::Authoritative(at), &snapshot, None),
        Err(EffectiveFactError::ScopeMismatch)
    );
    Ok(())
}

#[tokio::test]
async fn resolver_uses_deadline_without_reconciliation_and_bounds_cached_facts() -> TestResult {
    use gatekeep::{Context, FactResolver, Locale, TrustedServiceBinding};
    use gatekeep_keepsake::{FactBinding, KeepsakeResolver, PrincipalSubjectMapper};
    use keepsake::InMemoryActiveRelations;
    let at = OffsetDateTime::UNIX_EPOCH;
    let deadline = at + time::Duration::hours(1);
    let definition = RelationDefinition::new(
        TenantId::new("tenant")?,
        keepsake::RelationId::nil(),
        RelationKey::new("restriction", "admission")?,
        true,
        ExpiryPolicy::At {
            timestamp: deadline,
        },
    )?;
    let subject = SubjectRef::new("user", "a")?;
    let assignment = Keepsake::applied(
        keepsake::KeepsakeId::nil(),
        subject,
        &definition,
        at,
        BTreeMap::new(),
    )?;
    let source = InMemoryActiveRelations::new([ActiveRelation::new(assignment, definition)?]);
    let fact = FactId::new("restricted")?;
    let resolver = KeepsakeResolver::with_subject_mapper(source, PrincipalSubjectMapper)
        .with_binding(FactBinding::new(fact.clone(), keepsake::RelationId::nil()));
    let context = Context::from_trusted_service(
        TrustedServiceBinding::new(gatekeep::TenantId::new("tenant")?, "test")?,
        gatekeep::SubjectRef::new("user", "a")?,
        Locale::new("en-US")?,
    )?;
    let facts = resolver
        .resolve_for_decision(slice::from_ref(&fact), &context, &move || at)
        .await?;
    assert_eq!(facts.facts().presence(&fact), Presence::Present);
    assert_eq!(
        facts
            .metadata()
            .and_then(gatekeep::FactResolutionMetadata::fresh_until),
        Some(deadline)
    );
    let facts = resolver
        .resolve_for_decision(slice::from_ref(&fact), &context, &move || deadline)
        .await?;
    assert_eq!(facts.facts().presence(&fact), Presence::Absent);
    assert_eq!(facts.observed_at(), deadline);
    Ok(())
}

#[test]
fn missing_fulfillment_is_unavailable_until_scoped_evidence_is_supplied() -> TestResult {
    let at = OffsetDateTime::UNIX_EPOCH;
    let definition = RelationDefinition::new(
        TenantId::new("tenant")?,
        keepsake::RelationId::nil(),
        RelationKey::new("restriction", "admission")?,
        true,
        ExpiryPolicy::WhenFulfilled {
            policy: keepsake::FulfillmentPolicy::CounterAtLeast {
                key: "tasks".into(),
                threshold: 1,
            },
        },
    )?;
    let target = KeepsakeRelationTarget {
        tenant_id: definition.tenant_id.clone(),
        subject: SubjectRef::new("user", "a")?,
        relation_id: definition.id,
        fact: FactId::new("restricted")?,
        subject_slot: None,
    };
    let assignment = Keepsake::applied(
        keepsake::KeepsakeId::nil(),
        target.subject.clone(),
        &definition,
        at,
        BTreeMap::new(),
    )?;
    let snapshot = keepsake::RelationSnapshot::new(
        target.tenant_id.clone(),
        target.subject.clone(),
        target.relation_id,
        Some(ActiveRelation::new(assignment, definition)?),
    )?;
    assert_eq!(
        target.effective_presence(ObservationTime::Authoritative(at), &snapshot, None),
        Err(EffectiveFactError::Evidence(
            EffectiveRelationError::FulfillmentMissing
        ))
    );
    let evidence = keepsake::FulfillmentEvidence::new(
        target.tenant_id.clone(),
        keepsake::KeepsakeId::nil(),
        keepsake::FulfillmentSnapshot::empty().with_counter("tasks", 1),
    );
    assert_eq!(
        target.effective_presence(
            ObservationTime::Authoritative(at),
            &snapshot,
            Some(&evidence)
        )?,
        Presence::Absent
    );
    let other_tenant = keepsake::FulfillmentEvidence::new(
        TenantId::new("other")?,
        evidence.keepsake_id(),
        evidence.snapshot().clone(),
    );
    let old_assignment = keepsake::FulfillmentEvidence::new(
        target.tenant_id.clone(),
        keepsake::KeepsakeId::from_u128(1),
        evidence.snapshot().clone(),
    );
    for substituted in [other_tenant, old_assignment] {
        assert_eq!(
            target.effective_presence(
                ObservationTime::Authoritative(at),
                &snapshot,
                Some(&substituted)
            ),
            Err(EffectiveFactError::FulfillmentScopeMismatch)
        );
    }

    let absent = keepsake::RelationSnapshot::new(
        target.tenant_id.clone(),
        target.subject.clone(),
        target.relation_id,
        None,
    )?;
    assert_eq!(
        target.effective_presence(ObservationTime::Authoritative(at), &absent, Some(&evidence)),
        Err(EffectiveFactError::FulfillmentScopeMismatch)
    );
    Ok(())
}
