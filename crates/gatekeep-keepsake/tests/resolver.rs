//! Keepsake resolver integration tests.

mod support;

use std::collections::BTreeMap;

use gatekeep::{FactResolver, Presence, ResolveError, SubjectSlot};
use gatekeep_keepsake::{
    FactBinding, KeepsakeResolveError, KeepsakeResolver, PrincipalSubjectMapper, QueryPresence,
    tenant_scoped_subject,
};
use keepsake::RelationSpec;
use support::{
    PaidPlan, PaidPlanRelation, ResourceMember, ResourceMemberRelation, StoreError, TestResult,
    UnboundRelation, context, context_with_subjects, fact_id, principal_resolver_for, resolver_for,
    resolver_for_tenant, subject,
};

#[tokio::test]
async fn decision_resolution_maps_active_relations_to_known_facts() -> TestResult<()> {
    let principal = subject("user", "u_1")?;
    let resolver = resolver_for(&principal)?
        .with_relation_spec::<PaidPlan, PaidPlanRelation>()?
        .with_relation_spec::<ResourceMember, ResourceMemberRelation>()?;

    let facts = resolver
        .resolve_for_decision(
            &[fact_id("paid_plan")?, fact_id("resource_member")?],
            &context("tenant_1", principal)?,
        )
        .await?;

    assert_eq!(facts.presence(&fact_id("paid_plan")?), Presence::Present);
    assert_eq!(
        facts.presence(&fact_id("resource_member")?),
        Presence::Absent
    );
    assert_eq!(
        resolver.source().requested_relation_ids()?,
        vec![vec![PaidPlanRelation::ID, ResourceMemberRelation::ID]]
    );
    Ok(())
}

#[tokio::test]
async fn decision_resolution_can_bind_distinct_subject_slots() -> TestResult<()> {
    let skill_slot = SubjectSlot::new("skill-version")?;
    let source_slot = SubjectSlot::new("purlieu-source")?;
    let skill = subject("skill-version", "std/core@0.1.0")?;
    let source = subject("purlieu-source", "external/std")?;
    let resolver = KeepsakeResolver::new(
        support::FakeSource::default()
            .with_active_for_paid_plan(keepsake::SubjectRef::new(skill.kind(), skill.id())?)?
            .with_active_for_resource_member(keepsake::SubjectRef::new(
                source.kind(),
                source.id(),
            )?)?,
    )
    .with_binding(FactBinding::for_relation_spec_on_subject::<
        PaidPlan,
        PaidPlanRelation,
    >(skill_slot.clone())?)
    .with_binding(FactBinding::for_relation_spec_on_subject::<
        ResourceMember,
        ResourceMemberRelation,
    >(source_slot.clone())?);
    let cx = context_with_subjects(
        "tenant_1",
        subject("user", "u_1")?,
        BTreeMap::from([(skill_slot, skill), (source_slot, source)]),
    )?;

    let facts = resolver
        .resolve_for_decision(&[fact_id("paid_plan")?, fact_id("resource_member")?], &cx)
        .await?;

    assert_eq!(facts.presence(&fact_id("paid_plan")?), Presence::Present);
    assert_eq!(
        facts.presence(&fact_id("resource_member")?),
        Presence::Present
    );
    let mut requested = resolver.source().requested_relation_ids()?;
    requested.sort();
    assert_eq!(
        requested,
        vec![vec![PaidPlanRelation::ID], vec![ResourceMemberRelation::ID]]
    );
    Ok(())
}

#[tokio::test]
async fn tenant_scoped_mapping_keeps_equal_principals_separate() -> TestResult<()> {
    let principal = subject("user", "u_1")?;
    let resolver = resolver_for(&principal)?
        .with_relation_spec::<PaidPlan, PaidPlanRelation>()?
        .with_relation_spec::<ResourceMember, ResourceMemberRelation>()?;

    let tenant_two = resolver
        .resolve_for_decision(&[fact_id("paid_plan")?], &context("tenant_2", principal)?)
        .await?;

    assert_eq!(
        tenant_two.presence(&fact_id("paid_plan")?),
        Presence::Absent
    );
    Ok(())
}

#[tokio::test]
async fn tenant_scoped_mapping_does_not_collide_on_colons() -> TestResult<()> {
    let seeded_principal = subject("c", "u_1")?;
    let resolver = resolver_for_tenant("a:b", &seeded_principal)?
        .with_relation_spec::<PaidPlan, PaidPlanRelation>()?;

    let colliding_join_shape = resolver
        .resolve_for_decision(
            &[fact_id("paid_plan")?],
            &context("a", subject("b:c", "u_1")?)?,
        )
        .await?;

    assert_eq!(
        colliding_join_shape.presence(&fact_id("paid_plan")?),
        Presence::Absent
    );
    Ok(())
}

#[tokio::test]
async fn principal_only_mapping_is_available_for_existing_subject_schemes() -> TestResult<()> {
    let principal = subject("user", "u_1")?;
    let resolver = principal_resolver_for(&principal)?
        .map_subjects(PrincipalSubjectMapper)
        .with_relation_spec::<PaidPlan, PaidPlanRelation>()?;

    let facts = resolver
        .resolve_for_decision(&[fact_id("paid_plan")?], &context("tenant_2", principal)?)
        .await?;

    assert_eq!(facts.presence(&fact_id("paid_plan")?), Presence::Present);
    Ok(())
}

#[tokio::test]
async fn query_resolution_can_mix_known_and_deferred_facts() -> TestResult<()> {
    let principal = subject("user", "u_1")?;
    let resolver = resolver_for(&principal)?
        .with_relation_spec::<PaidPlan, PaidPlanRelation>()?
        .with_relation_spec_query_presence::<ResourceMember, ResourceMemberRelation>(
            QueryPresence::Defer,
        )?;

    let facts = resolver
        .resolve_for_query(
            &[fact_id("paid_plan")?, fact_id("resource_member")?],
            &context("tenant_1", principal)?,
        )
        .await?;

    assert_eq!(facts.presence(&fact_id("paid_plan")?), Presence::Present);
    assert_eq!(
        facts.presence(&fact_id("resource_member")?),
        Presence::Unknown
    );
    assert_eq!(
        resolver.source().requested_relation_ids()?,
        vec![vec![PaidPlanRelation::ID]]
    );
    Ok(())
}

#[tokio::test]
async fn missing_fact_reports_resolve_error_without_source_lookup() -> TestResult<()> {
    let principal = subject("user", "u_1")?;
    let resolver = resolver_for(&principal)?;

    let result = resolver
        .resolve_for_decision(&[fact_id("paid_plan")?], &context("tenant_1", principal)?)
        .await;

    assert!(matches!(
        result,
        Err(ResolveError::MissingFact(fact)) if fact.as_str() == "paid_plan"
    ));
    assert_eq!(resolver.source().calls(), 0);
    Ok(())
}

#[tokio::test]
async fn missing_subject_slot_reports_context_error_without_source_lookup() -> TestResult<()> {
    let slot = SubjectSlot::new("resource")?;
    let principal = subject("user", "u_1")?;
    let resolver =
        resolver_for(&principal)?.with_binding(FactBinding::for_relation_spec_on_subject::<
            PaidPlan,
            PaidPlanRelation,
        >(slot.clone())?);

    let result = resolver
        .resolve_for_decision(&[fact_id("paid_plan")?], &context("tenant_1", principal)?)
        .await;

    assert!(matches!(
        result,
        Err(ResolveError::MissingSubject { fact, slot: missing })
            if fact.as_str() == "paid_plan" && missing == slot
    ));
    assert_eq!(resolver.source().calls(), 0);
    Ok(())
}

#[tokio::test]
async fn source_errors_are_preserved_as_backend_errors() -> TestResult<()> {
    let resolver = KeepsakeResolver::new(support::FakeSource::failing())
        .with_binding(FactBinding::for_relation_spec::<PaidPlan, PaidPlanRelation>()?);

    let result = resolver
        .resolve_for_decision(
            &[fact_id("paid_plan")?],
            &context("tenant_1", subject("user", "u_1")?)?,
        )
        .await;

    assert!(matches!(
        result,
        Err(ResolveError::Backend(KeepsakeResolveError::Source(
            StoreError::Failed
        )))
    ));
    Ok(())
}

#[test]
fn manual_bindings_can_defer_runtime_fact_ids() -> TestResult<()> {
    let binding = FactBinding::with_query_presence(
        fact_id("runtime_fact")?,
        UnboundRelation::ID,
        QueryPresence::Defer,
    );

    assert_eq!(binding.fact().as_str(), "runtime_fact");
    assert_eq!(binding.relation_id(), UnboundRelation::ID);
    assert_eq!(binding.query_presence(), QueryPresence::Defer);
    Ok(())
}

#[test]
fn typed_binding_aliases_express_query_behavior() -> TestResult<()> {
    let resolved = FactBinding::resolve_relation::<PaidPlan, PaidPlanRelation>()?;
    let deferred = FactBinding::defer_relation::<ResourceMember, ResourceMemberRelation>()?;

    assert_eq!(resolved.query_presence(), QueryPresence::Resolve);
    assert_eq!(deferred.query_presence(), QueryPresence::Defer);
    Ok(())
}

#[test]
fn tenant_scoped_subject_helper_matches_default_mapper() -> TestResult<()> {
    let principal = subject("user", "u_1")?;
    let context = context("tenant_1", principal)?;

    assert_eq!(
        tenant_scoped_subject(&context)?,
        support::tenant_subject("tenant_1", &subject("user", "u_1")?)?
    );
    Ok(())
}
