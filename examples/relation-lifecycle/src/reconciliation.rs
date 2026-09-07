//! Delayed durable expiry and its application notification share one commit.
use dovecote::{EventId, EventSource, EventType, NewEvent, StreamName};
use gatekeep::KnownFacts;
use gatekeep::policy::permit;
use keepsake::{ApplyKeepsake, ExpiryPolicy, SubjectRef};
use sqlx::{Postgres, Transaction};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    Result,
    policy::{self, DecisionContext},
    scenarios::context,
    store::{Consumer, Outcome, RESTRICTION},
};

pub async fn verify(consumer: &Consumer, at: OffsetDateTime, assignment: Uuid) -> Result<()> {
    let before = consumer.count("events").await?;
    let replacement = ApplyKeepsake::new(
        consumer.tenant.clone(),
        SubjectRef::new("account", "alice")?,
        RESTRICTION,
        at,
        context()?,
    )
    .with_expiry(ExpiryPolicy::At {
        timestamp: at + Duration::minutes(1),
    });
    let scoped = consumer.relations.for_tenant(consumer.tenant.clone());
    let mut tx = consumer.pool.begin().await?;
    let observed = scoped
        .observe_in_transaction(&mut tx, &replacement.subject, RESTRICTION)
        .await?;
    // Effective expiry does not release persisted uniqueness or renew an assignment.
    let duplicate = scoped
        .apply_if_current_in_transaction(&mut tx, &observed, &replacement)
        .await?;
    assert!(duplicate.duplicate_prevented);
    assert_eq!(duplicate.keepsake.id(), assignment);
    tx.rollback().await?;

    let mut tx = consumer.pool.begin().await?;
    assert_eq!(stage(consumer, &mut tx, at).await?, vec![assignment]);
    assert_eq!(
        consumer.apply(&mut tx, &replacement).await?,
        Outcome::Applied(replacement.id)
    );
    tx.rollback().await?;
    assert_eq!(consumer.count("events").await?, before);
    let mut tx = consumer.pool.begin().await?;
    assert_eq!(stage(consumer, &mut tx, at).await?, vec![assignment]);
    assert_eq!(
        consumer.apply(&mut tx, &replacement).await?,
        Outcome::Applied(replacement.id)
    );
    let renewed = scoped
        .observe_in_transaction(&mut tx, &replacement.subject, RESTRICTION)
        .await?;
    assert_ne!(renewed, observed);
    assert_eq!(
        renewed
            .active_relation()?
            .ok_or("renewed assignment missing")?
            .keepsake()
            .id(),
        replacement.id
    );
    tx.commit().await?;
    assert_eq!(consumer.count("events").await?, before + 6);
    let mut tx = consumer.pool.begin().await?;
    assert!(stage(consumer, &mut tx, at).await?.is_empty());
    tx.commit().await?;
    assert_eq!(consumer.count("events").await?, before + 6);
    Ok(())
}

async fn stage(
    consumer: &Consumer,
    tx: &mut Transaction<'_, Postgres>,
    at: OffsetDateTime,
) -> Result<Vec<Uuid>> {
    if !consumer.authenticate(tx, "operator").await? {
        return Err("current expiry authority unavailable".into());
    }

    let policy = permit(());
    let facts = KnownFacts::new();
    let decision = gatekeep::evaluate(&policy, &facts);
    if !decision.is_permit() {
        return Err("expiry policy denied".into());
    }

    let scoped = consumer.relations.for_tenant(consumer.tenant.clone());
    let expired = scoped.expire_due_timed_in_transaction(tx, at, 10).await?;
    for id in &expired {
        let event_id = format!("expired-{id}");
        let context = DecisionContext {
            tenant: consumer.tenant.as_str(),
            principal: "operator",
            target: "alice",
            id: &event_id,
            at,
        };
        consumer
            .audit
            .record_decision_audit_in_transaction(
                tx,
                &policy::audit(&context, &policy, facts.clone(), &decision)?,
            )
            .await?;
        let event = NewEvent::builder(
            StreamName::new("application-notifications")?,
            EventId::new(event_id)?,
            EventSource::new("https://example.invalid/relation-consumer")?,
            EventType::new("application.relation-expired")?,
        )
        .time(at)
        .build()?;
        consumer
            .outbox
            .for_tenant(dovecote::TenantId::new(consumer.tenant.as_str())?)
            .enqueue(tx, event)
            .await?;
    }

    Ok(expired)
}
