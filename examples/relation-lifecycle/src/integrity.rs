//! Failure and concurrency evidence on real `PostgreSQL` transactions.
use dovecote::{EventId, EventSource, EventType, NewEvent, StreamName};
use keepsake::{ActorRef, ApplyKeepsake, CommandContext, ObservationTime};
use keepsake_sqlx::KeepsakeRepository;
use std::{collections::BTreeSet, time::Duration as StdDuration};
use time::{Duration, OffsetDateTime};
use tokio::{sync::oneshot, time::timeout};

use crate::{
    Result,
    store::{BLOCK, Consumer, pair},
};

pub async fn mandatory_intent_failure(consumer: &Consumer) -> Result<()> {
    let at = OffsetDateTime::UNIX_EPOCH + Duration::days(20_001);
    let command = ApplyKeepsake::new(
        consumer.tenant.clone(),
        pair("charlie", "dana")?,
        BLOCK,
        at,
        CommandContext::new(ActorRef::new("account", "operator")?),
    );
    let conflicting = NewEvent::builder(
        StreamName::new("application-notifications")?,
        EventId::new(command.audit_id.as_uuid().to_string())?,
        EventSource::new("https://example.invalid/relation-consumer")?,
        EventType::new("application.conflicting-intent")?,
    )
    .time(at)
    .build()?;
    let mut tx = consumer.pool.begin().await?;
    consumer
        .outbox
        .for_tenant(dovecote::TenantId::new(consumer.tenant.as_str())?)
        .enqueue(&mut tx, conflicting)
        .await?;
    tx.commit().await?;
    let before = (
        consumer.count("events").await?,
        consumer.count("actions").await?,
        consumer.count("relations").await?,
    );
    let mut tx = consumer.pool.begin().await?;
    assert!(consumer.apply(&mut tx, &command).await.is_err());
    tx.rollback().await?;
    assert_eq!(
        (
            consumer.count("events").await?,
            consumer.count("actions").await?,
            consumer.count("relations").await?
        ),
        before
    );
    Ok(())
}

pub async fn absent_race(consumer: &Consumer) -> Result<()> {
    let at = OffsetDateTime::UNIX_EPOCH + Duration::days(20_002);
    let scoped = consumer.relations.for_tenant(consumer.tenant.clone());
    let subject = pair("erin", "frank")?;
    let mut tx = consumer.pool.begin().await?;
    let absent = scoped
        .observe_in_transaction(&mut tx, &subject, BLOCK)
        .await?;
    assert!(absent.active_relation()?.is_none());
    let command = ApplyKeepsake::new(
        consumer.tenant.clone(),
        subject,
        BLOCK,
        at,
        CommandContext::new(ActorRef::new("account", "operator")?),
    );
    let pool = consumer.pool.clone();
    let tenant = consumer.tenant.clone();
    let (started, ready) = oneshot::channel();
    let mut writer = tokio::spawn(async move {
        let repo = KeepsakeRepository::new(pool, "https://example.invalid/keepsake-consumer")?;
        let _ = started.send(());
        repo.for_tenant(tenant).apply(&command).await
    });
    ready.await?;
    assert!(
        timeout(StdDuration::from_millis(100), &mut writer)
            .await
            .is_err()
    );
    scoped.revalidate_in_transaction(&mut tx, &absent).await?;
    sqlx::query("INSERT INTO application_sessions (tenant_id, session_id) VALUES ($1,'before-racing-block')")
        .bind(consumer.tenant.as_str()).execute(&mut *tx).await?;
    tx.commit().await?;
    writer.await??;
    let mut tx = consumer.pool.begin().await?;
    assert!(
        scoped
            .revalidate_in_transaction(&mut tx, &absent)
            .await
            .is_err()
    );
    tx.rollback().await?;
    Ok(())
}

pub async fn unavailable_storage(consumer: &Consumer) -> Result<()> {
    let mut tx = consumer.pool.begin().await?;
    // A failed transaction cannot manufacture an absent relation fact.
    assert!(sqlx::query("SELECT 1/0").execute(&mut *tx).await.is_err());
    assert!(
        consumer
            .admit(
                &mut tx,
                "storage-unavailable",
                ObservationTime::Authoritative(OffsetDateTime::UNIX_EPOCH),
                false
            )
            .await
            .is_err()
    );
    tx.rollback().await?;
    Ok(())
}

pub async fn restart_preserves_delivered_history(consumer: &Consumer) -> Result<()> {
    let tenant = dovecote::TenantId::new(consumer.tenant.as_str())?;
    let outbox = consumer.outbox.for_tenant(tenant.clone());
    let claims = outbox
        .claim(
            dovecote::WorkerId::new("synthetic-worker")?,
            dovecote::Lease::new(StdDuration::from_mins(1))?,
            dovecote::Limit::new(100)?,
        )
        .await?;
    assert!(!claims.is_empty());
    let before = outbox.page(None, dovecote::Limit::new(100)?).await?;
    // A real receiver deduplicates (tenant, source, id) before its own effect.
    let mut received = BTreeSet::new();
    for claim in &claims {
        let key = (claim.event().source().as_str(), claim.event().id().as_str());
        assert!(received.insert(key));
        assert!(!received.insert(key)); // Simulated duplicate delivery at the receiver.
        outbox.ack(claim.row_id(), claim.claim_token()).await?;
    }

    let pool = sqlx::PgPool::connect_with((*consumer.pool.connect_options()).clone()).await?;
    let repo = KeepsakeRepository::new(pool.clone(), "https://example.invalid/keepsake-consumer")?;
    repo.migrate().await?;
    repo.check_schema().await?;
    let restarted = dovecote_sqlx_postgres::PostgresDovecote::new(pool).for_tenant(tenant);
    let after = restarted.page(None, dovecote::Limit::new(100)?).await?;
    assert_eq!(
        before
            .iter()
            .map(dovecote::PagedEvent::event)
            .collect::<Vec<_>>(),
        after
            .iter()
            .map(dovecote::PagedEvent::event)
            .collect::<Vec<_>>()
    );
    assert!(
        restarted
            .claim(
                dovecote::WorkerId::new("restarted-worker")?,
                dovecote::Lease::new(StdDuration::from_mins(1))?,
                dovecote::Limit::new(100)?
            )
            .await?
            .is_empty()
    );
    Ok(())
}
