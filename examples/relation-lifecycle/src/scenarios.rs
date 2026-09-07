use crate::{admission, integrity};
use keepsake::{ActorRef, ApplyKeepsake, CommandContext, ObservationTime, RevokeBySubject};
use time::{Duration, OffsetDateTime};

use crate::{
    Result,
    store::{BLOCK, Consumer, Outcome, pair},
};

pub async fn run(consumer: &Consumer) -> Result<()> {
    let now = OffsetDateTime::UNIX_EPOCH + Duration::days(20_000);
    let mut tx = consumer.pool.begin().await?;
    assert!(
        consumer
            .admit(
                &mut tx,
                "already-admitted",
                ObservationTime::Authoritative(now),
                false
            )
            .await?
    );
    tx.commit().await?;
    let initial_events = consumer.count("events").await?;
    let block = ApplyKeepsake::new(
        consumer.tenant.clone(),
        pair("alice", "bob")?,
        BLOCK,
        now,
        context()?,
    );
    let mut tx = consumer.pool.begin().await?;
    assert_eq!(
        consumer.apply(&mut tx, &block).await?,
        Outcome::Applied(block.id)
    );
    tx.rollback().await?;
    assert_eq!(consumer.count("events").await?, initial_events);
    assert_eq!(consumer.count("actions").await?, 0);
    assert_eq!(consumer.count("relations").await?, 0);

    let mut tx = consumer.pool.begin().await?;
    assert_eq!(
        consumer.apply(&mut tx, &block).await?,
        Outcome::Applied(block.id)
    );
    tx.commit().await?;
    assert_eq!(consumer.count("events").await?, initial_events + 3);
    assert_eq!(consumer.count("actions").await?, 1);
    assert_eq!(consumer.count("relations").await?, 1);
    // Treat the first commit response as lost. Authenticate and revalidate current
    // authority before exposing its stable application receipt.
    let mut tx = consumer.pool.begin().await?;
    assert_eq!(
        consumer.apply(&mut tx, &block).await?,
        Outcome::Replayed(block.id)
    );
    tx.commit().await?;
    assert_eq!(consumer.count("events").await?, initial_events + 3);
    let mut conflict = block.clone();
    conflict
        .metadata
        .insert("different".into(), "private-value".into());
    let mut tx = consumer.pool.begin().await?;
    let error = consumer
        .apply(&mut tx, &conflict)
        .await
        .err()
        .ok_or("conflicting command unexpectedly succeeded")?;
    assert!(!error.to_string().contains("private-value"));
    tx.rollback().await?;

    let mut tx = consumer.pool.begin().await?;
    assert!(
        !consumer
            .admit(
                &mut tx,
                "denied-future",
                ObservationTime::Authoritative(now),
                true
            )
            .await?
    );
    tx.commit().await?; // Explicit audit-only denial commit.
    assert_eq!(consumer.count("sessions").await?, 1);
    assert_eq!(consumer.count("events").await?, initial_events + 4);
    assert_eq!(consumer.count("actions").await?, 1);
    revoked_authority(consumer, &block).await?;
    reapply(consumer, &block).await?;
    admission::reverse_block(consumer, now).await?;
    admission::timed(consumer, now).await?;
    integrity::mandatory_intent_failure(consumer).await?;
    integrity::absent_race(consumer).await?;
    integrity::unavailable_storage(consumer).await?;
    integrity::restart_preserves_delivered_history(consumer).await?;
    Ok(())
}

pub fn context() -> Result<CommandContext> {
    Ok(CommandContext::new(ActorRef::new("account", "operator")?))
}

async fn revoked_authority(consumer: &Consumer, command: &ApplyKeepsake) -> Result<()> {
    sqlx::query("UPDATE application_authorities SET enabled=false WHERE tenant_id=$1 AND principal='operator'")
        .bind(consumer.tenant.as_str()).execute(&consumer.pool).await?;
    let mut tx = consumer.pool.begin().await?;
    assert_eq!(consumer.apply(&mut tx, command).await?, Outcome::Denied);
    tx.rollback().await?;
    sqlx::query("UPDATE application_authorities SET enabled=true WHERE tenant_id=$1 AND principal='operator'")
        .bind(consumer.tenant.as_str()).execute(&consumer.pool).await?;
    Ok(())
}

async fn reapply(consumer: &Consumer, block: &ApplyKeepsake) -> Result<()> {
    let scoped = consumer.relations.for_tenant(consumer.tenant.clone());
    let mut tx = consumer.pool.begin().await?;
    let observed = scoped
        .observe_in_transaction(&mut tx, &block.subject, BLOCK)
        .await?;
    let revoke = RevokeBySubject::new(
        consumer.tenant.clone(),
        block.subject.clone(),
        BLOCK,
        block.at,
        context()?,
    );
    assert_eq!(
        scoped
            .revoke_if_current_in_transaction(&mut tx, &observed, &revoke)
            .await?
            .keepsake_id,
        block.id
    );
    tx.commit().await?;
    // Exact library retry must remain the original outcome after revocation.
    let mut tx = consumer.pool.begin().await?;
    let retry = scoped.apply_in_transaction(&mut tx, block).await?;
    assert!(retry.replayed);
    assert_eq!(retry.keepsake.id(), block.id);
    tx.commit().await?;
    let fresh = ApplyKeepsake::new(
        consumer.tenant.clone(),
        block.subject.clone(),
        BLOCK,
        block.at,
        context()?,
    );
    let mut tx = consumer.pool.begin().await?;
    consumer.apply(&mut tx, &fresh).await?;
    tx.commit().await?;
    let mut tx = consumer.pool.begin().await?;
    assert!(
        scoped
            .revalidate_in_transaction(&mut tx, &observed)
            .await
            .is_err()
    );
    tx.rollback().await?;
    let mut tx = consumer.pool.begin().await?;
    let current = scoped
        .observe_in_transaction(&mut tx, &block.subject, BLOCK)
        .await?;
    assert_eq!(
        current
            .active_relation()?
            .ok_or("missing re-applied relation")?
            .keepsake()
            .id(),
        fresh.id
    );
    scoped
        .revoke_if_current_in_transaction(
            &mut tx,
            &current,
            &RevokeBySubject::new(
                consumer.tenant.clone(),
                block.subject.clone(),
                BLOCK,
                block.at,
                context()?,
            ),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}
