//! New admission policy checks direction and effective deadlines.
use crate::reconciliation;
use crate::{
    Result,
    scenarios::context,
    store::{BLOCK, Consumer, RESTRICTION, pair},
};
use keepsake::{
    ApplyKeepsake, ExpiryPolicy, LifecycleState, ObservationTime, RevokeBySubject, SubjectRef,
};
use time::{Duration, OffsetDateTime};

pub async fn timed(consumer: &Consumer, now: OffsetDateTime) -> Result<()> {
    let deadline = now + Duration::minutes(1);
    let restriction = ApplyKeepsake::new(
        consumer.tenant.clone(),
        SubjectRef::new("account", "alice")?,
        RESTRICTION,
        now,
        context()?,
    )
    .with_expiry(ExpiryPolicy::At {
        timestamp: deadline,
    });
    let mut tx = consumer.pool.begin().await?;
    consumer.apply(&mut tx, &restriction).await?;
    tx.commit().await?;
    let mut tx = consumer.pool.begin().await?;
    assert!(
        !consumer
            .admit(
                &mut tx,
                "before-deadline",
                ObservationTime::Authoritative(deadline - Duration::microseconds(1)),
                false
            )
            .await?
    );
    tx.rollback().await?;
    let mut tx = consumer.pool.begin().await?;
    assert!(
        consumer
            .admit(
                &mut tx,
                "at-deadline",
                ObservationTime::Authoritative(deadline),
                false
            )
            .await?
    );
    tx.commit().await?;
    assert_eq!(consumer.count("sessions").await?, 2);
    let scoped = consumer.relations.for_tenant(consumer.tenant.clone());
    let mut tx = consumer.pool.begin().await?;
    let current = scoped
        .observe_in_transaction(&mut tx, &restriction.subject, RESTRICTION)
        .await?;
    assert_eq!(
        current
            .active_relation()?
            .ok_or("persisted applied row missing")?
            .keepsake()
            .state(),
        LifecycleState::Applied
    );
    tx.rollback().await?; // No reconciliation worker ever ran.
    for time in [
        ObservationTime::Unknown,
        ObservationTime::Stale,
        ObservationTime::checked(now, deadline),
    ] {
        let mut tx = consumer.pool.begin().await?;
        assert!(
            consumer
                .admit(&mut tx, "unavailable-time", time, false)
                .await
                .is_err()
        );
        tx.rollback().await?;
    }

    reconciliation::verify(consumer, deadline, restriction.id).await?;
    Ok(())
}

pub async fn reverse_block(consumer: &Consumer, now: OffsetDateTime) -> Result<()> {
    let command = ApplyKeepsake::new(
        consumer.tenant.clone(),
        pair("bob", "alice")?,
        BLOCK,
        now,
        context()?,
    );
    let mut tx = consumer.pool.begin().await?;
    consumer.apply(&mut tx, &command).await?;
    tx.commit().await?;
    let sessions = consumer.count("sessions").await?;
    let mut tx = consumer.pool.begin().await?;
    assert!(
        !consumer
            .admit(
                &mut tx,
                "reverse-denied",
                ObservationTime::Authoritative(now),
                false
            )
            .await?
    );
    tx.rollback().await?;
    assert_eq!(consumer.count("sessions").await?, sessions);
    let scoped = consumer.relations.for_tenant(consumer.tenant.clone());
    let mut tx = consumer.pool.begin().await?;
    let observed = scoped
        .observe_in_transaction(&mut tx, &command.subject, BLOCK)
        .await?;
    scoped
        .revoke_if_current_in_transaction(
            &mut tx,
            &observed,
            &RevokeBySubject::new(
                consumer.tenant.clone(),
                command.subject,
                BLOCK,
                now,
                context()?,
            ),
        )
        .await?;
    tx.commit().await?;
    Ok(())
}
