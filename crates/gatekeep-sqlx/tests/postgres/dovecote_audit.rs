use std::error::Error;
use std::sync::OnceLock;

use dovecote::{
    ContentType, EventData, EventId, EventSource, EventType, Limit, NewEvent, StreamName,
};
use gatekeep_sqlx::{DecisionAuditConfig, PgDovecoteAudit, decode_decision_audit};
use sqlx::{PgPool, postgres::PgPoolOptions, query_as, query_scalar, raw_sql};
use time::OffsetDateTime;

#[path = "../dovecote_audit_support/mod.rs"]
mod audit_support;

type TestResult<T> = Result<T, Box<dyn Error>>;

static TEST_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn serialize_live_test() -> tokio::sync::MutexGuard<'static, ()> {
    TEST_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

#[tokio::test]
#[ignore = "requires docker postgres; run `mise exec -- just test-db-postgres`"]
async fn postgres_dovecote_audit_maps_replays_and_decodes_the_complete_event() -> TestResult<()> {
    let _serial = serialize_live_test().await;
    let pool = pool().await?;
    prepare_database(&pool).await?;
    let sink = PgDovecoteAudit::new(pool.clone(), "https://audit.example.test/gatekeep")?;
    let entry = audit_support::audit_entry()?;

    let first = sink.record_decision_audit(&entry).await?;
    let second = sink.record_decision_audit(&entry).await?;
    assert!(matches!(first, dovecote::EnqueueOutcome::Enqueued { .. }));
    assert!(matches!(
        second,
        dovecote::EnqueueOutcome::AlreadyEnqueued { .. }
    ));

    let row: (
        String,
        String,
        String,
        String,
        Option<OffsetDateTime>,
        String,
        String,
        Vec<u8>,
        String,
    ) = query_as(
        "SELECT stream, event_id, source, event_type, occurred_at, datacontenttype, data_kind, data, extensions FROM dovecote_events",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.0, "gatekeep-audit");
    assert_eq!(row.1, "gatekeep-audit-decision-1");
    assert_eq!(row.2, "https://audit.example.test/gatekeep");
    assert_eq!(row.3, "gatekeep.decision_audit_recorded");
    assert_eq!(row.4, Some(entry.occurred_at()));
    assert_eq!(row.5, "application/json");
    assert_eq!(row.6, "json");
    assert_eq!(row.7, serde_json::to_vec(&entry)?);
    assert_eq!(row.8, "{}");

    let delivery: (String, i64, Option<OffsetDateTime>) =
        query_as("SELECT state, attempts, delivered_at FROM dovecote_deliveries")
            .fetch_one(&pool)
            .await?;
    assert_eq!(delivery.0, "pending");
    assert_eq!(delivery.1, 0);
    assert_eq!(delivery.2, None);

    let adapter = dovecote_sqlx_postgres::PostgresDovecote::new(pool.clone());
    let page = adapter.admin().page(None, Limit::new(10)?).await?;
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].event().id().as_str(), "gatekeep-audit-decision-1");
    assert_eq!(page[0].delivery().state(), dovecote::DeliveryState::Pending);
    assert_eq!(decode_decision_audit(sink.config(), &page[0])?, entry);
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker postgres; run `mise exec -- just test-db-postgres`"]
async fn postgres_dovecote_audit_rolls_back_with_the_caller_transaction() -> TestResult<()> {
    let _serial = serialize_live_test().await;
    let pool = pool().await?;
    prepare_database(&pool).await?;
    let sink = PgDovecoteAudit::new(pool.clone(), "https://audit.example.test/gatekeep")?;
    let mut transaction = pool.begin().await?;

    sink.record_decision_audit_in_transaction(&mut transaction, &audit_support::audit_entry()?)
        .await?;
    transaction.rollback().await?;

    assert_eq!(
        query_scalar::<_, i64>("SELECT count(*) FROM dovecote_events")
            .fetch_one(&pool)
            .await?,
        0
    );
    assert_eq!(
        query_scalar::<_, i64>("SELECT count(*) FROM dovecote_deliveries")
            .fetch_one(&pool)
            .await?,
        0
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker postgres; run `mise exec -- just test-db-postgres`"]
async fn postgres_dovecote_audit_rejects_changed_immutable_content() -> TestResult<()> {
    let _serial = serialize_live_test().await;
    let pool = pool().await?;
    prepare_database(&pool).await?;
    let sink = PgDovecoteAudit::new(pool.clone(), "https://audit.example.test/gatekeep")?;
    let entry = audit_support::audit_entry()?;
    sink.record_decision_audit(&entry).await?;

    let mut changed = serde_json::to_value(&entry)?;
    changed["request_id"] = serde_json::Value::String("request-2".to_owned());
    let changed: gatekeep::AuditEntry = serde_json::from_value(changed)?;
    let Err(error) = sink.record_decision_audit(&changed).await else {
        return Err("changed content unexpectedly succeeded".into());
    };
    assert!(matches!(
        error,
        gatekeep_sqlx::PgDovecoteAuditError::Dovecote(
            dovecote_sqlx_postgres::EnqueueError::IdempotencyConflict { .. }
        )
    ));
    assert_eq!(
        query_scalar::<_, i64>("SELECT count(*) FROM dovecote_events")
            .fetch_one(&pool)
            .await?,
        1
    );
    Ok(())
}

#[test]
fn postgres_current_decoder_rejects_reserved_legacy_identity() -> TestResult<()> {
    let config = DecisionAuditConfig::new("https://audit.example.test/gatekeep")?;
    let entry = audit_support::audit_entry()?;
    let mut payload = serde_json::to_value(&entry)?;
    payload["decision_audit_id"] = serde_json::Value::String("legacy-outbox-42".to_owned());
    let event = NewEvent::builder(
        StreamName::new("gatekeep-audit")?,
        EventId::new("gatekeep-audit-legacy-outbox-42")?,
        EventSource::new("https://audit.example.test/gatekeep")?,
        EventType::new("gatekeep.decision_audit_recorded")?,
    )
    .time(entry.occurred_at())
    .datacontenttype(ContentType::new("application/json")?)
    .data(EventData::json(serde_json::to_vec(&payload)?)?)
    .build()?
    .into_stored()?;

    let page = dovecote::PagedEvent::new(
        dovecote::TenantId::new("tenant-1")?,
        dovecote::RowId::new(1)?,
        event,
        OffsetDateTime::UNIX_EPOCH,
        dovecote::DeliverySnapshot::pending(
            OffsetDateTime::UNIX_EPOCH,
            dovecote::AttemptCount::new(0)?,
            None,
        )?,
    )?;
    assert!(decode_decision_audit(&config, &page).is_err());
    Ok(())
}

async fn pool() -> Result<PgPool, Box<dyn Error>> {
    let database_url = std::env::var("DATABASE_URL")?;
    gatekeep_sqlx::validate_database_url_for_backend::<gatekeep_sqlx::PostgresBackend>(
        &database_url,
    )?;
    Ok(PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?)
}

async fn prepare_database(pool: &PgPool) -> Result<(), Box<dyn Error>> {
    let installed: bool = query_scalar(
        "SELECT to_regclass('dovecote_schema') IS NOT NULL AND to_regclass('dovecote_events') IS NOT NULL AND to_regclass('dovecote_deliveries') IS NOT NULL",
    )
    .fetch_one(pool)
    .await?;
    if !installed {
        raw_sql(dovecote_sqlx_postgres::MIGRATIONS[0].sql())
            .execute(pool)
            .await?;
    }
    dovecote_sqlx_postgres::check_schema(pool).await?;
    sqlx::query("DELETE FROM dovecote_deliveries")
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM dovecote_events")
        .execute(pool)
        .await?;
    Ok(())
}
