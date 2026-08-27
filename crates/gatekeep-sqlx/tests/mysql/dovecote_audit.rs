use std::error::Error;
use std::sync::OnceLock;

use dovecote::{
    ContentType, EventData, EventId, EventSource, EventType, Limit, NewEvent, StreamName,
};
use gatekeep::{DecisionAuditId, RequestId};
use gatekeep_sqlx::{DecisionAuditConfig, MySqlDovecoteAudit, decode_decision_audit};
use sqlx::{MySqlPool, mysql::MySqlPoolOptions, query_as, query_scalar, raw_sql};
use time::PrimitiveDateTime;

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
#[ignore = "requires docker mysql; run `mise exec -- just test-db-mysql`"]
async fn mysql_dovecote_audit_maps_replays_and_decodes_the_complete_event() -> TestResult<()> {
    let _serial = serialize_live_test().await;
    let pool = pool().await?;
    prepare_database(&pool).await?;
    let sink = MySqlDovecoteAudit::new(pool.clone(), "https://audit.example.test/gatekeep")?;
    let entry = audit_support::audit_entry()?;

    let first = sink.record_decision_audit(&entry).await?;
    let second = sink.record_decision_audit(&entry).await?;
    assert!(matches!(first, dovecote::EnqueueOutcome::Enqueued { .. }));
    assert!(matches!(
        second,
        dovecote::EnqueueOutcome::AlreadyEnqueued { .. }
    ));

    let row: AuditEventRow = query_as(
        "SELECT stream, event_id, source, event_type, occurred_at, datacontenttype, data_kind, data, extensions FROM dovecote_events",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(checked_text(row.stream, "stream")?, "gatekeep-audit");
    assert_eq!(
        checked_text(row.event_id, "event id")?,
        "gatekeep-audit-decision-1"
    );
    assert_eq!(
        checked_text(row.source, "source")?,
        "https://audit.example.test/gatekeep"
    );
    assert_eq!(
        checked_text(row.event_type, "event type")?,
        "gatekeep.decision_audit_recorded"
    );
    assert_eq!(
        row.occurred_at.map(PrimitiveDateTime::assume_utc),
        Some(entry.occurred_at)
    );
    assert_eq!(
        checked_text(row.datacontenttype, "content type")?,
        "application/json"
    );
    assert_eq!(checked_text(row.data_kind, "data kind")?, "json");
    assert_eq!(row.data, serde_json::to_vec(&entry)?);
    assert_eq!(checked_text(row.extensions, "extensions")?, "{}");

    let delivery: (Vec<u8>, i64) = query_as("SELECT state, attempts FROM dovecote_deliveries")
        .fetch_one(&pool)
        .await?;
    assert_eq!(checked_text(delivery.0, "delivery state")?, "pending");
    assert_eq!(delivery.1, 0);

    let adapter = dovecote_sqlx_mysql::MySqlDovecote::new(pool.clone());
    let page = adapter.page(None, Limit::new(10)?).await?;
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].event().id().as_str(), "gatekeep-audit-decision-1");
    assert_eq!(page[0].delivery().state(), dovecote::DeliveryState::Pending);
    assert_eq!(
        decode_decision_audit(sink.config(), page[0].event())?,
        entry
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker mysql; run `mise exec -- just test-db-mysql`"]
async fn mysql_dovecote_audit_rolls_back_with_the_caller_transaction() -> TestResult<()> {
    let _serial = serialize_live_test().await;
    let pool = pool().await?;
    prepare_database(&pool).await?;
    let sink = MySqlDovecoteAudit::new(pool.clone(), "https://audit.example.test/gatekeep")?;
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
#[ignore = "requires docker mysql; run `mise exec -- just test-db-mysql`"]
async fn mysql_dovecote_audit_rejects_changed_immutable_content() -> TestResult<()> {
    let _serial = serialize_live_test().await;
    let pool = pool().await?;
    prepare_database(&pool).await?;
    let sink = MySqlDovecoteAudit::new(pool.clone(), "https://audit.example.test/gatekeep")?;
    let entry = audit_support::audit_entry()?;
    sink.record_decision_audit(&entry).await?;

    let mut changed = entry;
    changed.request_id = Some(RequestId::new("request-2")?);
    let Err(error) = sink.record_decision_audit(&changed).await else {
        return Err("changed content unexpectedly succeeded".into());
    };
    assert!(matches!(
        error,
        gatekeep_sqlx::MySqlDovecoteAuditError::Dovecote(
            dovecote_sqlx_mysql::EnqueueError::IdempotencyConflict { .. }
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
fn mysql_history_decode_accepts_reserved_legacy_identity_only_in_history() -> TestResult<()> {
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
    .time(entry.occurred_at)
    .datacontenttype(ContentType::new("application/json")?)
    .data(EventData::json(serde_json::to_vec(&payload)?)?)
    .build()?
    .into_stored()?;

    let imported = decode_decision_audit(&config, &event)?;
    assert_eq!(imported.decision_audit_id.as_str(), "legacy-outbox-42");
    assert_eq!(serde_json::to_value(&imported)?, payload);
    assert!(DecisionAuditId::new("legacy-outbox-42").is_err());
    Ok(())
}

fn checked_text(value: Vec<u8>, field: &'static str) -> Result<String, Box<dyn Error>> {
    String::from_utf8(value).map_err(|error| format!("stored {field} is not UTF-8: {error}").into())
}

#[derive(Debug, sqlx::FromRow)]
struct AuditEventRow {
    stream: Vec<u8>,
    event_id: Vec<u8>,
    source: Vec<u8>,
    event_type: Vec<u8>,
    occurred_at: Option<PrimitiveDateTime>,
    datacontenttype: Vec<u8>,
    data_kind: Vec<u8>,
    data: Vec<u8>,
    extensions: Vec<u8>,
}

async fn pool() -> Result<MySqlPool, Box<dyn Error>> {
    let database_url = std::env::var("MYSQL_DATABASE_URL")?;
    gatekeep_sqlx::validate_database_url_for_backend::<gatekeep_sqlx::MySqlBackend>(&database_url)?;
    Ok(MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?)
}

async fn prepare_database(pool: &MySqlPool) -> Result<(), Box<dyn Error>> {
    let installed: i64 = query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'dovecote_events'",
    )
    .fetch_one(pool)
    .await?;
    if installed == 0 {
        install_dovecote_schema(pool).await?;
    }
    dovecote_sqlx_mysql::check_schema(pool).await?;
    sqlx::query("DELETE FROM dovecote_deliveries")
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM dovecote_events")
        .execute(pool)
        .await?;
    Ok(())
}

async fn install_dovecote_schema(pool: &MySqlPool) -> Result<(), Box<dyn Error>> {
    // The migration contains trigger bodies with semicolons. Keep those
    // bodies together while executing the release artifact statement by
    // statement, as the Dovecote MySQL live gate does.
    let mut trigger = false;
    let mut buffered = String::new();
    for fragment in dovecote_sqlx_mysql::MIGRATIONS[0].sql().split(';') {
        let fragment = fragment.trim();
        if fragment.is_empty() {
            continue;
        }

        if fragment.to_ascii_uppercase().starts_with("CREATE TRIGGER") || trigger {
            if !buffered.is_empty() {
                buffered.push(';');
            }
            buffered.push_str(fragment);
            trigger = !fragment.to_ascii_uppercase().ends_with("END");
            if trigger {
                continue;
            }

            let statement: &'static str = Box::leak(buffered.clone().into_boxed_str());
            raw_sql(statement).execute(pool).await?;
            buffered.clear();
            continue;
        }

        sqlx::query(fragment).execute(pool).await?;
    }
    Ok(())
}
