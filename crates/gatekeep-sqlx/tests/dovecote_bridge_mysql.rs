#![allow(missing_docs)]
#![cfg(all(feature = "mysql-tests", feature = "dovecote-mysql"))]

#[path = "audit_support/mod.rs"]
mod audit_support;

use audit_support::audit_entry;
use gatekeep_sqlx::{
    BRIDGE_PAYLOAD_CODEC, BRIDGE_PAYLOAD_PROVENANCE_DUAL_WRITE, BridgeImportOptions,
    DovecoteAuditBridge, GATEKEEP_AUDIT_EVENT_TYPE, MySqlBackend, MySqlBridgeError,
    MySqlDecisionAuditRepository, SqlxAuditError, SqlxAuditStore,
    validate_database_url_for_backend,
};
use sqlx::{MySqlPool, Row, mysql::MySqlPoolOptions, raw_sql};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires docker mysql"]
async fn mysql_bridge_dual_write_uses_binary_identity_and_pending_delivery() -> TestResult<()> {
    let pool = database().await?;
    let repo = MySqlDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let entry = audit_entry()?;
    let outcome = repo
        .record_decision_audit_with_dovecote(&entry, &bridge)
        .await?;

    let mapping = sqlx::query(
        "select source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest, dovecote_row_id from gatekeep_dovecote_bridge_outbox where legacy_outbox_id = ?",
    )
    .bind(outcome.legacy_outbox_id)
    .fetch_one(&pool)
    .await?;
    let source: Vec<u8> = mapping.try_get("source")?;
    let event_id: Vec<u8> = mapping.try_get("event_id")?;
    let event_type: Vec<u8> = mapping.try_get("event_type")?;
    let payload: Vec<u8> = mapping.try_get("payload")?;
    let payload_provenance: String = mapping.try_get("payload_provenance")?;
    let payload_codec: String = mapping.try_get("payload_codec")?;
    let payload_digest: Vec<u8> = mapping.try_get("payload_digest")?;
    let dovecote_row_id: i64 = mapping.try_get("dovecote_row_id")?;
    assert_eq!(
        event_id,
        format!("gatekeep-outbox-{}", outcome.legacy_outbox_id).into_bytes()
    );
    assert_eq!(event_type, GATEKEEP_AUDIT_EVENT_TYPE.as_bytes());
    assert_eq!(payload, serde_json::to_vec(&entry)?);
    assert_eq!(payload_provenance, BRIDGE_PAYLOAD_PROVENANCE_DUAL_WRITE);
    assert_eq!(payload_codec, BRIDGE_PAYLOAD_CODEC);
    assert_eq!(
        payload_digest,
        repo.legacy_outbox_publication(outcome.legacy_outbox_id)
            .await?
            .payload_digest()
            .to_vec()
    );

    let event = sqlx::query(
        "select stream, event_id, source, event_type, datacontenttype, occurred_at, data from dovecote_events where row_id = ?",
    )
    .bind(dovecote_row_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(event.try_get::<Vec<u8>, _>("stream")?, b"gatekeep-audit");
    assert_eq!(event.try_get::<Vec<u8>, _>("event_id")?, event_id);
    assert_eq!(event.try_get::<Vec<u8>, _>("source")?, source);
    assert_eq!(event.try_get::<Vec<u8>, _>("event_type")?, event_type);
    assert_eq!(
        event.try_get::<Vec<u8>, _>("datacontenttype")?,
        b"application/json"
    );
    assert!(
        event
            .try_get::<Option<time::PrimitiveDateTime>, _>("occurred_at")?
            .is_none()
    );
    assert_eq!(event.try_get::<Vec<u8>, _>("data")?, payload);
    assert_eq!(
        sqlx::query_scalar::<_, Vec<u8>>(
            "select state from dovecote_deliveries where event_row_id = ?",
        )
        .bind(dovecote_row_id)
        .fetch_one(&pool)
        .await?,
        b"pending"
    );
    assert_eq!(
        repo.legacy_outbox_publication(outcome.legacy_outbox_id)
            .await?
            .event_id(),
        format!("gatekeep-outbox-{}", outcome.legacy_outbox_id)
    );
    let claim = repo
        .claim_legacy_outbox_with_dovecote(
            outcome.legacy_outbox_id,
            "legacy-publisher",
            Duration::from_mins(1),
        )
        .await?;
    let delivered_at = time::OffsetDateTime::parse(
        "2025-01-01T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )?;
    repo.acknowledge_legacy_outbox_with_dovecote(
        outcome.legacy_outbox_id,
        "legacy-publisher",
        claim.token(),
        delivered_at,
    )
    .await?;
    assert_eq!(
        sqlx::query_scalar::<_, Vec<u8>>(
            "select state from dovecote_deliveries where event_row_id = ?",
        )
        .bind(dovecote_row_id)
        .fetch_one(&pool)
        .await?,
        b"delivered"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker mysql"]
async fn mysql_bridge_imports_normalized_decision_without_outbox() -> TestResult<()> {
    let pool = database().await?;
    let repo = MySqlDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let decision_id = repo.record_decision_audit(&audit_entry()?).await?;
    sqlx::query("delete from gatekeep_audit_outbox where decision_id = ?")
        .bind(decision_id)
        .execute(&pool)
        .await?;

    let report = repo
        .import_legacy_history(&bridge, &gatekeep_sqlx::BridgeImportOptions::default())
        .await?;
    assert_eq!((report.imported, report.delivered), (1, 0));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from dovecote_events where event_id = 'gatekeep-audit-legacy-1'",
        )
        .fetch_one(&pool)
        .await?,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "select payload_provenance from gatekeep_dovecote_bridge_audit where decision_id = ?",
        )
        .bind(decision_id)
        .fetch_one(&pool)
        .await?,
        gatekeep_sqlx::BRIDGE_PAYLOAD_PROVENANCE_LEGACY_JSON_VALUE
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker mysql"]
#[allow(clippy::too_many_lines)]
async fn mysql_bridge_claim_replay_and_high_water_guards() -> TestResult<()> {
    let pool = database().await?;
    let repo = MySqlDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let delivered_at = time::OffsetDateTime::parse(
        "2025-01-01T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )?;

    let outcome = repo
        .record_decision_audit_with_dovecote(&audit_entry()?, &bridge)
        .await?;
    let first = repo
        .claim_legacy_outbox_with_dovecote(
            outcome.legacy_outbox_id,
            "legacy-publisher",
            Duration::from_mins(1),
        )
        .await?;
    let first_until: time::OffsetDateTime =
        sqlx::query_scalar("select claimed_until from gatekeep_audit_outbox where id = ?")
            .bind(outcome.legacy_outbox_id)
            .fetch_one(&pool)
            .await?;
    sqlx::query(
        "update gatekeep_audit_outbox set claimed_until = '2000-01-01 00:00:00' where id = ?",
    )
    .bind(outcome.legacy_outbox_id)
    .execute(&pool)
    .await?;
    let second = repo
        .claim_legacy_outbox_with_dovecote(
            outcome.legacy_outbox_id,
            "legacy-publisher",
            Duration::from_mins(1),
        )
        .await?;
    assert_ne!(first.token(), second.token());
    sqlx::query("update gatekeep_audit_outbox set claimed_until = ? where id = ?")
        .bind(first_until)
        .bind(outcome.legacy_outbox_id)
        .execute(&pool)
        .await?;
    assert!(matches!(
        repo.acknowledge_legacy_outbox_with_dovecote(
            outcome.legacy_outbox_id,
            "legacy-publisher",
            first.token(),
            delivered_at,
        )
        .await,
        Err(MySqlBridgeError::AckNotOwned(id)) if id == outcome.legacy_outbox_id
    ));
    repo.acknowledge_legacy_outbox_with_dovecote(
        outcome.legacy_outbox_id,
        "legacy-publisher",
        second.token(),
        delivered_at,
    )
    .await?;
    repo.acknowledge_legacy_outbox_with_dovecote(
        outcome.legacy_outbox_id,
        "legacy-publisher",
        second.token(),
        delivered_at,
    )
    .await?;

    let rollback = repo
        .record_decision_audit_with_dovecote(&audit_entry()?, &bridge)
        .await?;
    let rollback_claim = repo
        .claim_legacy_outbox_with_dovecote(
            rollback.legacy_outbox_id,
            "legacy-publisher",
            Duration::from_mins(1),
        )
        .await?;
    let rollback_row: i64 = sqlx::query_scalar(
        "select dovecote_row_id from gatekeep_dovecote_bridge_outbox where legacy_outbox_id = ?",
    )
    .bind(rollback.legacy_outbox_id)
    .fetch_one(&pool)
    .await?;
    sqlx::query("delete from dovecote_deliveries where event_row_id = ?")
        .bind(rollback_row)
        .execute(&pool)
        .await?;
    assert!(
        repo.acknowledge_legacy_outbox_with_dovecote(
            rollback.legacy_outbox_id,
            "legacy-publisher",
            rollback_claim.token(),
            delivered_at,
        )
        .await
        .is_err()
    );
    let rollback_state: (Option<String>, Option<time::OffsetDateTime>) =
        sqlx::query_as("select claimed_by, delivered_at from gatekeep_audit_outbox where id = ?")
            .bind(rollback.legacy_outbox_id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(rollback_state.0.as_deref(), Some("legacy-publisher"));
    assert!(rollback_state.1.is_none());
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker mysql"]
async fn mysql_bridge_deleted_tail_replay_preserves_cursor() -> TestResult<()> {
    let pool = database().await?;
    let repo = MySqlDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    repo.record_decision_audit(&audit_entry()?).await?;
    repo.record_decision_audit(&audit_entry()?).await?;
    let options =
        gatekeep_sqlx::BridgeImportOptions::new(1, "bridge-test", Duration::from_mins(1))?;
    let partial = repo.import_legacy_history(&bridge, &options).await?;
    assert_eq!((partial.high_water, partial.cursor), (2, 0));
    sqlx::query("delete from gatekeep_audit_outbox where id = 2")
        .execute(&pool)
        .await?;
    let repaired = repo.import_legacy_history(&bridge, &options).await?;
    assert_eq!((repaired.high_water, repaired.cursor), (2, 2));
    let replay = repo.import_legacy_history(&bridge, &options).await?;
    assert_eq!((replay.high_water, replay.cursor), (2, 2));
    assert!(replay.complete);
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker mysql"]
async fn mysql_bridge_outbox_and_audit_only_scans_share_batch_budget() -> TestResult<()> {
    let pool = database().await?;
    let repo = MySqlDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let entry = audit_entry()?;
    repo.record_decision_audit(&entry).await?;
    let second = repo.record_decision_audit(&entry).await?;
    let third = repo.record_decision_audit(&entry).await?;
    sqlx::query("delete from gatekeep_audit_outbox where decision_id in (?, ?)")
        .bind(second)
        .bind(third)
        .execute(&pool)
        .await?;

    let options = BridgeImportOptions::new(2, "batch-budget-test", Duration::from_mins(1))?;
    let first = repo.import_legacy_history(&bridge, &options).await?;
    assert_eq!((first.imported, first.cursor), (2, 2));
    assert!(!first.complete);
    let second = repo.import_legacy_history(&bridge, &options).await?;
    assert_eq!((second.imported, second.cursor), (1, 3));
    assert!(second.complete);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from dovecote_events")
            .fetch_one(&pool)
            .await?,
        3
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker mysql"]
async fn mysql_bridge_duplicate_outboxes_cross_batch_boundaries() -> TestResult<()> {
    let pool = database().await?;
    let repo = MySqlDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let entry = audit_entry()?;
    let decision_id = repo.record_decision_audit(&entry).await?;
    let payload = serde_json::to_string(&entry)?;
    sqlx::query("insert into gatekeep_audit_outbox (decision_id, payload) values (?, ?)")
        .bind(decision_id)
        .bind(payload)
        .execute(&pool)
        .await?;

    let options = BridgeImportOptions::new(1, "duplicate-outbox-test", Duration::from_mins(1))?;
    let first = repo.import_legacy_history(&bridge, &options).await?;
    assert_eq!(first.imported, 1);
    assert_eq!((first.outbox_high_water, first.outbox_cursor), (2, 1));
    assert!(!first.complete);
    let second = repo.import_legacy_history(&bridge, &options).await?;
    assert_eq!(second.imported, 1);
    assert_eq!((second.outbox_high_water, second.outbox_cursor), (2, 2));
    assert!(second.complete);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from dovecote_events")
            .fetch_one(&pool)
            .await?,
        2
    );
    Ok(())
}

async fn database() -> Result<MySqlPool, TestError> {
    let url = std::env::var("MYSQL_DATABASE_URL")?;
    validate_database_url_for_backend::<MySqlBackend>(&url)?;
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await?;
    for statement in [
        "drop table if exists gatekeep_dovecote_bridge_audit",
        "drop table if exists gatekeep_dovecote_bridge_outbox",
        "drop table if exists gatekeep_dovecote_bridge_state",
        "drop table if exists gatekeep_audit_outbox",
        "drop table if exists gatekeep_audit_reason_params",
        "drop table if exists gatekeep_audit_request_subjects",
        "drop table if exists gatekeep_audit_obligations",
        "drop table if exists gatekeep_audit_consulted_facts",
        "drop table if exists gatekeep_audit_decisions",
        "drop table if exists dovecote_deliveries",
        "drop table if exists dovecote_events",
    ] {
        raw_sql(statement).execute(&pool).await?;
    }

    for statement in [
        "drop trigger if exists dovecote_events_row_id_positive_insert",
        "drop trigger if exists dovecote_events_row_id_positive_update",
    ] {
        raw_sql(statement).execute(&pool).await?;
    }
    install_mysql_migration(&pool).await?;
    install_script(&pool, include_str!("../migrations/mysql/0001_audit.sql")).await?;
    install_script(
        &pool,
        include_str!("../migrations/mysql/0002_dovecote_bridge.sql"),
    )
    .await?;
    Ok(pool)
}

async fn install_script(pool: &MySqlPool, script: &'static str) -> Result<(), sqlx::Error> {
    for statement in script.split(';') {
        if !statement.trim().is_empty() {
            let statement: &'static str = statement;
            sqlx::query(statement).execute(pool).await?;
        }
    }
    Ok(())
}

async fn install_mysql_migration(pool: &MySqlPool) -> Result<(), sqlx::Error> {
    let mut trigger = false;
    let mut buffered = String::new();
    for fragment in
        include_str!("../../../../carrier/crates/dovecote-sqlx-mysql/migrations/0001_dovecote.sql")
            .split(';')
    {
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
            if !trigger {
                let statement: &'static str = Box::leak(buffered.clone().into_boxed_str());
                raw_sql(statement).execute(pool).await?;
                buffered.clear();
            }
            continue;
        }
        sqlx::query(fragment).execute(pool).await?;
    }
    Ok(())
}

type TestResult<T> = Result<T, TestError>;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Env(#[from] std::env::VarError),
    #[error(transparent)]
    Gatekeep(#[from] gatekeep::GatekeepError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Bridge(#[from] MySqlBridgeError),
    #[error(transparent)]
    Config(#[from] gatekeep_sqlx::BridgeConfigError),
    #[error(transparent)]
    Driver(#[from] gatekeep_sqlx::SqlxDriverError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Time(#[from] time::error::Parse),
    #[error(transparent)]
    Audit(#[from] SqlxAuditError),
}
