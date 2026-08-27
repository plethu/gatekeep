#![allow(missing_docs)]
#![cfg(all(feature = "sqlite-tests", feature = "dovecote-sqlite"))]

#[path = "audit_support/mod.rs"]
mod audit_support;

use audit_support::audit_entry;
use gatekeep::RequestId;
use gatekeep_sqlx::{
    BRIDGE_PAYLOAD_CODEC, BRIDGE_PAYLOAD_PROVENANCE_DUAL_WRITE, BridgeImportOptions,
    DovecoteAuditBridge, GATEKEEP_AUDIT_EVENT_TYPE, SqliteBridgeError,
    SqliteDecisionAuditRepository, SqlxAuditError, SqlxAuditStore,
};
use sqlx::{Row, SqlitePool, raw_sql, sqlite::SqlitePoolOptions};
use std::time::Duration;

#[tokio::test]
async fn dual_write_keeps_legacy_outbox_authoritative_and_dovecote_pending() -> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let entry = audit_entry()?;

    // Leave a prior legacy outbox row behind so the decision and outbox
    // sequences differ. The bridge contract must use the latter.
    let existing_decision_id = repo.record_decision_audit(&entry).await?;
    sqlx::query("insert into gatekeep_audit_outbox (decision_id, payload) values (?, ?)")
        .bind(existing_decision_id)
        .bind(serde_json::to_string(&entry)?)
        .execute(&pool)
        .await?;

    let outcome = repo
        .record_decision_audit_with_dovecote(&entry, &bridge)
        .await?;
    assert_eq!(outcome.legacy_outbox_id, 3);
    assert_eq!(outcome.decision_id, 2);
    assert_ne!(outcome.legacy_outbox_id, outcome.decision_id);

    let mapping = sqlx::query(
        "select source, event_id, event_type, payload, payload_provenance, payload_codec, payload_digest, dovecote_row_id from gatekeep_dovecote_bridge_outbox where legacy_outbox_id = ?",
    )
    .bind(outcome.legacy_outbox_id)
    .fetch_one(&pool)
    .await?;
    let source: String = mapping.try_get("source")?;
    let event_id: String = mapping.try_get("event_id")?;
    let event_type: String = mapping.try_get("event_type")?;
    let payload: Vec<u8> = mapping.try_get("payload")?;
    let payload_provenance: String = mapping.try_get("payload_provenance")?;
    let payload_codec: String = mapping.try_get("payload_codec")?;
    let payload_digest: Vec<u8> = mapping.try_get("payload_digest")?;
    let dovecote_row_id: i64 = mapping.try_get("dovecote_row_id")?;
    assert_eq!(event_id, "gatekeep-outbox-3");
    assert_eq!(event_type, GATEKEEP_AUDIT_EVENT_TYPE);
    assert_eq!(payload, serde_json::to_string(&entry)?.into_bytes());
    assert_eq!(payload_provenance, BRIDGE_PAYLOAD_PROVENANCE_DUAL_WRITE);
    assert_eq!(payload_codec, BRIDGE_PAYLOAD_CODEC);
    assert_eq!(payload_digest, {
        let publication = repo
            .legacy_outbox_publication(outcome.legacy_outbox_id)
            .await?;
        publication.payload_digest().to_vec()
    });
    assert_eq!(
        repo.legacy_outbox_publication(outcome.legacy_outbox_id)
            .await?
            .payload(),
        payload
    );

    let event = sqlx::query(
        "select stream, event_id, source, event_type, datacontenttype, occurred_at, data from dovecote_events where row_id = ?",
    )
    .bind(dovecote_row_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(event.try_get::<String, _>("stream")?, "gatekeep-audit");
    assert_eq!(event.try_get::<String, _>("event_id")?, event_id);
    assert_eq!(event.try_get::<String, _>("source")?, source);
    assert_eq!(event.try_get::<String, _>("event_type")?, event_type);
    assert_eq!(
        event.try_get::<String, _>("datacontenttype")?,
        "application/json"
    );
    assert!(event.try_get::<Option<String>, _>("occurred_at")?.is_none());
    assert_eq!(event.try_get::<Vec<u8>, _>("data")?, payload);
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "select state from dovecote_deliveries where event_row_id = ?",
        )
        .bind(dovecote_row_id)
        .fetch_one(&pool)
        .await?,
        "pending"
    );
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn bridge_acknowledges_legacy_and_finalizes_dovecote_atomically() -> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let outcome = repo
        .record_decision_audit_with_dovecote(&audit_entry()?, &bridge)
        .await?;
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
    repo.acknowledge_legacy_outbox_with_dovecote(
        outcome.legacy_outbox_id,
        "legacy-publisher",
        claim.token(),
        delivered_at,
    )
    .await?;

    let legacy = sqlx::query(
        "select claimed_by, claimed_until, delivered_at from gatekeep_audit_outbox where id = ?",
    )
    .bind(outcome.legacy_outbox_id)
    .fetch_one(&pool)
    .await?;
    assert!(legacy.try_get::<Option<String>, _>("claimed_by")?.is_none());
    assert!(
        legacy
            .try_get::<Option<String>, _>("claimed_until")?
            .is_none()
    );

    // A reclaim by the same worker must invalidate the old lease generation,
    // even when the legacy owner and expiry are restored byte-for-byte.
    let reclaimed = repo
        .record_decision_audit_with_dovecote(&audit_entry()?, &bridge)
        .await?;
    let first_claim = repo
        .claim_legacy_outbox_with_dovecote(
            reclaimed.legacy_outbox_id,
            "legacy-publisher",
            Duration::from_mins(1),
        )
        .await?;
    let first_until: String =
        sqlx::query_scalar("select claimed_until from gatekeep_audit_outbox where id = ?")
            .bind(reclaimed.legacy_outbox_id)
            .fetch_one(&pool)
            .await?;
    sqlx::query(
        "update gatekeep_audit_outbox set claimed_until = '2000-01-01T00:00:00Z' where id = ?",
    )
    .bind(reclaimed.legacy_outbox_id)
    .execute(&pool)
    .await?;
    let second_claim = repo
        .claim_legacy_outbox_with_dovecote(
            reclaimed.legacy_outbox_id,
            "legacy-publisher",
            Duration::from_mins(1),
        )
        .await?;
    assert_ne!(first_claim.token(), second_claim.token());
    // Simulate an expiry calculation that repeats the old claim exactly. The
    // bridge generation still distinguishes the two acquisitions.
    sqlx::query("update gatekeep_audit_outbox set claimed_until = ? where id = ?")
        .bind(&first_until)
        .bind(reclaimed.legacy_outbox_id)
        .execute(&pool)
        .await?;
    assert!(matches!(
        repo.acknowledge_legacy_outbox_with_dovecote(
            reclaimed.legacy_outbox_id,
            "legacy-publisher",
            first_claim.token(),
            delivered_at,
        )
        .await,
        Err(SqliteBridgeError::AckNotOwned(id)) if id == reclaimed.legacy_outbox_id
    ));
    repo.acknowledge_legacy_outbox_with_dovecote(
        reclaimed.legacy_outbox_id,
        "legacy-publisher",
        second_claim.token(),
        delivered_at,
    )
    .await?;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "select legacy_claim_token from gatekeep_dovecote_bridge_outbox where legacy_outbox_id = ?",
        )
        .bind(reclaimed.legacy_outbox_id)
        .fetch_one(&pool)
        .await?,
        second_claim.token()
    );
    let reclaimed_state: String = sqlx::query_scalar(
        "select state from dovecote_deliveries d join gatekeep_dovecote_bridge_outbox b on b.dovecote_row_id = d.event_row_id where b.legacy_outbox_id = ?",
    )
    .bind(reclaimed.legacy_outbox_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(reclaimed_state, "delivered");
    let reclaimed_legacy: Option<String> =
        sqlx::query_scalar("select delivered_at from gatekeep_audit_outbox where id = ?")
            .bind(reclaimed.legacy_outbox_id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(reclaimed_legacy, Some("2025-01-01T00:00:00Z".to_owned()));
    assert_eq!(
        legacy.try_get::<Option<String>, _>("delivered_at")?,
        Some("2025-01-01T00:00:00Z".to_owned())
    );
    let dovecote_row_id = sqlx::query_scalar::<_, i64>(
        "select dovecote_row_id from gatekeep_dovecote_bridge_outbox where legacy_outbox_id = ?",
    )
    .bind(outcome.legacy_outbox_id)
    .fetch_one(&pool)
    .await?;
    let delivery = sqlx::query(
        "select state, claim_token, claimed_by, claim_expires_at, delivered_at from dovecote_deliveries where event_row_id = ?",
    )
    .bind(dovecote_row_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(delivery.try_get::<String, _>("state")?, "delivered");
    assert!(
        delivery
            .try_get::<Option<Vec<u8>>, _>("claim_token")?
            .is_none()
    );
    assert!(
        delivery
            .try_get::<Option<String>, _>("claimed_by")?
            .is_none()
    );
    assert!(
        delivery
            .try_get::<Option<String>, _>("claim_expires_at")?
            .is_none()
    );
    assert!(
        delivery
            .try_get::<Option<String>, _>("delivered_at")?
            .is_some()
    );

    let mut stale_entry = audit_entry()?;
    stale_entry.request_id = Some(RequestId::new("req-stale")?);
    let stale = repo
        .record_decision_audit_with_dovecote(&stale_entry, &bridge)
        .await?;
    let stale_claim = repo
        .claim_legacy_outbox_with_dovecote(
            stale.legacy_outbox_id,
            "legacy-publisher",
            Duration::from_mins(1),
        )
        .await?;
    sqlx::query(
        "update gatekeep_audit_outbox set claimed_until = '2000-01-01T00:00:00.123456+05:30' where id = ?",
    )
    .bind(stale.legacy_outbox_id)
    .execute(&pool)
    .await?;
    assert!(matches!(
        repo.acknowledge_legacy_outbox_with_dovecote(
            stale.legacy_outbox_id,
            "legacy-publisher",
            stale_claim.token(),
            delivered_at,
        )
        .await,
        Err(SqliteBridgeError::AckNotOwned(id)) if id == stale.legacy_outbox_id
    ));
    Ok(())
}

#[tokio::test]
async fn bounded_history_import_resumes_and_preserves_delivered_state() -> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let entry = audit_entry()?;
    repo.record_decision_audit_with_dovecote(&entry, &bridge)
        .await?;
    repo.record_decision_audit(&entry).await?;
    sqlx::query("update gatekeep_audit_outbox set delivered_at = ? where id = 2")
        .bind("2025-01-01T00:00:00Z")
        .execute(&pool)
        .await?;

    let options = BridgeImportOptions::new(1, "bridge-test", Duration::from_secs(30))?;
    let first = repo.import_legacy_history(&bridge, &options).await?;
    assert_eq!((first.high_water, first.cursor), (2, 0));
    assert_eq!(
        (first.imported, first.already_imported, first.delivered),
        (0, 1, 0)
    );
    assert!(!first.complete);

    let second = repo.import_legacy_history(&bridge, &options).await?;
    assert_eq!((second.high_water, second.cursor), (2, 2));
    assert_eq!(
        (second.imported, second.already_imported, second.delivered),
        (1, 0, 1)
    );
    assert!(second.complete);
    let historical_publication = repo.legacy_outbox_publication(2).await?;
    assert_eq!(
        historical_publication.payload_provenance(),
        gatekeep_sqlx::BRIDGE_PAYLOAD_PROVENANCE_LEGACY_TEXT
    );
    assert_eq!(
        historical_publication.payload_codec(),
        gatekeep_sqlx::BRIDGE_PAYLOAD_CODEC
    );

    let replay = repo.import_legacy_history(&bridge, &options).await?;
    assert_eq!(
        (replay.cursor, replay.imported, replay.already_imported),
        (2, 0, 0)
    );
    assert!(replay.complete);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from dovecote_events where event_id = 'gatekeep-outbox-2'",
        )
        .fetch_one(&pool)
        .await?,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "select state from dovecote_deliveries d join dovecote_events e on e.row_id = d.event_row_id where e.event_id = 'gatekeep-outbox-2'",
        )
        .fetch_one(&pool)
        .await?,
        "delivered"
    );
    Ok(())
}

#[tokio::test]
async fn completed_high_water_captures_later_legacy_rows() -> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let entry = audit_entry()?;
    repo.record_decision_audit(&entry).await?;

    let first = repo
        .import_legacy_history(&bridge, &BridgeImportOptions::default())
        .await?;
    assert_eq!((first.high_water, first.cursor), (1, 1));
    assert!(first.complete);

    // A legacy writer commits after the first complete high-water range.
    repo.record_decision_audit(&entry).await?;
    let second = repo
        .import_legacy_history(&bridge, &BridgeImportOptions::default())
        .await?;
    assert_eq!((second.high_water, second.cursor), (2, 2));
    assert_eq!((second.imported, second.already_imported), (1, 0));
    assert!(second.complete);
    Ok(())
}

#[tokio::test]
async fn deleted_captured_tail_repairs_cursor_before_later_write() -> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let first_entry = audit_entry()?;
    let mut second_entry = audit_entry()?;
    second_entry.request_id = Some(RequestId::new("deleted-tail")?);
    repo.record_decision_audit(&first_entry).await?;
    repo.record_decision_audit(&second_entry).await?;

    let one = BridgeImportOptions::new(1, "deleted-tail-test", Duration::from_secs(30))?;
    let partial = repo.import_legacy_history(&bridge, &one).await?;
    assert_eq!((partial.high_water, partial.cursor), (2, 0));
    assert!(!partial.complete);

    // The remaining row was in the captured range but was removed before the
    // next batch. The persisted high-water must not move backwards with it.
    sqlx::query("delete from gatekeep_audit_outbox where id = 2")
        .execute(&pool)
        .await?;
    let repaired = repo.import_legacy_history(&bridge, &one).await?;
    assert_eq!((repaired.high_water, repaired.cursor), (2, 2));
    assert!(repaired.complete);
    assert_eq!(repaired.imported, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from dovecote_events where event_id = 'gatekeep-audit-legacy-2'",
        )
        .fetch_one(&pool)
        .await?,
        1
    );

    // A zero-change replay must retain the cursor even though the captured
    // tail is gone. This is the regression that prevents high-water from
    // moving backwards before a later writer arrives.
    let replay = repo.import_legacy_history(&bridge, &one).await?;
    assert_eq!((replay.high_water, replay.cursor), (2, 2));
    assert!(replay.complete);

    // A later writer receives a new source ID and is visible after repair.
    let mut later_entry = audit_entry()?;
    later_entry.request_id = Some(RequestId::new("later-write")?);
    let later = repo.record_decision_audit(&later_entry).await?;
    assert_eq!(later, 3);
    let captured = repo.import_legacy_history(&bridge, &one).await?;
    assert_eq!((captured.high_water, captured.cursor), (3, 3));
    assert_eq!(captured.imported, 1);
    assert!(captured.complete);
    Ok(())
}

#[tokio::test]
async fn normalized_decision_without_outbox_is_reconstructed_with_reserved_identity()
-> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let entry = audit_entry()?;
    let decision_id = repo.record_decision_audit(&entry).await?;
    sqlx::query("delete from gatekeep_audit_outbox where decision_id = ?")
        .bind(decision_id)
        .execute(&pool)
        .await?;

    let report = repo
        .import_legacy_history(&bridge, &BridgeImportOptions::default())
        .await?;
    assert_eq!((report.imported, report.delivered), (1, 0));
    assert!(report.complete);
    let event = sqlx::query(
        "select stream, event_id, source, event_type, datacontenttype, occurred_at, data from dovecote_events",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(event.try_get::<String, _>("stream")?, "gatekeep-audit");
    assert_eq!(
        event.try_get::<String, _>("event_id")?,
        "gatekeep-audit-legacy-1"
    );
    assert_eq!(
        event.try_get::<String, _>("source")?,
        "https://auth.example.test/gatekeep"
    );
    assert_eq!(
        event.try_get::<String, _>("event_type")?,
        GATEKEEP_AUDIT_EVENT_TYPE
    );
    assert_eq!(
        event.try_get::<String, _>("datacontenttype")?,
        "application/json"
    );
    assert!(event.try_get::<Option<String>, _>("occurred_at")?.is_none());
    let expected = gatekeep_sqlx::encode_reconstructed_audit_v1(&serde_json::to_value(&entry)?)?;
    assert_eq!(event.try_get::<Vec<u8>, _>("data")?, expected);
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "select payload_provenance from gatekeep_dovecote_bridge_audit where decision_id = ?",
        )
        .bind(decision_id)
        .fetch_one(&pool)
        .await?,
        gatekeep_sqlx::BRIDGE_PAYLOAD_PROVENANCE_LEGACY_JSON_VALUE
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "select state from dovecote_deliveries d join dovecote_events e on e.row_id = d.event_row_id",
        )
        .fetch_one(&pool)
        .await?,
        "pending"
    );
    Ok(())
}

#[tokio::test]
async fn duplicate_outbox_rows_for_one_decision_are_each_migrated() -> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let entry = audit_entry()?;
    let decision_id = repo.record_decision_audit(&entry).await?;
    let payload = serde_json::to_string(&entry)?;
    sqlx::query("insert into gatekeep_audit_outbox (decision_id, payload) values (?, ?)")
        .bind(decision_id)
        .bind(payload)
        .execute(&pool)
        .await?;

    let options = BridgeImportOptions::new(1, "duplicate-outbox-test", Duration::from_secs(30))?;
    let first = repo.import_legacy_history(&bridge, &options).await?;
    assert_eq!(first.imported, 1);
    assert!(!first.complete);
    let report = repo.import_legacy_history(&bridge, &options).await?;
    assert!(report.complete);
    assert_eq!(report.imported, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from dovecote_events")
            .fetch_one(&pool)
            .await?,
        2
    );
    for id in ["gatekeep-outbox-1", "gatekeep-outbox-2"] {
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "select state from dovecote_deliveries d join dovecote_events e on e.row_id = d.event_row_id where e.event_id = ?",
            )
            .bind(id)
            .fetch_one(&pool)
            .await?,
            "pending"
        );
    }
    Ok(())
}

#[tokio::test]
async fn outbox_and_audit_only_scans_share_the_batch_budget() -> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let entry = audit_entry()?;

    // Keep one outbox row, but leave two later decisions normalized-only. The
    // outbox cursor must finish its sequence before the decision scan begins,
    // and that second scan may consume only the remaining batch capacity.
    repo.record_decision_audit(&entry).await?;
    let second = repo.record_decision_audit(&entry).await?;
    let third = repo.record_decision_audit(&entry).await?;
    sqlx::query("delete from gatekeep_audit_outbox where decision_id in (?, ?)")
        .bind(second)
        .bind(third)
        .execute(&pool)
        .await?;

    let options = BridgeImportOptions::new(2, "batch-budget-test", Duration::from_secs(30))?;
    let first = repo.import_legacy_history(&bridge, &options).await?;
    assert_eq!((first.imported, first.cursor), (2, 2));
    assert_eq!((first.outbox_high_water, first.outbox_cursor), (1, 1));
    assert!(!first.complete);

    let second = repo.import_legacy_history(&bridge, &options).await?;
    assert_eq!((second.imported, second.cursor), (1, 3));
    assert_eq!((second.outbox_high_water, second.outbox_cursor), (1, 1));
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
async fn persisted_bridge_configuration_rejects_drift() -> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool);
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/one")?;
    let drifted = DovecoteAuditBridge::with_stream("https://auth.example.test/two", "other")?;
    let entry = audit_entry()?;
    repo.record_decision_audit_with_dovecote(&entry, &bridge)
        .await?;
    let result = repo
        .import_legacy_history(&drifted, &BridgeImportOptions::default())
        .await;
    assert!(matches!(result, Err(SqliteBridgeError::StateConflict)));
    Ok(())
}

#[tokio::test]
async fn active_claim_returns_typed_claimed_outcome() -> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    sqlx::query(
        "insert into gatekeep_dovecote_bridge_state (id, source, stream, claimed_by, claim_token, claim_until) values (1, ?, ?, 'other-worker', 'other-token', cast(unixepoch('now') * 1000 as integer) + 60000)",
    )
    .bind(bridge.source().as_str())
    .bind(bridge.stream().as_str())
    .execute(&pool)
    .await?;

    let result = repo
        .import_legacy_history(&bridge, &BridgeImportOptions::default())
        .await;
    assert!(matches!(result, Err(SqliteBridgeError::Claimed)));
    Ok(())
}

#[tokio::test]
async fn active_legacy_claim_is_not_imported_as_pending() -> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let entry = audit_entry()?;
    repo.record_decision_audit(&entry).await?;
    sqlx::query(
        "update gatekeep_audit_outbox set claimed_by = ?, claimed_until = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+1 minute') where id = 1",
    )
    .bind("legacy-publisher")
    .execute(&pool)
    .await?;

    let result = repo
        .import_legacy_history(&bridge, &BridgeImportOptions::default())
        .await;
    assert!(matches!(result, Err(SqliteBridgeError::LegacyClaimed(1))));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from dovecote_events")
            .fetch_one(&pool)
            .await?,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gatekeep_dovecote_bridge_state")
            .fetch_one(&pool)
            .await?,
        0
    );
    Ok(())
}

#[tokio::test]
async fn expired_legacy_claim_is_conditionally_fenced_before_import() -> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let entry = audit_entry()?;
    repo.record_decision_audit(&entry).await?;
    sqlx::query(
        "update gatekeep_audit_outbox set claimed_by = ?, claimed_until = '2020-01-01T00:00:00Z' where id = 1",
    )
    .bind("stale-publisher")
    .execute(&pool)
    .await?;

    repo.import_legacy_history(&bridge, &BridgeImportOptions::default())
        .await?;
    let claim =
        sqlx::query("select claimed_by, claimed_until from gatekeep_audit_outbox where id = 1")
            .fetch_one(&pool)
            .await?;
    assert!(claim.try_get::<Option<String>, _>("claimed_by")?.is_none());
    assert!(
        claim
            .try_get::<Option<String>, _>("claimed_until")?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn dual_write_enqueue_conflict_rolls_back_legacy_rows() -> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    sqlx::query(
        "insert into dovecote_events (stream, specversion, event_id, source, event_type, datacontenttype, data_kind, data) values (?, '1.0', ?, ?, ?, 'application/json', 'json', ?)",
    )
    .bind(bridge.stream().as_str())
    .bind("gatekeep-outbox-1")
    .bind(bridge.source().as_str())
    .bind(GATEKEEP_AUDIT_EVENT_TYPE)
    .bind(br#"{"different":true}"#.as_slice())
    .execute(&pool)
    .await?;
    let result = repo
        .record_decision_audit_with_dovecote(&audit_entry()?, &bridge)
        .await;
    assert!(matches!(
        result,
        Err(SqliteBridgeError::Dovecote(
            dovecote_sqlx_sqlite::EnqueueError::IdempotencyConflict { .. }
        ))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gatekeep_audit_decisions")
            .fetch_one(&pool)
            .await?,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gatekeep_audit_outbox")
            .fetch_one(&pool)
            .await?,
        0
    );
    Ok(())
}

#[tokio::test]
async fn existing_identity_conflict_rolls_back_mapping_and_cursor() -> TestResult<()> {
    let pool = database().await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
    let entry = audit_entry()?;
    repo.record_decision_audit(&entry).await?;
    sqlx::query(
        "insert into dovecote_events (stream, specversion, event_id, source, event_type, datacontenttype, data_kind, data) values (?, '1.0', ?, ?, ?, 'application/json', 'json', ?)",
    )
    .bind(bridge.stream().as_str())
    .bind("gatekeep-outbox-1")
    .bind(bridge.source().as_str())
    .bind(GATEKEEP_AUDIT_EVENT_TYPE)
    .bind(br#"{"different":true}"#.as_slice())
    .execute(&pool)
    .await?;

    let result = repo
        .import_legacy_history(&bridge, &BridgeImportOptions::default())
        .await;
    assert!(matches!(
        result,
        Err(SqliteBridgeError::DovecoteImport(
            dovecote_sqlx_sqlite::ImportError::IdentityConflict { .. }
        ))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gatekeep_dovecote_bridge_outbox",)
            .fetch_one(&pool)
            .await?,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gatekeep_dovecote_bridge_state",)
            .fetch_one(&pool)
            .await?,
        0
    );
    Ok(())
}

async fn database() -> Result<SqlitePool, sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    raw_sql(include_str!(
        "../../../../carrier/crates/dovecote-sqlx-sqlite/migrations/0001_dovecote.sql"
    ))
    .execute(&pool)
    .await?;
    raw_sql(include_str!("../migrations/sqlite/0001_audit.sql"))
        .execute(&pool)
        .await?;
    raw_sql(include_str!(
        "../migrations/sqlite/0002_dovecote_bridge.sql"
    ))
    .execute(&pool)
    .await?;
    Ok(pool)
}

type TestResult<T> = Result<T, TestError>;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Gatekeep(#[from] gatekeep::GatekeepError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Bridge(#[from] SqliteBridgeError),
    #[error(transparent)]
    Audit(#[from] SqlxAuditError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Config(#[from] gatekeep_sqlx::BridgeConfigError),
    #[error(transparent)]
    Time(#[from] time::error::Parse),
}
