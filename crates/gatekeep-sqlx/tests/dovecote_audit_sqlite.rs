#![allow(missing_docs)]
#![cfg(feature = "sqlite-tests")]

use std::collections::BTreeMap;

use dovecote::{
    ContentType, EventData, EventId, EventSource, EventType, Limit, NewEvent, StreamName,
};
use gatekeep::{
    AuditEntry, DecisionAuditId, DenialReason, DenyShape, EffectKind, FactId, FactResolution,
    FactResolutionEvidence, GatekeepError, ObligationId, ParamKey, PolicyAnchor, PolicyHash,
    PolicyId, Presence, ReasonCode, ReasonValue, RequestId, SubjectRef, SubjectSlot, TenantBinding,
    TenantId, Trace, TraceClause, TrustedServiceBinding,
};
use gatekeep_sqlx::{DecisionAuditConfig, SqliteDovecoteAudit, decode_decision_audit};
use sqlx::{SqlitePool, raw_sql, sqlite::SqlitePoolOptions};
use time::OffsetDateTime;

#[tokio::test]
async fn writes_one_complete_dovecote_event_with_stable_identity() -> Result<(), TestError> {
    let pool = database().await?;
    let sink = SqliteDovecoteAudit::new(pool.clone(), "https://audit.example.test/gatekeep")?;
    sink.check_schema().await?;
    let entry = audit_entry()?;

    let first = sink.record_decision_audit(&entry).await?;
    let second = sink.record_decision_audit(&entry).await?;
    assert!(matches!(first, dovecote::EnqueueOutcome::Enqueued { .. }));
    assert!(matches!(
        second,
        dovecote::EnqueueOutcome::AlreadyEnqueued { .. }
    ));

    let row: (String, String, String, String, Vec<u8>, String) = sqlx::query_as(
        "SELECT stream, event_id, source, event_type, data, datacontenttype FROM dovecote_events",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.0, "gatekeep-audit");
    assert_eq!(row.1, "gatekeep-audit-decision-1");
    assert_eq!(row.2, "https://audit.example.test/gatekeep");
    assert_eq!(row.3, "gatekeep.decision_audit_recorded");
    assert_eq!(row.4, serde_json::to_vec(&entry)?);
    assert_eq!(row.5, "application/json");
    assert_eq!(
        scalar(&pool, "SELECT count(*) FROM dovecote_events").await?,
        1
    );
    assert_eq!(
        scalar(&pool, "SELECT count(*) FROM dovecote_deliveries").await?,
        1
    );
    Ok(())
}

#[tokio::test]
async fn identical_audit_identity_is_independent_per_tenant() -> Result<(), TestError> {
    let pool = database().await?;
    let sink = SqliteDovecoteAudit::new(pool.clone(), "https://audit.example.test/gatekeep")?;
    let entry_a = audit_entry_for_tenant("tenant-1")?;
    let entry_b = audit_entry_for_tenant("tenant-2")?;

    assert_eq!(entry_a.decision_audit_id, entry_b.decision_audit_id);
    sink.record_decision_audit(&entry_a).await?;
    sink.record_decision_audit(&entry_b).await?;

    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT tenant_id, source, event_id FROM dovecote_events ORDER BY row_id")
            .fetch_all(&pool)
            .await?;
    assert_eq!(rows.len(), 2);
    for (row, tenant) in rows.iter().zip(["tenant-1", "tenant-2"]) {
        assert_eq!(row.0, tenant);
        assert_eq!(row.1, "https://audit.example.test/gatekeep");
        assert_eq!(row.2, "gatekeep-audit-decision-1");
    }

    let adapter = dovecote_sqlx_sqlite::SqliteDovecote::new(pool);
    let page_a = adapter
        .for_tenant(dovecote::TenantId::new("tenant-1")?)
        .page(None, Limit::new(10)?)
        .await?;
    let page_b = adapter
        .for_tenant(dovecote::TenantId::new("tenant-2")?)
        .page(None, Limit::new(10)?)
        .await?;
    assert_eq!(page_a.len(), 1);
    assert_eq!(page_b.len(), 1);
    let config = sink.config();
    assert_eq!(decode_decision_audit(config, &page_a[0])?, entry_a);
    assert_eq!(decode_decision_audit(config, &page_b[0])?, entry_b);
    Ok(())
}

#[tokio::test]
async fn caller_transaction_rollback_removes_the_audit_event() -> Result<(), TestError> {
    let pool = database().await?;
    let sink = SqliteDovecoteAudit::new(pool.clone(), "https://audit.example.test/gatekeep")?;
    let entry = audit_entry()?;
    let mut transaction = dovecote_sqlx_sqlite::begin_write(&pool).await?;

    sink.record_decision_audit_in_transaction(&mut transaction, &entry)
        .await?;
    transaction.rollback().await?;

    assert_eq!(
        scalar(&pool, "SELECT count(*) FROM dovecote_events").await?,
        0
    );
    assert_eq!(
        scalar(&pool, "SELECT count(*) FROM dovecote_deliveries").await?,
        0
    );
    Ok(())
}

#[tokio::test]
async fn schema_check_and_record_fail_before_mutation_when_schema_is_missing()
-> Result<(), TestError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let sink = SqliteDovecoteAudit::new(pool, "https://audit.example.test/gatekeep")?;

    assert!(sink.check_schema().await.is_err());
    assert!(matches!(
        sink.record_decision_audit(&audit_entry()?).await,
        Err(gatekeep_sqlx::SqliteDovecoteAuditError::Dovecote(_))
    ));
    Ok(())
}

#[tokio::test]
async fn changed_payload_with_the_same_identity_is_a_typed_conflict() -> Result<(), TestError> {
    let pool = database().await?;
    let sink = SqliteDovecoteAudit::new(pool.clone(), "https://audit.example.test/gatekeep")?;
    let entry = audit_entry()?;
    sink.record_decision_audit(&entry).await?;

    let mut changed = entry;
    changed.request_id = Some(RequestId::new("request-2")?);
    let Err(error) = sink.record_decision_audit(&changed).await else {
        return Err(TestError::ExpectedConflict);
    };

    assert!(matches!(
        error,
        gatekeep_sqlx::SqliteDovecoteAuditError::Dovecote(
            dovecote_sqlx_sqlite::EnqueueError::IdempotencyConflict { .. }
        )
    ));
    assert_eq!(
        scalar(&pool, "SELECT count(*) FROM dovecote_events").await?,
        1
    );
    Ok(())
}

#[test]
fn source_configuration_requires_an_absolute_uri() {
    assert!(DecisionAuditConfig::new("gatekeep-audit").is_err());
    assert!(DecisionAuditConfig::new("https://audit.example.test/gatekeep").is_ok());
}

#[test]
fn typed_history_projection_decodes_live_or_snapshot_event_shape() -> Result<(), TestError> {
    let config = DecisionAuditConfig::new("https://audit.example.test/gatekeep")?;
    let entry = audit_entry()?;
    let event = NewEvent::builder(
        StreamName::new("gatekeep-audit")?,
        EventId::new("gatekeep-audit-decision-1")?,
        EventSource::new("https://audit.example.test/gatekeep")?,
        EventType::new("gatekeep.decision_audit_recorded")?,
    )
    .time(entry.occurred_at)
    .datacontenttype(ContentType::new("application/json")?)
    .data(EventData::json(serde_json::to_vec(&entry)?)?)
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
    assert_eq!(decode_decision_audit(&config, &page)?, entry);
    Ok(())
}

#[test]
fn current_decoder_rejects_reserved_legacy_identity_without_widening_new_ids()
-> Result<(), TestError> {
    let config = DecisionAuditConfig::new("https://audit.example.test/gatekeep")?;
    let entry = audit_entry()?;
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
    assert!(DecisionAuditId::new("legacy-outbox-42").is_err());
    assert!(DecisionAuditId::from_legacy_import("Legacy-outbox-42").is_err());
    assert!(DecisionAuditId::from_legacy_import("legacy-").is_err());
    Ok(())
}

#[test]
fn current_decoder_rejects_missing_binding_even_with_a_tenant_row() -> Result<(), TestError> {
    let config = DecisionAuditConfig::new("https://audit.example.test/gatekeep")?;
    let entry = audit_entry()?;
    let mut payload = serde_json::to_value(&entry)?;
    payload["binding"] = serde_json::Value::Null;
    let event = NewEvent::builder(
        StreamName::new("gatekeep-audit")?,
        EventId::new("gatekeep-audit-decision-1")?,
        EventSource::new("https://audit.example.test/gatekeep")?,
        EventType::new("gatekeep.decision_audit_recorded")?,
    )
    .time(entry.occurred_at)
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
    assert!(matches!(
        decode_decision_audit(&config, &page),
        Err(gatekeep_sqlx::DecisionAuditDecodeError::Entry(
            gatekeep::AuditEntryError::MissingBinding
        ))
    ));
    Ok(())
}

#[test]
fn tenant_aware_decoder_rejects_payload_row_tenant_mismatch() -> Result<(), TestError> {
    let config = DecisionAuditConfig::new("https://audit.example.test/gatekeep")?;
    let entry = audit_entry()?;
    let event = NewEvent::builder(
        StreamName::new("gatekeep-audit")?,
        EventId::new("gatekeep-audit-decision-1")?,
        EventSource::new("https://audit.example.test/gatekeep")?,
        EventType::new("gatekeep.decision_audit_recorded")?,
    )
    .time(entry.occurred_at)
    .datacontenttype(ContentType::new("application/json")?)
    .data(EventData::json(serde_json::to_vec(&entry)?)?)
    .build()?
    .into_stored()?;
    let page = dovecote::PagedEvent::new(
        dovecote::TenantId::new("tenant-2")?,
        dovecote::RowId::new(1)?,
        event,
        OffsetDateTime::UNIX_EPOCH,
        dovecote::DeliverySnapshot::pending(
            OffsetDateTime::UNIX_EPOCH,
            dovecote::AttemptCount::new(0)?,
            None,
        )?,
    )?;

    assert!(matches!(
        gatekeep_sqlx::decode_decision_audit(&config, &page),
        Err(gatekeep_sqlx::DecisionAuditDecodeError::UnexpectedShape { field: "tenant" })
    ));
    Ok(())
}

async fn database() -> Result<SqlitePool, TestError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    raw_sql(dovecote_sqlx_sqlite::MIGRATIONS[0].sql())
        .execute(&pool)
        .await?;
    Ok(pool)
}

async fn scalar(pool: &SqlitePool, sql: &'static str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(sql).fetch_one(pool).await
}

fn audit_entry() -> Result<AuditEntry, GatekeepError> {
    audit_entry_for_tenant("tenant-1")
}

fn audit_entry_for_tenant(tenant_name: &str) -> Result<AuditEntry, GatekeepError> {
    let tenant = TenantId::new(tenant_name)?;
    let missing = FactId::new("owner")?;
    let mut params = BTreeMap::new();
    params.insert(
        ParamKey::new("missing_fact")?,
        ReasonValue::Fact(missing.clone()),
    );
    let reason = DenialReason {
        code: ReasonCode::new("not_owner")?,
        params,
        shape: DenyShape::Forbidden,
    };
    let decisive = TraceClause::Deny {
        denied: None,
        unsatisfied: vec![missing.clone()],
        label: None,
        reason: Some(reason.code.clone()),
        shape: DenyShape::Forbidden,
    };
    Ok(AuditEntry {
        decision_audit_id: DecisionAuditId::new("decision-1")?,
        occurred_at: OffsetDateTime::UNIX_EPOCH,
        request_id: Some(RequestId::new("request-1")?),
        anchor: PolicyAnchor {
            policy_id: PolicyId::new("case-read")?,
            policy_hash: PolicyHash::new("hash")?,
        },
        effect: EffectKind::Deny,
        obligations: vec![ObligationId::new("record-denial")?],
        consulted: vec![(missing.clone(), Presence::Absent)],
        decisive: decisive.clone(),
        denial_reason: Some(reason),
        trace: Trace {
            consulted: vec![(missing, Presence::Absent)],
            decisive,
        },
        binding: Some(TenantBinding::TrustedService(
            TrustedServiceBinding::new(tenant.clone(), "gatekeep-sqlx-tests").map_err(|_| {
                GatekeepError::InvalidPolicyRecord {
                    reason: "test binding construction",
                }
            })?,
        )),
        fact_resolution: Some(
            FactResolutionEvidence::from_resolution(
                &FactResolution::new(
                    gatekeep::KnownFacts::new(),
                    None,
                    OffsetDateTime::UNIX_EPOCH,
                )
                .map_err(|_| GatekeepError::InvalidPolicyRecord {
                    reason: "test fact resolution freshness",
                })?,
            )
            .map_err(|_| GatekeepError::InvalidPolicyRecord {
                reason: "test fact evidence serialization",
            })?,
        ),
        tenant,
        principal: SubjectRef::new("user", "mari")?,
        subjects: BTreeMap::from([(SubjectSlot::new("case")?, SubjectRef::new("case", "123")?)]),
        locale: gatekeep::Locale::new("en-US")?,
    })
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Gatekeep(#[from] GatekeepError),
    #[error(transparent)]
    Config(#[from] gatekeep_sqlx::DecisionAuditConfigError),
    #[error(transparent)]
    Audit(#[from] gatekeep_sqlx::SqliteDovecoteAuditError),
    #[error(transparent)]
    Schema(#[from] dovecote_sqlx_sqlite::SchemaError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Dovecote(#[from] dovecote::ValidationError),
    #[error(transparent)]
    DovecoteEnqueue(#[from] dovecote_sqlx_sqlite::EnqueueError),
    #[error(transparent)]
    DovecotePage(#[from] dovecote_sqlx_sqlite::PageError),
    #[error(transparent)]
    Decode(#[from] gatekeep_sqlx::DecisionAuditDecodeError),
    #[error("changed content unexpectedly succeeded")]
    ExpectedConflict,
}
