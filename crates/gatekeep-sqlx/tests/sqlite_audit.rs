#![allow(missing_docs)]
#![cfg(feature = "sqlite-tests")]

use std::collections::BTreeMap;

use gatekeep::{
    AuditEntry, DenialReason, DenyShape, EffectKind, FactId, ObligationId, ParamKey, PolicyAnchor,
    PolicyHash, PolicyId, Presence, ReasonCode, ReasonValue, RequestId, SubjectRef, SubjectSlot,
    TenantId, Trace, TraceClause,
};
use gatekeep_sqlx::{SqliteDecisionAuditRepository, SqlxAuditStore};
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};

#[tokio::test]
async fn sqlite_records_and_queries_structured_audit_rows() -> TestResult<()> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    migrate(&pool).await?;
    let repo = SqliteDecisionAuditRepository::new(pool.clone());
    let entry = audit_entry()?;

    let id = repo.record_decision_audit(&entry).await?;
    let records = repo.decision_audit_records(None, 10).await?;

    assert_eq!(
        records,
        vec![gatekeep_sqlx::DecisionAuditRecord { id, entry }]
    );
    assert_eq!(
        scalar_i64(&pool, "select count(*) from gatekeep_audit_consulted_facts").await?,
        2
    );
    assert_eq!(
        scalar_i64(&pool, "select count(*) from gatekeep_audit_obligations").await?,
        1
    );
    assert_eq!(
        scalar_i64(
            &pool,
            "select count(*) from gatekeep_audit_request_subjects"
        )
        .await?,
        1
    );
    assert_eq!(
        scalar_i64(&pool, "select count(*) from gatekeep_audit_reason_params").await?,
        2
    );
    Ok(())
}

async fn migrate(pool: &SqlitePool) -> TestResult<()> {
    for statement in include_str!("../migrations/sqlite/0001_audit.sql").split(';') {
        if !statement.trim().is_empty() {
            sqlx::query(statement).execute(pool).await?;
        }
    }
    Ok(())
}

async fn scalar_i64(pool: &SqlitePool, sql: &'static str) -> TestResult<i64> {
    let row = sqlx::query(sql).fetch_one(pool).await?;
    Ok(row.try_get(0)?)
}

fn audit_entry() -> TestResult<AuditEntry> {
    let missing = FactId::new("case_owner")?;
    let mut params = BTreeMap::new();
    params.insert(
        ParamKey::new("missing_fact")?,
        ReasonValue::Fact(missing.clone()),
    );
    params.insert(
        ParamKey::new("case_id")?,
        ReasonValue::Str("case-123".to_owned()),
    );
    let denial_reason = DenialReason {
        code: ReasonCode::new("case-read-denied")?,
        params,
        shape: DenyShape::Forbidden,
    };
    let decisive = TraceClause::Deny {
        denied: None,
        unsatisfied: vec![missing.clone()],
        label: None,
        reason: Some(denial_reason.code.clone()),
        shape: DenyShape::Forbidden,
    };
    Ok(AuditEntry {
        request_id: Some(RequestId::new("req-1")?),
        anchor: PolicyAnchor {
            policy_id: PolicyId::new("case_read")?,
            policy_hash: PolicyHash::new("hash")?,
        },
        effect: EffectKind::Deny,
        obligations: vec![ObligationId::new("redact")?],
        consulted: vec![
            (FactId::new("staff")?, Presence::Present),
            (missing, Presence::Absent),
        ],
        decisive: decisive.clone(),
        denial_reason: Some(denial_reason),
        trace: Trace {
            consulted: vec![
                (FactId::new("staff")?, Presence::Present),
                (FactId::new("case_owner")?, Presence::Absent),
            ],
            decisive,
        },
        tenant: Some(TenantId::new("tenant-a")?),
        principal: Some(SubjectRef::new("user", "mari")?),
        subjects: BTreeMap::from([(
            SubjectSlot::new("case")?,
            SubjectRef::new("case", "case-123")?,
        )]),
    })
}

type TestResult<T> = Result<T, TestError>;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Gatekeep(#[from] gatekeep::GatekeepError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Audit(#[from] gatekeep_sqlx::SqlxAuditError),
}
