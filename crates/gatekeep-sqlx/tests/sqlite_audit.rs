#![allow(missing_docs)]
#![cfg(feature = "sqlite-tests")]

#[path = "audit_support/mod.rs"]
mod audit_support;

use audit_support::audit_entry;
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
