use gatekeep_sqlx::{PgDecisionAuditRepository, SqlxAuditStore};
use sqlx::{PgPool, Row};

use crate::{
    audit_support::audit_entry,
    support::{TestResult, pool},
};

#[tokio::test]
#[ignore = "requires docker postgres; run `make test-db`"]
async fn records_and_queries_structured_audit_rows() -> TestResult<()> {
    let pool = pool().await?;
    reset_audit_schema(&pool).await?;
    let repo = PgDecisionAuditRepository::new(pool.clone());
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
    assert_eq!(
        scalar_i64(&pool, "select count(*) from gatekeep_audit_outbox").await?,
        1
    );
    Ok(())
}

async fn reset_audit_schema(pool: &PgPool) -> TestResult<()> {
    for statement in [
        "drop table if exists gatekeep_audit_outbox",
        "drop table if exists gatekeep_audit_reason_params",
        "drop table if exists gatekeep_audit_request_subjects",
        "drop table if exists gatekeep_audit_obligations",
        "drop table if exists gatekeep_audit_consulted_facts",
        "drop table if exists gatekeep_audit_decisions",
    ] {
        sqlx::query(statement).execute(pool).await?;
    }

    for statement in include_str!("../../migrations/postgres/0001_audit.sql").split(';') {
        if !statement.trim().is_empty() {
            sqlx::query(statement).execute(pool).await?;
        }
    }
    Ok(())
}

async fn scalar_i64(pool: &PgPool, sql: &'static str) -> TestResult<i64> {
    let row = sqlx::query(sql).fetch_one(pool).await?;
    Ok(row.try_get(0)?)
}
