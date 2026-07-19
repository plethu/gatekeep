use async_trait::async_trait;
use gatekeep::AuditEntry;
use sqlx::Transaction;

use super::support::{
    deny_shape_label, effect_label, position_i32, presence_label, records_from_json_rows,
};
use super::{DecisionAuditRecord, SqlxAuditError, SqlxAuditStore, SqlxDecisionAuditRepository};

/// Postgres-backed decision audit repository.
pub type PgDecisionAuditRepository = SqlxDecisionAuditRepository<crate::PostgresBackend>;

impl PgDecisionAuditRepository {
    /// Creates a repository from a Postgres pool.
    #[must_use]
    pub const fn new(pool: sqlx::PgPool) -> Self {
        Self::from_pool(pool)
    }
}

#[async_trait]
impl SqlxAuditStore<crate::PostgresBackend> for PgDecisionAuditRepository {
    async fn record_decision_audit(&self, entry: &AuditEntry) -> Result<i64, SqlxAuditError> {
        let mut tx = self.pool.begin().await?;
        let denial_reason_json = entry
            .denial_reason
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let id = sqlx::query_scalar::<_, i64>(
            r"
            insert into gatekeep_audit_decisions
              (request_id, policy_id, policy_hash, effect, trace, decisive_clause,
               denial_reason_code, denial_reason_shape, denial_reason, entry)
            values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            returning id
            ",
        )
        .bind(entry.request_id.as_ref().map(gatekeep::RequestId::as_str))
        .bind(entry.anchor.policy_id.as_str())
        .bind(entry.anchor.policy_hash.as_str())
        .bind(effect_label(entry))
        .bind(serde_json::to_value(&entry.trace)?)
        .bind(serde_json::to_value(&entry.decisive)?)
        .bind(
            entry
                .denial_reason
                .as_ref()
                .map(|reason| reason.code.as_str()),
        )
        .bind(
            entry
                .denial_reason
                .as_ref()
                .map(|reason| deny_shape_label(reason.shape)),
        )
        .bind(denial_reason_json)
        .bind(serde_json::to_value(entry)?)
        .fetch_one(&mut *tx)
        .await?;
        insert_children(&mut tx, id, entry).await?;
        insert_outbox(&mut tx, id, entry).await?;
        tx.commit().await?;
        Ok(id)
    }

    async fn decision_audit_records(
        &self,
        after_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<DecisionAuditRecord>, SqlxAuditError> {
        let rows = sqlx::query(
            "select id, entry from gatekeep_audit_decisions where ($1::bigint is null or id > $1) order by id limit $2",
        )
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        records_from_json_rows(rows)
    }
}

async fn insert_children(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    decision_id: i64,
    entry: &AuditEntry,
) -> Result<(), SqlxAuditError> {
    for (position, obligation) in entry.obligations.iter().enumerate() {
        sqlx::query(
            "insert into gatekeep_audit_obligations (decision_id, position, obligation_id) values ($1, $2, $3)",
        )
        .bind(decision_id)
        .bind(position_i32(position))
        .bind(obligation.as_str())
        .execute(&mut **tx)
        .await?;
    }

    for (position, (fact, presence)) in entry.consulted.iter().enumerate() {
        sqlx::query(
            "insert into gatekeep_audit_consulted_facts (decision_id, position, fact_id, presence) values ($1, $2, $3, $4)",
        )
        .bind(decision_id)
        .bind(position_i32(position))
        .bind(fact.as_str())
        .bind(presence_label(*presence))
        .execute(&mut **tx)
        .await?;
    }

    for (slot, subject) in &entry.subjects {
        sqlx::query(
            "insert into gatekeep_audit_request_subjects (decision_id, slot, subject_kind, subject_id) values ($1, $2, $3, $4)",
        )
        .bind(decision_id)
        .bind(slot.as_str())
        .bind(subject.kind())
        .bind(subject.id())
        .execute(&mut **tx)
        .await?;
    }

    if let Some(reason) = &entry.denial_reason {
        for (key, value) in &reason.params {
            sqlx::query(
                "insert into gatekeep_audit_reason_params (decision_id, key, value) values ($1, $2, $3)",
            )
            .bind(decision_id)
            .bind(key.as_str())
            .bind(serde_json::to_value(value)?)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

async fn insert_outbox(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    decision_id: i64,
    entry: &AuditEntry,
) -> Result<(), SqlxAuditError> {
    sqlx::query("insert into gatekeep_audit_outbox (decision_id, payload) values ($1, $2)")
        .bind(decision_id)
        .bind(serde_json::to_value(entry)?)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
