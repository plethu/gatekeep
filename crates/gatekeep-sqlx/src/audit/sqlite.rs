use async_trait::async_trait;
use gatekeep::{AuditEntry, ReasonValue};
use sqlx::Transaction;

use super::support::{
    deny_shape_label, effect_label, position_i32, presence_label, records_from_text_rows,
};
use super::{DecisionAuditRecord, SqlxAuditError, SqlxAuditStore, SqlxDecisionAuditRepository};

/// SQLite-backed decision audit repository.
pub type SqliteDecisionAuditRepository = SqlxDecisionAuditRepository<crate::SqliteBackend>;

impl SqliteDecisionAuditRepository {
    /// Creates a repository from a `SQLite` pool.
    #[must_use]
    pub const fn new(pool: sqlx::SqlitePool) -> Self {
        Self::from_pool(pool)
    }
}

#[async_trait]
impl SqlxAuditStore<crate::SqliteBackend> for SqliteDecisionAuditRepository {
    async fn record_decision_audit(&self, entry: &AuditEntry) -> Result<i64, SqlxAuditError> {
        let entry_json = serde_json::to_string(entry)?;
        let trace_json = serde_json::to_string(&entry.trace)?;
        let decisive_json = serde_json::to_string(&entry.decisive)?;
        let denial_reason_json = entry
            .denial_reason
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r"
            insert into gatekeep_audit_decisions
              (request_id, policy_id, policy_hash, effect, trace, decisive_clause,
               denial_reason_code, denial_reason_shape, denial_reason, entry)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ",
        )
        .bind(entry.request_id.as_ref().map(gatekeep::RequestId::as_str))
        .bind(entry.anchor.policy_id.as_str())
        .bind(entry.anchor.policy_hash.as_str())
        .bind(effect_label(entry))
        .bind(trace_json)
        .bind(decisive_json)
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
        .bind(entry_json)
        .execute(&mut *tx)
        .await?;
        let id = sqlx::query_scalar::<_, i64>("select last_insert_rowid()")
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
            "select id, entry from gatekeep_audit_decisions where (? is null or id > ?) order by id limit ?",
        )
        .bind(after_id)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        records_from_text_rows(rows)
    }
}

async fn insert_children(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    decision_id: i64,
    entry: &AuditEntry,
) -> Result<(), SqlxAuditError> {
    for (position, obligation) in entry.obligations.iter().enumerate() {
        sqlx::query(
            "insert into gatekeep_audit_obligations (decision_id, position, obligation_id) values (?, ?, ?)",
        )
        .bind(decision_id)
        .bind(position_i32(position))
        .bind(obligation.as_str())
        .execute(&mut **tx)
        .await?;
    }
    for (position, (fact, presence)) in entry.consulted.iter().enumerate() {
        sqlx::query(
            "insert into gatekeep_audit_consulted_facts (decision_id, position, fact_id, presence) values (?, ?, ?, ?)",
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
            "insert into gatekeep_audit_request_subjects (decision_id, slot, subject_kind, subject_id) values (?, ?, ?, ?)",
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
                "insert into gatekeep_audit_reason_params (decision_id, key, value) values (?, ?, ?)",
            )
            .bind(decision_id)
            .bind(key.as_str())
            .bind(reason_value_json(value)?)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

async fn insert_outbox(
    tx: &mut Transaction<'_, sqlx::Sqlite>,
    decision_id: i64,
    entry: &AuditEntry,
) -> Result<(), SqlxAuditError> {
    sqlx::query("insert into gatekeep_audit_outbox (decision_id, payload) values (?, ?)")
        .bind(decision_id)
        .bind(serde_json::to_string(entry)?)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn reason_value_json(value: &ReasonValue) -> Result<String, SqlxAuditError> {
    serde_json::to_string(value).map_err(SqlxAuditError::from)
}
