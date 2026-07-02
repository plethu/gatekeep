use std::marker::PhantomData;

use async_trait::async_trait;
use gatekeep::{AuditEntry, AuditSink};
use serde::{Deserialize, Serialize};
use sqlx::Pool;

use crate::GatekeepSqlxBackend;

#[cfg(feature = "mysql")]
mod mysql;
#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "sqlite")]
mod sqlite;
mod support;

#[cfg(feature = "mysql")]
pub use self::mysql::MySqlDecisionAuditRepository;
#[cfg(feature = "postgres")]
pub use self::postgres::PgDecisionAuditRepository;
#[cfg(feature = "sqlite")]
pub use self::sqlite::SqliteDecisionAuditRepository;

/// Persisted decision audit entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionAuditRecord {
    /// Monotonic row id for cursor export.
    pub id: i64,
    /// Reconstructed typed audit entry.
    pub entry: AuditEntry,
}

/// `SQLx` audit repository errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SqlxAuditError {
    /// `SQLx` returned an error.
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    /// Audit entry JSON could not be encoded or decoded.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Inserted row id did not fit in the portable audit id type.
    #[error("audit row id {id} does not fit in i64")]
    IdOverflow {
        /// Backend row id.
        id: u64,
    },
}

/// SQLx-side decision audit contract.
#[async_trait]
pub trait SqlxAuditStore<B>: Send + Sync
where
    B: GatekeepSqlxBackend,
{
    /// Records one authorization decision.
    async fn record_decision_audit(&self, entry: &AuditEntry) -> Result<i64, SqlxAuditError>;

    /// Reads decision audit records in stable id order.
    async fn decision_audit_records(
        &self,
        after_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<DecisionAuditRecord>, SqlxAuditError>;
}

/// SQLx-backed decision audit repository.
#[derive(Debug)]
pub struct SqlxDecisionAuditRepository<B>
where
    B: GatekeepSqlxBackend,
{
    pub(crate) pool: Pool<B::Database>,
    backend: PhantomData<fn() -> B>,
}

impl<B> Clone for SqlxDecisionAuditRepository<B>
where
    B: GatekeepSqlxBackend,
{
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            backend: PhantomData,
        }
    }
}

impl<B> SqlxDecisionAuditRepository<B>
where
    B: GatekeepSqlxBackend,
{
    pub(crate) const fn from_pool(pool: Pool<B::Database>) -> Self {
        Self {
            pool,
            backend: PhantomData,
        }
    }
}

#[async_trait]
impl<B> AuditSink for SqlxDecisionAuditRepository<B>
where
    B: GatekeepSqlxBackend,
    Self: SqlxAuditStore<B>,
{
    type Error = SqlxAuditError;

    async fn record(&self, entry: &AuditEntry) -> Result<(), Self::Error> {
        self.record_decision_audit(entry).await?;
        Ok(())
    }
}
