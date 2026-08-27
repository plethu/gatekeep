use async_trait::async_trait;
use gatekeep::{AuditEntry, AuditSink};
use sqlx::{Sqlite, SqlitePool, Transaction};

use dovecote::EnqueueOutcome;
use dovecote_sqlx_sqlite::SqliteDovecote;

use super::{
    DecisionAuditConfig, DecisionAuditConfigError, DecisionAuditEventError, event_from_entry,
};

/// `SQLite` Dovecote-backed decision audit sink.
#[derive(Clone)]
pub struct SqliteDovecoteAudit {
    dovecote: SqliteDovecote,
    config: DecisionAuditConfig,
}

impl SqliteDovecoteAudit {
    /// Creates a sink using an application-owned absolute source URI.
    ///
    /// # Errors
    ///
    /// Returns an error when `source` is not an absolute URI.
    pub fn new(
        pool: SqlitePool,
        source: impl Into<String>,
    ) -> Result<Self, DecisionAuditConfigError> {
        let config = DecisionAuditConfig::new(source)?;
        Ok(Self::from_config(pool, config))
    }

    /// Creates a sink from validated configuration.
    #[must_use]
    pub fn from_config(pool: SqlitePool, config: DecisionAuditConfig) -> Self {
        Self {
            dovecote: SqliteDovecote::new(pool),
            config,
        }
    }

    /// Returns the configuration used for newly constructed events.
    #[must_use]
    pub const fn config(&self) -> &DecisionAuditConfig {
        &self.config
    }

    /// Verifies that the selected database has the installed Dovecote schema.
    ///
    /// # Errors
    ///
    /// Returns the typed Dovecote schema error when the schema is absent or
    /// incompatible.
    pub async fn check_schema(&self) -> Result<(), dovecote_sqlx_sqlite::SchemaError> {
        self.dovecote.check_schema().await
    }

    /// Records an audit event in a transaction owned by this sink.
    ///
    /// `SQLite` uses Dovecote's `BEGIN IMMEDIATE` write transaction so schema
    /// reads and the event write cannot race another writer.
    ///
    /// # Errors
    ///
    /// Returns a typed event, Dovecote, or `SQLx` transaction error.
    pub async fn record_decision_audit(
        &self,
        entry: &AuditEntry,
    ) -> Result<EnqueueOutcome, SqliteDovecoteAuditError> {
        let mut transaction = self.dovecote.begin_write().await?;
        let outcome = self
            .record_decision_audit_in_transaction(&mut transaction, entry)
            .await?;
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Records an audit event in a caller-owned `SQLite` transaction.
    ///
    /// The caller must provide the immediate write transaction returned by
    /// [`SqliteDovecote::begin_write`] and must commit or roll it back. The
    /// operation is atomic with other writes in that transaction, but not with
    /// arbitrary business-state writes performed in another transaction.
    ///
    /// # Errors
    ///
    /// Returns a typed event or Dovecote error. The caller remains responsible
    /// for rolling back after an error.
    pub async fn record_decision_audit_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Sqlite>,
        entry: &AuditEntry,
    ) -> Result<EnqueueOutcome, SqliteDovecoteAuditError> {
        let event = event_from_entry(&self.config, entry)?;
        Ok(self.dovecote.enqueue(transaction, event).await?)
    }
}

/// Errors returned by [`SqliteDovecoteAudit`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SqliteDovecoteAuditError {
    /// The typed entry could not be converted to a Dovecote event.
    #[error(transparent)]
    Event(#[from] DecisionAuditEventError),
    /// Dovecote rejected the event or database operation.
    #[error(transparent)]
    Dovecote(#[from] dovecote_sqlx_sqlite::EnqueueError),
    /// The sink-owned transaction could not begin or commit.
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
impl AuditSink for SqliteDovecoteAudit {
    type Error = SqliteDovecoteAuditError;

    async fn record(&self, entry: &AuditEntry) -> Result<(), Self::Error> {
        self.record_decision_audit(entry).await.map(|_| ())
    }
}
