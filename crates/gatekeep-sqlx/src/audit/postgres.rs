use async_trait::async_trait;
use gatekeep::{AuditEntry, AuditSink};
use sqlx::{PgPool, Postgres, Transaction};

use dovecote::EnqueueOutcome;
use dovecote_sqlx_postgres::PostgresDovecote;

use super::{
    DecisionAuditConfig, DecisionAuditConfigError, DecisionAuditEventError, event_from_entry,
};

/// Postgres Dovecote-backed decision audit sink.
#[derive(Clone)]
pub struct PgDovecoteAudit {
    dovecote: PostgresDovecote,
    config: DecisionAuditConfig,
}

impl PgDovecoteAudit {
    /// Creates a sink using an application-owned absolute source URI.
    ///
    /// # Errors
    ///
    /// Returns an error when `source` is not an absolute URI.
    pub fn new(pool: PgPool, source: impl Into<String>) -> Result<Self, DecisionAuditConfigError> {
        let config = DecisionAuditConfig::new(source)?;
        Ok(Self::from_config(pool, config))
    }

    /// Creates a sink from validated configuration.
    #[must_use]
    pub fn from_config(pool: PgPool, config: DecisionAuditConfig) -> Self {
        Self {
            dovecote: PostgresDovecote::new(pool),
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
    pub async fn check_schema(&self) -> Result<(), dovecote_sqlx_postgres::SchemaError> {
        self.dovecote.check_schema().await
    }

    /// Records an audit event in a transaction owned by this sink.
    ///
    /// This is atomic between the Dovecote event and its pending delivery. Use
    /// [`Self::record_decision_audit_in_transaction`] when an application must
    /// include the event in its own transaction boundary.
    ///
    /// # Errors
    ///
    /// Returns a typed event, Dovecote, or `SQLx` transaction error.
    pub async fn record_decision_audit(
        &self,
        entry: &AuditEntry,
    ) -> Result<EnqueueOutcome, PgDovecoteAuditError> {
        let mut transaction = self.dovecote.pool().begin().await?;
        let outcome = self
            .record_decision_audit_in_transaction(&mut transaction, entry)
            .await?;
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Records an audit event in a caller-owned Postgres transaction.
    ///
    /// The caller must commit or roll back the transaction. The operation is
    /// atomic with other writes in that transaction, but not with arbitrary
    /// business-state writes performed in another transaction.
    ///
    /// # Errors
    ///
    /// Returns a typed event or Dovecote error. The caller remains responsible
    /// for rolling back after an error.
    pub async fn record_decision_audit_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        entry: &AuditEntry,
    ) -> Result<EnqueueOutcome, PgDovecoteAuditError> {
        let event = event_from_entry(&self.config, entry)?;
        Ok(self.dovecote.enqueue(transaction, event).await?)
    }
}

/// Errors returned by [`PgDovecoteAudit`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PgDovecoteAuditError {
    /// The typed entry could not be converted to a Dovecote event.
    #[error(transparent)]
    Event(#[from] DecisionAuditEventError),
    /// Dovecote rejected the event or database operation.
    #[error(transparent)]
    Dovecote(#[from] dovecote_sqlx_postgres::EnqueueError),
    /// The sink-owned transaction could not begin or commit.
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
impl AuditSink for PgDovecoteAudit {
    type Error = PgDovecoteAuditError;

    async fn record(&self, entry: &AuditEntry) -> Result<(), Self::Error> {
        self.record_decision_audit(entry).await.map(|_| ())
    }
}
