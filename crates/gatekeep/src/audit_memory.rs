use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use thiserror::Error;

use crate::{AuditEntry, AuditEntryError, AuditSink};

/// Error returned by the in-memory audit sink.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum InMemoryAuditError {
    /// The entry was not a valid current decision record.
    #[error(transparent)]
    InvalidEntry(#[from] AuditEntryError),
    /// The shared test buffer was poisoned by a previous panic.
    #[error("in-memory audit sink buffer is poisoned")]
    Poisoned,
}

/// Shared-buffer audit sink for tests and examples.
#[derive(Debug, Clone, Default)]
pub struct InMemoryAuditSink {
    // Test-only shared buffer for asserting emitted audit entries. Production
    // audit sinks should write to durable storage instead of sharing a mutex.
    entries: Arc<Mutex<Vec<AuditEntry>>>,
}

impl InMemoryAuditSink {
    /// Returns the entries recorded so far.
    ///
    /// # Errors
    ///
    /// Returns [`InMemoryAuditError::Poisoned`] when a previous panic poisoned
    /// the shared test buffer.
    pub fn entries(&self) -> Result<Vec<AuditEntry>, InMemoryAuditError> {
        self.entries
            .lock()
            .map_err(|_| InMemoryAuditError::Poisoned)
            .map(|entries| entries.clone())
    }
}

#[async_trait]
impl AuditSink for InMemoryAuditSink {
    type Error = InMemoryAuditError;

    async fn record(&self, entry: &AuditEntry) -> Result<(), Self::Error> {
        entry.validate_current()?;
        self.entries
            .lock()
            .map_err(|_| InMemoryAuditError::Poisoned)?
            .push(entry.clone());
        Ok(())
    }
}
