use crate::{AuditEntry, Decision};

/// An evaluated decision awaiting required persistence, not an authorization token.
///
/// The event is immutable. Retry its write using the same value, including its
/// observation time and occurrence identity. A new evaluation is a new event.
#[derive(Clone, Debug)]
pub struct PendingDecision<O> {
    decision: Decision<O>,
    entry: AuditEntry,
}

impl<O> PendingDecision<O> {
    pub(crate) const fn new(decision: Decision<O>, entry: AuditEntry) -> Self {
        Self { decision, entry }
    }

    /// Borrows the frozen event for an application-owned transaction or export.
    #[must_use]
    pub const fn entry(&self) -> &AuditEntry {
        &self.entry
    }

    /// Inspects the provisional decision. Required persistence has not succeeded.
    #[must_use]
    pub const fn decision(&self) -> &Decision<O> {
        &self.decision
    }
}
