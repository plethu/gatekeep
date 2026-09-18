use thiserror::Error;

/// Error produced while resolving, evaluating, tracing, or auditing a decision.
#[derive(Debug, Error)]
pub enum AuthorizationError<Resolve, Audit> {
    /// The request context failed tenant-binding validation before facts were
    /// resolved.
    #[error(transparent)]
    Context(#[from] crate::ContextError),
    /// Policy hashing failed before the decision could be anchored.
    #[error("failed to hash policy")]
    PolicyHash(#[source] postcard::Error),
    /// Fact resolution failed before evaluation.
    #[error(transparent)]
    Resolve(#[from] crate::ResolveError<Resolve>),
    /// Resolved fact-set evidence could not be serialized.
    #[error(transparent)]
    FactResolutionEvidence(#[from] crate::FactResolutionEvidenceError),
    /// The current audit entry failed its tenant-binding invariants.
    #[error(transparent)]
    AuditEntry(#[from] crate::AuditEntryError),
    /// Trace serialization failed after evaluation.
    #[error(transparent)]
    Trace(#[from] crate::TraceError),
    /// The captured decision occurrence could not cross the Dovecote time
    /// boundary without changing its meaning.
    #[error(transparent)]
    Occurrence(#[from] crate::DecisionAuditOccurrenceError),
    /// Audit recording failed.
    #[error("audit sink failed")]
    Audit {
        /// Reusable identity and occurrence time for an ambiguous retry.
        occurrence: crate::DecisionAuditOccurrence,
        /// Sink-specific failure.
        #[source]
        source: Audit,
    },
}

impl<Resolve, Audit> AuthorizationError<Resolve, Audit> {
    /// Returns the occurrence that was used when audit persistence failed.
    #[must_use]
    pub const fn audit_occurrence(&self) -> Option<&crate::DecisionAuditOccurrence> {
        match self {
            Self::Audit { occurrence, .. } => Some(occurrence),
            Self::Context(_)
            | Self::PolicyHash(_)
            | Self::Resolve(_)
            | Self::FactResolutionEvidence(_)
            | Self::AuditEntry(_)
            | Self::Trace(_)
            | Self::Occurrence(_) => None,
        }
    }
}
