use gatekeep::{FactId, GatekeepError, SubjectSlot};
use keepsake::KeepsakeError;
use thiserror::Error;

/// Backend error emitted by [`crate::KeepsakeResolver`].
#[derive(Debug, Error)]
pub enum KeepsakeResolveError<E> {
    /// Gatekeep and keepsake subject validation drifted apart.
    #[error(transparent)]
    Subject(#[from] KeepsakeError),
    /// The active-relation source failed.
    #[error("keepsake relation source failed")]
    Source(#[source] E),
    /// Gatekeep refused a constructed known-fact bundle.
    #[error(transparent)]
    Gatekeep(#[from] GatekeepError),
}

/// Errors returned while resolving a gatekeep fact into a keepsake target.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KeepsakeTargetError {
    /// The resolver has no binding for the requested fact.
    #[error("no keepsake binding configured for fact {fact}")]
    MissingBinding {
        /// Unbound fact id.
        fact: FactId,
    },

    /// The binding targets a request-scoped subject slot missing from the context.
    #[error("context is missing subject slot {slot} for fact {fact}")]
    MissingSubjectSlot {
        /// Fact whose binding needs the subject.
        fact: FactId,
        /// Missing subject slot.
        slot: SubjectSlot,
    },

    /// Gatekeep and keepsake subject validation drifted apart.
    #[error("keepsake subject validation failed for fact {fact}")]
    Subject {
        /// Fact whose target subject could not be built.
        fact: FactId,
        /// Validation failure from keepsake.
        #[source]
        source: KeepsakeError,
    },
}
