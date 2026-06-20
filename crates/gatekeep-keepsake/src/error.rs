use gatekeep::GatekeepError;
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
