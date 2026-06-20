use async_trait::async_trait;
use keepsake::{Keepsake, KeepsakeStore, SubjectRef};

/// Async source of active keepsake relations for a subject.
#[async_trait]
pub trait ActiveRelationSource: Send + Sync {
    /// Source-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns active keepsakes for the mapped subject.
    async fn active_for_subject(&self, subject: &SubjectRef) -> Result<Vec<Keepsake>, Self::Error>;
}

/// Adapter for synchronous [`KeepsakeStore`] implementations.
#[derive(Clone, Debug)]
pub struct SyncKeepsakeStore<S> {
    store: S,
}

impl<S> SyncKeepsakeStore<S> {
    /// Wraps a synchronous keepsake store.
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Returns the wrapped store.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }
}

#[async_trait]
impl<S> ActiveRelationSource for SyncKeepsakeStore<S>
where
    S: KeepsakeStore,
{
    type Error = S::Error;

    async fn active_for_subject(&self, subject: &SubjectRef) -> Result<Vec<Keepsake>, Self::Error> {
        self.store.active_for_subject(subject)
    }
}

#[cfg(feature = "sqlx")]
#[async_trait]
impl<C> ActiveRelationSource for keepsake_sqlx::KeepsakeRepository<C>
where
    C: keepsake_sqlx::RelationCache,
{
    type Error = keepsake_sqlx::RepositoryError;

    async fn active_for_subject(&self, subject: &SubjectRef) -> Result<Vec<Keepsake>, Self::Error> {
        Self::active_for_subject(self, subject).await
    }
}
