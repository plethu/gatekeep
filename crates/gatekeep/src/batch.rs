use crate::{
    AuthorizationDecision, AuthorizationError, Clock, Context, FactId, FactResolution,
    FactResolver, KnownFacts, ResolveError,
};
use async_trait::async_trait;

/// Provider-owned bulk loading. No default loop pretends to eliminate N+1 reads.
///
/// Return exactly one result per context in input order. Keys must include the
/// tenant, principal, subject/action and source scope relevant to each check.
/// Providers may deduplicate compatible reads, but must not share observations
/// across incompatible contexts. Gatekeep does not maintain a cross-request cache.
#[async_trait]
pub trait BatchFactResolver: FactResolver {
    /// Resolves one policy's facts for a bounded group of contexts.
    async fn resolve_batch(
        &self,
        required: &[FactId],
        contexts: &[Context],
        clock: &dyn Clock,
    ) -> Result<
        Vec<Result<FactResolution<KnownFacts>, ResolveError<Self::Error>>>,
        ResolveError<Self::Error>,
    >;
}

/// Whole-batch failure before any decisions are evaluated or persisted.
#[derive(Debug, thiserror::Error)]
pub enum BatchError<E> {
    /// The caller exceeded its explicit resource bound.
    #[error("authorization batch exceeds configured limit")]
    Limit,
    /// Context at this position was invalid before loading began.
    #[error("invalid context at batch position {index}")]
    Context {
        /// Zero-based input position.
        index: usize,
        /// Context validation failure.
        #[source]
        source: crate::ContextError,
    },
    /// The provider could not execute its bulk load.
    #[error("batch source failed")]
    Resolve(#[source] ResolveError<E>),
    /// The provider violated the input/output cardinality contract.
    #[error("batch source returned {actual} results for {expected} inputs")]
    Cardinality {
        /// Input count.
        expected: usize,
        /// Output count.
        actual: usize,
    },
}

/// Ordered results retaining decisions and per-item failures, including denials.
///
/// Persistence is sequential and per item, not atomic across this batch.
/// Dropping the future cancels remaining work; earlier writes may already be
/// durable and the in-flight write may be uncertain. No background tasks survive.
#[derive(Debug)]
pub struct BatchDecisions<O, R, A> {
    /// One result per input position. Successful denials retain their audit record.
    pub results: Vec<Result<AuthorizationDecision<O>, AuthorizationError<R, A>>>,
}

impl<O, R, A> BatchDecisions<O, R, A> {
    /// Returns all decisions only if every item completed required persistence.
    ///
    /// # Errors
    /// Returns the entire batch, preserving all item evidence, if any failed.
    /// This controls response handling; it does not roll back previous writes.
    pub fn into_strict(self) -> Result<Vec<AuthorizationDecision<O>>, Self> {
        if self.results.iter().any(Result::is_err) {
            return Err(self);
        }

        Ok(self.results.into_iter().filter_map(Result::ok).collect())
    }
}
