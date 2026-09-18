use super::Authorizer;
use crate::{AuditSink, AuthorizationError, Context, Lattice, PolicyObserver, PreparedPolicy};
use serde::Serialize;
use std::num::NonZeroUsize;

impl<R: crate::BatchFactResolver, A: AuditSink, W: PolicyObserver> Authorizer<R, A, W> {
    /// Performs one provider bulk load, then validates and persists each result.
    ///
    /// Every item is revalidated at its own enforcement boundary. There are no
    /// spawned tasks or cached permission results. Empty input performs no I/O.
    ///
    /// # Errors
    /// Returns a whole-batch error for size, initial scope, provider or cardinality
    /// failures. Per-item failures are retained in the returned ordered batch.
    pub async fn authorize_batch<O: Lattice + Serialize + Send + Sync>(
        &self,
        policy: &PreparedPolicy<O>,
        contexts: &[Context],
        limit: NonZeroUsize,
    ) -> Result<crate::BatchDecisions<O, R::Error, A::Error>, crate::BatchError<R::Error>> {
        if contexts.len() > limit.get() {
            return Err(crate::BatchError::Limit);
        }

        if contexts.is_empty() {
            return Ok(crate::BatchDecisions {
                results: Vec::new(),
            });
        }

        for (index, context) in contexts.iter().enumerate() {
            context
                .validate_at(self.clock.now_utc())
                .map_err(|source| crate::BatchError::Context { index, source })?;
        }

        let resolutions = self
            .resolver
            .resolve_batch(policy.required_facts(), contexts, self.clock.as_ref())
            .await
            .map_err(crate::BatchError::Resolve)?;
        if resolutions.len() != contexts.len() {
            return Err(crate::BatchError::Cardinality {
                expected: contexts.len(),
                actual: resolutions.len(),
            });
        }

        let mut results = Vec::with_capacity(contexts.len());
        for (context, resolution) in contexts.iter().zip(resolutions) {
            let result = match resolution {
                Ok(resolution) => {
                    self.finish(
                        policy.policy(),
                        policy.anchor(),
                        Some(policy.required_facts()),
                        context,
                        &resolution,
                    )
                    .await
                }

                Err(error) => Err(AuthorizationError::Resolve(error)),
            };
            results.push(result);
        }

        Ok(crate::BatchDecisions { results })
    }
}
