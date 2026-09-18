use std::error::Error;

use async_trait::async_trait;
use serde::Serialize;

use crate::{Clock, Context, FactResolution, KnownFacts, Lattice, PreparedPolicy, ResolveError};

/// Application-owned operations and named checks for one resource type.
///
/// Implement this with ordinary Rust functions and services. The associated
/// action is normally an enum; there is no global registry or string dispatch.
/// Each action selects a prepared policy. Resolution supplies explicit boolean
/// observations for its facts and propagates load errors with `?`.
///
/// The implementation must verify that principal and resource belong to the
/// supplied authenticated context. SQL mapping remains an explicit separate
/// contract; arbitrary Rust checks cannot be translated into SQL.
#[async_trait]
pub trait ResourcePolicy: Send + Sync {
    /// Application principal type.
    type Principal: Sync;
    /// Protected application resource.
    type Resource: Sync;
    /// Application operation, normally an enum.
    type Action: Sync;
    /// Granted value; use `()` for ordinary permit/deny.
    type Outcome: Lattice + Serialize + Send + Sync;
    /// Application check failure.
    type Error: Error + Send + Sync + 'static;

    /// Selects the immutable policy for this operation.
    fn policy(&self, action: &Self::Action) -> &PreparedPolicy<Self::Outcome>;

    /// Observes the required named checks for these domain values.
    ///
    /// Use the supplied clock, report false explicitly, and never turn a failed
    /// source read into false. Do not retain documents or credentials in evidence.
    async fn resolve(
        &self,
        action: &Self::Action,
        principal: &Self::Principal,
        resource: &Self::Resource,
        context: &Context,
        clock: &dyn Clock,
    ) -> Result<FactResolution<KnownFacts>, ResolveError<Self::Error>>;
}
