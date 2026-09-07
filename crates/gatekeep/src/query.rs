use crate::{Context, FactId, ResidualPolicy};
use thiserror::Error;

/// Lowers a residual policy into a backend filter and grade projection.
pub trait QueryLowering<O> {
    /// Backend-specific boolean filter type.
    type Filter;
    /// Backend-specific grade projection type.
    type Projection;

    /// Lowers a residual policy for an authorized-list query.
    ///
    /// # Errors
    ///
    /// Returns [`LowerError`] when a residual fact has no backend mapping or
    /// the outcome lattice cannot be projected by the backend.
    fn lower(
        &self,
        residual: &ResidualPolicy<O>,
        cx: &Context,
    ) -> Result<Lowered<Self::Filter, Self::Projection>, LowerError>;
}

/// Backend filter and grade projection produced by query lowering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lowered<F, P> {
    /// Boolean filter selecting authorized rows.
    pub filter: F,
    /// Projection computing the row's granted outcome.
    pub grade: P,
}

/// Error returned by query-lowering adapters.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LowerError {
    /// A residual fact has no backend predicate.
    #[error("residual fact cannot be lowered: {0}")]
    Unlowerable(FactId),
    /// The outcome lattice cannot be represented as a total-order projection.
    #[error("graded projection requires a total order")]
    NonTotalGrade,
}
