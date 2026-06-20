//! Keepsake-backed fact resolution for gatekeep.
//!
//! The adapter maps gatekeep `FactId`s to keepsake relation ids. Full decisions
//! resolve those facts from the principal's active keepsakes. Query resolution
//! can either do the same request-scoped lookup or mark selected facts as
//! `Unknown` so a later `QueryLowering` adapter can turn them into row
//! predicates.

#![forbid(unsafe_code)]

mod binding;
mod error;
mod resolver;
mod subject;

pub use binding::{FactBinding, FactBindingError, QueryPresence};
pub use error::KeepsakeResolveError;
pub use keepsake::ActiveRelationSource;
pub use resolver::KeepsakeResolver;
pub use subject::{PrincipalSubjectMapper, SubjectMapper, TenantScopedSubjectMapper};
