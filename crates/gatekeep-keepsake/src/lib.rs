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
mod target;

pub use binding::{FactBinding, FactBindingError, QueryPresence};
pub use error::{KeepsakeResolveError, KeepsakeTargetError};
#[cfg(feature = "in-memory")]
pub use keepsake::{ActiveRelationSeed, InMemoryActiveRelations, InMemoryActiveRelationsError};
pub use keepsake::{ActiveRelationSource, DynActiveRelationSource};
pub use resolver::KeepsakeResolver;
pub use subject::{
    PrincipalSubjectMapper, SubjectMapper, TenantScopedSubjectMapper, principal_subject,
    tenant_scoped_subject,
};
pub use target::KeepsakeRelationTarget;
