//! Code-first authorization primitives for deterministic Rust policy evaluation.
//!
//! Human guides and reference material are in the `docs/` directory of the
//! repository. API reference: <https://docs.rs/gatekeep>.

#![forbid(unsafe_code)]

mod audit;
#[cfg(any(test, feature = "test"))]
mod audit_memory;
mod context;
mod decision;
mod evaluate;
mod facts;
mod hooks;
mod identity;
mod partial;
mod policy_model;
mod query;
mod resolution;
mod tenant;

/// Condition builder helpers.
pub mod condition;
/// Policy builder helpers.
pub mod policy;

pub use audit::{
    AUDIT_ENTRY_SCHEMA_VERSION, AuditEntry, AuditEntryError, DecisionSummary, EffectKind,
    LegacyAuditEntry, LegacyPolicyAnchor, PolicyAnchor,
};
#[cfg(any(test, feature = "test"))]
pub use audit_memory::{InMemoryAuditError, InMemoryAuditSink};
pub use context::{Clock, Context, ContextError, SystemClock};
pub use decision::{
    Decision, DecisionTrace, DecisiveClause, DenialReason, DenyShape, Effect, ReasonValue, Trace,
    TraceClause, TraceError,
};
pub use evaluate::{
    POLICY_HASH_FORMAT_VERSION, evaluate, evaluate_residual, required_facts,
    required_residual_facts,
};
pub use facts::{KnownFacts, PartialFacts, Presence, TraceValue};
pub use hooks::{
    AuditSink, IdentityReasonCatalog, NoopAuditSink, NoopPolicyObserver, PolicyObserver,
    ReasonCatalog,
};
pub use identity::{
    ClauseLabel, DecisionAuditId, DecisionAuditOccurrence, DecisionAuditOccurrenceError, Fact,
    FactId, GatekeepError, GatekeepResult, Locale, MAX_TENANT_ID_BYTES, ObligationId,
    ObligationSpec, ParamKey, PolicyHash, PolicyId, ReasonCode, RequestId, StaticClauseLabel,
    StaticFactId, StaticObligationId, StaticParamKey, StaticReasonCode, StaticRequestId,
    StaticSubjectSlot, StaticTenantId, SubjectRef, SubjectSlot, TenantId,
};
pub use partial::{Residual, complete_residual, partial_evaluate};
pub use policy_model::{
    Condition, Lattice, Policy, ResidualPolicy, ResidualPolicyBranch, ResidualPolicyNode,
};
pub use query::{LowerError, Lowered, QueryLowering};
pub use resolution::{
    FactResolution, FactResolutionError, FactResolutionEvidence, FactResolutionEvidenceError,
    FactResolutionMetadata, FactResolver, ResolveError,
};
pub use tenant::{
    ApplicationVerifiedTenantBinding, BindingAuthority, BindingProvenance, EvidenceDigest,
    TenantBinding, TenantBindingError, TenantBindingEvidence, TrustedServiceBinding,
};
