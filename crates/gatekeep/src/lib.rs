//! Code-first authorization primitives for deterministic Rust policy evaluation.
//!
//! Human guides and reference material are in the `docs/` directory of the
//! repository. API reference: <https://docs.rs/gatekeep>.

#![forbid(unsafe_code)]

mod adapters;
#[cfg(any(test, feature = "test"))]
mod audit_memory;
mod decision;
mod evaluate;
mod facts;
mod identity;
mod partial;
mod policy_model;
mod tenant;

/// Condition builder helpers.
pub mod condition;
/// Policy builder helpers.
pub mod policy;

pub use adapters::{
    AuditEntry, AuditEntryError, AuditSink, Clock, Context, ContextError, DecisionSummary,
    EffectKind, FactResolution, FactResolutionError, FactResolutionEvidence,
    FactResolutionEvidenceError, FactResolutionMetadata, FactResolver, IdentityReasonCatalog,
    LowerError, Lowered, NoopAuditSink, NoopPolicyObserver, PolicyAnchor, PolicyObserver,
    QueryLowering, ReasonCatalog, ResolveError, SystemClock,
};
#[cfg(any(test, feature = "test"))]
pub use audit_memory::{InMemoryAuditError, InMemoryAuditSink};
pub use decision::{
    Decision, DecisionTrace, DecisiveClause, DenialReason, DenyShape, Effect, ReasonValue, Trace,
    TraceClause, TraceError,
};
pub use evaluate::{evaluate, evaluate_residual, required_facts, required_residual_facts};
pub use facts::{KnownFacts, PartialFacts, Presence, TraceValue};
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
pub use tenant::{
    ApplicationVerifiedTenantBinding, BindingAuthority, BindingProvenance, EvidenceDigest,
    TenantBinding, TenantBindingError, TenantBindingEvidence, TrustedServiceBinding,
};
