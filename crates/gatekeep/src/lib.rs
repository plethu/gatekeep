//! Code-first authorization primitives for deterministic Rust policy evaluation.
//!
//! The crate provides the pure gatekeep core: stable fact identities, reified
//! policy values, synchronous evaluation, partial evaluation for query lowering,
//! and adapter traits for application-owned IO boundaries.

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

/// Condition builder helpers.
pub mod condition;
/// Policy builder helpers.
pub mod policy;

pub use adapters::{
    AuditEntry, AuditSink, Context, DecisionSummary, EffectKind, FactResolver,
    IdentityReasonCatalog, LowerError, Lowered, NoopAuditSink, NoopPolicyObserver, PolicyAnchor,
    PolicyObserver, QueryLowering, ReasonCatalog, ResolveError,
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
    ClauseLabel, Fact, FactId, GatekeepError, GatekeepResult, Locale, ObligationId, ObligationSpec,
    ParamKey, PolicyHash, PolicyId, ReasonCode, RequestId, StaticClauseLabel, StaticFactId,
    StaticObligationId, StaticParamKey, StaticReasonCode, StaticRequestId, StaticSubjectSlot,
    StaticTenantId, SubjectRef, SubjectSlot, TenantId,
};
pub use partial::{Residual, complete_residual, partial_evaluate};
pub use policy_model::{
    Condition, Lattice, Policy, ResidualPolicy, ResidualPolicyBranch, ResidualPolicyNode,
};
