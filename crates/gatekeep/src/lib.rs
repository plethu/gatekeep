//! Code-first authorization primitives for deterministic Rust policy evaluation.
//!
//! The crate provides the pure gatekeep core: stable fact identities, reified
//! policy values, synchronous evaluation, partial evaluation for query lowering,
//! and adapter traits for application-owned IO boundaries.

#![forbid(unsafe_code)]

mod adapters;
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
pub use decision::{
    Decision, DecisionTrace, DecisiveClause, DenialReason, DenyShape, Effect, ReasonValue, Trace,
    TraceClause, TraceError,
};
pub use evaluate::{evaluate, required_facts};
pub use facts::{KnownFacts, PartialFacts, Presence, TraceValue};
pub use identity::{
    ClauseLabel, Fact, FactId, GatekeepError, GatekeepResult, Locale, ObligationId, ObligationSpec,
    ParamKey, PolicyHash, PolicyId, ReasonCode, RequestId, StaticClauseLabel, StaticFactId,
    StaticObligationId, StaticParamKey, StaticReasonCode, StaticRequestId, StaticTenantId,
    SubjectRef, TenantId,
};
pub use partial::{Residual, partial_evaluate};
pub use policy_model::{Condition, Lattice, Policy};
