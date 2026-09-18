//! Ordinary Rust gates and resource policies with inspectable decision evidence.
//!
//! Start with a named boolean check; use `()` for a permit/deny outcome.
//! ```
//! use gatekeep::{Fact, StaticFactId, KnownFacts, condition, policy, evaluate};
//! struct Owner;
//! impl Fact for Owner { const ID: StaticFactId = StaticFactId::new("record.owner"); }
//! let policy = policy::grant_clause((), condition::has::<Owner>()).into_policy();
//! let facts = KnownFacts::new().with_bool::<Owner>(true);
//! assert!(evaluate(&policy, &facts).is_permit());
//! ```
//! [`PreparedPolicy`] and [`Authorizer`] add checked resolution and required
//! audit persistence. [`ResourcePolicy`] groups typed application operations.
//! Graded outcomes, partial evaluation and explicit SQL mappings are optional
//! next steps. Applications own authentication, transactions and disclosure.
//!
//! [Guides](https://github.com/plethu/gatekeep/tree/main/docs) and the
//! [record service](https://github.com/plethu/gatekeep/tree/main/examples/record-service)
//! show these boundaries in use.

#![forbid(unsafe_code)]

mod attempt;
mod audit;
#[cfg(any(test, feature = "test"))]
mod audit_memory;
mod authorization;
mod authorization_error;
mod batch;
mod context;
mod decision;
mod evaluate;
mod explanation;
mod facts;
mod hooks;
mod identity;
mod inspection;
mod observation;
mod partial;
mod pending;
mod policy_model;
mod prepared;
mod query;
mod replay;
mod resolution;
mod resource;
mod tenant;

/// Condition builder helpers.
pub mod condition;
/// Policy builder helpers.
pub mod policy;

pub use audit::{
    AUDIT_ENTRY_SCHEMA_VERSION, AuditConstructionError, AuditEntry, AuditEntryError,
    DecisionSummary, EffectKind, LegacyAuditEntry, LegacyPolicyAnchor, PolicyAnchor,
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
pub use facts::{KnownFacts, ObservationFacts, PartialFacts, Presence, TraceValue};
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

pub use authorization::{AuthorizationDecision, Authorizer};
pub use authorization_error::AuthorizationError;
pub use explanation::ExplanationAudience;
pub use inspection::{PolicyAdvice, PolicyInspection};
pub use observation::{FactObservation, MAX_FACT_OBSERVATIONS, ObservationError};
pub use pending::PendingDecision;
pub use prepared::PreparedPolicy;
pub use replay::ReplayError;
pub use resource::ResourcePolicy;
/// Helpers for synthetic policy scenarios and finite outcome laws.
#[cfg(feature = "test")]
pub mod testing;
pub use attempt::{
    AttemptAuditSink, AttemptAuthorizationError, AttemptFailure, AttemptValidationError,
    AuthorizationAttempt,
};
pub use batch::{BatchDecisions, BatchError, BatchFactResolver};
