use std::convert::Infallible;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Decision, FactId, KnownFacts, Locale, ObligationId, PartialFacts, Policy, PolicyHash, PolicyId,
    Presence, SubjectRef, TenantId, Trace,
};

/// Request-scoped data passed to adapter boundaries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    /// Tenant selected by the application before resolution.
    pub tenant: TenantId,
    /// Principal selected by the application before resolution.
    pub principal: SubjectRef,
    /// Locale used by presentation adapters.
    pub locale: Locale,
    /// Optional request identifier for audit sinks.
    pub request_id: Option<crate::RequestId>,
}

/// Async boundary that resolves policy facts from application-owned storage.
#[async_trait]
pub trait FactResolver: Send + Sync {
    /// Resolver-specific backend error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Resolves every required fact to present or absent for a single decision.
    async fn resolve_for_decision(
        &self,
        required: &[FactId],
        cx: &Context,
    ) -> Result<KnownFacts, ResolveError<Self::Error>>;

    /// Resolves known request facts and marks query-deferred facts as unknown.
    async fn resolve_for_query(
        &self,
        required: &[FactId],
        cx: &Context,
    ) -> Result<PartialFacts, ResolveError<Self::Error>>;
}

/// Error returned by fact resolution orchestration.
#[derive(Debug, Error)]
pub enum ResolveError<E> {
    /// The backing resolver failed.
    #[error("fact backend failed")]
    Backend(#[from] E),
    /// A required fact could not be produced or classified.
    #[error("required fact is missing: {0}")]
    MissingFact(FactId),
    /// Fact resolution exceeded its deadline.
    #[error("fact resolution timed out")]
    Timeout,
}

/// Side-channel observer for decision summaries.
pub trait PolicyObserver: Send + Sync {
    /// Records or exports a decision summary.
    fn observe(&self, decision_summary: &DecisionSummary);
}

/// Observer that discards decision summaries.
#[derive(Default)]
pub struct NoopPolicyObserver;

impl PolicyObserver for NoopPolicyObserver {
    fn observe(&self, _decision_summary: &DecisionSummary) {}
}

/// Append-only audit boundary.
pub trait AuditSink: Send + Sync {
    /// Sink-specific write error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Records a durable audit entry.
    fn record(&self, entry: &AuditEntry) -> Result<(), Self::Error>;
}

/// Audit sink that discards entries.
#[derive(Default)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    type Error = Infallible;

    fn record(&self, _entry: &AuditEntry) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Lowers a residual policy into a backend filter and grade projection.
pub trait QueryLowering<O> {
    /// Backend-specific boolean filter type.
    type Filter;
    /// Backend-specific grade projection type.
    type Projection;

    /// Lowers a residual policy for an authorized-list query.
    fn lower(
        &self,
        residual: &Policy<O>,
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

/// Presentation adapter for localized denial reasons.
pub trait ReasonCatalog {
    /// Renders a denial reason for the requested locale.
    fn render(&self, reason: &crate::DenialReason, locale: &Locale) -> String;
}

/// Reason catalog that renders the stable reason code.
#[derive(Default)]
pub struct IdentityReasonCatalog;

impl ReasonCatalog for IdentityReasonCatalog {
    fn render(&self, reason: &crate::DenialReason, _locale: &Locale) -> String {
        reason.code.as_str().to_owned()
    }
}

/// Stable policy identity recorded with summaries and audit entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyAnchor {
    /// Author-assigned stable policy id.
    pub policy_id: PolicyId,
    /// Derived content hash of the policy AST.
    pub policy_hash: PolicyHash,
}

/// Permit/deny effect without the generic outcome value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectKind {
    /// Decision permitted.
    Permit,
    /// Decision denied.
    Deny,
}

impl<O> From<&Decision<O>> for EffectKind {
    fn from(decision: &Decision<O>) -> Self {
        match decision.effect {
            crate::Effect::Permit(_) => Self::Permit,
            crate::Effect::Deny => Self::Deny,
        }
    }
}

/// Monomorphic observer payload for a decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionSummary {
    /// Policy version that produced the decision.
    pub anchor: PolicyAnchor,
    /// Permit/deny effect.
    pub effect: EffectKind,
    /// Obligations attached to the decision.
    pub obligations: Vec<ObligationId>,
    /// Facts read by the evaluator.
    pub consulted: Vec<(FactId, Presence)>,
}

/// Durable audit payload for a decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Policy version that produced the decision.
    pub anchor: PolicyAnchor,
    /// Durable, non-generic decision trace.
    pub trace: Trace,
    /// Permit/deny effect.
    pub effect: EffectKind,
    /// Obligations attached to the decision.
    pub obligations: Vec<ObligationId>,
    /// Optional tenant recorded by an opt-in sink.
    pub tenant: Option<TenantId>,
    /// Optional principal recorded by an opt-in sink.
    pub principal: Option<SubjectRef>,
}
