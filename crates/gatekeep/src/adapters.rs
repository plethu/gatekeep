use std::{collections::BTreeMap, convert::Infallible};

use async_trait::async_trait;
use serde::{Deserialize, Serialize, de::Error as DeError};
use thiserror::Error;

use crate::{
    ApplicationVerifiedTenantBinding, BindingProvenance, Decision, DecisionAuditId,
    DecisionAuditOccurrence, DecisionAuditOccurrenceError, DenialReason, EvidenceDigest, FactId,
    KnownFacts, Locale, ObligationId, PartialFacts, PolicyHash, PolicyId, Presence, ReasonValue,
    RequestId, ResidualPolicy, SubjectRef, SubjectSlot, TenantBinding, TenantBindingError,
    TenantId, Trace, TraceClause, TrustedServiceBinding,
};

/// Application-owned source of UTC instants used at adapter boundaries.
///
/// The same clock can be passed to a fact resolver and used by an
/// authorization boundary, keeping source observation, freshness validation,
/// and audit timestamps coherent during replay and deterministic tests.
pub trait Clock: Send + Sync {
    /// Returns the current UTC instant according to the application clock.
    fn now_utc(&self) -> time::OffsetDateTime;
}

impl<F> Clock for F
where
    F: Fn() -> time::OffsetDateTime + Send + Sync,
{
    fn now_utc(&self) -> time::OffsetDateTime {
        self()
    }
}

/// Clock implementation that reads the system UTC wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }
}

/// Request-scoped data passed to adapter boundaries.
///
/// Context fields are private so callers must establish a tenant binding and
/// pass it through one of the explicit constructors. Gatekeep checks an
/// application-verified binding again at each authorization boundary because
/// a context can outlive its validity window while waiting in a queue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Context {
    tenant: TenantId,
    binding: TenantBinding,
    principal: SubjectRef,
    subjects: BTreeMap<SubjectSlot, SubjectRef>,
    locale: Locale,
    request_id: Option<crate::RequestId>,
    /// Optional decision occurrence supplied by the application for retry-safe
    /// audit propagation. When absent, the authorization boundary captures
    /// one after evaluation and before recording the audit entry. A caller
    /// retaining this value can reuse both its identity and occurrence time
    /// across an ambiguous retry.
    decision_audit_occurrence: Option<DecisionAuditOccurrence>,
}

impl Context {
    /// Constructs a context after checking the expected tenant and binding at
    /// the current wall-clock time.
    ///
    /// Prefer [`Self::from_application_verified`] or
    /// [`Self::from_trusted_service`] when the binding authority is known at
    /// the call site. This general constructor remains useful for code that
    /// stores the binding as [`TenantBinding`].
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the binding names another tenant or is
    /// outside its validity window.
    pub fn new(
        tenant: TenantId,
        binding: TenantBinding,
        principal: SubjectRef,
        locale: Locale,
    ) -> Result<Self, ContextError> {
        Self::new_at(
            tenant,
            binding,
            principal,
            locale,
            time::OffsetDateTime::now_utc(),
        )
    }

    /// Constructs a context using an explicit clock for deterministic callers
    /// and tests.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the binding names another tenant or is
    /// outside its validity window.
    pub fn new_at(
        tenant: TenantId,
        binding: TenantBinding,
        principal: SubjectRef,
        locale: Locale,
        now: time::OffsetDateTime,
    ) -> Result<Self, ContextError> {
        if tenant != *binding.tenant() {
            return Err(ContextError::TenantMismatch {
                expected: tenant,
                bound: binding.tenant().clone(),
            });
        }
        binding.validate_at(now).map_err(ContextError::Binding)?;
        Ok(Self {
            tenant,
            binding,
            principal,
            subjects: BTreeMap::new(),
            locale,
            request_id: None,
            decision_audit_occurrence: None,
        })
    }

    /// Constructs a context from an application-verified tenant binding.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the binding is not valid at construction
    /// time.
    pub fn from_application_verified(
        binding: ApplicationVerifiedTenantBinding,
        principal: SubjectRef,
        locale: Locale,
    ) -> Result<Self, ContextError> {
        let tenant = binding.tenant().clone();
        Self::new(
            tenant,
            TenantBinding::ApplicationVerified(binding),
            principal,
            locale,
        )
    }

    /// Constructs a context from an explicitly trusted service binding.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the binding cannot be used to construct a
    /// matching context.
    pub fn from_trusted_service(
        binding: TrustedServiceBinding,
        principal: SubjectRef,
        locale: Locale,
    ) -> Result<Self, ContextError> {
        let tenant = binding.tenant().clone();
        Self::new(
            tenant,
            TenantBinding::TrustedService(binding),
            principal,
            locale,
        )
    }

    /// Rechecks tenant binding freshness before a resolver or query adapter is
    /// allowed to use this context.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the binding has become stale, is not yet
    /// valid, or no longer agrees with the context tenant.
    pub fn validate_at(&self, now: time::OffsetDateTime) -> Result<(), ContextError> {
        if self.tenant != *self.binding.tenant() {
            return Err(ContextError::TenantMismatch {
                expected: self.tenant.clone(),
                bound: self.binding.tenant().clone(),
            });
        }
        self.binding.validate_at(now).map_err(ContextError::Binding)
    }

    /// Returns the context tenant.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Returns the validated tenant binding.
    #[must_use]
    pub const fn binding(&self) -> &TenantBinding {
        &self.binding
    }

    /// Returns the principal selected by the application.
    #[must_use]
    pub const fn principal(&self) -> &SubjectRef {
        &self.principal
    }

    /// Returns additional request-scoped subjects.
    #[must_use]
    pub const fn subjects(&self) -> &BTreeMap<SubjectSlot, SubjectRef> {
        &self.subjects
    }

    /// Returns the presentation locale.
    #[must_use]
    pub const fn locale(&self) -> &Locale {
        &self.locale
    }

    /// Returns the optional request identifier.
    #[must_use]
    pub const fn request_id(&self) -> Option<&RequestId> {
        self.request_id.as_ref()
    }

    /// Adds a named subject to this request context.
    #[must_use]
    pub fn with_subject(mut self, slot: SubjectSlot, subject: SubjectRef) -> Self {
        self.subjects.insert(slot, subject);
        self
    }

    /// Supplies a request identifier for audit sinks.
    #[must_use]
    pub fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Supplies the stable identity and occurrence time for a retryable
    /// authorization operation.
    #[must_use]
    pub fn with_decision_audit_occurrence(mut self, occurrence: DecisionAuditOccurrence) -> Self {
        self.decision_audit_occurrence = Some(occurrence);
        self
    }

    /// Returns the optional retry identity and occurrence time.
    #[must_use]
    pub const fn decision_audit_occurrence(&self) -> Option<&DecisionAuditOccurrence> {
        self.decision_audit_occurrence.as_ref()
    }
}

/// Error returned when a request context cannot establish a safe tenant
/// boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContextError {
    /// The context tenant differs from its binding tenant.
    #[error("tenant context does not match its binding: expected {expected}, bound {bound}")]
    TenantMismatch {
        /// Tenant selected by the application.
        expected: TenantId,
        /// Tenant carried by the binding.
        bound: TenantId,
    },
    /// The binding failed structural or freshness validation.
    #[error(transparent)]
    Binding(#[from] TenantBindingError),
}

/// One atomic result from a fact resolver.
///
/// Facts and the metadata describing the observation are returned together so
/// an adapter cannot accidentally associate metadata from another read (or a
/// previous request) with the current fact set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FactResolution<F> {
    facts: F,
    metadata: Option<FactResolutionMetadata>,
    observed_at: time::OffsetDateTime,
}

#[derive(Deserialize)]
struct FactResolutionWire<F> {
    facts: F,
    metadata: Option<FactResolutionMetadata>,
    observed_at: time::OffsetDateTime,
}

impl<'de, F> Deserialize<'de> for FactResolution<F>
where
    F: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = FactResolutionWire::deserialize(deserializer)?;
        Self::new(wire.facts, wire.metadata, wire.observed_at).map_err(D::Error::custom)
    }
}

impl<F> FactResolution<F> {
    /// Creates an atomic fact-resolution envelope.
    ///
    /// The observation time belongs to the resolver result rather than to the
    /// retry-stable decision occurrence. A freshness deadline must be at or
    /// after this observation time.
    ///
    /// # Errors
    ///
    /// Returns [`FactResolutionError::InvalidFreshnessWindow`] when the
    /// resolver reports a deadline before the observation.
    pub fn new(
        facts: F,
        metadata: Option<FactResolutionMetadata>,
        observed_at: time::OffsetDateTime,
    ) -> Result<Self, FactResolutionError> {
        if let Some(fresh_until) = metadata
            .as_ref()
            .and_then(FactResolutionMetadata::fresh_until)
            && fresh_until < observed_at
        {
            return Err(FactResolutionError::InvalidFreshnessWindow {
                observed_at,
                fresh_until,
            });
        }
        Ok(Self {
            facts,
            metadata,
            observed_at,
        })
    }

    /// Returns the resolved facts.
    #[must_use]
    pub const fn facts(&self) -> &F {
        &self.facts
    }

    /// Returns metadata captured by the resolver for this observation.
    #[must_use]
    pub const fn metadata(&self) -> Option<&FactResolutionMetadata> {
        self.metadata.as_ref()
    }

    /// Returns when the resolver observed the fact set.
    #[must_use]
    pub const fn observed_at(&self) -> time::OffsetDateTime {
        self.observed_at
    }

    /// Checks that the result is still fresh when it reaches the decision
    /// boundary.
    ///
    /// # Errors
    ///
    /// Returns [`FactResolutionError::ObservedInFuture`] when the resolver's
    /// observation is later than the receipt, or [`FactResolutionError::Expired`]
    /// when the freshness deadline has elapsed. The caller supplies one
    /// deterministic decision clock for this boundary; no clock-skew grace is
    /// applied.
    pub fn validate_at(
        &self,
        received_at: time::OffsetDateTime,
    ) -> Result<(), FactResolutionError> {
        if self.observed_at > received_at {
            return Err(FactResolutionError::ObservedInFuture {
                observed_at: self.observed_at,
                received_at,
            });
        }

        if let Some(fresh_until) = self
            .metadata
            .as_ref()
            .and_then(FactResolutionMetadata::fresh_until)
            && received_at >= fresh_until
        {
            return Err(FactResolutionError::Expired {
                received_at,
                fresh_until,
            });
        }
        Ok(())
    }

    /// Consumes the envelope and returns its facts and metadata.
    #[must_use]
    pub fn into_parts(self) -> (F, Option<FactResolutionMetadata>, time::OffsetDateTime) {
        (self.facts, self.metadata, self.observed_at)
    }
}

/// Resolver metadata supplied by an application for one fact-set observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactResolutionMetadata {
    source: BindingProvenance,
    revision: Option<BindingProvenance>,
    fresh_until: Option<time::OffsetDateTime>,
}

impl FactResolutionMetadata {
    /// Creates metadata for one observed fact-set read.
    #[must_use]
    pub const fn new(
        source: BindingProvenance,
        revision: Option<BindingProvenance>,
        fresh_until: Option<time::OffsetDateTime>,
    ) -> Self {
        Self {
            source,
            revision,
            fresh_until,
        }
    }

    /// Returns the source reference for the resolved fact set.
    #[must_use]
    pub const fn source(&self) -> &BindingProvenance {
        &self.source
    }

    /// Returns the optional source revision observed for the fact set.
    #[must_use]
    pub const fn revision(&self) -> Option<&BindingProvenance> {
        self.revision.as_ref()
    }

    /// Returns the optional freshness deadline supplied by the source.
    #[must_use]
    pub const fn fresh_until(&self) -> Option<time::OffsetDateTime> {
        self.fresh_until
    }
}

/// Bounded evidence for the complete resolved fact set used by one decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FactResolutionEvidence {
    source: Option<BindingProvenance>,
    revision: Option<BindingProvenance>,
    observed_at: time::OffsetDateTime,
    fresh_until: Option<time::OffsetDateTime>,
    fact_set_digest: EvidenceDigest,
}

#[derive(Deserialize)]
struct FactResolutionEvidenceWire {
    source: Option<BindingProvenance>,
    revision: Option<BindingProvenance>,
    observed_at: time::OffsetDateTime,
    fresh_until: Option<time::OffsetDateTime>,
    fact_set_digest: EvidenceDigest,
}

impl<'de> Deserialize<'de> for FactResolutionEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = FactResolutionEvidenceWire::deserialize(deserializer)?;
        let evidence = Self {
            source: wire.source,
            revision: wire.revision,
            observed_at: wire.observed_at,
            fresh_until: wire.fresh_until,
            fact_set_digest: wire.fact_set_digest,
        };
        evidence.validate().map_err(D::Error::custom)?;
        Ok(evidence)
    }
}

impl FactResolutionEvidence {
    fn validate(&self) -> Result<(), FactResolutionError> {
        if let Some(fresh_until) = self.fresh_until
            && fresh_until < self.observed_at
        {
            return Err(FactResolutionError::InvalidFreshnessWindow {
                observed_at: self.observed_at,
                fresh_until,
            });
        }
        Ok(())
    }

    /// Digests a complete fact set while retaining only bounded evidence.
    ///
    /// The digest is over Gatekeep's deterministic fact representation. This
    /// deliberately records a set-level reference; no raw fact values or
    /// per-fact claims are included in the audit entry.
    ///
    /// # Errors
    ///
    /// Returns [`FactResolutionEvidenceError`] when the deterministic fact
    /// representation cannot be serialized.
    pub fn from_resolution(
        resolution: &FactResolution<KnownFacts>,
    ) -> Result<Self, FactResolutionEvidenceError> {
        let encoded = postcard::to_allocvec(resolution.facts())
            .map_err(FactResolutionEvidenceError::Serialization)?;
        let fact_set_digest = EvidenceDigest::new(*blake3::hash(&encoded).as_bytes());
        let (source, revision, fresh_until) =
            resolution
                .metadata()
                .map_or((None, None, None), |metadata| {
                    (
                        Some(metadata.source.clone()),
                        metadata.revision.clone(),
                        metadata.fresh_until,
                    )
                });
        Ok(Self {
            source,
            revision,
            observed_at: resolution.observed_at(),
            fresh_until,
            fact_set_digest,
        })
    }

    /// Returns the source reference for the resolved fact set.
    #[must_use]
    pub const fn source(&self) -> Option<&BindingProvenance> {
        self.source.as_ref()
    }

    /// Returns the optional source revision observed for the fact set.
    #[must_use]
    pub const fn revision(&self) -> Option<&BindingProvenance> {
        self.revision.as_ref()
    }

    /// Returns when the resolver observed this fact set.
    #[must_use]
    pub const fn observed_at(&self) -> time::OffsetDateTime {
        self.observed_at
    }

    /// Returns the optional freshness deadline supplied by the source.
    #[must_use]
    pub const fn fresh_until(&self) -> Option<time::OffsetDateTime> {
        self.fresh_until
    }

    /// Returns the fixed-size digest of the complete resolved fact set.
    #[must_use]
    pub const fn fact_set_digest(&self) -> &EvidenceDigest {
        &self.fact_set_digest
    }
}

/// Failure while creating bounded fact-set evidence.
#[derive(Debug, Error)]
pub enum FactResolutionEvidenceError {
    /// Gatekeep's deterministic fact representation could not be serialized.
    #[error("resolved fact set could not be serialized for evidence")]
    Serialization(#[source] postcard::Error),
}

/// Invalid or stale freshness information in a resolver envelope.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FactResolutionError {
    /// The resolver reported a freshness deadline before its observation time.
    #[error("fact-resolution freshness deadline precedes its observation time")]
    InvalidFreshnessWindow {
        /// Time at which the source observed the fact set.
        observed_at: time::OffsetDateTime,
        /// Reported freshness deadline.
        fresh_until: time::OffsetDateTime,
    },
    /// The resolver result expired before the decision boundary consumed it.
    #[error("fact-resolution result expired before the decision boundary")]
    Expired {
        /// Time at which Gatekeep received the result.
        received_at: time::OffsetDateTime,
        /// Reported freshness deadline.
        fresh_until: time::OffsetDateTime,
    },
    /// The source observation is later than the decision boundary consuming it.
    #[error("fact-resolution observation is after the decision boundary")]
    ObservedInFuture {
        /// Time at which the source observed the fact set.
        observed_at: time::OffsetDateTime,
        /// Time at which Gatekeep received the result.
        received_at: time::OffsetDateTime,
    },
}

/// Async boundary that resolves policy facts from application-owned storage.
#[async_trait]
pub trait FactResolver: Send + Sync {
    /// Resolver-specific backend error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Resolves every required fact to present or absent for a single decision.
    ///
    /// The resolver must use `clock` for its `FactResolution::observed_at`
    /// value. Gatekeep passes the same application-owned clock used for
    /// boundary validation, so replay and deterministic callers do not mix
    /// wall-clock and application-clock timestamps.
    async fn resolve_for_decision(
        &self,
        required: &[FactId],
        cx: &Context,
        clock: &dyn Clock,
    ) -> Result<FactResolution<KnownFacts>, ResolveError<Self::Error>>;

    /// Resolves known request facts and marks query-deferred facts as unknown.
    ///
    /// The resolver must use `clock` for its `FactResolution::observed_at`
    /// value, as in [`Self::resolve_for_decision`].
    async fn resolve_for_query(
        &self,
        required: &[FactId],
        cx: &Context,
        clock: &dyn Clock,
    ) -> Result<FactResolution<PartialFacts>, ResolveError<Self::Error>>;
}

/// Error returned by fact resolution orchestration.
#[derive(Debug, Error)]
pub enum ResolveError<E> {
    /// The backing resolver failed.
    #[error("fact backend failed")]
    Backend(#[from] E),
    /// The resolver returned structurally invalid or stale freshness data.
    #[error(transparent)]
    Resolution(FactResolutionError),
    /// A required fact could not be produced or classified.
    #[error("required fact is missing: {0}")]
    MissingFact(FactId),
    /// A required request-scoped subject was not present in the context.
    #[error("required subject slot is missing for fact {fact}: {slot}")]
    MissingSubject {
        /// Fact whose binding required the subject.
        fact: FactId,
        /// Missing request-scoped subject slot.
        slot: SubjectSlot,
    },
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
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Sink-specific write error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Records a durable audit entry.
    async fn record(&self, entry: &AuditEntry) -> Result<(), Self::Error>;
}

/// Audit sink that discards entries.
#[derive(Default)]
pub struct NoopAuditSink;

#[async_trait]
impl AuditSink for NoopAuditSink {
    type Error = Infallible;

    async fn record(&self, _entry: &AuditEntry) -> Result<(), Self::Error> {
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

/// Current durable representation version for decision audit entries.
pub const AUDIT_ENTRY_SCHEMA_VERSION: u16 = 1;

/// Stable policy identity recorded with summaries and audit entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyAnchor {
    /// Author-assigned stable policy id.
    #[serde(rename = "policy_id")]
    id: PolicyId,
    /// Derived content hash of the policy AST.
    #[serde(rename = "policy_hash")]
    hash: PolicyHash,
    /// Format version used to derive `policy_hash`.
    #[serde(rename = "policy_hash_version")]
    hash_version: u16,
}

#[derive(Deserialize)]
struct PolicyAnchorWire {
    #[serde(rename = "policy_id")]
    id: PolicyId,
    #[serde(rename = "policy_hash")]
    hash: PolicyHash,
    #[serde(rename = "policy_hash_version")]
    hash_version: u16,
}

impl<'de> Deserialize<'de> for PolicyAnchor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = PolicyAnchorWire::deserialize(deserializer)?;
        if wire.hash_version != crate::POLICY_HASH_FORMAT_VERSION {
            return Err(D::Error::custom(format!(
                "unsupported policy hash format version {}; expected {}",
                wire.hash_version,
                crate::POLICY_HASH_FORMAT_VERSION
            )));
        }
        Ok(Self {
            id: wire.id,
            hash: wire.hash,
            hash_version: wire.hash_version,
        })
    }
}

impl PolicyAnchor {
    /// Constructs an anchor for the current policy-hash format.
    #[must_use]
    pub const fn new(policy_id: PolicyId, policy_hash: PolicyHash) -> Self {
        Self {
            id: policy_id,
            hash: policy_hash,
            hash_version: crate::POLICY_HASH_FORMAT_VERSION,
        }
    }

    /// Returns the author-assigned policy id.
    #[must_use]
    pub const fn policy_id(&self) -> &PolicyId {
        &self.id
    }

    /// Returns the derived policy hash.
    #[must_use]
    pub const fn policy_hash(&self) -> &PolicyHash {
        &self.hash
    }

    /// Returns the format version used to derive the policy hash.
    #[must_use]
    pub const fn policy_hash_version(&self) -> u16 {
        self.hash_version
    }

    const fn validate_current(&self) -> Result<(), AuditEntryError> {
        if self.hash_version != crate::POLICY_HASH_FORMAT_VERSION {
            return Err(AuditEntryError::UnsupportedPolicyHashVersion {
                expected: crate::POLICY_HASH_FORMAT_VERSION,
                actual: self.hash_version,
            });
        }
        Ok(())
    }
}

/// Policy anchor shape retained for explicit migration of pre-4.0 audit data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyPolicyAnchor {
    /// Author-assigned stable policy id.
    pub policy_id: PolicyId,
    /// Hash recorded by the historical audit representation.
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditEntry {
    /// Current durable audit representation version.
    schema_version: u16,
    /// Stable identity of this decision occurrence, independent of storage
    /// cursors and database-generated row ids.
    decision_audit_id: DecisionAuditId,
    /// Authoritative time at which the decision occurred.
    occurred_at: time::OffsetDateTime,
    /// Request identifier supplied by the application boundary.
    request_id: Option<RequestId>,
    /// Policy version that produced the decision.
    anchor: PolicyAnchor,
    /// Permit/deny effect.
    effect: EffectKind,
    /// Obligations attached to the decision.
    obligations: Vec<ObligationId>,
    /// Facts read by the evaluator in first-read order.
    consulted: Vec<(FactId, Presence)>,
    /// Clause that fixed the decision effect.
    decisive: TraceClause,
    /// Structured denial reason for deny decisions.
    denial_reason: Option<DenialReason>,
    /// Durable, non-generic decision trace.
    trace: Trace,
    /// Tenant binding used for this decision.
    binding: TenantBinding,
    /// Bounded evidence for the complete fact set.
    fact_resolution: FactResolutionEvidence,
    /// Tenant selected by the application before resolution.
    tenant: TenantId,
    /// Principal selected by the application before resolution.
    principal: SubjectRef,
    /// Named request subjects selected by the application before resolution.
    subjects: BTreeMap<SubjectSlot, SubjectRef>,
    /// Locale carried by the request context for a complete decision record.
    locale: Locale,
}

#[derive(Deserialize)]
struct AuditEntryWire {
    schema_version: u16,
    decision_audit_id: DecisionAuditId,
    occurred_at: time::OffsetDateTime,
    request_id: Option<RequestId>,
    anchor: PolicyAnchor,
    effect: EffectKind,
    obligations: Vec<ObligationId>,
    consulted: Vec<(FactId, Presence)>,
    decisive: TraceClause,
    denial_reason: Option<DenialReason>,
    trace: Trace,
    binding: TenantBinding,
    fact_resolution: FactResolutionEvidence,
    tenant: TenantId,
    principal: SubjectRef,
    #[serde(default)]
    subjects: BTreeMap<SubjectSlot, SubjectRef>,
    locale: Locale,
}

impl<'de> Deserialize<'de> for AuditEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AuditEntryWire::deserialize(deserializer)?;
        if wire.schema_version != AUDIT_ENTRY_SCHEMA_VERSION {
            return Err(D::Error::custom(format!(
                "unsupported audit entry schema version {}; expected {}",
                wire.schema_version, AUDIT_ENTRY_SCHEMA_VERSION
            )));
        }

        let occurrence = DecisionAuditOccurrence::new(wire.decision_audit_id, wire.occurred_at)
            .map_err(D::Error::custom)?;
        Self::new(
            occurrence,
            wire.request_id,
            wire.anchor,
            wire.effect,
            wire.obligations,
            wire.consulted,
            wire.decisive,
            wire.denial_reason,
            wire.trace,
            wire.binding,
            wire.fact_resolution,
            wire.tenant,
            wire.principal,
            wire.subjects,
            wire.locale,
        )
        .map_err(D::Error::custom)
    }
}

/// Historical audit shape used only by an explicit migration decoder.
///
/// This type is intentionally not accepted by [`AuditSink`] and cannot be
/// passed to current audit APIs. Its optional binding and fact evidence mirror
/// pre-4.0 payloads so migration code can inspect and map them deliberately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyAuditEntry {
    /// Historical decision identity as it appeared in the source record.
    pub decision_audit_id: String,
    /// Historical decision occurrence time.
    pub occurred_at: time::OffsetDateTime,
    /// Request identifier supplied by the historical application boundary.
    pub request_id: Option<RequestId>,
    /// Historical policy anchor without a hash-format marker.
    pub anchor: LegacyPolicyAnchor,
    /// Permit/deny effect.
    pub effect: EffectKind,
    /// Obligations attached to the decision.
    pub obligations: Vec<ObligationId>,
    /// Facts read by the evaluator.
    pub consulted: Vec<(FactId, Presence)>,
    /// Clause that fixed the decision effect.
    pub decisive: TraceClause,
    /// Structured denial reason for deny decisions.
    pub denial_reason: Option<DenialReason>,
    /// Durable decision trace.
    pub trace: Trace,
    /// Historical tenant binding, when the source contained one.
    #[serde(default)]
    pub binding: Option<TenantBinding>,
    /// Historical fact-set evidence, when the source contained one.
    #[serde(default)]
    pub fact_resolution: Option<FactResolutionEvidence>,
    /// Tenant selected by the historical application.
    pub tenant: TenantId,
    /// Principal selected by the historical application.
    pub principal: SubjectRef,
    /// Named request subjects selected by the historical application.
    #[serde(default)]
    pub subjects: BTreeMap<SubjectSlot, SubjectRef>,
    /// Locale carried by the historical request context.
    pub locale: Locale,
}

impl LegacyAuditEntry {
    /// Validates only the semantic fields retained by the historical shape.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEntryError`] when duplicated decision fields disagree.
    pub fn validate_semantics(&self) -> Result<(), AuditEntryError> {
        validate_audit_semantics(
            self.effect,
            &self.obligations,
            &self.consulted,
            &self.decisive,
            self.denial_reason.as_ref(),
            &self.trace,
        )
    }

    /// Imports this historical record after the caller supplies current
    /// binding, evidence, occurrence, and the known historical hash format.
    ///
    /// The supplied occurrence deliberately determines the new current
    /// identity; historical identities remain migration provenance and are
    /// never accepted as ordinary current identities.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEntryError`] when the historical semantics, supplied
    /// anchor version, or current entry invariants are invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn into_current(
        self,
        occurrence: DecisionAuditOccurrence,
        policy_hash_version: u16,
        binding: TenantBinding,
        fact_resolution: FactResolutionEvidence,
    ) -> Result<AuditEntry, AuditEntryError> {
        self.validate_semantics()?;
        if policy_hash_version != crate::POLICY_HASH_FORMAT_VERSION {
            return Err(AuditEntryError::UnsupportedPolicyHashVersion {
                expected: crate::POLICY_HASH_FORMAT_VERSION,
                actual: policy_hash_version,
            });
        }
        AuditEntry::new(
            occurrence,
            self.request_id,
            PolicyAnchor::new(self.anchor.policy_id, self.anchor.policy_hash),
            self.effect,
            self.obligations,
            self.consulted,
            self.decisive,
            self.denial_reason,
            self.trace,
            binding,
            fact_resolution,
            self.tenant,
            self.principal,
            self.subjects,
            self.locale,
        )
    }
}

/// Validation failure for a current durable audit entry.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditEntryError {
    /// The entry uses a schema version this crate does not understand.
    #[error("unsupported audit entry schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion {
        /// Schema version required by this release.
        expected: u16,
        /// Schema version found in the entry.
        actual: u16,
    },
    /// The policy hash uses a format version this crate does not understand.
    #[error("unsupported policy hash format version {actual}; expected {expected}")]
    UnsupportedPolicyHashVersion {
        /// Hash format required by this release.
        expected: u16,
        /// Hash format found in the anchor.
        actual: u16,
    },
    /// The entry tenant differs from the tenant carried by its binding.
    #[error("audit entry tenant does not match its binding")]
    BindingTenantMismatch,
    /// The decision occurrence does not satisfy the current durable contract.
    #[error("audit entry carries an invalid decision occurrence")]
    InvalidDecisionOccurrence(#[source] DecisionAuditOccurrenceError),
    /// Fact-resolution evidence has an impossible freshness window.
    #[error("audit entry carries invalid fact-resolution evidence")]
    InvalidFactResolutionEvidence(#[source] FactResolutionError),
    /// The duplicated decisive clause disagrees with the complete trace.
    #[error("audit entry decisive clause does not match its trace")]
    DecisiveTraceMismatch,
    /// The duplicated consulted-fact list disagrees with the complete trace.
    #[error("audit entry consulted facts do not match its trace")]
    ConsultedTraceMismatch,
    /// The effect disagrees with the decisive trace clause.
    #[error("audit entry effect does not match its decisive trace clause")]
    EffectTraceMismatch,
    /// Permit decisions cannot carry a denial reason.
    #[error("permit audit entry carries a denial reason")]
    PermitWithDenialReason,
    /// Deny decisions cannot carry permit-path obligations.
    #[error("deny audit entry carries obligations")]
    DenyWithObligations,
    /// The materialized denial reason disagrees with the decisive trace.
    #[error("audit entry denial reason does not match its decisive trace clause")]
    DenialReasonMismatch,
}

impl AuditEntry {
    /// Constructs a current audit entry with a validated occurrence, binding,
    /// and fact-resolution evidence.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEntryError`] when the binding does not cover the entry
    /// tenant or when required current evidence is absent.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        occurrence: DecisionAuditOccurrence,
        request_id: Option<RequestId>,
        anchor: PolicyAnchor,
        effect: EffectKind,
        obligations: Vec<ObligationId>,
        consulted: Vec<(FactId, Presence)>,
        decisive: TraceClause,
        denial_reason: Option<DenialReason>,
        trace: Trace,
        binding: TenantBinding,
        fact_resolution: FactResolutionEvidence,
        tenant: TenantId,
        principal: SubjectRef,
        subjects: BTreeMap<SubjectSlot, SubjectRef>,
        locale: Locale,
    ) -> Result<Self, AuditEntryError> {
        occurrence
            .validate()
            .map_err(AuditEntryError::InvalidDecisionOccurrence)?;
        let (decision_audit_id, occurred_at) = occurrence.into_parts();
        let entry = Self {
            schema_version: AUDIT_ENTRY_SCHEMA_VERSION,
            decision_audit_id,
            occurred_at,
            request_id,
            anchor,
            effect,
            obligations,
            consulted,
            decisive,
            denial_reason,
            trace,
            binding,
            fact_resolution,
            tenant,
            principal,
            subjects,
            locale,
        };
        entry.validate_current()?;
        Ok(entry)
    }

    /// Returns the current durable audit schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the stable identity and occurrence time as one validated value.
    #[must_use]
    pub fn occurrence(&self) -> DecisionAuditOccurrence {
        DecisionAuditOccurrence::from_validated_parts(
            self.decision_audit_id.clone(),
            self.occurred_at,
        )
    }

    /// Returns the stable decision identity.
    #[must_use]
    pub const fn decision_audit_id(&self) -> &DecisionAuditId {
        &self.decision_audit_id
    }

    /// Returns the authoritative decision occurrence time.
    #[must_use]
    pub const fn occurred_at(&self) -> time::OffsetDateTime {
        self.occurred_at
    }

    /// Returns the optional request identifier.
    #[must_use]
    pub const fn request_id(&self) -> Option<&RequestId> {
        self.request_id.as_ref()
    }

    /// Returns the policy anchor.
    #[must_use]
    pub const fn anchor(&self) -> &PolicyAnchor {
        &self.anchor
    }

    /// Returns the permit or deny effect.
    #[must_use]
    pub const fn effect(&self) -> EffectKind {
        self.effect
    }

    /// Returns obligations attached to the selected policy path.
    #[must_use]
    pub fn obligations(&self) -> &[ObligationId] {
        &self.obligations
    }

    /// Returns facts consulted by evaluation.
    #[must_use]
    pub fn consulted(&self) -> &[(FactId, Presence)] {
        &self.consulted
    }

    /// Returns the decisive trace clause.
    #[must_use]
    pub const fn decisive(&self) -> &TraceClause {
        &self.decisive
    }

    /// Returns the structured denial reason, when present.
    #[must_use]
    pub const fn denial_reason(&self) -> Option<&DenialReason> {
        self.denial_reason.as_ref()
    }

    /// Returns the complete durable decision trace.
    #[must_use]
    pub const fn trace(&self) -> &Trace {
        &self.trace
    }

    /// Returns the validated tenant binding used by the decision.
    #[must_use]
    pub const fn binding(&self) -> &TenantBinding {
        &self.binding
    }

    /// Returns bounded evidence for the complete resolved fact set.
    #[must_use]
    pub const fn fact_resolution(&self) -> &FactResolutionEvidence {
        &self.fact_resolution
    }

    /// Returns the tenant selected by the application.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Returns the principal selected by the application.
    #[must_use]
    pub const fn principal(&self) -> &SubjectRef {
        &self.principal
    }

    /// Returns named request subjects.
    #[must_use]
    pub const fn subjects(&self) -> &BTreeMap<SubjectSlot, SubjectRef> {
        &self.subjects
    }

    /// Returns the request presentation locale.
    #[must_use]
    pub const fn locale(&self) -> &Locale {
        &self.locale
    }

    /// Validates that this entry is safe to persist as a current decision.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEntryError`] when the schema or policy hash version is
    /// unsupported, the binding names another tenant, evidence is invalid, or
    /// denormalized decision fields contradict one another.
    pub fn validate_current(&self) -> Result<(), AuditEntryError> {
        if self.schema_version != AUDIT_ENTRY_SCHEMA_VERSION {
            return Err(AuditEntryError::UnsupportedSchemaVersion {
                expected: AUDIT_ENTRY_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        DecisionAuditOccurrence::from_validated_parts(
            self.decision_audit_id.clone(),
            self.occurred_at,
        )
        .validate()
        .map_err(AuditEntryError::InvalidDecisionOccurrence)?;
        self.anchor.validate_current()?;
        if self.binding.tenant() != &self.tenant {
            return Err(AuditEntryError::BindingTenantMismatch);
        }

        self.fact_resolution
            .validate()
            .map_err(AuditEntryError::InvalidFactResolutionEvidence)?;
        self.validate_semantics()
    }

    /// Validates consistency between the denormalized decision fields.
    ///
    /// This check applies to both current entries and decoded legacy history;
    /// it does not require current tenant-binding or fact-resolution evidence.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEntryError`] when effect, trace, consulted facts,
    /// obligations, or denial reason contradict one another.
    pub fn validate_semantics(&self) -> Result<(), AuditEntryError> {
        validate_audit_semantics(
            self.effect,
            &self.obligations,
            &self.consulted,
            &self.decisive,
            self.denial_reason.as_ref(),
            &self.trace,
        )
    }
}

fn validate_audit_semantics(
    effect: EffectKind,
    obligations: &[ObligationId],
    consulted: &[(FactId, Presence)],
    decisive: &TraceClause,
    denial_reason: Option<&DenialReason>,
    trace: &Trace,
) -> Result<(), AuditEntryError> {
    if decisive != &trace.decisive {
        return Err(AuditEntryError::DecisiveTraceMismatch);
    }

    if consulted != trace.consulted.as_slice() {
        return Err(AuditEntryError::ConsultedTraceMismatch);
    }

    match (effect, decisive) {
        (EffectKind::Permit, TraceClause::Permit { .. }) => {
            if denial_reason.is_some() {
                return Err(AuditEntryError::PermitWithDenialReason);
            }
        }
        (EffectKind::Deny, TraceClause::Deny { .. }) => {
            if !obligations.is_empty() {
                return Err(AuditEntryError::DenyWithObligations);
            }

            if !denial_reason_matches_trace(denial_reason, decisive) {
                return Err(AuditEntryError::DenialReasonMismatch);
            }
        }
        _ => return Err(AuditEntryError::EffectTraceMismatch),
    }

    Ok(())
}

fn denial_reason_matches_trace(reason: Option<&DenialReason>, decisive: &TraceClause) -> bool {
    let TraceClause::Deny {
        denied,
        unsatisfied,
        label,
        reason: reason_code,
        shape,
    } = decisive
    else {
        return reason.is_none();
    };

    let expected_code = reason_code
        .as_ref()
        .map(crate::ReasonCode::as_str)
        .or_else(|| label.as_ref().map(crate::ClauseLabel::as_str));
    let Some(expected_code) = expected_code else {
        return reason.is_none();
    };

    let Some(reason) = reason else {
        return false;
    };

    if reason.code.as_str() != expected_code || reason.shape != *shape {
        return false;
    }

    let actual = reason
        .params
        .iter()
        .map(|(key, value)| (key.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    if actual.len() != unsatisfied.len() + usize::from(denied.is_some()) {
        return false;
    }

    for (index, fact) in unsatisfied.iter().enumerate() {
        let key = if index == 0 {
            "missing_fact".to_owned()
        } else {
            format!("missing_fact_{index}")
        };

        if actual.get(key.as_str()) != Some(&&ReasonValue::Fact(fact.clone())) {
            return false;
        }
    }

    denied.as_ref().is_none_or(|value| {
        actual.get("denied_outcome") == Some(&&ReasonValue::Outcome(value.clone()))
    })
}
