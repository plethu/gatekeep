use crate::FactObservation;
use crate::{
    BindingProvenance, Clock, Context, EvidenceDigest, FactId, KnownFacts, PartialFacts,
    SubjectSlot,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize, de::Error as DeError};
use std::error::Error as StdError;
use thiserror::Error;

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    observations: Vec<crate::FactObservation>,
}

#[derive(Deserialize)]
struct FactResolutionWire<F> {
    facts: F,
    metadata: Option<FactResolutionMetadata>,
    observed_at: time::OffsetDateTime,
    #[serde(default)]
    observations: Vec<crate::FactObservation>,
}

impl<'de, F> Deserialize<'de> for FactResolution<F>
where
    F: Deserialize<'de> + crate::ObservationFacts,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = FactResolutionWire::deserialize(deserializer)?;
        FactObservation::match_all(&wire.observations, &wire.facts).map_err(D::Error::custom)?;
        let mut resolution =
            Self::new(wire.facts, wire.metadata, wire.observed_at).map_err(D::Error::custom)?;
        resolution.observations = wire.observations;
        resolution
            .observations
            .sort_by(|left, right| left.fact().cmp(right.fact()));
        Ok(resolution)
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
            observations: Vec::new(),
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
        for observation in &self.observations {
            observation.validate_at(received_at)?;
        }

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

    /// Selected bounded observations in stable fact order.
    #[must_use]
    pub fn observations(&self) -> &[crate::FactObservation] {
        &self.observations
    }

    /// Consumes the envelope and returns its facts and metadata.
    /// Selected per-fact evidence is discarded; retain the envelope for audit.
    #[must_use]
    pub fn into_parts(self) -> (F, Option<FactResolutionMetadata>, time::OffsetDateTime) {
        (self.facts, self.metadata, self.observed_at)
    }
}

impl FactResolution<KnownFacts> {
    /// Attaches selected per-fact evidence, checking it against explicit facts.
    ///
    /// # Errors
    /// Rejects duplicate identities, oversized bundles or conflicting values.
    pub fn with_observations(
        mut self,
        mut observations: Vec<crate::FactObservation>,
    ) -> Result<Self, crate::ObservationError> {
        FactObservation::match_all(&observations, &self.facts)?;
        observations.sort_by(|left, right| left.fact().cmp(right.fact()));
        self.observations = observations;
        Ok(self)
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    observations: Vec<crate::FactObservation>,
}

#[derive(Deserialize)]
struct FactResolutionEvidenceWire {
    source: Option<BindingProvenance>,
    revision: Option<BindingProvenance>,
    observed_at: time::OffsetDateTime,
    fresh_until: Option<time::OffsetDateTime>,
    fact_set_digest: EvidenceDigest,
    #[serde(default)]
    observations: Vec<crate::FactObservation>,
}

impl<'de> Deserialize<'de> for FactResolutionEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = FactResolutionEvidenceWire::deserialize(deserializer)?;
        let mut evidence = Self {
            source: wire.source,
            revision: wire.revision,
            observed_at: wire.observed_at,
            fresh_until: wire.fresh_until,
            fact_set_digest: wire.fact_set_digest,
            observations: wire.observations,
        };
        evidence
            .observations
            .sort_by(|left, right| left.fact().cmp(right.fact()));
        evidence.validate().map_err(D::Error::custom)?;
        FactObservation::validate_all(&evidence.observations).map_err(D::Error::custom)?;
        Ok(evidence)
    }
}

impl FactResolutionEvidence {
    pub(crate) fn validate(&self) -> Result<(), FactResolutionError> {
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
    /// retains a set-level reference and any explicitly selected boolean
    /// observations. Raw domain objects are never captured automatically.
    ///
    /// # Errors
    ///
    /// Returns [`FactResolutionEvidenceError`] when the deterministic fact
    /// representation cannot be serialized.
    pub fn from_resolution(
        resolution: &FactResolution<KnownFacts>,
    ) -> Result<Self, FactResolutionEvidenceError> {
        FactObservation::match_all(&resolution.observations, resolution.facts())?;
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
            observations: resolution.observations.clone(),
        })
    }

    /// Selected bounded observations; empty for historical set-only evidence.
    #[must_use]
    pub fn observations(&self) -> &[crate::FactObservation] {
        &self.observations
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
    /// Selected evidence conflicts with the supplied resolution.
    #[error(transparent)]
    Observation(#[from] crate::ObservationError),
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
    type Error: StdError + Send + Sync + 'static;

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
