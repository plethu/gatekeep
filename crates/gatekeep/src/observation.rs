use std::collections::BTreeSet;

use serde::{Deserialize, Serialize, de::Error as DeError};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    FactId, FactResolution, FactResolutionError, FactResolutionMetadata, ObservationFacts, Presence,
};

/// Maximum selected observations retained by one decision.
pub const MAX_FACT_OBSERVATIONS: usize = 256;

/// A selected boolean observation and bounded source metadata, never a domain object.
///
/// Source and revision labels are application assertions, not verified credentials.
/// An observation inherits the tenant/resource scope of its enclosing decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FactObservation {
    fact: FactId,
    value: bool,
    metadata: Option<FactResolutionMetadata>,
    observed_at: OffsetDateTime,
}

#[derive(Deserialize)]
struct ObservationWire {
    fact: FactId,
    value: bool,
    metadata: Option<FactResolutionMetadata>,
    observed_at: OffsetDateTime,
}

impl<'de> Deserialize<'de> for FactObservation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ObservationWire::deserialize(deserializer)?;
        Self::new(wire.fact, wire.value, wire.metadata, wire.observed_at).map_err(D::Error::custom)
    }
}

impl FactObservation {
    /// Records a bounded fact identity, boolean and optional source provenance.
    ///
    /// # Errors
    /// Rejects oversized identities and impossible freshness windows.
    pub fn new(
        fact: FactId,
        value: bool,
        metadata: Option<FactResolutionMetadata>,
        observed_at: OffsetDateTime,
    ) -> Result<Self, ObservationError> {
        if fact.as_str().len() > 128 || fact.as_str().chars().any(char::is_control) {
            return Err(ObservationError::InvalidIdentity);
        }
        FactResolution::new((), metadata.clone(), observed_at)?;
        Ok(Self {
            fact,
            value,
            metadata,
            observed_at,
        })
    }

    /// Stable named check.
    #[must_use]
    pub const fn fact(&self) -> &FactId {
        &self.fact
    }
    /// Observed boolean, including an explicit negative.
    #[must_use]
    pub const fn value(&self) -> bool {
        self.value
    }
    /// Source-provided metadata; absence makes no provenance claim.
    #[must_use]
    pub const fn metadata(&self) -> Option<&FactResolutionMetadata> {
        self.metadata.as_ref()
    }
    /// When this check was observed.
    #[must_use]
    pub const fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }
    /// Checks freshness at enforcement time.
    ///
    /// # Errors
    /// Rejects future or expired observations.
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), FactResolutionError> {
        FactResolution::new((), self.metadata.clone(), self.observed_at)?.validate_at(now)
    }
}

/// Invalid selected evidence. Error messages never include source content.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ObservationError {
    /// A fact identity exceeds the evidence bound or contains controls.
    #[error("invalid observation identity")]
    InvalidIdentity,
    /// The event exceeds the selected-observation bound.
    #[error("too many selected fact observations")]
    TooMany,
    /// An identity occurs twice, even with the same boolean.
    #[error("duplicate selected fact observation")]
    Duplicate,
    /// Evidence does not match the explicit resolved boolean.
    #[error("selected observation disagrees with resolved facts")]
    Mismatch,
    /// An observation has an impossible time or has expired.
    #[error(transparent)]
    Freshness(#[from] FactResolutionError),
}

impl FactObservation {
    pub(crate) fn validate_all(observations: &[Self]) -> Result<(), ObservationError> {
        if observations.len() > MAX_FACT_OBSERVATIONS {
            return Err(ObservationError::TooMany);
        }

        let mut seen = BTreeSet::new();
        for observation in observations {
            if !seen.insert(observation.fact()) {
                return Err(ObservationError::Duplicate);
            }
        }

        Ok(())
    }

    pub(crate) fn match_all(
        observations: &[Self],
        facts: &impl ObservationFacts,
    ) -> Result<(), ObservationError> {
        Self::validate_all(observations)?;
        for observation in observations {
            let expected = if observation.value() {
                Presence::Present
            } else {
                Presence::Absent
            };
            if facts.observation(observation.fact()) != Some(expected) {
                return Err(ObservationError::Mismatch);
            }
        }

        Ok(())
    }
}
