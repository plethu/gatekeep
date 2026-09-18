use crate::{
    AuditEntry, Decision, FactId, KnownFacts, Lattice, PreparedPolicy, Presence, evaluate,
};

/// Historical evidence cannot reconstruct the supplied policy's inputs.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    /// Policy identity, content hash or hash format differs.
    #[error("historical policy anchor does not match")]
    PolicyMismatch,
    /// Selected evidence omitted required observations; a digest cannot recover them.
    #[error("historical evidence is missing required observations")]
    MissingObservations(Vec<FactId>),
}

impl<O: Lattice> PreparedPolicy<O> {
    /// Reconstructs a historical decision from explicitly retained observations.
    ///
    /// Requires the same policy anchor and every required fact. Does not query
    /// sources, infer omitted negatives or refresh authority. This is historical
    /// analysis, not permission to perform a new operation, nor proof of source
    /// honesty or of the original event's integrity.
    ///
    /// # Errors
    /// Reports a mismatched anchor or all missing required observations.
    pub fn replay(&self, entry: &AuditEntry) -> Result<Decision<O>, ReplayError> {
        if self.anchor() != entry.anchor() {
            return Err(ReplayError::PolicyMismatch);
        }

        let facts =
            KnownFacts::from_known_entries(entry.fact_resolution().observations().iter().map(
                |observation| {
                    let value = if observation.value() {
                        Presence::Present
                    } else {
                        Presence::Absent
                    };
                    (observation.fact().clone(), value)
                },
            ));
        let missing: Vec<_> = self
            .required_facts()
            .iter()
            .filter(|fact| facts.observation(fact).is_none())
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(ReplayError::MissingObservations(missing));
        }

        Ok(evaluate(self.policy(), &facts))
    }
}
