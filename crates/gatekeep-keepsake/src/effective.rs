use gatekeep::Presence;
use keepsake::{
    EffectiveRelationError, FulfillmentEvidence, LifecycleState, ObservationTime, RelationSnapshot,
    effective_state,
};

use crate::KeepsakeRelationTarget;

/// Failure to resolve effective facts from an explicitly scoped observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EffectiveFactError {
    /// An assignment belongs to another tenant, subject or relation.
    #[error("effective relation observation scope mismatch")]
    ScopeMismatch,
    /// Fulfillment evidence targets another tenant or assignment incarnation.
    #[error("fulfillment evidence scope mismatch")]
    FulfillmentScopeMismatch,
    /// Time or lifecycle evidence cannot establish effective presence.
    #[error(transparent)]
    Evidence(#[from] EffectiveRelationError),
}

impl KeepsakeRelationTarget {
    /// Resolves effective presence from a current scoped assignment or absence.
    ///
    /// The caller owns the observation's completeness and concurrency provenance:
    /// protected writes must retain the database scope lock through commit. A
    /// scoped absence is not proof that another transaction cannot apply a relation.
    /// Fulfillment evidence must describe this assignment at the supplied time.
    ///
    /// # Errors
    /// Returns a scope mismatch or unavailable time/lifecycle evidence.
    pub fn effective_presence(
        &self,
        time: ObservationTime,
        snapshot: &RelationSnapshot,
        fulfillment: Option<&FulfillmentEvidence>,
    ) -> Result<Presence, EffectiveFactError> {
        time.instant()?;
        if snapshot.tenant_id() != &self.tenant_id
            || snapshot.subject() != &self.subject
            || snapshot.relation_id() != self.relation_id
        {
            return Err(EffectiveFactError::ScopeMismatch);
        }

        let Some(active) = snapshot.active() else {
            return if fulfillment.is_some() {
                Err(EffectiveFactError::FulfillmentScopeMismatch)
            } else {
                Ok(Presence::Absent)
            };
        };

        if let Some(evidence) = fulfillment
            && (evidence.tenant_id() != active.keepsake().tenant_id()
                || evidence.keepsake_id() != active.keepsake().id())
        {
            return Err(EffectiveFactError::FulfillmentScopeMismatch);
        }

        let fulfillment = fulfillment.map(FulfillmentEvidence::snapshot);
        Ok(
            if effective_state(time, active, fulfillment)? == LifecycleState::Applied {
                Presence::Present
            } else {
                Presence::Absent
            },
        )
    }
}
