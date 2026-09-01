use gatekeep::{FactId, SubjectSlot};
use keepsake::{CommandContext, RelationId, RevokeBySubject, SubjectRef};
use time::OffsetDateTime;

/// Resolved keepsake target for a gatekeep fact binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeepsakeRelationTarget {
    /// Tenant containing the subject and relation.
    pub tenant_id: keepsake::TenantId,
    /// Gatekeep fact that maps to this keepsake relation target.
    pub fact: FactId,
    /// Keepsake subject used for relation lookups and lifecycle writes.
    pub subject: SubjectRef,
    /// Keepsake relation definition id.
    pub relation_id: RelationId,
    /// Request-scoped subject slot used by this target, when any.
    pub subject_slot: Option<SubjectSlot>,
}

impl KeepsakeRelationTarget {
    /// Builds a keepsake revoke-by-subject command for this target.
    #[must_use]
    pub fn revoke_by_subject(
        &self,
        at: OffsetDateTime,
        context: CommandContext,
    ) -> RevokeBySubject {
        RevokeBySubject::new(
            self.tenant_id.clone(),
            self.subject.clone(),
            self.relation_id,
            at,
            context,
        )
    }
}
