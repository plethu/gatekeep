use gatekeep::{Fact, FactId, GatekeepError, SubjectSlot};
use keepsake::{RelationId, RelationSpec};
use thiserror::Error;

/// Whether a keepsake-backed fact is resolved during query preparation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum QueryPresence {
    /// Resolve the fact from the current principal's active keepsakes.
    #[default]
    Resolve,
    /// Leave the fact unknown so query lowering can evaluate it per row.
    Defer,
}

/// Mapping from one gatekeep fact to one keepsake relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactBinding {
    pub(crate) fact: FactId,
    pub(crate) relation_id: RelationId,
    pub(crate) subject_slot: Option<SubjectSlot>,
    pub(crate) query_presence: QueryPresence,
}

impl FactBinding {
    /// Builds a binding that resolves in both decision and query mode.
    #[must_use]
    pub const fn new(fact: FactId, relation_id: RelationId) -> Self {
        Self::with_subject_and_query_presence(fact, relation_id, None, QueryPresence::Resolve)
    }

    /// Builds a binding with explicit query-mode behavior.
    #[must_use]
    pub const fn with_query_presence(
        fact: FactId,
        relation_id: RelationId,
        query_presence: QueryPresence,
    ) -> Self {
        Self::with_subject_and_query_presence(fact, relation_id, None, query_presence)
    }

    /// Builds a binding for a request-scoped subject slot.
    #[must_use]
    pub const fn on_subject(
        fact: FactId,
        relation_id: RelationId,
        subject_slot: SubjectSlot,
    ) -> Self {
        Self::with_subject_and_query_presence(
            fact,
            relation_id,
            Some(subject_slot),
            QueryPresence::Resolve,
        )
    }

    /// Builds a binding for a request-scoped subject slot with explicit
    /// query-mode behavior.
    #[must_use]
    pub const fn with_subject_and_query_presence(
        fact: FactId,
        relation_id: RelationId,
        subject_slot: Option<SubjectSlot>,
        query_presence: QueryPresence,
    ) -> Self {
        Self {
            fact,
            relation_id,
            subject_slot,
            query_presence,
        }
    }

    /// Binds a typed gatekeep fact to a typed keepsake relation.
    ///
    /// # Errors
    ///
    /// Returns [`FactBindingError::Gatekeep`] if the fact marker exposes an
    /// invalid stable id.
    pub fn for_relation_spec<F, R>() -> Result<Self, FactBindingError>
    where
        F: Fact,
        R: RelationSpec,
    {
        Self::for_relation_spec_with_query_presence::<F, R>(QueryPresence::Resolve)
    }

    /// Binds a typed gatekeep fact to a typed keepsake relation on a
    /// request-scoped subject.
    ///
    /// # Errors
    ///
    /// Returns [`FactBindingError::Gatekeep`] if the fact marker exposes an
    /// invalid stable id.
    pub fn for_relation_spec_on_subject<F, R>(
        subject_slot: SubjectSlot,
    ) -> Result<Self, FactBindingError>
    where
        F: Fact,
        R: RelationSpec,
    {
        Self::for_relation_spec_on_subject_with_query_presence::<F, R>(
            subject_slot,
            QueryPresence::Resolve,
        )
    }

    /// Binds a typed gatekeep fact to a typed keepsake relation that is
    /// resolved during query preparation.
    ///
    /// # Errors
    ///
    /// Returns [`FactBindingError::Gatekeep`] if the fact marker exposes an
    /// invalid stable id.
    pub fn resolve_relation<F, R>() -> Result<Self, FactBindingError>
    where
        F: Fact,
        R: RelationSpec,
    {
        Self::for_relation_spec_with_query_presence::<F, R>(QueryPresence::Resolve)
    }

    /// Binds a typed gatekeep fact to a typed keepsake relation that is left
    /// unknown during query preparation for row-level lowering.
    ///
    /// # Errors
    ///
    /// Returns [`FactBindingError::Gatekeep`] if the fact marker exposes an
    /// invalid stable id.
    pub fn defer_relation<F, R>() -> Result<Self, FactBindingError>
    where
        F: Fact,
        R: RelationSpec,
    {
        Self::for_relation_spec_with_query_presence::<F, R>(QueryPresence::Defer)
    }

    /// Binds a typed gatekeep fact to a typed keepsake relation, with explicit
    /// query-mode behavior.
    ///
    /// # Errors
    ///
    /// Returns [`FactBindingError::Gatekeep`] if the fact marker exposes an
    /// invalid stable id.
    pub fn for_relation_spec_with_query_presence<F, R>(
        query_presence: QueryPresence,
    ) -> Result<Self, FactBindingError>
    where
        F: Fact,
        R: RelationSpec,
    {
        Ok(Self::with_query_presence(
            F::ID.to_owned_id()?,
            R::ID,
            query_presence,
        ))
    }

    /// Binds a typed gatekeep fact to a typed keepsake relation on a
    /// request-scoped subject, with explicit query-mode behavior.
    ///
    /// # Errors
    ///
    /// Returns [`FactBindingError::Gatekeep`] if the fact marker exposes an
    /// invalid stable id.
    pub fn for_relation_spec_on_subject_with_query_presence<F, R>(
        subject_slot: SubjectSlot,
        query_presence: QueryPresence,
    ) -> Result<Self, FactBindingError>
    where
        F: Fact,
        R: RelationSpec,
    {
        Ok(Self::with_subject_and_query_presence(
            F::ID.to_owned_id()?,
            R::ID,
            Some(subject_slot),
            query_presence,
        ))
    }

    /// Returns the gatekeep fact id.
    #[must_use]
    pub const fn fact(&self) -> &FactId {
        &self.fact
    }

    /// Returns the keepsake relation id.
    #[must_use]
    pub const fn relation_id(&self) -> RelationId {
        self.relation_id
    }

    /// Returns the request-scoped subject slot for this binding.
    #[must_use]
    pub const fn subject_slot(&self) -> Option<&SubjectSlot> {
        self.subject_slot.as_ref()
    }

    /// Returns query-mode resolution behavior.
    #[must_use]
    pub const fn query_presence(&self) -> QueryPresence {
        self.query_presence
    }
}

/// Errors returned while building typed fact bindings.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FactBindingError {
    /// The gatekeep fact marker had an invalid id.
    #[error(transparent)]
    Gatekeep(#[from] GatekeepError),
}
