use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use gatekeep::{
    Context, Fact, FactId, FactResolver, KnownFacts, PartialFacts, Presence, ResolveError,
};
use keepsake::{ActiveRelation, ActiveRelationSource, RelationId, RelationSpec};

use crate::{
    FactBinding, FactBindingError, KeepsakeRelationTarget, KeepsakeResolveError,
    KeepsakeTargetError, QueryPresence, SubjectMapper, TenantScopedSubjectMapper,
};

/// Resolves gatekeep facts from active keepsake relations for the principal.
#[derive(Clone, Debug)]
pub struct KeepsakeResolver<S, M = TenantScopedSubjectMapper> {
    source: S,
    subject_mapper: M,
    bindings: BTreeMap<FactId, FactBinding>,
}

impl<S> KeepsakeResolver<S, TenantScopedSubjectMapper> {
    /// Builds a resolver around an active-relation source.
    #[must_use]
    pub const fn new(source: S) -> Self {
        Self::with_subject_mapper(source, TenantScopedSubjectMapper)
    }
}

impl<S, M> KeepsakeResolver<S, M> {
    /// Builds a resolver with an explicit subject mapper.
    #[must_use]
    pub const fn with_subject_mapper(source: S, subject_mapper: M) -> Self {
        Self {
            source,
            subject_mapper,
            bindings: BTreeMap::new(),
        }
    }

    /// Replaces the subject mapper.
    #[must_use]
    pub fn map_subjects<Next>(self, subject_mapper: Next) -> KeepsakeResolver<S, Next> {
        KeepsakeResolver {
            source: self.source,
            subject_mapper,
            bindings: self.bindings,
        }
    }

    /// Adds or replaces a fact binding.
    #[must_use]
    pub fn with_binding(mut self, binding: FactBinding) -> Self {
        self.insert_binding(binding);
        self
    }

    /// Adds or replaces a fact binding.
    pub fn insert_binding(&mut self, binding: FactBinding) {
        self.bindings.insert(binding.fact.clone(), binding);
    }

    /// Adds or replaces a typed fact-to-relation binding.
    ///
    /// # Errors
    ///
    /// Returns [`FactBindingError::Gatekeep`] if the fact marker exposes an
    /// invalid stable id.
    pub fn with_relation_spec<F, R>(self) -> Result<Self, FactBindingError>
    where
        F: Fact,
        R: RelationSpec,
    {
        self.with_relation_spec_query_presence::<F, R>(QueryPresence::Resolve)
    }

    /// Adds or replaces a typed binding that is resolved during query
    /// preparation.
    ///
    /// # Errors
    ///
    /// Returns [`FactBindingError::Gatekeep`] if the fact marker exposes an
    /// invalid stable id.
    pub fn with_resolved_relation<F, R>(self) -> Result<Self, FactBindingError>
    where
        F: Fact,
        R: RelationSpec,
    {
        self.with_relation_spec_query_presence::<F, R>(QueryPresence::Resolve)
    }

    /// Adds or replaces a typed binding that is deferred during query
    /// preparation for row-level lowering.
    ///
    /// # Errors
    ///
    /// Returns [`FactBindingError::Gatekeep`] if the fact marker exposes an
    /// invalid stable id.
    pub fn with_deferred_relation<F, R>(self) -> Result<Self, FactBindingError>
    where
        F: Fact,
        R: RelationSpec,
    {
        self.with_relation_spec_query_presence::<F, R>(QueryPresence::Defer)
    }

    /// Adds or replaces a typed binding with explicit query-mode behavior.
    ///
    /// # Errors
    ///
    /// Returns [`FactBindingError::Gatekeep`] if the fact marker exposes an
    /// invalid stable id.
    pub fn with_relation_spec_query_presence<F, R>(
        self,
        query_presence: QueryPresence,
    ) -> Result<Self, FactBindingError>
    where
        F: Fact,
        R: RelationSpec,
    {
        Ok(
            self.with_binding(FactBinding::for_relation_spec_with_query_presence::<F, R>(
                query_presence,
            )?),
        )
    }

    /// Adds or replaces a typed binding resolved against a request-scoped
    /// subject slot.
    ///
    /// # Errors
    ///
    /// Returns [`FactBindingError::Gatekeep`] if the fact marker exposes an
    /// invalid stable id.
    pub fn with_relation_spec_on_subject<F, R>(
        self,
        subject_slot: gatekeep::SubjectSlot,
    ) -> Result<Self, FactBindingError>
    where
        F: Fact,
        R: RelationSpec,
    {
        Ok(
            self.with_binding(FactBinding::for_relation_spec_on_subject::<F, R>(
                subject_slot,
            )?),
        )
    }

    /// Returns the configured bindings keyed by fact id.
    #[must_use]
    pub const fn bindings(&self) -> &BTreeMap<FactId, FactBinding> {
        &self.bindings
    }

    /// Returns the wrapped active-relation source.
    #[must_use]
    pub const fn source(&self) -> &S {
        &self.source
    }

    /// Returns the subject mapper.
    #[must_use]
    pub const fn subject_mapper(&self) -> &M {
        &self.subject_mapper
    }
}

impl<S, M> KeepsakeResolver<S, M>
where
    M: SubjectMapper,
{
    /// Resolves one binding into the keepsake subject/relation target used for lookups.
    ///
    /// # Errors
    ///
    /// Returns [`KeepsakeTargetError::MissingSubjectSlot`] when the binding
    /// targets a request-scoped subject absent from the context, or
    /// [`KeepsakeTargetError::Subject`] when keepsake rejects the mapped subject.
    pub fn target_for_binding(
        &self,
        binding: &FactBinding,
        cx: &Context,
    ) -> Result<KeepsakeRelationTarget, KeepsakeTargetError> {
        let subject = if let Some(slot) = &binding.subject_slot {
            let Some(subject) = cx.subjects.get(slot) else {
                return Err(KeepsakeTargetError::MissingSubjectSlot {
                    fact: binding.fact.clone(),
                    slot: slot.clone(),
                });
            };
            keepsake::SubjectRef::new(subject.kind(), subject.id()).map_err(|source| {
                KeepsakeTargetError::Subject {
                    fact: binding.fact.clone(),
                    source,
                }
            })?
        } else {
            self.subject_mapper
                .subject(cx)
                .map_err(|source| KeepsakeTargetError::Subject {
                    fact: binding.fact.clone(),
                    source,
                })?
        };

        Ok(KeepsakeRelationTarget {
            fact: binding.fact.clone(),
            subject,
            relation_id: binding.relation_id,
            subject_slot: binding.subject_slot.clone(),
        })
    }

    /// Resolves a configured fact id into its keepsake subject/relation target.
    ///
    /// # Errors
    ///
    /// Returns [`KeepsakeTargetError::MissingBinding`] when the fact has no
    /// configured binding. Also returns the subject-resolution errors documented
    /// by [`Self::target_for_binding`].
    pub fn target_for_fact(
        &self,
        fact: &FactId,
        cx: &Context,
    ) -> Result<KeepsakeRelationTarget, KeepsakeTargetError> {
        let binding = self
            .bindings
            .get(fact)
            .ok_or_else(|| KeepsakeTargetError::MissingBinding { fact: fact.clone() })?;
        self.target_for_binding(binding, cx)
    }

    /// Resolves configured fact ids into keepsake subject/relation targets.
    ///
    /// # Errors
    ///
    /// Returns the first [`KeepsakeTargetError`] encountered while resolving the
    /// requested facts.
    pub fn targets_for_facts(
        &self,
        facts: &[FactId],
        cx: &Context,
    ) -> Result<Vec<KeepsakeRelationTarget>, KeepsakeTargetError> {
        facts
            .iter()
            .map(|fact| self.target_for_fact(fact, cx))
            .collect()
    }
}

#[async_trait]
impl<S, M> FactResolver for KeepsakeResolver<S, M>
where
    S: ActiveRelationSource,
    M: SubjectMapper,
{
    type Error = KeepsakeResolveError<S::Error>;

    async fn resolve_for_decision(
        &self,
        required: &[FactId],
        cx: &Context,
    ) -> Result<KnownFacts, ResolveError<Self::Error>> {
        let bindings = self.bindings_for(required)?;
        let active_relations = self.active_relation_ids_by_subject(cx, &bindings).await?;
        let entries = bindings.into_iter().map(|binding| {
            let presence = relation_presence(
                &active_relations,
                binding.subject_slot.as_ref(),
                binding.relation_id,
            );
            (binding.fact.clone(), presence)
        });
        Ok(KnownFacts::from_entries(entries).map_err(KeepsakeResolveError::Gatekeep)?)
    }

    async fn resolve_for_query(
        &self,
        required: &[FactId],
        cx: &Context,
    ) -> Result<PartialFacts, ResolveError<Self::Error>> {
        let bindings = self.bindings_for(required)?;
        let needs_active_lookup = bindings
            .iter()
            .any(|binding| binding.query_presence == QueryPresence::Resolve);
        let active_relations = if needs_active_lookup {
            let resolved_bindings = bindings
                .iter()
                .copied()
                .filter(|binding| binding.query_presence == QueryPresence::Resolve)
                .collect::<Vec<_>>();
            self.active_relation_ids_by_subject(cx, &resolved_bindings)
                .await?
        } else {
            BTreeSet::new()
        };
        let entries = bindings.into_iter().map(|binding| {
            let presence = match binding.query_presence {
                QueryPresence::Resolve => relation_presence(
                    &active_relations,
                    binding.subject_slot.as_ref(),
                    binding.relation_id,
                ),
                QueryPresence::Defer => Presence::Unknown,
            };
            (binding.fact.clone(), presence)
        });
        Ok(PartialFacts::from_entries(entries))
    }
}

impl<S, M> KeepsakeResolver<S, M>
where
    S: ActiveRelationSource,
    M: SubjectMapper,
{
    fn bindings_for<'binding>(
        &'binding self,
        required: &[FactId],
    ) -> Result<Vec<&'binding FactBinding>, ResolveError<KeepsakeResolveError<S::Error>>> {
        required
            .iter()
            .map(|fact| {
                self.bindings
                    .get(fact)
                    .ok_or_else(|| ResolveError::MissingFact(fact.clone()))
            })
            .collect()
    }

    async fn active_relation_ids_by_subject(
        &self,
        cx: &Context,
        bindings: &[&FactBinding],
    ) -> Result<
        BTreeSet<(Option<gatekeep::SubjectSlot>, RelationId)>,
        ResolveError<KeepsakeResolveError<S::Error>>,
    > {
        let mut grouped = BTreeMap::<Option<gatekeep::SubjectSlot>, SubjectLookup>::new();
        for binding in bindings {
            let target = self
                .target_for_binding(binding, cx)
                .map_err(|error| match error {
                    KeepsakeTargetError::MissingBinding { fact } => ResolveError::MissingFact(fact),
                    KeepsakeTargetError::MissingSubjectSlot { fact, slot } => {
                        ResolveError::MissingSubject { fact, slot }
                    }
                    KeepsakeTargetError::Subject { source, .. } => {
                        ResolveError::Backend(KeepsakeResolveError::from(source))
                    }
                })?;
            grouped
                .entry(target.subject_slot)
                .or_insert_with(|| SubjectLookup {
                    subject: target.subject,
                    relation_ids: BTreeSet::new(),
                })
                .relation_ids
                .insert(target.relation_id);
        }

        let mut active = BTreeSet::new();
        for (slot, lookup) in grouped {
            let relation_ids = lookup.relation_ids.into_iter().collect::<Vec<_>>();
            let active_relations = self
                .source
                .active_relations_for_subject_by_ids(&lookup.subject, &relation_ids)
                .await
                .map_err(KeepsakeResolveError::Source)?;
            for relation_id in active_relation_ids(active_relations) {
                active.insert((slot.clone(), relation_id));
            }
        }
        Ok(active)
    }
}

struct SubjectLookup {
    subject: keepsake::SubjectRef,
    relation_ids: BTreeSet<RelationId>,
}

fn active_relation_ids(active_relations: Vec<ActiveRelation>) -> BTreeSet<RelationId> {
    active_relations
        .into_iter()
        .map(|active| active.keepsake().relation_id())
        .collect()
}

fn relation_presence(
    active_relations: &BTreeSet<(Option<gatekeep::SubjectSlot>, RelationId)>,
    subject_slot: Option<&gatekeep::SubjectSlot>,
    relation_id: RelationId,
) -> Presence {
    if active_relations.contains(&(subject_slot.cloned(), relation_id)) {
        Presence::Present
    } else {
        Presence::Absent
    }
}
