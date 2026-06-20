use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use gatekeep::{
    Context, Fact, FactId, FactResolver, KnownFacts, PartialFacts, Presence, ResolveError,
};
use keepsake::{ActiveRelation, ActiveRelationSource, RelationId, RelationSpec};

use crate::{
    FactBinding, FactBindingError, KeepsakeResolveError, QueryPresence, SubjectMapper,
    TenantScopedSubjectMapper,
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
        let relation_ids = relation_ids(bindings.iter().copied());
        let active_relations = self.active_relation_ids(cx, &relation_ids).await?;
        let entries = bindings.into_iter().map(|binding| {
            let presence = relation_presence(&active_relations, binding.relation_id);
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
            let relation_ids = relation_ids(
                bindings
                    .iter()
                    .copied()
                    .filter(|binding| binding.query_presence == QueryPresence::Resolve),
            );
            self.active_relation_ids(cx, &relation_ids).await?
        } else {
            BTreeSet::new()
        };
        let entries = bindings.into_iter().map(|binding| {
            let presence = match binding.query_presence {
                QueryPresence::Resolve => relation_presence(&active_relations, binding.relation_id),
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

    async fn active_relation_ids(
        &self,
        cx: &Context,
        relation_ids: &[RelationId],
    ) -> Result<BTreeSet<RelationId>, KeepsakeResolveError<S::Error>> {
        let subject = self.subject_mapper.subject(cx)?;
        let active_relations = self
            .source
            .active_relations_for_subject_by_ids(&subject, relation_ids)
            .await
            .map_err(KeepsakeResolveError::Source)?;
        Ok(active_relation_ids(active_relations))
    }
}

fn relation_ids<'binding>(
    bindings: impl IntoIterator<Item = &'binding FactBinding>,
) -> Vec<RelationId> {
    bindings
        .into_iter()
        .map(FactBinding::relation_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn active_relation_ids(active_relations: Vec<ActiveRelation>) -> BTreeSet<RelationId> {
    active_relations
        .into_iter()
        .map(|active| active.keepsake().relation_id())
        .collect()
}

fn relation_presence(active_relations: &BTreeSet<RelationId>, relation_id: RelationId) -> Presence {
    if active_relations.contains(&relation_id) {
        Presence::Present
    } else {
        Presence::Absent
    }
}
