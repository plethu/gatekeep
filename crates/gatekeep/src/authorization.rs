mod attempts;
mod batch;
mod resource;

use std::{convert::Infallible, sync::Arc};

use serde::Serialize;

use crate::{
    AuditEntry, AuditSink, AuthorizationError, Clock, Context, Decision, DecisionAuditId,
    DecisionAuditOccurrence, DecisionSummary, FactResolutionEvidence, FactResolver, Lattice,
    NoopAuditSink, NoopPolicyObserver, Policy, PolicyAnchor, PolicyId, PolicyObserver,
    PreparedPolicy, ResolveError, SystemClock, evaluate, required_facts,
};

/// A completed authorization decision and its audit occurrence.
///
/// The configured sink has returned success. Explicitly unaudited authorizers
/// do not persist a record.
///
/// Denials are retained alongside permits. Applications must inspect the decision
/// before performing protected work. A returned obligation still needs execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationDecision<O> {
    /// Complete typed decision.
    pub decision: Decision<O>,
    /// Occurrence submitted to the configured sink.
    pub audit_occurrence: DecisionAuditOccurrence,
}

/// Framework-independent resolution, evaluation and required audit boundary.
pub struct Authorizer<R, A = NoopAuditSink, W = NoopPolicyObserver> {
    resolver: Arc<R>,
    audit_sink: Arc<A>,
    observer: Arc<W>,
    clock: Arc<dyn Clock>,
}

impl<R, A, W> Clone for Authorizer<R, A, W> {
    fn clone(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            audit_sink: Arc::clone(&self.audit_sink),
            observer: Arc::clone(&self.observer),
            clock: Arc::clone(&self.clock),
        }
    }
}

impl<R> Authorizer<R> {
    /// Explicitly chooses evaluation without audit persistence.
    #[must_use]
    pub fn unaudited(resolver: R) -> Self {
        Self::new(resolver, NoopAuditSink)
    }
}

impl<R, A> Authorizer<R, A> {
    /// Creates an authorizer with an explicitly supplied sink.
    #[must_use]
    pub fn new(resolver: R, audit_sink: A) -> Self {
        Self {
            resolver: Arc::new(resolver),
            audit_sink: Arc::new(audit_sink),
            observer: Arc::new(NoopPolicyObserver),
            clock: Arc::new(SystemClock),
        }
    }
}

impl<R, A, W> Authorizer<R, A, W> {
    /// Replaces the required audit sink.
    #[must_use]
    pub fn with_audit_sink<B>(self, audit_sink: B) -> Authorizer<R, B, W> {
        Authorizer {
            resolver: self.resolver,
            audit_sink: Arc::new(audit_sink),
            observer: self.observer,
            clock: self.clock,
        }
    }

    /// Replaces the observer, which runs only after successful audit persistence.
    #[must_use]
    pub fn with_observer<V>(self, observer: V) -> Authorizer<R, A, V> {
        Authorizer {
            resolver: self.resolver,
            audit_sink: self.audit_sink,
            observer: Arc::new(observer),
            clock: self.clock,
        }
    }

    /// Supplies the authoritative application clock.
    #[must_use]
    pub fn with_clock<C: Clock + 'static>(mut self, clock: C) -> Self {
        self.clock = Arc::new(clock);
        self
    }
}

impl<R: FactResolver, A: AuditSink, W: PolicyObserver> Authorizer<R, A, W> {
    /// Resolves every prepared fact explicitly, evaluates and persists a decision.
    ///
    /// # Errors
    /// Returns typed context, missing-fact, source, freshness or persistence errors.
    /// Omitted observations are errors even when a negated condition would permit.
    pub async fn authorize<O: Lattice + Serialize + Send + Sync>(
        &self,
        policy: &PreparedPolicy<O>,
        context: &Context,
    ) -> Result<AuthorizationDecision<O>, AuthorizationError<R::Error, A::Error>> {
        self.run(
            policy.policy(),
            policy.anchor(),
            policy.required_facts(),
            context,
            true,
        )
        .await
    }

    /// Resolves and freezes a checked decision for caller-controlled persistence.
    ///
    /// This is not permission to act. Call [`Self::persist_pending`] and inspect
    /// the resulting decision before disclosure. Keep the same pending value
    /// for an ambiguous audit retry; do not reevaluate under its occurrence ID.
    ///
    /// # Errors
    /// Returns context, resolution, completeness, evidence or trace failures.
    pub async fn prepare<O: Lattice + Serialize + Send + Sync>(
        &self,
        policy: &PreparedPolicy<O>,
        context: &Context,
    ) -> Result<crate::PendingDecision<O>, AuthorizationError<R::Error, A::Error>> {
        context.validate_at(self.clock.now_utc())?;
        let resolution = self
            .resolver
            .resolve_for_decision(policy.required_facts(), context, self.clock.as_ref())
            .await?;
        self.assemble(
            policy.policy(),
            policy.anchor(),
            Some(policy.required_facts()),
            context,
            &resolution,
        )
    }

    /// Evaluates the published policy path, preserving omission-as-absence semantics.
    /// Prefer [`Self::authorize`] for new checked callers.
    ///
    /// # Errors
    /// Returns typed validation, resolution, serialization or persistence failures.
    pub async fn authorize_policy<O: Lattice + Serialize + Send + Sync>(
        &self,
        id: PolicyId,
        policy: &Policy<O>,
        context: &Context,
    ) -> Result<AuthorizationDecision<O>, AuthorizationError<R::Error, A::Error>> {
        context.validate_at(self.clock.now_utc())?;
        let anchor = PolicyAnchor::new(id, policy.hash().map_err(AuthorizationError::PolicyHash)?);
        let required = required_facts(policy).into_iter().collect::<Vec<_>>();
        self.run(policy, &anchor, &required, context, false).await
    }

    async fn run<O: Lattice + Serialize + Send + Sync>(
        &self,
        policy: &Policy<O>,
        anchor: &PolicyAnchor,
        required: &[crate::FactId],
        context: &Context,
        checked: bool,
    ) -> Result<AuthorizationDecision<O>, AuthorizationError<R::Error, A::Error>> {
        context.validate_at(self.clock.now_utc())?;
        let resolution = self
            .resolver
            .resolve_for_decision(required, context, self.clock.as_ref())
            .await?;
        self.finish(
            policy,
            anchor,
            checked.then_some(required),
            context,
            &resolution,
        )
        .await
    }
}

impl<R: Send + Sync, A: AuditSink, W: PolicyObserver> Authorizer<R, A, W> {
    /// Freezes a checked decision from facts read in an application transaction.
    ///
    /// The caller owns source scope and transaction isolation. Persist the entry
    /// and commit before acting on this provisional decision.
    ///
    /// # Errors
    /// Rejects invalid context, incomplete/stale observations or invalid evidence.
    pub fn prepare_resolution<O: Lattice + Serialize + Send + Sync>(
        &self,
        policy: &PreparedPolicy<O>,
        context: &Context,
        resolution: &crate::FactResolution<crate::KnownFacts>,
    ) -> Result<crate::PendingDecision<O>, AuthorizationError<Infallible, A::Error>> {
        self.assemble(
            policy.policy(),
            policy.anchor(),
            Some(policy.required_facts()),
            context,
            resolution,
        )
    }

    async fn finish<O: Lattice + Serialize + Send + Sync, E>(
        &self,
        policy: &Policy<O>,
        anchor: &PolicyAnchor,
        required: Option<&[crate::FactId]>,
        context: &Context,
        resolution: &crate::FactResolution<crate::KnownFacts>,
    ) -> Result<AuthorizationDecision<O>, AuthorizationError<E, A::Error>> {
        let pending = self.assemble(policy, anchor, required, context, resolution)?;
        self.persist(pending).await
    }

    fn assemble<O: Lattice + Serialize + Send + Sync, E>(
        &self,
        policy: &Policy<O>,
        anchor: &PolicyAnchor,
        required: Option<&[crate::FactId]>,
        context: &Context,
        resolution: &crate::FactResolution<crate::KnownFacts>,
    ) -> Result<crate::PendingDecision<O>, AuthorizationError<E, A::Error>> {
        let received_at = self.clock.now_utc();
        context.validate_at(received_at)?;
        resolution
            .validate_at(received_at)
            .map_err(ResolveError::Resolution)?;
        if let Some(fact) = required
            .into_iter()
            .flatten()
            .find(|fact| resolution.facts().observation(fact).is_none())
        {
            return Err(ResolveError::MissingFact(fact.clone()).into());
        }

        let evidence = FactResolutionEvidence::from_resolution(resolution)?;
        let decision = evaluate(policy, resolution.facts());
        let occurrence = match context.decision_audit_occurrence() {
            Some(value) => value.clone(),
            None => {
                DecisionAuditOccurrence::new(DecisionAuditId::generate(), self.clock.now_utc())?
            }
        };
        let entry =
            AuditEntry::from_decision(occurrence, anchor.clone(), &decision, context, evidence)
                .map_err(|error| match error {
                    crate::AuditConstructionError::Trace(error) => AuthorizationError::Trace(error),
                    crate::AuditConstructionError::Entry(error) => {
                        AuthorizationError::AuditEntry(error)
                    }
                })?;
        Ok(crate::PendingDecision::new(decision, entry))
    }

    /// Persists a frozen event without resolving facts again.
    ///
    /// A successful retry records the original decision; it does not refresh its
    /// authority for a later protected operation. Reauthorize before later work.
    ///
    /// # Errors
    /// Returns the sink error; the caller retains the borrowed frozen event.
    pub async fn persist_pending<O: Clone + Send + Sync>(
        &self,
        pending: &crate::PendingDecision<O>,
    ) -> Result<AuthorizationDecision<O>, A::Error> {
        self.audit_sink.record(pending.entry()).await?;
        let entry = pending.entry();
        self.observer.observe(&DecisionSummary {
            anchor: entry.anchor().clone(),
            effect: entry.effect(),
            obligations: entry.obligations().to_vec(),
            consulted: entry.consulted().to_vec(),
        });
        Ok(AuthorizationDecision {
            decision: pending.decision().clone(),
            audit_occurrence: entry.occurrence(),
        })
    }

    async fn persist<O: Clone + Send + Sync, E>(
        &self,
        pending: crate::PendingDecision<O>,
    ) -> Result<AuthorizationDecision<O>, AuthorizationError<E, A::Error>> {
        self.persist_pending(&pending)
            .await
            .map_err(|source| AuthorizationError::Audit {
                occurrence: pending.entry().occurrence(),
                source,
            })
    }
}
