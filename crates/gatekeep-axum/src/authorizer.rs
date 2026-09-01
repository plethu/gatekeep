use std::sync::Arc;

use gatekeep::{
    AuditEntry, AuditSink, Context, Decision, DecisionAuditId, DecisionAuditOccurrence,
    DecisionSummary, DecisiveClause, DenyShape, Effect, EffectKind, FactResolutionEvidence,
    FactResolver, IdentityReasonCatalog, Lattice, NoopAuditSink, NoopPolicyObserver, Policy,
    PolicyAnchor, PolicyId, PolicyObserver, ReasonCatalog, ResolveError, SystemClock, evaluate,
    required_facts,
};
use serde::Serialize;

use crate::{DenialResponseConfig, GatekeepAxumError, GatekeepRejection};

/// Successful authorization result returned to handlers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorized<O> {
    /// Granted outcome.
    pub outcome: O,
    /// Full decision returned by the pure evaluator.
    pub decision: Decision<O>,
    /// Stable identity and occurrence time used by the durable audit record.
    /// Retain this value when an owning operation may need to retry.
    pub audit_occurrence: DecisionAuditOccurrence,
}

/// Axum-friendly authorization boundary.
pub struct Gatekeeper<R, A = NoopAuditSink, C = IdentityReasonCatalog, W = NoopPolicyObserver> {
    resolver: Arc<R>,
    audit_sink: Arc<A>,
    reason_catalog: Arc<C>,
    observer: Arc<W>,
    denial_response: DenialResponseConfig,
    clock: Arc<dyn gatekeep::Clock>,
}

impl<R, A, C, W> Clone for Gatekeeper<R, A, C, W> {
    fn clone(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            audit_sink: Arc::clone(&self.audit_sink),
            reason_catalog: Arc::clone(&self.reason_catalog),
            observer: Arc::clone(&self.observer),
            denial_response: self.denial_response.clone(),
            clock: Arc::clone(&self.clock),
        }
    }
}

impl<R> Gatekeeper<R> {
    /// Creates an explicitly unaudited gatekeeper with identity reason
    /// rendering.
    ///
    /// The name is intentionally explicit: use [`Self::new`] for production
    /// authorization where every decision must reach a durable audit sink.
    #[must_use]
    pub fn unaudited(resolver: R) -> Self {
        Self {
            resolver: Arc::new(resolver),
            audit_sink: Arc::new(NoopAuditSink),
            reason_catalog: Arc::new(IdentityReasonCatalog),
            observer: Arc::new(NoopPolicyObserver),
            denial_response: DenialResponseConfig::default(),
            clock: Arc::new(SystemClock),
        }
    }
}

impl<R, A> Gatekeeper<R, A> {
    /// Creates a gatekeeper with an explicit audit sink.
    #[must_use]
    pub fn new(resolver: R, audit_sink: A) -> Self {
        Self {
            resolver: Arc::new(resolver),
            audit_sink: Arc::new(audit_sink),
            reason_catalog: Arc::new(IdentityReasonCatalog),
            observer: Arc::new(NoopPolicyObserver),
            denial_response: DenialResponseConfig::default(),
            clock: Arc::new(SystemClock),
        }
    }
}

impl<R, A, C, W> Gatekeeper<R, A, C, W> {
    /// Replaces the audit sink.
    #[must_use]
    pub fn with_audit_sink<NextAudit>(
        self,
        audit_sink: NextAudit,
    ) -> Gatekeeper<R, NextAudit, C, W> {
        Gatekeeper {
            resolver: self.resolver,
            audit_sink: Arc::new(audit_sink),
            reason_catalog: self.reason_catalog,
            observer: self.observer,
            denial_response: self.denial_response,
            clock: self.clock,
        }
    }

    /// Replaces the reason catalog used for forbidden denials.
    #[must_use]
    pub fn with_reason_catalog<NextCatalog>(
        self,
        reason_catalog: NextCatalog,
    ) -> Gatekeeper<R, A, NextCatalog, W> {
        Gatekeeper {
            resolver: self.resolver,
            audit_sink: self.audit_sink,
            reason_catalog: Arc::new(reason_catalog),
            observer: self.observer,
            denial_response: self.denial_response,
            clock: self.clock,
        }
    }

    /// Replaces the side-channel decision observer.
    #[must_use]
    pub fn with_observer<NextObserver>(
        self,
        observer: NextObserver,
    ) -> Gatekeeper<R, A, C, NextObserver> {
        Gatekeeper {
            resolver: self.resolver,
            audit_sink: self.audit_sink,
            reason_catalog: self.reason_catalog,
            observer: Arc::new(observer),
            denial_response: self.denial_response,
            clock: self.clock,
        }
    }

    /// Replaces denial presentation settings.
    #[must_use]
    pub fn with_denial_response(mut self, denial_response: DenialResponseConfig) -> Self {
        self.denial_response = denial_response;
        self
    }

    /// Replaces the clock used by tenant validation, fact resolution, and
    /// audit occurrence capture.
    #[must_use]
    pub fn with_clock<F>(mut self, clock: F) -> Self
    where
        F: gatekeep::Clock + 'static,
    {
        self.clock = Arc::new(clock);
        self
    }
}

impl<R, A, C, W> Gatekeeper<R, A, C, W>
where
    R: FactResolver,
    A: AuditSink,
    C: ReasonCatalog + Send + Sync,
    W: PolicyObserver,
{
    /// Resolves facts, evaluates the policy, observes and audits the decision,
    /// and returns an axum rejection for denied requests.
    ///
    /// # Errors
    ///
    /// Returns [`GatekeepRejection`] when policy hashing, fact resolution,
    /// trace conversion, or audit persistence fails, or when the policy denies
    /// the request.
    pub async fn authorize<O>(
        &self,
        policy_id: PolicyId,
        policy: &Policy<O>,
        context: Context,
    ) -> Result<Authorized<O>, GatekeepRejection<R::Error, A::Error>>
    where
        O: Lattice + Serialize + Send + Sync,
    {
        context
            .validate_at(self.clock.now_utc())
            .map_err(GatekeepAxumError::Context)
            .map_err(GatekeepRejection::from_error)?;

        let anchor = PolicyAnchor::new(
            policy_id,
            policy
                .hash()
                .map_err(GatekeepAxumError::PolicyHash)
                .map_err(GatekeepRejection::from_error)?,
        );

        let required = required_facts(policy).into_iter().collect::<Vec<_>>();
        let resolution = self
            .resolver
            .resolve_for_decision(&required, &context, self.clock.as_ref())
            .await
            .map_err(GatekeepAxumError::Resolve)
            .map_err(GatekeepRejection::from_error)?;
        // Capture receipt/decision time separately from the resolver's source
        // observation time. The binding and freshness checks use this local
        // decision boundary, while audit evidence retains the envelope's
        // atomic `observed_at`.
        let received_at = self.clock.now_utc();
        context
            .validate_at(received_at)
            .map_err(GatekeepAxumError::Context)
            .map_err(GatekeepRejection::from_error)?;
        resolution
            .validate_at(received_at)
            .map_err(ResolveError::Resolution)
            .map_err(GatekeepAxumError::Resolve)
            .map_err(GatekeepRejection::from_error)?;
        let fact_resolution = FactResolutionEvidence::from_resolution(&resolution)
            .map_err(GatekeepAxumError::FactResolutionEvidence)
            .map_err(GatekeepRejection::from_error)?;
        let facts = resolution.facts();
        let decision = evaluate(policy, facts);

        let audit_occurrence = self
            .observe_and_audit(&anchor, &decision, &context, fact_resolution)
            .await
            .map_err(GatekeepRejection::from_error)?;

        match decision.effect.clone() {
            Effect::Permit(outcome) => Ok(Authorized {
                outcome,
                decision,
                audit_occurrence,
            }),
            Effect::Deny => {
                let reason = decision
                    .denial_reason()
                    .map_err(GatekeepAxumError::Trace)
                    .map_err(GatekeepRejection::from_error)?;
                let response = self.denial_response.denied(
                    denial_shape(&decision),
                    reason.as_ref(),
                    context.locale(),
                    self.reason_catalog.as_ref(),
                );
                Err(response.into())
            }
        }
    }

    async fn observe_and_audit<O>(
        &self,
        anchor: &PolicyAnchor,
        decision: &Decision<O>,
        context: &Context,
        fact_resolution: gatekeep::FactResolutionEvidence,
    ) -> Result<DecisionAuditOccurrence, GatekeepAxumError<R::Error, A::Error>>
    where
        O: Serialize + Clone + Sync,
    {
        let supplied_occurrence = context.decision_audit_occurrence().cloned();
        let occurrence = supplied_occurrence
            .map_or_else(
                || DecisionAuditOccurrence::new(DecisionAuditId::generate(), self.clock.now_utc()),
                |value| {
                    DecisionAuditOccurrence::new(
                        value.decision_audit_id().clone(),
                        value.occurred_at(),
                    )
                },
            )
            .map_err(GatekeepAxumError::Occurrence)?;
        let trace = decision.to_trace().map_err(GatekeepAxumError::Trace)?;
        let entry = AuditEntry::new(
            occurrence.clone(),
            context.request_id().cloned(),
            anchor.clone(),
            EffectKind::from(decision),
            decision.obligations.clone(),
            trace.consulted.clone(),
            trace.decisive.clone(),
            decision.denial_reason().map_err(GatekeepAxumError::Trace)?,
            trace,
            context.binding().clone(),
            fact_resolution,
            context.tenant().clone(),
            context.principal().clone(),
            context.subjects().clone(),
            context.locale().clone(),
        )
        .map_err(GatekeepAxumError::AuditEntry)?;

        let summary = DecisionSummary {
            anchor: anchor.clone(),
            effect: EffectKind::from(decision),
            obligations: decision.obligations.clone(),
            consulted: decision.trace.consulted.clone(),
        };
        self.audit_sink
            .record(&entry)
            .await
            .map_err(|source| GatekeepAxumError::Audit {
                occurrence: occurrence.clone(),
                source,
            })?;

        self.observer.observe(&summary);
        Ok(occurrence)
    }
}

const fn denial_shape<O>(decision: &Decision<O>) -> DenyShape {
    match &decision.trace.decisive {
        DecisiveClause::Deny { shape, .. } => *shape,
        DecisiveClause::Permit { .. } => DenyShape::Forbidden,
    }
}
