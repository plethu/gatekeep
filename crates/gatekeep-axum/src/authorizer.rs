use std::sync::Arc;

use gatekeep::{
    AuditEntry, AuditSink, Context, Decision, DecisionSummary, DecisiveClause, DenyShape, Effect,
    EffectKind, FactResolver, IdentityReasonCatalog, Lattice, NoopAuditSink, NoopPolicyObserver,
    Policy, PolicyAnchor, PolicyId, PolicyObserver, ReasonCatalog, evaluate, required_facts,
};
use serde::Serialize;

use crate::{DenialResponseConfig, GatekeepAxumError, GatekeepRejection};

/// Whether audit entries should include request subject identifiers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuditSubjects {
    /// Leave tenant and principal identifiers out of audit entries.
    #[default]
    Omit,
    /// Copy tenant and principal identifiers from the request context.
    Record,
}

/// Successful authorization result returned to handlers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorized<O> {
    /// Granted outcome.
    pub outcome: O,
    /// Full decision returned by the pure evaluator.
    pub decision: Decision<O>,
}

/// Axum-friendly authorization boundary.
pub struct Gatekeeper<R, A = NoopAuditSink, C = IdentityReasonCatalog, W = NoopPolicyObserver> {
    resolver: Arc<R>,
    audit_sink: Arc<A>,
    reason_catalog: Arc<C>,
    observer: Arc<W>,
    denial_response: DenialResponseConfig,
    audit_subjects: AuditSubjects,
}

impl<R, A, C, W> Clone for Gatekeeper<R, A, C, W> {
    fn clone(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            audit_sink: Arc::clone(&self.audit_sink),
            reason_catalog: Arc::clone(&self.reason_catalog),
            observer: Arc::clone(&self.observer),
            denial_response: self.denial_response.clone(),
            audit_subjects: self.audit_subjects,
        }
    }
}

impl<R> Gatekeeper<R> {
    /// Creates a gatekeeper with no-op audit and identity reason rendering.
    #[must_use]
    pub fn new(resolver: R) -> Self {
        Self {
            resolver: Arc::new(resolver),
            audit_sink: Arc::new(NoopAuditSink),
            reason_catalog: Arc::new(IdentityReasonCatalog),
            observer: Arc::new(NoopPolicyObserver),
            denial_response: DenialResponseConfig::default(),
            audit_subjects: AuditSubjects::default(),
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
            audit_subjects: self.audit_subjects,
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
            audit_subjects: self.audit_subjects,
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
            audit_subjects: self.audit_subjects,
        }
    }

    /// Replaces denial presentation settings.
    #[must_use]
    pub fn with_denial_response(mut self, denial_response: DenialResponseConfig) -> Self {
        self.denial_response = denial_response;
        self
    }

    /// Controls whether audit entries include tenant and principal identifiers.
    #[must_use]
    pub const fn with_audit_subjects(mut self, audit_subjects: AuditSubjects) -> Self {
        self.audit_subjects = audit_subjects;
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
    pub async fn authorize<O>(
        &self,
        policy_id: PolicyId,
        policy: &Policy<O>,
        context: Context,
    ) -> Result<Authorized<O>, GatekeepRejection<R::Error, A::Error>>
    where
        O: Lattice + Serialize + Send + Sync,
    {
        let anchor = PolicyAnchor {
            policy_id,
            policy_hash: policy
                .hash()
                .map_err(GatekeepAxumError::PolicyHash)
                .map_err(GatekeepRejection::from_error)?,
        };
        let required = required_facts(policy).into_iter().collect::<Vec<_>>();
        let facts = self
            .resolver
            .resolve_for_decision(&required, &context)
            .await
            .map_err(GatekeepAxumError::Resolve)
            .map_err(GatekeepRejection::from_error)?;
        let decision = evaluate(policy, &facts);

        self.observe_and_audit(&anchor, &decision, &context)
            .map_err(GatekeepRejection::from_error)?;

        match decision.effect.clone() {
            Effect::Permit(outcome) => Ok(Authorized { outcome, decision }),
            Effect::Deny => {
                let reason = decision
                    .denial_reason()
                    .map_err(GatekeepAxumError::Trace)
                    .map_err(GatekeepRejection::from_error)?;
                let response = self.denial_response.denied(
                    denial_shape(&decision),
                    reason.as_ref(),
                    &context.locale,
                    self.reason_catalog.as_ref(),
                );
                Err(response.into())
            }
        }
    }

    fn observe_and_audit<O>(
        &self,
        anchor: &PolicyAnchor,
        decision: &Decision<O>,
        context: &Context,
    ) -> Result<(), GatekeepAxumError<R::Error, A::Error>>
    where
        O: Serialize + Clone,
    {
        let (tenant, principal) = match self.audit_subjects {
            AuditSubjects::Omit => (None, None),
            AuditSubjects::Record => (
                Some(context.tenant.clone()),
                Some(context.principal.clone()),
            ),
        };
        let entry = AuditEntry {
            anchor: anchor.clone(),
            trace: decision.to_trace().map_err(GatekeepAxumError::Trace)?,
            effect: EffectKind::from(decision),
            obligations: decision.obligations.clone(),
            tenant,
            principal,
        };
        self.audit_sink
            .record(&entry)
            .map_err(GatekeepAxumError::Audit)?;

        let summary = DecisionSummary {
            anchor: anchor.clone(),
            effect: EffectKind::from(decision),
            obligations: decision.obligations.clone(),
            consulted: decision.trace.consulted.clone(),
        };
        self.observer.observe(&summary);
        Ok(())
    }
}

const fn denial_shape<O>(decision: &Decision<O>) -> DenyShape {
    match &decision.trace.decisive {
        DecisiveClause::Deny { shape, .. } => *shape,
        DecisiveClause::Permit { .. } => DenyShape::Forbidden,
    }
}
