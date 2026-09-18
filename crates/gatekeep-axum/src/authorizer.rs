use std::sync::Arc;

use gatekeep::{
    AuditSink, Authorizer, Context, Decision, DecisionAuditOccurrence, DecisiveClause, DenyShape,
    Effect, FactResolver, IdentityReasonCatalog, Lattice, NoopAuditSink, NoopPolicyObserver,
    Policy, PolicyId, PolicyObserver, PreparedPolicy, ReasonCatalog,
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
    authorizer: Authorizer<R, A, W>,
    reason_catalog: Arc<C>,
    denial_response: DenialResponseConfig,
}

impl<R, A, C, W> Clone for Gatekeeper<R, A, C, W> {
    fn clone(&self) -> Self {
        Self {
            authorizer: self.authorizer.clone(),
            reason_catalog: Arc::clone(&self.reason_catalog),
            denial_response: self.denial_response.clone(),
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
            authorizer: Authorizer::unaudited(resolver),
            reason_catalog: Arc::new(IdentityReasonCatalog),
            denial_response: DenialResponseConfig::default(),
        }
    }
}

impl<R, A> Gatekeeper<R, A> {
    /// Creates a gatekeeper with an explicit audit sink.
    #[must_use]
    pub fn new(resolver: R, audit_sink: A) -> Self {
        Self {
            authorizer: Authorizer::new(resolver, audit_sink),
            reason_catalog: Arc::new(IdentityReasonCatalog),
            denial_response: DenialResponseConfig::default(),
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
            authorizer: self.authorizer.with_audit_sink(audit_sink),
            reason_catalog: self.reason_catalog,
            denial_response: self.denial_response,
        }
    }

    /// Replaces the reason catalog used for forbidden denials.
    #[must_use]
    pub fn with_reason_catalog<NextCatalog>(
        self,
        reason_catalog: NextCatalog,
    ) -> Gatekeeper<R, A, NextCatalog, W> {
        Gatekeeper {
            authorizer: self.authorizer,
            reason_catalog: Arc::new(reason_catalog),
            denial_response: self.denial_response,
        }
    }

    /// Replaces the side-channel decision observer.
    #[must_use]
    pub fn with_observer<NextObserver>(
        self,
        observer: NextObserver,
    ) -> Gatekeeper<R, A, C, NextObserver> {
        Gatekeeper {
            authorizer: self.authorizer.with_observer(observer),
            reason_catalog: self.reason_catalog,
            denial_response: self.denial_response,
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
        self.authorizer = self.authorizer.with_clock(clock);
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
        let result = self
            .authorizer
            .authorize_policy(policy_id, policy, &context)
            .await
            .map_err(GatekeepRejection::from_error)?;
        self.present(result, &context)
    }

    /// Authorizes a prepared policy with explicit completeness checks.
    ///
    /// # Errors
    /// Returns a rejection on denial, omitted facts, invalid context or failed audit.
    pub async fn authorize_prepared<O>(
        &self,
        policy: &PreparedPolicy<O>,
        context: Context,
    ) -> Result<Authorized<O>, GatekeepRejection<R::Error, A::Error>>
    where
        O: Lattice + Serialize + Send + Sync,
    {
        let result = self
            .authorizer
            .authorize(policy, &context)
            .await
            .map_err(GatekeepRejection::from_error)?;
        self.present(result, &context)
    }
}

impl<R, A, C: ReasonCatalog, W> Gatekeeper<R, A, C, W> {
    fn present<O: Serialize + Clone, Resolve, Audit>(
        &self,
        result: gatekeep::AuthorizationDecision<O>,
        context: &Context,
    ) -> Result<Authorized<O>, GatekeepRejection<Resolve, Audit>> {
        let gatekeep::AuthorizationDecision {
            decision,
            audit_occurrence,
        } = result;
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
}

const fn denial_shape<O>(decision: &Decision<O>) -> DenyShape {
    match &decision.trace.decisive {
        DecisiveClause::Deny { shape, .. } => *shape,
        DecisiveClause::Permit { .. } => DenyShape::Forbidden,
    }
}

impl<R, A, C, W> Gatekeeper<R, A, C, W>
where
    R: gatekeep::ResourcePolicy,
    A: AuditSink,
    C: ReasonCatalog + Send + Sync,
    W: PolicyObserver,
{
    /// Authorizes an application-typed operation and applies HTTP denial presentation.
    ///
    /// # Errors
    /// Returns hidden/forbidden denial or typed source, evidence and audit failures.
    pub async fn authorize_resource(
        &self,
        action: &R::Action,
        principal: &R::Principal,
        resource: &R::Resource,
        context: Context,
    ) -> Result<Authorized<R::Outcome>, GatekeepRejection<R::Error, A::Error>> {
        let result = self
            .authorizer
            .authorize_resource(action, principal, resource, &context)
            .await
            .map_err(GatekeepRejection::from_error)?;
        self.present(result, &context)
    }
}
