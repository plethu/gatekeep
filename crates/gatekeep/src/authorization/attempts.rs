use super::Authorizer;
use crate::{
    AuditSink, AuditedDecision, AuthorizationError, Context, DecisionAuditId,
    DecisionAuditOccurrence, FactResolver, Lattice, PolicyObserver, PreparedPolicy,
};
use serde::Serialize;

impl<R: FactResolver, A: AuditSink, W: PolicyObserver> Authorizer<R, A, W> {
    /// Requires a separate attempt record if checked authorization fails before audit.
    ///
    /// Denials remain decision events. Decision-persistence errors retain their
    /// original category; recording another event would not repair that write.
    ///
    /// # Errors
    /// Returns both failures if attempt persistence also fails, or an explicit
    /// unscoped failure when the context cannot safely select an audit tenant.
    pub async fn authorize_recording_attempts<O, T>(
        &self,
        policy: &PreparedPolicy<O>,
        context: &Context,
        attempts: &T,
    ) -> Result<AuditedDecision<O>, crate::AttemptAuthorizationError<R::Error, A::Error, T::Error>>
    where
        O: Lattice + Serialize + Send + Sync,
        T: crate::AttemptAuditSink,
    {
        let authorization = match self.authorize(policy, context).await {
            Ok(decision) => return Ok(decision),
            Err(error) => error,
        };
        let failure = match &authorization {
            AuthorizationError::Audit { .. } | AuthorizationError::Occurrence(_) => {
                return Err(crate::AttemptAuthorizationError::Authorization(
                    authorization,
                ));
            }
            AuthorizationError::Resolve(_) => crate::AttemptFailure::Resolution,
            AuthorizationError::Trace(_) => crate::AttemptFailure::Trace,
            _ => crate::AttemptFailure::Evidence,
        };
        let now = self.clock.now_utc();
        let entry = DecisionAuditOccurrence::new(DecisionAuditId::generate(), now)
            .map_err(crate::AttemptValidationError::Occurrence)
            .and_then(|occurrence| {
                crate::AuthorizationAttempt::new(
                    context,
                    policy.anchor().clone(),
                    failure,
                    occurrence,
                    now,
                )
            });
        let entry = match entry {
            Ok(entry) => entry,
            Err(scope) => {
                return Err(crate::AttemptAuthorizationError::Unscoped {
                    authorization,
                    scope,
                });
            }
        };
        match attempts.record_attempt(&entry).await {
            Ok(()) => Err(crate::AttemptAuthorizationError::Authorization(
                authorization,
            )),
            Err(source) => Err(crate::AttemptAuthorizationError::Persistence {
                authorization,
                entry: Box::new(entry),
                source,
            }),
        }
    }
}
