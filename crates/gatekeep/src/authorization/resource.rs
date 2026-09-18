use super::Authorizer;
use crate::{AuditSink, AuthorizationDecision, AuthorizationError, Context, PolicyObserver};

impl<R: crate::ResourcePolicy, A: AuditSink, W: PolicyObserver> Authorizer<R, A, W> {
    /// Checks a typed resource operation using the same required audit boundary.
    ///
    /// The application must bind these domain values to the authenticated context.
    /// Gatekeep does not authenticate a principal or infer resource tenancy.
    ///
    /// # Errors
    /// Returns context, check, completeness, freshness or persistence failures.
    pub async fn authorize_resource(
        &self,
        action: &R::Action,
        principal: &R::Principal,
        resource: &R::Resource,
        context: &Context,
    ) -> Result<AuthorizationDecision<R::Outcome>, AuthorizationError<R::Error, A::Error>> {
        context.validate_at(self.clock.now_utc())?;
        let policy = self.resolver.policy(action);
        let resolution = self
            .resolver
            .resolve(action, principal, resource, context, self.clock.as_ref())
            .await?;
        self.finish(
            policy.policy(),
            policy.anchor(),
            Some(policy.required_facts()),
            context,
            &resolution,
        )
        .await
    }
}
