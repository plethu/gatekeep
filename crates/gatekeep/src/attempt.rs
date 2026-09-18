use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, error::Error as StdError};
use thiserror::Error;

use crate::{
    Context, DecisionAuditOccurrence, PolicyAnchor, RequestId, SubjectRef, TenantBinding, TenantId,
};

/// Failure category recorded without backend messages or untrusted request bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttemptFailure {
    /// Required source observations were unavailable or incomplete.
    Resolution,
    /// Evidence could not be validated or encoded.
    Evidence,
    /// A decision trace could not be encoded.
    Trace,
}

/// Separate durable event for an authorization attempt that produced no decision.
///
/// Only an already validated scope may construct this event. An invalid or
/// expired context must be handled by the application's authentication audit;
/// it is never assigned a fabricated tenant or recorded as a policy denial.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AttemptWire")]
pub struct AuthorizationAttempt {
    schema_version: u16,
    occurrence: DecisionAuditOccurrence,
    anchor: PolicyAnchor,
    tenant: TenantId,
    binding: TenantBinding,
    principal: SubjectRef,
    subjects: BTreeMap<crate::SubjectSlot, SubjectRef>,
    request_id: Option<RequestId>,
    failure: AttemptFailure,
}

#[derive(Deserialize)]
struct AttemptWire {
    schema_version: u16,
    occurrence: DecisionAuditOccurrence,
    anchor: PolicyAnchor,
    tenant: TenantId,
    binding: TenantBinding,
    principal: SubjectRef,
    subjects: BTreeMap<crate::SubjectSlot, SubjectRef>,
    request_id: Option<RequestId>,
    failure: AttemptFailure,
}

impl TryFrom<AttemptWire> for AuthorizationAttempt {
    type Error = AttemptValidationError;
    fn try_from(wire: AttemptWire) -> Result<Self, Self::Error> {
        let entry = Self {
            schema_version: wire.schema_version,
            occurrence: wire.occurrence,
            anchor: wire.anchor,
            tenant: wire.tenant,
            binding: wire.binding,
            principal: wire.principal,
            subjects: wire.subjects,
            request_id: wire.request_id,
            failure: wire.failure,
        };
        entry.validate()?;
        Ok(entry)
    }
}

impl AuthorizationAttempt {
    /// Records a failed attempt in a scope validated at the supplied receipt time.
    ///
    /// # Errors
    /// Rejects an invalid scope, mismatched tenant or unsupported format.
    pub fn new(
        context: &Context,
        anchor: PolicyAnchor,
        failure: AttemptFailure,
        occurrence: DecisionAuditOccurrence,
        now: time::OffsetDateTime,
    ) -> Result<Self, AttemptValidationError> {
        context.validate_at(now)?;
        let entry = Self {
            schema_version: 1,
            occurrence,
            anchor,
            tenant: context.tenant().clone(),
            binding: context.binding().clone(),
            principal: context.principal().clone(),
            subjects: context.subjects().clone(),
            request_id: context.request_id().cloned(),
            failure,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Revalidates the durable format without pretending old bindings are current.
    ///
    /// # Errors
    /// Rejects unsupported schemas and inconsistent scope.
    pub fn validate(&self) -> Result<(), AttemptValidationError> {
        if self.schema_version != 1 {
            return Err(AttemptValidationError::Schema);
        }

        if self.tenant != *self.binding.tenant() {
            return Err(AttemptValidationError::Tenant);
        }

        self.occurrence.validate()?;
        Ok(())
    }
    /// Durable attempt schema, independent of the decision schema.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }
    /// Trusted binding recorded for this attempt, not renewed authority.
    #[must_use]
    pub const fn binding(&self) -> &TenantBinding {
        &self.binding
    }
    /// Principal established by the application.
    #[must_use]
    pub const fn principal(&self) -> &SubjectRef {
        &self.principal
    }
    /// Application operation correlation, if supplied.
    #[must_use]
    pub const fn request_id(&self) -> Option<&RequestId> {
        self.request_id.as_ref()
    }
    /// Tenant established by the application.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    /// Frozen occurrence used on persistence retries.
    #[must_use]
    pub const fn occurrence(&self) -> &DecisionAuditOccurrence {
        &self.occurrence
    }
    /// Stable failure category.
    #[must_use]
    pub const fn failure(&self) -> AttemptFailure {
        self.failure
    }
    /// Resource references known within the trusted attempt scope.
    #[must_use]
    pub const fn subjects(&self) -> &BTreeMap<crate::SubjectSlot, SubjectRef> {
        &self.subjects
    }

    /// Policy being attempted.
    #[must_use]
    pub const fn anchor(&self) -> &PolicyAnchor {
        &self.anchor
    }
}

/// Failure establishing a trusted attempt record.
#[derive(Debug, Error)]
pub enum AttemptValidationError {
    /// No currently valid application scope was available.
    #[error(transparent)]
    Context(#[from] crate::ContextError),
    /// Unsupported durable format.
    #[error("unsupported attempt schema")]
    Schema,
    /// Tenant and binding disagree.
    #[error("attempt tenant disagrees with binding")]
    Tenant,
    /// Invalid occurrence identity/time.
    #[error(transparent)]
    Occurrence(#[from] crate::DecisionAuditOccurrenceError),
}

/// Required persistence boundary for failed attempts, separate from decisions.
#[async_trait]
pub trait AttemptAuditSink: Send + Sync {
    /// Storage failure, including uncertain commit outcomes.
    type Error: StdError + Send + Sync + 'static;
    /// Stores the frozen attempt; retry exactly this event after ambiguous errors.
    async fn record_attempt(&self, entry: &AuthorizationAttempt) -> Result<(), Self::Error>;
}

/// Complete failure result when recording failed authorization attempts.
#[derive(Debug, Error)]
pub enum AttemptAuthorizationError<R, A, T> {
    /// The original failure, after any required attempt record was persisted.
    #[error("authorization failed")]
    Authorization(#[source] crate::AuthorizationError<R, A>),
    /// No validated tenant scope was available to record the failed attempt.
    #[error("authorization failed without a valid audit scope")]
    Unscoped {
        /// Original failure.
        authorization: crate::AuthorizationError<R, A>,
        /// Why a trusted attempt event could not be constructed.
        scope: AttemptValidationError,
    },
    /// Required attempt persistence also failed; neither failure is discarded.
    #[error("required authorization-attempt audit failed")]
    Persistence {
        /// Original authorization failure.
        authorization: crate::AuthorizationError<R, A>,
        /// Immutable event to retry or reconcile.
        entry: Box<AuthorizationAttempt>,
        /// Storage failure takes operational precedence.
        #[source]
        source: T,
    },
}
