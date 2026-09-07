use crate::{
    ApplicationVerifiedTenantBinding, DecisionAuditOccurrence, Locale, RequestId, SubjectRef,
    SubjectSlot, TenantBinding, TenantBindingError, TenantId, TrustedServiceBinding,
};
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;

/// Application-owned source of UTC instants used at adapter boundaries.
///
/// The same clock can be passed to a fact resolver and used by an
/// authorization boundary, keeping source observation, freshness validation,
/// and audit timestamps coherent during replay and deterministic tests.
pub trait Clock: Send + Sync {
    /// Returns the current UTC instant according to the application clock.
    fn now_utc(&self) -> time::OffsetDateTime;
}

impl<F> Clock for F
where
    F: Fn() -> time::OffsetDateTime + Send + Sync,
{
    fn now_utc(&self) -> time::OffsetDateTime {
        self()
    }
}

/// Clock implementation that reads the system UTC wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }
}

/// Request-scoped data passed to adapter boundaries.
///
/// Context fields are private so callers must establish a tenant binding and
/// pass it through one of the explicit constructors. Gatekeep checks an
/// application-verified binding again at each authorization boundary because
/// a context can outlive its validity window while waiting in a queue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Context {
    tenant: TenantId,
    binding: TenantBinding,
    principal: SubjectRef,
    subjects: BTreeMap<SubjectSlot, SubjectRef>,
    locale: Locale,
    request_id: Option<crate::RequestId>,
    /// Optional decision occurrence supplied by the application for retry-safe
    /// audit propagation. When absent, the authorization boundary captures
    /// one after evaluation and before recording the audit entry. A caller
    /// retaining this value can reuse both its identity and occurrence time
    /// across an ambiguous retry.
    decision_audit_occurrence: Option<DecisionAuditOccurrence>,
}

impl Context {
    /// Constructs a context after checking the expected tenant and binding at
    /// the current wall-clock time.
    ///
    /// Prefer [`Self::from_application_verified`] or
    /// [`Self::from_trusted_service`] when the binding authority is known at
    /// the call site. This general constructor remains useful for code that
    /// stores the binding as [`TenantBinding`].
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the binding names another tenant or is
    /// outside its validity window.
    pub fn new(
        tenant: TenantId,
        binding: TenantBinding,
        principal: SubjectRef,
        locale: Locale,
    ) -> Result<Self, ContextError> {
        Self::new_at(
            tenant,
            binding,
            principal,
            locale,
            time::OffsetDateTime::now_utc(),
        )
    }

    /// Constructs a context using an explicit clock for deterministic callers
    /// and tests.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the binding names another tenant or is
    /// outside its validity window.
    pub fn new_at(
        tenant: TenantId,
        binding: TenantBinding,
        principal: SubjectRef,
        locale: Locale,
        now: time::OffsetDateTime,
    ) -> Result<Self, ContextError> {
        if tenant != *binding.tenant() {
            return Err(ContextError::TenantMismatch {
                expected: tenant,
                bound: binding.tenant().clone(),
            });
        }
        binding.validate_at(now).map_err(ContextError::Binding)?;
        Ok(Self {
            tenant,
            binding,
            principal,
            subjects: BTreeMap::new(),
            locale,
            request_id: None,
            decision_audit_occurrence: None,
        })
    }

    /// Constructs a context from an application-verified tenant binding.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the binding is not valid at construction
    /// time.
    pub fn from_application_verified(
        binding: ApplicationVerifiedTenantBinding,
        principal: SubjectRef,
        locale: Locale,
    ) -> Result<Self, ContextError> {
        let tenant = binding.tenant().clone();
        Self::new(
            tenant,
            TenantBinding::ApplicationVerified(binding),
            principal,
            locale,
        )
    }

    /// Constructs a context from an explicitly trusted service binding.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the binding cannot be used to construct a
    /// matching context.
    pub fn from_trusted_service(
        binding: TrustedServiceBinding,
        principal: SubjectRef,
        locale: Locale,
    ) -> Result<Self, ContextError> {
        let tenant = binding.tenant().clone();
        Self::new(
            tenant,
            TenantBinding::TrustedService(binding),
            principal,
            locale,
        )
    }

    /// Rechecks tenant binding freshness before a resolver or query adapter is
    /// allowed to use this context.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the binding has become stale, is not yet
    /// valid, or no longer agrees with the context tenant.
    pub fn validate_at(&self, now: time::OffsetDateTime) -> Result<(), ContextError> {
        if self.tenant != *self.binding.tenant() {
            return Err(ContextError::TenantMismatch {
                expected: self.tenant.clone(),
                bound: self.binding.tenant().clone(),
            });
        }
        self.binding.validate_at(now).map_err(ContextError::Binding)
    }

    /// Returns the context tenant.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Returns the validated tenant binding.
    #[must_use]
    pub const fn binding(&self) -> &TenantBinding {
        &self.binding
    }

    /// Returns the principal selected by the application.
    #[must_use]
    pub const fn principal(&self) -> &SubjectRef {
        &self.principal
    }

    /// Returns additional request-scoped subjects.
    #[must_use]
    pub const fn subjects(&self) -> &BTreeMap<SubjectSlot, SubjectRef> {
        &self.subjects
    }

    /// Returns the presentation locale.
    #[must_use]
    pub const fn locale(&self) -> &Locale {
        &self.locale
    }

    /// Returns the optional request identifier.
    #[must_use]
    pub const fn request_id(&self) -> Option<&RequestId> {
        self.request_id.as_ref()
    }

    /// Adds a named subject to this request context.
    #[must_use]
    pub fn with_subject(mut self, slot: SubjectSlot, subject: SubjectRef) -> Self {
        self.subjects.insert(slot, subject);
        self
    }

    /// Supplies a request identifier for audit sinks.
    #[must_use]
    pub fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Supplies the stable identity and occurrence time for a retryable
    /// authorization operation.
    #[must_use]
    pub fn with_decision_audit_occurrence(mut self, occurrence: DecisionAuditOccurrence) -> Self {
        self.decision_audit_occurrence = Some(occurrence);
        self
    }

    /// Returns the optional retry identity and occurrence time.
    #[must_use]
    pub const fn decision_audit_occurrence(&self) -> Option<&DecisionAuditOccurrence> {
        self.decision_audit_occurrence.as_ref()
    }
}

/// Error returned when a request context cannot establish a safe tenant
/// boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContextError {
    /// The context tenant differs from its binding tenant.
    #[error("tenant context does not match its binding: expected {expected}, bound {bound}")]
    TenantMismatch {
        /// Tenant selected by the application.
        expected: TenantId,
        /// Tenant carried by the binding.
        bound: TenantId,
    },
    /// The binding failed structural or freshness validation.
    #[error(transparent)]
    Binding(#[from] TenantBindingError),
}
