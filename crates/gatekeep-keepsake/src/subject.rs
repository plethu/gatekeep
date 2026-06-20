use gatekeep::Context;
use keepsake::{KeepsakeError, SubjectRef};

/// Maps a gatekeep request context to the keepsake subject being resolved.
pub trait SubjectMapper: Send + Sync {
    /// Builds the keepsake subject for this request.
    ///
    /// # Errors
    ///
    /// Returns [`KeepsakeError`] when the mapped subject is invalid.
    fn subject(&self, cx: &Context) -> Result<SubjectRef, KeepsakeError>;
}

/// Default tenant-aware subject mapper.
///
/// It keeps the principal id unchanged and prefixes the principal kind with the
/// tenant id, so equal principal ids in different tenants do not share keepsake
/// relations. Applications with an existing subject convention can provide a
/// custom [`SubjectMapper`] instead.
#[derive(Clone, Copy, Debug, Default)]
pub struct TenantScopedSubjectMapper;

impl SubjectMapper for TenantScopedSubjectMapper {
    fn subject(&self, cx: &Context) -> Result<SubjectRef, KeepsakeError> {
        SubjectRef::new(
            tenant_principal_kind(cx.tenant.as_str(), cx.principal.kind()),
            cx.principal.id(),
        )
    }
}

/// Principal-only subject mapper for applications that already encode tenancy
/// in keepsake subject identifiers.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrincipalSubjectMapper;

impl SubjectMapper for PrincipalSubjectMapper {
    fn subject(&self, cx: &Context) -> Result<SubjectRef, KeepsakeError> {
        SubjectRef::new(cx.principal.kind(), cx.principal.id())
    }
}

fn tenant_principal_kind(tenant: &str, principal_kind: &str) -> String {
    format!(
        "tenant:{}:{}principal:{}:{}",
        tenant.len(),
        tenant,
        principal_kind.len(),
        principal_kind
    )
}
