//! Explicit tenant bindings carried by authorization contexts.

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

use crate::TenantId;

const MAX_PROVENANCE_CHARS: usize = 128;
const EVIDENCE_DIGEST_BYTES: usize = 32;

/// Bounded application-supplied provenance for a tenant or resolver binding.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct BindingProvenance(String);

impl BindingProvenance {
    /// Creates a bounded, non-empty provenance label.
    ///
    /// The label records how the application established a binding. It is not
    /// a token, key, or assertion and Gatekeep does not verify it.
    ///
    /// # Errors
    ///
    /// Returns [`TenantBindingError::InvalidProvenance`] when the label is
    /// empty, contains control characters, or exceeds the bounded length.
    pub fn new(value: impl Into<String>) -> Result<Self, TenantBindingError> {
        let value = value.into();
        if value.trim().is_empty()
            || value.chars().any(char::is_control)
            || value.chars().count() > MAX_PROVENANCE_CHARS
        {
            return Err(TenantBindingError::InvalidProvenance { value });
        }
        Ok(Self(value))
    }

    /// Returns the provenance label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for BindingProvenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Fixed-size digest carried as evidence without retaining raw claims or
/// tokens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceDigest([u8; EVIDENCE_DIGEST_BYTES]);

impl EvidenceDigest {
    /// Constructs a digest from exactly 32 bytes.
    #[must_use]
    pub const fn new(bytes: [u8; EVIDENCE_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; EVIDENCE_DIGEST_BYTES] {
        &self.0
    }
}

/// Authority metadata supplied by the application that verified a binding.
///
/// The labels identify the verification authority and optional signing key;
/// they never contain raw issuer tokens, claims, or credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingAuthority {
    /// An issuer-backed identity assertion.
    Issuer {
        /// Issuer or authority reference.
        issuer: BindingProvenance,
        /// Optional provider key identifier used for verification.
        key_id: Option<BindingProvenance>,
    },
    /// A provider-backed directory or service assertion.
    Provider {
        /// Provider or authority reference.
        provider: BindingProvenance,
        /// Optional provider key identifier used for verification.
        key_id: Option<BindingProvenance>,
    },
}

/// Bounded evidence for an application-verified tenant binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantBindingEvidence {
    authority: BindingAuthority,
    authenticated_at: OffsetDateTime,
    claims_digest: EvidenceDigest,
}

impl TenantBindingEvidence {
    /// Creates evidence without retaining raw claims or tokens.
    #[must_use]
    pub const fn new(
        authority: BindingAuthority,
        authenticated_at: OffsetDateTime,
        claims_digest: EvidenceDigest,
    ) -> Self {
        Self {
            authority,
            authenticated_at,
            claims_digest,
        }
    }

    /// Returns the authority reference used by the application.
    #[must_use]
    pub const fn authority(&self) -> &BindingAuthority {
        &self.authority
    }

    /// Returns the time at which the application authenticated the binding.
    #[must_use]
    pub const fn authenticated_at(&self) -> OffsetDateTime {
        self.authenticated_at
    }

    /// Returns the fixed-size digest of the authenticated claims/binding.
    #[must_use]
    pub const fn claims_digest(&self) -> &EvidenceDigest {
        &self.claims_digest
    }
}

/// An application-verified tenant binding with an explicit validity window.
///
/// The application must establish the tenant association before constructing
/// this value. Gatekeep records bounded verification evidence and checks the
/// window; it deliberately does not verify tokens, JWTs, issuers, or directory
/// data. The lifetime is an application policy rather than a Gatekeep claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApplicationVerifiedTenantBinding {
    tenant: TenantId,
    evidence: TenantBindingEvidence,
    valid_from: OffsetDateTime,
    valid_until: OffsetDateTime,
}

#[derive(Deserialize)]
struct ApplicationVerifiedTenantBindingFields {
    tenant: TenantId,
    evidence: TenantBindingEvidence,
    valid_from: OffsetDateTime,
    valid_until: OffsetDateTime,
}

impl<'de> Deserialize<'de> for ApplicationVerifiedTenantBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = ApplicationVerifiedTenantBindingFields::deserialize(deserializer)?;
        Self::new(
            fields.tenant,
            fields.evidence,
            fields.valid_from,
            fields.valid_until,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl ApplicationVerifiedTenantBinding {
    /// Creates an application-verified binding.
    ///
    /// The validity window must be ordered. Its lifetime is an application
    /// policy: Gatekeep does not impose a portable maximum or turn this
    /// record into token verification. The caller chooses the clock used to
    /// determine whether the binding is currently usable via
    /// [`Self::validate_at`] or [`crate::Context::new_at`].
    ///
    /// # Errors
    ///
    /// Returns [`TenantBindingError::InvalidWindow`] for an inverted window or
    /// evidence whose authentication time is after the binding expires.
    pub fn new(
        tenant: TenantId,
        evidence: TenantBindingEvidence,
        valid_from: OffsetDateTime,
        valid_until: OffsetDateTime,
    ) -> Result<Self, TenantBindingError> {
        let lifetime = valid_until - valid_from;
        if lifetime <= Duration::ZERO || evidence.authenticated_at() > valid_until {
            return Err(TenantBindingError::InvalidWindow);
        }
        Ok(Self {
            tenant,
            evidence,
            valid_from,
            valid_until,
        })
    }

    /// Returns the tenant covered by the binding.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Returns structured evidence supplied by the application verifier.
    #[must_use]
    pub const fn evidence(&self) -> &TenantBindingEvidence {
        &self.evidence
    }

    /// Returns the inclusive start of the validity window.
    #[must_use]
    pub const fn valid_from(&self) -> OffsetDateTime {
        self.valid_from
    }

    /// Returns the exclusive end of the validity window.
    #[must_use]
    pub const fn valid_until(&self) -> OffsetDateTime {
        self.valid_until
    }

    /// Checks whether this binding is usable at `now`.
    ///
    /// # Errors
    ///
    /// Returns [`TenantBindingError::AuthenticatedInFuture`],
    /// [`TenantBindingError::NotYetValid`], or [`TenantBindingError::Stale`]
    /// when the evidence or binding window is not usable at `now`. Gatekeep
    /// intentionally allows no clock-skew grace period at this boundary.
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), TenantBindingError> {
        if self.evidence.authenticated_at() > now {
            return Err(TenantBindingError::AuthenticatedInFuture {
                authenticated_at: self.evidence.authenticated_at(),
                now,
            });
        }

        if now < self.valid_from {
            return Err(TenantBindingError::NotYetValid {
                valid_from: self.valid_from,
                now,
            });
        }

        if now >= self.valid_until {
            return Err(TenantBindingError::Stale {
                valid_until: self.valid_until,
                now,
            });
        }
        Ok(())
    }
}

/// A separately named binding for an explicitly trusted internal service.
///
/// This does not assert that an end-user identity was verified. It is intended
/// for controlled service-to-service or maintenance boundaries where the
/// caller already owns that trust decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedServiceBinding {
    tenant: TenantId,
    service: BindingProvenance,
}

impl TrustedServiceBinding {
    /// Creates a trusted-service tenant binding.
    ///
    /// # Errors
    ///
    /// Returns [`TenantBindingError::InvalidProvenance`] for an invalid service
    /// label.
    pub fn new(tenant: TenantId, service: impl Into<String>) -> Result<Self, TenantBindingError> {
        Ok(Self {
            tenant,
            service: BindingProvenance::new(service)?,
        })
    }

    /// Returns the tenant covered by the binding.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Returns the trusted service label.
    #[must_use]
    pub const fn service(&self) -> &BindingProvenance {
        &self.service
    }
}

/// The binding authority carried by a [`crate::Context`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TenantBinding {
    /// An application-verified binding with bounded freshness.
    ApplicationVerified(ApplicationVerifiedTenantBinding),
    /// An explicitly trusted internal-service binding.
    TrustedService(TrustedServiceBinding),
}

impl TenantBinding {
    /// Returns the tenant covered by this binding.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        match self {
            Self::ApplicationVerified(binding) => binding.tenant(),
            Self::TrustedService(binding) => binding.tenant(),
        }
    }

    /// Validates freshness when this binding has a bounded validity window.
    /// Trusted service bindings are intentionally validated by their separate
    /// construction path and have no user-token freshness claim.
    ///
    /// # Errors
    ///
    /// Returns [`TenantBindingError::NotYetValid`] or
    /// [`TenantBindingError::Stale`] when an application-verified binding is
    /// outside its validity window.
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), TenantBindingError> {
        match self {
            Self::ApplicationVerified(binding) => binding.validate_at(now),
            Self::TrustedService(_) => Ok(()),
        }
    }
}

/// Errors returned when constructing or validating a tenant binding.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TenantBindingError {
    /// Provenance was empty, contained controls, or exceeded its bound.
    #[error(
        "tenant binding provenance must be non-empty, printable, and at most 128 characters: {value:?}"
    )]
    InvalidProvenance {
        /// Rejected provenance value.
        value: String,
    },
    /// The validity window was empty, inverted, or inconsistent with evidence.
    #[error("tenant binding validity window is invalid")]
    InvalidWindow,
    /// The binding is not active yet.
    #[error("tenant binding is not yet valid at {now}; it starts at {valid_from}")]
    NotYetValid {
        /// Start of the binding validity window.
        valid_from: OffsetDateTime,
        /// Clock time at which validation was attempted.
        now: OffsetDateTime,
    },
    /// The binding is no longer active.
    #[error("tenant binding is stale at {now}; it expired at {valid_until}")]
    Stale {
        /// End of the binding validity window.
        valid_until: OffsetDateTime,
        /// Clock time at which validation was attempted.
        now: OffsetDateTime,
    },
    /// The application authentication evidence is from the future relative
    /// to the clock used at this authorization boundary.
    #[error(
        "tenant binding authentication is from the future at {now}; it occurred at {authenticated_at}"
    )]
    AuthenticatedInFuture {
        /// Time recorded by the application verifier.
        authenticated_at: OffsetDateTime,
        /// Clock time at which validation was attempted.
        now: OffsetDateTime,
    },
}
