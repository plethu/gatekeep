use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};

/// Result type used by gatekeep constructors and validators.
pub type GatekeepResult<T> = Result<T, GatekeepError>;

/// Maximum UTF-8 byte length shared with Dovecote tenant routing values.
pub const MAX_TENANT_ID_BYTES: usize = 255;

/// Validation errors returned by typed gatekeep records.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GatekeepError {
    /// Identifier input was empty or whitespace only.
    #[error("{field} must not be empty")]
    EmptyIdentifier {
        /// Name of the identifier field that failed validation.
        field: &'static str,
    },
    /// An identifier uses a prefix reserved for imported legacy identities.
    #[error("{field} uses the reserved prefix {prefix:?}")]
    ReservedIdentifierPrefix {
        /// Name of the identifier field that failed validation.
        field: &'static str,
        /// Prefix reserved for migration identities.
        prefix: &'static str,
    },
    /// Locale input was not a simple BCP 47-style tag.
    #[error("invalid locale tag: {value}")]
    InvalidLocale {
        /// Rejected locale value.
        value: String,
    },
    /// A legacy decision identity was missing the migration namespace.
    #[error("invalid imported legacy decision audit id: {value}")]
    InvalidLegacyIdentifier {
        /// Rejected imported identity.
        value: String,
    },
    /// A policy model record failed structural validation.
    #[error("policy record is invalid: {reason}")]
    InvalidPolicyRecord {
        /// Static validation reason.
        reason: &'static str,
    },
    /// A tenant identifier exceeds the shared UTF-8 byte bound.
    #[error("tenant_id exceeds {max_bytes} UTF-8 bytes (was {actual_bytes})")]
    TenantIdTooLong {
        /// Maximum accepted UTF-8 byte length.
        max_bytes: usize,
        /// Rejected UTF-8 byte length.
        actual_bytes: usize,
    },
    /// A tenant identifier contains a forbidden Unicode control character.
    #[error("tenant_id contains forbidden control character U+{code_point:04X}")]
    TenantIdControlCharacter {
        /// Rejected Unicode scalar value.
        code_point: u32,
    },
    /// A tenant identifier contains a Unicode noncharacter.
    #[error("tenant_id contains forbidden Unicode noncharacter U+{code_point:04X}")]
    TenantIdNoncharacter {
        /// Rejected Unicode scalar value.
        code_point: u32,
    },
}

fn validate_identifier(field: &'static str, value: impl Into<String>) -> GatekeepResult<String> {
    let value = value.into();
    if value.trim().is_empty() {
        Err(GatekeepError::EmptyIdentifier { field })
    } else if field == "decision_audit_id" && value.starts_with("legacy-") {
        Err(GatekeepError::ReservedIdentifierPrefix {
            field,
            prefix: "legacy-",
        })
    } else {
        Ok(value)
    }
}

fn validate_tenant_id(value: impl Into<String>) -> GatekeepResult<String> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(GatekeepError::EmptyIdentifier { field: "tenant_id" });
    }

    if value.len() > MAX_TENANT_ID_BYTES {
        return Err(GatekeepError::TenantIdTooLong {
            max_bytes: MAX_TENANT_ID_BYTES,
            actual_bytes: value.len(),
        });
    }

    for character in value.chars() {
        let code_point = character as u32;
        if character.is_control() {
            return Err(GatekeepError::TenantIdControlCharacter { code_point });
        }

        if (0xFDD0..=0xFDEF).contains(&code_point)
            || code_point & 0xFFFF == 0xFFFF
            || code_point & 0xFFFF == 0xFFFE
        {
            return Err(GatekeepError::TenantIdNoncharacter { code_point });
        }
    }

    Ok(value)
}

fn validate_locale(value: impl Into<String>) -> GatekeepResult<String> {
    let value = value.into();
    let valid = !value.trim().is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    if valid {
        Ok(value)
    } else {
        Err(GatekeepError::InvalidLocale { value })
    }
}

macro_rules! owned_id {
    ($name:ident, $field:literal) => {
        /// Owned gatekeep identifier.
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Creates a validated identifier.
            ///
            /// # Errors
            ///
            /// Returns [`GatekeepError::EmptyIdentifier`] when `value` is empty
            /// or contains only whitespace.
            pub fn new(value: impl Into<String>) -> GatekeepResult<Self> {
                validate_identifier($field, value).map(Self)
            }

            #[allow(dead_code)]
            pub(crate) fn from_trusted(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Returns the identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

macro_rules! static_id {
    ($name:ident, $owned:ident, $validator:path) => {
        /// Static gatekeep identifier.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(&'static str);

        impl $name {
            /// Creates a compile-time validated static identifier.
            #[must_use]
            pub const fn new(value: &'static str) -> Self {
                $validator(value);
                Self(value)
            }

            /// Returns the identifier string.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                self.0
            }

            /// Converts this static identifier into its owned form.
            ///
            /// # Errors
            ///
            /// Returns [`GatekeepError::EmptyIdentifier`] if the static and
            /// owned identifier validation rules have drifted apart.
            pub fn to_owned_id(self) -> GatekeepResult<$owned> {
                $owned::new(self.0)
            }
        }
    };
    ($name:ident, $owned:ident) => {
        static_id!($name, $owned, assert_valid_static_id);
    };
}

const fn assert_valid_static_id(value: &str) {
    let bytes = value.as_bytes();
    assert!(!bytes.is_empty(), "static identity must not be empty");
    let mut index = 0;
    let mut has_non_whitespace = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if !(byte == b' ' || byte == b'\n' || byte == b'\r' || byte == b'\t') {
            has_non_whitespace = true;
        }
        index += 1;
    }
    assert!(has_non_whitespace, "static identity must not be whitespace");
}

const fn assert_valid_static_tenant_id(value: &str) {
    assert_valid_static_id(value);
    assert!(
        value.len() <= MAX_TENANT_ID_BYTES,
        "static tenant identity exceeds 255 UTF-8 bytes"
    );
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let first = bytes[index];
        let (code_point, width) = match first {
            0x00..=0x7F => (first as u32, 1),
            0x80..=0xDF => {
                let code_point = ((first & 0x1F) as u32) << 6 | (bytes[index + 1] & 0x3F) as u32;
                (code_point, 2)
            }
            0xE0..=0xEF => {
                let code_point = ((first & 0x0F) as u32) << 12
                    | ((bytes[index + 1] & 0x3F) as u32) << 6
                    | (bytes[index + 2] & 0x3F) as u32;
                (code_point, 3)
            }
            _ => {
                let code_point = ((first & 0x07) as u32) << 18
                    | ((bytes[index + 1] & 0x3F) as u32) << 12
                    | ((bytes[index + 2] & 0x3F) as u32) << 6
                    | (bytes[index + 3] & 0x3F) as u32;
                (code_point, 4)
            }
        };
        assert!(
            !(code_point <= 0x1F || code_point == 0x7F),
            "static tenant identity contains a control character"
        );
        assert!(
            !((code_point >= 0xFDD0 && code_point <= 0xFDEF)
                || code_point & 0xFFFF == 0xFFFF
                || code_point & 0xFFFF == 0xFFFE),
            "static tenant identity contains a Unicode noncharacter"
        );
        index += width;
    }
}

owned_id!(FactId, "fact_id");
owned_id!(ClauseLabel, "clause_label");
owned_id!(ObligationId, "obligation_id");
owned_id!(ParamKey, "param_key");
owned_id!(PolicyHash, "policy_hash");
owned_id!(PolicyId, "policy_id");
owned_id!(ReasonCode, "reason_code");
owned_id!(RequestId, "request_id");
owned_id!(DecisionAuditId, "decision_audit_id");
owned_id!(SubjectSlot, "subject_slot");
/// Tenant routing identity shared with Dovecote's 255-byte `CloudEvents` value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantId(String);

impl TenantId {
    /// Creates a tenant identifier with Dovecote-compatible validation.
    ///
    /// # Errors
    ///
    /// Returns a typed [`GatekeepError`] for an empty, overlong, or forbidden
    /// tenant value.
    pub fn new(value: impl Into<String>) -> GatekeepResult<Self> {
        validate_tenant_id(value).map(Self)
    }

    #[allow(dead_code)]
    pub(crate) fn from_trusted(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the tenant identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for TenantId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TenantId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl DecisionAuditId {
    /// Generates a new sortable identifier for one decision occurrence.
    ///
    /// Generate this once at the authorization or application orchestration
    /// boundary and retain it when the owning operation is retried. The
    /// identifier is a domain identity, not a database row id.
    #[must_use]
    pub fn generate() -> Self {
        Self::from_trusted(uuid::Uuid::now_v7().to_string())
    }

    /// Constructs an identity while importing a legacy decision audit record.
    ///
    /// The `legacy-` namespace is reserved so ordinary new decision identities
    /// cannot collide with imported history. This escape hatch is intentionally
    /// named for migration code; new decisions must use [`Self::new`] or
    /// [`Self::generate`].
    ///
    /// # Errors
    ///
    /// Returns [`GatekeepError::InvalidLegacyIdentifier`] unless `value` has
    /// the exact, case-sensitive `legacy-` prefix and a non-empty suffix.
    pub fn from_legacy_import(value: impl Into<String>) -> GatekeepResult<Self> {
        let value = value.into();
        if value
            .strip_prefix("legacy-")
            .is_some_and(|suffix| !suffix.is_empty())
        {
            Ok(Self::from_trusted(value))
        } else {
            Err(GatekeepError::InvalidLegacyIdentifier { value })
        }
    }
}

/// The stable identity and authoritative occurrence time for one decision.
///
/// Applications may construct and retain this value at their authorization
/// orchestration boundary. Reusing it for an ambiguous retry keeps both the
/// `CloudEvents` identity and the serialized occurrence time unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DecisionAuditOccurrence {
    /// Stable identity of the decision occurrence.
    decision_audit_id: DecisionAuditId,
    /// Occurrence time normalized to UTC at exact microsecond precision.
    occurred_at: OffsetDateTime,
}

impl DecisionAuditOccurrence {
    /// Validates and normalizes a decision occurrence for Dovecote storage.
    ///
    /// Dovecote's portable instant range starts at the Unix epoch and ends at
    /// the final microsecond of 9999-12-31. Sub-microsecond values are
    /// truncated once, before serialization, so a retry cannot silently
    /// change the durable event bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionAuditOccurrenceError`] when the time is outside the
    /// portable range.
    pub fn new(
        decision_audit_id: DecisionAuditId,
        occurred_at: OffsetDateTime,
    ) -> Result<Self, DecisionAuditOccurrenceError> {
        const MAX_PORTABLE_UNIX_SECONDS: i64 = 253_402_300_799;
        if decision_audit_id.as_str().starts_with("legacy-") {
            return Err(DecisionAuditOccurrenceError::ReservedLegacyIdentity);
        }

        let seconds = occurred_at.unix_timestamp();
        if !(0..=MAX_PORTABLE_UNIX_SECONDS).contains(&seconds) {
            return Err(DecisionAuditOccurrenceError::OutOfRange);
        }

        let nanosecond = occurred_at.nanosecond();
        let normalized_nanosecond = nanosecond - (nanosecond % 1_000);
        if seconds == MAX_PORTABLE_UNIX_SECONDS && normalized_nanosecond > 999_999_000 {
            return Err(DecisionAuditOccurrenceError::OutOfRange);
        }

        let normalized = occurred_at
            .replace_nanosecond(normalized_nanosecond)
            .map_err(|_| DecisionAuditOccurrenceError::OutOfRange)?;

        Ok(Self {
            decision_audit_id,
            occurred_at: normalized.to_offset(UtcOffset::UTC),
        })
    }

    /// Returns the stable identity of this decision occurrence.
    #[must_use]
    pub const fn decision_audit_id(&self) -> &DecisionAuditId {
        &self.decision_audit_id
    }

    /// Returns the normalized UTC occurrence time.
    #[must_use]
    pub const fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    /// Revalidates that this value retains its constructor invariants.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionAuditOccurrenceError`] for reserved identities,
    /// out-of-range instants, non-UTC offsets, or sub-microsecond precision.
    pub fn validate(&self) -> Result<(), DecisionAuditOccurrenceError> {
        Self::new(self.decision_audit_id.clone(), self.occurred_at)?;
        if self.occurred_at.offset() != UtcOffset::UTC
            || !self.occurred_at.nanosecond().is_multiple_of(1_000)
        {
            return Err(DecisionAuditOccurrenceError::NonCanonical);
        }
        Ok(())
    }

    pub(crate) fn into_parts(self) -> (DecisionAuditId, OffsetDateTime) {
        (self.decision_audit_id, self.occurred_at)
    }

    pub(crate) const fn from_validated_parts(
        decision_audit_id: DecisionAuditId,
        occurred_at: OffsetDateTime,
    ) -> Self {
        Self {
            decision_audit_id,
            occurred_at,
        }
    }
}

impl<'de> Deserialize<'de> for DecisionAuditOccurrence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            decision_audit_id: DecisionAuditId,
            occurred_at: OffsetDateTime,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.decision_audit_id, wire.occurred_at).map_err(serde::de::Error::custom)
    }
}

/// Validation failure for a decision occurrence crossing the SQL audit
/// boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DecisionAuditOccurrenceError {
    /// Imported legacy identities cannot be used for new occurrences.
    #[error("legacy decision identities are valid only while importing history")]
    ReservedLegacyIdentity,
    /// The occurrence is outside Dovecote's portable instant range.
    #[error("decision occurrence is outside Dovecote's portable instant range")]
    OutOfRange,
    /// The occurrence was not normalized through the validating constructor.
    #[error("decision occurrence must use UTC at exact microsecond precision")]
    NonCanonical,
}

static_id!(StaticFactId, FactId);
static_id!(StaticClauseLabel, ClauseLabel);
static_id!(StaticObligationId, ObligationId);
static_id!(StaticParamKey, ParamKey);
static_id!(StaticReasonCode, ReasonCode);
static_id!(StaticRequestId, RequestId);
static_id!(StaticSubjectSlot, SubjectSlot);
static_id!(StaticTenantId, TenantId, assert_valid_static_tenant_id);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Language or locale tag used by human-facing reason text.
pub struct Locale(String);

impl Locale {
    /// Creates a locale tag from non-empty ASCII alphanumeric and `-` input.
    ///
    /// # Errors
    ///
    /// Returns [`GatekeepError::InvalidLocale`] when `value` is empty or
    /// contains unsupported characters.
    pub fn new(value: impl Into<String>) -> GatekeepResult<Self> {
        validate_locale(value).map(Self)
    }

    /// Returns the locale tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Locale {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Locale {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Marker trait for compile-time known facts.
pub trait Fact {
    /// Stable fact identifier.
    const ID: StaticFactId;
}

/// Marker trait for compile-time known obligations.
pub trait ObligationSpec {
    /// Stable obligation identifier.
    const ID: StaticObligationId;
}

/// Application-owned subject reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SubjectRef {
    /// Subject namespace, such as `user` or `team`.
    kind: String,
    /// Subject identifier inside the namespace.
    id: String,
}

impl SubjectRef {
    /// Creates a validated subject reference.
    ///
    /// # Errors
    ///
    /// Returns [`GatekeepError::EmptyIdentifier`] when either component is
    /// empty or contains only whitespace.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> GatekeepResult<Self> {
        Ok(Self {
            kind: validate_identifier("subject_kind", kind)?,
            id: validate_identifier("subject_id", id)?,
        })
    }

    /// Returns the subject namespace.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Returns the subject identifier inside its namespace.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl<'de> Deserialize<'de> for SubjectRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SubjectRefRecord {
            kind: String,
            id: String,
        }

        let record = SubjectRefRecord::deserialize(deserializer)?;
        Self::new(record.kind, record.id).map_err(serde::de::Error::custom)
    }
}
