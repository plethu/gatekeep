use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Result type used by gatekeep constructors and validators.
pub type GatekeepResult<T> = Result<T, GatekeepError>;

/// Validation errors returned by typed gatekeep records.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GatekeepError {
    /// Identifier input was empty or whitespace only.
    #[error("{field} must not be empty")]
    EmptyIdentifier {
        /// Name of the identifier field that failed validation.
        field: &'static str,
    },
    /// Locale input was not a simple BCP 47-style tag.
    #[error("invalid locale tag: {value}")]
    InvalidLocale {
        /// Rejected locale value.
        value: String,
    },
    /// A policy model record failed structural validation.
    #[error("policy record is invalid: {reason}")]
    InvalidPolicyRecord {
        /// Static validation reason.
        reason: &'static str,
    },
}

fn validate_identifier(field: &'static str, value: impl Into<String>) -> GatekeepResult<String> {
    let value = value.into();
    if value.trim().is_empty() {
        Err(GatekeepError::EmptyIdentifier { field })
    } else {
        Ok(value)
    }
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
    ($name:ident, $owned:ident) => {
        /// Static gatekeep identifier.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(&'static str);

        impl $name {
            /// Creates a compile-time validated static identifier.
            #[must_use]
            pub const fn new(value: &'static str) -> Self {
                assert_valid_static_id(value);
                Self(value)
            }

            /// Returns the identifier string.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                self.0
            }

            /// Converts this static identifier into its owned form.
            pub fn to_owned_id(self) -> GatekeepResult<$owned> {
                $owned::new(self.0)
            }
        }
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

owned_id!(FactId, "fact_id");
owned_id!(ClauseLabel, "clause_label");
owned_id!(ObligationId, "obligation_id");
owned_id!(ParamKey, "param_key");
owned_id!(PolicyHash, "policy_hash");
owned_id!(PolicyId, "policy_id");
owned_id!(ReasonCode, "reason_code");
owned_id!(RequestId, "request_id");
owned_id!(SubjectSlot, "subject_slot");
owned_id!(TenantId, "tenant_id");

static_id!(StaticFactId, FactId);
static_id!(StaticClauseLabel, ClauseLabel);
static_id!(StaticObligationId, ObligationId);
static_id!(StaticParamKey, ParamKey);
static_id!(StaticReasonCode, ReasonCode);
static_id!(StaticRequestId, RequestId);
static_id!(StaticSubjectSlot, SubjectSlot);
static_id!(StaticTenantId, TenantId);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Language or locale tag used by human-facing reason text.
pub struct Locale(String);

impl Locale {
    /// Creates a locale tag from non-empty ASCII alphanumeric and `-` input.
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
