//! Dovecote-backed decision audit event construction.
//!
//! Gatekeep owns the typed decision value; Dovecote owns durable SQL event and
//! delivery state. This module only validates the application source and
//! serializes one complete [`gatekeep::AuditEntry`] into Dovecote's event
//! shape. It deliberately contains no Gatekeep-owned audit tables or paging
//! model.

use gatekeep::{AuditEntry, DecisionAuditId, GatekeepError};
use serde_json::Error as JsonError;
use thiserror::Error;
use url::Url;

use dovecote::{ContentType, EventData, EventId, EventSource, EventType, NewEvent, StreamName};

#[cfg(feature = "mysql")]
mod mysql;
#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "sqlite")]
mod sqlite;

#[cfg(feature = "mysql")]
pub use self::mysql::{MySqlDovecoteAudit, MySqlDovecoteAuditError};
#[cfg(feature = "postgres")]
pub use self::postgres::{PgDovecoteAudit, PgDovecoteAuditError};
#[cfg(feature = "sqlite")]
pub use self::sqlite::{SqliteDovecoteAudit, SqliteDovecoteAuditError};

/// The default Dovecote stream for Gatekeep decision audit events.
pub const DEFAULT_AUDIT_STREAM: &str = "gatekeep-audit";
/// The durable event type for Gatekeep decision audit events.
pub const DECISION_AUDIT_EVENT_TYPE: &str = "gatekeep.decision_audit_recorded";
/// The explicit JSON content type used for every decision audit event.
pub const DECISION_AUDIT_CONTENT_TYPE: &str = "application/json";

/// Configuration required to write Gatekeep audit events.
///
/// The source is application-owned and must be an absolute URI. Gatekeep does
/// not invent an identity for the application or use a process-local default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionAuditConfig {
    source: EventSource,
    stream: StreamName,
    event_type: EventType,
    content_type: ContentType,
}

impl DecisionAuditConfig {
    /// Creates configuration using Gatekeep's stable stream, event type, and
    /// JSON content type defaults.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionAuditConfigError::Source`] when `source` is not an
    /// absolute URI accepted by `CloudEvents`.
    pub fn new(source: impl Into<String>) -> Result<Self, DecisionAuditConfigError> {
        let source = source.into();
        let parsed = Url::parse(&source).map_err(|_| DecisionAuditConfigError::Source {
            value: source.clone(),
        })?;
        if parsed.scheme().is_empty() {
            return Err(DecisionAuditConfigError::Source { value: source });
        }

        Ok(Self {
            source: EventSource::new(source)
                .map_err(|source| DecisionAuditConfigError::SourceValue { source })?,
            stream: StreamName::new(DEFAULT_AUDIT_STREAM)
                .map_err(|source| DecisionAuditConfigError::Stream { source })?,
            event_type: EventType::new(DECISION_AUDIT_EVENT_TYPE)
                .map_err(|source| DecisionAuditConfigError::EventType { source })?,
            content_type: ContentType::new(DECISION_AUDIT_CONTENT_TYPE)
                .map_err(|source| DecisionAuditConfigError::ContentType { source })?,
        })
    }

    /// Returns the configured absolute event source.
    #[must_use]
    pub const fn source(&self) -> &EventSource {
        &self.source
    }

    /// Returns the fixed Gatekeep audit stream.
    #[must_use]
    pub const fn stream(&self) -> &StreamName {
        &self.stream
    }

    /// Returns the fixed Gatekeep audit event type.
    #[must_use]
    pub const fn event_type(&self) -> &EventType {
        &self.event_type
    }
}

/// Errors while validating the application-owned audit source.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DecisionAuditConfigError {
    /// The source was not an absolute URI.
    #[error("decision audit source must be an absolute URI: {value}")]
    Source {
        /// Rejected source value.
        value: String,
    },
    /// Dovecote rejected the source URI.
    #[error("invalid decision audit source: {source}")]
    SourceValue {
        /// Validation failure from Dovecote.
        #[source]
        source: dovecote::ValidationError,
    },
    /// The built-in stream default was rejected by Dovecote.
    #[error("invalid decision audit stream: {source}")]
    Stream {
        /// Validation failure from Dovecote.
        #[source]
        source: dovecote::ValidationError,
    },
    /// The built-in event type was rejected by Dovecote.
    #[error("invalid decision audit event type: {source}")]
    EventType {
        /// Validation failure from Dovecote.
        #[source]
        source: dovecote::ValidationError,
    },
    /// The built-in content type was rejected by Dovecote.
    #[error("invalid decision audit content type: {source}")]
    ContentType {
        /// Validation failure from Dovecote.
        #[source]
        source: dovecote::ValidationError,
    },
}

/// Errors while converting a typed Gatekeep entry into a validated Dovecote
/// event.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DecisionAuditEventError {
    /// The typed entry could not be serialized as JSON.
    #[error("serialize decision audit entry")]
    Json(#[source] JsonError),
    /// The entry uses the migration-only legacy identity namespace.
    #[error("validate decision audit identity")]
    Identity(#[source] GatekeepError),
    /// The generated event identity or event content failed Dovecote
    /// validation.
    #[error("validate decision audit event")]
    Validation(#[source] dovecote::ValidationError),
}

/// Errors returned while decoding a Dovecote event as a Gatekeep decision
/// audit entry.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DecisionAuditDecodeError {
    /// A required Dovecote event attribute did not match Gatekeep's contract.
    #[error("unexpected Gatekeep decision audit event {field}")]
    UnexpectedShape {
        /// Attribute that did not match.
        field: &'static str,
    },
    /// The event did not carry JSON data.
    #[error("decision audit event has no JSON payload")]
    MissingPayload,
    /// The event payload was not a valid typed entry.
    #[error("decode decision audit payload")]
    Json(#[source] JsonError),
    /// The event identity suffix was not a valid typed decision identity.
    #[error("decode decision audit identity")]
    Identity(#[source] GatekeepError),
}

/// Decodes a Dovecote event from either live or snapshot paging into the
/// complete typed Gatekeep audit entry.
///
/// This is a projection over Dovecote's event model; it does not create a
/// second SQL audit repository or delivery state. The event's source, stream,
/// type, content type, identity, and occurrence time are checked before the
/// payload is accepted.
///
/// # Errors
///
/// Returns [`DecisionAuditDecodeError`] when the event shape or typed JSON
/// payload does not match Gatekeep's event contract.
pub fn decode_decision_audit(
    config: &DecisionAuditConfig,
    event: &dovecote::StoredEvent,
) -> Result<AuditEntry, DecisionAuditDecodeError> {
    if event.stream() != config.stream()
        || event.source() != config.source()
        || event.event_type() != config.event_type()
        || event.datacontenttype().map(dovecote::ContentType::as_str)
            != Some(DECISION_AUDIT_CONTENT_TYPE)
    {
        return Err(DecisionAuditDecodeError::UnexpectedShape {
            field: "attributes",
        });
    }

    let Some(dovecote::EventData::Json(payload)) = event.data() else {
        return Err(DecisionAuditDecodeError::MissingPayload);
    };

    let entry = decode_payload(payload.as_bytes())?;
    let expected_id = format!("gatekeep-audit-{}", entry.decision_audit_id.as_str());
    if event.id().as_str() != expected_id || event.time() != Some(entry.occurred_at) {
        return Err(DecisionAuditDecodeError::UnexpectedShape {
            field: "identity or occurrence time",
        });
    }
    // Deserialization already validates this field. Reconstructing it here
    // makes the identity boundary explicit and keeps this check future-proof
    // if AuditEntry's representation ever becomes more permissive.
    if !entry.decision_audit_id.as_str().starts_with("legacy-") {
        DecisionAuditId::new(entry.decision_audit_id.as_str().to_owned())
            .map_err(DecisionAuditDecodeError::Identity)?;
    }
    Ok(entry)
}

/// Decodes normal payloads through their ordinary serde contract, with one
/// migration-only exception for the reserved legacy identity namespace. The
/// exception is deliberately local to history projection: normal
/// `AuditEntry` deserialization and new-decision construction still reject
/// `legacy-` identities.
fn decode_payload(payload: &[u8]) -> Result<AuditEntry, DecisionAuditDecodeError> {
    let mut value: serde_json::Value =
        serde_json::from_slice(payload).map_err(DecisionAuditDecodeError::Json)?;
    let Some(raw_id) = value.get("decision_audit_id").and_then(|id| id.as_str()) else {
        return serde_json::from_value(value).map_err(DecisionAuditDecodeError::Json);
    };

    if !raw_id.starts_with("legacy-") {
        return serde_json::from_value(value).map_err(DecisionAuditDecodeError::Json);
    }

    let legacy_id = DecisionAuditId::from_legacy_import(raw_id.to_owned())
        .map_err(DecisionAuditDecodeError::Identity)?;
    // Deserialize every other field through AuditEntry's typed contract. A
    // non-legacy placeholder is used only while serde constructs the record;
    // it never escapes this function.
    value["decision_audit_id"] = serde_json::Value::String("imported-history".to_owned());
    let mut entry: AuditEntry =
        serde_json::from_value(value).map_err(DecisionAuditDecodeError::Json)?;
    entry.decision_audit_id = legacy_id;
    Ok(entry)
}

fn event_from_entry(
    config: &DecisionAuditConfig,
    entry: &AuditEntry,
) -> Result<NewEvent, DecisionAuditEventError> {
    // Legacy identities are accepted only by the history decoder. Ordinary
    // enqueue must never create a fresh event in the migration namespace.
    DecisionAuditId::new(entry.decision_audit_id.as_str().to_owned())
        .map_err(DecisionAuditEventError::Identity)?;
    let event_id = EventId::new(format!(
        "gatekeep-audit-{}",
        entry.decision_audit_id.as_str()
    ))
    .map_err(DecisionAuditEventError::Validation)?;
    let payload = serde_json::to_vec(entry).map_err(DecisionAuditEventError::Json)?;
    NewEvent::builder(
        config.stream.clone(),
        event_id,
        config.source.clone(),
        config.event_type.clone(),
    )
    .time(entry.occurred_at)
    .datacontenttype(config.content_type.clone())
    .data(EventData::json(payload).map_err(DecisionAuditEventError::Validation)?)
    .build()
    .map_err(DecisionAuditEventError::Validation)
}
