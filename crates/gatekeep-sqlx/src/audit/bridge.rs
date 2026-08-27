//! Opt-in migration and dual-write support for Dovecote.
//!
//! This module owns only the values shared by the backend-specific bridge
//! implementations.  SQL, transaction ownership, database clocks, and claim
//! fencing remain in the backend modules.  The bridge is deliberately not
//! part of the default audit path: an application must construct a
//! [`DovecoteAuditBridge`] with a stable absolute source and call an explicit
//! bridge method.

use std::time::Duration;

use dovecote::{
    AbsoluteUri, ContentType, EnqueueOutcome, EventData, EventId, EventSource, EventType,
    ImportOutcome, NewEvent, StreamName,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Default stream for Gatekeep decision audit events.
pub const DEFAULT_DOVECOTE_STREAM: &str = "gatekeep-audit";
/// Stable `CloudEvents` type used by the existing Gatekeep audit outbox.
pub const GATEKEEP_AUDIT_EVENT_TYPE: &str = "gatekeep.decision_audit_recorded";
/// Versioned codec used for every payload persisted by the bridge mapping.
pub const BRIDGE_PAYLOAD_CODEC: &str = "gatekeep-audit-json-v1";
/// Provenance for a payload written by the opt-in dual-write path.
pub const BRIDGE_PAYLOAD_PROVENANCE_DUAL_WRITE: &str = "gatekeep-dual-write-v1";
/// Provenance for an exact UTF-8 text payload exported from `SQLite` legacy rows.
pub const BRIDGE_PAYLOAD_PROVENANCE_LEGACY_TEXT: &str = "gatekeep-legacy-text-v1";
/// Provenance for a payload reconstructed from a `PostgreSQL` JSONB or `MySQL`
/// JSON value using [`BRIDGE_PAYLOAD_CODEC`].
pub const BRIDGE_PAYLOAD_PROVENANCE_LEGACY_JSON_VALUE: &str = "gatekeep-legacy-json-value-v1";
const JSON_CONTENT_TYPE: &str = "application/json";

/// Configuration for the opt-in Gatekeep-to-Dovecote bridge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DovecoteAuditBridge {
    source: AbsoluteUri,
    stream: StreamName,
}

impl DovecoteAuditBridge {
    /// Creates a bridge using [`DEFAULT_DOVECOTE_STREAM`].
    ///
    /// The source must be an absolute URI controlled by the application.  It
    /// is intentionally not inferred from a hostname, database, or process.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeConfigError`] when the source is not an absolute URI.
    pub fn new(source: impl Into<String>) -> Result<Self, BridgeConfigError> {
        Self::with_stream(source, DEFAULT_DOVECOTE_STREAM)
    }

    /// Creates a bridge with an application-selected Dovecote stream.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeConfigError`] when the source or stream is invalid.
    pub fn with_stream(
        source: impl Into<String>,
        stream: impl Into<String>,
    ) -> Result<Self, BridgeConfigError> {
        let source = AbsoluteUri::new(source).map_err(BridgeConfigError::Source)?;
        let stream = StreamName::new(stream).map_err(BridgeConfigError::Stream)?;
        Ok(Self { source, stream })
    }

    /// Returns the stable absolute application source.
    #[must_use]
    pub const fn source(&self) -> &AbsoluteUri {
        &self.source
    }

    /// Returns the configured Dovecote stream.
    #[must_use]
    pub const fn stream(&self) -> &StreamName {
        &self.stream
    }

    /// Derives the deterministic identity exposed by a legacy publisher.
    ///
    /// The decimal legacy outbox row ID is used, rather than the decision row
    /// ID.  This distinction is part of the migration contract.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeEventError`] when the row ID or event type is invalid.
    pub fn publication(
        &self,
        legacy_outbox_id: i64,
        event_type: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<BridgePublication, BridgeEventError> {
        self.publication_with_provenance(
            legacy_outbox_id,
            event_type,
            payload,
            BRIDGE_PAYLOAD_PROVENANCE_DUAL_WRITE,
        )
    }

    pub(crate) fn publication_with_provenance(
        &self,
        legacy_outbox_id: i64,
        event_type: impl Into<String>,
        payload: impl Into<Vec<u8>>,
        payload_provenance: &'static str,
    ) -> Result<BridgePublication, BridgeEventError> {
        let event_id = derive_event_id(legacy_outbox_id)?;
        let event_type = event_type.into();
        validate_event_type(&event_type)?;
        let event_type = EventType::new(event_type).map_err(BridgeEventError::EventType)?;
        let payload = payload.into();
        // The legacy outbox is a JSON payload.  Validate it before handing it
        // to a publisher so a bridge identity cannot hide malformed data.
        EventData::json(payload.clone()).map_err(BridgeEventError::Payload)?;
        validate_payload_provenance(payload_provenance)?;
        Ok(BridgePublication {
            legacy_outbox_id,
            source: self.source.as_str().to_owned(),
            event_id: event_id.as_str().to_owned(),
            event_type: event_type.as_str().to_owned(),
            payload_provenance: payload_provenance.to_owned(),
            payload_codec: BRIDGE_PAYLOAD_CODEC.to_owned(),
            payload_digest: payload_digest(&payload),
            payload,
        })
    }

    pub(crate) fn event(
        &self,
        legacy_outbox_id: i64,
        event_type: &str,
        payload: Vec<u8>,
    ) -> Result<NewEvent, BridgeEventError> {
        let event_id = derive_event_id(legacy_outbox_id)?;
        validate_event_type(event_type)?;
        let event_type = EventType::new(event_type).map_err(BridgeEventError::EventType)?;
        let data = EventData::json(payload).map_err(BridgeEventError::Payload)?;
        self.event_with_source(event_id, self.source.as_str(), event_type, data)
    }

    pub(super) fn reconstructed_audit_publication(
        &self,
        decision_id: i64,
        event_type: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<LegacyAuditPublication, BridgeEventError> {
        if decision_id <= 0 {
            return Err(BridgeEventError::LegacyDecisionId(decision_id));
        }

        let event_type = event_type.into();
        validate_event_type(&event_type)?;
        let payload = payload.into();
        EventData::json(payload.clone()).map_err(BridgeEventError::Payload)?;
        validate_payload_provenance(BRIDGE_PAYLOAD_PROVENANCE_LEGACY_JSON_VALUE)?;
        Ok(LegacyAuditPublication {
            decision_id,
            source: self.source.as_str().to_owned(),
            event_id: derive_audit_event_id(decision_id)?.as_str().to_owned(),
            event_type,
            payload_provenance: BRIDGE_PAYLOAD_PROVENANCE_LEGACY_JSON_VALUE.to_owned(),
            payload_codec: BRIDGE_PAYLOAD_CODEC.to_owned(),
            payload_digest: payload_digest(&payload),
            payload,
        })
    }

    pub(super) fn event_from_reconstructed_audit(
        &self,
        publication: &LegacyAuditPublication,
    ) -> Result<NewEvent, BridgeEventError> {
        let event_id =
            EventId::new(publication.event_id.clone()).map_err(BridgeEventError::EventId)?;
        let event_type =
            EventType::new(publication.event_type.clone()).map_err(BridgeEventError::EventType)?;
        validate_event_type(&publication.event_type)?;
        let data =
            EventData::json(publication.payload.clone()).map_err(BridgeEventError::Payload)?;
        self.event_with_source(event_id, &publication.source, event_type, data)
    }

    pub(crate) fn event_from_publication(
        &self,
        publication: &BridgePublication,
    ) -> Result<NewEvent, BridgeEventError> {
        let event_id =
            EventId::new(publication.event_id().to_owned()).map_err(BridgeEventError::EventId)?;
        let event_type = EventType::new(publication.event_type().to_owned())
            .map_err(BridgeEventError::EventType)?;
        validate_event_type(publication.event_type())?;
        let data =
            EventData::json(publication.payload().to_owned()).map_err(BridgeEventError::Payload)?;
        self.event_with_source(event_id, publication.source(), event_type, data)
    }

    fn event_with_source(
        &self,
        event_id: EventId,
        source: &str,
        event_type: EventType,
        data: EventData,
    ) -> Result<NewEvent, BridgeEventError> {
        NewEvent::builder(
            self.stream.clone(),
            event_id,
            EventSource::new(source).map_err(BridgeEventError::Source)?,
            event_type,
        )
        .datacontenttype(
            ContentType::new(JSON_CONTENT_TYPE).map_err(BridgeEventError::ContentType)?,
        )
        .data(data)
        .build()
        .map_err(BridgeEventError::Event)
    }
}

fn derive_event_id(legacy_outbox_id: i64) -> Result<EventId, BridgeEventError> {
    if legacy_outbox_id <= 0 {
        return Err(BridgeEventError::LegacyOutboxId(legacy_outbox_id));
    }
    EventId::new(format!("gatekeep-outbox-{legacy_outbox_id}")).map_err(BridgeEventError::EventId)
}

fn derive_audit_event_id(decision_id: i64) -> Result<EventId, BridgeEventError> {
    if decision_id <= 0 {
        return Err(BridgeEventError::LegacyDecisionId(decision_id));
    }
    EventId::new(format!("gatekeep-audit-legacy-{decision_id}")).map_err(BridgeEventError::EventId)
}

fn validate_event_type(event_type: &str) -> Result<(), BridgeEventError> {
    if event_type != GATEKEEP_AUDIT_EVENT_TYPE {
        return Err(BridgeEventError::EventTypeMismatch {
            expected: GATEKEEP_AUDIT_EVENT_TYPE,
            actual: event_type.to_owned(),
        });
    }
    Ok(())
}

/// Identity and exact payload bytes that a legacy publisher must expose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgePublication {
    legacy_outbox_id: i64,
    source: String,
    event_id: String,
    event_type: String,
    payload_provenance: String,
    payload_codec: String,
    payload_digest: [u8; 32],
    payload: Vec<u8>,
}

/// Reconstructed identity and payload for a normalized decision row that has
/// no legacy outbox row.  This is migration evidence only: there is no legacy
/// publisher claim surface for this publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LegacyAuditPublication {
    pub(super) decision_id: i64,
    pub(super) source: String,
    pub(super) event_id: String,
    pub(super) event_type: String,
    pub(super) payload_provenance: String,
    pub(super) payload_codec: String,
    pub(super) payload_digest: [u8; 32],
    pub(super) payload: Vec<u8>,
}

impl LegacyAuditPublication {
    pub(super) fn from_persisted(
        decision_id: i64,
        persisted: PersistedBridgePublication,
    ) -> Result<Self, BridgeEventError> {
        let PersistedBridgePublication {
            source,
            event_id,
            event_type,
            payload_provenance,
            payload_codec,
            payload_digest: persisted_payload_digest,
            payload,
        } = persisted;
        if decision_id <= 0 {
            return Err(BridgeEventError::LegacyDecisionId(decision_id));
        }

        AbsoluteUri::new(source.clone()).map_err(BridgeEventError::Source)?;
        let expected = derive_audit_event_id(decision_id)?;
        EventId::new(event_id.clone()).map_err(BridgeEventError::EventId)?;
        if event_id != expected.as_str() {
            return Err(BridgeEventError::PersistedIdentity {
                expected: expected.as_str().to_owned(),
                actual: event_id,
            });
        }

        EventType::new(event_type.clone()).map_err(BridgeEventError::EventType)?;
        validate_event_type(&event_type)?;
        EventData::json(payload.clone()).map_err(BridgeEventError::Payload)?;
        validate_payload_provenance(&payload_provenance)?;
        if payload_codec != BRIDGE_PAYLOAD_CODEC {
            return Err(BridgeEventError::PayloadMetadata {
                detail: format!(
                    "unsupported payload codec {payload_codec:?}, expected {BRIDGE_PAYLOAD_CODEC:?}"
                ),
            });
        }

        let persisted_payload_digest =
            <[u8; 32]>::try_from(persisted_payload_digest).map_err(|_| {
                BridgeEventError::PayloadMetadata {
                    detail: "payload digest must contain exactly 32 SHA-256 bytes".to_owned(),
                }
            })?;
        if persisted_payload_digest != payload_digest(&payload) {
            return Err(BridgeEventError::PayloadDigestMismatch);
        }

        Ok(Self {
            decision_id,
            source,
            event_id,
            event_type,
            payload_provenance,
            payload_codec,
            payload_digest: persisted_payload_digest,
            payload,
        })
    }
}

pub(super) struct PersistedBridgePublication {
    pub(super) source: String,
    pub(super) event_id: String,
    pub(super) event_type: String,
    pub(super) payload_provenance: String,
    pub(super) payload_codec: String,
    pub(super) payload_digest: Vec<u8>,
    pub(super) payload: Vec<u8>,
}

impl BridgePublication {
    pub(super) fn from_persisted(
        legacy_outbox_id: i64,
        persisted: PersistedBridgePublication,
    ) -> Result<Self, BridgeEventError> {
        let PersistedBridgePublication {
            source,
            event_id,
            event_type,
            payload_provenance,
            payload_codec,
            payload_digest: persisted_payload_digest,
            payload,
        } = persisted;
        if legacy_outbox_id <= 0 {
            return Err(BridgeEventError::LegacyOutboxId(legacy_outbox_id));
        }
        AbsoluteUri::new(source.clone()).map_err(BridgeEventError::Source)?;
        EventId::new(event_id.clone()).map_err(BridgeEventError::EventId)?;
        let expected = derive_event_id(legacy_outbox_id)?;
        if event_id != expected.as_str() {
            return Err(BridgeEventError::PersistedIdentity {
                expected: expected.as_str().to_owned(),
                actual: event_id,
            });
        }
        EventType::new(event_type.clone()).map_err(BridgeEventError::EventType)?;
        validate_event_type(&event_type)?;
        EventData::json(payload.clone()).map_err(BridgeEventError::Payload)?;
        validate_payload_provenance(&payload_provenance)?;
        if payload_codec != BRIDGE_PAYLOAD_CODEC {
            return Err(BridgeEventError::PayloadMetadata {
                detail: format!(
                    "unsupported payload codec {payload_codec:?}, expected {BRIDGE_PAYLOAD_CODEC:?}"
                ),
            });
        }

        let persisted_payload_digest =
            <[u8; 32]>::try_from(persisted_payload_digest).map_err(|_| {
                BridgeEventError::PayloadMetadata {
                    detail: "payload digest must contain exactly 32 SHA-256 bytes".to_owned(),
                }
            })?;
        if persisted_payload_digest != payload_digest(&payload) {
            return Err(BridgeEventError::PayloadDigestMismatch);
        }
        Ok(Self {
            legacy_outbox_id,
            source,
            event_id,
            event_type,
            payload_provenance,
            payload_codec,
            payload_digest: persisted_payload_digest,
            payload,
        })
    }

    /// Legacy outbox row ID used to derive the `CloudEvents` identity.
    #[must_use]
    pub const fn legacy_outbox_id(&self) -> i64 {
        self.legacy_outbox_id
    }

    /// Stable absolute `CloudEvents` source.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Deterministic `gatekeep-outbox-<legacy outbox id>` event ID.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Legacy event type.
    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// How the bridge obtained the persisted payload bytes.
    #[must_use]
    pub fn payload_provenance(&self) -> &str {
        &self.payload_provenance
    }

    /// Versioned codec name used for the persisted payload bytes.
    #[must_use]
    pub fn payload_codec(&self) -> &str {
        &self.payload_codec
    }

    /// SHA-256 digest of the exact payload bytes.
    #[must_use]
    pub const fn payload_digest(&self) -> &[u8] {
        &self.payload_digest
    }

    /// Exact UTF-8 JSON payload bytes to publish.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Result of a dual-write decision audit operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeWriteOutcome {
    /// Legacy normalized decision row ID.
    pub decision_id: i64,
    /// Legacy outbox row ID.  This, not `decision_id`, is the event identity input.
    pub legacy_outbox_id: i64,
    /// Dovecote's idempotent insertion result.  A successful dual-write leaves
    /// the Dovecote delivery in its initial pending state.
    pub dovecote: EnqueueOutcome,
}

/// Opaque generation for one legacy publisher claim.
///
/// A generation is persisted beside the bridge mapping and is replaced on
/// every bridge-aware acquisition.  It is deliberately independent of the
/// legacy row's owner and expiry: those values are not a lease generation and
/// may repeat after a reclaim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyOutboxClaim {
    legacy_outbox_id: i64,
    token: String,
}

impl LegacyOutboxClaim {
    pub(super) const fn new(legacy_outbox_id: i64, token: String) -> Self {
        Self {
            legacy_outbox_id,
            token,
        }
    }

    /// Legacy outbox row owned by this claim.
    #[must_use]
    pub const fn legacy_outbox_id(&self) -> i64 {
        self.legacy_outbox_id
    }

    /// Opaque token required when acknowledging this claim.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }
}

/// Bounded importer configuration.  Multiple callers may invoke an importer
/// concurrently; the persisted bridge claim token serializes each batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeImportOptions {
    batch_size: u32,
    worker: String,
    lease: Duration,
}

impl BridgeImportOptions {
    /// Creates bounded importer options.
    ///
    /// `batch_size` must be positive and no greater than Dovecote's page
    /// ceiling.  `lease` must be a finite positive duration accepted by
    /// Dovecote.  The worker name is persisted only as operational claim
    /// metadata and must not contain secrets.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeConfigError`] when an option is outside Dovecote's
    /// bounded operational contract.
    pub fn new(
        batch_size: u32,
        worker: impl Into<String>,
        lease: Duration,
    ) -> Result<Self, BridgeConfigError> {
        let batch_size = dovecote::Limit::new(batch_size)
            .map_err(BridgeConfigError::ImportLimit)?
            .get();
        let worker = dovecote::WorkerId::new(worker)
            .map_err(BridgeConfigError::ImportWorker)?
            .as_str()
            .to_owned();
        let lease = dovecote::Lease::new(lease).map_err(BridgeConfigError::ImportLease)?;
        Ok(Self {
            batch_size,
            worker,
            lease: lease.get(),
        })
    }

    /// A conservative one-hundred-row import with a five-minute claim lease.
    ///
    /// # Errors
    ///
    /// This only fails if the constants drift outside Dovecote's validated
    /// bounds.
    pub fn default_checked() -> Result<Self, BridgeConfigError> {
        Self::new(100, "gatekeep-dovecote-importer", Duration::from_mins(5))
    }

    /// Maximum number of legacy rows processed by one transaction.
    #[must_use]
    pub const fn batch_size(&self) -> u32 {
        self.batch_size
    }

    /// Operational identity stored in bridge claim metadata.
    #[must_use]
    pub fn worker(&self) -> &str {
        &self.worker
    }

    /// Duration for which a claimed batch remains owned by the worker.
    #[must_use]
    pub const fn lease(&self) -> Duration {
        self.lease
    }
}

impl Default for BridgeImportOptions {
    fn default() -> Self {
        // These values are also checked by `default_checked`; keeping the
        // infallible default is useful for callers that use configuration
        // structs, while `new` remains available for untrusted input.
        Self {
            batch_size: 100,
            worker: "gatekeep-dovecote-importer".to_owned(),
            lease: Duration::from_mins(5),
        }
    }
}

/// Summary returned after one or more bounded importer batches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeImportReport {
    /// Inclusive high-water normalized decision row ID captured for this
    /// import run.
    pub high_water: i64,
    /// Last normalized legacy decision row ID examined by the importer.
    pub cursor: i64,
    /// Inclusive high-water legacy outbox row ID captured for this import run.
    pub outbox_high_water: i64,
    /// Last legacy outbox row ID examined by the importer.
    pub outbox_cursor: i64,
    /// Number of rows inserted into Dovecote during this call.
    pub imported: u64,
    /// Number of rows that were already present with identical content.
    pub already_imported: u64,
    /// Number of rows represented as delivered imports.
    pub delivered: u64,
    /// True when the high-water range is complete.
    pub complete: bool,
}

impl BridgeImportReport {
    pub(crate) const fn empty(
        high_water: i64,
        cursor: i64,
        outbox_high_water: i64,
        outbox_cursor: i64,
        complete: bool,
    ) -> Self {
        Self {
            high_water,
            cursor,
            outbox_high_water,
            outbox_cursor,
            imported: 0,
            already_imported: 0,
            delivered: 0,
            complete,
        }
    }
}

/// Configuration failures at the bridge boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeConfigError {
    /// The source is not a stable absolute URI.
    #[error("bridge source is not a valid absolute URI: {0}")]
    Source(#[source] dovecote::ValidationError),
    /// The configured stream is invalid.
    #[error("bridge stream is invalid: {0}")]
    Stream(#[source] dovecote::ValidationError),
    /// Import batch size is invalid.
    #[error("bridge import batch size is invalid: {0}")]
    ImportLimit(#[source] dovecote::ValidationError),
    /// Import worker identity is invalid.
    #[error("bridge import worker is invalid: {0}")]
    ImportWorker(#[source] dovecote::ValidationError),
    /// Import lease is invalid.
    #[error("bridge import lease is invalid: {0}")]
    ImportLease(#[source] dovecote::ValidationError),
}

/// Event construction failures before a database transaction is attempted.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeEventError {
    /// Legacy outbox IDs are positive database IDs, not decision IDs.
    #[error("legacy outbox row ID must be positive: {0}")]
    LegacyOutboxId(i64),
    /// Normalized legacy decision IDs are positive database IDs.
    #[error("legacy decision row ID must be positive: {0}")]
    LegacyDecisionId(i64),
    /// Event ID validation failed.
    #[error("derived event ID is invalid: {0}")]
    EventId(#[source] dovecote::ValidationError),
    /// Persisted mapping does not match the deterministic legacy identity.
    #[error("persisted bridge identity is {actual}, expected {expected}")]
    PersistedIdentity {
        /// Identity derived from the legacy outbox row ID.
        expected: String,
        /// Identity found in the persisted mapping.
        actual: String,
    },
    /// Legacy outbox event type is not the Gatekeep audit event type.
    #[error("legacy event type is {actual}, expected {expected}")]
    EventTypeMismatch {
        /// Required Gatekeep audit event type.
        expected: &'static str,
        /// Event type found in the legacy outbox row.
        actual: String,
    },
    /// Event source validation failed.
    #[error("event source is invalid: {0}")]
    Source(#[source] dovecote::ValidationError),
    /// Event type validation failed.
    #[error("legacy event type is invalid: {0}")]
    EventType(#[source] dovecote::ValidationError),
    /// Event content type validation failed.
    #[error("event content type is invalid: {0}")]
    ContentType(#[source] dovecote::ValidationError),
    /// Legacy payload is not one valid JSON value.
    #[error("legacy audit payload is invalid JSON: {0}")]
    Payload(#[source] dovecote::ValidationError),
    /// Payload provenance or codec metadata is not supported by this bridge.
    #[error("invalid bridge payload metadata: {detail}")]
    PayloadMetadata {
        /// Explanation of the invalid metadata.
        detail: String,
    },
    /// Persisted digest does not match the exact bytes being reconciled.
    #[error("persisted bridge payload digest does not match its payload bytes")]
    PayloadDigestMismatch,
    /// The final Dovecote event failed cross-field validation.
    #[error("Dovecote event is invalid: {0}")]
    Event(#[source] dovecote::ValidationError),
}

fn validate_payload_provenance(provenance: &str) -> Result<(), BridgeEventError> {
    if matches!(
        provenance,
        BRIDGE_PAYLOAD_PROVENANCE_DUAL_WRITE
            | BRIDGE_PAYLOAD_PROVENANCE_LEGACY_TEXT
            | BRIDGE_PAYLOAD_PROVENANCE_LEGACY_JSON_VALUE
    ) {
        Ok(())
    } else {
        Err(BridgeEventError::PayloadMetadata {
            detail: format!("unsupported payload provenance {provenance:?}"),
        })
    }
}

/// Encodes a legacy normalized decision value with Gatekeep's named
/// deterministic migration codec.
///
/// Database JSON columns do not preserve the
/// producer's original byte spelling, so callers record this codec and its
/// digest in the mapping. The returned bytes are reconstructed bytes, not a
/// claim about the original database representation.
///
/// # Errors
///
/// Returns the `serde_json` encoding error if the value cannot be serialized.
pub fn encode_reconstructed_audit_v1(
    value: &serde_json::Value,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

/// Encodes a typed Gatekeep audit entry with the same versioned bridge codec.
///
/// This is used by the opt-in dual-write path and is kept beside the
/// reconstruction function so legacy and bridge payloads cannot drift.
///
/// # Errors
///
/// Returns the `serde_json` encoding error if the entry cannot be serialized.
pub fn encode_audit_entry_v1(entry: &gatekeep::AuditEntry) -> Result<Vec<u8>, serde_json::Error> {
    encode_reconstructed_audit_v1(&serde_json::to_value(entry)?)
}

fn payload_digest(payload: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(payload);
    let mut result = [0_u8; 32];
    result.copy_from_slice(&digest);
    result
}

/// Maps a Dovecote import result to a bridge-local count without changing the
/// adapter's exact rerun semantics.
pub(super) const fn count_import(
    outcome: &ImportOutcome,
    delivered: bool,
) -> (bool, bool, bool, Option<dovecote::RowId>) {
    match outcome {
        ImportOutcome::Imported { row_id } => (true, false, delivered, Some(*row_id)),
        ImportOutcome::AlreadyImported { row_id } => (false, true, delivered, Some(*row_id)),
        _ => (false, false, false, None),
    }
}

pub(super) fn new_claim_token(_worker: &str) -> String {
    Uuid::new_v4().simple().to_string()
}

pub(super) const fn outcome_row_id(outcome: &EnqueueOutcome) -> Option<dovecote::RowId> {
    match outcome {
        EnqueueOutcome::Enqueued { row_id } | EnqueueOutcome::AlreadyEnqueued { row_id } => {
            Some(*row_id)
        }
        _ => None,
    }
}

pub(super) const fn import_row_id(outcome: &ImportOutcome) -> Option<dovecote::RowId> {
    match outcome {
        ImportOutcome::Imported { row_id } | ImportOutcome::AlreadyImported { row_id } => {
            Some(*row_id)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_defaults_are_stable_and_sources_must_be_absolute() -> Result<(), BridgeConfigError> {
        let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
        assert_eq!(
            bridge.source().as_str(),
            "https://auth.example.test/gatekeep"
        );
        assert_eq!(bridge.stream().as_str(), DEFAULT_DOVECOTE_STREAM);
        assert!(DovecoteAuditBridge::new("auth.example.test/gatekeep").is_err());
        Ok(())
    }

    #[test]
    fn publication_uses_legacy_outbox_id_and_exact_json_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let bridge = DovecoteAuditBridge::new("https://auth.example.test/gatekeep")?;
        let payload = br#"{"z":1,"a":[true,null]}"#.to_vec();
        let publication = bridge.publication(41, GATEKEEP_AUDIT_EVENT_TYPE, payload.clone())?;
        assert_eq!(publication.event_id(), "gatekeep-outbox-41");
        assert_eq!(publication.payload(), payload.as_slice());
        assert_eq!(
            publication.payload_provenance(),
            BRIDGE_PAYLOAD_PROVENANCE_DUAL_WRITE
        );
        assert_eq!(publication.payload_codec(), BRIDGE_PAYLOAD_CODEC);
        assert_eq!(publication.payload_digest().len(), 32);
        let event = bridge.event(41, GATEKEEP_AUDIT_EVENT_TYPE, payload.clone())?;
        assert_eq!(event.stream().as_str(), DEFAULT_DOVECOTE_STREAM);
        assert_eq!(event.id().as_str(), "gatekeep-outbox-41");
        assert_eq!(event.source().as_str(), publication.source());
        assert_eq!(event.event_type().as_str(), GATEKEEP_AUDIT_EVENT_TYPE);
        assert_eq!(
            event.datacontenttype().map(ContentType::as_str),
            Some(JSON_CONTENT_TYPE)
        );
        assert!(event.time().is_none());
        assert_eq!(
            event.data().map(EventData::as_bytes),
            Some(payload.as_slice())
        );
        Ok(())
    }

    #[test]
    fn persisted_identity_rejects_config_or_mapping_drift() {
        let result = BridgePublication::from_persisted(
            41,
            PersistedBridgePublication {
                source: "https://auth.example.test/gatekeep".to_owned(),
                event_id: "wrong-id".to_owned(),
                event_type: GATEKEEP_AUDIT_EVENT_TYPE.to_owned(),
                payload_provenance: BRIDGE_PAYLOAD_PROVENANCE_DUAL_WRITE.to_owned(),
                payload_codec: BRIDGE_PAYLOAD_CODEC.to_owned(),
                payload_digest: vec![0; 32],
                payload: br"{}".to_vec(),
            },
        );
        assert!(matches!(
            result,
            Err(BridgeEventError::PersistedIdentity { .. })
        ));
    }

    #[test]
    fn importer_defaults_are_bounded() {
        let options = BridgeImportOptions::default();
        assert_eq!(options.batch_size(), 100);
        assert_eq!(options.worker(), "gatekeep-dovecote-importer");
        assert_eq!(options.lease(), Duration::from_mins(5));
        assert!(BridgeImportOptions::new(0, "worker", Duration::from_secs(1)).is_err());
    }

    #[test]
    fn named_json_codec_has_stable_golden_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let value: serde_json::Value = serde_json::from_str(
            r#"{"number":1.25,"missing":null,"empty":[],"blank":"","nested":{"é":"café"}}"#,
        )?;
        assert_eq!(
            encode_reconstructed_audit_v1(&value)?,
            r#"{"number":1.25,"missing":null,"empty":[],"blank":"","nested":{"é":"café"}}"#
                .as_bytes()
        );
        assert!(
            !String::from_utf8(encode_reconstructed_audit_v1(
                &serde_json::json!({"present": [], "blank": ""})
            )?)?
            .contains("absent")
        );
        Ok(())
    }
}
