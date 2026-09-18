use dovecote::{EventData, EventId, EventType, NewEvent, PagedEvent, TenantId};
use gatekeep::AuthorizationAttempt;
use thiserror::Error;

use super::{DECISION_AUDIT_CONTENT_TYPE, DecisionAuditConfig};

/// Event type distinguishing failed attempts from completed policy decisions.
pub const ATTEMPT_AUDIT_EVENT_TYPE: &str = "gatekeep.authorization_attempt_failed";

/// Invalid attempt event or durable payload.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AttemptAuditEventError {
    /// Encoded evidence exceeds the supported one MiB payload bound.
    #[error("authorization attempt payload exceeds size limit")]
    PayloadTooLarge,
    /// Invalid Gatekeep attempt record.
    #[error(transparent)]
    Attempt(#[from] gatekeep::AttemptValidationError),
    /// Invalid event attributes.
    #[error(transparent)]
    Event(#[from] dovecote::ValidationError),
    /// Invalid JSON payload.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Stored attributes or tenant disagree with the record.
    #[error("authorization attempt event does not match its payload")]
    Shape,
}

pub(super) fn event_from_attempt(
    config: &DecisionAuditConfig,
    entry: &AuthorizationAttempt,
) -> Result<(TenantId, NewEvent), AttemptAuditEventError> {
    entry.validate()?;
    let payload = serde_json::to_vec(entry)?;
    if payload.len() > super::MAX_AUDIT_PAYLOAD_BYTES {
        return Err(AttemptAuditEventError::PayloadTooLarge);
    }

    let event = NewEvent::builder(
        config.stream().clone(),
        EventId::new(format!(
            "gatekeep-attempt-{}",
            entry.occurrence().decision_audit_id()
        ))?,
        config.source().clone(),
        EventType::new(ATTEMPT_AUDIT_EVENT_TYPE)?,
    )
    .time(entry.occurrence().occurred_at())
    .datacontenttype(dovecote::ContentType::new(DECISION_AUDIT_CONTENT_TYPE)?)
    .data(EventData::json(payload)?)
    .build()?;
    Ok((TenantId::new(entry.tenant().as_str())?, event))
}

/// Decodes a bounded attempt event and verifies scope, identity, time and type.
///
/// # Errors
/// Rejects malformed, mismatched or oversized records. Decision events need
/// [`super::decode_decision_audit`], never this decoder.
pub fn decode_authorization_attempt(
    config: &DecisionAuditConfig,
    paged: &PagedEvent,
) -> Result<AuthorizationAttempt, AttemptAuditEventError> {
    let event = paged.event();
    if event.stream() != config.stream()
        || event.source() != config.source()
        || event.event_type().as_str() != ATTEMPT_AUDIT_EVENT_TYPE
        || event.datacontenttype().map(dovecote::ContentType::as_str)
            != Some(DECISION_AUDIT_CONTENT_TYPE)
    {
        return Err(AttemptAuditEventError::Shape);
    }

    let Some(EventData::Json(payload)) = event.data() else {
        return Err(AttemptAuditEventError::Shape);
    };

    if payload.as_bytes().len() > super::MAX_AUDIT_PAYLOAD_BYTES {
        return Err(AttemptAuditEventError::Shape);
    }

    let entry: AuthorizationAttempt = serde_json::from_slice(payload.as_bytes())?;
    if entry.tenant().as_str() != paged.tenant_id().as_str()
        || event.time() != Some(entry.occurrence().occurred_at())
        || event.id().as_str()
            != format!(
                "gatekeep-attempt-{}",
                entry.occurrence().decision_audit_id()
            )
    {
        return Err(AttemptAuditEventError::Shape);
    }

    entry.validate()?;
    Ok(entry)
}
