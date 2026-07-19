//! Test helpers for asserting gatekeep axum denial responses.

use axum::{
    body::{Body, to_bytes},
    http::StatusCode,
    response::Response,
};
use thiserror::Error;

use crate::{DenialBody, DenialError};

const DENIAL_BODY_FIELDS: &[&str] = &["error", "message", "reason"];

/// Expected HTTP denial response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedDenial {
    status: StatusCode,
    error: DenialError,
    message: Option<String>,
    reason: ExpectedReason,
}

impl ExpectedDenial {
    /// Expects a visible forbidden denial.
    #[must_use]
    pub const fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error: DenialError::Forbidden,
            message: None,
            reason: ExpectedReason::Any,
        }
    }

    /// Expects a hidden not-found denial.
    #[must_use]
    pub const fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error: DenialError::NotFound,
            message: None,
            reason: ExpectedReason::Any,
        }
    }

    /// Expects the denial body to contain this exact message.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Expects the denial body to contain this exact reason code.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = ExpectedReason::Some(reason.into());
        self
    }

    /// Expects the denial body to omit its reason code.
    #[must_use]
    pub fn without_reason(mut self) -> Self {
        self.reason = ExpectedReason::None;
        self
    }
}

/// Parses and asserts an axum denial response.
///
/// The parsed body is returned so tests can make additional application-specific
/// assertions without reparsing the response.
///
/// # Errors
///
/// Returns [`DenialAssertError`] if the HTTP status, JSON body, denial category,
/// message, or reason does not match the expectation.
pub async fn assert_denial_response(
    response: Response<Body>,
    expected: ExpectedDenial,
) -> Result<DenialBody, DenialAssertError> {
    let status = response.status();
    if status != expected.status {
        return Err(DenialAssertError::Status {
            expected: expected.status,
            actual: status,
        });
    }

    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .map_err(DenialAssertError::Body)?;
    let value =
        serde_json::from_slice::<serde_json::Value>(&bytes).map_err(DenialAssertError::Json)?;
    let fields = denial_body_fields(&value)?;
    if fields != DENIAL_BODY_FIELDS {
        return Err(DenialAssertError::Fields { actual: fields });
    }

    let body = serde_json::from_value::<DenialBody>(value).map_err(DenialAssertError::Json)?;
    if body.error != expected.error {
        return Err(DenialAssertError::Error {
            expected: expected.error,
            actual: body.error,
        });
    }

    if let Some(expected_message) = expected.message
        && body.message != expected_message
    {
        return Err(DenialAssertError::Message {
            expected: expected_message,
            actual: body.message,
        });
    }

    match expected.reason {
        ExpectedReason::None if body.reason.is_some() => {
            return Err(DenialAssertError::Reason {
                expected: None,
                actual: body.reason,
            });
        }
        ExpectedReason::Some(expected_reason)
            if body.reason.as_deref() != Some(&expected_reason) =>
        {
            return Err(DenialAssertError::Reason {
                expected: Some(expected_reason),
                actual: body.reason,
            });
        }
        ExpectedReason::Any | ExpectedReason::None | ExpectedReason::Some(_) => {}
    }
    Ok(body)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExpectedReason {
    Any,
    None,
    Some(String),
}

fn denial_body_fields(value: &serde_json::Value) -> Result<Vec<String>, DenialAssertError> {
    let serde_json::Value::Object(object) = value else {
        return Err(DenialAssertError::Shape);
    };

    let mut fields = object.keys().cloned().collect::<Vec<_>>();
    fields.sort();
    Ok(fields)
}

/// Error returned by [`assert_denial_response`].
#[derive(Debug, Error)]
pub enum DenialAssertError {
    /// The HTTP status did not match.
    #[error("expected denial status {expected}, got {actual}")]
    Status {
        /// Expected HTTP status.
        expected: StatusCode,
        /// Actual HTTP status.
        actual: StatusCode,
    },
    /// The response body could not be collected.
    #[error("failed to read denial body")]
    Body(#[source] axum::Error),
    /// The response body was not a `DenialBody` JSON payload.
    #[error("failed to decode denial body")]
    Json(#[source] serde_json::Error),
    /// The response body was not a JSON object.
    #[error("denial body must be a JSON object")]
    Shape,
    /// The response body contained unexpected fields.
    #[error("expected denial fields [\"error\", \"message\", \"reason\"], got {actual:?}")]
    Fields {
        /// Actual response fields.
        actual: Vec<String>,
    },
    /// The denial category did not match.
    #[error("expected denial error {expected:?}, got {actual:?}")]
    Error {
        /// Expected denial category.
        expected: DenialError,
        /// Actual denial category.
        actual: DenialError,
    },
    /// The denial message did not match.
    #[error("expected denial message {expected:?}, got {actual:?}")]
    Message {
        /// Expected denial message.
        expected: String,
        /// Actual denial message.
        actual: String,
    },
    /// The denial reason did not match.
    #[error("expected denial reason {expected:?}, got {actual:?}")]
    Reason {
        /// Expected denial reason.
        expected: Option<String>,
        /// Actual denial reason.
        actual: Option<String>,
    },
}
