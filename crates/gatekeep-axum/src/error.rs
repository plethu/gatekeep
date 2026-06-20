use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

use crate::DenialResponse;

/// Error produced while resolving, evaluating, tracing, or auditing a decision.
#[derive(Debug, Error)]
pub enum GatekeepAxumError<Resolve, Audit> {
    /// Policy hashing failed before the decision could be anchored.
    #[error("failed to hash policy")]
    PolicyHash(#[source] postcard::Error),
    /// Fact resolution failed before evaluation.
    #[error(transparent)]
    Resolve(#[from] gatekeep::ResolveError<Resolve>),
    /// Trace serialization failed after evaluation.
    #[error(transparent)]
    Trace(#[from] gatekeep::TraceError),
    /// Audit recording failed.
    #[error("audit sink failed")]
    Audit(#[source] Audit),
}

/// Axum rejection returned by [`crate::Gatekeeper::authorize`].
#[derive(Debug)]
pub enum GatekeepRejection<Resolve, Audit> {
    /// The policy denied the request.
    Denied(DenialResponse),
    /// The authorization boundary failed before a response could be trusted.
    Error(GatekeepAxumError<Resolve, Audit>),
}

impl<Resolve, Audit> GatekeepRejection<Resolve, Audit> {
    pub(crate) const fn from_error(error: GatekeepAxumError<Resolve, Audit>) -> Self {
        Self::Error(error)
    }
}

impl<Resolve, Audit> From<DenialResponse> for GatekeepRejection<Resolve, Audit> {
    fn from(response: DenialResponse) -> Self {
        Self::Denied(response)
    }
}

impl<Resolve, Audit> From<GatekeepAxumError<Resolve, Audit>> for GatekeepRejection<Resolve, Audit> {
    fn from(error: GatekeepAxumError<Resolve, Audit>) -> Self {
        Self::Error(error)
    }
}

impl<Resolve, Audit> IntoResponse for GatekeepRejection<Resolve, Audit> {
    fn into_response(self) -> Response {
        match self {
            Self::Denied(denial) => denial.into_response(),
            Self::Error(_error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "authorization_error",
                    message: "authorization failed",
                }),
            )
                .into_response(),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: &'static str,
}
