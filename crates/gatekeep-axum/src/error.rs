use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::DenialResponse;

/// Framework-independent authorization failure.
pub use gatekeep::AuthorizationError as GatekeepAxumError;

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
