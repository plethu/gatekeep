use std::collections::BTreeMap;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use gatekeep::{DenialReason, DenyShape, Locale, ReasonCatalog, ReasonCode};
use serde::{Deserialize, Serialize};

/// HTTP denial category returned by the axum adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialError {
    /// The resource may exist, but the principal is not allowed to access it.
    Forbidden,
    /// The denial must be presented as a generic missing resource.
    NotFound,
}

/// JSON body emitted for authorization denials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenialBody {
    /// Stable HTTP-facing denial category.
    pub error: DenialError,
    /// Human-facing localized or configured message.
    pub message: String,
    /// Specific stable reason code, omitted for hidden denials.
    pub reason: Option<String>,
}

/// HTTP denial response produced by a policy denial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DenialResponse {
    /// HTTP status selected from the denial shape.
    pub status: StatusCode,
    /// JSON response body.
    pub body: DenialBody,
}

impl IntoResponse for DenialResponse {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

/// Presentation settings for policy denials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DenialResponseConfig {
    forbidden_fallback: String,
    hidden_fallback: String,
    hidden_reason: Option<ReasonCode>,
}

impl DenialResponseConfig {
    /// Creates response settings with conservative default messages.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses this message when a forbidden denial has no stable reason.
    #[must_use]
    pub fn with_forbidden_fallback(mut self, message: impl Into<String>) -> Self {
        self.forbidden_fallback = message.into();
        self
    }

    /// Uses this message for hidden denials unless a generic hidden reason is configured.
    #[must_use]
    pub fn with_hidden_fallback(mut self, message: impl Into<String>) -> Self {
        self.hidden_fallback = message.into();
        self
    }

    /// Renders hidden denials through the catalog using this generic reason code.
    ///
    /// The configured code is a replacement for the hidden policy reason, not
    /// the hidden policy reason itself.
    pub fn try_with_hidden_reason(
        mut self,
        reason: impl Into<String>,
    ) -> gatekeep::GatekeepResult<Self> {
        self.hidden_reason = Some(ReasonCode::new(reason)?);
        Ok(self)
    }

    pub(crate) fn denied<C: ReasonCatalog>(
        &self,
        shape: DenyShape,
        reason: Option<&DenialReason>,
        locale: &Locale,
        catalog: &C,
    ) -> DenialResponse {
        match shape {
            DenyShape::Forbidden => self.forbidden(reason, locale, catalog),
            DenyShape::Hidden => self.hidden(locale, catalog),
        }
    }

    fn forbidden<C: ReasonCatalog>(
        &self,
        reason: Option<&DenialReason>,
        locale: &Locale,
        catalog: &C,
    ) -> DenialResponse {
        let message = reason.map_or_else(
            || self.forbidden_fallback.clone(),
            |reason| catalog.render(reason, locale),
        );
        DenialResponse {
            status: StatusCode::FORBIDDEN,
            body: DenialBody {
                error: DenialError::Forbidden,
                message,
                reason: reason.map(|reason| reason.code.as_str().to_owned()),
            },
        }
    }

    fn hidden<C: ReasonCatalog>(&self, locale: &Locale, catalog: &C) -> DenialResponse {
        let message = self.hidden_reason.as_ref().map_or_else(
            || self.hidden_fallback.clone(),
            |code| {
                let reason = DenialReason {
                    code: code.clone(),
                    params: BTreeMap::new(),
                    shape: DenyShape::Forbidden,
                };
                catalog.render(&reason, locale)
            },
        );
        DenialResponse {
            status: StatusCode::NOT_FOUND,
            body: DenialBody {
                error: DenialError::NotFound,
                message,
                reason: None,
            },
        }
    }
}

impl Default for DenialResponseConfig {
    fn default() -> Self {
        Self {
            forbidden_fallback: "forbidden".to_owned(),
            hidden_fallback: "not found".to_owned(),
            hidden_reason: None,
        }
    }
}
