use crate::{AuditEntry, DecisionSummary, Locale};
use async_trait::async_trait;
use std::convert::Infallible;
use std::error::Error as StdError;

/// Side-channel observer for decision summaries.
pub trait PolicyObserver: Send + Sync {
    /// Records or exports a decision summary.
    fn observe(&self, decision_summary: &DecisionSummary);
}

/// Observer that discards decision summaries.
#[derive(Default)]
pub struct NoopPolicyObserver;

impl PolicyObserver for NoopPolicyObserver {
    fn observe(&self, _decision_summary: &DecisionSummary) {}
}

/// Append-only audit boundary.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Sink-specific write error.
    type Error: StdError + Send + Sync + 'static;

    /// Records a durable audit entry.
    async fn record(&self, entry: &AuditEntry) -> Result<(), Self::Error>;
}

/// Audit sink that discards entries.
#[derive(Default)]
pub struct NoopAuditSink;

#[async_trait]
impl AuditSink for NoopAuditSink {
    type Error = Infallible;

    async fn record(&self, _entry: &AuditEntry) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Presentation adapter for localized denial reasons.
pub trait ReasonCatalog {
    /// Renders a denial reason for the requested locale.
    fn render(&self, reason: &crate::DenialReason, locale: &Locale) -> String;
}

/// Reason catalog that renders the stable reason code.
#[derive(Default)]
pub struct IdentityReasonCatalog;

impl ReasonCatalog for IdentityReasonCatalog {
    fn render(&self, reason: &crate::DenialReason, _locale: &Locale) -> String {
        reason.code.as_str().to_owned()
    }
}
