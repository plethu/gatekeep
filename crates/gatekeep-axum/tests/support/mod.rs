//! Test fixtures for gatekeep-axum integration tests.

use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use gatekeep::{
    AuditEntry, AuditSink, Context, DecisionSummary, Fact, FactId, FactResolver, KnownFacts,
    Lattice, Locale, PartialFacts, Policy, PolicyObserver, ReasonCatalog, ResolveError,
    StaticFactId, SubjectRef, TenantId, condition, policy,
};
use gatekeep_axum::GatekeepRejection;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum Access {
    Denied,
    Full,
}

impl Lattice for Access {
    fn meet(&self, other: &Self) -> Self {
        std::cmp::min(*self, *other)
    }

    fn join(&self, other: &Self) -> Self {
        std::cmp::max(*self, *other)
    }

    fn top() -> Self {
        Self::Full
    }

    fn bottom() -> Self {
        Self::Denied
    }
}

pub struct CaseReader;

impl Fact for CaseReader {
    const ID: StaticFactId = StaticFactId::new("case_reader");
}

#[derive(Clone)]
pub struct StaticResolver {
    pub facts: KnownFacts,
}

#[async_trait]
impl FactResolver for StaticResolver {
    type Error = Infallible;

    async fn resolve_for_decision(
        &self,
        _required: &[FactId],
        _cx: &Context,
    ) -> Result<KnownFacts, ResolveError<Self::Error>> {
        Ok(self.facts.clone())
    }

    async fn resolve_for_query(
        &self,
        _required: &[FactId],
        _cx: &Context,
    ) -> Result<PartialFacts, ResolveError<Self::Error>> {
        Ok(PartialFacts::new())
    }
}

#[derive(Clone, Default)]
pub struct RecordingAudit {
    entries: Arc<Mutex<Vec<AuditEntry>>>,
}

impl RecordingAudit {
    pub fn entries(&self) -> Result<Vec<AuditEntry>, RecordingError> {
        self.entries
            .lock()
            .map_err(|_error| RecordingError::Poisoned)
            .map(|entries| entries.clone())
    }
}

impl AuditSink for RecordingAudit {
    type Error = RecordingError;

    fn record(&self, entry: &AuditEntry) -> Result<(), Self::Error> {
        self.entries
            .lock()
            .map_err(|_error| RecordingError::Poisoned)?
            .push(entry.clone());
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct FailingAudit;

impl AuditSink for FailingAudit {
    type Error = FailingAuditError;

    fn record(&self, _entry: &AuditEntry) -> Result<(), Self::Error> {
        Err(FailingAuditError)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("audit write failed")]
pub struct FailingAuditError;

#[derive(Clone, Default)]
pub struct RecordingObserver {
    summaries: Arc<Mutex<Vec<DecisionSummary>>>,
}

impl RecordingObserver {
    pub fn summaries(&self) -> Result<Vec<DecisionSummary>, RecordingError> {
        self.summaries
            .lock()
            .map_err(|_error| RecordingError::Poisoned)
            .map(|summaries| summaries.clone())
    }
}

impl PolicyObserver for RecordingObserver {
    fn observe(&self, decision_summary: &DecisionSummary) {
        if let Ok(mut summaries) = self.summaries.lock() {
            summaries.push(decision_summary.clone());
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecordingError {
    #[error("recording buffer is poisoned")]
    Poisoned,
}

#[derive(Clone, Default)]
pub struct StaticCatalog {
    messages: BTreeMap<String, String>,
}

impl StaticCatalog {
    pub fn with_message(mut self, code: &str, message: &str) -> Self {
        self.messages.insert(code.to_owned(), message.to_owned());
        self
    }
}

impl ReasonCatalog for StaticCatalog {
    fn render(&self, reason: &gatekeep::DenialReason, _locale: &Locale) -> String {
        self.messages
            .get(reason.code.as_str())
            .cloned()
            .unwrap_or_else(|| reason.code.as_str().to_owned())
    }
}

#[derive(Clone, Default)]
pub struct ShapeAwareCatalog;

impl ReasonCatalog for ShapeAwareCatalog {
    fn render(&self, reason: &gatekeep::DenialReason, _locale: &Locale) -> String {
        match reason.shape {
            gatekeep::DenyShape::Forbidden if reason.code.as_str() == "not-found" => {
                "missing".to_owned()
            }
            gatekeep::DenyShape::Hidden => "hidden code suppressed".to_owned(),
            gatekeep::DenyShape::Forbidden => reason.code.as_str().to_owned(),
        }
    }
}

pub fn read_policy() -> Result<Policy<Access>, gatekeep::GatekeepError> {
    policy::grant(Access::Full, condition::has::<CaseReader>())
        .try_labeled("case_read")?
        .try_reason("case-read-denied")
}

pub fn hidden_read_policy() -> Result<Policy<Access>, gatekeep::GatekeepError> {
    Ok(read_policy()?.hidden())
}

pub fn context() -> Result<Context, gatekeep::GatekeepError> {
    Ok(Context {
        tenant: TenantId::new("tenant_a")?,
        principal: SubjectRef::new("user", "mari")?,
        subjects: std::collections::BTreeMap::new(),
        locale: Locale::new("en-US")?,
        request_id: None,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum TestError {
    #[error(transparent)]
    Gatekeep(#[from] gatekeep::GatekeepError),
    #[error(transparent)]
    Record(#[from] RecordingError),
    #[error(transparent)]
    Http(#[from] axum::http::Error),
    #[error(transparent)]
    Axum(#[from] axum::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    DenialAssert(#[from] gatekeep_axum::test_support::DenialAssertError),
    #[error("request was unexpectedly permitted")]
    UnexpectedPermit,
    #[error("request was expected to deny")]
    ExpectedDenial,
    #[error("request was expected to fail at the authorization boundary")]
    ExpectedBoundaryError,
    #[error("authorization failed")]
    Authorization,
}

impl From<GatekeepRejection<Infallible, RecordingError>> for TestError {
    fn from(_rejection: GatekeepRejection<Infallible, RecordingError>) -> Self {
        Self::Authorization
    }
}
