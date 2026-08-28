//! Axum authorization adapter tests.

mod support;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::Response,
    routing::get,
};
use gatekeep::{
    ApplicationVerifiedTenantBinding, BindingAuthority, BindingProvenance, Clock, Context,
    DecisionAuditId, DecisionAuditOccurrence, EvidenceDigest, FactId, FactResolution, FactResolver,
    KnownFacts, Locale, PartialFacts, Policy, PolicyId, ResolveError, SubjectRef, TenantBinding,
    TenantBindingEvidence, TenantId, condition, policy,
};
use gatekeep_axum::{
    DenialError, DenialResponseConfig, GatekeepAxumError, GatekeepRejection, Gatekeeper,
    test_support::{DenialAssertError, ExpectedDenial, assert_denial_response},
};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use support::{
    Access, CaseReader, FailOnceAudit, FailingAudit, RecordingAudit, RecordingObserver,
    ShapeAwareCatalog, StaticCatalog, StaticResolver, TestError, context, hidden_read_policy,
    read_policy,
};
use time::OffsetDateTime;
use tokio::sync::oneshot;
use tower::ServiceExt;

#[tokio::test]
async fn permit_records_audit_and_observer_payloads() -> Result<(), TestError> {
    let audit = RecordingAudit::default();
    let observer = RecordingObserver::default();
    let gatekeeper = Gatekeeper::new(
        StaticResolver {
            facts: KnownFacts::new().with_present::<CaseReader>(),
        },
        audit.clone(),
    )
    .with_observer(observer.clone());
    let policy = read_policy()?;
    let context = context()?;

    let authorized = gatekeeper
        .authorize(PolicyId::new("case_read")?, &policy, context.clone())
        .await?;

    assert_eq!(authorized.outcome, Access::Full);
    let entries = audit.entries()?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tenant, *context.tenant());
    assert_eq!(entries[0].principal, *context.principal());
    assert_eq!(entries[0].binding.as_ref(), Some(context.binding()));
    assert_eq!(
        entries[0]
            .fact_resolution
            .as_ref()
            .and_then(|value| value.source().map(gatekeep::BindingProvenance::as_str)),
        Some("test.static-resolver")
    );
    let resolution = entries[0]
        .fact_resolution
        .as_ref()
        .ok_or(TestError::MissingAuditOccurrence)?;
    let authenticated_at = match context.binding() {
        TenantBinding::ApplicationVerified(binding) => binding.evidence().authenticated_at(),
        TenantBinding::TrustedService(_) => unreachable!("test uses application binding"),
    };
    assert!(resolution.observed_at() >= authenticated_at);
    assert_ne!(resolution.fact_set_digest().as_bytes(), &[0; 32]);
    assert_eq!(
        resolution
            .revision()
            .map(gatekeep::BindingProvenance::as_str),
        Some("test.static-revision")
    );
    let summaries = observer.summaries()?;
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].consulted.len(), 1);
    Ok(())
}

#[tokio::test]
async fn audit_identity_and_occurrence_time_are_captured_once() -> Result<(), TestError> {
    let audit = RecordingAudit::default();
    let decision_audit_id = DecisionAuditId::new("decision-retry-1")?;
    let occurred_at = OffsetDateTime::UNIX_EPOCH + time::Duration::microseconds(42);
    let occurrence = DecisionAuditOccurrence::new(decision_audit_id.clone(), occurred_at)?;
    let gatekeeper = Gatekeeper::new(
        StaticResolver {
            facts: KnownFacts::new().with_present::<CaseReader>(),
        },
        audit.clone(),
    );
    let context = context()?.with_decision_audit_occurrence(occurrence);

    let authorized = gatekeeper
        .authorize(PolicyId::new("case_read")?, &read_policy()?, context)
        .await?;

    let entries = audit.entries()?;
    assert_eq!(entries[0].decision_audit_id, decision_audit_id);
    assert_eq!(entries[0].occurred_at, occurred_at);
    assert_eq!(authorized.audit_occurrence.occurred_at, occurred_at);
    Ok(())
}

#[tokio::test]
async fn ordinary_clock_is_normalized_to_microseconds() -> Result<(), TestError> {
    let before = OffsetDateTime::now_utc();
    let authorized = Gatekeeper::unaudited(StaticResolver {
        facts: KnownFacts::new().with_present::<CaseReader>(),
    })
    .authorize(PolicyId::new("case_read")?, &read_policy()?, context()?)
    .await?;
    let after = OffsetDateTime::now_utc();
    let before_microsecond = before.replace_nanosecond(before.nanosecond() / 1_000 * 1_000)?;

    assert!(authorized.audit_occurrence.occurred_at >= before_microsecond);
    assert!(authorized.audit_occurrence.occurred_at <= after);
    assert_eq!(
        authorized.audit_occurrence.occurred_at.nanosecond() % 1_000,
        0
    );
    Ok(())
}

#[tokio::test]
async fn ambiguous_audit_failure_replays_identity_but_refreshes_observation_time()
-> Result<(), TestError> {
    let audit = FailOnceAudit::default();
    let gatekeeper = Gatekeeper::new(
        StaticResolver {
            facts: KnownFacts::new().with_present::<CaseReader>(),
        },
        audit.clone(),
    );
    let policy_id = PolicyId::new("case_read")?;
    let policy = read_policy()?;
    let context = context()?;

    let first_rejection = match gatekeeper
        .authorize(policy_id.clone(), &policy, context.clone())
        .await
    {
        Ok(_authorized) => return Err(TestError::ExpectedBoundaryError),
        Err(rejection) => rejection,
    };
    let occurrence = match first_rejection {
        GatekeepRejection::Error(error) => error
            .audit_occurrence()
            .cloned()
            .ok_or(TestError::MissingAuditOccurrence)?,
        GatekeepRejection::Denied(_) => return Err(TestError::ExpectedBoundaryError),
    };

    let authorized = gatekeeper
        .authorize(
            policy_id,
            &policy,
            context.with_decision_audit_occurrence(occurrence.clone()),
        )
        .await
        .map_err(|_rejection| TestError::Authorization)?;
    let entries = audit.entries()?;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].decision_audit_id, entries[1].decision_audit_id);
    assert_eq!(entries[0].occurred_at, entries[1].occurred_at);
    assert_eq!(
        entries[0]
            .fact_resolution
            .as_ref()
            .map(gatekeep::FactResolutionEvidence::fact_set_digest),
        entries[1]
            .fact_resolution
            .as_ref()
            .map(gatekeep::FactResolutionEvidence::fact_set_digest)
    );
    assert!(
        entries[1]
            .fact_resolution
            .as_ref()
            .ok_or(TestError::MissingAuditOccurrence)?
            .observed_at()
            >= entries[0]
                .fact_resolution
                .as_ref()
                .ok_or(TestError::MissingAuditOccurrence)?
                .observed_at()
    );
    assert_eq!(authorized.audit_occurrence, occurrence);
    Ok(())
}

#[tokio::test]
async fn forbidden_denial_renders_specific_localized_reason() -> Result<(), TestError> {
    let gatekeeper = Gatekeeper::unaudited(StaticResolver {
        facts: KnownFacts::new().with_absent::<CaseReader>(),
    })
    .with_reason_catalog(
        StaticCatalog::default().with_message("case-read-denied", "case access denied"),
    );

    let rejection = match gatekeeper
        .authorize(PolicyId::new("case_read")?, &read_policy()?, context()?)
        .await
    {
        Ok(_authorized) => return Err(TestError::UnexpectedPermit),
        Err(rejection) => rejection,
    };

    let GatekeepRejection::Denied(response) = rejection else {
        return Err(TestError::ExpectedDenial);
    };
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(response.body.error, DenialError::Forbidden);
    assert_eq!(response.body.message, "case access denied");
    assert_eq!(response.body.reason, Some("case-read-denied".to_owned()));
    Ok(())
}

#[tokio::test]
async fn hidden_denial_uses_generic_not_found_response() -> Result<(), TestError> {
    let gatekeeper = Gatekeeper::unaudited(StaticResolver {
        facts: KnownFacts::new().with_absent::<CaseReader>(),
    });
    let state = AppState {
        gatekeeper,
        policy_id: PolicyId::new("case_read")?,
        policy: hidden_read_policy()?,
        context: context()?,
    };

    let app = Router::new()
        .route("/cases/123", get(hidden_handler))
        .with_state(state);
    let request = Request::builder().uri("/cases/123").body(Body::empty())?;

    let response = match app.oneshot(request).await {
        Ok(response) => response,
        Err(error) => match error {},
    };

    let body = assert_denial_response(
        response,
        ExpectedDenial::not_found()
            .with_message("not found")
            .without_reason(),
    )
    .await?;
    assert!(!format!("{body:?}").contains("case-read-denied"));
    Ok(())
}

#[tokio::test]
async fn denial_helper_rejects_extra_serialized_fields() -> Result<(), TestError> {
    let response = Response::builder().status(StatusCode::NOT_FOUND).body(Body::from(
        r#"{"error":"not_found","message":"not found","reason":null,"debug_reason":"case-read-denied"}"#,
    ))?;

    let error =
        assert_denial_response(response, ExpectedDenial::not_found().without_reason()).await;

    assert!(matches!(error, Err(DenialAssertError::Fields { .. })));
    Ok(())
}

#[tokio::test]
async fn unlabeled_hidden_denial_still_uses_not_found_response() -> Result<(), TestError> {
    let gatekeeper = Gatekeeper::unaudited(StaticResolver {
        facts: KnownFacts::new().with_absent::<CaseReader>(),
    });

    let rejection = match gatekeeper
        .authorize(
            PolicyId::new("case_read")?,
            &policy::grant(Access::Full, condition::has::<CaseReader>()).hidden(),
            context()?,
        )
        .await
    {
        Ok(_authorized) => return Err(TestError::UnexpectedPermit),
        Err(rejection) => rejection,
    };

    let GatekeepRejection::Denied(response) = rejection else {
        return Err(TestError::ExpectedDenial);
    };
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.body.error, DenialError::NotFound);
    assert_eq!(response.body.message, "not found");
    assert_eq!(response.body.reason, None);
    Ok(())
}

#[tokio::test]
async fn hidden_denial_can_render_configured_generic_catalog_reason() -> Result<(), TestError> {
    let gatekeeper = Gatekeeper::unaudited(StaticResolver {
        facts: KnownFacts::new().with_absent::<CaseReader>(),
    })
    .with_reason_catalog(ShapeAwareCatalog)
    .with_denial_response(DenialResponseConfig::new().try_with_hidden_reason("not-found")?);

    let rejection = match gatekeeper
        .authorize(
            PolicyId::new("case_read")?,
            &hidden_read_policy()?,
            context()?,
        )
        .await
    {
        Ok(_authorized) => return Err(TestError::UnexpectedPermit),
        Err(rejection) => rejection,
    };

    let GatekeepRejection::Denied(response) = rejection else {
        return Err(TestError::ExpectedDenial);
    };
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.body.message, "missing");
    assert_eq!(response.body.reason, None);
    Ok(())
}

#[tokio::test]
async fn observer_runs_only_after_audit_succeeds() -> Result<(), TestError> {
    let observer = RecordingObserver::default();
    let gatekeeper = Gatekeeper::new(
        StaticResolver {
            facts: KnownFacts::new().with_present::<CaseReader>(),
        },
        FailingAudit,
    )
    .with_observer(observer.clone());

    let rejection = match gatekeeper
        .authorize(PolicyId::new("case_read")?, &read_policy()?, context()?)
        .await
    {
        Ok(_authorized) => return Err(TestError::UnexpectedPermit),
        Err(rejection) => rejection,
    };

    let GatekeepRejection::Error(_error) = rejection else {
        return Err(TestError::ExpectedBoundaryError);
    };
    assert!(observer.summaries()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn authorize_awaits_audit_before_returning_permit() -> Result<(), TestError> {
    let (release, wait_for_release) = oneshot::channel();
    let completed = Arc::new(AtomicBool::new(false));
    let audit = BlockingAudit {
        release: tokio::sync::Mutex::new(Some(wait_for_release)),
        completed: Arc::clone(&completed),
    };

    let gatekeeper = Gatekeeper::new(
        StaticResolver {
            facts: KnownFacts::new().with_present::<CaseReader>(),
        },
        audit,
    );
    let policy_id = PolicyId::new("case_read")?;
    let policy = read_policy()?;
    let context = context()?;

    let task = tokio::spawn(async move { gatekeeper.authorize(policy_id, &policy, context).await });

    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    assert!(!completed.load(Ordering::SeqCst));

    release
        .send(())
        .map_err(|()| TestError::AuditReleaseDropped)?;
    let authorized = task.await.map_err(TestError::Join)??;

    assert_eq!(authorized.outcome, Access::Full);
    assert!(completed.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn stale_binding_is_rejected_before_fact_resolution() -> Result<(), TestError> {
    let now = OffsetDateTime::UNIX_EPOCH;
    let binding = ApplicationVerifiedTenantBinding::new(
        TenantId::new("tenant_a")?,
        TenantBindingEvidence::new(
            BindingAuthority::Issuer {
                issuer: BindingProvenance::new("test")?,
                key_id: None,
            },
            now,
            EvidenceDigest::new([0; 32]),
        ),
        now,
        now + time::Duration::minutes(1),
    )?;
    let context = Context::new_at(
        TenantId::new("tenant_a")?,
        TenantBinding::ApplicationVerified(binding),
        SubjectRef::new("user", "mari")?,
        Locale::new("en-US")?,
        now,
    )?;
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let gatekeeper = Gatekeeper::unaudited(CountingResolver {
        calls: Arc::clone(&calls),
    })
    .with_clock(move || now + time::Duration::minutes(2));

    let Err(rejection) = gatekeeper
        .authorize(PolicyId::new("case_read")?, &read_policy()?, context)
        .await
    else {
        return Err(TestError::ExpectedBoundaryError);
    };

    assert!(matches!(
        rejection,
        GatekeepRejection::Error(GatekeepAxumError::Context(gatekeep::ContextError::Binding(
            gatekeep::TenantBindingError::Stale { .. }
        )))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn binding_expiry_during_resolution_is_rejected_before_evaluation_or_audit()
-> Result<(), TestError> {
    let now = OffsetDateTime::UNIX_EPOCH;
    let binding = ApplicationVerifiedTenantBinding::new(
        TenantId::new("tenant_a")?,
        TenantBindingEvidence::new(
            BindingAuthority::Issuer {
                issuer: BindingProvenance::new("test")?,
                key_id: None,
            },
            now,
            EvidenceDigest::new([0; 32]),
        ),
        now,
        now + time::Duration::minutes(1),
    )?;
    let context = Context::new_at(
        TenantId::new("tenant_a")?,
        TenantBinding::ApplicationVerified(binding),
        SubjectRef::new("user", "mari")?,
        Locale::new("en-US")?,
        now,
    )?;
    let clock_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let clock_state = Arc::clone(&clock_calls);
    let audit = RecordingAudit::default();
    let gatekeeper = Gatekeeper::new(
        StaticResolver {
            facts: KnownFacts::new().with_present::<CaseReader>(),
        },
        audit.clone(),
    )
    .with_clock(move || {
        if clock_state.fetch_add(1, Ordering::SeqCst) == 0 {
            now
        } else {
            now + time::Duration::minutes(2)
        }
    });

    let result = gatekeeper
        .authorize(PolicyId::new("case_read")?, &read_policy()?, context)
        .await;
    assert!(matches!(
        result,
        Err(GatekeepRejection::Error(GatekeepAxumError::Context(
            gatekeep::ContextError::Binding(gatekeep::TenantBindingError::Stale { .. })
        )))
    ));
    assert!(audit.entries()?.is_empty());
    Ok(())
}

struct BlockingAudit {
    release: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
    completed: Arc<AtomicBool>,
}

#[derive(Clone)]
struct CountingResolver {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl FactResolver for CountingResolver {
    type Error = Infallible;

    async fn resolve_for_decision(
        &self,
        _required: &[FactId],
        _cx: &Context,
        clock: &dyn Clock,
    ) -> Result<FactResolution<KnownFacts>, ResolveError<Self::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        FactResolution::new(KnownFacts::new(), None, clock.now_utc())
            .map_err(ResolveError::Resolution)
    }

    async fn resolve_for_query(
        &self,
        _required: &[FactId],
        _cx: &Context,
        clock: &dyn Clock,
    ) -> Result<FactResolution<PartialFacts>, ResolveError<Self::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        FactResolution::new(PartialFacts::new(), None, clock.now_utc())
            .map_err(ResolveError::Resolution)
    }
}

#[async_trait::async_trait]
impl gatekeep::AuditSink for BlockingAudit {
    type Error = support::RecordingError;

    async fn record(&self, _entry: &gatekeep::AuditEntry) -> Result<(), Self::Error> {
        let release = self.release.lock().await.take();
        if let Some(release) = release {
            let _ = release.await;
        }
        self.completed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    gatekeeper: Gatekeeper<StaticResolver>,
    policy_id: PolicyId,
    policy: Policy<Access>,
    context: gatekeep::Context,
}

async fn hidden_handler(
    State(state): State<AppState>,
) -> Result<&'static str, GatekeepRejection<std::convert::Infallible, std::convert::Infallible>> {
    state
        .gatekeeper
        .authorize(state.policy_id, &state.policy, state.context)
        .await?;
    Ok("ok")
}
