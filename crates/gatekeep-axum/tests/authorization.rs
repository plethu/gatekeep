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
use gatekeep::{KnownFacts, Policy, PolicyId, condition, policy};
use gatekeep_axum::{
    AuditSubjects, DenialError, DenialResponseConfig, GatekeepRejection, Gatekeeper,
    test_support::{DenialAssertError, ExpectedDenial, assert_denial_response},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use support::{
    Access, CaseReader, FailingAudit, RecordingAudit, RecordingObserver, ShapeAwareCatalog,
    StaticCatalog, StaticResolver, TestError, context, hidden_read_policy, read_policy,
};
use tokio::sync::oneshot;
use tower::ServiceExt;

#[tokio::test]
async fn permit_records_audit_and_observer_payloads() -> Result<(), TestError> {
    let audit = RecordingAudit::default();
    let observer = RecordingObserver::default();
    let gatekeeper = Gatekeeper::new(StaticResolver {
        facts: KnownFacts::new().with_present::<CaseReader>(),
    })
    .with_audit_sink(audit.clone())
    .with_observer(observer.clone())
    .with_audit_subjects(AuditSubjects::Record);
    let policy = read_policy()?;
    let context = context()?;

    let authorized = gatekeeper
        .authorize(PolicyId::new("case_read")?, &policy, context.clone())
        .await?;

    assert_eq!(authorized.outcome, Access::Full);
    let entries = audit.entries()?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tenant, Some(context.tenant));
    assert_eq!(entries[0].principal, Some(context.principal));
    let summaries = observer.summaries()?;
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].consulted.len(), 1);
    Ok(())
}

#[tokio::test]
async fn forbidden_denial_renders_specific_localized_reason() -> Result<(), TestError> {
    let gatekeeper = Gatekeeper::new(StaticResolver {
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
    let gatekeeper = Gatekeeper::new(StaticResolver {
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
    let gatekeeper = Gatekeeper::new(StaticResolver {
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
    let gatekeeper = Gatekeeper::new(StaticResolver {
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
    let gatekeeper = Gatekeeper::new(StaticResolver {
        facts: KnownFacts::new().with_present::<CaseReader>(),
    })
    .with_audit_sink(FailingAudit)
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
    let gatekeeper = Gatekeeper::new(StaticResolver {
        facts: KnownFacts::new().with_present::<CaseReader>(),
    })
    .with_audit_sink(audit);
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

struct BlockingAudit {
    release: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
    completed: Arc<AtomicBool>,
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
