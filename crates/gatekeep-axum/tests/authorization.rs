//! Axum authorization adapter tests.

mod support;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode},
    routing::get,
};
use gatekeep::{KnownFacts, Policy, PolicyId, condition, policy};
use gatekeep_axum::{
    AuditSubjects, DenialBody, DenialError, DenialResponseConfig, GatekeepRejection, Gatekeeper,
};
use support::{
    Access, CaseReader, FailingAudit, RecordingAudit, RecordingObserver, ShapeAwareCatalog,
    StaticCatalog, StaticResolver, TestError, context, hidden_read_policy, read_policy,
};
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

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let body: DenialBody = serde_json::from_slice(&bytes)?;
    assert_eq!(body.error, DenialError::NotFound);
    assert_eq!(body.message, "not found");
    assert_eq!(body.reason, None);
    assert!(!String::from_utf8_lossy(&bytes).contains("case-read-denied"));
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
