//! Executable disclosure, tenant, fallback, batch and durable-denial contracts.
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use gatekeep::{
    ApplicationVerifiedTenantBinding, BindingAuthority, BindingProvenance, Context, EvidenceDigest,
    Locale, SubjectRef, TenantBinding, TenantBindingEvidence, TenantId,
};
use gatekeep::{Authorizer, PolicyId, PreparedPolicy};
use gatekeep_example_record_service::{
    Access, ExampleError, RecordResolver, context, database, read_policy, router,
};
use gatekeep_sqlx::SqliteDovecoteAudit;
use std::{
    io::{Error as IoError, ErrorKind},
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
};
use time::OffsetDateTime;
use tower::ServiceExt;

#[tokio::test]
async fn returned_fields_follow_tiers_and_denials_are_durable() -> Result<(), ExampleError> {
    let pool = database().await?;
    let app = router(pool.clone()).await?;
    for (person, tier, shared, private) in [
        ("owner", "full", true, true),
        ("participant", "shared", true, false),
        ("parent", "released", false, false),
        ("emergency", "full", true, true),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/people/{person}/records/one"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await?)?;
        assert_eq!(value["access"], tier);
        assert_eq!(value.get("shared_notes").is_some(), shared);
        assert_eq!(value.get("private_notes").is_some(), private);
    }

    for person in ["admin", "expired", "disabled", "stranger"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/people/{person}/records/one"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(to_bytes(response.into_body(), 8192).await?.is_empty());
    }

    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM dovecote_events")
        .fetch_one(&pool)
        .await?;
    assert_eq!(events, 8);
    Ok(())
}

#[tokio::test]
async fn bulk_resolution_matches_single_checks_with_one_sql_call() -> Result<(), ExampleError> {
    let pool = database().await?;
    let resolver = RecordResolver::new(pool.clone());
    let authorizer = Authorizer::new(
        resolver.clone(),
        SqliteDovecoteAudit::new(pool.clone(), "https://demo.example/audit")?,
    );
    let policy = PreparedPolicy::new(PolicyId::new("record.read")?, read_policy()?)?;
    let contexts = [
        context("demo", "owner", "one")?,
        context("demo", "participant", "one")?,
        context("other", "owner", "one")?,
    ];
    let batch = authorizer
        .authorize_batch(
            &policy,
            &contexts,
            NonZeroUsize::new(16).ok_or("invalid limit")?,
        )
        .await?;
    assert_eq!(resolver.query_count(), 1);
    let expected = [Some(&Access::Full), Some(&Access::Shared), None];
    for ((result, context), expected) in batch.results.into_iter().zip(&contexts).zip(expected) {
        let decision = result?;
        assert_eq!(decision.decision.outcome(), expected);
        let single = authorizer.authorize(&policy, context).await?;
        assert_eq!(decision.decision, single.decision);
    }
    assert_eq!(resolver.query_count(), 4);
    Ok(())
}

#[tokio::test]
async fn rollback_removes_mutation_and_event_together() -> Result<(), ExampleError> {
    let pool = database().await?;
    let audit = SqliteDovecoteAudit::new(pool.clone(), "https://demo.example/audit")?;
    let authorizer = Authorizer::new(RecordResolver::new(pool.clone()), audit.clone());
    let policy = PreparedPolicy::new(PolicyId::new("record.read")?, read_policy()?)?;
    let context = context("demo", "owner", "one")?;
    let store = dovecote_sqlx_sqlite::SqliteDovecote::new(pool.clone());
    let mut transaction = store.begin_write().await?;
    let resolution = gatekeep_example_record_service::resolve_in_transaction(
        &mut transaction,
        &context,
        &gatekeep::SystemClock,
    )
    .await?;
    let pending = authorizer.prepare_resolution(&policy, &context, &resolution)?;
    sqlx::query("UPDATE records SET summary = 'changed' WHERE tenant = 'demo'")
        .execute(&mut *transaction)
        .await?;
    audit
        .record_decision_audit_in_transaction(&mut transaction, pending.entry())
        .await?;
    transaction.rollback().await?;
    let summary: String = sqlx::query_scalar("SELECT summary FROM records WHERE tenant = 'demo'")
        .fetch_one(&pool)
        .await?;
    assert_eq!(summary, "Synthetic released summary");
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM dovecote_events")
        .fetch_one(&pool)
        .await?;
    assert_eq!(events, 0);
    Ok(())
}

#[tokio::test]
async fn source_failure_is_a_separate_durable_attempt() -> Result<(), ExampleError> {
    let pool = database().await?;
    let audit = SqliteDovecoteAudit::new(pool.clone(), "https://demo.example/audit")?;
    let authorizer = Authorizer::new(RecordResolver::new(pool.clone()), audit.clone());
    let policy = PreparedPolicy::new(PolicyId::new("record.read")?, read_policy()?)?;
    sqlx::query("DROP TABLE record_access")
        .execute(&pool)
        .await?;
    let failure = authorizer
        .authorize_recording_attempts(&policy, &context("demo", "owner", "one")?, &audit)
        .await;
    assert!(matches!(
        failure,
        Err(gatekeep::AttemptAuthorizationError::Authorization(_))
    ));
    let (event_type, payload): (String, Vec<u8>) =
        sqlx::query_as("SELECT event_type, data FROM dovecote_events")
            .fetch_one(&pool)
            .await?;
    assert_eq!(event_type, gatekeep_sqlx::ATTEMPT_AUDIT_EVENT_TYPE);
    let attempt: gatekeep::AuthorizationAttempt = serde_json::from_slice(&payload)?;
    assert_eq!(attempt.failure(), gatekeep::AttemptFailure::Resolution);
    let page = dovecote_sqlx_sqlite::SqliteDovecote::new(pool.clone())
        .for_tenant(dovecote::TenantId::new("demo")?)
        .page(None, dovecote::Limit::new(10)?)
        .await?;
    assert_eq!(
        gatekeep_sqlx::decode_authorization_attempt(audit.config(), &page[0])?,
        attempt
    );
    assert!(gatekeep_sqlx::decode_decision_audit(audit.config(), &page[0]).is_err());
    assert_eq!(attempt.subjects().len(), 1);
    assert!(!String::from_utf8(payload)?.contains("no such table"));
    let repeated = audit.record_authorization_attempt(&attempt).await?;
    assert!(matches!(
        repeated,
        dovecote::EnqueueOutcome::AlreadyEnqueued { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn sql_list_returns_real_rows_with_filtered_counts_and_disclosure_history()
-> Result<(), ExampleError> {
    let pool = database().await?;
    let app = router(pool.clone()).await?;
    for (person, total, tier) in [
        ("participant", 1, Some("shared")),
        ("parent", 1, Some("released")),
        ("admin", 0, None),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/people/{person}/records"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await?)?;
        assert_eq!(body["total"], total);
        assert_eq!(
            body["records"].as_array().ok_or("missing records")?.len(),
            usize::try_from(total)?
        );
        if let Some(tier) = tier {
            assert_eq!(body["records"][0]["access"], tier);
            assert!(body["records"][0].get("private_notes").is_none());
        }
    }

    let payloads: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT data FROM dovecote_events WHERE event_type = 'record_demo.list_assembled'",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(payloads.len(), 3);
    for payload in payloads {
        let text = String::from_utf8(payload)?;
        assert!(!text.contains("Synthetic"));
        assert!(!text.contains("Other private"));
    }

    Ok(())
}

struct FailedAttemptSink(AtomicUsize);
#[async_trait::async_trait]
impl gatekeep::AttemptAuditSink for FailedAttemptSink {
    type Error = IoError;
    async fn record_attempt(&self, _: &gatekeep::AuthorizationAttempt) -> Result<(), Self::Error> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(IoError::other("synthetic persistence failure"))
    }
}

#[tokio::test]
async fn attempt_failures_retain_both_errors_and_never_invent_trusted_scope()
-> Result<(), ExampleError> {
    let pool = database().await?;
    sqlx::query("DROP TABLE record_access")
        .execute(&pool)
        .await?;
    let resolver = RecordResolver::new(pool);
    let authorizer = Authorizer::unaudited(resolver.clone());
    let attempts = FailedAttemptSink(AtomicUsize::new(0));
    let policy = PreparedPolicy::new(PolicyId::new("record.read")?, read_policy()?)?;
    let failure = authorizer
        .authorize_recording_attempts(&policy, &context("demo", "owner", "one")?, &attempts)
        .await;
    let Err(gatekeep::AttemptAuthorizationError::Persistence {
        authorization,
        entry,
        source,
    }) = failure
    else {
        return Err("expected both source and audit failures".into());
    };
    assert!(matches!(
        authorization,
        gatekeep::AuthorizationError::Resolve(_)
    ));
    assert_eq!(entry.failure(), gatekeep::AttemptFailure::Resolution);
    assert_eq!(source.kind(), ErrorKind::Other);
    assert_eq!(attempts.0.load(Ordering::Relaxed), 1);
    let now = OffsetDateTime::UNIX_EPOCH;
    let binding = ApplicationVerifiedTenantBinding::new(
        TenantId::new("demo")?,
        TenantBindingEvidence::new(
            BindingAuthority::Provider {
                provider: BindingProvenance::new("test")?,
                key_id: None,
            },
            now,
            EvidenceDigest::new([0; 32]),
        ),
        now,
        now + time::Duration::seconds(1),
    )?;
    let stale = Context::new_at(
        TenantId::new("demo")?,
        TenantBinding::ApplicationVerified(binding),
        SubjectRef::new("person", "owner")?,
        Locale::new("en")?,
        now,
    )?;
    let calls = resolver.query_count();
    let authorizer = authorizer.with_clock(move || now + time::Duration::seconds(2));
    assert!(matches!(
        authorizer
            .authorize_recording_attempts(&policy, &stale, &attempts)
            .await,
        Err(gatekeep::AttemptAuthorizationError::Unscoped { .. })
    ));
    assert_eq!(resolver.query_count(), calls);
    assert_eq!(attempts.0.load(Ordering::Relaxed), 1);
    Ok(())
}
