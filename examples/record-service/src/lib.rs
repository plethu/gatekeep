//! Synthetic case records: typed disclosure, hidden denial, emergency fallback,
//! database-backed observations and required Dovecote persistence.
//! The URL selects a fixture identity; this is not production authentication.
mod list;
mod policy;
mod resolver;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use gatekeep::{
    Authorizer, Context, Locale, PolicyId, PreparedPolicy, SubjectRef, SubjectSlot, TenantId,
    TrustedServiceBinding,
};
use gatekeep_sqlx::SqliteDovecoteAudit;
pub use policy::{Access, read_policy};
pub use resolver::{RecordResolver, resolve_in_transaction};
use serde::Serialize;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use std::{error::Error, sync::Arc};

struct Owner;
struct Shared;
struct Released;
struct Emergency;
struct Enabled;

#[derive(Serialize)]
struct ListView {
    total: i64,
    records: Vec<View>,
}

/// Example setup failure.
pub type ExampleError = Box<dyn Error + Send + Sync>;

/// Creates the isolated in-memory example database and all synthetic fixtures.
///
/// # Errors
/// Returns database or Dovecote migration failures.
pub async fn database() -> Result<SqlitePool, ExampleError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    for migration in dovecote_sqlx_sqlite::MIGRATIONS {
        sqlx::raw_sql(migration.sql()).execute(&pool).await?;
    }
    sqlx::raw_sql(include_str!("fixtures.sql"))
        .execute(&pool)
        .await?;
    Ok(pool)
}

/// Establishes an explicitly trusted local fixture identity and resource.
///
/// # Errors
/// Returns invalid identity or binding errors.
pub fn context(tenant: &str, person: &str, record: &str) -> Result<Context, ExampleError> {
    Ok(Context::from_trusted_service(
        TrustedServiceBinding::new(TenantId::new(tenant)?, "synthetic-local-fixture")?,
        SubjectRef::new("person", person)?,
        Locale::new("en")?,
    )?
    .with_subject(
        SubjectSlot::new("record")?,
        SubjectRef::new("record", record)?,
    ))
}

/// Builds the application router around real database rows and a required sink.
///
/// # Errors
/// Returns policy preparation, configuration or schema errors.
pub async fn router(pool: SqlitePool) -> Result<Router, ExampleError> {
    let sink = SqliteDovecoteAudit::new(pool.clone(), "https://record-demo.example/audit")?;
    sink.check_schema().await?;
    let state = Arc::new(App {
        authorizer: Authorizer::new(RecordResolver::new(pool.clone()), sink.clone()),
        audit: sink,
        policy: PreparedPolicy::new(PolicyId::new("record.read")?, read_policy()?)?,
        pool,
    });
    Ok(Router::new()
        .route("/people/{person}/records", get(App::list))
        .route("/people/{person}/records/{record}", get(read))
        .with_state(state))
}

struct App {
    authorizer: Authorizer<RecordResolver, SqliteDovecoteAudit>,
    policy: PreparedPolicy<Access>,
    pool: SqlitePool,
    audit: SqliteDovecoteAudit,
}

#[derive(Serialize)]
struct View {
    id: String,
    access: Access,
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_notes: Option<String>,
}

async fn read(
    State(app): State<Arc<App>>,
    Path((person, record)): Path<(String, String)>,
) -> Result<Json<View>, StatusCode> {
    let context = context("demo", &person, &record).map_err(|_| StatusCode::BAD_REQUEST)?;
    let store = dovecote_sqlx_sqlite::SqliteDovecote::new(app.pool.clone());
    let mut transaction = store
        .begin_write()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let resolution = resolve_in_transaction(&mut transaction, &context, &gatekeep::SystemClock)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let pending = app
        .authorizer
        .prepare_resolution(&app.policy, &context, &resolution)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    app.audit
        .record_decision_audit_in_transaction(&mut transaction, pending.entry())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let Some(access) = pending.decision().outcome().copied() else {
        transaction
            .commit()
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Err(StatusCode::NOT_FOUND);
    };
    // BEGIN IMMEDIATE fences permission changes and projection through commit.
    let row: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT summary, CASE WHEN ? THEN shared_notes END, CASE WHEN ? THEN private_notes END FROM records WHERE tenant = ? AND id = ?")
        .bind(access >= Access::Shared).bind(access == Access::Full)
        .bind(context.tenant().as_str()).bind(&record).fetch_one(&mut *transaction).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    transaction
        .commit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(View {
        id: record,
        access,
        summary: row.0,
        shared_notes: row.1,
        private_notes: row.2,
    }))
}
