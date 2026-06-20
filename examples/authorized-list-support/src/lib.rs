//! Shared support for the runnable authorized-list examples.

use std::convert::Infallible;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use gatekeep::{
    Context, Effect, Fact, FactId, FactResolver, GatekeepError, Lattice, Locale, LowerError,
    Policy, PolicyId, QueryLowering, Residual, ResolveError, StaticFactId, SubjectRef, TenantId,
    condition, partial_evaluate, policy, required_facts,
};
use gatekeep_axum::{GatekeepRejection, Gatekeeper};
use gatekeep_fluent::{FluentCatalog, FluentCatalogError};
use gatekeep_sqlx::{PgFactPredicates, PgFragment, PgLowerer, SqlOutcome};
use serde::{Deserialize, Serialize};
use sqlx::{Execute, Postgres, QueryBuilder};

/// Golden SQL emitted by the example authorized-list route.
pub const EXPECTED_LIST_SQL: &str = "SELECT cases.id, cases.title, GREATEST(CASE WHEN (cases.shared) IS TRUE THEN $1 ELSE NULL END, CASE WHEN (cases.owner_id = $2) IS TRUE THEN $3 ELSE NULL END) AS access_grade FROM cases WHERE cases.tenant_id = $4 AND (((cases.shared) IS TRUE) OR ((cases.owner_id = $5) IS TRUE))";

/// Number of ordered binds emitted by [`EXPECTED_LIST_SQL`].
pub const EXPECTED_LIST_BINDS: usize = 5;

/// Builds the example router around an application-provided fact resolver.
///
/// # Errors
///
/// Returns [`BuildError`] if the example policy, context, or Fluent catalog
/// cannot be constructed.
pub fn router<R>(resolver: R) -> Result<Router, BuildError>
where
    R: FactResolver + Clone + Send + Sync + 'static,
{
    let state = AppState::new(resolver)?;
    Ok(Router::new()
        .route("/cases", get(list_cases::<R>))
        .route("/staff/cases/{case_id}", get(get_staff_case::<R>))
        .with_state(state))
}

/// Returns the request context shared by the examples.
///
/// # Errors
///
/// Returns [`GatekeepError`] if one of the owned identifiers is invalid.
pub fn request_context() -> Result<Context, GatekeepError> {
    Ok(Context {
        tenant: TenantId::new("tenant_1")?,
        principal: SubjectRef::new("user", "user_123")?,
        subjects: std::collections::BTreeMap::new(),
        locale: Locale::new("en-US")?,
        request_id: None,
    })
}

#[derive(Clone)]
struct AppState<R> {
    gatekeeper: Gatekeeper<R, gatekeep::NoopAuditSink, FluentCatalog>,
    resolver: R,
    staff_detail_policy: Policy<ReadAccess>,
    list_policy: Policy<ReadAccess>,
    lowerer: PgLowerer<CasePredicates>,
    context: Context,
}

impl<R> AppState<R>
where
    R: FactResolver + Clone + Send + Sync + 'static,
{
    fn new(resolver: R) -> Result<Self, BuildError> {
        let catalog = FluentCatalog::new()
            .with_resource("en-US", "case-read-denied = You cannot read this case.")?;
        let gatekeeper = Gatekeeper::new(resolver.clone()).with_reason_catalog(catalog);
        Ok(Self {
            gatekeeper,
            resolver,
            staff_detail_policy: staff_detail_policy()?,
            list_policy: list_policy()?,
            lowerer: PgLowerer::new(CasePredicates),
            context: request_context()?,
        })
    }
}

async fn get_staff_case<R>(
    State(state): State<AppState<R>>,
    Path(case_id): Path<String>,
) -> Result<Json<CaseDetail>, AppError<R::Error>>
where
    R: FactResolver + Clone + Send + Sync + 'static,
{
    let authorized = state
        .gatekeeper
        .authorize(
            PolicyId::new("staff_case_detail")?,
            &state.staff_detail_policy,
            state.context.clone(),
        )
        .await?;
    Ok(Json(CaseDetail {
        id: case_id,
        title: "case file".to_owned(),
        access: authorized.outcome,
    }))
}

async fn list_cases<R>(
    State(state): State<AppState<R>>,
) -> Result<Json<AuthorizedList>, AppError<R::Error>>
where
    R: FactResolver + Clone + Send + Sync + 'static,
{
    Ok(Json(lower_authorized_list(&state).await?))
}

async fn lower_authorized_list<R>(state: &AppState<R>) -> Result<AuthorizedList, AppError<R::Error>>
where
    R: FactResolver + Clone + Send + Sync + 'static,
{
    let required = required_facts(&state.list_policy)
        .into_iter()
        .collect::<Vec<_>>();
    let facts = state
        .resolver
        .resolve_for_query(&required, &state.context)
        .await?;
    let residual = partial_evaluate(&state.list_policy, &facts);
    let lowered = match residual {
        Residual::Pending { residual, .. } => state.lowerer.lower(&residual, &state.context)?,
        Residual::Resolved(decision) => lowered_resolved(&decision.effect),
    };

    let bind_count = lowered.grade.binds().count() + 1 + lowered.filter.binds().count();
    let mut builder = QueryBuilder::<Postgres>::new("SELECT cases.id, cases.title, ");
    lowered.grade.push_to(&mut builder);
    builder.push(" AS access_grade FROM cases WHERE cases.tenant_id = ");
    builder.push_bind(state.context.tenant.as_str().to_owned());
    builder.push(" AND (");
    lowered.filter.push_to(&mut builder);
    builder.push(")");
    let query = builder.build();

    Ok(AuthorizedList {
        sql: query.sql().as_str().to_owned(),
        bind_count,
    })
}

fn lowered_resolved(effect: &Effect<ReadAccess>) -> gatekeep::Lowered<PgFragment, PgFragment> {
    match effect {
        Effect::Permit(outcome) => gatekeep::Lowered {
            filter: PgFragment::trusted("TRUE"),
            grade: PgFragment::bind(outcome.to_sql_ordinal()),
        },
        Effect::Deny => gatekeep::Lowered {
            filter: PgFragment::trusted("FALSE"),
            grade: PgFragment::trusted("NULL"),
        },
    }
}

fn staff_detail_policy() -> Result<Policy<ReadAccess>, GatekeepError> {
    policy::grant(ReadAccess::Full, condition::has::<Staff>())
        .try_labeled("staff_case_detail")?
        .try_reason("case-read-denied")
}

fn list_policy() -> Result<Policy<ReadAccess>, GatekeepError> {
    Ok(policy::any([
        policy::grant(ReadAccess::Redacted, condition::has::<SharedCase>())
            .try_labeled("shared_case")?,
        policy::grant(
            ReadAccess::Full,
            condition::all([condition::has::<Staff>(), condition::has::<CaseOwner>()]),
        )
        .try_labeled("owned_case")?,
    ]))
}

/// Outcome grade used by the examples.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadAccess {
    /// Only redacted case fields may be returned.
    Redacted,
    /// Full case fields may be returned.
    Full,
}

impl Lattice for ReadAccess {
    fn meet(&self, other: &Self) -> Self {
        (*self).min(*other)
    }

    fn join(&self, other: &Self) -> Self {
        (*self).max(*other)
    }

    fn top() -> Self {
        Self::Full
    }

    fn bottom() -> Self {
        Self::Redacted
    }
}

impl SqlOutcome for ReadAccess {
    fn to_sql_ordinal(&self) -> i64 {
        match self {
            Self::Redacted => 1,
            Self::Full => 2,
        }
    }
}

/// Principal request fact resolved before point authorization or query lowering.
pub struct Staff;

impl Fact for Staff {
    const ID: StaticFactId = StaticFactId::new("staff");
}

/// Resource fact deferred to SQL lowering.
pub struct SharedCase;

impl Fact for SharedCase {
    const ID: StaticFactId = StaticFactId::new("shared_case");
}

/// Resource fact deferred to SQL lowering.
pub struct CaseOwner;

impl Fact for CaseOwner {
    const ID: StaticFactId = StaticFactId::new("case_owner");
}

#[derive(Clone, Debug)]
struct CasePredicates;

impl PgFactPredicates for CasePredicates {
    fn predicate(&self, fact: &FactId, cx: &Context) -> Option<PgFragment> {
        match fact.as_str() {
            "shared_case" => Some(PgFragment::trusted("cases.shared")),
            "case_owner" => {
                let mut fragment = PgFragment::trusted("cases.owner_id = ");
                fragment.push_fragment(PgFragment::bind(cx.principal.id()));
                Some(fragment)
            }
            _ => None,
        }
    }
}

/// Detail response emitted by the point-authorization route.
#[derive(Debug, Serialize, Deserialize)]
pub struct CaseDetail {
    /// Case id from the route.
    pub id: String,
    /// Case title from application storage.
    pub title: String,
    /// Authorized access grade.
    pub access: ReadAccess,
}

/// Authorized-list response emitted by the query route.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizedList {
    /// SQL text built by `sqlx::QueryBuilder`.
    pub sql: String,
    /// Count of bind values appended to the query builder.
    pub bind_count: usize,
}

#[derive(Debug, thiserror::Error)]
enum AppError<E> {
    #[error("authorization rejected")]
    Authorization(GatekeepRejection<E, Infallible>),
    #[error(transparent)]
    Gatekeep(#[from] GatekeepError),
    #[error(transparent)]
    Resolve(#[from] ResolveError<E>),
    #[error(transparent)]
    Lower(#[from] LowerError),
}

impl<E> From<GatekeepRejection<E, Infallible>> for AppError<E> {
    fn from(error: GatekeepRejection<E, Infallible>) -> Self {
        Self::Authorization(error)
    }
}

impl<E> IntoResponse for AppError<E> {
    fn into_response(self) -> Response {
        match self {
            Self::Authorization(rejection) => rejection.into_response(),
            Self::Gatekeep(_) | Self::Resolve(_) | Self::Lower(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "authorization_error",
                    "message": "authorization failed"
                })),
            )
                .into_response(),
        }
    }
}

/// Error returned while constructing the example router.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// Gatekeep rejected a static identifier.
    #[error(transparent)]
    Gatekeep(#[from] GatekeepError),
    /// The Fluent catalog could not be built.
    #[error(transparent)]
    Fluent(#[from] FluentCatalogError),
}
