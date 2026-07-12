use gatekeep::{
    Condition, Context, Effect, Fact, FactId, GatekeepError, KnownFacts, Lattice, Locale, Presence,
    QueryLowering, StaticFactId, SubjectRef, TenantId, evaluate_residual,
};
use gatekeep_sqlx::{
    PgFactPredicates, PgFragment, PgLowerer, PgValue, PostgresBackend, SqlOutcome,
    validate_database_url_for_backend,
};
use sqlx::{PgPool, Postgres, QueryBuilder, postgres::PgPoolOptions};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum Tier {
    Released,
    Shared,
    Full,
}

impl Lattice for Tier {
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
        Self::Released
    }
}

impl SqlOutcome for Tier {
    fn to_sql_ordinal(&self) -> i64 {
        match self {
            Self::Released => 0,
            Self::Shared => 1,
            Self::Full => 2,
        }
    }
}

pub struct Shared;
impl Fact for Shared {
    const ID: StaticFactId = StaticFactId::new("shared");
}

pub struct Owner;
impl Fact for Owner {
    const ID: StaticFactId = StaticFactId::new("owner");
}

pub struct NullableFlag;
impl Fact for NullableFlag {
    const ID: StaticFactId = StaticFactId::new("nullable_flag");
}

#[derive(Default)]
struct Predicates;

impl PgFactPredicates for Predicates {
    fn predicate(&self, fact: &FactId, cx: &Context) -> Option<PgFragment> {
        match fact.as_str() {
            "shared" => Some(PgFragment::trusted("cases.shared")),
            "nullable_flag" => Some(PgFragment::trusted("cases.nullable_flag")),
            "owner" => {
                let mut fragment = PgFragment::trusted("cases.owner_id = ");
                fragment.push_fragment(PgFragment::bind(cx.principal.id()));
                Some(fragment)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Case {
    id: i32,
    shared: bool,
    owner_id: Option<&'static str>,
    nullable_flag: Option<bool>,
}

pub async fn assert_lowered_matches_residual(
    pool: &PgPool,
    cx: &Context,
    cases: &[Case],
    residual: &gatekeep::ResidualPolicy<Tier>,
) -> TestResult<()> {
    assert_eq!(
        selected_rows(pool, cx, residual).await?,
        expected_rows(residual, cases, cx)?
    );
    Ok(())
}

pub fn push_typed_bind(
    query: &mut QueryBuilder<Postgres>,
    value: impl Into<PgValue>,
    pg_type: &str,
    prefix_comma: bool,
) {
    if prefix_comma {
        query.push(", ");
    }
    PgFragment::bind(value).push_to(query);
    query.push("::");
    query.push(pg_type);
}

pub async fn selected_rows(
    pool: &PgPool,
    cx: &Context,
    residual: &gatekeep::ResidualPolicy<Tier>,
) -> TestResult<Vec<(i32, i64)>> {
    let lowered = PgLowerer::new(Predicates).lower(residual, cx)?;
    let mut query = QueryBuilder::<Postgres>::new("SELECT cases.id, ");
    lowered.grade.push_to(&mut query);
    query.push(" AS grade FROM cases WHERE ");
    lowered.filter.push_to(&mut query);
    query.push(" ORDER BY cases.id");

    Ok(query.build_query_as::<(i32, i64)>().fetch_all(pool).await?)
}

pub const fn grant(outcome: Tier, condition: Condition) -> gatekeep::ResidualPolicy<Tier> {
    gatekeep::ResidualPolicy::Grant {
        outcome,
        condition,
        label: None,
        deny_shape: gatekeep::DenyShape::Forbidden,
        obligations: Vec::new(),
        reason: None,
    }
}

pub const fn cases() -> [Case; 6] {
    [
        Case {
            id: 1,
            shared: false,
            owner_id: None,
            nullable_flag: None,
        },
        Case {
            id: 2,
            shared: true,
            owner_id: None,
            nullable_flag: None,
        },
        Case {
            id: 3,
            shared: false,
            owner_id: Some("subject-1"),
            nullable_flag: None,
        },
        Case {
            id: 4,
            shared: false,
            owner_id: Some("subject-1"),
            nullable_flag: Some(true),
        },
        Case {
            id: 5,
            shared: true,
            owner_id: Some("subject-1"),
            nullable_flag: Some(true),
        },
        Case {
            id: 6,
            shared: false,
            owner_id: Some("subject-1"),
            nullable_flag: Some(false),
        },
    ]
}

pub async fn pool() -> TestResult<PgPool> {
    let database_url = std::env::var("DATABASE_URL")?;
    validate_database_url_for_backend::<PostgresBackend>(&database_url)?;
    Ok(PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?)
}

pub async fn reset_database(pool: &PgPool) -> TestResult<()> {
    sqlx::query("drop table if exists cases")
        .execute(pool)
        .await?;
    sqlx::query(
        r"
        create table cases (
            id integer primary key,
            shared boolean not null,
            owner_id text,
            nullable_flag boolean
        )
        ",
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_cases(pool: &PgPool, cases: &[Case]) -> TestResult<()> {
    for case in cases {
        sqlx::query(
            r"
            insert into cases (id, shared, owner_id, nullable_flag)
            values ($1, $2, $3, $4)
            ",
        )
        .bind(case.id)
        .bind(case.shared)
        .bind(case.owner_id)
        .bind(case.nullable_flag)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub fn cx() -> Result<Context, GatekeepError> {
    Ok(Context {
        tenant: TenantId::new("tenant-1")?,
        principal: SubjectRef::new("user", "subject-1")?,
        subjects: std::collections::BTreeMap::new(),
        locale: Locale::new("en-GB")?,
        request_id: None,
    })
}

fn expected_rows(
    residual: &gatekeep::ResidualPolicy<Tier>,
    cases: &[Case],
    cx: &Context,
) -> TestResult<Vec<(i32, i64)>> {
    let mut rows = Vec::new();
    for case in cases {
        let decision = evaluate_residual(residual, &facts_for(case, cx)?);
        if let Effect::Permit(tier) = decision.effect {
            rows.push((case.id, tier.to_sql_ordinal()));
        }
    }
    Ok(rows)
}

fn facts_for(case: &Case, cx: &Context) -> Result<KnownFacts, GatekeepError> {
    KnownFacts::from_entries([
        (FactId::new("shared")?, presence(case.shared)),
        (
            FactId::new("owner")?,
            presence(case.owner_id == Some(cx.principal.id())),
        ),
        (
            FactId::new("nullable_flag")?,
            presence(case.nullable_flag == Some(true)),
        ),
    ])
}

const fn presence(value: bool) -> Presence {
    if value {
        Presence::Present
    } else {
        Presence::Absent
    }
}

pub type TestResult<T> = core::result::Result<T, TestError>;

#[derive(Debug, thiserror::Error)]
pub enum TestError {
    #[error(transparent)]
    Audit(#[from] gatekeep_sqlx::SqlxAuditError),
    #[error(transparent)]
    Env(#[from] std::env::VarError),
    #[error(transparent)]
    Driver(#[from] gatekeep_sqlx::SqlxDriverError),
    #[error(transparent)]
    Gatekeep(#[from] GatekeepError),
    #[error(transparent)]
    Lower(#[from] gatekeep::LowerError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error("test temporal value should be valid")]
    InvalidTemporalValue,
    #[error("partial evaluation unexpectedly resolved")]
    UnexpectedResolvedResidual,
}
