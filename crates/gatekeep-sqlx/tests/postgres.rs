#![allow(missing_docs)]
#![cfg(feature = "postgres-tests")]
//! Docker-backed Postgres differential tests.

use gatekeep::{
    Condition, Context, Effect, Fact, FactId, GatekeepError, KnownFacts, Lattice, Locale,
    PartialFacts, Presence, QueryLowering, Residual, StaticFactId, SubjectRef, TenantId, condition,
    evaluate_residual, partial_evaluate, policy,
};
use gatekeep_sqlx::{PgFactPredicates, PgFragment, PgLowerer, SqlOutcome};
use sqlx::{PgPool, Postgres, QueryBuilder, postgres::PgPoolOptions};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
enum Tier {
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

struct Shared;
impl Fact for Shared {
    const ID: StaticFactId = StaticFactId::new("shared");
}

struct Owner;
impl Fact for Owner {
    const ID: StaticFactId = StaticFactId::new("owner");
}

struct NullableFlag;
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
                fragment.push_fragment(PgFragment::bind_text(cx.principal.id.clone()));
                Some(fragment)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct Case {
    id: i32,
    shared: bool,
    owner_id: Option<&'static str>,
    nullable_flag: Option<bool>,
}

#[tokio::test]
#[ignore = "requires docker postgres; run `make test-db`"]
async fn lowered_filters_and_grades_match_in_memory_residual_evaluation() -> TestResult<()> {
    let pool = pool().await?;
    reset_database(&pool).await?;
    let cases = cases();
    insert_cases(&pool, &cases).await?;
    let cx = cx()?;

    let policy = policy::any([
        policy::grant(Tier::Shared, condition::has::<Shared>()),
        policy::grant(
            Tier::Full,
            Condition::All(vec![
                condition::has::<Owner>(),
                condition::not(condition::has::<NullableFlag>()),
            ]),
        ),
    ]);
    let partial = PartialFacts::new()
        .with_unknown::<Shared>()
        .with_unknown::<Owner>()
        .with_unknown::<NullableFlag>();
    let Residual::Pending { residual, .. } = partial_evaluate(&policy, &partial) else {
        return Err(TestError::UnexpectedResolvedResidual);
    };
    assert_lowered_matches_residual(&pool, &cx, &cases, &residual).await?;

    assert_lowered_matches_residual(
        &pool,
        &cx,
        &cases,
        &gatekeep::ResidualPolicy::All(vec![
            grant(Tier::Shared, condition::has::<Shared>()),
            grant(Tier::Full, condition::has::<Owner>()),
        ]),
    )
    .await?;

    assert_lowered_matches_residual(
        &pool,
        &cx,
        &cases,
        &gatekeep::ResidualPolicy::OrElse {
            primary: Box::new(grant(Tier::Shared, condition::has::<Shared>())),
            fallback: Box::new(grant(Tier::Full, condition::has::<Owner>())),
        },
    )
    .await?;

    assert_lowered_matches_residual(
        &pool,
        &cx,
        &cases,
        &grant(
            Tier::Full,
            condition::any([condition::has::<Shared>(), condition::has::<Owner>()]),
        ),
    )
    .await?;
    assert_lowered_matches_residual(
        &pool,
        &cx,
        &cases,
        &grant(Tier::Shared, condition::always()),
    )
    .await?;
    assert_lowered_matches_residual(&pool, &cx, &cases, &grant(Tier::Full, condition::never()))
        .await?;

    assert_lowered_matches_residual(
        &pool,
        &cx,
        &cases,
        &gatekeep::ResidualPolicy::Permit(Tier::Shared),
    )
    .await?;
    assert_lowered_matches_residual(&pool, &cx, &cases, &gatekeep::ResidualPolicy::Deny).await?;
    assert_lowered_matches_residual(
        &pool,
        &cx,
        &cases,
        &gatekeep::ResidualPolicy::All(Vec::new()),
    )
    .await?;
    assert_lowered_matches_residual(
        &pool,
        &cx,
        &cases,
        &gatekeep::ResidualPolicy::Any(Vec::new()),
    )
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires docker postgres; run `make test-db`"]
async fn obligated_or_else_fallback_is_pruned_in_postgres() -> TestResult<()> {
    let pool = pool().await?;
    reset_database(&pool).await?;
    let cases = cases();
    insert_cases(&pool, &cases).await?;
    let cx = cx()?;
    let residual = gatekeep::ResidualPolicy::OrElse {
        primary: Box::new(grant(Tier::Shared, condition::has::<Shared>())),
        fallback: Box::new(gatekeep::ResidualPolicy::Grant {
            outcome: Tier::Full,
            condition: condition::has::<Owner>(),
            label: None,
            deny_shape: gatekeep::DenyShape::Forbidden,
            obligations: vec![gatekeep::ObligationId::new("break_glass")?],
            reason: None,
        }),
    };

    assert_eq!(
        selected_rows(&pool, &cx, &residual).await?,
        vec![(2, 1), (5, 1)]
    );
    Ok(())
}

async fn assert_lowered_matches_residual(
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

async fn selected_rows(
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
            presence(case.owner_id == Some(cx.principal.id.as_str())),
        ),
        (
            FactId::new("nullable_flag")?,
            presence(case.nullable_flag == Some(true)),
        ),
    ])
}

const fn grant(outcome: Tier, condition: Condition) -> gatekeep::ResidualPolicy<Tier> {
    gatekeep::ResidualPolicy::Grant {
        outcome,
        condition,
        label: None,
        deny_shape: gatekeep::DenyShape::Forbidden,
        obligations: Vec::new(),
        reason: None,
    }
}

const fn cases() -> [Case; 6] {
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

async fn pool() -> TestResult<PgPool> {
    let database_url = std::env::var("DATABASE_URL")?;
    Ok(PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?)
}

async fn reset_database(pool: &PgPool) -> TestResult<()> {
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

async fn insert_cases(pool: &PgPool, cases: &[Case]) -> TestResult<()> {
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

fn cx() -> Result<Context, GatekeepError> {
    Ok(Context {
        tenant: TenantId::new("tenant-1")?,
        principal: SubjectRef {
            kind: "user".to_owned(),
            id: "subject-1".to_owned(),
        },
        locale: Locale::new("en-GB")?,
        request_id: None,
    })
}

const fn presence(value: bool) -> Presence {
    if value {
        Presence::Present
    } else {
        Presence::Absent
    }
}

type TestResult<T> = core::result::Result<T, TestError>;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Env(#[from] std::env::VarError),
    #[error(transparent)]
    Gatekeep(#[from] GatekeepError),
    #[error(transparent)]
    Lower(#[from] gatekeep::LowerError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error("partial evaluation unexpectedly resolved")]
    UnexpectedResolvedResidual,
}
