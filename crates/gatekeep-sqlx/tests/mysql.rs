//! MySQL-backed gatekeep `SQLx` differential tests.
#![cfg(feature = "mysql-tests")]

#[path = "mysql/dovecote_audit.rs"]
mod dovecote_audit;

use gatekeep::{
    ApplicationVerifiedTenantBinding, BindingAuthority, BindingProvenance, Condition, Context,
    Effect, EvidenceDigest, Fact, FactId, GatekeepError, KnownFacts, Lattice, Locale, Presence,
    QueryLowering, StaticFactId, SubjectRef, TenantBinding, TenantBindingEvidence, TenantId,
    condition, evaluate_residual,
};
use gatekeep_sqlx::{
    MySqlBackend, SqlOutcome, SqlxFactPredicates, SqlxFragment, SqlxLowerer, TenantColumn,
    validate_database_url_for_backend,
};
use sqlx::{MySql, MySqlPool, QueryBuilder, mysql::MySqlPoolOptions};

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

#[derive(Default)]
struct Predicates;

impl SqlxFactPredicates<MySqlBackend> for Predicates {
    fn predicate(&self, fact: &FactId, cx: &Context) -> Option<SqlxFragment<MySqlBackend>> {
        match fact.as_str() {
            "shared" => Some(SqlxFragment::trusted("cases.shared")),
            "owner" => {
                let mut fragment = SqlxFragment::trusted("cases.owner_id = ");
                fragment.push_fragment(SqlxFragment::bind(cx.principal().id()));
                Some(fragment)
            }
            _ => None,
        }
    }
}

#[tokio::test]
#[ignore = "requires docker mysql; run `mise exec -- just test-db-mysql`"]
async fn lowered_filters_and_grades_match_in_memory_residual_evaluation() -> TestResult<()> {
    let pool = pool().await?;
    reset_database(&pool).await?;
    let cases = cases();
    insert_cases(&pool, &cases).await?;

    let cx = cx()?;
    let residual = gatekeep::ResidualPolicy::Any(vec![
        grant(Tier::Shared, condition::has::<Shared>()),
        grant(Tier::Full, condition::has::<Owner>()),
    ]);

    assert_eq!(
        selected_rows(&pool, &cx, &residual).await?,
        expected_rows(&residual, &cases, &cx)?
    );
    Ok(())
}

async fn selected_rows(
    pool: &MySqlPool,
    cx: &Context,
    residual: &gatekeep::ResidualPolicy<Tier>,
) -> TestResult<Vec<(i32, i64)>> {
    let lowered = SqlxLowerer::<MySqlBackend, _, _>::new(
        Predicates,
        TenantColumn::new("cases", "tenant_id")?,
    )
    .lower(residual, cx)?;
    let mut query = QueryBuilder::<MySql>::new("SELECT cases.id, ");
    lowered.grade.push_to(&mut query);
    query.push(" AS grade FROM cases WHERE ");
    lowered.filter.push_to(&mut query);
    query.push(" ORDER BY cases.id");

    Ok(query.build_query_as::<(i32, i64)>().fetch_all(pool).await?)
}

async fn pool() -> TestResult<MySqlPool> {
    let database_url = std::env::var("MYSQL_DATABASE_URL")?;
    validate_database_url_for_backend::<MySqlBackend>(&database_url)?;
    Ok(MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?)
}

async fn reset_database(pool: &MySqlPool) -> TestResult<()> {
    sqlx::query("drop table if exists cases")
        .execute(pool)
        .await?;
    sqlx::query(
        r"
        create table cases (
            id integer primary key,
            tenant_id text not null,
            shared boolean not null,
            owner_id text
        )
        ",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_cases(pool: &MySqlPool, cases: &[Case]) -> TestResult<()> {
    for case in cases {
        sqlx::query(
            r"
            insert into cases (id, tenant_id, shared, owner_id)
            values (?, ?, ?, ?)
            ",
        )
        .bind(case.id)
        .bind("tenant-1")
        .bind(case.shared)
        .bind(case.owner_id)
        .execute(pool)
        .await?;
    }
    Ok(())
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

#[derive(Clone, Debug)]
struct Case {
    id: i32,
    shared: bool,
    owner_id: Option<&'static str>,
}

const fn cases() -> [Case; 4] {
    [
        Case {
            id: 1,
            shared: false,
            owner_id: None,
        },
        Case {
            id: 2,
            shared: true,
            owner_id: None,
        },
        Case {
            id: 3,
            shared: false,
            owner_id: Some("subject-1"),
        },
        Case {
            id: 4,
            shared: true,
            owner_id: Some("subject-1"),
        },
    ]
}

fn cx() -> TestResult<Context> {
    let now = time::OffsetDateTime::UNIX_EPOCH;
    let tenant = TenantId::new("tenant-1")?;
    let binding = ApplicationVerifiedTenantBinding::new(
        tenant.clone(),
        TenantBindingEvidence::new(
            BindingAuthority::Issuer {
                issuer: BindingProvenance::new("test")?,
                key_id: None,
            },
            now,
            EvidenceDigest::new([0; 32]),
        ),
        now,
        now + time::Duration::hours(1),
    )?;
    Ok(Context::new_at(
        tenant,
        TenantBinding::ApplicationVerified(binding),
        SubjectRef::new("user", "subject-1")?,
        Locale::new("en-GB")?,
        now,
    )?)
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
            presence(case.owner_id == Some(cx.principal().id())),
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

type TestResult<T> = core::result::Result<T, TestError>;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Env(#[from] std::env::VarError),
    #[error(transparent)]
    Driver(#[from] gatekeep_sqlx::SqlxDriverError),
    #[error(transparent)]
    Gatekeep(#[from] GatekeepError),
    #[error(transparent)]
    Context(#[from] gatekeep::ContextError),
    #[error(transparent)]
    Binding(#[from] gatekeep::TenantBindingError),
    #[error(transparent)]
    Lower(#[from] gatekeep::LowerError),
    #[error(transparent)]
    TenantColumn(#[from] gatekeep_sqlx::TenantColumnError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}
