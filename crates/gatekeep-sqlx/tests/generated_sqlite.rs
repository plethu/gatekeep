//! Exhaustive bounded policy compositions against actual `SQLite` null semantics.
#![cfg(feature = "sqlite-tests")]
use gatekeep::{
    Context, Fact, FactId, KnownFacts, Lattice, Locale, PartialFacts, Policy, StaticFactId,
    SubjectRef, TenantId, TrustedServiceBinding, condition, evaluate, partial_evaluate, policy,
};
use gatekeep_sqlx::{
    SqlOutcome, SqliteBackend, SqlxFactPredicates, SqlxFragment, SqlxLowerer, TenantColumn,
};
use serde::Serialize;
use sqlx::{QueryBuilder, Sqlite, SqlitePool, sqlite::SqlitePoolOptions};
use std::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
enum Tier {
    Shared,
    Full,
}
impl Lattice for Tier {
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
        Self::Shared
    }
}
impl SqlOutcome for Tier {
    fn to_sql_ordinal(&self) -> i64 {
        match self {
            Self::Shared => 0,
            Self::Full => 1,
        }
    }
}
struct Owner;
struct Member;
impl Fact for Owner {
    const ID: StaticFactId = StaticFactId::new("owner");
}
impl Fact for Member {
    const ID: StaticFactId = StaticFactId::new("member");
}
struct Predicates;
impl SqlxFactPredicates<SqliteBackend> for Predicates {
    fn predicate(&self, fact: &FactId, _: &Context) -> Option<SqlxFragment<SqliteBackend>> {
        match fact.as_str() {
            "owner" => Some(SqlxFragment::trusted("records.owner")),
            "member" => Some(SqlxFragment::trusted("records.member")),
            _ => None,
        }
    }
}
fn policies() -> Vec<Policy<Tier>> {
    let leaves = [
        policy::deny(),
        policy::permit(Tier::Shared),
        policy::permit(Tier::Full),
        policy::grant_clause(Tier::Full, condition::has::<Owner>()).into_policy(),
        policy::grant_clause(Tier::Shared, condition::has::<Member>()).into_policy(),
        policy::grant_clause(Tier::Full, condition::not(condition::has::<Owner>())).into_policy(),
    ];
    leaves
        .iter()
        .flat_map(|left| {
            leaves.iter().flat_map(move |right| {
                [
                    policy::all([left.clone(), right.clone()]),
                    policy::any([left.clone(), right.clone()]),
                    policy::or_else(left.clone(), right.clone()),
                ]
            })
        })
        .collect()
}

#[tokio::test]
async fn generated_compositions_match_direct_evaluation_and_guard_projection()
-> Result<(), Box<dyn Error>> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    sqlx::query("CREATE TABLE records (tenant TEXT, owner BOOLEAN, member BOOLEAN)")
        .execute(&pool)
        .await?;
    let context = Context::from_trusted_service(
        TrustedServiceBinding::new(TenantId::new("selected")?, "test")?,
        SubjectRef::new("person", "alex")?,
        Locale::new("en")?,
    )?;
    let lowerer = SqlxLowerer::new(Predicates, TenantColumn::new("records", "tenant")?);
    let partial = PartialFacts::new()
        .with_unknown::<Owner>()
        .with_unknown::<Member>();
    let samples = [None, Some(false), Some(true)];
    for policy in policies() {
        let plan = lowerer.lower_result(&partial_evaluate(&policy, &partial), &context)?;
        for (owner, member) in samples
            .into_iter()
            .flat_map(|owner| samples.into_iter().map(move |member| (owner, member)))
        {
            check_rows(&pool, &policy, &plan, owner, member).await?;
        }
    }

    Ok(())
}

async fn check_rows(
    pool: &SqlitePool,
    policy: &Policy<Tier>,
    plan: &gatekeep::Lowered<SqlxFragment<SqliteBackend>, SqlxFragment<SqliteBackend>>,
    owner: Option<bool>,
    member: Option<bool>,
) -> Result<(), Box<dyn Error>> {
    sqlx::query("DELETE FROM records").execute(pool).await?;
    for tenant in ["selected", "other"] {
        sqlx::query("INSERT INTO records VALUES (?, ?, ?)")
            .bind(tenant)
            .bind(owner)
            .bind(member)
            .execute(pool)
            .await?;
    }

    let decision = evaluate(
        policy,
        &KnownFacts::new()
            .with_bool::<Owner>(owner == Some(true))
            .with_bool::<Member>(member == Some(true)),
    );
    let mut query = QueryBuilder::<Sqlite>::new("SELECT ");
    plan.grade.push_to(&mut query);
    query.push(" FROM records WHERE ");
    plan.filter.push_to(&mut query);
    let rows = query
        .build_query_scalar::<Option<i64>>()
        .fetch_all(pool)
        .await?;
    let expected = decision
        .outcome()
        .map(|tier| Some(tier.to_sql_ordinal()))
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(
        rows, expected,
        "policy={policy:?}, owner={owner:?}, member={member:?}"
    );
    // A caller accidentally omitting the WHERE filter still cannot project
    // another tenant's grade. This does not authorize returning the row itself.
    let mut projection = QueryBuilder::<Sqlite>::new("SELECT ");
    plan.grade.push_to(&mut projection);
    projection.push(" FROM records WHERE tenant = 'other'");
    let grade = projection
        .build_query_scalar::<Option<i64>>()
        .fetch_one(pool)
        .await?;
    assert_eq!(grade, None);
    Ok(())
}
