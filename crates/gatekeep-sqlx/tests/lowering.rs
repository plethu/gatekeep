//! Gatekeep `SQLx` lowering tests.

use gatekeep::{
    Condition, Context, Effect, Fact, FactId, GatekeepError, KnownFacts, Lattice, Locale,
    PartialFacts, Presence, QueryLowering, Residual, StaticFactId, SubjectRef, TenantId, condition,
    evaluate, partial_evaluate, policy,
};
#[cfg(feature = "sqlite")]
use gatekeep_sqlx::SqliteBackend;
#[cfg(feature = "sqlite")]
use gatekeep_sqlx::validate_database_url_for_backend;
#[cfg(feature = "mysql")]
use gatekeep_sqlx::{MySqlBackend, SqlxFactPredicates, SqlxFragment, SqlxLowerer};
use gatekeep_sqlx::{PgFactPredicates, PgFragment, PgLowerer, PgValue, SqlOutcome};
use gatekeep_sqlx::{SqlxDriver, infer_enabled_driver_from_url};
#[cfg(all(feature = "sqlite", not(feature = "mysql")))]
use gatekeep_sqlx::{SqlxFactPredicates, SqlxFragment, SqlxLowerer};
use sqlx::{
    Execute, Postgres, QueryBuilder,
    types::{
        Uuid,
        time::{Date, PrimitiveDateTime, Time},
    },
};

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

struct Staff;
impl Fact for Staff {
    const ID: StaticFactId = StaticFactId::new("staff");
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
    fn predicate(&self, fact: &FactId, _cx: &Context) -> Option<PgFragment> {
        match fact.as_str() {
            "shared" => Some(PgFragment::trusted("cases.shared")),
            "nullable_flag" => Some(PgFragment::trusted("cases.nullable_flag")),
            "owner" => {
                let mut fragment = PgFragment::trusted("cases.owner_id = ");
                fragment.push_fragment(PgFragment::bind("subject-1"));
                Some(fragment)
            }
            _ => None,
        }
    }
}

#[cfg(feature = "sqlite")]
impl SqlxFactPredicates<SqliteBackend> for Predicates {
    fn predicate(&self, fact: &FactId, _cx: &Context) -> Option<SqlxFragment<SqliteBackend>> {
        match fact.as_str() {
            "shared" => Some(SqlxFragment::trusted("cases.shared")),
            "nullable_flag" => Some(SqlxFragment::trusted("cases.nullable_flag")),
            "owner" => {
                let mut fragment = SqlxFragment::trusted("cases.owner_id = ");
                fragment.push_fragment(SqlxFragment::bind("subject-1"));
                Some(fragment)
            }
            _ => None,
        }
    }
}

#[cfg(feature = "mysql")]
impl SqlxFactPredicates<MySqlBackend> for Predicates {
    fn predicate(&self, fact: &FactId, _cx: &Context) -> Option<SqlxFragment<MySqlBackend>> {
        match fact.as_str() {
            "shared" => Some(SqlxFragment::trusted("cases.shared")),
            "nullable_flag" => Some(SqlxFragment::trusted("cases.nullable_flag")),
            "owner" => {
                let mut fragment = SqlxFragment::trusted("cases.owner_id = ");
                fragment.push_fragment(SqlxFragment::bind("subject-1"));
                Some(fragment)
            }
            _ => None,
        }
    }
}

fn cx() -> Result<Context, GatekeepError> {
    Ok(Context {
        tenant: TenantId::new("tenant-1")?,
        principal: SubjectRef::new("user", "subject-1")?,
        subjects: std::collections::BTreeMap::new(),
        locale: Locale::new("en-GB")?,
        request_id: None,
    })
}

#[test]
fn lowers_partial_residual_to_filter_and_grade() -> Result<(), TestError> {
    let policy = policy::any([
        policy::grant(Tier::Shared, condition::has::<Shared>()),
        policy::grant(
            Tier::Full,
            Condition::All(vec![condition::has::<Staff>(), condition::has::<Owner>()]),
        ),
    ]);
    let partial = PartialFacts::new()
        .with_unknown::<Shared>()
        .with_present::<Staff>()
        .with_unknown::<Owner>();
    let residual = partial_evaluate(&policy, &partial);
    let Residual::Pending { residual, .. } = residual else {
        return Err(TestError::UnexpectedResolvedResidual);
    };

    let lowered = PgLowerer::new(Predicates).lower(&residual, &cx()?)?;

    assert_eq!(
        lowered.filter.to_postgres_sql(),
        "((cases.shared) IS TRUE) OR ((cases.owner_id = $1) IS TRUE)"
    );
    assert_eq!(
        lowered.grade.to_postgres_sql(),
        "GREATEST(CASE WHEN (cases.shared) IS TRUE THEN $1 ELSE NULL END, CASE WHEN (cases.owner_id = $2) IS TRUE THEN $3 ELSE NULL END)"
    );
    Ok(())
}

#[test]
fn lower_filter_reports_unlowerable_facts() -> Result<(), TestError> {
    let residual = gatekeep::ResidualPolicy::Grant {
        outcome: Tier::Full,
        condition: condition::has::<Staff>(),
        label: None,
        deny_shape: gatekeep::DenyShape::Forbidden,
        obligations: Vec::new(),
        reason: None,
    };

    let error = PgLowerer::new(Predicates).lower_filter(&residual, &cx()?);

    let Err(error) = error else {
        return Err(TestError::ExpectedUnlowerableFact);
    };

    assert_eq!(
        error,
        gatekeep::LowerError::Unlowerable(FactId::new("staff")?)
    );
    Ok(())
}

#[test]
fn lowered_filter_matches_in_memory_evaluation_for_sampled_rows() -> Result<(), TestError> {
    let policy = policy::any([
        policy::grant(Tier::Shared, condition::has::<Shared>()),
        policy::grant(Tier::Full, condition::has::<Owner>()),
    ]);
    let partial = PartialFacts::new()
        .with_unknown::<Shared>()
        .with_unknown::<Owner>();
    let Residual::Pending { residual, .. } = partial_evaluate(&policy, &partial) else {
        return Err(TestError::UnexpectedResolvedResidual);
    };

    let lowered = PgLowerer::new(Predicates).lower_filter(&residual, &cx()?)?;
    assert_eq!(
        lowered.to_postgres_sql(),
        "((cases.shared) IS TRUE) OR ((cases.owner_id = $1) IS TRUE)"
    );

    for (shared, owner) in [(false, false), (true, false), (false, true), (true, true)] {
        let facts = KnownFacts::from_entries([
            (FactId::new("shared")?, presence(shared)),
            (FactId::new("owner")?, presence(owner)),
        ])?;
        let decision = evaluate(&policy, &facts);
        let selected = shared || owner;
        assert_eq!(matches!(decision.effect, Effect::Permit(_)), selected);
    }

    Ok(())
}

#[test]
fn deny_trace_arm_does_not_make_any_projection_unlowerable() -> Result<(), TestError> {
    let residual = gatekeep::ResidualPolicy::Any(vec![
        gatekeep::ResidualPolicy::DenyWithTrace {
            denied: Some(Tier::Shared),
            unsatisfied: vec![FactId::new("staff")?],
            label: None,
            reason: None,
            shape: gatekeep::DenyShape::Forbidden,
        },
        gatekeep::ResidualPolicy::Grant {
            outcome: Tier::Full,
            condition: condition::has::<Owner>(),
            label: None,
            deny_shape: gatekeep::DenyShape::Forbidden,
            obligations: Vec::new(),
            reason: None,
        },
    ]);

    let lowered = PgLowerer::new(Predicates).lower(&residual, &cx()?)?;

    assert_eq!(
        lowered.grade.to_postgres_sql(),
        "GREATEST(NULL, CASE WHEN (cases.owner_id = $1) IS TRUE THEN $2 ELSE NULL END)"
    );
    Ok(())
}

#[test]
fn obligated_or_else_fallback_is_skipped_before_lowering() -> Result<(), TestError> {
    let residual = gatekeep::ResidualPolicy::OrElse {
        primary: Box::new(gatekeep::ResidualPolicy::Grant {
            outcome: Tier::Shared,
            condition: condition::has::<Shared>(),
            label: None,
            deny_shape: gatekeep::DenyShape::Forbidden,
            obligations: Vec::new(),
            reason: None,
        }),
        fallback: Box::new(gatekeep::ResidualPolicy::Grant {
            outcome: Tier::Full,
            condition: condition::has::<Staff>(),
            label: None,
            deny_shape: gatekeep::DenyShape::Forbidden,
            obligations: vec![gatekeep::ObligationId::new("break_glass")?],
            reason: None,
        }),
    };

    let adapter = PgLowerer::new(Predicates);

    let filter = adapter.lower_filter(&residual, &cx()?)?;
    let lowered = adapter.lower(&residual, &cx()?)?;

    assert_eq!(filter.to_postgres_sql(), "(cases.shared) IS TRUE");
    assert_eq!(lowered.filter.to_postgres_sql(), "(cases.shared) IS TRUE");
    assert_eq!(
        lowered.grade.to_postgres_sql(),
        "CASE WHEN (cases.shared) IS TRUE THEN $1 ELSE NULL END"
    );
    Ok(())
}

#[test]
fn fragments_append_to_sqlx_query_builder_with_stable_bind_order() -> Result<(), TestError> {
    let residual = gatekeep::ResidualPolicy::Any(vec![
        gatekeep::ResidualPolicy::Grant {
            outcome: Tier::Shared,
            condition: condition::has::<Shared>(),
            label: None,
            deny_shape: gatekeep::DenyShape::Forbidden,
            obligations: Vec::new(),
            reason: None,
        },
        gatekeep::ResidualPolicy::Grant {
            outcome: Tier::Full,
            condition: condition::has::<Owner>(),
            label: None,
            deny_shape: gatekeep::DenyShape::Forbidden,
            obligations: Vec::new(),
            reason: None,
        },
    ]);
    let lowered = PgLowerer::new(Predicates).lower(&residual, &cx()?)?;
    let mut builder = QueryBuilder::<Postgres>::new("SELECT ");

    lowered.grade.push_to(&mut builder);
    builder.push(" FROM cases WHERE ");
    lowered.filter.push_to(&mut builder);

    let query = builder.build();
    assert_eq!(
        query.sql().as_str(),
        "SELECT GREATEST(CASE WHEN (cases.shared) IS TRUE THEN $1 ELSE NULL END, CASE WHEN (cases.owner_id = $2) IS TRUE THEN $3 ELSE NULL END) FROM cases WHERE ((cases.shared) IS TRUE) OR ((cases.owner_id = $4) IS TRUE)"
    );
    Ok(())
}

#[test]
fn database_url_driver_inference_matches_enabled_sqlx_features() -> Result<(), TestError> {
    assert_eq!(
        infer_enabled_driver_from_url("postgres://gatekeep@localhost/db")?,
        SqlxDriver::Postgres
    );
    assert_eq!(
        infer_enabled_driver_from_url("postgresql://gatekeep@localhost/db")?,
        SqlxDriver::Postgres
    );

    #[cfg(feature = "sqlite")]
    assert_eq!(
        infer_enabled_driver_from_url("sqlite::memory:")?,
        SqlxDriver::Sqlite
    );

    #[cfg(feature = "mysql")]
    assert_eq!(
        infer_enabled_driver_from_url("mysql://gatekeep@localhost/db")?,
        SqlxDriver::MySql
    );

    let Err(error) = infer_enabled_driver_from_url("file:///tmp/gatekeep.db") else {
        return Err(TestError::ExpectedDriverError);
    };
    assert_eq!(
        error,
        gatekeep_sqlx::SqlxDriverError::UnsupportedUrlScheme {
            scheme: Some("file".to_owned()),
        }
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn database_url_validation_rejects_backend_mismatch() -> Result<(), TestError> {
    let Err(error) =
        validate_database_url_for_backend::<SqliteBackend>("postgres://gatekeep@localhost/db")
    else {
        return Err(TestError::ExpectedDriverError);
    };

    assert_eq!(
        error,
        gatekeep_sqlx::SqlxDriverError::BackendMismatch {
            expected: "sqlite",
            actual: "postgres",
        }
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_fragments_use_question_mark_placeholders() -> Result<(), TestError> {
    let residual = shared_or_owner_residual();
    let lowered = SqlxLowerer::<SqliteBackend, _, _>::new(Predicates).lower(&residual, &cx()?)?;

    assert_eq!(
        lowered.filter.to_sql(),
        "((cases.shared) IS TRUE) OR ((cases.owner_id = ?) IS TRUE)"
    );
    assert_eq!(
        lowered.grade.to_sql(),
        "CASE WHEN (CASE WHEN (cases.shared) IS TRUE THEN ? ELSE NULL END) IS NULL THEN CASE WHEN (cases.owner_id = ?) IS TRUE THEN ? ELSE NULL END WHEN (CASE WHEN (cases.owner_id = ?) IS TRUE THEN ? ELSE NULL END) IS NULL THEN CASE WHEN (cases.shared) IS TRUE THEN ? ELSE NULL END ELSE max(CASE WHEN (cases.shared) IS TRUE THEN ? ELSE NULL END, CASE WHEN (cases.owner_id = ?) IS TRUE THEN ? ELSE NULL END) END"
    );
    Ok(())
}

#[cfg(feature = "mysql")]
#[test]
fn mysql_fragments_use_question_mark_placeholders() -> Result<(), TestError> {
    let residual = shared_or_owner_residual();
    let lowered = SqlxLowerer::<MySqlBackend, _, _>::new(Predicates).lower(&residual, &cx()?)?;

    assert_eq!(
        lowered.filter.to_sql(),
        "((cases.shared) IS TRUE) OR ((cases.owner_id = ?) IS TRUE)"
    );
    assert_eq!(
        lowered.grade.to_sql(),
        "CASE WHEN (CASE WHEN (cases.shared) IS TRUE THEN ? ELSE NULL END) IS NULL THEN CASE WHEN (cases.owner_id = ?) IS TRUE THEN ? ELSE NULL END WHEN (CASE WHEN (cases.owner_id = ?) IS TRUE THEN ? ELSE NULL END) IS NULL THEN CASE WHEN (cases.shared) IS TRUE THEN ? ELSE NULL END ELSE GREATEST(CASE WHEN (cases.shared) IS TRUE THEN ? ELSE NULL END, CASE WHEN (cases.owner_id = ?) IS TRUE THEN ? ELSE NULL END) END"
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_lowered_query_matches_in_memory_evaluation() -> Result<(), TestError> {
    use sqlx::{Sqlite, sqlite::SqlitePoolOptions};

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    reset_sqlite_database(&pool).await?;
    insert_sqlite_cases(&pool).await?;

    let residual = shared_or_owner_residual();
    let lowered = SqlxLowerer::<SqliteBackend, _, _>::new(Predicates).lower(&residual, &cx()?)?;
    let mut query = QueryBuilder::<Sqlite>::new("SELECT cases.id, ");
    lowered.grade.push_to(&mut query);
    query.push(" AS grade FROM cases WHERE ");
    lowered.filter.push_to(&mut query);
    query.push(" ORDER BY cases.id");

    let rows = query
        .build_query_as::<(i32, i64)>()
        .fetch_all(&pool)
        .await?;

    assert_eq!(rows, vec![(2, 1), (3, 2), (4, 2)]);
    Ok(())
}

#[test]
fn fragments_support_common_postgres_bind_values() -> Result<(), TestError> {
    let values = common_bind_values()?;
    let fragment = values_fragment(&values);

    assert_eq!(
        fragment.to_postgres_sql(),
        "values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
    );
    assert_eq!(fragment.binds().cloned().collect::<Vec<_>>(), values);
    Ok(())
}

#[test]
fn negated_fact_predicate_treats_sql_null_as_absent() -> Result<(), TestError> {
    let residual = gatekeep::ResidualPolicy::Grant {
        outcome: Tier::Released,
        condition: condition::not(condition::has::<NullableFlag>()),
        label: None,
        deny_shape: gatekeep::DenyShape::Forbidden,
        obligations: Vec::new(),
        reason: None,
    };

    let lowered = PgLowerer::new(Predicates).lower_filter(&residual, &cx()?)?;

    assert_eq!(
        lowered.to_postgres_sql(),
        "NOT ((cases.nullable_flag) IS TRUE)"
    );
    Ok(())
}

#[test]
fn empty_residual_combinators_lower_as_deny() -> Result<(), TestError> {
    let adapter = PgLowerer::new(Predicates);

    for residual in [
        gatekeep::ResidualPolicy::<Tier>::All(Vec::new()),
        gatekeep::ResidualPolicy::<Tier>::Any(Vec::new()),
    ] {
        let lowered = adapter.lower(&residual, &cx()?)?;
        assert_eq!(lowered.filter.to_postgres_sql(), "FALSE");
        assert_eq!(lowered.grade.to_postgres_sql(), "NULL");
    }

    Ok(())
}

#[cfg(any(feature = "sqlite", feature = "mysql"))]
fn shared_or_owner_residual() -> gatekeep::ResidualPolicy<Tier> {
    gatekeep::ResidualPolicy::Any(vec![
        gatekeep::ResidualPolicy::Grant {
            outcome: Tier::Shared,
            condition: condition::has::<Shared>(),
            label: None,
            deny_shape: gatekeep::DenyShape::Forbidden,
            obligations: Vec::new(),
            reason: None,
        },
        gatekeep::ResidualPolicy::Grant {
            outcome: Tier::Full,
            condition: condition::has::<Owner>(),
            label: None,
            deny_shape: gatekeep::DenyShape::Forbidden,
            obligations: Vec::new(),
            reason: None,
        },
    ])
}

#[cfg(feature = "sqlite")]
async fn reset_sqlite_database(pool: &sqlx::SqlitePool) -> Result<(), TestError> {
    sqlx::query(
        r"
        create table cases (
            id integer primary key,
            shared boolean not null,
            owner_id text
        )
        ",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(feature = "sqlite")]
async fn insert_sqlite_cases(pool: &sqlx::SqlitePool) -> Result<(), TestError> {
    for (id, shared, owner_id) in [
        (1, false, None),
        (2, true, None),
        (3, false, Some("subject-1")),
        (4, true, Some("subject-1")),
    ] {
        sqlx::query(
            r"
            insert into cases (id, shared, owner_id)
            values (?, ?, ?)
            ",
        )
        .bind(id)
        .bind(shared)
        .bind(owner_id)
        .execute(pool)
        .await?;
    }
    Ok(())
}

fn common_bind_values() -> Result<Vec<PgValue>, TestError> {
    let date = Date::from_ordinal_date(2026, 171).map_err(|_| TestError::InvalidTemporalValue)?;
    let time = Time::from_hms(14, 30, 15).map_err(|_| TestError::InvalidTemporalValue)?;
    let timestamp = PrimitiveDateTime::new(date, time);

    Ok(vec![
        true.into(),
        7_i16.into(),
        42_i32.into(),
        99_i64.into(),
        "owner".into(),
        vec![1, 2, 3, 4].into(),
        Uuid::from_u128(0x123e_4567_e89b_12d3_a456_4266_1417_4000).into(),
        date.into(),
        time.into(),
        timestamp.into(),
        timestamp.assume_utc().into(),
    ])
}

fn values_fragment(values: &[PgValue]) -> PgFragment {
    let mut fragment = PgFragment::trusted("values (");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            fragment.push_fragment(PgFragment::trusted(", "));
        }
        fragment.push_fragment(PgFragment::bind(value.clone()));
    }
    fragment.push_fragment(PgFragment::trusted(")"));
    fragment
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Gatekeep(#[from] GatekeepError),
    #[error(transparent)]
    Lower(#[from] gatekeep::LowerError),
    #[error(transparent)]
    Driver(#[from] gatekeep_sqlx::SqlxDriverError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error("test temporal value should be valid")]
    InvalidTemporalValue,
    #[error("partial evaluation unexpectedly resolved")]
    UnexpectedResolvedResidual,
    #[error("staff fact should be unlowerable")]
    ExpectedUnlowerableFact,
    #[error("expected SQLx driver configuration error")]
    ExpectedDriverError,
}

const fn presence(value: bool) -> Presence {
    if value {
        Presence::Present
    } else {
        Presence::Absent
    }
}
