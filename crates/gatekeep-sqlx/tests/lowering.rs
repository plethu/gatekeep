//! Gatekeep `SQLx` lowering tests.

use gatekeep::{
    Condition, Context, Effect, Fact, FactId, GatekeepError, KnownFacts, Lattice, Locale,
    PartialFacts, Presence, QueryLowering, Residual, StaticFactId, SubjectRef, TenantId, condition,
    evaluate, partial_evaluate, policy,
};
use gatekeep_sqlx::{PgFactPredicates, PgFragment, PgLowerer, SqlOutcome};
use sqlx::{Execute, Postgres, QueryBuilder};

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
                fragment.push_fragment(PgFragment::bind_text("subject-1"));
                Some(fragment)
            }
            _ => None,
        }
    }
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

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Gatekeep(#[from] GatekeepError),
    #[error(transparent)]
    Lower(#[from] gatekeep::LowerError),
    #[error("partial evaluation unexpectedly resolved")]
    UnexpectedResolvedResidual,
    #[error("staff fact should be unlowerable")]
    ExpectedUnlowerableFact,
}

const fn presence(value: bool) -> Presence {
    if value {
        Presence::Present
    } else {
        Presence::Absent
    }
}
