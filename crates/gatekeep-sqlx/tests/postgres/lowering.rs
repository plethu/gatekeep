use gatekeep::{Condition, PartialFacts, Residual, condition, partial_evaluate, policy};

use crate::support::{
    NullableFlag, Owner, Shared, TestError, TestResult, Tier, assert_lowered_matches_residual,
    cases, cx, grant, insert_cases, pool, reset_database, selected_rows,
};

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
