//! send-app case-access acceptance model.

use gatekeep::{
    ClauseLabel, DenyShape, Effect, Fact, KnownFacts, Lattice, ObligationSpec, PartialFacts,
    Policy, Residual, StaticFactId, StaticObligationId, complete_residual, condition, evaluate,
    partial_evaluate, policy, required_residual_facts,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
enum ReadTier {
    Released,
    Shared,
    Full,
}

impl Lattice for ReadTier {
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

struct RoleAccess;
impl Fact for RoleAccess {
    const ID: StaticFactId = StaticFactId::new("role_access");
}

struct ParticipantRole;
impl Fact for ParticipantRole {
    const ID: StaticFactId = StaticFactId::new("participant_role");
}

struct ResourceShared;
impl Fact for ResourceShared {
    const ID: StaticFactId = StaticFactId::new("resource_shared");
}

struct ResourceFull;
impl Fact for ResourceFull {
    const ID: StaticFactId = StaticFactId::new("resource_full");
}

struct BreakGlassActive;
impl Fact for BreakGlassActive {
    const ID: StaticFactId = StaticFactId::new("break_glass_active");
}

struct BreakGlass;
impl ObligationSpec for BreakGlass {
    const ID: StaticObligationId = StaticObligationId::new("break_glass");
}

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Gatekeep(#[from] gatekeep::GatekeepError),
    #[error(transparent)]
    Trace(#[from] gatekeep::TraceError),
    #[error("{0}")]
    Message(&'static str),
}

#[test]
fn case_read_policy_covers_tiering_hidden_denial_and_break_glass() -> Result<(), TestError> {
    let policy = case_read_policy()?;

    let shared_decision = evaluate(
        &policy,
        &KnownFacts::new()
            .with_present::<RoleAccess>()
            .with_present::<ParticipantRole>()
            .with_present::<ResourceShared>()
            .with_absent::<ResourceFull>()
            .with_absent::<BreakGlassActive>(),
    );
    assert_eq!(shared_decision.effect, Effect::Permit(ReadTier::Shared));
    assert!(shared_decision.obligations.is_empty());

    let full_decision = evaluate(
        &policy,
        &KnownFacts::new()
            .with_present::<RoleAccess>()
            .with_present::<ParticipantRole>()
            .with_present::<ResourceShared>()
            .with_present::<ResourceFull>()
            .with_absent::<BreakGlassActive>(),
    );
    assert_eq!(full_decision.effect, Effect::Permit(ReadTier::Full));
    assert!(full_decision.obligations.is_empty());

    let hidden_decision = evaluate(
        &policy,
        &KnownFacts::new()
            .with_absent::<RoleAccess>()
            .with_absent::<ParticipantRole>()
            .with_absent::<ResourceShared>()
            .with_absent::<ResourceFull>()
            .with_absent::<BreakGlassActive>(),
    );
    let Some(reason) = hidden_decision.denial_reason()? else {
        return Err(TestError::Message("denied case read should carry a reason"));
    };
    assert_eq!(hidden_decision.effect, Effect::Deny);
    assert_eq!(reason.shape, DenyShape::Hidden);
    assert_eq!(reason.code.as_str(), "case_not_found");

    let break_glass_decision = evaluate(
        &policy,
        &KnownFacts::new()
            .with_absent::<RoleAccess>()
            .with_absent::<ParticipantRole>()
            .with_absent::<ResourceShared>()
            .with_absent::<ResourceFull>()
            .with_present::<BreakGlassActive>(),
    );
    assert_eq!(break_glass_decision.effect, Effect::Permit(ReadTier::Full));
    assert_eq!(break_glass_decision.obligations.len(), 1);
    assert_eq!(break_glass_decision.obligations[0].as_str(), "break_glass");

    Ok(())
}

#[test]
fn authorized_list_partial_evaluation_defers_resource_facts() -> Result<(), TestError> {
    let policy = case_read_policy()?;
    let partial = PartialFacts::new()
        .with_present::<RoleAccess>()
        .with_present::<ParticipantRole>()
        .with_unknown::<ResourceShared>()
        .with_unknown::<ResourceFull>()
        .with_absent::<BreakGlassActive>();
    let completed = KnownFacts::new()
        .with_present::<RoleAccess>()
        .with_present::<ParticipantRole>()
        .with_present::<ResourceShared>()
        .with_absent::<ResourceFull>()
        .with_absent::<BreakGlassActive>();

    let reduced = partial_evaluate(&policy, &partial);
    let Residual::Pending { residual, .. } = &reduced else {
        return Err(TestError::Message(
            "resource facts should remain as residual",
        ));
    };

    let residual_facts = required_residual_facts(residual)
        .into_iter()
        .map(|fact| fact.as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(residual_facts, vec!["resource_full", "resource_shared"]);
    let original = evaluate(&policy, &completed);
    let completed_residual = complete_residual(&reduced, &completed);

    assert_eq!(completed_residual.effect, original.effect);
    assert_eq!(completed_residual.obligations, original.obligations);
    Ok(())
}

fn case_read_policy() -> Result<Policy<ReadTier>, gatekeep::GatekeepError> {
    Ok(policy::or_else(
        policy::all([
            policy::grant(ReadTier::Full, condition::has::<RoleAccess>())
                .labeled(ClauseLabel::new("case_role")?)
                .reason(gatekeep::ReasonCode::new("case_not_found")?)
                .hidden(),
            policy::grant(ReadTier::Full, condition::has::<ParticipantRole>())
                .labeled(ClauseLabel::new("participant_role")?)
                .reason(gatekeep::ReasonCode::new("case_not_found")?)
                .hidden(),
            policy::any([
                policy::grant(ReadTier::Full, condition::has::<ResourceFull>())
                    .labeled(ClauseLabel::new("case_full")?)
                    .reason(gatekeep::ReasonCode::new("case_read_forbidden")?),
                policy::grant(ReadTier::Shared, condition::has::<ResourceShared>())
                    .labeled(ClauseLabel::new("case_shared")?)
                    .reason(gatekeep::ReasonCode::new("case_read_forbidden")?),
            ]),
        ]),
        policy::grant(ReadTier::Full, condition::has::<BreakGlassActive>())
            .labeled(ClauseLabel::new("break_glass")?)
            .reason(gatekeep::ReasonCode::new("case_not_found")?)
            .hidden()
            .with_obligation::<BreakGlass>(),
    ))
}
