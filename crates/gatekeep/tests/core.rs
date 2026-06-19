//! Core gatekeep behavior tests.

use gatekeep::{
    ClauseLabel, DenyShape, Effect, Fact, FactId, KnownFacts, Lattice, ObligationSpec,
    PartialFacts, Policy, Presence, Residual, StaticFactId, StaticObligationId, complete_residual,
    condition, evaluate, partial_evaluate, policy, required_facts,
};
use proptest::prelude::*;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error(transparent)]
    Gatekeep(#[from] gatekeep::GatekeepError),
    #[error(transparent)]
    Trace(#[from] gatekeep::TraceError),
    #[error(transparent)]
    Postcard(#[from] postcard::Error),
    #[error("{0}")]
    Message(&'static str),
}

fn assert_denial_metadata(
    decision: &gatekeep::Decision<ReadTier>,
    expected_label: &str,
    expected_reason: Option<&str>,
    expected_shape: DenyShape,
) -> Result<(), TestError> {
    let gatekeep::DecisiveClause::Deny {
        label,
        reason,
        shape,
        ..
    } = &decision.trace.decisive
    else {
        return Err(TestError::Message("decision should deny"));
    };
    let Some(label) = label else {
        return Err(TestError::Message("denial should carry label"));
    };
    assert_eq!(label.as_str(), expected_label);
    assert_eq!(
        reason.as_ref().map(gatekeep::ReasonCode::as_str),
        expected_reason
    );
    assert_eq!(*shape, expected_shape);
    Ok(())
}

fn assert_denial_fact_params(
    decision: &gatekeep::Decision<ReadTier>,
    expected: &[&str],
) -> Result<(), TestError> {
    let Some(reason) = decision.denial_reason()? else {
        return Err(TestError::Message("decision should have denial reason"));
    };
    let facts = reason
        .params
        .values()
        .filter_map(|value| match value {
            gatekeep::ReasonValue::Fact(fact) => Some(fact.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(facts, expected);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
enum ReadTier {
    Released,
    Shared,
    Full,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
enum Scope {
    Left,
    Right,
    Both,
    None,
}

impl Lattice for Scope {
    fn meet(&self, other: &Self) -> Self {
        match (*self, *other) {
            (Self::None, _)
            | (_, Self::None)
            | (Self::Left, Self::Right)
            | (Self::Right, Self::Left) => Self::None,
            (Self::Both, value) | (value, Self::Both) => value,
            (Self::Left, Self::Left) => Self::Left,
            (Self::Right, Self::Right) => Self::Right,
        }
    }

    fn join(&self, other: &Self) -> Self {
        match (*self, *other) {
            (Self::Both, _)
            | (_, Self::Both)
            | (Self::Left, Self::Right)
            | (Self::Right, Self::Left) => Self::Both,
            (Self::None, value) | (value, Self::None) => value,
            (Self::Left, Self::Left) => Self::Left,
            (Self::Right, Self::Right) => Self::Right,
        }
    }

    fn top() -> Self {
        Self::Both
    }

    fn bottom() -> Self {
        Self::None
    }
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

struct ResourceShared;
impl Fact for ResourceShared {
    const ID: StaticFactId = StaticFactId::new("resource_shared");
}

struct ResourceFull;
impl Fact for ResourceFull {
    const ID: StaticFactId = StaticFactId::new("resource_full");
}

struct BreakGlass;
impl ObligationSpec for BreakGlass {
    const ID: StaticObligationId = StaticObligationId::new("break_glass");
}

struct AuditOverride;
impl ObligationSpec for AuditOverride {
    const ID: StaticObligationId = StaticObligationId::new("audit_override");
}

#[test]
fn empty_policy_combinators_fail_closed() {
    let facts = KnownFacts::new();

    assert_eq!(
        evaluate(&policy::all::<ReadTier>([]), &facts).effect,
        Effect::Deny
    );
    assert_eq!(
        evaluate(&policy::any::<ReadTier>([]), &facts).effect,
        Effect::Deny
    );
}

#[test]
fn grant_denial_carries_reason_metadata() -> Result<(), TestError> {
    let decision = evaluate(
        &policy::grant(ReadTier::Full, condition::has::<RoleAccess>())
            .try_labeled("case_read")?
            .try_reason("case_read_denied")?
            .hidden(),
        &KnownFacts::new(),
    );

    let Some(reason) = decision.denial_reason()? else {
        return Err(TestError::Message(
            "denied grant should have reason metadata",
        ));
    };
    assert_eq!(reason.code.as_str(), "case_read_denied");
    assert_eq!(reason.shape, DenyShape::Hidden);
    assert!(
        reason
            .params
            .keys()
            .any(|key| key.as_str() == "missing_fact")
    );
    Ok(())
}

#[test]
fn all_denial_only_reports_the_failing_fact() -> Result<(), TestError> {
    let policy = policy::grant(
        ReadTier::Full,
        condition::all([
            condition::has::<RoleAccess>(),
            condition::has::<ResourceFull>(),
        ]),
    )
    .try_labeled("case_read")?;

    let decision = evaluate(&policy, &KnownFacts::new().with_present::<RoleAccess>());
    let Some(reason) = decision.denial_reason()? else {
        return Err(TestError::Message(
            "denied grant should have reason metadata",
        ));
    };

    let missing = reason
        .params
        .values()
        .filter_map(|value| match value {
            gatekeep::ReasonValue::Fact(fact) => Some(fact.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(missing, vec!["resource_full"]);
    Ok(())
}

#[test]
fn all_uses_meet_and_obligations_from_meet_arm() {
    let policy = policy::all([
        policy::grant(ReadTier::Full, condition::always()).with_obligation::<BreakGlass>(),
        policy::grant(ReadTier::Shared, condition::always()).with_obligation::<AuditOverride>(),
    ]);

    let decision = evaluate(&policy, &KnownFacts::new());

    assert_eq!(decision.effect, Effect::Permit(ReadTier::Shared));
    assert_eq!(decision.obligations.len(), 1);
    assert_eq!(decision.obligations[0].as_str(), "audit_override");
}

#[test]
fn any_supports_non_total_lattice_join() -> Result<(), TestError> {
    let policy = policy::any([
        policy::grant(Scope::Left, condition::always()),
        policy::grant(Scope::Right, condition::always()),
    ]);

    let decision = evaluate(&policy, &KnownFacts::new());

    assert_eq!(decision.effect, Effect::Permit(Scope::Both));
    match decision.trace.decisive {
        gatekeep::DecisiveClause::Permit { granted, .. } => {
            assert_eq!(granted, Scope::Both);
        }
        gatekeep::DecisiveClause::Deny { .. } => {
            return Err(TestError::Message("non-total join test should permit"));
        }
    }
    Ok(())
}

#[test]
fn all_synthesized_meet_trace_matches_effect() -> Result<(), TestError> {
    let policy = policy::all([
        policy::grant(Scope::Left, condition::always()),
        policy::grant(Scope::Right, condition::always()),
    ]);

    let decision = evaluate(&policy, &KnownFacts::new());

    assert_eq!(decision.effect, Effect::Permit(Scope::None));
    match decision.trace.decisive {
        gatekeep::DecisiveClause::Permit { granted, .. } => {
            assert_eq!(granted, Scope::None);
        }
        gatekeep::DecisiveClause::Deny { .. } => {
            return Err(TestError::Message("non-total meet test should permit"));
        }
    }
    Ok(())
}

#[test]
fn any_unions_obligations_for_arms_at_winning_grade() {
    let policy = policy::any([
        policy::grant(ReadTier::Full, condition::always()).with_obligation::<BreakGlass>(),
        policy::grant(ReadTier::Full, condition::always()).with_obligation::<AuditOverride>(),
        policy::grant(ReadTier::Shared, condition::always()),
    ]);

    let decision = evaluate(&policy, &KnownFacts::new());

    assert_eq!(decision.effect, Effect::Permit(ReadTier::Full));
    assert_eq!(decision.obligations.len(), 2);
    assert_eq!(decision.obligations[0].as_str(), "break_glass");
    assert_eq!(decision.obligations[1].as_str(), "audit_override");
}

#[test]
fn or_else_skips_fallback_when_primary_permits() {
    let policy = policy::or_else(
        policy::grant(ReadTier::Shared, condition::has::<RoleAccess>()),
        policy::grant(ReadTier::Full, condition::has::<ResourceFull>())
            .with_obligation::<BreakGlass>(),
    );
    let facts = KnownFacts::new().with_present::<RoleAccess>();

    let decision = evaluate(&policy, &facts);

    assert_eq!(decision.effect, Effect::Permit(ReadTier::Shared));
    assert!(decision.obligations.is_empty());
    assert_eq!(decision.trace.consulted.len(), 1);
    assert_eq!(decision.trace.consulted[0].0.as_str(), "role_access");
}

#[test]
fn partial_any_keeps_top_permit_pending_to_preserve_obligations() -> Result<(), TestError> {
    let policy = policy::any([
        policy::grant(ReadTier::Full, condition::has::<RoleAccess>())
            .with_obligation::<BreakGlass>(),
        policy::grant(ReadTier::Full, condition::has::<ResourceFull>())
            .with_obligation::<AuditOverride>(),
    ]);
    let partial = PartialFacts::new()
        .with_present::<RoleAccess>()
        .with_unknown::<ResourceFull>();
    let completed = KnownFacts::new()
        .with_present::<RoleAccess>()
        .with_present::<ResourceFull>();

    let reduced = partial_evaluate(&policy, &partial);
    let decision = match &reduced {
        Residual::Pending { .. } => complete_residual(&reduced, &completed),
        Residual::Resolved(_) => {
            return Err(TestError::Message(
                "top permit with pending top arm must remain pending",
            ));
        }
    };

    assert_eq!(decision.effect, Effect::Permit(ReadTier::Full));
    assert_eq!(decision.obligations.len(), 2);
    assert_eq!(decision.obligations[0].as_str(), "break_glass");
    assert_eq!(decision.obligations[1].as_str(), "audit_override");
    Ok(())
}

#[test]
fn partial_resolved_decision_keeps_consulted_facts_and_label() -> Result<(), TestError> {
    let policy = policy::any([
        policy::grant(ReadTier::Shared, condition::has::<RoleAccess>())
            .try_labeled("role_access")?,
        policy::grant(ReadTier::Released, condition::has::<ResourceShared>()),
    ]);
    let partial = PartialFacts::new()
        .with_present::<RoleAccess>()
        .with_absent::<ResourceShared>();

    let Residual::Resolved(decision) = partial_evaluate(&policy, &partial) else {
        return Err(TestError::Message("known facts should resolve policy"));
    };

    assert_eq!(decision.effect, Effect::Permit(ReadTier::Shared));
    assert_eq!(decision.trace.consulted.len(), 2);
    match decision.trace.decisive {
        gatekeep::DecisiveClause::Permit { label, .. } => {
            let Some(label) = label else {
                return Err(TestError::Message("permit trace should keep label"));
            };
            assert_eq!(label.as_str(), "role_access");
        }
        gatekeep::DecisiveClause::Deny { .. } => {
            return Err(TestError::Message("decision should permit"));
        }
    }
    Ok(())
}

#[test]
fn partial_any_all_deny_keeps_first_denial_label() -> Result<(), TestError> {
    let policy = policy::any([
        policy::grant(ReadTier::Full, condition::has::<RoleAccess>()).try_labeled("first")?,
        policy::grant(ReadTier::Full, condition::has::<ResourceFull>()).try_labeled("second")?,
    ]);
    let partial = PartialFacts::new()
        .with_absent::<RoleAccess>()
        .with_absent::<ResourceFull>();

    let Residual::Resolved(decision) = partial_evaluate(&policy, &partial) else {
        return Err(TestError::Message("all-deny partial any should resolve"));
    };

    match decision.trace.decisive {
        gatekeep::DecisiveClause::Deny { label, .. } => {
            let Some(label) = label else {
                return Err(TestError::Message("first denial label should be preserved"));
            };
            assert_eq!(label.as_str(), "first");
        }
        gatekeep::DecisiveClause::Permit { .. } => {
            return Err(TestError::Message("all-deny policy should deny"));
        }
    }
    Ok(())
}

#[test]
fn partial_any_pending_keeps_first_resolved_denial_metadata() -> Result<(), TestError> {
    let policy = policy::any([
        policy::grant(ReadTier::Full, condition::has::<RoleAccess>())
            .try_labeled("first")?
            .try_reason("first_denied")?
            .hidden(),
        policy::grant(ReadTier::Full, condition::has::<ResourceFull>()).try_labeled("second")?,
    ]);
    let partial = PartialFacts::new()
        .with_absent::<RoleAccess>()
        .with_unknown::<ResourceFull>();
    let completed = KnownFacts::new()
        .with_absent::<RoleAccess>()
        .with_absent::<ResourceFull>();

    let original = evaluate(&policy, &completed);
    let reduced = partial_evaluate(&policy, &partial);
    if !matches!(&reduced, Residual::Pending { .. }) {
        return Err(TestError::Message("unknown fact should keep any pending"));
    }
    let reduced = complete_residual(&reduced, &completed);

    assert_denial_metadata(&original, "first", Some("first_denied"), DenyShape::Hidden)?;
    assert_denial_metadata(&reduced, "first", Some("first_denied"), DenyShape::Hidden)?;
    assert_denial_fact_params(&original, &["role_access"])?;
    assert_denial_fact_params(&reduced, &["role_access"])?;
    Ok(())
}

#[test]
fn partial_or_else_pending_primary_keeps_fallback_denial_metadata() -> Result<(), TestError> {
    let policy = policy::or_else(
        policy::grant(ReadTier::Full, condition::has::<RoleAccess>()).try_labeled("primary")?,
        policy::grant(ReadTier::Shared, condition::has::<ResourceShared>())
            .try_labeled("fallback")?
            .try_reason("fallback_denied")?
            .hidden(),
    );
    let partial = PartialFacts::new()
        .with_unknown::<RoleAccess>()
        .with_absent::<ResourceShared>();
    let completed = KnownFacts::new()
        .with_absent::<RoleAccess>()
        .with_absent::<ResourceShared>();

    let original = evaluate(&policy, &completed);
    let reduced = partial_evaluate(&policy, &partial);
    if !matches!(&reduced, Residual::Pending { .. }) {
        return Err(TestError::Message(
            "unknown primary should keep or_else pending",
        ));
    }
    let reduced = complete_residual(&reduced, &completed);

    assert_denial_metadata(
        &original,
        "fallback",
        Some("fallback_denied"),
        DenyShape::Hidden,
    )?;
    assert_denial_metadata(
        &reduced,
        "fallback",
        Some("fallback_denied"),
        DenyShape::Hidden,
    )?;
    assert_denial_fact_params(&original, &["resource_shared"])?;
    assert_denial_fact_params(&reduced, &["resource_shared"])?;
    Ok(())
}

#[test]
fn complete_residual_merges_prior_and_residual_consulted_facts() {
    let policy = policy::all([
        policy::grant(ReadTier::Shared, condition::has::<RoleAccess>()),
        policy::grant(ReadTier::Full, condition::has::<ResourceFull>()),
    ]);
    let partial = PartialFacts::new()
        .with_present::<RoleAccess>()
        .with_unknown::<ResourceFull>();
    let completed = KnownFacts::new()
        .with_present::<RoleAccess>()
        .with_present::<ResourceFull>();
    let reduced = partial_evaluate(&policy, &partial);

    let decision = complete_residual(&reduced, &completed);
    let consulted = decision
        .trace
        .consulted
        .iter()
        .map(|(fact, _presence)| fact.as_str())
        .collect::<Vec<_>>();

    assert_eq!(consulted, vec!["role_access", "resource_full"]);
}

#[test]
fn required_facts_are_sorted_and_deduped() {
    let policy = policy::any([
        policy::grant(ReadTier::Full, condition::has::<ResourceFull>()),
        policy::grant(ReadTier::Shared, condition::has::<RoleAccess>()),
        policy::grant(ReadTier::Released, condition::has::<ResourceFull>()),
    ]);

    let facts = required_facts(&policy)
        .into_iter()
        .map(|fact| fact.as_str().to_owned())
        .collect::<Vec<_>>();

    assert_eq!(facts, vec!["resource_full", "role_access"]);
}

#[test]
fn policy_hash_changes_with_structure() -> Result<(), TestError> {
    let first = policy::grant(ReadTier::Full, condition::has::<RoleAccess>());
    let second = policy::grant(ReadTier::Full, condition::always());

    assert_ne!(first.hash()?, second.hash()?);
    Ok(())
}

#[test]
fn known_facts_reject_unknown_presence() -> Result<(), TestError> {
    let result = KnownFacts::from_entries([(FactId::new("resource_full")?, Presence::Unknown)]);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn known_facts_deserialization_rejects_unknown_presence() {
    let value = serde_json::json!({
        "role_access": ["Unknown", null]
    });

    let result = serde_json::from_value::<KnownFacts>(value);

    assert!(result.is_err());
}

proptest! {
    #[test]
    fn partial_evaluation_preserves_effect_and_obligations(
        role_present in any::<bool>(),
        shared_present in any::<bool>(),
        full_present in any::<bool>(),
    ) {
        let policy = list_policy().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let role_access = FactId::new("role_access")
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let resource_shared = FactId::new("resource_shared")
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let resource_full = FactId::new("resource_full")
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let partial = PartialFacts::new()
            .with_fact(
                role_access.clone(),
                if role_present { Presence::Present } else { Presence::Absent },
            )
            .with_unknown::<ResourceShared>()
            .with_unknown::<ResourceFull>();
        let completed = KnownFacts::from_entries([
            (
                role_access,
                if role_present { Presence::Present } else { Presence::Absent },
            ),
            (
                resource_shared,
                if shared_present { Presence::Present } else { Presence::Absent },
            ),
            (
                resource_full,
                if full_present { Presence::Present } else { Presence::Absent },
            ),
        ])
        .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let original = evaluate(&policy, &completed);
        let reduced = partial_evaluate(&policy, &partial);
        let residual = match reduced {
            Residual::Resolved(decision) => decision,
            Residual::Pending { .. } => complete_residual(&reduced, &completed),
        };

        prop_assert_eq!(residual.effect, original.effect);
        prop_assert_eq!(residual.obligations, original.obligations);
    }
}

fn list_policy() -> Result<Policy<ReadTier>, gatekeep::GatekeepError> {
    Ok(policy::or_else(
        policy::all([
            policy::grant(ReadTier::Full, condition::has::<RoleAccess>()),
            policy::any([
                policy::grant(ReadTier::Full, condition::has::<ResourceFull>()),
                policy::grant(ReadTier::Shared, condition::has::<ResourceShared>()),
            ]),
        ]),
        policy::grant(ReadTier::Full, condition::has::<ResourceFull>())
            .labeled(ClauseLabel::new("break_glass")?)
            .with_obligation::<BreakGlass>(),
    ))
}
