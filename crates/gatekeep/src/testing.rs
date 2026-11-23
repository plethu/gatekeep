//! Scenario comparison, decisive-clause checks and finite lattice checks for
//! policy authors.
use crate::policy::{IntoLabel, IntoReasonCode};
use crate::{
    ClauseLabel, Decision, DecisiveClause, DenyShape, Effect, GatekeepResult, KnownFacts, Lattice,
    Policy, ReasonCode, evaluate,
};
use std::error::Error;
use std::fmt;

/// What changed for one supplied scenario. This is not a proof of equivalence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioComparison<O> {
    /// Previous decision.
    pub before: Decision<O>,
    /// Proposed decision.
    pub after: Decision<O>,
}

impl<O: PartialEq> ScenarioComparison<O> {
    /// Whether permission, outcome, obligations or disclosure shape changed.
    #[must_use]
    pub fn authority_changed(&self) -> bool {
        self.before.effect != self.after.effect
            || self.before.obligations != self.after.obligations
            || shape(&self.before) != shape(&self.after)
    }

    /// Whether the recorded explanation changed, independently of authority.
    #[must_use]
    pub fn explanation_changed(&self) -> bool {
        self.before.trace != self.after.trace
    }
}

const fn shape<O>(decision: &Decision<O>) -> Option<DenyShape> {
    match decision.trace.decisive {
        DecisiveClause::Deny { shape, .. } => Some(shape),
        DecisiveClause::Permit { .. } => None,
    }
}

/// Compares two policy revisions on explicit synthetic observations.
#[must_use]
pub fn compare_scenario<O: Lattice>(
    before: &Policy<O>,
    after: &Policy<O>,
    facts: &KnownFacts,
) -> ScenarioComparison<O> {
    ScenarioComparison {
        before: evaluate(before, facts),
        after: evaluate(after, facts),
    }
}

/// The clause that fixed a decision: its effect, label and reason code.
///
/// Use it to pin which layer of a composed policy decides a scenario, so a
/// refactor that reorders or flattens layers fails a test instead of silently
/// changing the explanation. Permits carry no reason code. A permit whose
/// outcome was produced by combining several clauses, rather than taken from
/// one of them, has no label.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Decider<O> {
    /// Permit or deny effect, including the permitted outcome.
    pub effect: Effect<O>,
    /// Label of the deciding clause, when it has one.
    pub label: Option<ClauseLabel>,
    /// Reason code of the deciding denial, when it has one.
    pub reason: Option<ReasonCode>,
}

impl<O> Decider<O> {
    /// Expects an unlabeled permit with `outcome`.
    #[must_use]
    pub const fn permit(outcome: O) -> Self {
        Self {
            effect: Effect::Permit(outcome),
            label: None,
            reason: None,
        }
    }

    /// Expects an unlabeled denial without a reason code.
    #[must_use]
    pub const fn deny() -> Self {
        Self {
            effect: Effect::Deny,
            label: None,
            reason: None,
        }
    }

    /// Expects the deciding clause to carry `label`.
    #[must_use]
    pub fn labeled(mut self, label: impl IntoLabel) -> Self {
        self.label = Some(label.into_label());
        self
    }

    /// Expects the deciding clause to carry a validated `label`.
    ///
    /// # Errors
    ///
    /// Returns an identifier error when `label` is empty or whitespace.
    pub fn try_labeled(self, label: impl Into<String>) -> GatekeepResult<Self> {
        Ok(self.labeled(ClauseLabel::new(label)?))
    }

    /// Expects the deciding denial to carry `reason`.
    #[must_use]
    pub fn reason(mut self, reason: impl IntoReasonCode) -> Self {
        self.reason = Some(reason.into_reason_code());
        self
    }

    /// Expects the deciding denial to carry a validated `reason`.
    ///
    /// # Errors
    ///
    /// Returns an identifier error when `reason` is empty or whitespace.
    pub fn try_reason(self, reason: impl Into<String>) -> GatekeepResult<Self> {
        Ok(self.reason(ReasonCode::new(reason)?))
    }
}

impl<O: Clone> Decider<O> {
    /// Reads the deciding clause from an evaluated decision.
    #[must_use]
    pub fn of(decision: &Decision<O>) -> Self {
        let (label, reason) = match &decision.trace.decisive {
            DecisiveClause::Permit { label, .. } => (label.clone(), None),
            DecisiveClause::Deny { label, reason, .. } => (label.clone(), reason.clone()),
        };
        Self {
            effect: decision.effect.clone(),
            label,
            reason,
        }
    }
}

/// One scenario whose decision came from an unexpected clause.
///
/// Labels and reason codes are stable identifiers and are reported. Outcomes
/// are not copied into the failure; evaluate the scenario directly to inspect
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeciderMismatch {
    /// Scenario name supplied by the caller.
    pub scenario: String,
    /// Whether the effect or permitted outcome differed.
    pub effect_differs: bool,
    /// Expected label of the deciding clause.
    pub expected_label: Option<ClauseLabel>,
    /// Label of the clause that actually decided.
    pub actual_label: Option<ClauseLabel>,
    /// Expected reason code of the deciding denial.
    pub expected_reason: Option<ReasonCode>,
    /// Reason code of the denial that actually decided.
    pub actual_reason: Option<ReasonCode>,
}

impl fmt::Display for DeciderMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.scenario)?;
        if self.effect_differs {
            f.write_str(" effect differs;")?;
        }
        if self.expected_label != self.actual_label {
            write!(
                f,
                " label expected {}, got {};",
                Shown(self.expected_label.as_ref()),
                Shown(self.actual_label.as_ref())
            )?;
        }
        if self.expected_reason != self.actual_reason {
            write!(
                f,
                " reason expected {}, got {};",
                Shown(self.expected_reason.as_ref()),
                Shown(self.actual_reason.as_ref())
            )?;
        }
        Ok(())
    }
}

struct Shown<'a, T>(Option<&'a T>);

impl<T: fmt::Display> fmt::Display for Shown<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(value) => write!(f, "`{value}`"),
            None => f.write_str("none"),
        }
    }
}

/// Every scenario that [`check_deciders`] found decided by an unexpected clause.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeciderMismatches {
    /// Mismatched scenarios in input order.
    pub mismatches: Vec<DeciderMismatch>,
}

impl fmt::Display for DeciderMismatches {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unexpected deciding clause")?;
        for mismatch in &self.mismatches {
            write!(f, "\n  {mismatch}")?;
        }
        Ok(())
    }
}

impl Error for DeciderMismatches {}

/// Evaluates named synthetic scenarios and checks which clause decides each.
///
/// Each scenario's effect, permitted outcome, deciding label and reason code
/// must equal the expected [`Decider`] exactly. Every scenario is evaluated;
/// all mismatches are reported together. Like [`compare_scenario`], this covers
/// only the supplied scenarios.
///
/// ```
/// # use gatekeep::{condition, policy, Fact, KnownFacts, StaticFactId};
/// use gatekeep::testing::{check_deciders, Decider};
/// # struct Owner;
/// # impl Fact for Owner { const ID: StaticFactId = StaticFactId::new("owner"); }
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let policy = policy::grant_clause((), condition::has::<Owner>())
///     .try_labeled("owner")?
///     .try_reason("not_owner")?
///     .into_policy();
///
/// check_deciders(&policy, [
///     ("owner", KnownFacts::new().with_bool::<Owner>(true),
///      Decider::permit(()).try_labeled("owner")?),
///     ("stranger", KnownFacts::new().with_bool::<Owner>(false),
///      Decider::deny().try_labeled("owner")?.try_reason("not_owner")?),
/// ])?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns every scenario whose deciding clause differs from its expectation.
pub fn check_deciders<O, S>(
    policy: &Policy<O>,
    scenarios: impl IntoIterator<Item = (S, KnownFacts, Decider<O>)>,
) -> Result<(), DeciderMismatches>
where
    O: Lattice,
    S: Into<String>,
{
    let mismatches = scenarios
        .into_iter()
        .filter_map(|(scenario, facts, expected)| {
            let actual = Decider::of(&evaluate(policy, &facts));
            (actual != expected).then(|| DeciderMismatch {
                scenario: scenario.into(),
                effect_differs: actual.effect != expected.effect,
                expected_label: expected.label,
                actual_label: actual.label,
                expected_reason: expected.reason,
                actual_reason: actual.reason,
            })
        })
        .collect::<Vec<_>>();
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(DeciderMismatches { mismatches })
    }
}

/// A law failed for supplied outcomes. Values are intentionally not dumped.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("outcome lattice violates {law}")]
pub struct LatticeLawFailure {
    /// Name of the failed law.
    pub law: &'static str,
}

/// Exhaustively checks laws over a caller-supplied finite outcome set.
///
/// Supply every outcome to establish the finite contract. A sample only checks
/// those samples and is not a proof for an infinite or incompletely listed type.
///
/// # Errors
/// Reports missing bounds, closure, idempotence, identity, absorption,
/// commutativity or associativity violations.
pub fn check_lattice<O: Lattice>(values: &[O]) -> Result<(), LatticeLawFailure> {
    ensure(
        values.contains(&O::top()) && values.contains(&O::bottom()),
        "listed bounds",
    )?;
    for left in values {
        ensure(
            left.meet(left) == *left && left.join(left) == *left,
            "idempotence",
        )?;
        ensure(
            left.meet(&O::top()) == *left && left.join(&O::bottom()) == *left,
            "identity",
        )?;
        for right in values {
            check_pair(values, left, right)?;
        }
    }

    Ok(())
}

fn check_pair<O: Lattice>(values: &[O], left: &O, right: &O) -> Result<(), LatticeLawFailure> {
    ensure(
        values.contains(&left.meet(right)) && values.contains(&left.join(right)),
        "closure",
    )?;
    ensure(
        left.meet(right) == right.meet(left) && left.join(right) == right.join(left),
        "commutativity",
    )?;
    ensure(
        left.meet(&left.join(right)) == *left && left.join(&left.meet(right)) == *left,
        "absorption",
    )?;
    for third in values {
        ensure(
            left.meet(&right.meet(third)) == left.meet(right).meet(third)
                && left.join(&right.join(third)) == left.join(right).join(third),
            "associativity",
        )?;
    }

    Ok(())
}

const fn ensure(condition: bool, law: &'static str) -> Result<(), LatticeLawFailure> {
    if condition {
        Ok(())
    } else {
        Err(LatticeLawFailure { law })
    }
}
