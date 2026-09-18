//! Scenario comparison and finite lattice checks for policy authors.
use crate::{Decision, DecisiveClause, DenyShape, KnownFacts, Lattice, Policy, evaluate};

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
