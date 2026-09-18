use serde::Serialize;

use crate::{FactId, Policy, PolicyAnchor, PolicyId, required_facts};

/// Immutable policy with its versioned identity and required facts computed once.
///
/// Preparation does not execute application checks or cache their results.
#[derive(Clone, Debug)]
pub struct PreparedPolicy<O> {
    policy: Policy<O>,
    anchor: PolicyAnchor,
    required: Vec<FactId>,
}

impl<O: Serialize> PreparedPolicy<O> {
    /// Prepares a policy for repeated evaluation.
    ///
    /// # Errors
    /// Returns a serialization error if the outcome cannot be hashed.
    pub fn new(id: PolicyId, policy: Policy<O>) -> Result<Self, postcard::Error> {
        let anchor = PolicyAnchor::new(id, policy.hash()?);
        let required = required_facts(&policy).into_iter().collect();
        Ok(Self {
            policy,
            anchor,
            required,
        })
    }
}

impl<O> PreparedPolicy<O> {
    /// Borrows the original policy; its semantics and hash format are unchanged.
    #[must_use]
    pub const fn policy(&self) -> &Policy<O> {
        &self.policy
    }

    /// Borrows the prepared policy identity.
    #[must_use]
    pub const fn anchor(&self) -> &PolicyAnchor {
        &self.anchor
    }

    /// Borrows required identities in deterministic order.
    #[must_use]
    pub fn required_facts(&self) -> &[FactId] {
        &self.required
    }
}
