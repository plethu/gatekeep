//! Compile gate for repository-facing Rust examples.

#[cfg(doctest)]
#[doc = include_str!("../../../README.md")]
mod readme_doctests {}

#[cfg(doctest)]
#[doc = include_str!("../../../docs/quickstart.md")]
mod quickstart_doctests {}

#[cfg(doctest)]
#[doc = include_str!("../../../docs/reference/policy-combinators.md")]
mod policy_combinator_doctests {}

#[cfg(doctest)]
#[doc = include_str!("../../../docs/reference/reason-catalogs.md")]
mod reason_catalog_doctests {}

#[cfg(doctest)]
#[doc = include_str!("../../../docs/concepts/lattice-outcomes.md")]
mod lattice_outcome_doctests {}

#[cfg(doctest)]
#[doc = include_str!("../../../docs/concepts/facts-and-context.md")]
mod facts_context_doctests {}

#[cfg(doctest)]
#[doc = include_str!("../../../docs/concepts/authorization-model.md")]
mod authorization_model_doctests {}

#[cfg(doctest)]
#[doc = include_str!("../../../docs/concepts/decisions-and-audit.md")]
mod decision_audit_doctests {}
