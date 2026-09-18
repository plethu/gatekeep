//! Authoring diagnostics distinguish authority, explanations and retained evidence.
#[cfg(feature = "test")]
use gatekeep::testing::{check_lattice, compare_scenario};
use gatekeep::{
    Authorizer, Context, Fact, FactId, FactObservation, FactResolution, KnownFacts, Locale,
    PolicyId, PreparedPolicy, ReplayError, StaticFactId, SubjectRef, TenantId,
    TrustedServiceBinding, condition, policy,
};
use std::error::Error;
use time::OffsetDateTime;

struct Owner;
impl Fact for Owner {
    const ID: StaticFactId = StaticFactId::new("owner");
}

#[test]
fn replay_requires_matching_policy_and_explicit_observations() -> Result<(), Box<dyn Error>> {
    let now = OffsetDateTime::now_utc();
    let context = Context::from_trusted_service(
        TrustedServiceBinding::new(TenantId::new("one")?, "test")?,
        SubjectRef::new("person", "alex")?,
        Locale::new("en")?,
    )?;
    let prepared = PreparedPolicy::new(
        PolicyId::new("read")?,
        policy::grant_clause((), condition::has::<Owner>()).into_policy(),
    )?;
    let authorizer = Authorizer::unaudited(()).with_clock(move || now);
    let resolution = FactResolution::new(KnownFacts::new().with_bool::<Owner>(false), None, now)?;
    let incomplete = authorizer.prepare_resolution(&prepared, &context, &resolution)?;
    assert_eq!(
        prepared.replay(incomplete.entry()),
        Err(ReplayError::MissingObservations(vec![FactId::new(
            "owner"
        )?]))
    );
    let complete = resolution.with_observations(vec![FactObservation::new(
        FactId::new("owner")?,
        false,
        None,
        now,
    )?])?;
    let pending = authorizer.prepare_resolution(&prepared, &context, &complete)?;
    assert_eq!(&prepared.replay(pending.entry())?, pending.decision());
    let different = PreparedPolicy::new(PolicyId::new("read")?, policy::permit(()))?;
    assert_eq!(
        different.replay(pending.entry()),
        Err(ReplayError::PolicyMismatch)
    );
    Ok(())
}

#[cfg(feature = "test")]
#[test]
fn comparison_distinguishes_relabeling_from_broader_authority() -> Result<(), Box<dyn Error>> {
    let original = policy::grant_clause((), condition::has::<Owner>())
        .try_labeled("owner")?
        .into_policy();
    let relabeled = policy::grant_clause((), condition::has::<Owner>())
        .try_labeled("ownership")?
        .into_policy();
    let present = KnownFacts::new().with_bool::<Owner>(true);
    let labels = compare_scenario(&original, &relabeled, &present);
    assert!(!labels.authority_changed());
    assert!(labels.explanation_changed());
    let absent = KnownFacts::new().with_bool::<Owner>(false);
    let broadened = compare_scenario(&original, &policy::permit(()), &absent);
    assert!(broadened.authority_changed());
    Ok(())
}

#[cfg(feature = "test")]
#[test]
fn finite_lattice_checks_reject_incomplete_domains() {
    assert!(check_lattice(&[()]).is_ok());
    assert_eq!(
        check_lattice::<()>(&[]).map_err(|error| error.law),
        Err("listed bounds")
    );
}
