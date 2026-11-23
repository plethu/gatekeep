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

// Declared broadest first so a derived `Ord` would disagree with the listed order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Access {
    Full,
    Edit,
    Read,
    None,
}

gatekeep::ordered_lattice!(Access: None < Read < Edit < Full);

#[test]
fn ordered_lattice_uses_the_listed_order() {
    use gatekeep::Lattice;
    assert_eq!(Access::bottom(), Access::None);
    assert_eq!(Access::top(), Access::Full);
    assert_eq!(Access::Edit.meet(&Access::Read), Access::Read);
    assert_eq!(Access::Read.meet(&Access::Edit), Access::Read);
    assert_eq!(Access::Edit.join(&Access::Read), Access::Edit);
    assert_eq!(Access::Full.meet(&Access::Full), Access::Full);
}

#[cfg(feature = "test")]
#[test]
fn ordered_lattice_satisfies_finite_laws() {
    assert_eq!(
        check_lattice(&[Access::None, Access::Read, Access::Edit, Access::Full]),
        Ok(())
    );
}

#[cfg(feature = "test")]
mod layered {
    use super::Access;
    use gatekeep::testing::{Decider, check_deciders};
    use gatekeep::{Fact, KnownFacts, Policy, ReasonCode, StaticFactId, condition, policy};
    use std::error::Error;

    macro_rules! facts {
        ($($name:ident),* $(,)?) => {
            $(
                struct $name;
                impl Fact for $name {
                    const ID: StaticFactId = StaticFactId::new(stringify!($name));
                }
            )*
        };
    }
    facts!(
        DevTools, FeatureOn, Suspended, Admin, Editor, Member, ProPlan
    );

    fn layered() -> Result<Policy<Access>, Box<dyn Error>> {
        Ok(policy::or_else(
            policy::grant_clause(Access::Full, condition::has::<DevTools>())
                .try_labeled("dev_tools")?
                .into_policy(),
            policy::all([
                policy::deny_when(
                    condition::not(condition::has::<FeatureOn>()),
                    ReasonCode::new("feature_disabled")?,
                ),
                policy::deny_when(
                    condition::all([
                        condition::has::<Suspended>(),
                        condition::not(condition::has::<Admin>()),
                    ]),
                    ReasonCode::new("account_restricted")?,
                ),
                policy::any([
                    policy::grant_clause(Access::Full, condition::has::<Admin>())
                        .try_labeled("role.admin")?
                        .into_policy(),
                    policy::grant_clause(Access::Edit, condition::has::<Editor>())
                        .try_labeled("role.editor")?
                        .into_policy(),
                    policy::grant_clause(Access::Read, condition::has::<Member>())
                        .try_labeled("role.member")?
                        .try_reason("no_role")?
                        .into_policy(),
                ]),
                policy::any([
                    policy::grant_clause(Access::Edit, condition::has::<ProPlan>())
                        .try_labeled("tier.pro")?
                        .into_policy(),
                    policy::grant_clause(Access::Read, condition::always())
                        .try_labeled("tier.free")?
                        .into_policy(),
                ]),
            ]),
        ))
    }

    fn base() -> KnownFacts {
        KnownFacts::new()
            .with_bool::<DevTools>(false)
            .with_bool::<FeatureOn>(true)
            .with_bool::<Suspended>(false)
            .with_bool::<Admin>(false)
            .with_bool::<Editor>(false)
            .with_bool::<Member>(false)
            .with_bool::<ProPlan>(false)
    }

    #[test]
    fn each_layer_decides_its_scenarios() -> Result<(), Box<dyn Error>> {
        let policy = layered()?;
        check_deciders(
            &policy,
            [
                (
                    "dev tools bypass a disabled feature",
                    base()
                        .with_bool::<DevTools>(true)
                        .with_bool::<FeatureOn>(false),
                    Decider::permit(Access::Full).try_labeled("dev_tools")?,
                ),
                (
                    "feature flag gates admins",
                    base()
                        .with_bool::<FeatureOn>(false)
                        .with_bool::<Admin>(true),
                    Decider::deny().try_reason("feature_disabled")?,
                ),
                (
                    "restriction vetoes an editor",
                    base()
                        .with_bool::<Suspended>(true)
                        .with_bool::<Editor>(true),
                    Decider::deny().try_reason("account_restricted")?,
                ),
                (
                    "admin is exempt from the restriction but capped by tier",
                    base().with_bool::<Suspended>(true).with_bool::<Admin>(true),
                    Decider::permit(Access::Read).try_labeled("tier.free")?,
                ),
                (
                    "pro tier caps an admin at edit",
                    base().with_bool::<Admin>(true).with_bool::<ProPlan>(true),
                    Decider::permit(Access::Edit).try_labeled("tier.pro")?,
                ),
                (
                    "role binds below the tier ceiling",
                    base().with_bool::<Member>(true).with_bool::<ProPlan>(true),
                    Decider::permit(Access::Read).try_labeled("role.member")?,
                ),
                (
                    "no role denies with the first failed role",
                    base(),
                    Decider::deny().try_labeled("role.admin")?,
                ),
            ],
        )?;
        Ok(())
    }

    #[test]
    fn mismatches_name_every_failed_scenario() -> Result<(), Box<dyn Error>> {
        let policy = layered()?;
        let Err(error) = check_deciders(
            &policy,
            [
                (
                    "matches",
                    base().with_bool::<DevTools>(true),
                    Decider::permit(Access::Full).try_labeled("dev_tools")?,
                ),
                (
                    "wrong layer",
                    base().with_bool::<Admin>(true).with_bool::<ProPlan>(true),
                    Decider::permit(Access::Edit).try_labeled("role.admin")?,
                ),
                (
                    "wrong effect",
                    base().with_bool::<FeatureOn>(false),
                    Decider::permit(Access::Read).try_reason("feature_disabled")?,
                ),
            ],
        ) else {
            return Err("expected mismatches".into());
        };
        let names = error
            .mismatches
            .iter()
            .map(|mismatch| mismatch.scenario.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["wrong layer", "wrong effect"]);
        let wrong_layer = error.mismatches.first().ok_or("missing mismatch")?;
        assert!(!wrong_layer.effect_differs);
        assert_eq!(
            wrong_layer.actual_label.as_ref().map(ToString::to_string),
            Some("tier.pro".to_owned())
        );
        assert_eq!(
            error.to_string(),
            "unexpected deciding clause\n  \
             wrong layer: label expected `role.admin`, got `tier.pro`;\n  \
             wrong effect: effect differs;"
        );
        Ok(())
    }
}
