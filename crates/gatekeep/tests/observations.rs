//! Selected evidence and historical schema contracts.
use gatekeep::{
    FactId, FactObservation, FactResolution, FactResolutionEvidence, KnownFacts, ObservationError,
    Presence,
};
use std::error::Error;
use time::OffsetDateTime;

#[test]
fn negative_observations_are_retained_and_conflicts_rejected() -> Result<(), Box<dyn Error>> {
    let now = OffsetDateTime::now_utc();
    let fact = FactId::new("record.owner")?;
    let facts = KnownFacts::from_entries([(fact.clone(), Presence::Absent)])?;
    let resolution = FactResolution::new(facts, None, now)?;
    let positive = FactObservation::new(fact.clone(), true, None, now)?;
    assert_eq!(
        resolution.clone().with_observations(vec![positive]),
        Err(ObservationError::Mismatch)
    );
    let negative = FactObservation::new(fact, false, None, now)?;
    assert_eq!(
        resolution
            .clone()
            .with_observations(vec![negative.clone(), negative.clone()]),
        Err(ObservationError::Duplicate)
    );
    let resolution = resolution.with_observations(vec![negative.clone()])?;
    let evidence = FactResolutionEvidence::from_resolution(&resolution)?;
    assert_eq!(evidence.observations(), &[negative]);
    assert_eq!(
        serde_json::from_str::<FactResolutionEvidence>(&serde_json::to_string(&evidence)?)?,
        evidence
    );
    Ok(())
}

#[test]
fn deserialized_conflicting_evidence_cannot_cross_decision_boundary() -> Result<(), Box<dyn Error>>
{
    let now = OffsetDateTime::now_utc();
    let fact = FactId::new("owner")?;
    let resolution = FactResolution::new(
        KnownFacts::from_entries([(fact.clone(), Presence::Absent)])?,
        None,
        now,
    )?
    .with_observations(vec![FactObservation::new(fact, false, None, now)?])?;
    let mut wire = serde_json::to_value(resolution)?;
    wire["observations"][0]["value"] = true.into();
    assert!(serde_json::from_value::<FactResolution<KnownFacts>>(wire).is_err());
    Ok(())
}

#[test]
fn selected_fact_expiry_is_enforced_even_without_set_expiry() -> Result<(), Box<dyn Error>> {
    let now = OffsetDateTime::now_utc();
    let fact = FactId::new("emergency")?;
    let metadata = gatekeep::FactResolutionMetadata::new(
        gatekeep::BindingProvenance::new("grants")?,
        None,
        Some(now),
    );
    let observation = FactObservation::new(fact.clone(), true, Some(metadata), now)?;
    let resolution = FactResolution::new(
        KnownFacts::from_entries([(fact, Presence::Present)])?,
        None,
        now,
    )?
    .with_observations(vec![observation])?;
    assert!(matches!(
        resolution.validate_at(now),
        Err(gatekeep::FactResolutionError::Expired { .. })
    ));
    Ok(())
}
