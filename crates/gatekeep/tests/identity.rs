//! Identity-boundary validation tests.

use gatekeep::{
    DecisionAuditId, DecisionAuditOccurrence, DecisionAuditOccurrenceError, GatekeepError,
    SubjectRef,
};

#[test]
fn generated_decision_audit_ids_are_valid_and_distinct() {
    let first = DecisionAuditId::generate();
    let second = DecisionAuditId::generate();

    assert!(!first.as_str().is_empty());
    assert_ne!(first, second);
    assert!(DecisionAuditId::new(first.as_str()).is_ok());
}

#[test]
fn decision_audit_ids_reject_only_the_reserved_legacy_prefix() -> Result<(), GatekeepError> {
    assert_eq!(
        DecisionAuditId::new("legacy-123"),
        Err(GatekeepError::ReservedIdentifierPrefix {
            field: "decision_audit_id",
            prefix: "legacy-",
        })
    );
    assert!(DecisionAuditId::new("Legacy-123").is_ok());
    assert!(DecisionAuditId::new("legacy").is_ok());
    assert!(DecisionAuditId::new("legacy--123").is_err());
    let legacy = DecisionAuditId::from_legacy_import("legacy-outbox-123")?;
    assert_eq!(
        DecisionAuditOccurrence::new(legacy, time::OffsetDateTime::UNIX_EPOCH),
        Err(DecisionAuditOccurrenceError::ReservedLegacyIdentity)
    );
    Ok(())
}

#[test]
fn decision_audit_id_deserialization_uses_reserved_prefix_validation() {
    let result = serde_json::from_str::<DecisionAuditId>(r#""legacy-import-123""#);
    assert!(result.is_err(), "reserved legacy identity must be rejected");
    if let Err(error) = result {
        assert!(
            error
                .to_string()
                .contains("decision_audit_id uses the reserved prefix")
        );
    }
}

#[test]
fn decision_occurrence_normalizes_utc_at_microsecond_precision()
-> Result<(), Box<dyn std::error::Error>> {
    let id = DecisionAuditId::new("decision-1")?;
    let at = time::OffsetDateTime::from_unix_timestamp_nanos(123_000)?
        .to_offset(time::UtcOffset::from_hms(2, 0, 0)?);

    let occurrence = DecisionAuditOccurrence::new(id, at)?;

    assert_eq!(
        occurrence.occurred_at,
        time::OffsetDateTime::UNIX_EPOCH + time::Duration::microseconds(123)
    );
    assert_eq!(occurrence.occurred_at.offset(), time::UtcOffset::UTC);
    Ok(())
}

#[test]
fn decision_occurrence_normalizes_submicroseconds_and_rejects_invalid_endpoints()
-> Result<(), Box<dyn std::error::Error>> {
    let id = DecisionAuditId::new("decision-1")?;
    let submicrosecond = time::OffsetDateTime::from_unix_timestamp_nanos(1)?;
    let normalized = DecisionAuditOccurrence::new(id.clone(), submicrosecond)?;
    assert_eq!(normalized.occurred_at, time::OffsetDateTime::UNIX_EPOCH);

    let before_epoch = time::OffsetDateTime::UNIX_EPOCH - time::Duration::nanoseconds(1_000);
    assert_eq!(
        DecisionAuditOccurrence::new(id.clone(), before_epoch),
        Err(DecisionAuditOccurrenceError::OutOfRange)
    );

    let after_max = time::OffsetDateTime::new_in_offset(
        time::Date::from_calendar_date(9999, time::Month::December, 31)?,
        time::Time::from_hms_micro(23, 59, 59, 999_999)?,
        time::UtcOffset::from_hms(-1, 0, 0)?,
    );
    assert_eq!(
        DecisionAuditOccurrence::new(id, after_max),
        Err(DecisionAuditOccurrenceError::OutOfRange)
    );
    Ok(())
}

#[test]
fn subject_ref_constructor_rejects_empty_parts() {
    assert_eq!(
        SubjectRef::new("", "alice"),
        Err(GatekeepError::EmptyIdentifier {
            field: "subject_kind"
        })
    );
    assert_eq!(
        SubjectRef::new("user", " "),
        Err(GatekeepError::EmptyIdentifier {
            field: "subject_id"
        })
    );
}

#[test]
fn subject_ref_deserialization_rejects_empty_parts() {
    let value = serde_json::json!({
        "kind": "user",
        "id": ""
    });

    let result = serde_json::from_value::<SubjectRef>(value);

    assert!(result.is_err());
}

#[test]
fn subject_ref_keeps_valid_parts() -> Result<(), GatekeepError> {
    let subject = SubjectRef::new("user", "alice")?;

    assert_eq!(subject.kind(), "user");
    assert_eq!(subject.id(), "alice");
    Ok(())
}
