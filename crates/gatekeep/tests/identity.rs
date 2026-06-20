//! Identity-boundary validation tests.

use gatekeep::{GatekeepError, SubjectRef};

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
