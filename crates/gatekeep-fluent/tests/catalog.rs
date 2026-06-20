//! Fluent catalog integration tests.

use std::collections::BTreeMap;

use gatekeep::{DenialReason, DenyShape, FactId, Locale, ParamKey, ReasonCode, ReasonValue};
use gatekeep_fluent::{FluentCatalog, FluentCatalogError};
use thiserror::Error;

#[derive(Debug, Error)]
enum TestError {
    #[error(transparent)]
    Catalog(#[from] FluentCatalogError),
    #[error(transparent)]
    Gatekeep(#[from] gatekeep::GatekeepError),
}

fn reason(code: &str, params: BTreeMap<ParamKey, ReasonValue>) -> Result<DenialReason, TestError> {
    Ok(DenialReason {
        code: ReasonCode::new(code)?,
        params,
        shape: DenyShape::Forbidden,
    })
}

fn hidden_reason(code: &str) -> Result<DenialReason, TestError> {
    Ok(DenialReason {
        code: ReasonCode::new(code)?,
        params: BTreeMap::new(),
        shape: DenyShape::Hidden,
    })
}

#[test]
fn renders_reason_with_structured_params() -> Result<(), TestError> {
    let mut params = BTreeMap::new();
    params.insert(
        ParamKey::new("missing_fact")?,
        ReasonValue::Fact(FactId::new("case_owner")?),
    );
    params.insert(
        ParamKey::new("required_tier")?,
        ReasonValue::Str("full".to_owned()),
    );
    params.insert(ParamKey::new("count")?, ReasonValue::Int(2));

    let catalog = FluentCatalog::new().with_resource(
        "en-US",
        "case-read-denied = Missing { $missing_fact }; need { $required_tier }; count { $count }.",
    )?;
    let rendered =
        catalog.render_reason(&reason("case-read-denied", params)?, &Locale::new("en-US")?);

    assert_eq!(
        rendered,
        "Missing \u{2068}case_owner\u{2069}; need \u{2068}full\u{2069}; count \u{2068}2\u{2069}."
    );
    Ok(())
}

#[test]
fn falls_back_to_language_then_configured_locale_then_reason_code() -> Result<(), TestError> {
    let english = FluentCatalog::new()
        .with_fallback_locale("fr-FR")?
        .with_resource("en", "case-read-denied = English fallback")?
        .with_resource("fr-FR", "case-read-denied = French fallback")?;

    let specific = english.render_reason(
        &reason("case-read-denied", BTreeMap::new())?,
        &Locale::new("en-US")?,
    );
    let fallback = english.render_reason(
        &reason("case-read-denied", BTreeMap::new())?,
        &Locale::new("es-ES")?,
    );
    let code = english.render_reason(
        &reason("other-reason", BTreeMap::new())?,
        &Locale::new("es-ES")?,
    );

    assert_eq!(specific, "English fallback");
    assert_eq!(fallback, "French fallback");
    assert_eq!(code, "other-reason");
    Ok(())
}

#[test]
fn rejects_invalid_resources_and_duplicate_messages() -> Result<(), TestError> {
    let parse = FluentCatalog::new().with_resource("en-US", "bad = {");
    assert!(matches!(parse, Err(FluentCatalogError::Parse { .. })));

    let duplicate = FluentCatalog::new()
        .with_resource("en-US", "case-read-denied = One")?
        .with_resource("en-US", "case-read-denied = Two");
    assert!(matches!(
        duplicate,
        Err(FluentCatalogError::Resource { .. })
    ));
    Ok(())
}

#[test]
fn hidden_denials_render_only_generic_messages() -> Result<(), TestError> {
    let catalog = FluentCatalog::new()
        .with_hidden_message("generic-not-found", "missing")?
        .with_resource(
            "en-US",
            "case-read-denied = This exact case denial must stay hidden.
generic-not-found = Not found.",
        )?;

    let rendered =
        catalog.render_reason(&hidden_reason("case-read-denied")?, &Locale::new("en-US")?);
    let missing_catalog =
        FluentCatalog::new().with_resource("en-US", "case-read-denied = This must not render.")?;

    assert_eq!(rendered, "Not found.");
    assert_eq!(
        missing_catalog.render_reason(&hidden_reason("case-read-denied")?, &Locale::new("en-US")?),
        "not found"
    );
    assert_eq!(
        catalog.try_render_reason(&hidden_reason("case-read-denied")?, &Locale::new("en-US")?),
        Some("Not found.".to_owned())
    );
    Ok(())
}
