//! Fluent-backed reason catalog for gatekeep denial reasons.
//!
//! ```
//! use gatekeep::{DenialReason, DenyShape, Locale, ReasonCatalog, ReasonCode};
//! use gatekeep_fluent::FluentCatalog;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let catalog = FluentCatalog::new()
//!     .with_resource("en-US", "case-read-denied = You cannot read this case.")?;
//! let reason = DenialReason {
//!     code: ReasonCode::new("case-read-denied")?,
//!     params: Default::default(),
//!     shape: DenyShape::Forbidden,
//! };
//!
//! assert_eq!(
//!     catalog.render(&reason, &Locale::new("en-US")?),
//!     "You cannot read this case."
//! );
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeMap;

use fluent_bundle::{
    FluentArgs, FluentError, FluentResource, FluentValue, concurrent::FluentBundle,
};
use gatekeep::{DenialReason, DenyShape, Locale, ReasonCatalog, ReasonValue};
use thiserror::Error;
use unic_langid::{LanguageIdentifier, LanguageIdentifierError};

const DEFAULT_HIDDEN_MESSAGE: &str = "not found";
const DEFAULT_HIDDEN_MESSAGE_ID: &str = "not-found";

/// Fluent catalog keyed by gatekeep reason codes.
pub struct FluentCatalog {
    bundles: BTreeMap<String, FluentBundle<FluentResource>>,
    fallback_locale: Option<String>,
    hidden_message_id: String,
    hidden_fallback: String,
}

impl Default for FluentCatalog {
    fn default() -> Self {
        Self::new()
    }
}

impl FluentCatalog {
    /// Creates an empty catalog.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bundles: BTreeMap::new(),
            fallback_locale: None,
            hidden_message_id: DEFAULT_HIDDEN_MESSAGE_ID.to_owned(),
            hidden_fallback: DEFAULT_HIDDEN_MESSAGE.to_owned(),
        }
    }

    /// Sets the locale to try after the requested locale cannot render.
    ///
    /// # Errors
    ///
    /// Returns [`FluentCatalogError::InvalidLocale`] when `locale` is not a
    /// well-formed Unicode language identifier.
    pub fn set_fallback_locale(
        &mut self,
        locale: impl AsRef<str>,
    ) -> Result<(), FluentCatalogError> {
        let locale = parse_locale(locale.as_ref())?;
        self.fallback_locale = Some(locale.to_string());
        Ok(())
    }

    /// Returns this catalog with a fallback locale configured.
    ///
    /// # Errors
    ///
    /// Returns [`FluentCatalogError::InvalidLocale`] when `locale` is not a
    /// well-formed Unicode language identifier.
    pub fn with_fallback_locale(
        mut self,
        locale: impl AsRef<str>,
    ) -> Result<Self, FluentCatalogError> {
        self.set_fallback_locale(locale)?;
        Ok(self)
    }

    /// Sets the generic message used for hidden denials.
    ///
    /// Hidden denials must not render their specific reason code because that
    /// can disclose the protected resource's existence. The catalog looks up
    /// `message_id` in the requested locale and then the fallback locale; if no
    /// message exists, it returns `fallback`.
    ///
    /// # Errors
    ///
    /// Returns [`FluentCatalogError::EmptyMessageId`] when `message_id` is blank
    /// or [`FluentCatalogError::EmptyFallbackMessage`] when `fallback` is blank.
    pub fn set_hidden_message(
        &mut self,
        message_id: impl Into<String>,
        fallback: impl Into<String>,
    ) -> Result<(), FluentCatalogError> {
        self.hidden_message_id = validate_message_id(message_id.into())?;
        self.hidden_fallback = validate_hidden_fallback(fallback.into())?;
        Ok(())
    }

    /// Returns this catalog with a generic hidden-denial message configured.
    ///
    /// # Errors
    ///
    /// Returns [`FluentCatalogError::EmptyMessageId`] when `message_id` is blank
    /// or [`FluentCatalogError::EmptyFallbackMessage`] when `fallback` is blank.
    pub fn with_hidden_message(
        mut self,
        message_id: impl Into<String>,
        fallback: impl Into<String>,
    ) -> Result<Self, FluentCatalogError> {
        self.set_hidden_message(message_id, fallback)?;
        Ok(self)
    }

    /// Adds an FTL resource to the bundle for `locale`.
    ///
    /// Multiple resources may be added to one locale. Fluent duplicate-message
    /// errors are reported instead of overriding an earlier message.
    ///
    /// # Errors
    ///
    /// Returns [`FluentCatalogError`] when the locale is invalid, the FTL source
    /// has parse errors, or Fluent rejects the resource for that locale.
    pub fn add_resource(
        &mut self,
        locale: impl AsRef<str>,
        source: impl Into<String>,
    ) -> Result<(), FluentCatalogError> {
        let locale = parse_locale(locale.as_ref())?;
        let locale_key = locale.to_string();
        let resource = parse_resource(&locale_key, source.into())?;
        let bundle = self
            .bundles
            .entry(locale_key.clone())
            .or_insert_with(|| FluentBundle::new_concurrent(vec![locale]));
        bundle
            .add_resource(resource)
            .map_err(|errors| FluentCatalogError::Resource {
                locale: locale_key,
                errors: display_errors(errors),
            })
    }

    /// Returns this catalog with an FTL resource added.
    ///
    /// # Errors
    ///
    /// Returns [`FluentCatalogError`] when the resource cannot be added.
    pub fn with_resource(
        mut self,
        locale: impl AsRef<str>,
        source: impl Into<String>,
    ) -> Result<Self, FluentCatalogError> {
        self.add_resource(locale, source)?;
        Ok(self)
    }

    /// Renders `reason`, falling back to the stable reason code for forbidden
    /// denials or to the generic hidden message for hidden denials.
    #[must_use]
    pub fn render_reason(&self, reason: &DenialReason, locale: &Locale) -> String {
        if reason.shape == DenyShape::Hidden {
            return self.render_hidden(locale);
        }
        self.try_render_reason(reason, locale)
            .unwrap_or_else(|| reason.code.as_str().to_owned())
    }

    /// Renders `reason` only when a matching Fluent message exists and resolves
    /// without runtime formatting errors.
    ///
    /// Hidden denials use the configured generic hidden message id instead of
    /// `reason.code`.
    #[must_use]
    pub fn try_render_reason(&self, reason: &DenialReason, locale: &Locale) -> Option<String> {
        if reason.shape == DenyShape::Hidden {
            return self.try_render_hidden(locale);
        }
        for locale_key in self.locale_candidates(locale) {
            if let Some(rendered) = self.render_from_bundle(reason, &locale_key) {
                return Some(rendered);
            }
        }
        None
    }

    fn render_hidden(&self, locale: &Locale) -> String {
        self.try_render_hidden(locale)
            .unwrap_or_else(|| self.hidden_fallback.clone())
    }

    fn try_render_hidden(&self, locale: &Locale) -> Option<String> {
        for locale_key in self.locale_candidates(locale) {
            if let Some(rendered) = self.render_message(&self.hidden_message_id, None, &locale_key)
            {
                return Some(rendered);
            }
        }
        None
    }

    fn locale_candidates(&self, locale: &Locale) -> Vec<String> {
        let mut candidates = Vec::new();
        push_locale_candidate(&mut candidates, locale.as_str());
        if let Some((language, _rest)) = locale.as_str().split_once('-') {
            push_locale_candidate(&mut candidates, language);
        }
        if let Some(fallback_locale) = &self.fallback_locale {
            push_locale_candidate(&mut candidates, fallback_locale);
            if let Some((language, _rest)) = fallback_locale.split_once('-') {
                push_locale_candidate(&mut candidates, language);
            }
        }
        candidates
    }

    fn render_from_bundle(&self, reason: &DenialReason, locale_key: &str) -> Option<String> {
        let args = fluent_args(reason);
        self.render_message(reason.code.as_str(), Some(&args), locale_key)
    }

    fn render_message(
        &self,
        message_id: &str,
        args: Option<&FluentArgs<'_>>,
        locale_key: &str,
    ) -> Option<String> {
        let bundle = self.bundles.get(locale_key)?;
        let message = bundle.get_message(message_id)?;
        let pattern = message.value()?;
        let mut errors = Vec::new();
        let rendered = bundle.format_pattern(pattern, args, &mut errors);
        errors.is_empty().then(|| rendered.into_owned())
    }
}

impl ReasonCatalog for FluentCatalog {
    fn render(&self, reason: &DenialReason, locale: &Locale) -> String {
        self.render_reason(reason, locale)
    }
}

/// Errors returned while building a [`FluentCatalog`].
#[derive(Debug, Error, PartialEq)]
pub enum FluentCatalogError {
    /// The locale could not be parsed by `unic-langid`.
    #[error("invalid fluent locale {locale}: {source}")]
    InvalidLocale {
        /// Rejected locale string.
        locale: String,
        /// Parser error returned by `unic-langid`.
        source: LanguageIdentifierError,
    },
    /// FTL source could not be parsed.
    #[error("failed to parse fluent resource for {locale}: {}", errors.join("; "))]
    Parse {
        /// Locale the resource was intended for.
        locale: String,
        /// Parse errors reported by Fluent.
        errors: Vec<String>,
    },
    /// Fluent rejected the parsed resource.
    #[error("failed to add fluent resource for {locale}: {}", errors.join("; "))]
    Resource {
        /// Locale the resource was intended for.
        locale: String,
        /// Resource errors reported by Fluent.
        errors: Vec<String>,
    },
    /// Hidden-denial generic message id was blank.
    #[error("{field} must not be empty")]
    EmptyMessageId {
        /// Name of the message-id field.
        field: &'static str,
    },
    /// Hidden-denial fallback message was blank.
    #[error("{field} must not be empty")]
    EmptyFallbackMessage {
        /// Name of the fallback-message field.
        field: &'static str,
    },
}

fn parse_locale(locale: &str) -> Result<LanguageIdentifier, FluentCatalogError> {
    locale
        .parse::<LanguageIdentifier>()
        .map_err(|source| FluentCatalogError::InvalidLocale {
            locale: locale.to_owned(),
            source,
        })
}

fn parse_resource(locale: &str, source: String) -> Result<FluentResource, FluentCatalogError> {
    FluentResource::try_new(source).map_err(|(_resource, errors)| FluentCatalogError::Parse {
        locale: locale.to_owned(),
        errors: errors.into_iter().map(|error| error.to_string()).collect(),
    })
}

fn display_errors(errors: Vec<FluentError>) -> Vec<String> {
    errors.into_iter().map(|error| error.to_string()).collect()
}

fn validate_message_id(value: String) -> Result<String, FluentCatalogError> {
    if value.trim().is_empty() {
        Err(FluentCatalogError::EmptyMessageId {
            field: "hidden message id",
        })
    } else {
        Ok(value)
    }
}

fn validate_hidden_fallback(value: String) -> Result<String, FluentCatalogError> {
    if value.trim().is_empty() {
        Err(FluentCatalogError::EmptyFallbackMessage {
            field: "hidden fallback message",
        })
    } else {
        Ok(value)
    }
}

fn push_locale_candidate(candidates: &mut Vec<String>, locale: &str) {
    if let Ok(locale) = locale.parse::<LanguageIdentifier>() {
        let candidate = locale.to_string();
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    }
}

fn fluent_args(reason: &DenialReason) -> FluentArgs<'static> {
    let mut args = FluentArgs::with_capacity(reason.params.len());
    for (key, value) in &reason.params {
        args.set(key.as_str().to_owned(), fluent_value(value));
    }
    args
}

fn fluent_value(value: &ReasonValue) -> FluentValue<'static> {
    match value {
        ReasonValue::Str(value) => FluentValue::from(value.clone()),
        ReasonValue::Int(value) => FluentValue::from(*value),
        ReasonValue::Fact(fact) => FluentValue::from(fact.as_str().to_owned()),
        ReasonValue::Outcome(value) => json_value(value),
    }
}

fn json_value(value: &serde_json::Value) -> FluentValue<'static> {
    match value {
        serde_json::Value::Null => FluentValue::from("null"),
        serde_json::Value::Bool(value) => FluentValue::from(value.to_string()),
        serde_json::Value::Number(value) => number_value(value),
        serde_json::Value::String(value) => FluentValue::from(value.clone()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            FluentValue::from(value.to_string())
        }
    }
}

fn number_value(value: &serde_json::Number) -> FluentValue<'static> {
    value
        .as_i64()
        .map_or_else(|| unsigned_or_float_value(value), FluentValue::from)
}

fn unsigned_or_float_value(value: &serde_json::Number) -> FluentValue<'static> {
    value.as_u64().map_or_else(
        || float_value(value),
        |value| {
            i64::try_from(value)
                .map_or_else(|_| FluentValue::from(value.to_string()), FluentValue::from)
        },
    )
}

fn float_value(value: &serde_json::Number) -> FluentValue<'static> {
    value
        .as_f64()
        .map_or_else(|| FluentValue::from(value.to_string()), FluentValue::from)
}
