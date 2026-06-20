//! Axum adapter for gatekeep authorization boundaries.
//!
//! The crate keeps policy selection and context construction in the application.
//! Handlers call [`Gatekeeper::authorize`] with a policy value and use
//! [`GatekeepRejection`] as an axum rejection.

#![forbid(unsafe_code)]

mod authorizer;
mod error;
mod response;

pub use authorizer::{AuditSubjects, Authorized, Gatekeeper};
pub use error::{GatekeepAxumError, GatekeepRejection};
pub use response::{DenialBody, DenialError, DenialResponse, DenialResponseConfig};
