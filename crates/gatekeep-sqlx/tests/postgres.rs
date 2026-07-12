#![allow(missing_docs)]
#![cfg(feature = "postgres-tests")]
//! Docker-backed Postgres tests.

#[path = "postgres/audit.rs"]
mod audit;
#[path = "audit_support/mod.rs"]
mod audit_support;
#[path = "postgres/binds.rs"]
mod binds;
#[path = "postgres/lowering.rs"]
mod lowering;
#[path = "postgres/support.rs"]
mod support;
