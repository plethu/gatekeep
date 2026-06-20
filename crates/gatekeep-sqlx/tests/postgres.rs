#![allow(missing_docs)]
#![cfg(feature = "postgres-tests")]
//! Docker-backed Postgres tests.

#[path = "postgres/binds.rs"]
mod binds;
#[path = "postgres/lowering.rs"]
mod lowering;
#[path = "postgres/support.rs"]
mod support;
