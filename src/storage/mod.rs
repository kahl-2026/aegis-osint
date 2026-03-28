//! Storage module
//!
//! Provides database abstraction for SQLite and optional Postgres backends.

mod database;
mod models;
mod queries;

pub use database::Storage;
pub use models::*;
