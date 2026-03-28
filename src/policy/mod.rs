//! Policy engine module
//!
//! Enforces guardrails, rate limits, and safety gates for all operations.

mod engine;
mod rules;

pub use engine::{AuditEntry, Policy, PolicyEngine};
pub use rules::{PolicyCheck, PolicyCheckResult, PolicyRule};
