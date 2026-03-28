//! Findings management module

mod scoring;
mod verifier;

pub use scoring::{RiskScorer, SeverityCalculator};
pub use verifier::FindingVerifier;
