//! Offensive OSINT module
//!
//! Contains modules for authorized bug bounty reconnaissance:
//! - Asset discovery (CT logs, DNS, ASN mapping)
//! - Web reconnaissance (endpoints, headers, fingerprinting)
//! - Cloud exposure detection
//! - Historical correlation

pub mod cloud;
pub mod correlation;
pub mod discovery;
pub mod orchestrator;
pub mod web;

pub use orchestrator::OffensiveOrchestrator;
