//! Defensive OSINT module
//!
//! Contains modules for continuous attack surface monitoring:
//! - Attack surface inventory
//! - Drift detection
//! - Brand monitoring
//! - Leak monitoring

pub mod brand;
pub mod drift;
pub mod monitor;
pub mod orchestrator;
pub mod scanner;

pub use orchestrator::DefensiveOrchestrator;
pub use scanner::DefensiveScanner;
