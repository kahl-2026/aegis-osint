//! AegisOSINT - Production-grade OSINT platform for authorized security operations
//!
//! # Overview
//!
//! AegisOSINT is a Rust-based CLI tool designed for:
//! - **Offensive OSINT**: Authorized bug bounty reconnaissance and exposure discovery
//! - **Defensive OSINT**: Continuous external attack surface monitoring
//!
//! # Safety and Legal Compliance
//!
//! This tool is designed for **authorized use only**. All operations require:
//! - Explicit scope definition before any network activity
//! - In-scope validation for all targets
//! - User acknowledgment of authorization
//!
//! # Architecture
//!
//! The platform uses a modular architecture with:
//! - Compiled modules only (no dynamic plugin loading)
//! - Policy-enforced guardrails
//! - Full audit trail of all operations

pub mod cli;
pub mod config;
pub mod defensive;
pub mod findings;
pub mod offensive;
pub mod policy;
pub mod reporting;
pub mod scope;
pub mod storage;
pub mod utils;

// Re-export commonly used types
pub use config::Config;
pub use policy::{Policy, PolicyEngine};
pub use scope::{Scope, ScopeEngine, ScopeItem};
pub use storage::Storage;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Application name
pub const APP_NAME: &str = "AegisOSINT";

/// Legal disclaimer shown on first run and in help
pub const LEGAL_DISCLAIMER: &str = r#"
╔══════════════════════════════════════════════════════════════════════════════╗
║                           LEGAL AND ETHICAL NOTICE                           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  AegisOSINT is designed for AUTHORIZED security testing and defensive       ║
║  OSINT operations ONLY.                                                      ║
║                                                                              ║
║  BY USING THIS TOOL, YOU ACKNOWLEDGE AND AGREE THAT:                         ║
║                                                                              ║
║  1. You have explicit written authorization to test all targets              ║
║  2. You will only operate within defined, authorized scope                   ║
║  3. You understand that unauthorized access is illegal                       ║
║  4. You accept full responsibility for your actions                          ║
║  5. You will comply with all applicable laws and regulations                 ║
║                                                                              ║
║  UNAUTHORIZED ACCESS TO COMPUTER SYSTEMS IS A CRIMINAL OFFENSE.              ║
║  The authors assume no liability for misuse of this software.                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"#;

/// Short legal notice for CLI help
pub const LEGAL_NOTICE_SHORT: &str =
    "⚠️  AUTHORIZED USE ONLY - Requires explicit scope authorization before any operation";
