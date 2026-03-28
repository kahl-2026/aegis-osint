//! CLI Command Definitions
//!
//! This module defines all CLI commands using clap derive macros.

mod assets;
mod defensive;
mod doctor;
mod findings;
mod init;
pub mod menu;
mod offensive;
mod report;
mod scope;

pub use assets::AssetsCommand;
pub use defensive::DefensiveCommand;
pub use doctor::DoctorCommand;
pub use findings::FindingsCommand;
pub use init::InitCommand;
pub use menu::Menu;
pub use offensive::{OffensiveCommand, ScanProfile};
pub use report::ReportCommand;
pub use scope::ScopeCommand;

use crate::LEGAL_NOTICE_SHORT;
use clap::{Parser, Subcommand};

/// AegisOSINT - Production-grade OSINT platform for authorized security operations
#[derive(Parser, Debug)]
#[command(
    name = "aegis",
    author = "AegisOSINT Contributors",
    version,
    about = "Production-grade OSINT platform for authorized bug bounty and defensive operations",
    long_about = format!(
        "AegisOSINT - Production-grade CLI platform for:\n\n\
         • Offensive OSINT: Authorized bug bounty reconnaissance\n\
         • Defensive OSINT: Continuous attack surface monitoring\n\n\
         {}\n\n\
         Use 'aegis <command> --help' for more information about a command.",
        LEGAL_NOTICE_SHORT
    ),
    after_help = "For more information, visit: https://github.com/yourusername/aegis-osint",
    propagate_version = true
)]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output format (text, json, quiet)
    #[arg(short, long, global = true, default_value = "text")]
    pub format: OutputFormat,

    /// Suppress colorized output
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Configuration file path
    #[arg(short, long, global = true, env = "AEGIS_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    /// Database connection string
    #[arg(long, global = true, env = "AEGIS_DATABASE")]
    pub database: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Output format options
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text with colors
    Text,
    /// Machine-readable JSON
    Json,
    /// Minimal output for scripts
    Quiet,
}

/// All available commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage authorized scopes and programs
    #[command(subcommand)]
    Scope(ScopeCommand),

    /// Run offensive OSINT operations (bug bounty recon)
    #[command(subcommand)]
    Offensive(OffensiveCommand),

    /// Run defensive OSINT operations (attack surface monitoring)
    #[command(subcommand)]
    Defensive(DefensiveCommand),

    /// Manage security findings
    #[command(subcommand)]
    Findings(FindingsCommand),

    /// Generate and export reports
    #[command(subcommand)]
    Report(ReportCommand),

    /// Asset management and tracking
    #[command(subcommand)]
    Assets(AssetsCommand),

    /// System health check and diagnostics
    Doctor(DoctorCommand),

    /// Initialize a new project or configuration
    Init(InitCommand),

    /// Launch interactive menu (default when no command given)
    Menu,
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Text
    }
}
