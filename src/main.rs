//! AegisOSINT CLI Entry Point
//!
//! This is the main entry point for the AegisOSINT command-line interface.

use aegis_osint::cli::{Cli, Commands, Menu};
use aegis_osint::config::Config;
use aegis_osint::policy::PolicyEngine;
use aegis_osint::storage::Storage;
use aegis_osint::LEGAL_DISCLAIMER;
use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::process::ExitCode;
use tracing::error;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Exit codes for deterministic error handling
#[allow(dead_code)]
mod exit_codes {
    pub const SUCCESS: u8 = 0;
    pub const GENERAL_ERROR: u8 = 1;
    pub const SCOPE_VIOLATION: u8 = 2;
    pub const POLICY_VIOLATION: u8 = 3;
    pub const CONFIG_ERROR: u8 = 4;
    pub const STORAGE_ERROR: u8 = 5;
    pub const NETWORK_ERROR: u8 = 6;
    pub const AUTHORIZATION_REQUIRED: u8 = 7;
    pub const INVALID_INPUT: u8 = 8;
}

#[tokio::main]
async fn main() -> ExitCode {
    // Initialize logging
    init_logging();

    // Parse CLI arguments
    let cli = Cli::parse();

    // Run the application
    match run(cli).await {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            error!("{}", format!("Fatal error: {}", e).red().bold());
            if let Some(source) = e.source() {
                error!("{}", format!("Caused by: {}", source).red());
            }
            ExitCode::from(exit_codes::GENERAL_ERROR)
        }
    }
}

/// Initialize logging subsystem
fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false).with_thread_ids(false))
        .with(filter)
        .init();
}

/// Main application logic
async fn run(cli: Cli) -> Result<u8> {
    // Check for first run and require acknowledgment
    let config = Config::load_or_create().await?;

    if !config.authorization_acknowledged {
        return handle_first_run().await;
    }

    // If no command given, or explicit menu command, launch interactive menu
    match cli.command {
        None | Some(Commands::Menu) => {
            return run_interactive_menu().await;
        }
        _ => {}
    }

    // Initialize core components
    let storage = Storage::initialize(&config).await?;
    let policy_engine = PolicyEngine::new(&config, &storage).await?;

    // Dispatch to command handlers
    match cli.command.unwrap() {
        Commands::Scope(cmd) => cmd.execute(&storage, &policy_engine).await,
        Commands::Offensive(cmd) => cmd.execute(&storage, &policy_engine).await,
        Commands::Defensive(cmd) => cmd.execute(&storage, &policy_engine).await,
        Commands::Findings(cmd) => cmd.execute(&storage, &policy_engine).await,
        Commands::Report(cmd) => cmd.execute(&storage, &policy_engine).await,
        Commands::Assets(cmd) => cmd.execute(&storage, &policy_engine).await,
        Commands::Doctor(cmd) => cmd.execute(&storage, &policy_engine).await,
        Commands::Init(cmd) => cmd.execute(&storage, &policy_engine).await,
        Commands::Menu => unreachable!(), // Already handled above
    }
}

/// Run the interactive menu system
async fn run_interactive_menu() -> Result<u8> {
    // Initialize storage and config for the menu
    let config = Config::load_or_create().await?;
    let storage = Storage::initialize(&config).await?;
    
    let mut menu = Menu::with_storage_and_config(storage, config);
    menu.run().await?;
    Ok(exit_codes::SUCCESS)
}

/// Handle first run authorization flow
async fn handle_first_run() -> Result<u8> {
    use std::io::{self, Write};

    println!("{}", LEGAL_DISCLAIMER.yellow());
    println!();

    print!("{}", "Do you acknowledge and accept these terms? [y/N]: ".bold());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let confirmed = matches!(input.trim().to_lowercase().as_str(), "y" | "yes");

    if confirmed {
        let mut config = Config::load_or_create().await?;
        config.authorization_acknowledged = true;
        config.save().await?;

        println!();
        println!(
            "{}",
            "✓ Authorization acknowledged. You may now use AegisOSINT."
                .green()
                .bold()
        );
        println!();
        println!("{}", "Quick start:".bold());
        println!("  {} - Import authorized scope", "aegis scope import --file scope.yaml".cyan());
        println!("  {} - Run offensive recon", "aegis offensive run --program <name>".cyan());
        println!("  {} - Start defensive monitoring", "aegis defensive monitor --scope <id>".cyan());
        println!("  {} - Launch interactive menu", "aegis menu".cyan());
        println!("  {} - System health check", "aegis doctor".cyan());
        println!();

        // Offer to launch menu
        print!("{}", "Launch interactive menu now? [Y/n]: ".bold());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let launch_menu = !matches!(input.trim().to_lowercase().as_str(), "n" | "no");

        if launch_menu {
            return run_interactive_menu().await;
        }

        Ok(exit_codes::SUCCESS)
    } else {
        println!();
        println!(
            "{}",
            "Authorization required to use AegisOSINT. Exiting."
                .red()
                .bold()
        );
        Ok(exit_codes::AUTHORIZATION_REQUIRED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_codes_are_unique() {
        let codes = vec![
            exit_codes::SUCCESS,
            exit_codes::GENERAL_ERROR,
            exit_codes::SCOPE_VIOLATION,
            exit_codes::POLICY_VIOLATION,
            exit_codes::CONFIG_ERROR,
            exit_codes::STORAGE_ERROR,
            exit_codes::NETWORK_ERROR,
            exit_codes::AUTHORIZATION_REQUIRED,
            exit_codes::INVALID_INPUT,
        ];

        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(codes.len(), unique.len(), "Exit codes must be unique");
    }
}
