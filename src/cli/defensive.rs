//! Defensive OSINT commands

use crate::policy::PolicyEngine;
use crate::storage::Storage;
use anyhow::Result;
use clap::{Args, Subcommand};
use colored::Colorize;

/// Defensive OSINT commands for attack surface monitoring
#[derive(Subcommand, Debug)]
pub enum DefensiveCommand {
    /// Start continuous monitoring
    Monitor(DefensiveMonitorArgs),

    /// Run a one-time scan
    Scan(DefensiveScanArgs),

    /// Show monitoring status
    Status(DefensiveStatusArgs),

    /// Configure alerting
    Alerts(DefensiveAlertsArgs),

    /// Show attack surface summary
    Summary(DefensiveSummaryArgs),
}

#[derive(Args, Debug)]
pub struct DefensiveMonitorArgs {
    /// Scope ID to monitor
    #[arg(short, long)]
    pub scope: String,

    /// Check interval in minutes
    #[arg(long, default_value = "60")]
    pub interval: u32,

    /// Enable drift detection
    #[arg(long, default_value = "true")]
    pub drift_detection: bool,

    /// Enable brand monitoring
    #[arg(long, default_value = "true")]
    pub brand_monitoring: bool,

    /// Enable leak monitoring
    #[arg(long, default_value = "true")]
    pub leak_monitoring: bool,

    /// Run in background (daemon mode)
    #[arg(short, long)]
    pub daemon: bool,
}

#[derive(Args, Debug)]
pub struct DefensiveScanArgs {
    /// Scope ID to scan
    #[arg(short, long)]
    pub scope: String,

    /// Specific checks to run
    #[arg(short, long, value_delimiter = ',')]
    pub checks: Option<Vec<String>>,
}

#[derive(Args, Debug)]
pub struct DefensiveStatusArgs {
    /// Scope ID (optional, shows all if not specified)
    #[arg(short, long)]
    pub scope: Option<String>,
}

#[derive(Args, Debug)]
pub struct DefensiveAlertsArgs {
    /// Scope ID
    #[arg(short, long)]
    pub scope: String,

    /// Alert destination (email, webhook, slack)
    #[arg(long)]
    pub destination: Option<String>,

    /// Minimum severity for alerts
    #[arg(long)]
    pub min_severity: Option<String>,

    /// Show current alert configuration
    #[arg(long)]
    pub show: bool,
}

#[derive(Args, Debug)]
pub struct DefensiveSummaryArgs {
    /// Scope ID
    #[arg(short, long)]
    pub scope: String,

    /// Time period (7d, 30d, 90d)
    #[arg(long, default_value = "30d")]
    pub period: String,
}

impl DefensiveCommand {
    pub async fn execute(&self, storage: &Storage, policy: &PolicyEngine) -> Result<u8> {
        match self {
            DefensiveCommand::Monitor(args) => Self::handle_monitor(args, storage, policy).await,
            DefensiveCommand::Scan(args) => Self::handle_scan(args, storage, policy).await,
            DefensiveCommand::Status(args) => Self::handle_status(args, storage).await,
            DefensiveCommand::Alerts(args) => Self::handle_alerts(args, storage).await,
            DefensiveCommand::Summary(args) => Self::handle_summary(args, storage).await,
        }
    }

    async fn handle_monitor(
        args: &DefensiveMonitorArgs,
        storage: &Storage,
        policy: &PolicyEngine,
    ) -> Result<u8> {
        use crate::defensive::DefensiveOrchestrator;

        println!(
            "{}",
            "AegisOSINT - Defensive Monitoring".cyan().bold()
        );
        println!();

        // Look up scope
        let scope = storage.get_scope(&args.scope).await?;
        let scope = match scope {
            Some(s) => s,
            None => {
                println!(
                    "{}",
                    format!("Scope '{}' not found.", args.scope).red().bold()
                );
                return Ok(8);
            }
        };

        // Check policy
        let policy_check = policy.check_defensive_operation(&scope).await?;
        if !policy_check.allowed {
            println!("{}", "✗ Operation blocked by policy".red().bold());
            for reason in &policy_check.reasons {
                println!("  {} {}", "•".red(), reason);
            }
            return Ok(3);
        }

        println!("{}", "Configuration:".bold());
        println!("  {} {}", "Scope:".bold(), scope.name.cyan());
        println!("  {} {} minutes", "Interval:".bold(), args.interval);
        println!(
            "  {} {}",
            "Drift Detection:".bold(),
            if args.drift_detection { "enabled".green() } else { "disabled".yellow() }
        );
        println!(
            "  {} {}",
            "Brand Monitoring:".bold(),
            if args.brand_monitoring { "enabled".green() } else { "disabled".yellow() }
        );
        println!(
            "  {} {}",
            "Leak Monitoring:".bold(),
            if args.leak_monitoring { "enabled".green() } else { "disabled".yellow() }
        );
        println!();

        if args.daemon {
            println!("{}", "Starting background monitoring...".cyan());

            let orchestrator = DefensiveOrchestrator::new(
                scope,
                args.interval,
                args.drift_detection,
                args.brand_monitoring,
                args.leak_monitoring,
                policy.clone(),
                storage.clone(),
            );

            // Register daemon monitor state and return monitor ID.
            let monitor_id = orchestrator.start_daemon().await?;

            println!(
                "{}",
                format!("✓ Monitoring started (ID: {})", monitor_id).green().bold()
            );
            println!();
            println!(
                "Check status: {}",
                format!("aegis defensive status --scope {}", args.scope).cyan()
            );

            Ok(0)
        } else {
            println!("{}", "Starting interactive monitoring...".cyan());
            println!("{}", "(Press Ctrl+C to stop)".yellow());
            println!();

            let orchestrator = DefensiveOrchestrator::new(
                scope,
                args.interval,
                args.drift_detection,
                args.brand_monitoring,
                args.leak_monitoring,
                policy.clone(),
                storage.clone(),
            );

            orchestrator.run_interactive().await?;

            Ok(0)
        }
    }

    async fn handle_scan(
        args: &DefensiveScanArgs,
        storage: &Storage,
        policy: &PolicyEngine,
    ) -> Result<u8> {
        use crate::defensive::DefensiveScanner;

        println!("{}", "Running defensive scan...".cyan());
        println!();

        let scope = storage.get_scope(&args.scope).await?;
        let scope = match scope {
            Some(s) => s,
            None => {
                println!(
                    "{}",
                    format!("Scope '{}' not found.", args.scope).red().bold()
                );
                return Ok(8);
            }
        };

        // Check policy
        let policy_check = policy.check_defensive_operation(&scope).await?;
        if !policy_check.allowed {
            println!("{}", "✗ Operation blocked by policy".red().bold());
            return Ok(3);
        }

        let scanner = DefensiveScanner::new(scope, policy.clone(), storage.clone());
        let results = scanner.scan(args.checks.as_ref()).await?;

        println!("{}", "Defensive Scan Summary".bold().underline());
        println!("{}", "─".repeat(60).dimmed());
        println!("  {:24} {}", "Scope ID".bold(), args.scope.cyan());
        println!("  {:24} {}", "Assets inventoried".bold(), results.assets_count);
        println!("  {:24} {}", "Drift changes".bold(), results.changes_count);
        println!("  {:24} {}", "Open exposures".bold(), results.exposures_count);
        println!("  {:24} {:.2}s", "Duration".bold(), results.duration_secs);
        println!("{}", "─".repeat(60).dimmed());

        if results.changes_count > 0 || results.exposures_count > 0 {
            println!();
            if let Ok(recent) = storage
                .list_findings(
                    None,
                    Some(&args.scope),
                    None,
                    Some("open".to_string()),
                    None,
                    10,
                    "severity",
                )
                .await
            {
                if !recent.is_empty() {
                    println!("{}", "Top open findings:".bold());
                    for f in recent {
                        let sev = match f.severity.as_str() {
                            "critical" => f.severity.red().bold().to_string(),
                            "high" => f.severity.red().to_string(),
                            "medium" => f.severity.yellow().to_string(),
                            "low" => f.severity.green().to_string(),
                            _ => f.severity.blue().to_string(),
                        };
                        println!(
                            "  {} {:10} {} ({})",
                            "•".cyan(),
                            sev,
                            f.title,
                            f.asset.dimmed()
                        );
                    }
                    println!();
                }
            }
            println!(
                "View details: {}",
                format!("aegis findings list --scope {}", args.scope).cyan()
            );
            println!(
                "Asset drift diff: {}",
                format!("aegis assets diff --scope {} --since 2024-01-01", args.scope).cyan()
            );
        }

        Ok(0)
    }

    async fn handle_status(args: &DefensiveStatusArgs, storage: &Storage) -> Result<u8> {
        let monitors = storage.list_monitors(args.scope.as_deref()).await?;

        if monitors.is_empty() {
            println!("{}", "No active monitors.".yellow());
            return Ok(0);
        }

        println!("{}", "Active Monitors:".bold());
        println!();

        for monitor in monitors {
            println!(
                "  {} [{}]",
                monitor.scope_id.cyan().bold(),
                monitor.status.green()
            );
            println!("    {} {}", "Started:".bold(), monitor.started_at);
            println!("    {} {}", "Last check:".bold(), monitor.last_check);
            println!("    {} {}", "Next check:".bold(), monitor.next_check);
            println!("    {} {}", "Checks run:".bold(), monitor.check_count);
            println!();
        }

        Ok(0)
    }

    async fn handle_alerts(args: &DefensiveAlertsArgs, storage: &Storage) -> Result<u8> {
        if args.show {
            let config = storage.get_alert_config(&args.scope).await?;

            match config {
                Some(config) => {
                    println!("{}", format!("Alert Configuration: {}", args.scope).bold());
                    println!();
                    println!("  {} {}", "Destination:".bold(), config.destination);
                    println!("  {} {}", "Min Severity:".bold(), config.min_severity);
                    println!("  {} {}", "Enabled:".bold(), config.enabled);
                }
                None => {
                    println!(
                        "{}",
                        format!("No alert configuration for scope '{}'", args.scope).yellow()
                    );
                }
            }
        } else if let Some(destination) = &args.destination {
            storage
                .set_alert_config(
                    &args.scope,
                    destination,
                    args.min_severity.as_deref().unwrap_or("medium"),
                )
                .await?;
            println!(
                "{}",
                "✓ Alert configuration updated".green().bold()
            );
        } else {
            println!("{}", "Specify --destination to configure alerts, or --show to view current configuration".yellow());
        }

        Ok(0)
    }

    async fn handle_summary(args: &DefensiveSummaryArgs, storage: &Storage) -> Result<u8> {
        let summary = storage.get_attack_surface_summary(&args.scope, &args.period).await?;

        println!(
            "{}",
            format!("Attack Surface Summary: {} ({})", args.scope, args.period).bold()
        );
        println!();

        println!("{}", "Asset Inventory:".bold());
        println!("  {} {}", "Domains:".bold(), summary.domain_count);
        println!("  {} {}", "Subdomains:".bold(), summary.subdomain_count);
        println!("  {} {}", "IP Addresses:".bold(), summary.ip_count);
        println!("  {} {}", "Services:".bold(), summary.service_count);
        println!();

        println!("{}", "Changes This Period:".bold());
        println!(
            "  {} {} ({} new, {} removed)",
            "Assets:".bold(),
            summary.asset_changes,
            summary.assets_added,
            summary.assets_removed
        );
        println!(
            "  {} {}",
            "Configuration changes:".bold(),
            summary.config_changes
        );
        println!(
            "  {} {}",
            "Certificate changes:".bold(),
            summary.cert_changes
        );
        println!();

        println!("{}", "Risk Summary:".bold());
        println!(
            "  {} {}",
            "Critical findings:".bold(),
            format!("{}", summary.critical_findings).red()
        );
        println!(
            "  {} {}",
            "High findings:".bold(),
            format!("{}", summary.high_findings).yellow()
        );
        println!(
            "  {} {}",
            "Medium findings:".bold(),
            summary.medium_findings
        );
        println!(
            "  {} {}",
            "Low findings:".bold(),
            summary.low_findings
        );

        Ok(0)
    }
}
