//! Offensive OSINT commands

use crate::policy::PolicyEngine;
use crate::storage::{FindingContext, Storage};
use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;

/// Offensive OSINT commands for authorized bug bounty recon
#[derive(Subcommand, Debug)]
pub enum OffensiveCommand {
    /// Run offensive OSINT scan
    Run(OffensiveRunArgs),

    /// List available scan profiles
    Profiles(OffensiveProfilesArgs),

    /// Show scan status
    Status(OffensiveStatusArgs),

    /// Stop a running scan
    Stop(OffensiveStopArgs),
}

/// Scan profile determining aggressiveness
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, Default)]
pub enum ScanProfile {
    /// Safe mode - minimal footprint, passive only
    #[default]
    Safe,
    /// Standard mode - balanced active/passive recon
    Standard,
    /// Thorough mode - comprehensive but slower
    Thorough,
    /// Aggressive mode - expanded active probing within policy controls
    Aggressive,
}

#[derive(Args, Debug)]
pub struct OffensiveRunArgs {
    /// Bug bounty program name
    #[arg(short, long)]
    pub program: String,

    /// Scope ID to use
    #[arg(short, long)]
    pub scope: Option<String>,

    /// Scan profile (safe, standard, thorough, aggressive)
    #[arg(long, value_enum, default_value = "safe")]
    pub profile: ScanProfile,

    /// Specific modules to run (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    pub modules: Option<Vec<String>>,

    /// Skip specific modules
    #[arg(long, value_delimiter = ',')]
    pub skip: Option<Vec<String>>,

    /// Output directory for results
    #[arg(short, long)]
    pub output: Option<std::path::PathBuf>,

    /// Maximum concurrent operations
    #[arg(long, default_value = "10")]
    pub concurrency: usize,

    /// Dry run - validate scope but don't execute
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct OffensiveProfilesArgs {
    /// Show detailed module information
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Args, Debug)]
pub struct OffensiveStatusArgs {
    /// Scan run ID
    #[arg(required = true)]
    pub run_id: String,

    /// Follow output in real-time
    #[arg(short, long)]
    pub follow: bool,
}

#[derive(Args, Debug)]
pub struct OffensiveStopArgs {
    /// Scan run ID
    #[arg(required = true)]
    pub run_id: String,

    /// Force stop without cleanup
    #[arg(long)]
    pub force: bool,
}

impl OffensiveCommand {
    pub async fn execute(&self, storage: &Storage, policy: &PolicyEngine) -> Result<u8> {
        match self {
            OffensiveCommand::Run(args) => Self::handle_run(args, storage, policy).await,
            OffensiveCommand::Profiles(args) => Self::handle_profiles(args).await,
            OffensiveCommand::Status(args) => Self::handle_status(args, storage).await,
            OffensiveCommand::Stop(args) => Self::handle_stop(args, storage).await,
        }
    }

    async fn handle_run(
        args: &OffensiveRunArgs,
        storage: &Storage,
        policy: &PolicyEngine,
    ) -> Result<u8> {
        use crate::offensive::OffensiveOrchestrator;
        use indicatif::{ProgressBar, ProgressStyle};

        println!("{}", "AegisOSINT - Offensive Reconnaissance".cyan().bold());
        println!();

        // Display scope validation header
        println!("{}", "⚠️  SCOPE VALIDATION".yellow().bold());
        println!("{}", "─".repeat(60));

        // Look up the scope
        let scope_id = args.scope.clone().unwrap_or_else(|| args.program.clone());
        let scope = storage.get_scope(&scope_id).await?;

        let scope = match scope {
            Some(s) => s,
            None => {
                println!(
                    "{}",
                    format!("Scope '{}' not found.", scope_id).red().bold()
                );
                println!();
                println!(
                    "Import a scope first: {}",
                    "aegis scope import --file scope.yaml".cyan()
                );
                return Ok(8);
            }
        };

        // Display scope information
        println!("  {} {}", "Program:".bold(), args.program.cyan());
        println!("  {} {}", "Scope ID:".bold(), scope.id.cyan());
        println!("  {} {}", "Scope Name:".bold(), scope.name);
        println!(
            "  {} {} domains, {} CIDRs",
            "In-Scope:".bold(),
            scope.domain_count,
            scope.cidr_count
        );
        println!("  {} {:?}", "Profile:".bold(), args.profile);
        println!("{}", "─".repeat(60));
        println!();

        // Check policy allows this operation
        let policy_check = policy
            .check_offensive_operation(&args.program, &scope)
            .await?;
        if !policy_check.allowed {
            println!("{}", "✗ Operation blocked by policy".red().bold());
            for reason in &policy_check.reasons {
                println!("  {} {}", "•".red(), reason);
            }
            return Ok(3); // POLICY_VIOLATION
        }

        if args.dry_run {
            println!("{}", "✓ Dry run completed - scope validated".green().bold());
            println!();
            println!("Modules selected for this profile:");
            let modules = Self::get_modules_for_profile(args.profile);
            for module in modules {
                println!("  {} {}", "•".green(), module);
            }
            return Ok(0);
        }

        // Create scan run
        let run_id = storage
            .create_scan_run(&args.program, &scope.id, "offensive")
            .await?;
        println!("{}", format!("Scan ID: {}", run_id).cyan());
        println!();

        // Initialize progress bar
        let progress = ProgressBar::new(100);
        let style = ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}% {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("█▓░");
        progress.set_style(style);

        // Create and run the orchestrator
        let orchestrator = OffensiveOrchestrator::new(
            scope,
            args.profile,
            args.concurrency,
            policy.clone(),
            storage.clone(),
        );

        let result = orchestrator
            .execute(&run_id, |stage, percent| {
                progress.set_position(percent as u64);
                progress.set_message(stage.to_string());
            })
            .await;

        progress.finish_and_clear();

        match result {
            Ok(summary) => {
                println!("{}", "✓ Scan completed".green().bold());
                println!();
                println!("{}", "Scan Summary".bold().underline());
                println!("{}", "─".repeat(60).dimmed());
                println!("  {:24} {}", "Program".bold(), args.program.cyan());
                println!("  {:24} {}", "Scope ID".bold(), scope_id.cyan());
                println!("  {:24} {}", "Run ID".bold(), run_id.cyan());
                println!("  {:24} {:?}", "Profile".bold(), args.profile);
                println!(
                    "  {:24} {}",
                    "Assets discovered".bold(),
                    summary.assets_count
                );
                println!(
                    "  {:24} {}",
                    "Findings created".bold(),
                    summary.findings_count
                );
                println!("  {:24} {:.2}s", "Duration".bold(), summary.duration_secs);
                println!("{}", "─".repeat(60).dimmed());

                if let Ok(recent) = storage
                    .list_findings(
                        None,
                        FindingContext {
                            scope: Some(&scope_id),
                            run: Some(&run_id),
                        },
                        None,
                        None,
                        10_000,
                        "severity",
                    )
                    .await
                {
                    if !recent.is_empty() {
                        println!("{}", "Findings from this run:".bold());
                        let mut severity_totals = std::collections::BTreeMap::new();
                        for finding in &recent {
                            *severity_totals
                                .entry(finding.severity.as_str())
                                .or_insert(0usize) += 1;
                        }
                        println!(
                            "  critical={} high={} medium={} low={} info={}",
                            severity_totals.get("critical").copied().unwrap_or(0),
                            severity_totals.get("high").copied().unwrap_or(0),
                            severity_totals.get("medium").copied().unwrap_or(0),
                            severity_totals.get("low").copied().unwrap_or(0),
                            severity_totals.get("info").copied().unwrap_or(0)
                        );
                        println!();
                        for f in recent.iter().take(25) {
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
                        if recent.len() > 25 {
                            println!(
                                "  {} Showing first 25 of {} findings",
                                "…".yellow(),
                                recent.len()
                            );
                        }
                        println!();
                    }
                }
                println!();
                println!(
                    "View findings: {}",
                    format!("aegis findings list --scope {} --severity high", scope_id).cyan()
                );
                println!(
                    "Export report: {}",
                    format!(
                        "aegis report export --scope {} --format markdown --output report.md",
                        scope_id
                    )
                    .cyan()
                );
                Ok(0)
            }
            Err(e) => {
                println!("{}", format!("✗ Scan failed: {}", e).red().bold());
                Ok(1)
            }
        }
    }

    async fn handle_profiles(args: &OffensiveProfilesArgs) -> Result<u8> {
        println!("{}", "Available Scan Profiles".bold());
        println!();

        // Safe profile
        println!("{}", "safe".green().bold());
        println!("  Minimal footprint, passive reconnaissance only");
        println!(
            "  {} CT logs, DNS records, public metadata",
            "Includes:".bold()
        );
        if args.verbose {
            println!("  Modules:");
            for module in Self::get_modules_for_profile(ScanProfile::Safe) {
                println!("    • {}", module);
            }
        }
        println!();

        // Standard profile
        println!("{}", "standard".cyan().bold());
        println!("  Balanced active/passive reconnaissance");
        println!(
            "  {} All safe + light probing, fingerprinting",
            "Includes:".bold()
        );
        if args.verbose {
            println!("  Modules:");
            for module in Self::get_modules_for_profile(ScanProfile::Standard) {
                println!("    • {}", module);
            }
        }
        println!();

        // Thorough profile
        println!("{}", "thorough".yellow().bold());
        println!("  Comprehensive reconnaissance (slower)");
        println!("  {} All standard + deep enumeration", "Includes:".bold());
        if args.verbose {
            println!("  Modules:");
            for module in Self::get_modules_for_profile(ScanProfile::Thorough) {
                println!("    • {}", module);
            }
        }
        println!();

        println!("{}", "aggressive".red().bold());
        println!("  High-depth active recon (explicit opt-in)");
        println!(
            "  {} All thorough + expanded probing and enumeration",
            "Includes:".bold()
        );
        if args.verbose {
            println!("  Modules:");
            for module in Self::get_modules_for_profile(ScanProfile::Aggressive) {
                println!("    • {}", module);
            }
        }

        Ok(0)
    }

    async fn handle_status(args: &OffensiveStatusArgs, storage: &Storage) -> Result<u8> {
        let run = storage.get_scan_run(&args.run_id).await?;

        match run {
            Some(run) => {
                println!("{}", format!("Scan: {}", run.id).bold());
                println!();
                println!("  {} {}", "Status:".bold(), run.status);
                println!("  {} {}", "Program:".bold(), run.program);
                println!("  {} {}", "Scope:".bold(), run.scope_id);
                println!("  {} {}", "Started:".bold(), run.started_at);
                if let Some(ended) = run.ended_at {
                    println!("  {} {}", "Ended:".bold(), ended);
                }
                println!("  {} {}%", "Progress:".bold(), run.progress);
                println!("  {} {}", "Findings:".bold(), run.findings_count);
                Ok(0)
            }
            None => {
                println!("{}", format!("Scan '{}' not found.", args.run_id).red());
                Ok(8)
            }
        }
    }

    async fn handle_stop(args: &OffensiveStopArgs, storage: &Storage) -> Result<u8> {
        let run = storage.get_scan_run(&args.run_id).await?;

        match run {
            Some(run) if run.status == "running" => {
                storage.update_scan_status(&args.run_id, "stopped").await?;
                println!(
                    "{}",
                    format!("✓ Scan '{}' stopped", args.run_id).green().bold()
                );
                Ok(0)
            }
            Some(run) => {
                println!(
                    "{}",
                    format!(
                        "Scan '{}' is not running (status: {})",
                        args.run_id, run.status
                    )
                    .yellow()
                );
                Ok(0)
            }
            None => {
                println!("{}", format!("Scan '{}' not found.", args.run_id).red());
                Ok(8)
            }
        }
    }

    fn get_modules_for_profile(profile: ScanProfile) -> Vec<&'static str> {
        match profile {
            ScanProfile::Safe => vec![
                "ct-logs",
                "dns-records",
                "whois",
                "public-metadata",
                "historical-dns",
            ],
            ScanProfile::Standard => vec![
                "ct-logs",
                "dns-records",
                "whois",
                "public-metadata",
                "historical-dns",
                "service-fingerprint",
                "header-analysis",
                "js-analysis",
                "cloud-exposure",
            ],
            ScanProfile::Thorough => vec![
                "ct-logs",
                "dns-records",
                "whois",
                "public-metadata",
                "historical-dns",
                "service-fingerprint",
                "header-analysis",
                "js-analysis",
                "cloud-exposure",
                "subdomain-bruteforce",
                "port-scan",
                "tech-fingerprint",
                "repo-scan",
            ],
            ScanProfile::Aggressive => vec![
                "ct-logs",
                "dns-records",
                "whois",
                "public-metadata",
                "historical-dns",
                "service-fingerprint (expanded ports)",
                "header-analysis",
                "js-analysis",
                "cloud-exposure",
                "aggressive-path-probing",
                "subdomain-permutation-enum",
                "historical-correlation",
                "repo-scan",
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OffensiveCommand, ScanProfile};

    #[test]
    fn aggressive_profile_includes_expanded_modules() {
        let modules = OffensiveCommand::get_modules_for_profile(ScanProfile::Aggressive);
        assert!(modules.contains(&"aggressive-path-probing"));
        assert!(modules.contains(&"subdomain-permutation-enum"));
        assert!(modules.contains(&"historical-correlation"));
    }
}
