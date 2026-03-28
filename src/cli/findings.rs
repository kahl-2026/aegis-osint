//! Findings management commands

use crate::policy::PolicyEngine;
use crate::storage::Storage;
use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;

/// Findings management commands
#[derive(Subcommand, Debug)]
pub enum FindingsCommand {
    /// List findings
    List(FindingsListArgs),

    /// Show finding details
    Show(FindingsShowArgs),

    /// Verify a finding
    Verify(FindingsVerifyArgs),

    /// Update finding status
    Update(FindingsUpdateArgs),

    /// Export findings
    Export(FindingsExportArgs),

    /// Generate remediation queue
    Remediation(FindingsRemediationArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum FindingStatus {
    Open,
    Verified,
    Fixed,
    FalsePositive,
    Accepted,
    Duplicate,
}

#[derive(Args, Debug)]
pub struct FindingsListArgs {
    /// Filter by severity
    #[arg(short, long, value_enum)]
    pub severity: Option<Severity>,

    /// Filter by scope ID
    #[arg(long)]
    pub scope: Option<String>,

    /// Filter by scan run ID
    #[arg(long)]
    pub run: Option<String>,

    /// Filter by status
    #[arg(long, value_enum)]
    pub status: Option<FindingStatus>,

    /// Filter by asset
    #[arg(long)]
    pub asset: Option<String>,

    /// Maximum number of results
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Sort by field (severity, date, confidence)
    #[arg(long, default_value = "severity")]
    pub sort: String,
}

#[derive(Args, Debug)]
pub struct FindingsShowArgs {
    /// Finding ID
    #[arg(required = true)]
    pub id: String,

    /// Show full evidence
    #[arg(long)]
    pub full: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct FindingsVerifyArgs {
    /// Finding ID
    #[arg(required = true)]
    pub id: String,

    /// Re-run verification checks
    #[arg(long)]
    pub recheck: bool,

    /// Add verification notes
    #[arg(long)]
    pub notes: Option<String>,
}

#[derive(Args, Debug)]
pub struct FindingsUpdateArgs {
    /// Finding ID
    #[arg(required = true)]
    pub id: String,

    /// New status
    #[arg(short, long, value_enum)]
    pub status: FindingStatus,

    /// Add notes
    #[arg(long)]
    pub notes: Option<String>,
}

#[derive(Args, Debug)]
pub struct FindingsExportArgs {
    /// Filter by scope
    #[arg(long)]
    pub scope: Option<String>,

    /// Filter by severity
    #[arg(long, value_enum)]
    pub severity: Option<Severity>,

    /// Output format
    #[arg(short, long, default_value = "json")]
    pub format: String,

    /// Output file
    #[arg(short, long)]
    pub output: std::path::PathBuf,

    /// Bug bounty submission format
    #[arg(long)]
    pub bounty_format: bool,
}

#[derive(Args, Debug)]
pub struct FindingsRemediationArgs {
    /// Scope ID
    #[arg(short, long)]
    pub scope: String,

    /// Include ownership information
    #[arg(long)]
    pub with_owners: bool,

    /// Include SLA metadata
    #[arg(long)]
    pub with_sla: bool,

    /// Output format (json, csv, yaml)
    #[arg(short, long, default_value = "json")]
    pub format: String,
}

impl FindingsCommand {
    pub async fn execute(&self, storage: &Storage, _policy: &PolicyEngine) -> Result<u8> {
        match self {
            FindingsCommand::List(args) => Self::handle_list(args, storage).await,
            FindingsCommand::Show(args) => Self::handle_show(args, storage).await,
            FindingsCommand::Verify(args) => Self::handle_verify(args, storage).await,
            FindingsCommand::Update(args) => Self::handle_update(args, storage).await,
            FindingsCommand::Export(args) => Self::handle_export(args, storage).await,
            FindingsCommand::Remediation(args) => Self::handle_remediation(args, storage).await,
        }
    }

    async fn handle_list(args: &FindingsListArgs, storage: &Storage) -> Result<u8> {
        let findings = storage
            .list_findings(
                args.severity.as_ref().map(|s| format!("{:?}", s).to_lowercase()),
                args.scope.as_deref(),
                args.run.as_deref(),
                args.status.as_ref().map(|s| format!("{:?}", s).to_lowercase()),
                args.asset.as_deref(),
                args.limit,
                &args.sort,
            )
            .await?;

        if findings.is_empty() {
            println!("{}", "No findings found.".yellow());
            return Ok(0);
        }

        println!(
            "{}",
            format!("Findings ({} total):", findings.len()).bold()
        );
        println!();

        for finding in &findings {
            let severity_color = match finding.severity.as_str() {
                "critical" => finding.severity.red().bold(),
                "high" => finding.severity.red(),
                "medium" => finding.severity.yellow(),
                "low" => finding.severity.blue(),
                _ => finding.severity.normal(),
            };

            println!(
                "  {} [{}] {}",
                finding.id.cyan(),
                severity_color,
                finding.title.bold()
            );
            println!("    Asset: {} | Confidence: {}%", finding.asset, finding.confidence);
            if let Some(status) = &finding.status {
                println!("    Status: {}", status);
            }
            println!();
        }

        if findings.len() >= args.limit {
            println!(
                "{}",
                format!("Showing first {} results. Use --limit to see more.", args.limit).yellow()
            );
        }

        Ok(0)
    }

    async fn handle_show(args: &FindingsShowArgs, storage: &Storage) -> Result<u8> {
        let finding = storage.get_finding(&args.id).await?;

        match finding {
            Some(finding) => {
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&finding)?);
                    return Ok(0);
                }

                let severity_color = match finding.severity.as_str() {
                    "critical" => finding.severity.red().bold(),
                    "high" => finding.severity.red(),
                    "medium" => finding.severity.yellow(),
                    "low" => finding.severity.blue(),
                    _ => finding.severity.normal(),
                };

                println!(
                    "{}",
                    format!("Finding: {}", finding.title).bold()
                );
                println!("{}", "─".repeat(60));
                println!();
                println!("  {} {}", "ID:".bold(), finding.id);
                println!("  {} {}", "Severity:".bold(), severity_color);
                println!("  {} {}%", "Confidence:".bold(), finding.confidence);
                println!("  {} {}", "Asset:".bold(), finding.asset);
                println!("  {} {}", "Type:".bold(), finding.finding_type);
                println!("  {} {}", "Status:".bold(), finding.status.as_deref().unwrap_or("open"));
                println!("  {} {}", "Discovered:".bold(), finding.created_at);
                println!();

                println!("{}", "Description:".bold());
                println!("  {}", finding.description);
                println!();

                println!("{}", "Impact:".bold());
                println!("  {}", finding.impact);
                println!();

                if args.full {
                    println!("{}", "Evidence:".bold());
                    for evidence in &finding.evidence {
                        println!("  {} {}", "•".cyan(), evidence.description);
                        println!("    Source: {}", evidence.source);
                        println!("    Timestamp: {}", evidence.timestamp);
                        if let Some(data) = &evidence.data {
                            println!("    Data: {}", data);
                        }
                        println!();
                    }

                    println!("{}", "Provenance:".bold());
                    println!("  {} {}", "Source:".bold(), finding.source);
                    println!("  {} {}", "Method:".bold(), finding.method);
                    println!("  {} {}", "Scope verified:".bold(), finding.scope_verified);
                }

                println!();
                println!("{}", "Reproduction:".bold());
                println!("  {}", finding.reproduction.as_deref().unwrap_or("N/A"));

                Ok(0)
            }
            None => {
                println!(
                    "{}",
                    format!("Finding '{}' not found.", args.id).red()
                );
                Ok(8)
            }
        }
    }

    async fn handle_verify(args: &FindingsVerifyArgs, storage: &Storage) -> Result<u8> {
        use crate::findings::FindingVerifier;

        let finding = storage.get_finding(&args.id).await?;

        match finding {
            Some(finding) => {
                println!("{}", format!("Verifying finding: {}", finding.title).cyan());

                if args.recheck {
                    let verifier = FindingVerifier::new(storage.clone());
                    let result = verifier.verify(&finding).await?;

                    if result.verified {
                        println!("{}", "✓ Finding verified".green().bold());
                        storage.update_finding_status(&args.id, "verified", args.notes.as_deref()).await?;
                    } else {
                        println!("{}", "✗ Finding could not be verified".yellow());
                        println!("  Reason: {}", result.reason);
                    }
                } else {
                    storage.update_finding_status(&args.id, "verified", args.notes.as_deref()).await?;
                    println!("{}", "✓ Finding marked as verified".green().bold());
                }

                Ok(0)
            }
            None => {
                println!(
                    "{}",
                    format!("Finding '{}' not found.", args.id).red()
                );
                Ok(8)
            }
        }
    }

    async fn handle_update(args: &FindingsUpdateArgs, storage: &Storage) -> Result<u8> {
        let finding = storage.get_finding(&args.id).await?;

        match finding {
            Some(_) => {
                let status = format!("{:?}", args.status).to_lowercase();
                storage.update_finding_status(&args.id, &status, args.notes.as_deref()).await?;
                println!(
                    "{}",
                    format!("✓ Finding '{}' updated to {}", args.id, status).green().bold()
                );
                Ok(0)
            }
            None => {
                println!(
                    "{}",
                    format!("Finding '{}' not found.", args.id).red()
                );
                Ok(8)
            }
        }
    }

    async fn handle_export(args: &FindingsExportArgs, storage: &Storage) -> Result<u8> {
        use crate::reporting::ReportGenerator;

        let findings = storage
            .list_findings(
                args.severity.as_ref().map(|s| format!("{:?}", s).to_lowercase()),
                args.scope.as_deref(),
                None,
                Some("open".to_string()),
                None,
                1000,
                "severity",
            )
            .await?;

        if findings.is_empty() {
            println!("{}", "No findings to export.".yellow());
            return Ok(0);
        }

        let generator = ReportGenerator::new();
        let content = if args.bounty_format {
            generator.generate_bounty_report(&findings)?
        } else {
            match args.format.as_str() {
                "json" => generator.generate_json(&findings)?,
                "md" | "markdown" => generator.generate_markdown(&findings)?,
                "html" => generator.generate_html(&findings)?,
                _ => {
                    println!("{}", format!("Unknown format: {}", args.format).red());
                    return Ok(8);
                }
            }
        };

        tokio::fs::write(&args.output, content).await?;
        println!(
            "{}",
            format!("✓ {} findings exported to {:?}", findings.len(), args.output).green().bold()
        );

        Ok(0)
    }

    async fn handle_remediation(args: &FindingsRemediationArgs, storage: &Storage) -> Result<u8> {
        let queue = storage.generate_remediation_queue(
            &args.scope,
            args.with_owners,
            args.with_sla,
        ).await?;

        if queue.is_empty() {
            println!("{}", "No open findings require remediation.".yellow());
            return Ok(0);
        }

        println!("{}", format!("Remediation Queue ({} items):", queue.len()).bold());
        println!();

        for item in &queue {
            let severity_color = match item.severity.as_str() {
                "critical" => item.severity.red().bold(),
                "high" => item.severity.red(),
                "medium" => item.severity.yellow(),
                _ => item.severity.blue(),
            };

            println!(
                "  {} [{}] {}",
                item.finding_id.cyan(),
                severity_color,
                item.title.bold()
            );
            println!("    Asset: {}", item.asset);
            if args.with_owners {
                println!("    Owner: {}", item.owner.as_deref().unwrap_or("Unassigned"));
            }
            if args.with_sla {
                println!("    SLA: {}", item.sla.as_deref().unwrap_or("Not set"));
            }
            println!();
        }

        Ok(0)
    }
}
