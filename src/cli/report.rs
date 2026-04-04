//! Report generation commands

use crate::policy::PolicyEngine;
use crate::storage::{FindingContext, Storage};
use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use std::path::PathBuf;

/// Report generation commands
#[derive(Subcommand, Debug)]
pub enum ReportCommand {
    /// Export report
    Export(ReportExportArgs),

    /// Generate executive summary
    Summary(ReportSummaryArgs),

    /// List available report templates
    Templates(ReportTemplatesArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, Default)]
pub enum ReportFormat {
    #[default]
    Json,
    Markdown,
    Html,
}

#[derive(Args, Debug)]
pub struct ReportExportArgs {
    /// Output format
    #[arg(short, long, value_enum, default_value = "json")]
    pub format: ReportFormat,

    /// Output file path
    #[arg(short, long)]
    pub output: PathBuf,

    /// Scope ID to report on
    #[arg(long)]
    pub scope: Option<String>,

    /// Scan run ID to report on
    #[arg(long)]
    pub run: Option<String>,

    /// Include only findings with minimum severity
    #[arg(long)]
    pub min_severity: Option<String>,

    /// Report type (technical, executive, bounty)
    #[arg(short, long, default_value = "technical")]
    pub report_type: String,

    /// Include evidence in report
    #[arg(long)]
    pub with_evidence: bool,
}

#[derive(Args, Debug)]
pub struct ReportSummaryArgs {
    /// Scope ID
    #[arg(short, long)]
    pub scope: String,

    /// Time period (7d, 30d, 90d)
    #[arg(long, default_value = "30d")]
    pub period: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "markdown")]
    pub format: ReportFormat,

    /// Output file (optional, prints to stdout if not specified)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ReportTemplatesArgs {
    /// Show template details
    #[arg(long)]
    pub verbose: bool,
}

impl ReportCommand {
    pub async fn execute(&self, storage: &Storage, _policy: &PolicyEngine) -> Result<u8> {
        match self {
            ReportCommand::Export(args) => Self::handle_export(args, storage).await,
            ReportCommand::Summary(args) => Self::handle_summary(args, storage).await,
            ReportCommand::Templates(args) => Self::handle_templates(args).await,
        }
    }

    async fn handle_export(args: &ReportExportArgs, storage: &Storage) -> Result<u8> {
        use crate::reporting::ReportGenerator;

        println!("{}", "Generating report...".cyan());

        // Gather findings
        let findings = storage
            .list_findings(
                args.min_severity.clone(),
                FindingContext {
                    scope: args.scope.as_deref(),
                    run: args.run.as_deref(),
                },
                None,
                None,
                10000,
                "severity",
            )
            .await?;

        if findings.is_empty() {
            println!("{}", "No findings to report.".yellow());
            return Ok(0);
        }

        let generator = ReportGenerator::new();

        let content = match (&args.report_type.as_str(), &args.format) {
            (&"bounty", _) => generator.generate_bounty_report(&findings)?,
            (&"executive", ReportFormat::Html) => generator.generate_executive_html(&findings)?,
            (&"executive", _) => generator.generate_executive_markdown(&findings)?,
            (_, ReportFormat::Json) => generator.generate_json(&findings)?,
            (_, ReportFormat::Markdown) => generator.generate_markdown(&findings)?,
            (_, ReportFormat::Html) => generator.generate_html(&findings)?,
        };

        tokio::fs::write(&args.output, content).await?;

        println!(
            "{}",
            format!(
                "✓ Report generated: {:?} ({} findings)",
                args.output,
                findings.len()
            )
            .green()
            .bold()
        );

        Ok(0)
    }

    async fn handle_summary(args: &ReportSummaryArgs, storage: &Storage) -> Result<u8> {
        use crate::reporting::ReportGenerator;

        let summary = storage
            .get_attack_surface_summary(&args.scope, &args.period)
            .await?;

        let generator = ReportGenerator::new();
        let content = match args.format {
            ReportFormat::Json => serde_json::to_string_pretty(&summary)?,
            ReportFormat::Markdown => generator.generate_summary_markdown(&summary)?,
            ReportFormat::Html => generator.generate_summary_html(&summary)?,
        };

        match &args.output {
            Some(path) => {
                tokio::fs::write(path, &content).await?;
                println!(
                    "{}",
                    format!("✓ Summary exported to {:?}", path).green().bold()
                );
            }
            None => {
                println!("{}", content);
            }
        }

        Ok(0)
    }

    async fn handle_templates(_args: &ReportTemplatesArgs) -> Result<u8> {
        println!("{}", "Available Report Templates:".bold());
        println!();

        println!("{}", "technical".cyan().bold());
        println!("  Full technical report with all findings and evidence");
        println!("  Formats: JSON, Markdown, HTML");
        println!();

        println!("{}", "executive".cyan().bold());
        println!("  High-level summary for stakeholders");
        println!("  Formats: Markdown, HTML");
        println!();

        println!("{}", "bounty".cyan().bold());
        println!("  Bug bounty submission-ready format");
        println!("  Includes: title, impact, reproduction, evidence, scope mapping");
        println!("  Formats: Markdown");
        println!();

        Ok(0)
    }
}
