//! Asset management commands

use crate::policy::PolicyEngine;
use crate::storage::Storage;
use anyhow::Result;
use clap::{Args, Subcommand};
use colored::Colorize;

/// Asset management commands
#[derive(Subcommand, Debug)]
pub enum AssetsCommand {
    /// List assets
    List(AssetsListArgs),

    /// Show asset diff over time
    Diff(AssetsDiffArgs),

    /// Show asset details
    Show(AssetsShowArgs),

    /// Tag an asset
    Tag(AssetsTagArgs),

    /// Export assets
    Export(AssetsExportArgs),
}

#[derive(Args, Debug)]
pub struct AssetsListArgs {
    /// Filter by scope
    #[arg(short, long)]
    pub scope: Option<String>,

    /// Filter by asset type (domain, ip, service, etc.)
    #[arg(short = 't', long)]
    pub asset_type: Option<String>,

    /// Filter by tag
    #[arg(long)]
    pub tag: Option<String>,

    /// Maximum results
    #[arg(short, long, default_value = "100")]
    pub limit: usize,
}

#[derive(Args, Debug)]
pub struct AssetsDiffArgs {
    /// Scope ID
    #[arg(short, long)]
    pub scope: String,

    /// Start date (ISO format or relative like "7d", "30d")
    #[arg(long)]
    pub since: String,

    /// End date (optional, defaults to now)
    #[arg(long)]
    pub until: Option<String>,

    /// Show only additions
    #[arg(long)]
    pub added_only: bool,

    /// Show only removals
    #[arg(long)]
    pub removed_only: bool,
}

#[derive(Args, Debug)]
pub struct AssetsShowArgs {
    /// Asset ID
    #[arg(required = true)]
    pub id: String,

    /// Show full history
    #[arg(long)]
    pub history: bool,

    /// Show related findings
    #[arg(long)]
    pub findings: bool,
}

#[derive(Args, Debug)]
pub struct AssetsTagArgs {
    /// Asset ID
    #[arg(required = true)]
    pub id: String,

    /// Tags to add
    #[arg(short, long, value_delimiter = ',')]
    pub add: Option<Vec<String>>,

    /// Tags to remove
    #[arg(short, long, value_delimiter = ',')]
    pub remove: Option<Vec<String>>,
}

#[derive(Args, Debug)]
pub struct AssetsExportArgs {
    /// Scope ID
    #[arg(short, long)]
    pub scope: String,

    /// Output format (json, csv, yaml)
    #[arg(short, long, default_value = "json")]
    pub format: String,

    /// Output file
    #[arg(short, long)]
    pub output: std::path::PathBuf,
}

impl AssetsCommand {
    pub async fn execute(&self, storage: &Storage, _policy: &PolicyEngine) -> Result<u8> {
        match self {
            AssetsCommand::List(args) => Self::handle_list(args, storage).await,
            AssetsCommand::Diff(args) => Self::handle_diff(args, storage).await,
            AssetsCommand::Show(args) => Self::handle_show(args, storage).await,
            AssetsCommand::Tag(args) => Self::handle_tag(args, storage).await,
            AssetsCommand::Export(args) => Self::handle_export(args, storage).await,
        }
    }

    async fn handle_list(args: &AssetsListArgs, storage: &Storage) -> Result<u8> {
        let assets = storage
            .list_assets(
                args.scope.as_deref(),
                args.asset_type.as_deref(),
                args.tag.as_deref(),
                args.limit,
            )
            .await?;

        if assets.is_empty() {
            println!("{}", "No assets found.".yellow());
            return Ok(0);
        }

        println!("{}", format!("Assets ({}):", assets.len()).bold());
        println!();

        for asset in &assets {
            let type_color = match asset.asset_type.as_str() {
                "domain" => asset.asset_type.cyan(),
                "subdomain" => asset.asset_type.blue(),
                "ip" => asset.asset_type.green(),
                "service" => asset.asset_type.yellow(),
                _ => asset.asset_type.normal(),
            };

            println!("  {} [{}] {}", asset.id.cyan(), type_color, asset.value.bold());
            if !asset.tags.is_empty() {
                println!("    Tags: {}", asset.tags.join(", "));
            }
            println!("    First seen: {} | Last seen: {}", asset.first_seen, asset.last_seen);
            println!();
        }

        Ok(0)
    }

    async fn handle_diff(args: &AssetsDiffArgs, storage: &Storage) -> Result<u8> {
        let diff = storage
            .get_asset_diff(&args.scope, &args.since, args.until.as_deref())
            .await?;

        println!(
            "{}",
            format!("Asset Diff: {} (since {})", args.scope, args.since).bold()
        );
        println!();

        if !args.removed_only {
            if diff.added.is_empty() {
                println!("{}", "No assets added.".yellow());
            } else {
                println!("{}", format!("Added ({}):", diff.added.len()).green().bold());
                for asset in &diff.added {
                    println!("  {} {} [{}]", "+".green(), asset.value, asset.asset_type);
                }
            }
            println!();
        }

        if !args.added_only {
            if diff.removed.is_empty() {
                println!("{}", "No assets removed.".yellow());
            } else {
                println!("{}", format!("Removed ({}):", diff.removed.len()).red().bold());
                for asset in &diff.removed {
                    println!("  {} {} [{}]", "-".red(), asset.value, asset.asset_type);
                }
            }
            println!();
        }

        if diff.modified.is_empty() {
            if !args.added_only && !args.removed_only {
                println!("{}", "No assets modified.".yellow());
            }
        } else if !args.added_only && !args.removed_only {
            println!(
                "{}",
                format!("Modified ({}):", diff.modified.len()).yellow().bold()
            );
            for asset in &diff.modified {
                println!("  {} {} [{}]", "~".yellow(), asset.value, asset.asset_type);
            }
        }

        Ok(0)
    }

    async fn handle_show(args: &AssetsShowArgs, storage: &Storage) -> Result<u8> {
        let asset = storage.get_asset(&args.id).await?;

        match asset {
            Some(asset) => {
                println!("{}", format!("Asset: {}", asset.value).bold());
                println!("{}", "─".repeat(60));
                println!();
                println!("  {} {}", "ID:".bold(), asset.id);
                println!("  {} {}", "Type:".bold(), asset.asset_type);
                println!("  {} {}", "Scope:".bold(), asset.scope_id);
                println!("  {} {}", "First seen:".bold(), asset.first_seen);
                println!("  {} {}", "Last seen:".bold(), asset.last_seen);
                println!("  {} {}", "Tags:".bold(), asset.tags.join(", "));
                println!();

                if let Some(metadata) = &asset.metadata {
                    println!("{}", "Metadata:".bold());
                    println!("{}", serde_json::to_string_pretty(metadata)?);
                    println!();
                }

                if args.history {
                    println!("{}", "History:".bold());
                    let history = storage.get_asset_history(&args.id).await?;
                    for event in &history {
                        println!(
                            "  {} {} - {}",
                            event.timestamp, event.event_type, event.description
                        );
                    }
                    println!();
                }

                if args.findings {
                    println!("{}", "Related Findings:".bold());
                    let findings = storage.get_findings_for_asset(&args.id).await?;
                    if findings.is_empty() {
                        println!("  No findings.");
                    } else {
                        for finding in &findings {
                            println!(
                                "  {} [{}] {}",
                                finding.id.cyan(),
                                finding.severity,
                                finding.title
                            );
                        }
                    }
                }

                Ok(0)
            }
            None => {
                println!("{}", format!("Asset '{}' not found.", args.id).red());
                Ok(8)
            }
        }
    }

    async fn handle_tag(args: &AssetsTagArgs, storage: &Storage) -> Result<u8> {
        let asset = storage.get_asset(&args.id).await?;

        match asset {
            Some(_) => {
                if let Some(add_tags) = &args.add {
                    storage.add_asset_tags(&args.id, add_tags).await?;
                    println!(
                        "{}",
                        format!("✓ Added tags: {}", add_tags.join(", ")).green()
                    );
                }

                if let Some(remove_tags) = &args.remove {
                    storage.remove_asset_tags(&args.id, remove_tags).await?;
                    println!(
                        "{}",
                        format!("✓ Removed tags: {}", remove_tags.join(", ")).yellow()
                    );
                }

                Ok(0)
            }
            None => {
                println!("{}", format!("Asset '{}' not found.", args.id).red());
                Ok(8)
            }
        }
    }

    async fn handle_export(args: &AssetsExportArgs, storage: &Storage) -> Result<u8> {
        let assets = storage
            .list_assets(Some(&args.scope), None, None, 100000)
            .await?;

        if assets.is_empty() {
            println!("{}", "No assets to export.".yellow());
            return Ok(0);
        }

        let content = match args.format.as_str() {
            "json" => serde_json::to_string_pretty(&assets)?,
            "yaml" => serde_yaml::to_string(&assets)?,
            "csv" => {
                let mut csv = String::from("id,type,value,scope,first_seen,last_seen,tags\n");
                for asset in &assets {
                    csv.push_str(&format!(
                        "{},{},{},{},{},{},\"{}\"\n",
                        asset.id,
                        asset.asset_type,
                        asset.value,
                        asset.scope_id,
                        asset.first_seen,
                        asset.last_seen,
                        asset.tags.join(";")
                    ));
                }
                csv
            }
            _ => {
                println!("{}", format!("Unknown format: {}", args.format).red());
                return Ok(8);
            }
        };

        tokio::fs::write(&args.output, content).await?;
        println!(
            "{}",
            format!("✓ {} assets exported to {:?}", assets.len(), args.output)
                .green()
                .bold()
        );

        Ok(0)
    }
}
