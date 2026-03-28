//! Scope management commands

use crate::policy::PolicyEngine;
use crate::storage::Storage;
use anyhow::Result;
use clap::{Args, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

/// Scope management commands
#[derive(Subcommand, Debug)]
pub enum ScopeCommand {
    /// Import scope from a YAML file
    Import(ScopeImportArgs),

    /// List all defined scopes
    List(ScopeListArgs),

    /// Show scope details
    Show(ScopeShowArgs),

    /// Validate a scope definition
    Validate(ScopeValidateArgs),

    /// Delete a scope
    Delete(ScopeDeleteArgs),

    /// Export scope to file
    Export(ScopeExportArgs),
}

#[derive(Args, Debug)]
pub struct ScopeImportArgs {
    /// Path to scope YAML file
    #[arg(short, long)]
    pub file: PathBuf,

    /// Program name to associate with this scope
    #[arg(short, long)]
    pub program: Option<String>,

    /// Overwrite existing scope with same ID
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ScopeListArgs {
    /// Filter by program name
    #[arg(short, long)]
    pub program: Option<String>,

    /// Show only active scopes
    #[arg(long)]
    pub active_only: bool,
}

#[derive(Args, Debug)]
pub struct ScopeShowArgs {
    /// Scope ID to show
    #[arg(required = true)]
    pub id: String,

    /// Show full details including all items
    #[arg(long)]
    pub full: bool,
}

#[derive(Args, Debug)]
pub struct ScopeValidateArgs {
    /// Path to scope YAML file
    #[arg(short, long)]
    pub file: PathBuf,

    /// Strict validation mode
    #[arg(long)]
    pub strict: bool,
}

#[derive(Args, Debug)]
pub struct ScopeDeleteArgs {
    /// Scope ID to delete
    #[arg(required = true)]
    pub id: String,

    /// Skip confirmation prompt
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ScopeExportArgs {
    /// Scope ID to export
    #[arg(required = true)]
    pub id: String,

    /// Output file path
    #[arg(short, long)]
    pub output: PathBuf,
}

impl ScopeCommand {
    pub async fn execute(&self, storage: &Storage, policy: &PolicyEngine) -> Result<u8> {
        match self {
            ScopeCommand::Import(args) => Self::handle_import(args, storage, policy).await,
            ScopeCommand::List(args) => Self::handle_list(args, storage).await,
            ScopeCommand::Show(args) => Self::handle_show(args, storage).await,
            ScopeCommand::Validate(args) => Self::handle_validate(args).await,
            ScopeCommand::Delete(args) => Self::handle_delete(args, storage).await,
            ScopeCommand::Export(args) => Self::handle_export(args, storage).await,
        }
    }

    async fn handle_import(
        args: &ScopeImportArgs,
        storage: &Storage,
        _policy: &PolicyEngine,
    ) -> Result<u8> {
        use crate::scope::{ScopeDefinition, ScopeEngine};

        println!("{}", "Importing scope...".cyan());

        // Read and parse the scope file
        let content = tokio::fs::read_to_string(&args.file).await?;
        let definition: ScopeDefinition = serde_yaml::from_str(&content)?;

        // Validate the scope
        let engine = ScopeEngine::new();
        let validation_result = engine.validate_definition(&definition)?;

        if !validation_result.is_valid {
            println!("{}", "Scope validation failed:".red().bold());
            for error in &validation_result.errors {
                println!("  {} {}", "✗".red(), error);
            }
            return Ok(8); // INVALID_INPUT
        }

        // Check for existing scope
        if let Some(existing) = storage.get_scope(&definition.id).await? {
            if !args.force {
                println!(
                    "{}",
                    format!(
                        "Scope '{}' already exists. Use --force to overwrite.",
                        existing.id
                    )
                    .yellow()
                );
                return Ok(8);
            }
            println!(
                "{}",
                format!("Overwriting existing scope '{}'", existing.id).yellow()
            );
        }

        // Import the scope
        let scope = engine.create_scope(definition, args.program.clone())?;
        storage.save_scope(&scope).await?;

        println!("{}", "✓ Scope imported successfully".green().bold());
        println!();
        println!("  {} {}", "ID:".bold(), scope.id);
        println!("  {} {}", "Name:".bold(), scope.name);
        println!("  {} {}", "Items:".bold(), scope.items.len());

        if !validation_result.warnings.is_empty() {
            println!();
            println!("{}", "Warnings:".yellow());
            for warning in &validation_result.warnings {
                println!("  {} {}", "⚠".yellow(), warning);
            }
        }

        Ok(0)
    }

    async fn handle_list(args: &ScopeListArgs, storage: &Storage) -> Result<u8> {
        let scopes = storage.list_scopes(args.program.as_deref()).await?;

        if scopes.is_empty() {
            println!("{}", "No scopes found.".yellow());
            println!();
            println!(
                "Import a scope with: {}",
                "aegis scope import --file scope.yaml".cyan()
            );
            return Ok(0);
        }

        println!("{}", "Scopes:".bold());
        println!();

        for scope in scopes {
            if args.active_only && !scope.active {
                continue;
            }

            let status = if scope.active {
                "active".green()
            } else {
                "inactive".yellow()
            };

            println!(
                "  {} {} [{}]",
                scope.id.cyan().bold(),
                scope.name,
                status
            );
            println!(
                "    {} domains, {} CIDRs, {} wildcards",
                scope.domain_count, scope.cidr_count, scope.wildcard_count
            );
            if let Some(program) = &scope.program {
                println!("    Program: {}", program.cyan());
            }
            println!();
        }

        Ok(0)
    }

    async fn handle_show(args: &ScopeShowArgs, storage: &Storage) -> Result<u8> {
        let scope = storage.get_scope(&args.id).await?;

        match scope {
            Some(scope) => {
                println!("{}", format!("Scope: {}", scope.name).bold());
                println!();
                println!("  {} {}", "ID:".bold(), scope.id);
                println!(
                    "  {} {}",
                    "Status:".bold(),
                    if scope.active { "Active".green() } else { "Inactive".yellow() }
                );
                if let Some(program) = &scope.program {
                    println!("  {} {}", "Program:".bold(), program);
                }
                println!("  {} {}", "Created:".bold(), scope.created_at);
                println!("  {} {}", "Updated:".bold(), scope.updated_at);
                println!();

                if args.full {
                    println!("{}", "In-Scope Items:".bold().green());
                    for item in &scope.items {
                        if item.in_scope {
                            println!("  {} {} ({})", "+".green(), item.value, item.item_type);
                        }
                    }
                    println!();

                    let out_of_scope: Vec<_> =
                        scope.items.iter().filter(|i| !i.in_scope).collect();
                    if !out_of_scope.is_empty() {
                        println!("{}", "Out-of-Scope Items:".bold().red());
                        for item in out_of_scope {
                            println!("  {} {} ({})", "-".red(), item.value, item.item_type);
                        }
                    }
                } else {
                    println!(
                        "  {} in-scope items, {} out-of-scope items",
                        scope.items.iter().filter(|i| i.in_scope).count(),
                        scope.items.iter().filter(|i| !i.in_scope).count()
                    );
                    println!();
                    println!("Use {} for full details", "--full".cyan());
                }

                Ok(0)
            }
            None => {
                println!(
                    "{}",
                    format!("Scope '{}' not found.", args.id).red()
                );
                Ok(8)
            }
        }
    }

    async fn handle_validate(args: &ScopeValidateArgs) -> Result<u8> {
        use crate::scope::{ScopeDefinition, ScopeEngine};

        println!("{}", "Validating scope...".cyan());

        let content = tokio::fs::read_to_string(&args.file).await?;
        let definition: ScopeDefinition = serde_yaml::from_str(&content)?;

        let engine = ScopeEngine::new();
        let result = engine.validate_definition(&definition)?;

        if result.is_valid {
            println!("{}", "✓ Scope is valid".green().bold());

            if !result.warnings.is_empty() {
                println!();
                println!("{}", "Warnings:".yellow());
                for warning in &result.warnings {
                    println!("  {} {}", "⚠".yellow(), warning);
                }
            }

            Ok(0)
        } else {
            println!("{}", "✗ Scope validation failed".red().bold());
            println!();
            for error in &result.errors {
                println!("  {} {}", "✗".red(), error);
            }
            Ok(8)
        }
    }

    async fn handle_delete(args: &ScopeDeleteArgs, storage: &Storage) -> Result<u8> {
        use dialoguer::Confirm;

        let scope = storage.get_scope(&args.id).await?;

        match scope {
            Some(scope) => {
                if !args.force {
                    let confirmed = Confirm::new()
                        .with_prompt(format!(
                            "Delete scope '{}' ({})? This cannot be undone.",
                            scope.id, scope.name
                        ))
                        .default(false)
                        .interact()?;

                    if !confirmed {
                        println!("{}", "Deletion cancelled.".yellow());
                        return Ok(0);
                    }
                }

                storage.delete_scope(&args.id).await?;
                println!(
                    "{}",
                    format!("✓ Scope '{}' deleted", args.id).green().bold()
                );
                Ok(0)
            }
            None => {
                println!(
                    "{}",
                    format!("Scope '{}' not found.", args.id).red()
                );
                Ok(8)
            }
        }
    }

    async fn handle_export(args: &ScopeExportArgs, storage: &Storage) -> Result<u8> {
        let scope = storage.get_scope(&args.id).await?;

        match scope {
            Some(scope) => {
                let yaml = serde_yaml::to_string(&scope)?;
                tokio::fs::write(&args.output, yaml).await?;
                println!(
                    "{}",
                    format!("✓ Scope exported to {:?}", args.output).green().bold()
                );
                Ok(0)
            }
            None => {
                println!(
                    "{}",
                    format!("Scope '{}' not found.", args.id).red()
                );
                Ok(8)
            }
        }
    }
}
