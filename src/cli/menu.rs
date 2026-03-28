//! Interactive menu system for AegisOSINT

use crate::config::Config;
use crate::defensive::DefensiveScanner;
use crate::offensive::OffensiveOrchestrator;
use crate::policy::PolicyEngine;
use crate::scope::{Scope, ScopeDefinition, ScopeEngine, ScopeItem, ScopeItemType};
use crate::reporting::ReportGenerator;
use crate::storage::Storage;
use crate::utils::validation::{validate_asn, validate_cidr, validate_domain, validate_url};
use anyhow::Result;
use chrono::Utc;
use colored::Colorize;
use std::io::{self, Write};
use super::offensive::ScanProfile;

/// Main menu options
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MainMenuOption {
    OffensiveMode,
    DefensiveMode,
    ManageScopes,
    ViewFindings,
    GenerateReports,
    ManageAssets,
    Settings,
    Help,
    Quit,
}

/// Offensive mode options
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OffensiveMenuOption {
    RunRecon,
    ViewStatus,
    StopScan,
    ViewResults,
    Back,
}

/// Defensive mode options
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DefensiveMenuOption {
    StartMonitor,
    StopMonitor,
    ViewAlerts,
    ConfigureAlerts,
    Back,
}

/// Scope management options
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScopeMenuOption {
    ImportScope,
    CreateScope,
    AddTarget,
    ListScopes,
    ViewScope,
    ValidateTarget,
    DeleteScope,
    Back,
}

/// Settings menu options
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SettingsMenuOption {
    ViewSettings,
    EditRateLimit,
    EditTimeout,
    EditUserAgent,
    EditDatabase,
    ResetDefaults,
    Back,
}

/// Interactive menu system
pub struct Menu {
    width: usize,
    storage: Option<Storage>,
    config: Option<Config>,
}

impl Menu {
    pub fn new() -> Self {
        Self { 
            width: 60,
            storage: None,
            config: None,
        }
    }

    /// Create menu with storage and config
    pub fn with_storage_and_config(storage: Storage, config: Config) -> Self {
        Self {
            width: 60,
            storage: Some(storage),
            config: Some(config),
        }
    }

    async fn update_config<F>(&mut self, mutator: F) -> Result<()>
    where
        F: FnOnce(&mut Config),
    {
        if let Some(ref mut config) = self.config {
            mutator(config);
            config.save().await?;
            Ok(())
        } else {
            anyhow::bail!("Settings not loaded")
        }
    }

    /// Clear screen
    fn clear(&self) {
        print!("\x1B[2J\x1B[1;1H");
        io::stdout().flush().unwrap();
    }

    /// Print centered text
    fn center(&self, text: &str) -> String {
        let padding = (self.width.saturating_sub(text.len())) / 2;
        format!("{:padding$}{}", "", text, padding = padding)
    }

    /// Print a horizontal line
    fn line(&self) -> String {
        "─".repeat(self.width)
    }

    /// Print the banner
    pub fn print_banner(&self) {
        self.clear();
        println!();
        println!("{}", self.center("╔═══════════════════════════════════════════╗").cyan());
        println!("{}", self.center("║            AegisOSINT v0.1.0              ║").cyan());
        println!("{}", self.center("║   Production OSINT for Bug Bounty & Defense  ║").cyan());
        println!("{}", self.center("╚═══════════════════════════════════════════╝").cyan());
        println!();
        println!("{}", self.center("⚠️  AUTHORIZED USE ONLY").yellow().bold());
        println!();
    }

    /// Print a section header
    fn print_header(&self, title: &str) {
        println!();
        println!("  {} {}", "▶".cyan(), title.bold());
        println!("  {}", self.line().dimmed());
    }

    /// Read user input
    fn read_input(&self, prompt: &str) -> String {
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    }

    /// Read a single character
    fn read_char(&self, prompt: &str) -> char {
        let input = self.read_input(prompt);
        input.chars().next().unwrap_or(' ')
    }

    /// Wait for enter
    fn wait_enter(&self) {
        self.read_input(&format!("\n  {} Press Enter to continue...", "→".dimmed()));
    }

    /// Show main menu and get selection
    pub fn main_menu(&self) -> MainMenuOption {
        self.print_banner();
        self.print_header("Main Menu");
        
        println!();
        println!("  {}  {} Offensive Recon", "1".cyan().bold(), "🎯".to_string());
        println!("     {}", "Bug bounty reconnaissance operations".dimmed());
        println!();
        println!("  {}  {} Defensive Monitor", "2".cyan().bold(), "🛡️".to_string());
        println!("     {}", "Attack surface monitoring".dimmed());
        println!();
        println!("  {}  {} Manage Scopes", "3".cyan().bold(), "📋".to_string());
        println!("     {}", "Import, view, and validate scopes".dimmed());
        println!();
        println!("  {}  {} View Findings", "4".cyan().bold(), "🔍".to_string());
        println!("     {}", "Browse and verify discoveries".dimmed());
        println!();
        println!("  {}  {} Generate Reports", "5".cyan().bold(), "📊".to_string());
        println!("     {}", "Export JSON, Markdown, HTML reports".dimmed());
        println!();
        println!("  {}  {} Manage Assets", "6".cyan().bold(), "🌐".to_string());
        println!("     {}", "View and track discovered assets".dimmed());
        println!();
        println!("  {}  {} Settings", "7".cyan().bold(), "⚙️".to_string());
        println!("     {}", "Configure rate limits, database, etc.".dimmed());
        println!();
        println!("  {}  {} Help", "h".cyan().bold(), "❓".to_string());
        println!("     {}", "Documentation and usage guide".dimmed());
        println!();
        println!("  {}  {} Quit", "q".cyan().bold(), "🚪".to_string());
        println!();

        let choice = self.read_char(&format!("  {} ", "Select option:".bold()));
        
        match choice {
            '1' => MainMenuOption::OffensiveMode,
            '2' => MainMenuOption::DefensiveMode,
            '3' => MainMenuOption::ManageScopes,
            '4' => MainMenuOption::ViewFindings,
            '5' => MainMenuOption::GenerateReports,
            '6' => MainMenuOption::ManageAssets,
            '7' => MainMenuOption::Settings,
            'h' | 'H' => MainMenuOption::Help,
            'q' | 'Q' => MainMenuOption::Quit,
            _ => MainMenuOption::Help,
        }
    }

    /// Show offensive mode menu
    pub fn offensive_menu(&self) -> OffensiveMenuOption {
        self.print_banner();
        self.print_header("Offensive Recon 🎯");
        
        println!();
        println!("  {}  {} Run Reconnaissance", "1".cyan().bold(), "▶".green());
        println!("     {}", "Start a new recon scan against a scope".dimmed());
        println!();
        println!("  {}  {} View Running Scans", "2".cyan().bold(), "📡".to_string());
        println!("     {}", "Check status of active operations".dimmed());
        println!();
        println!("  {}  {} Stop Scan", "3".cyan().bold(), "⏹".red());
        println!("     {}", "Terminate a running scan".dimmed());
        println!();
        println!("  {}  {} View Results", "4".cyan().bold(), "📋".to_string());
        println!("     {}", "Browse scan results and findings".dimmed());
        println!();
        println!("  {}  ← Back to Main Menu", "b".cyan().bold());
        println!();

        let choice = self.read_char(&format!("  {} ", "Select option:".bold()));
        
        match choice {
            '1' => OffensiveMenuOption::RunRecon,
            '2' => OffensiveMenuOption::ViewStatus,
            '3' => OffensiveMenuOption::StopScan,
            '4' => OffensiveMenuOption::ViewResults,
            'b' | 'B' | 'q' | 'Q' => OffensiveMenuOption::Back,
            _ => OffensiveMenuOption::Back,
        }
    }

    /// Show defensive mode menu
    pub fn defensive_menu(&self) -> DefensiveMenuOption {
        self.print_banner();
        self.print_header("Defensive Monitor 🛡️");
        
        println!();
        println!("  {}  {} Start Monitoring", "1".cyan().bold(), "▶".green());
        println!("     {}", "Begin attack surface monitoring".dimmed());
        println!();
        println!("  {}  {} Stop Monitoring", "2".cyan().bold(), "⏹".red());
        println!("     {}", "Stop active monitors".dimmed());
        println!();
        println!("  {}  {} View Alerts", "3".cyan().bold(), "🔔".to_string());
        println!("     {}", "Review recent alerts and changes".dimmed());
        println!();
        println!("  {}  {} Configure Alerts", "4".cyan().bold(), "⚙️".to_string());
        println!("     {}", "Set up alert rules and thresholds".dimmed());
        println!();
        println!("  {}  ← Back to Main Menu", "b".cyan().bold());
        println!();

        let choice = self.read_char(&format!("  {} ", "Select option:".bold()));
        
        match choice {
            '1' => DefensiveMenuOption::StartMonitor,
            '2' => DefensiveMenuOption::StopMonitor,
            '3' => DefensiveMenuOption::ViewAlerts,
            '4' => DefensiveMenuOption::ConfigureAlerts,
            'b' | 'B' | 'q' | 'Q' => DefensiveMenuOption::Back,
            _ => DefensiveMenuOption::Back,
        }
    }

    /// Show scope management menu
    pub fn scope_menu(&self) -> ScopeMenuOption {
        self.print_banner();
        self.print_header("Manage Scopes 📋");
        
        println!();
        println!("  {}  {} Import Scope", "1".cyan().bold(), "📥".to_string());
        println!("     {}", "Import scope from YAML file".dimmed());
        println!();
        println!("  {}  {} Create Scope", "2".cyan().bold(), "➕".to_string());
        println!("     {}", "Create a new scope manually".dimmed());
        println!();
        println!("  {}  {} Add Target to Scope", "3".cyan().bold(), "🎯".to_string());
        println!("     {}", "Add domain, CIDR, or URL to a scope".dimmed());
        println!();
        println!("  {}  {} List Scopes", "4".cyan().bold(), "📃".to_string());
        println!("     {}", "View all imported scopes".dimmed());
        println!();
        println!("  {}  {} View Scope Details", "5".cyan().bold(), "🔎".to_string());
        println!("     {}", "Inspect a specific scope".dimmed());
        println!();
        println!("  {}  {} Validate Target", "6".cyan().bold(), "✓".green());
        println!("     {}", "Check if a target is in scope".dimmed());
        println!();
        println!("  {}  {} Delete Scope", "7".cyan().bold(), "🗑".red());
        println!("     {}", "Remove a scope from the database".dimmed());
        println!();
        println!("  {}  ← Back to Main Menu", "b".cyan().bold());
        println!();

        let choice = self.read_char(&format!("  {} ", "Select option:".bold()));
        
        match choice {
            '1' => ScopeMenuOption::ImportScope,
            '2' => ScopeMenuOption::CreateScope,
            '3' => ScopeMenuOption::AddTarget,
            '4' => ScopeMenuOption::ListScopes,
            '5' => ScopeMenuOption::ViewScope,
            '6' => ScopeMenuOption::ValidateTarget,
            '7' => ScopeMenuOption::DeleteScope,
            'b' | 'B' | 'q' | 'Q' => ScopeMenuOption::Back,
            _ => ScopeMenuOption::Back,
        }
    }

    /// Show help screen
    pub fn show_help(&self) {
        self.print_banner();
        self.print_header("Help & Documentation ❓");
        
        println!();
        println!("  {}", "AegisOSINT is a production-grade OSINT platform for:".bold());
        println!();
        println!("  • {} - Authorized bug bounty reconnaissance", "Offensive Mode".cyan());
        println!("    Asset discovery, web recon, cloud exposure checks");
        println!();
        println!("  • {} - External attack surface monitoring", "Defensive Mode".cyan());
        println!("    Drift detection, brand monitoring, leak alerts");
        println!();
        println!("  {}", self.line().dimmed());
        println!();
        println!("  {}", "Quick Commands:".bold());
        println!();
        println!("    aegis scope import --file scope.yaml");
        println!("    aegis offensive run --scope <id> --profile safe");
        println!("    aegis defensive monitor --scope <id>");
        println!("    aegis findings list --severity high");
        println!("    aegis report export --format md");
        println!();
        println!("  {}", self.line().dimmed());
        println!();
        println!("  {}", "⚠️  Legal Notice:".yellow().bold());
        println!("  Only use on systems you have explicit authorization to test.");
        println!("  Unauthorized access is illegal and may result in prosecution.");
        println!();
        
        self.wait_enter();
    }

    /// Prompt for file path
    pub fn prompt_file(&self, prompt: &str) -> String {
        println!();
        self.read_input(&format!("  {} {}: ", "📁".to_string(), prompt))
    }

    /// Prompt for scope selection
    pub fn prompt_scope(&self, scopes: &[(String, String)]) -> Option<String> {
        if scopes.is_empty() {
            println!();
            println!("  {} No scopes found. Import a scope first.", "⚠".yellow());
            self.wait_enter();
            return None;
        }

        println!();
        println!("  {}", "Available Scopes:".bold());
        println!();
        
        for (i, (id, name)) in scopes.iter().enumerate() {
            println!("  {}  {} ({})", format!("{}", i + 1).cyan().bold(), name, id.dimmed());
        }
        
        println!();
        let input = self.read_input(&format!("  {} Select scope (number or ID): ", "→".cyan()));
        
        // Try as number first
        if let Ok(num) = input.parse::<usize>() {
            if num > 0 && num <= scopes.len() {
                return Some(scopes[num - 1].0.clone());
            }
        }
        
        // Try as ID
        if scopes.iter().any(|(id, _)| id == &input) {
            return Some(input);
        }
        
        None
    }

    /// Prompt for profile selection
    pub fn prompt_profile(&self) -> String {
        println!();
        println!("  {}", "Scan Profiles:".bold());
        println!();
        println!("  {}  {} - Passive only, minimal requests", "1".cyan().bold(), "safe".green());
        println!("  {}  {} - Balanced recon with rate limiting", "2".cyan().bold(), "standard".yellow());
        println!();
        
        let choice = self.read_char(&format!("  {} Select profile [1]: ", "→".cyan()));
        
        match choice {
            '2' => "standard".to_string(),
            _ => "safe".to_string(),
        }
    }

    /// Prompt for severity filter
    pub fn prompt_severity(&self) -> Option<String> {
        println!();
        println!("  {}", "Filter by Severity:".bold());
        println!();
        println!("  {}  {} Critical", "1".cyan().bold(), "🔴".to_string());
        println!("  {}  {} High", "2".cyan().bold(), "🟠".to_string());
        println!("  {}  {} Medium", "3".cyan().bold(), "🟡".to_string());
        println!("  {}  {} Low", "4".cyan().bold(), "🟢".to_string());
        println!("  {}  {} Info", "5".cyan().bold(), "🔵".to_string());
        println!("  {}  All", "a".cyan().bold());
        println!();
        
        let choice = self.read_char(&format!("  {} Select severity [a]: ", "→".cyan()));
        
        match choice {
            '1' => Some("critical".to_string()),
            '2' => Some("high".to_string()),
            '3' => Some("medium".to_string()),
            '4' => Some("low".to_string()),
            '5' => Some("info".to_string()),
            _ => None,
        }
    }

    /// Prompt for report format
    pub fn prompt_report_format(&self) -> String {
        println!();
        println!("  {}", "Report Formats:".bold());
        println!();
        println!("  {}  {} - Machine-readable", "1".cyan().bold(), "JSON".cyan());
        println!("  {}  {} - Technical analyst report", "2".cyan().bold(), "Markdown".cyan());
        println!("  {}  {} - Executive summary", "3".cyan().bold(), "HTML".cyan());
        println!("  {}  {} - Bug bounty submission", "4".cyan().bold(), "Bounty".cyan());
        println!();
        
        let choice = self.read_char(&format!("  {} Select format [1]: ", "→".cyan()));
        
        match choice {
            '2' => "md".to_string(),
            '3' => "html".to_string(),
            '4' => "bounty".to_string(),
            _ => "json".to_string(),
        }
    }

    /// Prompt for output path
    pub fn prompt_output_path(&self, default_ext: &str) -> String {
        println!();
        let default = format!("report.{}", default_ext);
        let input = self.read_input(&format!("  {} Output file [{}]: ", "📄".to_string(), default.dimmed()));
        
        if input.is_empty() {
            default
        } else {
            input
        }
    }

    /// Prompt for target type
    pub fn prompt_target_type(&self) -> String {
        println!();
        println!("  {}", "Target Types:".bold());
        println!();
        println!("  {}  {} Domain (e.g., example.com)", "1".cyan().bold(), "🌐".to_string());
        println!("  {}  {} Wildcard (e.g., *.example.com)", "2".cyan().bold(), "✳️".to_string());
        println!("  {}  {} CIDR Range (e.g., 192.168.1.0/24)", "3".cyan().bold(), "🔢".to_string());
        println!("  {}  {} URL (e.g., https://api.example.com)", "4".cyan().bold(), "🔗".to_string());
        println!("  {}  {} ASN (e.g., AS12345)", "5".cyan().bold(), "🏢".to_string());
        println!();
        
        let choice = self.read_char(&format!("  {} Select type [1]: ", "→".cyan()));
        
        match choice {
            '2' => "wildcard".to_string(),
            '3' => "cidr".to_string(),
            '4' => "url".to_string(),
            '5' => "asn".to_string(),
            _ => "domain".to_string(),
        }
    }

    /// Prompt for target value
    pub fn prompt_target_value(&self, target_type: &str) -> String {
        println!();
        let example = match target_type {
            "wildcard" => "*.example.com",
            "cidr" => "192.168.1.0/24",
            "url" => "https://api.example.com",
            "asn" => "AS12345",
            _ => "example.com",
        };
        self.read_input(&format!("  {} Enter {} (e.g., {}): ", "🎯".to_string(), target_type, example.dimmed()))
    }

    /// Prompt for scope name
    pub fn prompt_scope_name(&self) -> String {
        println!();
        self.read_input(&format!("  {} Scope name: ", "📛".to_string()))
    }

    /// Prompt for scope description
    pub fn prompt_scope_description(&self) -> Option<String> {
        println!();
        let input = self.read_input(&format!("  {} Description (optional): ", "📝".to_string()));
        if input.is_empty() {
            None
        } else {
            Some(input)
        }
    }

    /// Prompt for program name
    pub fn prompt_program_name(&self) -> Option<String> {
        println!();
        let input = self.read_input(&format!("  {} Program name (optional, e.g., HackerOne-CompanyX): ", "🏷️".to_string()));
        if input.is_empty() {
            None
        } else {
            Some(input)
        }
    }

    /// Prompt for numeric value
    pub fn prompt_number(&self, prompt: &str, default: u32) -> u32 {
        println!();
        let input = self.read_input(&format!("  {} {} [{}]: ", "🔢".to_string(), prompt, default));
        input.parse().unwrap_or(default)
    }

    /// Prompt for string value with default
    pub fn prompt_string(&self, prompt: &str, default: &str) -> String {
        println!();
        let input = self.read_input(&format!("  {} {} [{}]: ", "📝".to_string(), prompt, default.dimmed()));
        if input.is_empty() {
            default.to_string()
        } else {
            input
        }
    }

    /// Show settings menu
    pub fn settings_menu(&self) -> SettingsMenuOption {
        self.print_banner();
        self.print_header("Settings ⚙️");
        
        println!();
        println!("  {}  {} View Current Settings", "1".cyan().bold(), "👁".to_string());
        println!("     {}", "Display all configuration values".dimmed());
        println!();
        println!("  {}  {} Edit Rate Limit", "2".cyan().bold(), "⏱".to_string());
        println!("     {}", "Set requests per second".dimmed());
        println!();
        println!("  {}  {} Edit Timeout", "3".cyan().bold(), "⌛".to_string());
        println!("     {}", "Set request timeout".dimmed());
        println!();
        println!("  {}  {} Edit User Agent", "4".cyan().bold(), "🤖".to_string());
        println!("     {}", "Set HTTP user agent string".dimmed());
        println!();
        println!("  {}  {} Database Settings", "5".cyan().bold(), "💾".to_string());
        println!("     {}", "Configure database backend".dimmed());
        println!();
        println!("  {}  {} Reset to Defaults", "6".cyan().bold(), "🔄".to_string());
        println!("     {}", "Restore default configuration".dimmed());
        println!();
        println!("  {}  ← Back to Main Menu", "b".cyan().bold());
        println!();

        let choice = self.read_char(&format!("  {} ", "Select option:".bold()));
        
        match choice {
            '1' => SettingsMenuOption::ViewSettings,
            '2' => SettingsMenuOption::EditRateLimit,
            '3' => SettingsMenuOption::EditTimeout,
            '4' => SettingsMenuOption::EditUserAgent,
            '5' => SettingsMenuOption::EditDatabase,
            '6' => SettingsMenuOption::ResetDefaults,
            'b' | 'B' | 'q' | 'Q' => SettingsMenuOption::Back,
            _ => SettingsMenuOption::Back,
        }
    }

    /// Display settings with values
    pub fn display_settings(&self, rate_limit: u32, timeout: u64, user_agent: &str, db_path: &str, db_type: &str) {
        println!();
        println!("  {}", "Current Configuration:".bold());
        println!("  {}", self.line().dimmed());
        println!();
        println!("    {:20} {}", "Database Type:".bold(), db_type.cyan());
        println!("    {:20} {}", "Database Path:".bold(), db_path.dimmed());
        println!("    {:20} {} req/s", "Rate Limit:".bold(), rate_limit.to_string().cyan());
        println!("    {:20} {} seconds", "Request Timeout:".bold(), timeout.to_string().cyan());
        println!("    {:20} {}", "User Agent:".bold(), user_agent.dimmed());
        println!();
        println!("  {}", self.line().dimmed());
    }

    /// Show scope details
    pub fn display_scope_details(&self, name: &str, description: Option<&str>, program: Option<&str>, 
                                  domains: &[String], wildcards: &[String], cidrs: &[String], urls: &[String]) {
        println!();
        println!("  {}", format!("Scope: {}", name).bold());
        println!("  {}", self.line().dimmed());
        
        if let Some(desc) = description {
            println!("  {} {}", "Description:".dimmed(), desc);
        }
        if let Some(prog) = program {
            println!("  {} {}", "Program:".dimmed(), prog.cyan());
        }
        println!();
        
        if !domains.is_empty() {
            println!("  {} Domains ({}):", "🌐".to_string(), domains.len());
            for d in domains.iter().take(10) {
                println!("     {}", d.green());
            }
            if domains.len() > 10 {
                println!("     {} ... and {} more", "".dimmed(), domains.len() - 10);
            }
            println!();
        }
        
        if !wildcards.is_empty() {
            println!("  {} Wildcards ({}):", "✳️".to_string(), wildcards.len());
            for w in wildcards.iter().take(10) {
                println!("     {}", w.green());
            }
            if wildcards.len() > 10 {
                println!("     {} ... and {} more", "".dimmed(), wildcards.len() - 10);
            }
            println!();
        }
        
        if !cidrs.is_empty() {
            println!("  {} CIDR Ranges ({}):", "🔢".to_string(), cidrs.len());
            for c in cidrs.iter().take(10) {
                println!("     {}", c.green());
            }
            if cidrs.len() > 10 {
                println!("     {} ... and {} more", "".dimmed(), cidrs.len() - 10);
            }
            println!();
        }
        
        if !urls.is_empty() {
            println!("  {} URLs ({}):", "🔗".to_string(), urls.len());
            for u in urls.iter().take(10) {
                println!("     {}", u.green());
            }
            if urls.len() > 10 {
                println!("     {} ... and {} more", "".dimmed(), urls.len() - 10);
            }
            println!();
        }
        
        println!("  {}", self.line().dimmed());
    }

    /// Show success message
    pub fn show_success(&self, message: &str) {
        println!();
        println!("  {} {}", "✓".green().bold(), message.green());
    }

    /// Show error message
    pub fn show_error(&self, message: &str) {
        println!();
        println!("  {} {}", "✗".red().bold(), message.red());
    }

    /// Show warning message
    pub fn show_warning(&self, message: &str) {
        println!();
        println!("  {} {}", "⚠".yellow().bold(), message.yellow());
    }

    /// Show info message
    pub fn show_info(&self, message: &str) {
        println!();
        println!("  {} {}", "ℹ".blue().bold(), message);
    }

    /// Confirm action
    pub fn confirm(&self, message: &str) -> bool {
        println!();
        let input = self.read_input(&format!("  {} {} [y/N]: ", "?".yellow(), message));
        matches!(input.to_lowercase().as_str(), "y" | "yes")
    }

    /// Display a progress indicator
    pub fn show_progress(&self, message: &str) {
        print!("  {} {}...", "⟳".cyan(), message);
        io::stdout().flush().unwrap();
    }

    /// Complete progress
    pub fn complete_progress(&self) {
        println!(" {}", "done".green());
    }

    /// Show a table of findings
    pub fn show_findings_table(&self, findings: &[(String, String, String, String)]) {
        println!();
        println!("  {}", "Findings:".bold());
        println!("  {}", self.line().dimmed());
        println!("  {:8} {:12} {:20} {}", "ID".bold(), "SEVERITY".bold(), "TYPE".bold(), "TARGET".bold());
        println!("  {}", self.line().dimmed());
        
        for (id, severity, finding_type, target) in findings {
            let severity_colored = match severity.as_str() {
                "critical" => severity.red().bold().to_string(),
                "high" => severity.red().to_string(),
                "medium" => severity.yellow().to_string(),
                "low" => severity.green().to_string(),
                _ => severity.blue().to_string(),
            };
            
            let short_id = if id.len() > 8 { &id[..8] } else { id };
            let short_target = if target.len() > 30 { format!("{}...", &target[..27]) } else { target.clone() };
            
            println!("  {:8} {:12} {:20} {}", short_id.dimmed(), severity_colored, finding_type, short_target);
        }
        
        println!("  {}", self.line().dimmed());
        println!();
    }

    /// Run the interactive menu loop
    pub async fn run(&mut self) -> Result<()> {
        loop {
            match self.main_menu() {
                MainMenuOption::OffensiveMode => {
                    self.run_offensive_menu().await?;
                }
                MainMenuOption::DefensiveMode => {
                    self.run_defensive_menu().await?;
                }
                MainMenuOption::ManageScopes => {
                    self.run_scope_menu().await?;
                }
                MainMenuOption::ViewFindings => {
                    self.run_findings_view().await?;
                }
                MainMenuOption::GenerateReports => {
                    self.run_report_generation().await?;
                }
                MainMenuOption::ManageAssets => {
                    self.run_assets_view().await?;
                }
                MainMenuOption::Settings => {
                    self.run_settings().await?;
                }
                MainMenuOption::Help => {
                    self.show_help();
                }
                MainMenuOption::Quit => {
                    self.print_banner();
                    println!("  {} Goodbye!", "👋".to_string());
                    println!();
                    break;
                }
            }
        }
        
        Ok(())
    }

    async fn run_offensive_menu(&mut self) -> Result<()> {
        loop {
            match self.offensive_menu() {
                OffensiveMenuOption::RunRecon => {
                    self.show_info("Starting reconnaissance wizard...");
                    
                    let scopes = self.get_scope_list().await;
                    
                    if let Some(scope_id) = self.prompt_scope(&scopes) {
                        let profile_str = self.prompt_profile();
                        let profile = match profile_str.as_str() {
                            "standard" => ScanProfile::Standard,
                            _ => ScanProfile::Safe,
                        };

                        if self.confirm("Start reconnaissance now?") {
                            if let (Some(storage), Some(config)) =
                                (self.storage.clone(), self.config.clone())
                            {
                                match storage.get_scope(&scope_id).await {
                                    Ok(Some(scope)) => {
                                        let policy = PolicyEngine::new(&config, &storage).await?;
                                        let program_name = scope
                                            .program
                                            .clone()
                                            .unwrap_or_else(|| "menu-scan".to_string());

                                        let policy_check =
                                            policy.check_offensive_operation(&program_name, &scope).await?;
                                        if !policy_check.allowed {
                                            self.show_error("Operation blocked by policy");
                                            for reason in policy_check.reasons {
                                                println!("  {} {}", "•".red(), reason);
                                            }
                                            self.wait_enter();
                                            continue;
                                        }

                                        self.show_progress("Creating scan run");
                                        let run_id =
                                            storage.create_scan_run(&program_name, &scope.id, "offensive").await?;
                                        self.complete_progress();
                                        self.show_info(&format!("Scan ID: {}", run_id));

                                        let orchestrator = OffensiveOrchestrator::new(
                                            scope,
                                            profile,
                                            10,
                                            policy,
                                            storage.clone(),
                                        );

                                        let mut last_reported = 0u8;
                                        let result = orchestrator
                                            .execute(&run_id, |stage, percent| {
                                                if percent >= last_reported.saturating_add(10) || percent == 100 {
                                                    println!("  {} [{}%] {}", "→".cyan(), percent, stage);
                                                    last_reported = percent;
                                                }
                                            })
                                            .await;

                                        match result {
                                            Ok(summary) => {
                                                self.show_success("Scan completed");
                                                println!();
                                                println!("  {} {}", "Assets discovered:".bold(), summary.assets_count);
                                                println!("  {} {}", "Findings:".bold(), summary.findings_count);
                                                println!("  {} {:.1}s", "Duration:".bold(), summary.duration_secs);
                                            }
                                            Err(e) => self.show_error(&format!("Scan failed: {}", e)),
                                        }
                                    }
                                    Ok(None) => self.show_error("Selected scope not found"),
                                    Err(e) => self.show_error(&format!("Failed to load scope: {}", e)),
                                }
                            } else {
                                self.show_error("Storage/config not initialized");
                            }
                        }
                    }
                    
                    self.wait_enter();
                }
                OffensiveMenuOption::ViewStatus => {
                    self.show_info("No active scans");
                    self.wait_enter();
                }
                OffensiveMenuOption::StopScan => {
                    self.show_info("No scans to stop");
                    self.wait_enter();
                }
                OffensiveMenuOption::ViewResults => {
                    self.show_info("No results yet");
                    self.wait_enter();
                }
                OffensiveMenuOption::Back => break,
            }
        }
        Ok(())
    }

    async fn run_defensive_menu(&mut self) -> Result<()> {
        loop {
            match self.defensive_menu() {
                DefensiveMenuOption::StartMonitor => {
                    self.show_info("Starting defensive scan...");
                    
                    let scopes = self.get_scope_list().await;
                    
                    if let Some(scope_id) = self.prompt_scope(&scopes) {
                        if self.confirm("Run defensive checks now?") {
                            if let (Some(storage), Some(config)) =
                                (self.storage.clone(), self.config.clone())
                            {
                                match storage.get_scope(&scope_id).await {
                                    Ok(Some(scope)) => {
                                        let policy = PolicyEngine::new(&config, &storage).await?;
                                        let policy_check = policy.check_defensive_operation(&scope).await?;
                                        if !policy_check.allowed {
                                            self.show_error("Defensive operation blocked by policy");
                                            for reason in policy_check.reasons {
                                                println!("  {} {}", "•".red(), reason);
                                            }
                                            self.wait_enter();
                                            continue;
                                        }

                                        let scanner =
                                            DefensiveScanner::new(scope, policy, storage.clone());
                                        let result = scanner.scan(None).await?;

                                        self.show_success("Defensive scan completed");
                                        println!();
                                        println!("  {} {}", "Assets checked:".bold(), result.assets_count);
                                        println!("  {} {}", "Changes detected:".bold(), result.changes_count);
                                        println!("  {} {}", "Exposures detected:".bold(), result.exposures_count);
                                        println!("  {} {:.1}s", "Duration:".bold(), result.duration_secs);
                                        self.show_warning(
                                            "Continuous daemon monitoring is not yet wired in the interactive menu. Use 'aegis defensive monitor --scope <id>' for continuous mode.",
                                        );
                                    }
                                    Ok(None) => self.show_error("Selected scope not found"),
                                    Err(e) => self.show_error(&format!("Failed to load scope: {}", e)),
                                }
                            } else {
                                self.show_error("Storage/config not initialized");
                            }
                        }
                    }
                    
                    self.wait_enter();
                }
                DefensiveMenuOption::StopMonitor => {
                    self.show_info("No active monitors");
                    self.wait_enter();
                }
                DefensiveMenuOption::ViewAlerts => {
                    self.show_info("No alerts");
                    self.wait_enter();
                }
                DefensiveMenuOption::ConfigureAlerts => {
                    self.show_info("Alert configuration coming soon");
                    self.wait_enter();
                }
                DefensiveMenuOption::Back => break,
            }
        }
        Ok(())
    }

    async fn run_scope_menu(&mut self) -> Result<()> {
        loop {
            match self.scope_menu() {
                ScopeMenuOption::ImportScope => {
                    let file = self.prompt_file("Path to scope YAML file");
                    
                    if !file.is_empty() {
                        if std::path::Path::new(&file).exists() {
                            if let Some(ref storage) = self.storage {
                                match self.import_scope_from_file(&file, storage).await {
                                    Ok(scope_id) => {
                                        self.show_success(&format!("Scope imported with ID: {}", scope_id));
                                    }
                                    Err(e) => {
                                        self.show_error(&format!("Import failed: {}", e));
                                    }
                                }
                            } else {
                                self.show_error("Storage not initialized");
                            }
                        } else {
                            self.show_error("File not found");
                        }
                    }
                    
                    self.wait_enter();
                }
                ScopeMenuOption::CreateScope => {
                    self.print_banner();
                    self.print_header("Create New Scope 📋");
                    
                    let name = self.prompt_scope_name();
                    if name.is_empty() {
                        self.show_error("Scope name is required");
                        self.wait_enter();
                        continue;
                    }
                    
                    let description = self.prompt_scope_description();
                    let program = self.prompt_program_name();
                    
                    // Create the scope
                    let scope_id = uuid::Uuid::new_v4().to_string();
                    let scope = Scope {
                        id: scope_id.clone(),
                        name: name.clone(),
                        description,
                        program,
                        items: Vec::new(),
                        active: true,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        rules: None,
                        domain_count: 0,
                        cidr_count: 0,
                        wildcard_count: 0,
                    };
                    
                    if let Some(ref storage) = self.storage {
                        match storage.save_scope(&scope).await {
                            Ok(_) => {
                                self.show_success(&format!("Scope '{}' created with ID: {}", name, scope_id));
                                self.show_info("Use 'Add Target' to add domains, CIDRs, etc.");
                            }
                            Err(e) => {
                                self.show_error(&format!("Failed to save scope: {}", e));
                            }
                        }
                    } else {
                        self.show_error("Storage not initialized");
                    }
                    
                    self.wait_enter();
                }
                ScopeMenuOption::AddTarget => {
                    self.print_banner();
                    self.print_header("Add Target to Scope 🎯");
                    
                    // First, list and select scope
                    let scopes = self.get_scope_list().await;
                    
                    if let Some(scope_id) = self.prompt_scope(&scopes) {
                        let target_type = self.prompt_target_type();
                        let target_value = self.prompt_target_value(&target_type);
                        
                        if target_value.is_empty() {
                            self.show_error("Target value is required");
                            self.wait_enter();
                            continue;
                        }

                        let is_valid = match target_type.as_str() {
                            "wildcard" => target_value.starts_with("*.") && validate_domain(target_value.trim_start_matches("*."))?,
                            "cidr" => validate_cidr(&target_value),
                            "url" => validate_url(&target_value),
                            "asn" => validate_asn(&target_value),
                            _ => validate_domain(&target_value)?,
                        };
                        if !is_valid {
                            self.show_error(&format!("Invalid {} target format: {}", target_type, target_value));
                            self.wait_enter();
                            continue;
                        }
                        
                        if let Some(ref storage) = self.storage {
                            match storage.get_scope(&scope_id).await {
                                Ok(Some(mut scope)) => {
                                    // Add the new item
                                    let item_type = match target_type.as_str() {
                                        "wildcard" => ScopeItemType::Wildcard,
                                        "cidr" => ScopeItemType::Cidr,
                                        "url" => ScopeItemType::Url,
                                        "asn" => ScopeItemType::Asn,
                                        _ => ScopeItemType::Domain,
                                    };

                                    if scope.items.iter().any(|i| {
                                        i.in_scope && i.item_type == item_type && i.value.eq_ignore_ascii_case(&target_value)
                                    }) {
                                        self.show_warning("Target already exists in this scope");
                                        self.wait_enter();
                                        continue;
                                    }

                                    scope.items.push(ScopeItem {
                                        value: target_value.clone(),
                                        item_type,
                                        in_scope: true,
                                        notes: None,
                                        priority: 0,
                                    });
                                    
                                    // Update counts
                                    match target_type.as_str() {
                                        "domain" => scope.domain_count += 1,
                                        "wildcard" => scope.wildcard_count += 1,
                                        "cidr" => scope.cidr_count += 1,
                                        _ => {}
                                    }
                                    scope.updated_at = Utc::now();
                                    
                                    match storage.save_scope(&scope).await {
                                        Ok(_) => {
                                            self.show_success(&format!("Added {} '{}' to scope", target_type, target_value));
                                        }
                                        Err(e) => {
                                            self.show_error(&format!("Failed to save: {}", e));
                                        }
                                    }
                                }
                                Ok(None) => {
                                    self.show_error("Scope not found");
                                }
                                Err(e) => {
                                    self.show_error(&format!("Failed to load scope: {}", e));
                                }
                            }
                        } else {
                            self.show_error("Storage not initialized");
                        }
                    }
                    
                    self.wait_enter();
                }
                ScopeMenuOption::ListScopes => {
                    self.print_banner();
                    self.print_header("All Scopes 📃");
                    
                    let scopes = self.get_scope_list().await;
                    
                    if scopes.is_empty() {
                        self.show_info("No scopes found. Create or import a scope first.");
                    } else {
                        println!();
                        println!("  {:8} {:30}", "ID".bold(), "NAME".bold());
                        println!("  {}", self.line().dimmed());
                        
                        for (id, name) in &scopes {
                            let short_id = if id.len() > 8 { &id[..8] } else { id };
                            println!("  {:8} {:30}", short_id.dimmed(), name);
                        }
                        
                        println!();
                        println!("  {} {} scope(s) found", "Total:".bold(), scopes.len());
                    }
                    
                    self.wait_enter();
                }
                ScopeMenuOption::ViewScope => {
                    self.print_banner();
                    self.print_header("View Scope Details 🔎");
                    
                    let scopes = self.get_scope_list().await;
                    
                    if let Some(scope_id) = self.prompt_scope(&scopes) {
                        if let Some(ref storage) = self.storage {
                            match storage.get_scope(&scope_id).await {
                                Ok(Some(scope)) => {
                                    let domains: Vec<String> = scope.items.iter()
                                        .filter(|i| i.item_type == ScopeItemType::Domain && i.in_scope)
                                        .map(|i| i.value.clone())
                                        .collect();
                                    let wildcards: Vec<String> = scope.items.iter()
                                        .filter(|i| i.item_type == ScopeItemType::Wildcard && i.in_scope)
                                        .map(|i| i.value.clone())
                                        .collect();
                                    let cidrs: Vec<String> = scope.items.iter()
                                        .filter(|i| i.item_type == ScopeItemType::Cidr && i.in_scope)
                                        .map(|i| i.value.clone())
                                        .collect();
                                    let urls: Vec<String> = scope.items.iter()
                                        .filter(|i| i.item_type == ScopeItemType::Url && i.in_scope)
                                        .map(|i| i.value.clone())
                                        .collect();
                                    
                                    self.display_scope_details(
                                        &scope.name,
                                        scope.description.as_deref(),
                                        scope.program.as_deref(),
                                        &domains,
                                        &wildcards,
                                        &cidrs,
                                        &urls,
                                    );
                                }
                                Ok(None) => {
                                    self.show_error("Scope not found");
                                }
                                Err(e) => {
                                    self.show_error(&format!("Failed to load scope: {}", e));
                                }
                            }
                        }
                    }
                    
                    self.wait_enter();
                }
                ScopeMenuOption::ValidateTarget => {
                    self.print_banner();
                    self.print_header("Validate Target ✓");
                    
                    println!();
                    let target = self.read_input("  Enter target to validate: ");
                    
                    if !target.is_empty() {
                        let normalized_target = if target.starts_with("http://") || target.starts_with("https://") {
                            url::Url::parse(&target)
                                .ok()
                                .and_then(|u| u.host_str().map(|h| h.to_string()))
                                .unwrap_or_else(|| target.clone())
                        } else {
                            target.clone()
                        };

                        self.show_info(&format!("Checking: {}", normalized_target));
                        
                        let scopes = self.get_scope_list().await;
                        if scopes.is_empty() {
                            self.show_warning("No scopes configured for validation");
                        } else {
                            let mut found_in_scope = false;
                            if let Some(ref storage) = self.storage {
                                for (scope_id, scope_name) in &scopes {
                                    if let Ok(Some(scope)) = storage.get_scope(scope_id).await {
                                        if scope.is_in_scope(&normalized_target).in_scope {
                                            self.show_success(&format!("✓ IN SCOPE: '{}' in scope '{}'", normalized_target, scope_name));
                                            found_in_scope = true;
                                            break;
                                        }
                                    }
                                }
                            }
                            
                            if !found_in_scope {
                                self.show_warning(&format!("✗ OUT OF SCOPE: '{}' not found in any scope", normalized_target));
                            }
                        }
                    }
                    
                    self.wait_enter();
                }
                ScopeMenuOption::DeleteScope => {
                    self.print_banner();
                    self.print_header("Delete Scope 🗑");
                    
                    let scopes = self.get_scope_list().await;
                    
                    if scopes.is_empty() {
                        self.show_warning("No scopes to delete");
                    } else if let Some(scope_id) = self.prompt_scope(&scopes) {
                        if self.confirm(&format!("Delete scope {}?", scope_id)) {
                            if let Some(ref storage) = self.storage {
                                match storage.delete_scope(&scope_id).await {
                                    Ok(_) => {
                                        self.show_success("Scope deleted");
                                    }
                                    Err(e) => {
                                        self.show_error(&format!("Failed to delete: {}", e));
                                    }
                                }
                            }
                        }
                    }
                    
                    self.wait_enter();
                }
                ScopeMenuOption::Back => break,
            }
        }
        Ok(())
    }

    /// Get list of scopes from storage
    async fn get_scope_list(&self) -> Vec<(String, String)> {
        if let Some(ref storage) = self.storage {
            match storage.list_scopes(None).await {
                Ok(scopes) => scopes.iter().map(|s| (s.id.clone(), s.name.clone())).collect(),
                Err(_) => vec![],
            }
        } else {
            vec![]
        }
    }

    /// Import scope from YAML file
    async fn import_scope_from_file(&self, path: &str, storage: &Storage) -> Result<String> {
        let content = tokio::fs::read_to_string(path).await?;
        let def: ScopeDefinition = serde_yaml::from_str(&content)?;

        let engine = ScopeEngine::new();
        let validation = engine.validate_definition(&def)?;
        if !validation.is_valid {
            anyhow::bail!(
                "Invalid scope definition: {}",
                validation.errors.join(", ")
            );
        }

        let scope = engine.create_scope(def, None)?;
        let scope_id = scope.id.clone();
        
        storage.save_scope(&scope).await?;
        
        Ok(scope_id)
    }

    async fn run_findings_view(&mut self) -> Result<()> {
        self.print_banner();
        self.print_header("View Findings 🔍");
        
        let severity = self.prompt_severity();

        if let Some(ref storage) = self.storage {
            match storage
                .list_findings(
                    severity,
                    None,
                    None,
                    None,
                    None,
                    100,
                    "severity",
                )
                .await
            {
                Ok(findings) => {
                    if findings.is_empty() {
                        self.show_info("No findings yet. Run a scan first.");
                    } else {
                        let rows: Vec<(String, String, String, String)> = findings
                            .into_iter()
                            .map(|f| (f.id, f.severity, f.title, f.asset))
                            .collect();
                        self.show_findings_table(&rows);
                    }
                }
                Err(e) => self.show_error(&format!("Failed to load findings: {}", e)),
            }
        } else {
            self.show_error("Storage not initialized");
        }
        
        self.wait_enter();
        Ok(())
    }

    async fn run_report_generation(&mut self) -> Result<()> {
        self.print_banner();
        self.print_header("Generate Reports 📊");
        
        let format = self.prompt_report_format();
        let output = self.prompt_output_path(&format);
        
        if self.confirm(&format!("Generate {} report to {}?", format, output)) {
            if let Some(ref storage) = self.storage {
                match storage
                    .list_findings(None, None, None, None, None, 10_000, "date")
                    .await
                {
                    Ok(findings) => {
                        if findings.is_empty() {
                            self.show_warning("No findings available to report");
                        } else {
                            self.show_progress("Generating report");
                            let generator = ReportGenerator::new();

                            let rendered = match format.as_str() {
                                "md" => generator.generate_markdown(&findings),
                                "html" => generator.generate_html(&findings),
                                "bounty" => generator.generate_bounty_report(&findings),
                                _ => generator.generate_json(&findings),
                            };

                            match rendered {
                                Ok(content) => match tokio::fs::write(&output, content).await {
                                    Ok(_) => {
                                        self.complete_progress();
                                        self.show_success(&format!("Report saved to {}", output));
                                    }
                                    Err(e) => {
                                        self.complete_progress();
                                        self.show_error(&format!("Failed to write report: {}", e));
                                    }
                                },
                                Err(e) => {
                                    self.complete_progress();
                                    self.show_error(&format!("Failed to generate report: {}", e));
                                }
                            }
                        }
                    }
                    Err(e) => self.show_error(&format!("Failed to query findings: {}", e)),
                }
            } else {
                self.show_error("Storage not initialized");
            }
        }
        
        self.wait_enter();
        Ok(())
    }

    async fn run_assets_view(&mut self) -> Result<()> {
        self.print_banner();
        self.print_header("Manage Assets 🌐");

        if let Some(ref storage) = self.storage {
            match storage.list_assets(None, None, None, 200).await {
                Ok(assets) => {
                    if assets.is_empty() {
                        self.show_info("No assets discovered yet. Run a scan first.");
                    } else {
                        println!();
                        println!("  {:10} {:14} {}", "ID".bold(), "TYPE".bold(), "VALUE".bold());
                        println!("  {}", self.line().dimmed());
                        for asset in assets {
                            let short_id = if asset.id.len() > 10 {
                                format!("{}...", &asset.id[..7])
                            } else {
                                asset.id.clone()
                            };
                            println!(
                                "  {:10} {:14} {}",
                                short_id.dimmed(),
                                asset.asset_type.cyan(),
                                asset.value
                            );
                        }
                    }
                }
                Err(e) => self.show_error(&format!("Failed to list assets: {}", e)),
            }
        } else {
            self.show_error("Storage not initialized");
        }
        
        self.wait_enter();
        Ok(())
    }

    async fn run_settings(&mut self) -> Result<()> {
        loop {
            match self.settings_menu() {
                SettingsMenuOption::ViewSettings => {
                    self.print_banner();
                    self.print_header("Current Settings 👁");
                    
                    if let Some(ref config) = self.config {
                        self.display_settings(
                            config.rate_limit.requests_per_second,
                            config.request_timeout_secs,
                            &config.user_agent,
                            config.database_url(),
                            &config.database.db_type,
                        );
                    } else {
                        self.show_info("Settings not loaded. Using defaults.");
                        self.display_settings(10, 30, "AegisOSINT/0.1.0", "~/.local/share/aegis-osint/aegis.db", "sqlite");
                    }
                    
                    self.wait_enter();
                }
                SettingsMenuOption::EditRateLimit => {
                    self.print_banner();
                    self.print_header("Edit Rate Limit ⏱");
                    
                    let current = self.config.as_ref().map(|c| c.rate_limit.requests_per_second).unwrap_or(10);
                    let new_val = self.prompt_number("Requests per second", current);
                    
                    if new_val != current {
                        match self
                            .update_config(|config| {
                                config.rate_limit.requests_per_second = new_val;
                            })
                            .await
                        {
                            Ok(_) => self.show_success(&format!("Rate limit updated to {} req/s", new_val)),
                            Err(e) => self.show_error(&format!("Failed to save: {}", e)),
                        }
                    } else {
                        self.show_info("No changes made");
                    }
                    
                    self.wait_enter();
                }
                SettingsMenuOption::EditTimeout => {
                    self.print_banner();
                    self.print_header("Edit Request Timeout ⌛");
                    
                    let current = self.config.as_ref().map(|c| c.request_timeout_secs as u32).unwrap_or(30);
                    let new_val = self.prompt_number("Timeout in seconds", current);
                    
                    if new_val != current {
                        match self
                            .update_config(|config| {
                                config.request_timeout_secs = new_val as u64;
                            })
                            .await
                        {
                            Ok(_) => self.show_success(&format!("Timeout updated to {} seconds", new_val)),
                            Err(e) => self.show_error(&format!("Failed to save: {}", e)),
                        }
                    } else {
                        self.show_info("No changes made");
                    }
                    
                    self.wait_enter();
                }
                SettingsMenuOption::EditUserAgent => {
                    self.print_banner();
                    self.print_header("Edit User Agent 🤖");
                    
                    let current = self.config.as_ref().map(|c| c.user_agent.clone()).unwrap_or_else(|| "AegisOSINT/0.1.0".to_string());
                    let new_val = self.prompt_string("User agent string", &current);
                    
                    if new_val != current {
                        match self
                            .update_config(|config| {
                                config.user_agent = new_val.clone();
                            })
                            .await
                        {
                            Ok(_) => self.show_success(&format!("User agent updated to '{}'", new_val)),
                            Err(e) => self.show_error(&format!("Failed to save: {}", e)),
                        }
                    } else {
                        self.show_info("No changes made");
                    }
                    
                    self.wait_enter();
                }
                SettingsMenuOption::EditDatabase => {
                    self.print_banner();
                    self.print_header("Database Settings 💾");
                    
                    println!();
                    println!("  {}", "Database Backend:".bold());
                    println!();
                    println!("  {}  {} SQLite (local file)", "1".cyan().bold(), "📁".to_string());
                    println!("  {}  {} PostgreSQL (remote server)", "2".cyan().bold(), "🐘".to_string());
                    println!();
                    
                    let choice = self.read_char(&format!("  {} Select backend [1]: ", "→".cyan()));
                    
                    match choice {
                        '2' => {
                            println!();
                            let conn_str = self.read_input("  PostgreSQL connection string: ");
                            if !conn_str.is_empty() {
                                match self
                                    .update_config(|config| {
                                        config.database.db_type = "postgres".to_string();
                                        config.database.connection = conn_str.clone();
                                    })
                                    .await
                                {
                                    Ok(_) => {
                                        self.show_success("Database configured to PostgreSQL");
                                        self.show_warning("Restart AegisOSINT for changes to take effect");
                                    }
                                    Err(e) => self.show_error(&format!("Failed to save: {}", e)),
                                }
                            }
                        }
                        _ => {
                            let default_sqlite = self
                                .config
                                .as_ref()
                                .map(|c| c.database.connection.clone())
                                .unwrap_or_else(|| "~/.local/share/aegis-osint/aegis.db".to_string());
                            let sqlite_path = self.prompt_string(
                                "SQLite database file path",
                                &default_sqlite,
                            );
                            match self
                                .update_config(|config| {
                                    config.database.db_type = "sqlite".to_string();
                                    config.database.connection = sqlite_path.clone();
                                })
                                .await
                            {
                                Ok(_) => {
                                    self.show_success("Database configured to SQLite");
                                    self.show_warning("Restart AegisOSINT for changes to take effect");
                                }
                                Err(e) => self.show_error(&format!("Failed to save: {}", e)),
                            }
                        }
                    }
                    
                    self.wait_enter();
                }
                SettingsMenuOption::ResetDefaults => {
                    self.print_banner();
                    self.print_header("Reset to Defaults 🔄");
                    
                    if self.confirm("Reset all settings to defaults?") {
                        match self
                            .update_config(|config| {
                                config.rate_limit.requests_per_second = 10;
                                config.rate_limit.burst_size = 20;
                                config.request_timeout_secs = 30;
                                config.user_agent = format!("AegisOSINT/{}", env!("CARGO_PKG_VERSION"));
                                config.verbose = false;
                            })
                            .await
                        {
                            Ok(_) => self.show_success("Settings reset to defaults"),
                            Err(e) => self.show_error(&format!("Failed to save: {}", e)),
                        }
                    } else {
                        self.show_info("Reset cancelled");
                    }
                    
                    self.wait_enter();
                }
                SettingsMenuOption::Back => break,
            }
        }
        Ok(())
    }
}

impl Default for Menu {
    fn default() -> Self {
        Self::new()
    }
}
