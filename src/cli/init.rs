//! Init command for project initialization

use crate::policy::PolicyEngine;
use crate::storage::Storage;
use anyhow::Result;
use clap::Args;
use colored::Colorize;

/// Initialize AegisOSINT project or configuration
#[derive(Args, Debug)]
pub struct InitCommand {
    /// Initialize in specific directory
    #[arg(short, long)]
    pub path: Option<std::path::PathBuf>,

    /// Create example scope file
    #[arg(long)]
    pub with_examples: bool,

    /// Force overwrite existing configuration
    #[arg(long)]
    pub force: bool,
}

impl InitCommand {
    pub async fn execute(&self, _storage: &Storage, _policy: &PolicyEngine) -> Result<u8> {
        use std::path::PathBuf;

        let base_path = self.path.clone().unwrap_or_else(|| PathBuf::from("."));
        let aegis_dir = base_path.join(".aegis");

        println!("{}", "Initializing AegisOSINT project...".cyan().bold());
        println!();

        // Check if already initialized
        if aegis_dir.exists() && !self.force {
            println!(
                "{}",
                "Project already initialized. Use --force to reinitialize.".yellow()
            );
            return Ok(0);
        }

        // Create directory structure
        std::fs::create_dir_all(&aegis_dir)?;
        std::fs::create_dir_all(aegis_dir.join("scopes"))?;
        std::fs::create_dir_all(aegis_dir.join("reports"))?;
        std::fs::create_dir_all(aegis_dir.join("evidence"))?;

        println!("  {} Created .aegis directory", "✓".green());

        // Create default config
        let config_content = r#"# AegisOSINT Project Configuration
version: 1

# Default database (SQLite)
database:
  type: sqlite
  path: .aegis/aegis.db

# Policy settings
policy:
  # Rate limiting
  rate_limit:
    requests_per_second: 10
    burst_size: 20
  
  # Retry configuration
  retry:
    max_attempts: 3
    backoff_ms: 1000
  
  # Safety gates
  safety:
    require_scope_validation: true
    block_out_of_scope: true
    log_all_requests: true

# Reporting defaults
reporting:
  include_evidence: true
  default_format: json
"#;

        std::fs::write(aegis_dir.join("config.yaml"), config_content)?;
        println!("  {} Created default configuration", "✓".green());

        // Create policy file
        let policy_content = r#"# AegisOSINT Policy Configuration
version: 1

# Global kill switch - set to true to stop all operations
kill_switch: false

# Out-of-scope patterns that are NEVER allowed
blocked_patterns:
  - "*.gov"
  - "*.mil"
  - "*.edu"
  - "localhost"
  - "127.0.0.1"
  - "10.*"
  - "192.168.*"
  - "172.16.*"

# Modules that require explicit opt-in
restricted_modules:
  - port-scan
  - subdomain-bruteforce

# Audit logging
audit:
  enabled: true
  log_path: .aegis/audit.log
  log_blocked_actions: true
"#;

        std::fs::write(aegis_dir.join("policy.yaml"), policy_content)?;
        println!("  {} Created policy configuration", "✓".green());

        // Create example files if requested
        if self.with_examples {
            let example_scope = r#"# Example Scope Definition
# Rename this file and customize for your target program

id: example-program
name: Example Bug Bounty Program
description: Example scope file for AegisOSINT

# Program metadata
program:
  name: Example Security Program
  platform: hackerone  # or bugcrowd, intigriti, self-hosted
  url: https://hackerone.com/example
  
# In-scope targets
in_scope:
  domains:
    - "*.example.com"
    - "api.example.com"
    - "app.example.com"
  
  cidrs:
    - "203.0.113.0/24"
  
  # Specific exclusions within wildcards
  exclude:
    - "admin.example.com"
    - "internal.example.com"

# Explicitly out-of-scope
out_of_scope:
  domains:
    - "blog.example.com"
    - "status.example.com"
  
  cidrs:
    - "198.51.100.0/24"

# Testing rules from the program
rules:
  # What types of testing are allowed
  allowed:
    - passive_recon
    - dns_enumeration
    - subdomain_discovery
    - web_fingerprinting
    - header_analysis
  
  # What's explicitly prohibited
  prohibited:
    - denial_of_service
    - social_engineering
    - physical_access
    - credential_stuffing
  
  # Rate limiting requirements from program
  rate_limits:
    requests_per_second: 5
    max_concurrent: 3

# Notes
notes: |
  - No testing on weekends
  - Contact security@example.com before testing critical infrastructure
  - Maximum 10 requests per second
"#;

            std::fs::write(
                aegis_dir.join("scopes/example-scope.yaml"),
                example_scope,
            )?;
            println!("  {} Created example scope file", "✓".green());
        }

        // Create .gitignore
        let gitignore = r#"# AegisOSINT
.aegis/aegis.db
.aegis/audit.log
.aegis/reports/
.aegis/evidence/
*.tmp
"#;

        std::fs::write(aegis_dir.join(".gitignore"), gitignore)?;

        println!();
        println!("{}", "✓ Project initialized successfully!".green().bold());
        println!();
        println!("{}", "Next steps:".bold());
        println!(
            "  1. Edit {} with your policy settings",
            ".aegis/policy.yaml".cyan()
        );
        if self.with_examples {
            println!(
                "  2. Customize {} for your target",
                ".aegis/scopes/example-scope.yaml".cyan()
            );
        } else {
            println!(
                "  2. Create a scope file in {}",
                ".aegis/scopes/".cyan()
            );
        }
        println!(
            "  3. Import the scope: {}",
            "aegis scope import --file .aegis/scopes/your-scope.yaml".cyan()
        );
        println!(
            "  4. Run a scan: {}",
            "aegis offensive run --program <name>".cyan()
        );

        Ok(0)
    }
}
