//! Doctor command for system health checks

use crate::policy::PolicyEngine;
use crate::storage::Storage;
use anyhow::Result;
use clap::Args;
use colored::Colorize;

/// System health check command
#[derive(Args, Debug)]
pub struct DoctorCommand {
    /// Run all checks including optional ones
    #[arg(long)]
    pub full: bool,

    /// Fix issues automatically where possible
    #[arg(long)]
    pub fix: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

impl DoctorCommand {
    pub async fn execute(&self, storage: &Storage, policy: &PolicyEngine) -> Result<u8> {
        if self.json {
            return self.execute_json(storage, policy).await;
        }

        println!("{}", "AegisOSINT System Health Check".cyan().bold());
        println!("{}", "─".repeat(50));
        println!();

        let mut all_ok = true;
        let mut issues = Vec::new();

        // Check 1: Configuration
        print!("Checking configuration... ");
        match self.check_config().await {
            Ok(()) => println!("{}", "OK".green()),
            Err(e) => {
                println!("{}", "FAIL".red());
                issues.push(format!("Configuration: {}", e));
                all_ok = false;
            }
        }

        // Check 2: Database
        print!("Checking database... ");
        match self.check_database(storage).await {
            Ok(()) => println!("{}", "OK".green()),
            Err(e) => {
                println!("{}", "FAIL".red());
                issues.push(format!("Database: {}", e));
                all_ok = false;
            }
        }

        // Check 3: Policy engine
        print!("Checking policy engine... ");
        match self.check_policy(policy).await {
            Ok(()) => println!("{}", "OK".green()),
            Err(e) => {
                println!("{}", "FAIL".red());
                issues.push(format!("Policy engine: {}", e));
                all_ok = false;
            }
        }

        // Check 4: Network connectivity (optional)
        if self.full {
            print!("Checking network connectivity... ");
            match self.check_network().await {
                Ok(()) => println!("{}", "OK".green()),
                Err(e) => {
                    println!("{}", "WARN".yellow());
                    issues.push(format!("Network (optional): {}", e));
                }
            }
        }

        // Check 5: External tools
        print!("Checking external tools... ");
        let tool_status = self.check_tools().await;
        if tool_status.all_ok {
            println!("{}", "OK".green());
        } else {
            println!("{}", "WARN".yellow());
            for missing in &tool_status.missing {
                issues.push(format!("Missing tool (optional): {}", missing));
            }
        }

        // Check 6: Data directory
        print!("Checking data directory... ");
        match self.check_data_dir().await {
            Ok(()) => println!("{}", "OK".green()),
            Err(e) => {
                if self.fix {
                    print!("fixing... ");
                    if let Ok(()) = self.fix_data_dir().await {
                        println!("{}", "FIXED".green());
                    } else {
                        println!("{}", "FAIL".red());
                        issues.push(format!("Data directory: {}", e));
                        all_ok = false;
                    }
                } else {
                    println!("{}", "FAIL".red());
                    issues.push(format!("Data directory: {}", e));
                    all_ok = false;
                }
            }
        }

        // Check 7: Scopes
        print!("Checking scopes... ");
        let scope_count = storage.count_scopes().await?;
        if scope_count > 0 {
            println!("{} ({} scope(s))", "OK".green(), scope_count);
        } else {
            println!("{}", "WARN - no scopes defined".yellow());
            issues.push(
                "No scopes defined. Import one with: aegis scope import --file scope.yaml"
                    .to_string(),
            );
        }

        println!();
        println!("{}", "─".repeat(50));

        if all_ok && issues.is_empty() {
            println!("{}", "✓ All checks passed".green().bold());
            Ok(0)
        } else if all_ok {
            println!("{}", "⚠ System OK with warnings:".yellow().bold());
            for issue in &issues {
                println!("  {} {}", "•".yellow(), issue);
            }
            Ok(0)
        } else {
            println!("{}", "✗ Issues found:".red().bold());
            for issue in &issues {
                println!("  {} {}", "•".red(), issue);
            }
            if !self.fix {
                println!();
                println!(
                    "Run {} to attempt automatic fixes",
                    "aegis doctor --fix".cyan()
                );
            }
            Ok(1)
        }
    }

    async fn execute_json(&self, storage: &Storage, policy: &PolicyEngine) -> Result<u8> {
        #[derive(serde::Serialize)]
        struct HealthReport {
            status: String,
            checks: Vec<CheckResult>,
        }

        #[derive(serde::Serialize)]
        struct CheckResult {
            name: String,
            status: String,
            message: Option<String>,
        }

        let mut checks = Vec::new();

        // Run all checks and collect results
        checks.push(CheckResult {
            name: "configuration".to_string(),
            status: match self.check_config().await {
                Ok(()) => "ok".to_string(),
                Err(e) => format!("fail: {}", e),
            },
            message: None,
        });

        checks.push(CheckResult {
            name: "database".to_string(),
            status: match self.check_database(storage).await {
                Ok(()) => "ok".to_string(),
                Err(e) => format!("fail: {}", e),
            },
            message: None,
        });

        checks.push(CheckResult {
            name: "policy".to_string(),
            status: match self.check_policy(policy).await {
                Ok(()) => "ok".to_string(),
                Err(e) => format!("fail: {}", e),
            },
            message: None,
        });

        let all_ok = checks.iter().all(|c| c.status == "ok");

        let report = HealthReport {
            status: if all_ok { "healthy" } else { "unhealthy" }.to_string(),
            checks,
        };

        println!("{}", serde_json::to_string_pretty(&report)?);

        Ok(if all_ok { 0 } else { 1 })
    }

    async fn check_config(&self) -> Result<()> {
        use crate::config::Config;
        Config::load_or_create().await?;
        Ok(())
    }

    async fn check_database(&self, storage: &Storage) -> Result<()> {
        storage.health_check().await
    }

    async fn check_policy(&self, policy: &PolicyEngine) -> Result<()> {
        policy.validate().await
    }

    async fn check_network(&self) -> Result<()> {
        // Simple connectivity check
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        client
            .get("https://dns.google/resolve?name=example.com&type=A")
            .send()
            .await?;

        Ok(())
    }

    async fn check_tools(&self) -> ToolStatus {
        let tools = vec![
            ("dig", false),   // DNS queries
            ("whois", false), // WHOIS lookups
            ("nmap", false),  // Port scanning (optional)
        ];

        let mut missing = Vec::new();

        for (tool, _required) in tools {
            if std::process::Command::new("which")
                .arg(tool)
                .output()
                .map(|o| !o.status.success())
                .unwrap_or(true)
            {
                missing.push(tool.to_string());
            }
        }

        ToolStatus {
            all_ok: missing.is_empty(),
            missing,
        }
    }

    async fn check_data_dir(&self) -> Result<()> {
        use directories::ProjectDirs;

        let dirs = ProjectDirs::from("io", "aegis", "aegis-osint")
            .ok_or_else(|| anyhow::anyhow!("Could not determine data directory"))?;

        let data_dir = dirs.data_dir();
        if !data_dir.exists() {
            anyhow::bail!("Data directory does not exist: {:?}", data_dir);
        }

        Ok(())
    }

    async fn fix_data_dir(&self) -> Result<()> {
        use directories::ProjectDirs;

        let dirs = ProjectDirs::from("io", "aegis", "aegis-osint")
            .ok_or_else(|| anyhow::anyhow!("Could not determine data directory"))?;

        std::fs::create_dir_all(dirs.data_dir())?;
        Ok(())
    }
}

struct ToolStatus {
    all_ok: bool,
    missing: Vec<String>,
}
