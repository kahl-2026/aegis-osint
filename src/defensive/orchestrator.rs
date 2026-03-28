//! Defensive OSINT orchestrator

use crate::policy::PolicyEngine;
use crate::scope::Scope;
use crate::storage::Storage;
use anyhow::Result;
use chrono::Utc;

/// Orchestrator for defensive operations
#[allow(dead_code)]
pub struct DefensiveOrchestrator {
    scope: Scope,
    interval_minutes: u32,
    drift_detection: bool,
    brand_monitoring: bool,
    leak_monitoring: bool,
    policy: PolicyEngine,
    storage: Storage,
}

impl DefensiveOrchestrator {
    /// Create a new orchestrator
    pub fn new(
        scope: Scope,
        interval_minutes: u32,
        drift_detection: bool,
        brand_monitoring: bool,
        leak_monitoring: bool,
        policy: PolicyEngine,
        storage: Storage,
    ) -> Self {
        Self {
            scope,
            interval_minutes,
            drift_detection,
            brand_monitoring,
            leak_monitoring,
            policy,
            storage,
        }
    }

    /// Start daemon mode monitoring
    pub async fn start_daemon(&self) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();

        // Register the monitor
        let now = Utc::now();
        let next_check = now + chrono::Duration::minutes(self.interval_minutes as i64);

        sqlx::query(
            r#"
            INSERT INTO monitors (id, scope_id, status, interval_minutes, drift_detection, brand_monitoring, leak_monitoring, started_at, next_check)
            VALUES (?, ?, 'running', ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&self.scope.id)
        .bind(self.interval_minutes as i32)
        .bind(self.drift_detection)
        .bind(self.brand_monitoring)
        .bind(self.leak_monitoring)
        .bind(now.to_rfc3339())
        .bind(next_check.to_rfc3339())
        .execute(self.storage.pool())
        .await?;

        Ok(id)
    }

    /// Run interactive monitoring (blocking)
    pub async fn run_interactive(&self) -> Result<()> {
        use tokio::time::{interval, Duration};
        use colored::Colorize;

        let mut ticker = interval(Duration::from_secs(self.interval_minutes as u64 * 60));

        loop {
            ticker.tick().await;

            println!("{}", format!("[{}] Running monitoring check...", Utc::now().format("%H:%M:%S")).cyan());

            // Run monitoring checks
            if self.drift_detection {
                self.check_drift().await?;
            }

            if self.brand_monitoring {
                self.check_brand().await?;
            }

            if self.leak_monitoring {
                self.check_leaks().await?;
            }

            println!("{}", "Check complete. Waiting for next interval...".green());
        }
    }

    async fn check_drift(&self) -> Result<()> {
        let monitor = super::monitor::AttackSurfaceMonitor::new(
            self.scope.clone(),
            self.interval_minutes,
            self.policy.clone(),
            self.storage.clone(),
        );
        let result = monitor.check().await?;
        if result.has_changes() {
            tracing::warn!(
                "Drift detection: {} total changes (dns={}, cert={}, subdomains={}, services={})",
                result.total_changes(),
                result.dns_changes.len(),
                result.cert_changes.len(),
                result.new_subdomains.len(),
                result.new_services.len()
            );
        } else {
            tracing::info!("Drift detection: no changes");
        }
        Ok(())
    }

    async fn check_brand(&self) -> Result<()> {
        use super::brand::BrandMonitor;

        if let Some(ref program) = self.scope.program {
            let mut monitor = BrandMonitor::new(program);
            for item in &self.scope.items {
                if item.in_scope
                    && matches!(
                        item.item_type,
                        crate::scope::ScopeItemType::Domain | crate::scope::ScopeItemType::Wildcard
                    )
                {
                    monitor.add_known_domain(item.value.trim_start_matches("*."));
                }
            }

            let candidates = monitor.generate_typosquats();
            let suspicious = candidates
                .iter()
                .map(|c| format!("{}.com", c.domain))
                .filter(|d| !monitor.is_known(d))
                .take(25)
                .collect::<Vec<_>>();

            if !suspicious.is_empty() {
                tracing::warn!(
                    "Brand monitoring identified {} suspicious candidate domains for '{}'",
                    suspicious.len(),
                    program
                );
            } else {
                tracing::info!("Brand monitoring: no suspicious candidates");
            }
        }

        Ok(())
    }

    async fn check_leaks(&self) -> Result<()> {
        let critical = self
            .storage
            .list_findings(
                Some("critical".to_string()),
                Some(&self.scope.id),
                None,
                Some("open".to_string()),
                None,
                1000,
                "date",
            )
            .await?;
        let high = self
            .storage
            .list_findings(
                Some("high".to_string()),
                Some(&self.scope.id),
                None,
                Some("open".to_string()),
                None,
                1000,
                "date",
            )
            .await?;

        tracing::info!(
            "Leak monitoring: open high/critical findings = {}",
            critical.len() + high.len()
        );
        Ok(())
    }
}

