//! Defensive scanner for one-time scans

use crate::policy::PolicyEngine;
use crate::scope::Scope;
use crate::storage::{DefensiveScanResult, Storage};
use anyhow::Result;
use chrono::Utc;
use std::time::Instant;

/// Scanner for defensive operations
#[allow(dead_code)]
pub struct DefensiveScanner {
    scope: Scope,
    policy: PolicyEngine,
    storage: Storage,
}

impl DefensiveScanner {
    /// Create a new scanner
    pub fn new(scope: Scope, policy: PolicyEngine, storage: Storage) -> Self {
        Self {
            scope,
            policy,
            storage,
        }
    }

    /// Run a defensive scan
    pub async fn scan(&self, checks: Option<&Vec<String>>) -> Result<DefensiveScanResult> {
        let policy_check = self.policy.check_defensive_operation(&self.scope).await?;
        if !policy_check.allowed {
            anyhow::bail!(
                "Defensive scan blocked by policy: {}",
                policy_check.reasons.join(", ")
            );
        }

        let start = Instant::now();
        let mut assets_count = 0;
        let mut changes_count = 0;
        let mut exposures_count = 0;

        let default_checks = vec![
            "inventory".to_string(),
            "drift".to_string(),
            "exposure".to_string(),
        ];
        let all_checks = checks.map(|c| c.as_slice()).unwrap_or(default_checks.as_slice());

        for check in all_checks {
            match check.as_ref() {
                "inventory" => {
                    let count = self.run_inventory().await?;
                    assets_count += count;
                }
                "drift" => {
                    let count = self.run_drift_detection().await?;
                    changes_count += count;
                }
                "exposure" => {
                    let count = self.run_exposure_check().await?;
                    exposures_count += count;
                }
                _ => {
                    tracing::warn!("Unknown check: {}", check);
                }
            }
        }

        Ok(DefensiveScanResult {
            assets_count,
            changes_count,
            exposures_count,
            duration_secs: start.elapsed().as_secs_f64(),
        })
    }

    async fn run_inventory(&self) -> Result<usize> {
        let assets = self
            .storage
            .list_assets(Some(&self.scope.id), None, None, 10_000)
            .await?;

        if !assets.is_empty() {
            return Ok(assets.len());
        }

        // Bootstrap from scope items if no discovered assets exist yet
        for item in &self.scope.items {
            if !item.in_scope {
                continue;
            }
            let value = item.value.trim().to_string();
            if value.is_empty() {
                continue;
            }
            let asset_type = match item.item_type {
                crate::scope::ScopeItemType::Cidr => "cidr",
                crate::scope::ScopeItemType::Asn => "asn",
                crate::scope::ScopeItemType::Url => "url",
                crate::scope::ScopeItemType::Repository => "repo",
                _ => "subdomain",
            };

            let id = format!("inventory-{}-{}", asset_type, sha256_short(&value));
            let now = Utc::now().to_rfc3339();
            self.storage
                .save_asset(&crate::storage::Asset {
                    id,
                    scope_id: self.scope.id.clone(),
                    asset_type: asset_type.to_string(),
                    value,
                    tags: vec!["inventory".to_string()],
                    metadata: None,
                    first_seen: now.clone(),
                    last_seen: now,
                })
                .await?;
        }

        let refreshed = self
            .storage
            .list_assets(Some(&self.scope.id), None, None, 10_000)
            .await?;
        Ok(refreshed.len())
    }

    async fn run_drift_detection(&self) -> Result<usize> {
        let monitor = super::monitor::AttackSurfaceMonitor::new(
            self.scope.clone(),
            60,
            self.policy.clone(),
            self.storage.clone(),
        );
        let result = monitor.check().await?;
        Ok(result.total_changes())
    }

    async fn run_exposure_check(&self) -> Result<usize> {
        let findings = self
            .storage
            .list_findings(
                Some("critical".to_string()),
                Some(&self.scope.id),
                None,
                Some("open".to_string()),
                None,
                10_000,
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
                10_000,
                "date",
            )
            .await?;
        Ok(findings.len() + high.len())
    }
}

fn sha256_short(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)[..12].to_string()
}
