//! Policy engine implementation

use super::rules::PolicyCheckResult;
use crate::config::Config;
use crate::scope::Scope;
use crate::storage::Storage;
use anyhow::Result;
use chrono::{DateTime, Utc};
use governor::Quota;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy version
    #[serde(default = "default_version")]
    pub version: u32,

    /// Global kill switch
    #[serde(default)]
    pub kill_switch: bool,

    /// Blocked patterns (never allowed)
    #[serde(default)]
    pub blocked_patterns: Vec<String>,

    /// Restricted modules (require explicit opt-in)
    #[serde(default)]
    pub restricted_modules: Vec<String>,

    /// Rate limit settings
    #[serde(default)]
    pub rate_limits: PolicyRateLimits,

    /// Safety settings
    #[serde(default)]
    pub safety: SafetySettings,

    /// Audit settings
    #[serde(default)]
    pub audit: AuditSettings,
}

fn default_version() -> u32 {
    1
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: 1,
            kill_switch: false,
            blocked_patterns: vec![
                "*.gov".to_string(),
                "*.mil".to_string(),
                "*.edu".to_string(),
                "localhost".to_string(),
                "127.0.0.1".to_string(),
            ],
            restricted_modules: vec!["port-scan".to_string(), "subdomain-bruteforce".to_string()],
            rate_limits: PolicyRateLimits::default(),
            safety: SafetySettings::default(),
            audit: AuditSettings::default(),
        }
    }
}

/// Rate limit settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRateLimits {
    /// Global requests per second
    #[serde(default = "default_rps")]
    pub requests_per_second: u32,

    /// Burst size
    #[serde(default = "default_burst")]
    pub burst_size: u32,

    /// Retry budget (max retries per target)
    #[serde(default = "default_retry_budget")]
    pub retry_budget: u32,
}

fn default_rps() -> u32 {
    10
}

fn default_burst() -> u32 {
    20
}

fn default_retry_budget() -> u32 {
    3
}

impl Default for PolicyRateLimits {
    fn default() -> Self {
        Self {
            requests_per_second: default_rps(),
            burst_size: default_burst(),
            retry_budget: default_retry_budget(),
        }
    }
}

/// Safety settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetySettings {
    /// Require scope validation before any operation
    #[serde(default = "default_true")]
    pub require_scope_validation: bool,

    /// Block out-of-scope targets
    #[serde(default = "default_true")]
    pub block_out_of_scope: bool,

    /// Log all network requests
    #[serde(default = "default_true")]
    pub log_all_requests: bool,

    /// Require explicit confirmation for destructive actions
    #[serde(default = "default_true")]
    pub require_confirmation: bool,
}

fn default_true() -> bool {
    true
}

impl Default for SafetySettings {
    fn default() -> Self {
        Self {
            require_scope_validation: true,
            block_out_of_scope: true,
            log_all_requests: true,
            require_confirmation: true,
        }
    }
}

/// Audit settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSettings {
    /// Enable audit logging
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Log blocked actions
    #[serde(default = "default_true")]
    pub log_blocked_actions: bool,

    /// Audit log path
    #[serde(default)]
    pub log_path: Option<String>,
}

impl Default for AuditSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            log_blocked_actions: true,
            log_path: None,
        }
    }
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Action type
    pub action: String,

    /// Target (if applicable)
    pub target: Option<String>,

    /// Scope ID (if applicable)
    pub scope_id: Option<String>,

    /// Whether action was allowed
    pub allowed: bool,

    /// Reason for decision
    pub reason: String,

    /// Additional metadata
    pub metadata: Option<HashMap<String, String>>,
}

/// Policy engine for enforcing guardrails
#[derive(Clone)]
pub struct PolicyEngine {
    /// Policy configuration
    policy: Arc<RwLock<Policy>>,

    /// Rate limiter (using direct/keyed rate limiting)
    rate_limiter: Arc<governor::RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>,

    /// Storage reference for audit logging
    storage: Storage,

    /// Retry counts per target
    retry_counts: Arc<RwLock<HashMap<String, u32>>>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub async fn new(config: &Config, storage: &Storage) -> Result<Self> {
        let policy = if let Some(ref policy_path) = config.policy_path {
            let content = tokio::fs::read_to_string(policy_path).await?;
            serde_yaml::from_str(&content)?
        } else {
            Policy::default()
        };

        let quota = Quota::per_second(
            NonZeroU32::new(policy.rate_limits.requests_per_second).unwrap_or(NonZeroU32::MIN),
        );
        let rate_limiter = governor::RateLimiter::direct(quota);

        Ok(Self {
            policy: Arc::new(RwLock::new(policy)),
            rate_limiter: Arc::new(rate_limiter),
            storage: storage.clone(),
            retry_counts: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Validate the policy engine state
    pub async fn validate(&self) -> Result<()> {
        let policy = self.policy.read().await;
        if policy.kill_switch {
            anyhow::bail!("Policy kill switch is active");
        }
        Ok(())
    }

    /// Check if operations are globally enabled
    pub async fn is_enabled(&self) -> bool {
        let policy = self.policy.read().await;
        !policy.kill_switch
    }

    /// Activate the kill switch (stops all operations)
    pub async fn activate_kill_switch(&self) {
        let mut policy = self.policy.write().await;
        policy.kill_switch = true;
        tracing::warn!("Kill switch activated - all operations stopped");
    }

    /// Check if a target is blocked by policy
    pub async fn is_blocked(&self, target: &str) -> bool {
        let policy = self.policy.read().await;
        for pattern in &policy.blocked_patterns {
            if Self::matches_pattern(target, pattern) {
                return true;
            }
        }
        false
    }

    /// Check if a module is restricted
    pub async fn is_module_restricted(&self, module: &str) -> bool {
        let policy = self.policy.read().await;
        policy.restricted_modules.contains(&module.to_string())
    }

    /// Check policy for an offensive operation
    pub async fn check_offensive_operation(
        &self,
        program: &str,
        scope: &Scope,
    ) -> Result<PolicyCheckResult> {
        let policy = self.policy.read().await;

        // Check kill switch
        if policy.kill_switch {
            return Ok(PolicyCheckResult {
                allowed: false,
                reasons: vec!["Global kill switch is active".to_string()],
            });
        }

        // Check scope is active
        if !scope.active {
            return Ok(PolicyCheckResult {
                allowed: false,
                reasons: vec![format!("Scope '{}' is not active", scope.id)],
            });
        }

        // Log the check
        if policy.audit.enabled {
            self.log_audit(AuditEntry {
                timestamp: Utc::now(),
                action: "offensive_operation_check".to_string(),
                target: Some(program.to_string()),
                scope_id: Some(scope.id.clone()),
                allowed: true,
                reason: "Policy check passed".to_string(),
                metadata: None,
            })
            .await?;
        }

        Ok(PolicyCheckResult {
            allowed: true,
            reasons: vec![],
        })
    }

    /// Check policy for a defensive operation
    pub async fn check_defensive_operation(&self, scope: &Scope) -> Result<PolicyCheckResult> {
        let policy = self.policy.read().await;

        if policy.kill_switch {
            return Ok(PolicyCheckResult {
                allowed: false,
                reasons: vec!["Global kill switch is active".to_string()],
            });
        }

        if !scope.active {
            return Ok(PolicyCheckResult {
                allowed: false,
                reasons: vec![format!("Scope '{}' is not active", scope.id)],
            });
        }

        Ok(PolicyCheckResult {
            allowed: true,
            reasons: vec![],
        })
    }

    /// Check if a specific target can be accessed
    pub async fn check_target(&self, target: &str, scope: &Scope) -> Result<PolicyCheckResult> {
        let policy = self.policy.read().await;

        // Check kill switch
        if policy.kill_switch {
            return Ok(PolicyCheckResult {
                allowed: false,
                reasons: vec!["Global kill switch is active".to_string()],
            });
        }

        // Check blocked patterns
        if self.is_blocked(target).await {
            self.log_blocked_action("target_access", target, "Matched blocked pattern")
                .await?;
            return Ok(PolicyCheckResult {
                allowed: false,
                reasons: vec![format!("Target '{}' matches blocked pattern", target)],
            });
        }

        // Check scope
        if policy.safety.require_scope_validation {
            let scope_check = scope.is_in_scope(target);
            if !scope_check.in_scope && policy.safety.block_out_of_scope {
                self.log_blocked_action("target_access", target, &scope_check.reason)
                    .await?;
                return Ok(PolicyCheckResult {
                    allowed: false,
                    reasons: vec![scope_check.reason],
                });
            }
        }

        Ok(PolicyCheckResult {
            allowed: true,
            reasons: vec![],
        })
    }

    /// Wait for rate limit clearance
    pub async fn wait_for_rate_limit(&self) {
        self.rate_limiter.until_ready().await;
    }

    /// Check retry budget for a target
    pub async fn check_retry_budget(&self, target: &str) -> bool {
        let policy = self.policy.read().await;
        let counts = self.retry_counts.read().await;
        let count = counts.get(target).copied().unwrap_or(0);
        count < policy.rate_limits.retry_budget
    }

    /// Increment retry count for a target
    pub async fn increment_retry(&self, target: &str) {
        let mut counts = self.retry_counts.write().await;
        *counts.entry(target.to_string()).or_insert(0) += 1;
    }

    /// Log an audit entry
    async fn log_audit(&self, entry: AuditEntry) -> Result<()> {
        self.storage.log_audit_entry(&entry).await
    }

    /// Log a blocked action
    async fn log_blocked_action(&self, action: &str, target: &str, reason: &str) -> Result<()> {
        let policy = self.policy.read().await;
        if policy.audit.log_blocked_actions {
            self.log_audit(AuditEntry {
                timestamp: Utc::now(),
                action: format!("blocked:{}", action),
                target: Some(target.to_string()),
                scope_id: None,
                allowed: false,
                reason: reason.to_string(),
                metadata: None,
            })
            .await?;
        }
        Ok(())
    }

    /// Pattern matching helper
    fn matches_pattern(target: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            let re_pattern = pattern.replace('.', r"\.").replace('*', ".*");
            if let Ok(re) = regex::Regex::new(&format!("^{}$", re_pattern)) {
                return re.is_match(target);
            }
        }
        target.eq_ignore_ascii_case(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        assert!(PolicyEngine::matches_pattern("test.gov", "*.gov"));
        assert!(PolicyEngine::matches_pattern("sub.test.gov", "*.gov"));
        assert!(!PolicyEngine::matches_pattern("test.com", "*.gov"));
        assert!(PolicyEngine::matches_pattern("localhost", "localhost"));
    }

    #[test]
    fn test_default_policy() {
        let policy = Policy::default();
        assert!(!policy.kill_switch);
        assert!(policy.blocked_patterns.contains(&"*.gov".to_string()));
    }
}
