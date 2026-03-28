//! Policy rules and checks

use serde::{Deserialize, Serialize};

/// Result of a policy check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheckResult {
    /// Whether the action is allowed
    pub allowed: bool,

    /// Reasons for the decision
    pub reasons: Vec<String>,
}

impl PolicyCheckResult {
    /// Create an allowed result
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            reasons: vec![],
        }
    }

    /// Create a denied result
    pub fn denied(reason: String) -> Self {
        Self {
            allowed: false,
            reasons: vec![reason],
        }
    }

    /// Create a denied result with multiple reasons
    pub fn denied_multiple(reasons: Vec<String>) -> Self {
        Self {
            allowed: false,
            reasons,
        }
    }

    /// Add a reason to the result
    pub fn with_reason(mut self, reason: String) -> Self {
        self.reasons.push(reason);
        self
    }
}

/// A policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule name
    pub name: String,

    /// Rule description
    pub description: String,

    /// Whether the rule is enabled
    pub enabled: bool,

    /// Rule type
    pub rule_type: RuleType,

    /// Rule action
    pub action: RuleAction,

    /// Rule patterns (if applicable)
    pub patterns: Vec<String>,
}

/// Type of policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    /// Block specific patterns
    Block,
    /// Allow specific patterns
    Allow,
    /// Rate limit
    RateLimit,
    /// Require confirmation
    Confirm,
    /// Log only
    Log,
}

/// Action to take when rule matches
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Deny the action
    Deny,
    /// Allow the action
    Allow,
    /// Warn but allow
    Warn,
    /// Log and allow
    Log,
}

/// A policy check interface
pub trait PolicyCheck {
    /// Check the policy for a given action
    fn check(&self, action: &str, target: Option<&str>) -> PolicyCheckResult;

    /// Get the rule name
    fn name(&self) -> &str;

    /// Whether the check is enabled
    fn enabled(&self) -> bool;
}

impl PolicyCheck for PolicyRule {
    fn check(&self, _action: &str, target: Option<&str>) -> PolicyCheckResult {
        if !self.enabled {
            return PolicyCheckResult::allowed();
        }

        if let Some(target) = target {
            for pattern in &self.patterns {
                if Self::matches_pattern(target, pattern) {
                    match self.action {
                        RuleAction::Deny => {
                            return PolicyCheckResult::denied(format!(
                                "Blocked by rule '{}': matches pattern '{}'",
                                self.name, pattern
                            ));
                        }
                        RuleAction::Allow => return PolicyCheckResult::allowed(),
                        RuleAction::Warn => {
                            return PolicyCheckResult::allowed()
                                .with_reason(format!("Warning from rule '{}': matches '{}'", self.name, pattern));
                        }
                        RuleAction::Log => {
                            tracing::info!(
                                rule = %self.name,
                                pattern = %pattern,
                                target = %target,
                                "Policy log rule matched"
                            );
                            return PolicyCheckResult::allowed();
                        }
                    }
                }
            }
        }

        PolicyCheckResult::allowed()
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn enabled(&self) -> bool {
        self.enabled
    }
}

impl PolicyRule {
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
    fn test_policy_check_result() {
        let allowed = PolicyCheckResult::allowed();
        assert!(allowed.allowed);

        let denied = PolicyCheckResult::denied("Test reason".to_string());
        assert!(!denied.allowed);
        assert_eq!(denied.reasons.len(), 1);
    }

    #[test]
    fn test_policy_rule() {
        let rule = PolicyRule {
            name: "block-gov".to_string(),
            description: "Block .gov domains".to_string(),
            enabled: true,
            rule_type: RuleType::Block,
            action: RuleAction::Deny,
            patterns: vec!["*.gov".to_string()],
        };

        let result = rule.check("access", Some("test.gov"));
        assert!(!result.allowed);

        let result = rule.check("access", Some("test.com"));
        assert!(result.allowed);
    }

    #[test]
    fn test_disabled_rule() {
        let rule = PolicyRule {
            name: "disabled".to_string(),
            description: "Disabled rule".to_string(),
            enabled: false,
            rule_type: RuleType::Block,
            action: RuleAction::Deny,
            patterns: vec!["*".to_string()],
        };

        let result = rule.check("access", Some("anything"));
        assert!(result.allowed);
    }
}
