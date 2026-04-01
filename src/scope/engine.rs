//! Scope engine for validation and operations

use super::{Scope, ScopeDefinition, ValidationResult};
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;

/// Scope engine for managing scope operations
pub struct ScopeEngine {
    /// Blocked patterns that are never allowed
    blocked_patterns: Vec<String>,
}

impl ScopeEngine {
    /// Create a new scope engine with default blocked patterns
    pub fn new() -> Self {
        Self {
            blocked_patterns: vec![
                "*.gov".to_string(),
                "*.mil".to_string(),
                "*.edu".to_string(),
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
                "10.*".to_string(),
                "192.168.*".to_string(),
                "172.16.*".to_string(),
                "172.17.*".to_string(),
                "172.18.*".to_string(),
                "172.19.*".to_string(),
                "172.20.*".to_string(),
                "172.21.*".to_string(),
                "172.22.*".to_string(),
                "172.23.*".to_string(),
                "172.24.*".to_string(),
                "172.25.*".to_string(),
                "172.26.*".to_string(),
                "172.27.*".to_string(),
                "172.28.*".to_string(),
                "172.29.*".to_string(),
                "172.30.*".to_string(),
                "172.31.*".to_string(),
            ],
        }
    }

    /// Create scope engine with custom blocked patterns
    pub fn with_blocked_patterns(blocked: Vec<String>) -> Self {
        Self {
            blocked_patterns: blocked,
        }
    }

    /// Validate a scope definition
    pub fn validate_definition(&self, definition: &ScopeDefinition) -> Result<ValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Validate ID
        if definition.id.is_empty() {
            errors.push("Scope ID is required".to_string());
        } else if !Self::is_valid_id(&definition.id) {
            errors.push(format!(
                "Invalid scope ID '{}': must be alphanumeric with hyphens",
                definition.id
            ));
        }

        // Validate name
        if definition.name.is_empty() {
            errors.push("Scope name is required".to_string());
        }

        // Validate in-scope items
        let mut seen_items: HashSet<String> = HashSet::new();

        for domain in &definition.in_scope.domains {
            if !Self::is_valid_domain_or_wildcard(domain) {
                errors.push(format!("Invalid domain pattern: {}", domain));
            }
            if self.is_blocked(domain) {
                errors.push(format!("Blocked pattern in scope: {}", domain));
            }
            if !seen_items.insert(domain.to_lowercase()) {
                warnings.push(format!("Duplicate domain: {}", domain));
            }
        }

        for cidr in &definition.in_scope.cidrs {
            if !Self::is_valid_cidr(cidr) {
                errors.push(format!("Invalid CIDR notation: {}", cidr));
            }
            if self.is_blocked_cidr(cidr) {
                errors.push(format!("Blocked CIDR in scope (private/reserved): {}", cidr));
            }
        }

        for asn in &definition.in_scope.asns {
            if !Self::is_valid_asn(asn) {
                errors.push(format!("Invalid ASN: {}", asn));
            }
        }

        // Validate out-of-scope items
        for domain in &definition.out_of_scope.domains {
            if !Self::is_valid_domain_or_wildcard(domain) {
                errors.push(format!("Invalid out-of-scope domain: {}", domain));
            }
        }

        // Check for conflicting rules
        for in_domain in &definition.in_scope.domains {
            for out_domain in &definition.out_of_scope.domains {
                if in_domain == out_domain {
                    errors.push(format!(
                        "Domain '{}' is both in-scope and out-of-scope",
                        in_domain
                    ));
                }
            }
        }

        // Warn about very broad scopes
        for domain in &definition.in_scope.domains {
            if domain == "*" || domain == "*.*" {
                warnings.push(format!(
                    "Very broad wildcard '{}' - consider narrowing scope",
                    domain
                ));
            }
        }

        // Validate exclusions reference valid wildcards
        for exclude in &definition.in_scope.exclude {
            let has_matching_wildcard = definition.in_scope.domains.iter().any(|d| {
                if let Some(base) = d.strip_prefix("*.") {
                    exclude.ends_with(base)
                } else {
                    false
                }
            });

            if !has_matching_wildcard {
                warnings.push(format!(
                    "Exclusion '{}' doesn't match any wildcard scope",
                    exclude
                ));
            }
        }

        Ok(ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
        })
    }

    /// Create a scope from a validated definition
    pub fn create_scope(
        &self,
        definition: ScopeDefinition,
        program: Option<String>,
    ) -> Result<Scope> {
        // Validate first
        let validation = self.validate_definition(&definition)?;
        if !validation.is_valid {
            anyhow::bail!(
                "Invalid scope definition: {}",
                validation.errors.join(", ")
            );
        }

        Ok(Scope::from_definition(definition, program))
    }

    /// Check if a target is blocked by global policy
    pub fn is_blocked(&self, target: &str) -> bool {
        for pattern in &self.blocked_patterns {
            if Self::matches_pattern(target, pattern) {
                return true;
            }
        }
        false
    }

    /// Check if a CIDR is blocked (private/reserved ranges)
    fn is_blocked_cidr(&self, cidr: &str) -> bool {
        if let Ok(network) = cidr.parse::<ipnetwork::IpNetwork>() {
            // Check if it's a private range
            match network {
                ipnetwork::IpNetwork::V4(net) => {
                    let ip = net.ip();
                    // 10.0.0.0/8
                    if ip.octets()[0] == 10 {
                        return true;
                    }
                    // 172.16.0.0/12
                    if ip.octets()[0] == 172 && (ip.octets()[1] >= 16 && ip.octets()[1] <= 31) {
                        return true;
                    }
                    // 192.168.0.0/16
                    if ip.octets()[0] == 192 && ip.octets()[1] == 168 {
                        return true;
                    }
                    // 127.0.0.0/8 (loopback)
                    if ip.octets()[0] == 127 {
                        return true;
                    }
                }
                ipnetwork::IpNetwork::V6(net) => {
                    let ip = net.ip();
                    // ::1 (loopback)
                    if ip.is_loopback() {
                        return true;
                    }
                    // fc00::/7 (unique local)
                    let segments = ip.segments();
                    if (segments[0] & 0xfe00) == 0xfc00 {
                        return true;
                    }
                    // fe80::/10 (link-local)
                    if (segments[0] & 0xffc0) == 0xfe80 {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if an ID is valid (alphanumeric with hyphens)
    fn is_valid_id(id: &str) -> bool {
        let mut chars = id.chars();
        let Some(first) = chars.next() else {
            return false;
        };

        if !first.is_ascii_alphabetic() {
            return false;
        }

        chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    /// Check if a domain or wildcard pattern is valid
    fn is_valid_domain_or_wildcard(domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }

        // Allow wildcard prefix
        let check_domain = domain.strip_prefix("*.").unwrap_or(domain).trim();
        if check_domain.is_empty() || check_domain.len() > 253 {
            return false;
        }

        for label in check_domain.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }
            if label.starts_with('-') || label.ends_with('-') {
                return false;
            }
            if !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                return false;
            }
        }

        true
    }

    /// Check if a CIDR is valid
    fn is_valid_cidr(cidr: &str) -> bool {
        cidr.parse::<ipnetwork::IpNetwork>().is_ok()
    }

    /// Check if an ASN is valid
    fn is_valid_asn(asn: &str) -> bool {
        let normalized = asn.to_uppercase();
        let number_part = normalized.strip_prefix("AS").unwrap_or(&normalized);
        number_part.parse::<u32>().is_ok()
    }

    /// Check if a target matches a pattern
    fn matches_pattern(target: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            // Simple wildcard matching
            let re_pattern = pattern
                .replace('.', r"\.")
                .replace('*', ".*");
            if let Ok(re) = Regex::new(&format!("^{}$", re_pattern)) {
                return re.is_match(target);
            }
        }
        target.eq_ignore_ascii_case(pattern)
    }

    /// Normalize a domain to consistent format
    pub fn normalize_domain(domain: &str) -> String {
        domain
            .trim()
            .to_lowercase()
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string()
    }

    /// Expand a wildcard to potential subdomains (for discovery guidance)
    pub fn expand_wildcard_hints(wildcard: &str) -> Vec<String> {
        if let Some(base) = wildcard.strip_prefix("*.") {
            vec![
                format!("www.{}", base),
                format!("api.{}", base),
                format!("app.{}", base),
                format!("dev.{}", base),
                format!("staging.{}", base),
                format!("test.{}", base),
                format!("admin.{}", base),
                format!("portal.{}", base),
                format!("mail.{}", base),
                format!("cdn.{}", base),
            ]
        } else {
            vec![]
        }
    }
}

impl Default for ScopeEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_id() {
        assert!(ScopeEngine::is_valid_id("test-scope"));
        assert!(ScopeEngine::is_valid_id("TestScope123"));
        assert!(ScopeEngine::is_valid_id("my_scope"));
        assert!(!ScopeEngine::is_valid_id("123invalid"));
        assert!(!ScopeEngine::is_valid_id(""));
    }

    #[test]
    fn test_valid_domain() {
        assert!(ScopeEngine::is_valid_domain_or_wildcard("example.com"));
        assert!(ScopeEngine::is_valid_domain_or_wildcard("*.example.com"));
        assert!(ScopeEngine::is_valid_domain_or_wildcard("sub.domain.example.com"));
        assert!(!ScopeEngine::is_valid_domain_or_wildcard(""));
        assert!(!ScopeEngine::is_valid_domain_or_wildcard("-invalid.com"));
    }

    #[test]
    fn test_blocked_patterns() {
        let engine = ScopeEngine::new();
        assert!(engine.is_blocked("test.gov"));
        assert!(engine.is_blocked("something.mil"));
        assert!(engine.is_blocked("localhost"));
        assert!(engine.is_blocked("127.0.0.1"));
        assert!(!engine.is_blocked("example.com"));
    }

    #[test]
    fn test_blocked_cidr() {
        let engine = ScopeEngine::new();
        assert!(engine.is_blocked_cidr("10.0.0.0/8"));
        assert!(engine.is_blocked_cidr("192.168.1.0/24"));
        assert!(engine.is_blocked_cidr("172.16.0.0/12"));
        assert!(!engine.is_blocked_cidr("8.8.8.0/24"));
    }

    #[test]
    fn test_normalize_domain() {
        assert_eq!(
            ScopeEngine::normalize_domain("https://Example.COM/"),
            "example.com"
        );
        assert_eq!(
            ScopeEngine::normalize_domain("http://test.com"),
            "test.com"
        );
    }

    #[test]
    fn test_validation() {
        let engine = ScopeEngine::new();

        let valid_def = ScopeDefinition {
            id: "test-scope".to_string(),
            name: "Test Scope".to_string(),
            description: None,
            program: None,
            in_scope: super::super::definition::InScopeDefinition {
                domains: vec!["*.example.com".to_string()],
                ..Default::default()
            },
            out_of_scope: Default::default(),
            rules: None,
            notes: None,
        };

        let result = engine.validate_definition(&valid_def).unwrap();
        assert!(result.is_valid);

        // Invalid - empty ID
        let invalid_def = ScopeDefinition {
            id: "".to_string(),
            name: "Test".to_string(),
            ..valid_def.clone()
        };

        let result = engine.validate_definition(&invalid_def).unwrap();
        assert!(!result.is_valid);
    }
}
