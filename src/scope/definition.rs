//! Scope definition types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Type of scope item
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeItemType {
    /// Exact domain match
    Domain,
    /// Wildcard subdomain pattern (*.example.com)
    Wildcard,
    /// IP CIDR range
    Cidr,
    /// ASN (AS number)
    Asn,
    /// Organization identifier
    Org,
    /// URL pattern
    Url,
    /// Repository (e.g., GitHub org/repo)
    Repository,
}

impl std::fmt::Display for ScopeItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeItemType::Domain => write!(f, "domain"),
            ScopeItemType::Wildcard => write!(f, "wildcard"),
            ScopeItemType::Cidr => write!(f, "cidr"),
            ScopeItemType::Asn => write!(f, "asn"),
            ScopeItemType::Org => write!(f, "org"),
            ScopeItemType::Url => write!(f, "url"),
            ScopeItemType::Repository => write!(f, "repository"),
        }
    }
}

/// A single scope item (domain, CIDR, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeItem {
    /// Item value (e.g., "*.example.com", "192.168.1.0/24")
    pub value: String,

    /// Type of scope item
    pub item_type: ScopeItemType,

    /// Whether this item is in-scope (true) or explicitly out-of-scope (false)
    pub in_scope: bool,

    /// Optional notes about this item
    pub notes: Option<String>,

    /// Priority for matching (higher = matched first)
    #[serde(default)]
    pub priority: i32,
}

/// YAML scope definition for import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeDefinition {
    /// Unique scope identifier
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Description
    #[serde(default)]
    pub description: Option<String>,

    /// Associated program metadata
    #[serde(default)]
    pub program: Option<ProgramMetadata>,

    /// In-scope items
    #[serde(default)]
    pub in_scope: InScopeDefinition,

    /// Out-of-scope items
    #[serde(default)]
    pub out_of_scope: OutOfScopeDefinition,

    /// Testing rules and restrictions
    #[serde(default)]
    pub rules: Option<TestingRules>,

    /// Additional notes
    #[serde(default)]
    pub notes: Option<String>,
}

/// Program metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramMetadata {
    /// Program name
    pub name: String,

    /// Platform (hackerone, bugcrowd, etc.)
    #[serde(default)]
    pub platform: Option<String>,

    /// Program URL
    #[serde(default)]
    pub url: Option<String>,

    /// Program type
    #[serde(default)]
    pub program_type: Option<String>,
}

/// In-scope definition from YAML
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InScopeDefinition {
    /// Domains (can include wildcards like *.example.com)
    #[serde(default)]
    pub domains: Vec<String>,

    /// CIDR ranges
    #[serde(default)]
    pub cidrs: Vec<String>,

    /// ASN numbers
    #[serde(default)]
    pub asns: Vec<String>,

    /// Organizations
    #[serde(default)]
    pub orgs: Vec<String>,

    /// URLs
    #[serde(default)]
    pub urls: Vec<String>,

    /// Repositories
    #[serde(default)]
    pub repositories: Vec<String>,

    /// Explicit exclusions within wildcards
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Out-of-scope definition from YAML
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutOfScopeDefinition {
    /// Domains
    #[serde(default)]
    pub domains: Vec<String>,

    /// CIDR ranges
    #[serde(default)]
    pub cidrs: Vec<String>,

    /// URLs
    #[serde(default)]
    pub urls: Vec<String>,
}

/// Testing rules and restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestingRules {
    /// Allowed testing types
    #[serde(default)]
    pub allowed: Vec<String>,

    /// Prohibited testing types
    #[serde(default)]
    pub prohibited: Vec<String>,

    /// Rate limits
    #[serde(default)]
    pub rate_limits: Option<RateLimits>,
}

/// Rate limits from program rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimits {
    /// Requests per second
    #[serde(default)]
    pub requests_per_second: Option<u32>,

    /// Maximum concurrent connections
    #[serde(default)]
    pub max_concurrent: Option<u32>,
}

/// Stored scope object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    /// Unique identifier
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Description
    pub description: Option<String>,

    /// Associated program name
    pub program: Option<String>,

    /// All scope items
    pub items: Vec<ScopeItem>,

    /// Whether scope is active
    pub active: bool,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,

    /// Testing rules
    pub rules: Option<TestingRules>,

    /// Cached counts for display
    #[serde(default)]
    pub domain_count: usize,
    #[serde(default)]
    pub cidr_count: usize,
    #[serde(default)]
    pub wildcard_count: usize,
}

impl Scope {
    /// Create a new scope from definition
    pub fn from_definition(def: ScopeDefinition, program: Option<String>) -> Self {
        let mut items = Vec::new();

        // Add in-scope domains
        for domain in &def.in_scope.domains {
            let item_type = if domain.starts_with("*.") {
                ScopeItemType::Wildcard
            } else {
                ScopeItemType::Domain
            };
            items.push(ScopeItem {
                value: domain.clone(),
                item_type,
                in_scope: true,
                notes: None,
                priority: 0,
            });
        }

        // Add in-scope CIDRs
        for cidr in &def.in_scope.cidrs {
            items.push(ScopeItem {
                value: cidr.clone(),
                item_type: ScopeItemType::Cidr,
                in_scope: true,
                notes: None,
                priority: 0,
            });
        }

        // Add in-scope ASNs
        for asn in &def.in_scope.asns {
            items.push(ScopeItem {
                value: asn.clone(),
                item_type: ScopeItemType::Asn,
                in_scope: true,
                notes: None,
                priority: 0,
            });
        }

        // Add in-scope URLs
        for url in &def.in_scope.urls {
            items.push(ScopeItem {
                value: url.clone(),
                item_type: ScopeItemType::Url,
                in_scope: true,
                notes: None,
                priority: 0,
            });
        }

        // Add in-scope repositories
        for repo in &def.in_scope.repositories {
            items.push(ScopeItem {
                value: repo.clone(),
                item_type: ScopeItemType::Repository,
                in_scope: true,
                notes: None,
                priority: 0,
            });
        }

        // Add explicit exclusions (higher priority)
        for exclude in &def.in_scope.exclude {
            let item_type = if exclude.starts_with("*.") {
                ScopeItemType::Wildcard
            } else {
                ScopeItemType::Domain
            };
            items.push(ScopeItem {
                value: exclude.clone(),
                item_type,
                in_scope: false,
                notes: Some("Explicit exclusion".to_string()),
                priority: 10,
            });
        }

        // Add out-of-scope domains
        for domain in &def.out_of_scope.domains {
            let item_type = if domain.starts_with("*.") {
                ScopeItemType::Wildcard
            } else {
                ScopeItemType::Domain
            };
            items.push(ScopeItem {
                value: domain.clone(),
                item_type,
                in_scope: false,
                notes: None,
                priority: 5,
            });
        }

        // Add out-of-scope CIDRs
        for cidr in &def.out_of_scope.cidrs {
            items.push(ScopeItem {
                value: cidr.clone(),
                item_type: ScopeItemType::Cidr,
                in_scope: false,
                notes: None,
                priority: 5,
            });
        }

        // Count items
        let domain_count = items
            .iter()
            .filter(|i| i.in_scope && i.item_type == ScopeItemType::Domain)
            .count();
        let cidr_count = items
            .iter()
            .filter(|i| i.in_scope && i.item_type == ScopeItemType::Cidr)
            .count();
        let wildcard_count = items
            .iter()
            .filter(|i| i.in_scope && i.item_type == ScopeItemType::Wildcard)
            .count();

        let now = Utc::now();

        Self {
            id: def.id,
            name: def.name,
            description: def.description,
            program: program.or(def.program.map(|p| p.name)),
            items,
            active: true,
            created_at: now,
            updated_at: now,
            rules: def.rules,
            domain_count,
            cidr_count,
            wildcard_count,
        }
    }

    /// Check if a target is in scope
    pub fn is_in_scope(&self, target: &str) -> ScopeCheckResult {
        // Sort items by priority (highest first)
        let mut sorted_items: Vec<_> = self.items.iter().collect();
        sorted_items.sort_by(|a, b| b.priority.cmp(&a.priority));

        for item in sorted_items {
            if Self::matches_item(target, item) {
                return ScopeCheckResult {
                    in_scope: item.in_scope,
                    matched_item: Some(item.clone()),
                    reason: if item.in_scope {
                        format!("Matched in-scope item: {}", item.value)
                    } else {
                        format!("Matched out-of-scope item: {}", item.value)
                    },
                };
            }
        }

        ScopeCheckResult {
            in_scope: false,
            matched_item: None,
            reason: "Target did not match any scope items".to_string(),
        }
    }

    /// Check if a target matches a scope item
    fn matches_item(target: &str, item: &ScopeItem) -> bool {
        match item.item_type {
            ScopeItemType::Domain => target.eq_ignore_ascii_case(&item.value),
            ScopeItemType::Wildcard => {
                // *.example.com matches any.example.com, sub.any.example.com, etc.
                if let Some(base) = item.value.strip_prefix("*.") {
                    target.ends_with(&format!(".{}", base)) || target.eq_ignore_ascii_case(base)
                } else {
                    false
                }
            }
            ScopeItemType::Cidr => {
                // Parse CIDR and check if IP is in range
                if let Ok(network) = item.value.parse::<ipnetwork::IpNetwork>() {
                    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
                        return network.contains(ip);
                    }
                }
                false
            }
            ScopeItemType::Asn => {
                // ASN matching would require lookup
                item.value.eq_ignore_ascii_case(target)
            }
            ScopeItemType::Url => target.starts_with(&item.value),
            ScopeItemType::Repository => target.eq_ignore_ascii_case(&item.value),
            ScopeItemType::Org => target.eq_ignore_ascii_case(&item.value),
        }
    }
}

/// Result of a scope check
#[derive(Debug, Clone)]
pub struct ScopeCheckResult {
    /// Whether the target is in scope
    pub in_scope: bool,

    /// The item that matched (if any)
    pub matched_item: Option<ScopeItem>,

    /// Human-readable reason
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_item_type_display() {
        assert_eq!(format!("{}", ScopeItemType::Domain), "domain");
        assert_eq!(format!("{}", ScopeItemType::Wildcard), "wildcard");
        assert_eq!(format!("{}", ScopeItemType::Cidr), "cidr");
    }

    #[test]
    fn test_wildcard_matching() {
        let scope = Scope {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: None,
            program: None,
            items: vec![ScopeItem {
                value: "*.example.com".to_string(),
                item_type: ScopeItemType::Wildcard,
                in_scope: true,
                notes: None,
                priority: 0,
            }],
            active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            rules: None,
            domain_count: 0,
            cidr_count: 0,
            wildcard_count: 1,
        };

        assert!(scope.is_in_scope("sub.example.com").in_scope);
        assert!(scope.is_in_scope("deep.sub.example.com").in_scope);
        assert!(!scope.is_in_scope("other.com").in_scope);
    }

    #[test]
    fn test_exclusion_priority() {
        let scope = Scope {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: None,
            program: None,
            items: vec![
                ScopeItem {
                    value: "*.example.com".to_string(),
                    item_type: ScopeItemType::Wildcard,
                    in_scope: true,
                    notes: None,
                    priority: 0,
                },
                ScopeItem {
                    value: "admin.example.com".to_string(),
                    item_type: ScopeItemType::Domain,
                    in_scope: false,
                    notes: None,
                    priority: 10,
                },
            ],
            active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            rules: None,
            domain_count: 0,
            cidr_count: 0,
            wildcard_count: 1,
        };

        // Regular subdomain should be in scope
        assert!(scope.is_in_scope("api.example.com").in_scope);

        // Excluded domain should be out of scope
        assert!(!scope.is_in_scope("admin.example.com").in_scope);
    }

    #[test]
    fn test_cidr_matching() {
        let scope = Scope {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: None,
            program: None,
            items: vec![ScopeItem {
                value: "192.168.1.0/24".to_string(),
                item_type: ScopeItemType::Cidr,
                in_scope: true,
                notes: None,
                priority: 0,
            }],
            active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            rules: None,
            domain_count: 0,
            cidr_count: 1,
            wildcard_count: 0,
        };

        assert!(scope.is_in_scope("192.168.1.1").in_scope);
        assert!(scope.is_in_scope("192.168.1.254").in_scope);
        assert!(!scope.is_in_scope("192.168.2.1").in_scope);
    }
}
