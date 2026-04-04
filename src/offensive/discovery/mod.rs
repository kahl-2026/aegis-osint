//! Asset discovery module
//!
//! Implements passive and low-impact asset discovery:
//! - Certificate Transparency logs
//! - DNS enumeration
//! - ASN/netblock mapping
//! - Service fingerprinting

use crate::policy::PolicyEngine;
use crate::scope::Scope;
use crate::storage::{Asset, Storage};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashSet;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// Asset discovery engine
pub struct DiscoveryEngine {
    scope: Scope,
    policy: PolicyEngine,
    storage: Storage,
    resolver: TokioAsyncResolver,
}

impl DiscoveryEngine {
    /// Create a new discovery engine
    pub async fn new(scope: Scope, policy: PolicyEngine, storage: Storage) -> Result<Self> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

        Ok(Self {
            scope,
            policy,
            storage,
            resolver,
        })
    }

    /// Run CT log discovery for a domain
    pub async fn discover_ct_logs(&self, base_domain: &str) -> Result<Vec<String>> {
        // Validate scope
        let check = self.policy.check_target(base_domain, &self.scope).await?;
        if !check.allowed {
            tracing::warn!(
                "CT log discovery blocked for {}: {}",
                base_domain,
                check.reasons.join(", ")
            );
            return Ok(vec![]);
        }

        // Wait for rate limit
        self.policy.wait_for_rate_limit().await;

        let mut discovered = Vec::new();

        // Query crt.sh API (Certificate Transparency)
        let url = format!("https://crt.sh/?q=%.{}&output=json", base_domain);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(entries) = response.json::<Vec<CtLogEntry>>().await {
                        let mut seen = HashSet::new();
                        for entry in entries {
                            let name = entry.name_value.to_lowercase();
                            // Handle multiple names in one entry
                            for name in name.split('\n') {
                                let name = name.trim();
                                if !name.is_empty() && !seen.contains(name) {
                                    // Verify it's in scope
                                    if self.scope.is_in_scope(name).in_scope {
                                        discovered.push(name.to_string());
                                        seen.insert(name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("CT log query failed for {}: {}", base_domain, e);
            }
        }

        // Save discovered assets
        for subdomain in &discovered {
            self.save_asset(subdomain, "subdomain").await?;
        }

        tracing::info!(
            "CT logs: discovered {} subdomains for {}",
            discovered.len(),
            base_domain
        );
        Ok(discovered)
    }

    /// Run DNS enumeration for a domain
    pub async fn discover_dns(&self, domain: &str) -> Result<DnsDiscoveryResult> {
        // Validate scope
        let check = self.policy.check_target(domain, &self.scope).await?;
        if !check.allowed {
            return Ok(DnsDiscoveryResult::default());
        }

        self.policy.wait_for_rate_limit().await;

        let mut result = DnsDiscoveryResult::default();

        // A records
        if let Ok(response) = self.resolver.lookup_ip(domain).await {
            for ip in response.iter() {
                result.a_records.push(ip.to_string());
            }
        }

        // MX records
        if let Ok(response) = self.resolver.mx_lookup(domain).await {
            for record in response.iter() {
                result.mx_records.push(record.exchange().to_string());
            }
        }

        // NS records
        if let Ok(response) = self.resolver.ns_lookup(domain).await {
            for record in response.iter() {
                result.ns_records.push(record.to_string());
            }
        }

        // TXT records
        if let Ok(response) = self.resolver.txt_lookup(domain).await {
            for record in response.iter() {
                result.txt_records.push(record.to_string());
            }
        }

        // Save IPs as assets
        for ip in &result.a_records {
            if self.scope.is_in_scope(ip).in_scope {
                self.save_asset(ip, "ip").await?;
            }
        }

        Ok(result)
    }

    /// Aggressive subdomain permutation checks for common hostnames
    pub async fn discover_common_subdomains(
        &self,
        domain: &str,
        prefixes: &[&str],
    ) -> Result<Vec<String>> {
        let check = self.policy.check_target(domain, &self.scope).await?;
        if !check.allowed {
            return Ok(Vec::new());
        }

        let mut discovered = Vec::new();
        let mut seen = HashSet::new();
        for prefix in prefixes {
            let candidate = format!("{}.{}", prefix, domain);
            if !self.scope.is_in_scope(&candidate).in_scope {
                continue;
            }
            self.policy.wait_for_rate_limit().await;
            if let Ok(response) = self.resolver.lookup_ip(&candidate).await {
                let has_records = response.iter().next().is_some();
                if has_records && seen.insert(candidate.clone()) {
                    self.save_asset(&candidate, "subdomain").await?;
                    discovered.push(candidate);
                }
            }
        }

        Ok(discovered)
    }

    /// Discover ASN information for an IP
    pub async fn discover_asn(&self, ip: &str) -> Result<Option<AsnInfo>> {
        // Validate scope
        let check = self.policy.check_target(ip, &self.scope).await?;
        if !check.allowed {
            return Ok(None);
        }

        self.policy.wait_for_rate_limit().await;

        // Query Team Cymru DNS service for ASN info
        // Reverse IP octets and append .origin.asn.cymru.com
        let octets: Vec<&str> = ip.split('.').collect();
        if octets.len() != 4 {
            return Ok(None);
        }

        let reversed = format!(
            "{}.{}.{}.{}.origin.asn.cymru.com",
            octets[3], octets[2], octets[1], octets[0]
        );

        if let Ok(response) = self.resolver.txt_lookup(&reversed).await {
            for record in response.iter() {
                let txt = record.to_string();
                // Format: "ASN | IP/Prefix | Country | Registry | Allocated"
                let parts: Vec<&str> = txt.split('|').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    return Ok(Some(AsnInfo {
                        asn: parts[0].trim_matches('"').to_string(),
                        prefix: parts[1].to_string(),
                        country: parts[2].to_string(),
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Run service fingerprinting (basic)
    pub async fn fingerprint_service(&self, host: &str, port: u16) -> Result<Option<ServiceInfo>> {
        // Validate scope
        let check = self.policy.check_target(host, &self.scope).await?;
        if !check.allowed {
            return Ok(None);
        }

        self.policy.wait_for_rate_limit().await;

        const HTTPS_PORTS: &[u16] = &[443, 8443, 9443];
        const HTTP_PORTS: &[u16] = &[80, 8080, 8081, 8000, 8888, 3000, 5000, 7001, 9000];

        // For HTTPS services, try to get certificate info
        if HTTPS_PORTS.contains(&port) {
            return self.fingerprint_https(host, port).await;
        }

        // For HTTP, do a simple HEAD request
        if HTTP_PORTS.contains(&port) {
            return self.fingerprint_http(host, port).await;
        }

        Ok(None)
    }

    async fn fingerprint_https(&self, host: &str, port: u16) -> Result<Option<ServiceInfo>> {
        let url = format!("https://{}:{}/", host, port);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(false)
            .build()?;

        match client.head(&url).send().await {
            Ok(response) => {
                let mut info = ServiceInfo {
                    service: "https".to_string(),
                    version: None,
                    banner: None,
                    headers: std::collections::HashMap::new(),
                };

                // Extract server header
                if let Some(server) = response.headers().get("server") {
                    if let Ok(s) = server.to_str() {
                        info.headers.insert("server".to_string(), s.to_string());
                    }
                }

                // Extract other interesting headers
                for (name, value) in response.headers().iter() {
                    let name_str = name.to_string().to_lowercase();
                    if name_str.starts_with("x-") || name_str.contains("powered") {
                        if let Ok(v) = value.to_str() {
                            info.headers.insert(name_str, v.to_string());
                        }
                    }
                }

                Ok(Some(info))
            }
            Err(_) => Ok(None),
        }
    }

    async fn fingerprint_http(&self, host: &str, port: u16) -> Result<Option<ServiceInfo>> {
        let url = format!("http://{}:{}/", host, port);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        match client.head(&url).send().await {
            Ok(response) => {
                let mut info = ServiceInfo {
                    service: "http".to_string(),
                    version: None,
                    banner: None,
                    headers: std::collections::HashMap::new(),
                };

                if let Some(server) = response.headers().get("server") {
                    if let Ok(s) = server.to_str() {
                        info.headers.insert("server".to_string(), s.to_string());
                    }
                }

                Ok(Some(info))
            }
            Err(_) => Ok(None),
        }
    }

    /// Save discovered asset to storage
    async fn save_asset(&self, value: &str, asset_type: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let id = format!("{}-{}", asset_type, sha256_short(value));

        let asset = Asset {
            id,
            scope_id: self.scope.id.clone(),
            asset_type: asset_type.to_string(),
            value: value.to_string(),
            tags: vec![],
            metadata: None,
            first_seen: now.clone(),
            last_seen: now,
        };

        self.storage.save_asset(&asset).await
    }
}

/// Helper to create short hash for IDs
fn sha256_short(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)[..12].to_string()
}

/// CT log entry from crt.sh
#[derive(Debug, serde::Deserialize)]
struct CtLogEntry {
    name_value: String,
}

/// DNS discovery result
#[derive(Debug, Default)]
pub struct DnsDiscoveryResult {
    pub a_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub txt_records: Vec<String>,
}

/// ASN information
#[derive(Debug)]
pub struct AsnInfo {
    pub asn: String,
    pub prefix: String,
    pub country: String,
}

/// Service fingerprint information
#[derive(Debug)]
pub struct ServiceInfo {
    pub service: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub headers: std::collections::HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_short() {
        let hash = sha256_short("example.com");
        assert_eq!(hash.len(), 12);
    }
}
