//! Continuous monitoring module

use crate::policy::PolicyEngine;
use crate::scope::Scope;
use crate::storage::Storage;
use anyhow::Result;
use chrono::Utc;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// Monitor for continuous attack surface tracking
#[allow(dead_code)]
pub struct AttackSurfaceMonitor {
    scope: Scope,
    interval_minutes: u32,
    policy: PolicyEngine,
    storage: Storage,
}

impl AttackSurfaceMonitor {
    /// Create a new monitor
    pub fn new(
        scope: Scope,
        interval_minutes: u32,
        policy: PolicyEngine,
        storage: Storage,
    ) -> Self {
        Self {
            scope,
            interval_minutes,
            policy,
            storage,
        }
    }

    /// Run a single monitoring check
    pub async fn check(&self) -> Result<MonitorCheckResult> {
        let policy_check = self.policy.check_defensive_operation(&self.scope).await?;
        if !policy_check.allowed {
            let reasons = policy_check.reasons.join(", ");
            anyhow::bail!("Defensive monitoring blocked by policy: {}", reasons);
        }

        let mut result = MonitorCheckResult::default();

        // Check DNS changes
        result.dns_changes = self.check_dns_changes().await?;

        // Check certificate changes
        result.cert_changes = self.check_cert_changes().await?;

        // Check for new subdomains
        result.new_subdomains = self.check_new_subdomains().await?;

        // Check for new ports/services
        result.new_services = self.check_new_services().await?;

        Ok(result)
    }

    async fn check_dns_changes(&self) -> Result<Vec<DnsChange>> {
        let mut changes = Vec::new();
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

        let assets = self.storage.list_assets(Some(&self.scope.id), Some("subdomain"), None, 500).await?;
        for asset in assets {
            let host = asset.value.trim().to_lowercase();
            if host.is_empty() {
                continue;
            }

            if let Ok(ips) = resolver.lookup_ip(&host).await {
                let current = ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>();
                if !current.is_empty() {
                    let joined = current.join(",");
                    let old = asset
                        .metadata
                        .as_ref()
                        .and_then(|m| m.get("dns_a_records"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if !old.is_empty() && old != joined {
                        changes.push(DnsChange {
                            domain: host.clone(),
                            record_type: "A".to_string(),
                            old_value: old,
                            new_value: joined,
                            detected_at: Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        Ok(changes)
    }

    async fn check_cert_changes(&self) -> Result<Vec<CertChange>> {
        let mut changes = Vec::new();

        let assets = self.storage.list_assets(Some(&self.scope.id), Some("subdomain"), None, 500).await?;
        for asset in assets {
            let host = asset.value.trim().to_lowercase();
            if host.is_empty() {
                continue;
            }

            let url = format!("https://{}/", host);
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .danger_accept_invalid_certs(true)
                .build()?;

            if let Ok(resp) = client.head(&url).send().await {
                if let Some(server) = resp.headers().get("server").and_then(|v| v.to_str().ok()) {
                    let old = asset
                        .metadata
                        .as_ref()
                        .and_then(|m| m.get("tls_server_header"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if !old.is_empty() && old != server {
                        changes.push(CertChange {
                            domain: host.clone(),
                            change_type: CertChangeType::IssuerChanged,
                            details: format!("Server header changed from '{}' to '{}'", old, server),
                            detected_at: Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        Ok(changes)
    }

    async fn check_new_subdomains(&self) -> Result<Vec<String>> {
        let mut discovered = Vec::new();
        let mut known = std::collections::HashSet::new();
        let current_assets = self
            .storage
            .list_assets(Some(&self.scope.id), Some("subdomain"), None, 10_000)
            .await?;
        for a in current_assets {
            known.insert(a.value.to_lowercase());
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()?;

        for item in &self.scope.items {
            if !item.in_scope {
                continue;
            }
            let base = item.value.trim_start_matches("*.").to_lowercase();
            if base.contains('/') || base.is_empty() {
                continue;
            }

            let url = format!("https://crt.sh/?q=%.{}&output=json", base);
            if let Ok(resp) = client.get(&url).send().await {
                if resp.status().is_success() {
                    if let Ok(rows) = resp.json::<Vec<CtRow>>().await {
                        for row in rows {
                            for raw in row.name_value.split('\n') {
                                let host = raw.trim().trim_start_matches("*.").to_lowercase();
                                if host.ends_with(&base) && !known.contains(&host) {
                                    discovered.push(host.clone());
                                    known.insert(host);
                                }
                            }
                        }
                    }
                }
            }
        }

        discovered.sort();
        discovered.dedup();
        Ok(discovered)
    }

    async fn check_new_services(&self) -> Result<Vec<ServiceChange>> {
        let mut changes = Vec::new();
        let ports = [80u16, 443, 8080, 8443];

        let ip_assets = self
            .storage
            .list_assets(Some(&self.scope.id), Some("ip"), None, 1000)
            .await?;

        for ip_asset in ip_assets {
            let host = ip_asset.value.clone();
            for port in ports {
                let addr = format!("{}:{}", host, port);
                if let Ok(parsed) = addr.parse::<std::net::SocketAddr>() {
                    let reachable = tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        tokio::net::TcpStream::connect(parsed),
                    )
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                    .is_some();

                    if reachable {
                        changes.push(ServiceChange {
                            host: host.clone(),
                            port,
                            service: if port == 443 || port == 8443 {
                                "https".to_string()
                            } else {
                                "http".to_string()
                            },
                            change_type: ServiceChangeType::New,
                            detected_at: Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        Ok(changes)
    }
}

/// Result of a monitoring check
#[derive(Debug, Default)]
pub struct MonitorCheckResult {
    pub dns_changes: Vec<DnsChange>,
    pub cert_changes: Vec<CertChange>,
    pub new_subdomains: Vec<String>,
    pub new_services: Vec<ServiceChange>,
}

impl MonitorCheckResult {
    pub fn has_changes(&self) -> bool {
        !self.dns_changes.is_empty()
            || !self.cert_changes.is_empty()
            || !self.new_subdomains.is_empty()
            || !self.new_services.is_empty()
    }

    pub fn total_changes(&self) -> usize {
        self.dns_changes.len()
            + self.cert_changes.len()
            + self.new_subdomains.len()
            + self.new_services.len()
    }
}

/// DNS change detection
#[derive(Debug)]
pub struct DnsChange {
    pub domain: String,
    pub record_type: String,
    pub old_value: String,
    pub new_value: String,
    pub detected_at: String,
}

/// Certificate change detection
#[derive(Debug)]
pub struct CertChange {
    pub domain: String,
    pub change_type: CertChangeType,
    pub details: String,
    pub detected_at: String,
}

/// Type of certificate change
#[derive(Debug)]
pub enum CertChangeType {
    NewCert,
    Expiring,
    Expired,
    Renewed,
    IssuerChanged,
}

/// Service change detection
#[derive(Debug)]
pub struct ServiceChange {
    pub host: String,
    pub port: u16,
    pub service: String,
    pub change_type: ServiceChangeType,
    pub detected_at: String,
}

/// Type of service change
#[derive(Debug)]
pub enum ServiceChangeType {
    New,
    Removed,
    VersionChanged,
}

#[derive(Debug, serde::Deserialize)]
struct CtRow {
    name_value: String,
}
