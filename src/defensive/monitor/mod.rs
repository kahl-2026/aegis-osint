//! Continuous monitoring module

use crate::policy::PolicyEngine;
use crate::scope::Scope;
use crate::storage::{Asset, Storage};
use anyhow::Result;
use chrono::Utc;
use serde_json::Value;
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
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

        let assets = self
            .storage
            .list_assets(Some(&self.scope.id), Some("subdomain"), None, 500)
            .await?;
        for mut asset in assets {
            let host = asset.value.trim().to_lowercase();
            if host.is_empty() {
                continue;
            }

            if let Ok(ips) = resolver.lookup_ip(&host).await {
                let mut current = ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>();
                current.sort();
                current.dedup();
                if !current.is_empty() {
                    let joined = current.join(",");
                    let old =
                        Self::get_metadata_string(&asset, "dns_a_records").unwrap_or_default();
                    if !old.is_empty() && old != joined {
                        let detected_at = Utc::now().to_rfc3339();
                        changes.push(DnsChange {
                            domain: host.clone(),
                            record_type: "A".to_string(),
                            old_value: old,
                            new_value: joined.clone(),
                            detected_at: detected_at.clone(),
                        });
                        self.storage
                            .save_asset_history_event(
                                &asset.id,
                                "dns_change",
                                &format!("A record set changed for {}", host),
                                &detected_at,
                            )
                            .await?;
                    }

                    let now = Utc::now().to_rfc3339();
                    Self::set_metadata_string(&mut asset, "dns_a_records", joined);
                    Self::set_metadata_string(&mut asset, "dns_last_checked", now.clone());
                    asset.last_seen = now;
                    self.storage.save_asset(&asset).await?;
                }
            }
        }

        Ok(changes)
    }

    async fn check_cert_changes(&self) -> Result<Vec<CertChange>> {
        let mut changes = Vec::new();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .danger_accept_invalid_certs(false)
            .build()?;

        let assets = self
            .storage
            .list_assets(Some(&self.scope.id), Some("subdomain"), None, 500)
            .await?;
        for mut asset in assets {
            let host = asset.value.trim().to_lowercase();
            if host.is_empty() {
                continue;
            }

            let url = format!("https://{}/", host);
            if let Ok(resp) = client.head(&url).send().await {
                if let Some(signature) = Self::build_tls_signature(resp.headers()) {
                    let old = Self::get_metadata_string(&asset, "tls_observed_signature")
                        .unwrap_or_default();
                    if !old.is_empty() && old != signature {
                        let detected_at = Utc::now().to_rfc3339();
                        changes.push(CertChange {
                            domain: host.clone(),
                            change_type: CertChangeType::IssuerChanged,
                            details: format!(
                                "TLS response signature changed from '{}' to '{}'",
                                old, signature
                            ),
                            detected_at: detected_at.clone(),
                        });
                        self.storage
                            .save_asset_history_event(
                                &asset.id,
                                "cert_change",
                                &format!("TLS signature changed for {}", host),
                                &detected_at,
                            )
                            .await?;
                    }

                    let now = Utc::now().to_rfc3339();
                    Self::set_metadata_string(&mut asset, "tls_observed_signature", signature);
                    Self::set_metadata_string(&mut asset, "tls_last_checked", now.clone());
                    asset.last_seen = now;
                    self.storage.save_asset(&asset).await?;
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
                                if host.ends_with(&base)
                                    && !known.contains(&host)
                                    && self.scope.is_in_scope(&host).in_scope
                                {
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
        for host in &discovered {
            let asset_id = self
                .save_discovered_asset("subdomain", host, vec!["monitoring".to_string()])
                .await?;
            self.storage
                .save_asset_history_event(
                    &asset_id,
                    "asset_discovered",
                    &format!("Discovered new subdomain {}", host),
                    &Utc::now().to_rfc3339(),
                )
                .await?;
        }
        Ok(discovered)
    }

    async fn check_new_services(&self) -> Result<Vec<ServiceChange>> {
        let mut changes = Vec::new();
        let ports = [80u16, 443, 8080, 8443];
        let mut seen_changes = std::collections::HashSet::new();
        let existing_services = self
            .storage
            .list_assets(Some(&self.scope.id), Some("service"), None, 20_000)
            .await?;
        let mut existing_set = existing_services
            .into_iter()
            .map(|asset| asset.value.to_lowercase())
            .collect::<std::collections::HashSet<_>>();

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
                        let service_key = format!("{}:{}", host.to_lowercase(), port);
                        if existing_set.contains(&service_key) || !seen_changes.insert(service_key)
                        {
                            continue;
                        }
                        let detected_at = Utc::now().to_rfc3339();
                        changes.push(ServiceChange {
                            host: host.clone(),
                            port,
                            service: if port == 443 || port == 8443 {
                                "https".to_string()
                            } else {
                                "http".to_string()
                            },
                            change_type: ServiceChangeType::New,
                            detected_at: detected_at.clone(),
                        });
                        let service_asset_id = self
                            .save_discovered_asset(
                                "service",
                                &format!("{}:{}", host, port),
                                vec!["monitoring".to_string(), "service".to_string()],
                            )
                            .await?;
                        self.storage
                            .save_asset_history_event(
                                &service_asset_id,
                                "service_change",
                                &format!("Discovered new service {}:{}", host, port),
                                &detected_at,
                            )
                            .await?;
                        existing_set.insert(format!("{}:{}", host.to_lowercase(), port));
                    }
                }
            }
        }

        Ok(changes)
    }

    async fn save_discovered_asset(
        &self,
        asset_type: &str,
        value: &str,
        tags: Vec<String>,
    ) -> Result<String> {
        let now = Utc::now().to_rfc3339();
        let id = format!("{}-{}", asset_type, sha256_short(value));
        self.storage
            .save_asset(&Asset {
                id: id.clone(),
                scope_id: self.scope.id.clone(),
                asset_type: asset_type.to_string(),
                value: value.to_string(),
                tags,
                metadata: None,
                first_seen: now.clone(),
                last_seen: now,
            })
            .await?;
        Ok(id)
    }

    fn get_metadata_string(asset: &Asset, key: &str) -> Option<String> {
        asset
            .metadata
            .as_ref()
            .and_then(|m| m.get(key))
            .and_then(|v| v.as_str())
            .map(ToString::to_string)
    }

    fn set_metadata_string(asset: &mut Asset, key: &str, value: String) {
        let metadata = asset
            .metadata
            .get_or_insert_with(std::collections::HashMap::new);
        metadata.insert(key.to_string(), Value::String(value));
    }

    fn build_tls_signature(headers: &reqwest::header::HeaderMap) -> Option<String> {
        let mut parts = Vec::new();
        for key in ["server", "strict-transport-security", "alt-svc"] {
            if let Some(value) = headers.get(key).and_then(|v| v.to_str().ok()) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    parts.push(format!("{}={}", key, trimmed));
                }
            }
        }
        if parts.is_empty() {
            return None;
        }
        parts.sort();
        Some(parts.join("|"))
    }
}

fn sha256_short(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)[..12].to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_short_len() {
        assert_eq!(sha256_short("monitoring").len(), 12);
    }

    #[test]
    fn test_build_tls_signature() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("server", "nginx".parse().expect("valid header"));
        headers.insert(
            "strict-transport-security",
            "max-age=31536000".parse().expect("valid header"),
        );

        let signature = AttackSurfaceMonitor::build_tls_signature(&headers);
        assert_eq!(
            signature.as_deref(),
            Some("server=nginx|strict-transport-security=max-age=31536000")
        );
    }
}
