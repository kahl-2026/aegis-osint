//! Defensive scanner for one-time scans

use crate::defensive::brand::BrandMonitor;
use crate::policy::PolicyEngine;
use crate::scope::{Scope, ScopeItemType};
use crate::storage::{
    Asset, DefensiveCount, DefensiveScanResult, Evidence, Finding, FindingContext, FindingSummary,
    Storage,
};
use anyhow::Result;
use chrono::Utc;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;
use tokio::time::{timeout, Duration};

#[derive(Default)]
struct InventorySummary {
    total_assets: usize,
    by_type: Vec<DefensiveCount>,
}

#[derive(Default)]
struct ExposureSummary {
    action_exposures: usize,
    open_findings_total: usize,
    by_severity: Vec<DefensiveCount>,
    top_exposures: Vec<FindingSummary>,
}

struct DefensiveFindingDraft<'a> {
    id_prefix: &'a str,
    asset: &'a str,
    finding_type: &'a str,
    title: &'a str,
    description: String,
    impact: &'a str,
    severity: &'a str,
    source: &'a str,
    method: &'a str,
    evidence: Vec<Evidence>,
}

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
        let mut result = DefensiveScanResult {
            assets_count: 0,
            changes_count: 0,
            exposures_count: 0,
            checks_run: Vec::new(),
            inventory_breakdown: Vec::new(),
            drift_dns_changes: 0,
            drift_cert_changes: 0,
            drift_new_subdomains: 0,
            drift_new_services: 0,
            open_findings_count: 0,
            open_findings_breakdown: Vec::new(),
            top_exposures: Vec::new(),
            suspicious_brand_domains: Vec::new(),
            risky_services: Vec::new(),
            duration_secs: 0.0,
        };

        let default_checks = vec![
            "inventory".to_string(),
            "drift".to_string(),
            "exposure".to_string(),
            "brand".to_string(),
            "service-audit".to_string(),
        ];
        let selected_checks: Vec<String> = checks.cloned().unwrap_or(default_checks);

        for check in selected_checks {
            let normalized = check.trim().to_lowercase();
            match normalized.as_str() {
                "inventory" => {
                    let summary = self.run_inventory().await?;
                    result.assets_count = summary.total_assets;
                    result.inventory_breakdown = summary.by_type;
                    result.checks_run.push("inventory".to_string());
                }
                "drift" => {
                    let drift = self.run_drift_detection().await?;
                    result.drift_dns_changes = drift.dns_changes.len();
                    result.drift_cert_changes = drift.cert_changes.len();
                    result.drift_new_subdomains = drift.new_subdomains.len();
                    result.drift_new_services = drift.new_services.len();
                    result.changes_count = drift.total_changes();
                    result.checks_run.push("drift".to_string());
                }
                "exposure" => {
                    let summary = self.run_exposure_check().await?;
                    result.exposures_count += summary.action_exposures;
                    result.open_findings_count = summary.open_findings_total;
                    result.open_findings_breakdown = summary.by_severity;
                    result.top_exposures = summary.top_exposures;
                    result.checks_run.push("exposure".to_string());
                }
                "brand" => {
                    let suspicious = self.run_brand_monitoring().await?;
                    result.exposures_count += suspicious.len();
                    result.suspicious_brand_domains = suspicious;
                    result.checks_run.push("brand".to_string());
                }
                "service" | "service-audit" => {
                    let risky = self.run_service_exposure_audit().await?;
                    result.exposures_count += risky.len();
                    result.risky_services = risky;
                    result.checks_run.push("service-audit".to_string());
                }
                _ => {
                    tracing::warn!("Unknown defensive check: {}", normalized);
                }
            }
        }

        result.duration_secs = start.elapsed().as_secs_f64();
        Ok(result)
    }

    async fn run_inventory(&self) -> Result<InventorySummary> {
        let assets = self
            .storage
            .list_assets(Some(&self.scope.id), None, None, 10_000)
            .await?;

        if !assets.is_empty() {
            return Ok(InventorySummary {
                total_assets: assets.len(),
                by_type: Self::asset_type_counts(&assets),
            });
        }

        // Bootstrap from scope items if no discovered assets exist yet.
        for item in &self.scope.items {
            if !item.in_scope {
                continue;
            }
            let value = item.value.trim().to_string();
            if value.is_empty() {
                continue;
            }
            let asset_type = match item.item_type {
                ScopeItemType::Cidr => "cidr",
                ScopeItemType::Asn => "asn",
                ScopeItemType::Url => "url",
                ScopeItemType::Repository => "repo",
                _ => "subdomain",
            };

            let id = format!("inventory-{}-{}", asset_type, sha256_short(&value));
            let now = Utc::now().to_rfc3339();
            self.storage
                .save_asset(&Asset {
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
        Ok(InventorySummary {
            total_assets: refreshed.len(),
            by_type: Self::asset_type_counts(&refreshed),
        })
    }

    async fn run_drift_detection(&self) -> Result<super::monitor::MonitorCheckResult> {
        let monitor = super::monitor::AttackSurfaceMonitor::new(
            self.scope.clone(),
            60,
            self.policy.clone(),
            self.storage.clone(),
        );
        monitor.check().await
    }

    async fn run_exposure_check(&self) -> Result<ExposureSummary> {
        let context = FindingContext {
            scope: Some(&self.scope.id),
            run: None,
        };
        let mut by_severity = Vec::new();
        let mut open_total = 0usize;
        let mut action_exposures = 0usize;

        for severity in ["critical", "high", "medium", "low", "info"] {
            let findings = self
                .storage
                .list_findings(
                    Some(severity.to_string()),
                    context,
                    Some("open".to_string()),
                    None,
                    10_000,
                    "date",
                )
                .await?;
            let count = findings.len();
            if count > 0 {
                by_severity.push(DefensiveCount {
                    name: severity.to_string(),
                    count,
                });
            }
            open_total += count;
            if matches!(severity, "critical" | "high" | "medium") {
                action_exposures += count;
            }
        }

        let top_open = self
            .storage
            .list_findings(
                None,
                context,
                Some("open".to_string()),
                None,
                20,
                "severity",
            )
            .await?;
        let top_exposures = top_open
            .into_iter()
            .map(|finding| FindingSummary {
                id: finding.id,
                asset: finding.asset,
                title: finding.title,
                severity: finding.severity,
                confidence: finding.confidence,
                status: finding.status,
            })
            .collect();

        Ok(ExposureSummary {
            action_exposures,
            open_findings_total: open_total,
            by_severity,
            top_exposures,
        })
    }

    async fn run_brand_monitoring(&self) -> Result<Vec<String>> {
        let brand_source = self
            .scope
            .program
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(&self.scope.name);
        let mut known_domains = HashSet::new();
        for item in &self.scope.items {
            if !item.in_scope {
                continue;
            }
            match item.item_type {
                ScopeItemType::Domain | ScopeItemType::Wildcard => {
                    let domain = item.value.trim_start_matches("*.").to_lowercase();
                    if !domain.is_empty() {
                        known_domains.insert(domain);
                    }
                }
                ScopeItemType::Url => {
                    if let Ok(parsed) = url::Url::parse(&item.value) {
                        if let Some(host) = parsed.host_str() {
                            known_domains.insert(host.trim_start_matches("*.").to_lowercase());
                        }
                    }
                }
                _ => {}
            }
        }

        if known_domains.is_empty() {
            return Ok(Vec::new());
        }

        let mut monitor = BrandMonitor::new(brand_source);
        for domain in &known_domains {
            monitor.add_known_domain(domain);
        }

        let mut candidate_scores = HashMap::<String, (f64, Vec<String>)>::new();
        for variation in monitor.generate_typosquats() {
            let mut candidate = variation.domain.trim().to_lowercase();
            if candidate.is_empty() {
                continue;
            }
            if !candidate.contains('.') {
                candidate.push_str(".com");
            }
            if monitor.is_known(&candidate) {
                continue;
            }

            let analysis = monitor.analyze_domain(&candidate);
            if !analysis.is_suspicious {
                continue;
            }

            candidate_scores
                .entry(candidate)
                .and_modify(|(best_score, best_patterns)| {
                    if analysis.similarity_score > *best_score {
                        *best_score = analysis.similarity_score;
                        *best_patterns = analysis.impersonation_patterns.clone();
                    }
                })
                .or_insert((analysis.similarity_score, analysis.impersonation_patterns));
        }

        let mut ranked = candidate_scores.into_iter().collect::<Vec<_>>();
        ranked.sort_by(|left, right| {
            right
                .1
                 .0
                .partial_cmp(&left.1 .0)
                .unwrap_or(Ordering::Equal)
        });

        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
        let mut suspicious = Vec::new();
        for (domain, (similarity, patterns)) in ranked.into_iter().take(24) {
            let resolves = matches!(
                timeout(Duration::from_secs(3), resolver.lookup_ip(domain.as_str())).await,
                Ok(Ok(ips)) if ips.iter().next().is_some()
            );
            if !resolves {
                continue;
            }

            let pattern_list = if patterns.is_empty() {
                "none".to_string()
            } else {
                patterns.join(",")
            };
            let severity = if patterns
                .iter()
                .any(|pattern| pattern == "credential_harvesting" || pattern == "trust_abuse")
            {
                "high"
            } else {
                "medium"
            };
            let title = if severity == "high" {
                "Likely active brand impersonation domain"
            } else {
                "Potential active typosquat domain"
            };

            self.save_defensive_finding(DefensiveFindingDraft {
                id_prefix: "def-brand-impersonation",
                asset: &domain,
                finding_type: "brand-impersonation",
                title,
                description: format!(
                    "Suspicious domain {} resolved during defensive brand monitoring (similarity {:.2}).",
                    domain, similarity
                ),
                impact: "Active brand impersonation infrastructure can support phishing, credential theft, and trust abuse.",
                severity,
                source: "defensive-brand-monitor",
                method: "dns-resolution",
                evidence: vec![Evidence {
                    description: "Resolved suspicious brand-like domain".to_string(),
                    source: "brand-monitor".to_string(),
                    data: Some(format!(
                        "similarity={:.2};patterns={}",
                        similarity, pattern_list
                    )),
                    timestamp: Utc::now().to_rfc3339(),
                }],
            })
            .await?;

            suspicious.push(domain);
        }

        suspicious.sort();
        suspicious.dedup();
        Ok(suspicious)
    }

    async fn run_service_exposure_audit(&self) -> Result<Vec<String>> {
        let mut risky_services = Vec::new();
        let service_assets = self
            .storage
            .list_assets(Some(&self.scope.id), Some("service"), None, 20_000)
            .await?;

        for service in service_assets {
            let Some((host, port)) = Self::parse_service_endpoint(&service.value) else {
                continue;
            };
            let Some((severity, risk_label, impact)) = Self::risky_port_profile(port) else {
                continue;
            };

            let endpoint = format!("{}:{}", host, port);
            let title = format!("Externally reachable risky service port {}", port);
            risky_services.push(format!("{} [{}]", endpoint, risk_label));
            self.save_defensive_finding(DefensiveFindingDraft {
                id_prefix: "def-service-exposure",
                asset: &endpoint,
                finding_type: "service-exposure",
                title: &title,
                description: format!(
                    "Service asset {} matches risky service profile '{}'.",
                    endpoint, risk_label
                ),
                impact,
                severity,
                source: "defensive-service-audit",
                method: "asset-port-profile",
                evidence: vec![Evidence {
                    description: "Risky service port profile match".to_string(),
                    source: "service-asset".to_string(),
                    data: Some(format!("port={};profile={}", port, risk_label)),
                    timestamp: Utc::now().to_rfc3339(),
                }],
            })
            .await?;
        }

        risky_services.sort();
        risky_services.dedup();
        Ok(risky_services)
    }

    async fn save_defensive_finding(&self, draft: DefensiveFindingDraft<'_>) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let finding = Finding {
            id: format!("{}-{}", draft.id_prefix, sha256_short(draft.asset)),
            scope_id: self.scope.id.clone(),
            run_id: None,
            asset: draft.asset.to_string(),
            finding_type: draft.finding_type.to_string(),
            title: draft.title.to_string(),
            description: draft.description,
            impact: draft.impact.to_string(),
            severity: draft.severity.to_string(),
            confidence: 80,
            status: Some("open".to_string()),
            reproduction: Some(
                "Validate this defensive exposure in context and assign remediation owner."
                    .to_string(),
            ),
            source: draft.source.to_string(),
            method: draft.method.to_string(),
            scope_verified: true,
            evidence: draft.evidence,
            created_at: now.clone(),
            updated_at: now,
        };
        self.storage.save_finding(&finding).await
    }

    fn parse_service_endpoint(value: &str) -> Option<(String, u16)> {
        let trimmed = value.trim();
        let (host, port) = trimmed.rsplit_once(':')?;
        let parsed_port = port.parse::<u16>().ok()?;
        let normalized_host = host.trim().trim_start_matches('[').trim_end_matches(']');
        if normalized_host.is_empty() {
            return None;
        }
        Some((normalized_host.to_string(), parsed_port))
    }

    fn risky_port_profile(port: u16) -> Option<(&'static str, &'static str, &'static str)> {
        match port {
            23 => Some((
                "high",
                "telnet-cleartext-admin",
                "Telnet is an insecure administrative protocol and is commonly abused when exposed.",
            )),
            2375 => Some((
                "high",
                "docker-api-unauthenticated",
                "Docker daemon API exposure can allow remote container execution and host compromise.",
            )),
            3389 => Some((
                "high",
                "rdp-exposed",
                "Public RDP exposure increases brute-force and credential replay attack risk.",
            )),
            6379 => Some((
                "high",
                "redis-exposed",
                "Public Redis services are frequently abused for data theft and remote code execution paths.",
            )),
            9200 => Some((
                "high",
                "elasticsearch-exposed",
                "Public Elasticsearch nodes can leak indexed data and cluster metadata.",
            )),
            27017 => Some((
                "high",
                "mongodb-exposed",
                "Public MongoDB exposure can allow unauthorized data access.",
            )),
            11211 => Some((
                "high",
                "memcached-exposed",
                "Memcached exposure can enable data leakage and amplification abuse.",
            )),
            21 => Some((
                "medium",
                "ftp-exposed",
                "Public FTP service often implies weaker transport security and credential exposure risk.",
            )),
            5900 => Some((
                "medium",
                "vnc-exposed",
                "Public VNC endpoints are common brute-force and unauthorized access targets.",
            )),
            3306 => Some((
                "medium",
                "mysql-exposed",
                "Public MySQL exposure can increase risk of credential abuse and data exfiltration.",
            )),
            5432 => Some((
                "medium",
                "postgres-exposed",
                "Public PostgreSQL exposure can increase risk of unauthorized data access.",
            )),
            _ => None,
        }
    }

    fn asset_type_counts(assets: &[Asset]) -> Vec<DefensiveCount> {
        let mut by_type = BTreeMap::<String, usize>::new();
        for asset in assets {
            *by_type.entry(asset.asset_type.clone()).or_insert(0usize) += 1;
        }
        by_type
            .into_iter()
            .map(|(name, count)| DefensiveCount { name, count })
            .collect()
    }
}

fn sha256_short(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::DefensiveScanner;

    #[test]
    fn parse_service_endpoint_handles_basic_host_port() {
        let parsed = DefensiveScanner::parse_service_endpoint("scanme.nmap.org:443");
        assert_eq!(parsed, Some(("scanme.nmap.org".to_string(), 443)));
    }

    #[test]
    fn risky_port_profile_flags_expected_ports() {
        assert!(DefensiveScanner::risky_port_profile(23).is_some());
        assert!(DefensiveScanner::risky_port_profile(2375).is_some());
        assert!(DefensiveScanner::risky_port_profile(443).is_none());
    }
}
