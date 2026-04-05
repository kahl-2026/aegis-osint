//! OSINT toolkit suites for expanded intelligence collection.
//!
//! These suites rely on lawful, public-data sources and preserve scope/policy checks.

use crate::policy::PolicyEngine;
use crate::scope::{Scope, ScopeItemType};
use crate::storage::{Asset, Evidence, Finding, ModuleSummary, Storage};
use anyhow::Result;
use chrono::{DateTime, Utc};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioAsyncResolver;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolkitSuite {
    DnsIntelligence,
    RepoIntelligence,
    TlsInfrastructure,
    LeakMentions,
}

impl ToolkitSuite {
    pub fn label(self) -> &'static str {
        match self {
            ToolkitSuite::DnsIntelligence => "dns-intelligence-suite",
            ToolkitSuite::RepoIntelligence => "repo-intelligence-suite",
            ToolkitSuite::TlsInfrastructure => "tls-infra-intelligence-suite",
            ToolkitSuite::LeakMentions => "leak-mention-intelligence-suite",
        }
    }

    pub fn all() -> [Self; 4] {
        [
            ToolkitSuite::DnsIntelligence,
            ToolkitSuite::RepoIntelligence,
            ToolkitSuite::TlsInfrastructure,
            ToolkitSuite::LeakMentions,
        ]
    }
}

#[derive(Default)]
struct SuiteCounters {
    assets_discovered: usize,
    findings_created: usize,
    evidence_collected: usize,
}

pub struct OsintToolkitEngine {
    scope: Scope,
    policy: PolicyEngine,
    storage: Storage,
    client: reqwest::Client,
    resolver: TokioAsyncResolver,
    run_id: Option<String>,
}

impl OsintToolkitEngine {
    pub fn new(
        scope: Scope,
        policy: PolicyEngine,
        storage: Storage,
        run_id: Option<&str>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .user_agent("AegisOSINT/0.1 (+authorized-security-testing)")
            .build()?;
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

        Ok(Self {
            scope,
            policy,
            storage,
            client,
            resolver,
            run_id: run_id.map(str::to_string),
        })
    }

    pub async fn run_suite(&self, suite: ToolkitSuite, aggressive: bool) -> Result<ModuleSummary> {
        match suite {
            ToolkitSuite::DnsIntelligence => self.run_dns_suite(aggressive).await,
            ToolkitSuite::RepoIntelligence => self.run_repo_suite(aggressive).await,
            ToolkitSuite::TlsInfrastructure => self.run_tls_infra_suite(aggressive).await,
            ToolkitSuite::LeakMentions => self.run_leak_mention_suite(aggressive).await,
        }
    }

    pub async fn run_all(&self, aggressive: bool) -> Result<Vec<ModuleSummary>> {
        let mut summaries = Vec::new();
        for suite in ToolkitSuite::all() {
            summaries.push(self.run_suite(suite, aggressive).await?);
        }
        Ok(summaries)
    }

    async fn run_dns_suite(&self, aggressive: bool) -> Result<ModuleSummary> {
        let mut counters = SuiteCounters::default();
        let domains = self.scope_domains();

        for domain in domains {
            let check = self.policy.check_target(&domain, &self.scope).await?;
            if !check.allowed {
                continue;
            }

            self.policy.wait_for_rate_limit().await;
            if let Ok(ns) = self.resolver.ns_lookup(&domain).await {
                let ns_count = ns.iter().count();
                if ns_count <= 1 {
                    self.save_finding(
                        &mut counters,
                        "dns-ns-concentration",
                        &domain,
                        "dns-intelligence",
                        "Single nameserver concentration detected",
                        &format!(
                            "Domain {} resolves to {} nameserver(s), reducing DNS resilience.",
                            domain, ns_count
                        ),
                        "Single-provider nameserver dependency can increase outage and takeover blast-radius.",
                        "low",
                        "ns-resilience-check",
                        vec![Evidence {
                            description: "Nameserver diversity check".to_string(),
                            source: "dns-ns-lookup".to_string(),
                            data: Some(format!("nameserver_count={}", ns_count)),
                            timestamp: Utc::now().to_rfc3339(),
                        }],
                    )
                    .await?;
                }
            }

            let wildcard_label = format!(
                "aegis-probe-{}-{}",
                sha256_short(&domain),
                &uuid::Uuid::new_v4().to_string()[..8]
            );
            let wildcard_host = format!("{}.{}", wildcard_label, domain);
            self.policy.wait_for_rate_limit().await;
            if let Ok(response) = self.resolver.lookup_ip(&wildcard_host).await {
                if response.iter().next().is_some() {
                    self.save_finding(
                        &mut counters,
                        "dns-wildcard-detected",
                        &domain,
                        "dns-intelligence",
                        "Potential wildcard DNS behavior detected",
                        &format!(
                            "Random host {} resolved successfully, indicating wildcard DNS behavior.",
                            wildcard_host
                        ),
                        "Wildcard DNS can increase false positives and hide dangling-host risks.",
                        "medium",
                        "wildcard-dns-probe",
                        vec![Evidence {
                            description: "Wildcard probe host resolved".to_string(),
                            source: "dns-a-lookup".to_string(),
                            data: Some(wildcard_host),
                            timestamp: Utc::now().to_rfc3339(),
                        }],
                    )
                    .await?;
                }
            }

            let mut prefix_checks = vec!["www", "api", "app", "portal"];
            if aggressive {
                prefix_checks.extend(["dev", "test", "staging", "beta", "admin", "status"]);
            }

            let mut discovered_subdomains = Vec::new();
            for prefix in prefix_checks {
                let candidate = format!("{}.{}", prefix, domain);
                self.policy.wait_for_rate_limit().await;
                if let Ok(cname_response) =
                    self.resolver.lookup(&candidate, RecordType::CNAME).await
                {
                    for record in cname_response.iter() {
                        if let RData::CNAME(name) = record {
                            let target = name.to_string().trim_end_matches('.').to_string();
                            if self.looks_like_takeover_target(&target) {
                                self.policy.wait_for_rate_limit().await;
                                let resolvable = self.resolver.lookup_ip(&target).await.is_ok();
                                if !resolvable {
                                    self.save_finding(
                                        &mut counters,
                                        "dns-takeover-candidate",
                                        &candidate,
                                        "dns-intelligence",
                                        "Potential dangling CNAME takeover candidate",
                                        &format!(
                                            "{} points to {} which currently does not resolve.",
                                            candidate, target
                                        ),
                                        "Dangling third-party CNAMEs can allow hostile service claim and content takeover.",
                                        "high",
                                        "cname-dangling-check",
                                        vec![Evidence {
                                            description: "Dangling CNAME target".to_string(),
                                            source: "dns-cname-lookup".to_string(),
                                            data: Some(format!("{} -> {}", candidate, target)),
                                            timestamp: Utc::now().to_rfc3339(),
                                        }],
                                    )
                                    .await?;
                                }
                            }
                        }
                    }
                }

                if aggressive {
                    self.policy.wait_for_rate_limit().await;
                    if let Ok(ip_response) = self.resolver.lookup_ip(&candidate).await {
                        if ip_response.iter().next().is_some()
                            && self.scope.is_in_scope(&candidate).in_scope
                        {
                            discovered_subdomains.push(candidate.clone());
                            self.save_asset(
                                &candidate,
                                "subdomain",
                                vec!["dns-intel".to_string(), "aggressive".to_string()],
                            )
                            .await?;
                            counters.assets_discovered += 1;
                        }
                    }
                }
            }

            if aggressive && !discovered_subdomains.is_empty() {
                discovered_subdomains.sort();
                discovered_subdomains.dedup();
                let sample = discovered_subdomains
                    .iter()
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                self.save_finding(
                    &mut counters,
                    "dns-subdomain-expansion",
                    &domain,
                    "dns-intelligence",
                    "Expanded DNS subdomain set discovered",
                    &format!(
                        "Aggressive DNS checks discovered {} subdomains for {}.",
                        discovered_subdomains.len(),
                        domain
                    ),
                    "Expanded host inventory can expose additional attack surface requiring validation.",
                    "info",
                    "dns-prefix-enum",
                    vec![Evidence {
                        description: "Discovered subdomain sample".to_string(),
                        source: "dns-prefix-enum".to_string(),
                        data: Some(sample),
                        timestamp: Utc::now().to_rfc3339(),
                    }],
                )
                .await?;
            }
        }

        Ok(ModuleSummary {
            module: ToolkitSuite::DnsIntelligence.label().to_string(),
            assets_discovered: counters.assets_discovered,
            findings_created: counters.findings_created,
            evidence_collected: counters.evidence_collected,
        })
    }

    async fn run_repo_suite(&self, aggressive: bool) -> Result<ModuleSummary> {
        let mut counters = SuiteCounters::default();

        for org in self.scope_org_candidates() {
            self.policy.wait_for_rate_limit().await;
            let url = format!(
                "https://api.github.com/orgs/{}/repos?type=public&per_page=100",
                org
            );
            if let Ok(response) = self.client.get(url).send().await {
                if response.status().is_success() {
                    if let Ok(repos) = response.json::<Vec<GitHubRepoExt>>().await {
                        if !repos.is_empty() {
                            counters.assets_discovered += repos.len();
                            let summary = repos
                                .iter()
                                .take(6)
                                .map(|repo| repo.name.as_str())
                                .collect::<Vec<_>>()
                                .join(", ");
                            self.save_finding(
                                &mut counters,
                                "repo-org-summary",
                                &org,
                                "repo-intelligence",
                                "Public repository inventory discovered",
                                &format!(
                                    "Discovered {} public repositories for organization candidate '{}'.",
                                    repos.len(),
                                    org
                                ),
                                "Public repository inventory can expose code footprint, services, and integration references.",
                                "info",
                                "github-org-repo-enum",
                                vec![Evidence {
                                    description: "Repository sample".to_string(),
                                    source: "github-api".to_string(),
                                    data: Some(summary),
                                    timestamp: Utc::now().to_rfc3339(),
                                }],
                            )
                            .await?;
                        }

                        for repo in repos {
                            let mut reasons = Vec::new();
                            if let Some(keyword) = detect_sensitive_keyword(
                                &repo.name,
                                repo.description.as_deref().unwrap_or_default(),
                            ) {
                                reasons.push(format!("metadata keyword '{}'", keyword));
                            }
                            if aggressive && repo.looks_stale() {
                                reasons.push("stale maintenance profile".to_string());
                            }
                            if reasons.is_empty() {
                                continue;
                            }

                            self.save_finding(
                                &mut counters,
                                "repo-risk-indicator",
                                &repo.html_url,
                                "repo-intelligence",
                                "Repository risk indicator observed",
                                &format!(
                                    "Repository {} flagged by: {}.",
                                    repo.full_name.as_deref().unwrap_or(&repo.name),
                                    reasons.join(", ")
                                ),
                                "Repository metadata indicators may suggest exposed internal material or weak maintenance hygiene.",
                                if reasons.iter().any(|r| r.contains("keyword")) {
                                    "medium"
                                } else {
                                    "low"
                                },
                                "repo-metadata-analysis",
                                vec![Evidence {
                                    description: "Repository metadata snapshot".to_string(),
                                    source: "github-api".to_string(),
                                    data: Some(format!(
                                        "url={}, stars={}, archived={}, updated_at={}",
                                        repo.html_url,
                                        repo.stargazers_count.unwrap_or_default(),
                                        repo.archived.unwrap_or_default(),
                                        repo.updated_at.clone().unwrap_or_default()
                                    )),
                                    timestamp: Utc::now().to_rfc3339(),
                                }],
                            )
                            .await?;
                        }
                    }
                }
            }
        }

        for base_url in self.scope_urls() {
            for path in [
                "/.git/HEAD",
                "/.git/config",
                "/.svn/entries",
                "/.hg/requires",
                "/.bzr/README",
            ] {
                self.policy.wait_for_rate_limit().await;
                let probe = format!("{}{}", base_url.trim_end_matches('/'), path);
                if let Ok(response) = self.client.get(&probe).send().await {
                    if !response.status().is_success() {
                        continue;
                    }
                    let body = response.text().await.unwrap_or_default();
                    if !is_likely_repo_artifact(path, &body) {
                        continue;
                    }

                    self.save_finding(
                        &mut counters,
                        "repo-artifact-exposure",
                        &probe,
                        "repo-intelligence",
                        "Repository artifact exposure detected",
                        &format!(
                            "Endpoint {} appears to expose repository metadata/artifacts.",
                            probe
                        ),
                        "Exposed repository artifacts can reveal source history, secrets, and deployment internals.",
                        if path.starts_with("/.git") { "high" } else { "medium" },
                        "repo-artifact-probe",
                        vec![Evidence {
                            description: "Repository artifact response sample".to_string(),
                            source: "http-get".to_string(),
                            data: Some(Self::truncate_chars(&body, 180)),
                            timestamp: Utc::now().to_rfc3339(),
                        }],
                    )
                    .await?;
                }
            }
        }

        Ok(ModuleSummary {
            module: ToolkitSuite::RepoIntelligence.label().to_string(),
            assets_discovered: counters.assets_discovered,
            findings_created: counters.findings_created,
            evidence_collected: counters.evidence_collected,
        })
    }

    async fn run_tls_infra_suite(&self, aggressive: bool) -> Result<ModuleSummary> {
        let mut counters = SuiteCounters::default();

        for domain in self.scope_domains() {
            self.policy.wait_for_rate_limit().await;
            let crt_url = format!("https://crt.sh/?q=%.{}&output=json", domain);
            if let Ok(response) = self.client.get(crt_url).send().await {
                if !response.status().is_success() {
                    continue;
                }
                let entries = response
                    .json::<Vec<CtLogIntelEntry>>()
                    .await
                    .unwrap_or_default();
                if entries.is_empty() {
                    continue;
                }
                counters.assets_discovered += entries.len();

                let mut expiring = Vec::new();
                let mut wildcard_names = HashSet::new();
                let mut issuer_set = HashSet::new();
                for entry in &entries {
                    if let Some(issuer) = entry.issuer_name.as_deref() {
                        issuer_set.insert(issuer.to_string());
                    }
                    for raw in entry.name_value.split('\n') {
                        let name = raw.trim();
                        if name.starts_with("*.") {
                            wildcard_names.insert(name.to_string());
                        }
                    }

                    if let Some(not_after) = parse_cert_timestamp(entry.not_after.as_deref()) {
                        let days = (not_after - Utc::now()).num_days();
                        if days <= 45 {
                            expiring.push((entry.common_name.clone(), days));
                        }
                    }
                }

                if !expiring.is_empty() {
                    let sample = expiring
                        .iter()
                        .take(4)
                        .map(|(cn, days)| format!("{}:{}d", cn, days))
                        .collect::<Vec<_>>()
                        .join(", ");
                    self.save_finding(
                        &mut counters,
                        "tls-cert-expiry",
                        &domain,
                        "tls-infra-intelligence",
                        "Certificate expiry window approaching",
                        &format!(
                            "{} certificates for {} are near expiry (<=45 days).",
                            expiring.len(),
                            domain
                        ),
                        "Near-expiry certificates can lead to outages and emergency renewal windows.",
                        "medium",
                        "crt-expiry-analysis",
                        vec![Evidence {
                            description: "Expiring certificate sample".to_string(),
                            source: "crt.sh".to_string(),
                            data: Some(sample),
                            timestamp: Utc::now().to_rfc3339(),
                        }],
                    )
                    .await?;
                }

                if !wildcard_names.is_empty() {
                    self.save_finding(
                        &mut counters,
                        "tls-wildcard-cert",
                        &domain,
                        "tls-infra-intelligence",
                        "Wildcard certificates observed",
                        &format!(
                            "Observed {} wildcard certificate names tied to {}.",
                            wildcard_names.len(),
                            domain
                        ),
                        "Wildcard certificates widen blast radius if private keys are compromised.",
                        "low",
                        "crt-wildcard-analysis",
                        vec![Evidence {
                            description: "Wildcard certificate name sample".to_string(),
                            source: "crt.sh".to_string(),
                            data: Some(
                                wildcard_names
                                    .iter()
                                    .take(6)
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            ),
                            timestamp: Utc::now().to_rfc3339(),
                        }],
                    )
                    .await?;
                }

                if aggressive && issuer_set.len() > 3 {
                    self.save_finding(
                        &mut counters,
                        "tls-issuer-sprawl",
                        &domain,
                        "tls-infra-intelligence",
                        "Certificate issuer sprawl detected",
                        &format!(
                            "Observed {} distinct certificate issuers for {}.",
                            issuer_set.len(),
                            domain
                        ),
                        "High issuer sprawl can indicate inconsistent certificate governance.",
                        "low",
                        "crt-issuer-correlation",
                        vec![Evidence {
                            description: "Distinct issuers".to_string(),
                            source: "crt.sh".to_string(),
                            data: Some(
                                issuer_set
                                    .into_iter()
                                    .take(8)
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            ),
                            timestamp: Utc::now().to_rfc3339(),
                        }],
                    )
                    .await?;
                }
            }
        }

        let server_version_re = regex::Regex::new(r"[a-zA-Z]+[/ ]\d").ok();
        for url in self.scope_urls() {
            if !url.starts_with("https://") {
                continue;
            }
            self.policy.wait_for_rate_limit().await;
            if let Ok(response) = self.client.head(&url).send().await {
                if !response.status().is_success() {
                    continue;
                }
                if let Some(server) = response.headers().get("server") {
                    if let Ok(server_str) = server.to_str() {
                        let leaks_version = server_version_re
                            .as_ref()
                            .is_some_and(|re| re.is_match(server_str));
                        if leaks_version {
                            self.save_finding(
                                &mut counters,
                                "infra-server-fingerprint",
                                &url,
                                "tls-infra-intelligence",
                                "Server version fingerprint exposed",
                                &format!(
                                    "Server header '{}' reveals detailed server fingerprinting data.",
                                    server_str
                                ),
                                "Detailed server fingerprinting can improve attacker exploit matching.",
                                "low",
                                "https-head-fingerprint",
                                vec![Evidence {
                                    description: "Server header".to_string(),
                                    source: "https-head".to_string(),
                                    data: Some(server_str.to_string()),
                                    timestamp: Utc::now().to_rfc3339(),
                                }],
                            )
                            .await?;
                        }
                    }
                }
            }
        }

        Ok(ModuleSummary {
            module: ToolkitSuite::TlsInfrastructure.label().to_string(),
            assets_discovered: counters.assets_discovered,
            findings_created: counters.findings_created,
            evidence_collected: counters.evidence_collected,
        })
    }

    async fn run_leak_mention_suite(&self, aggressive: bool) -> Result<ModuleSummary> {
        let mut counters = SuiteCounters::default();
        let leak_keywords = [
            "leak",
            "breach",
            "dump",
            "credential",
            "password",
            "token",
            "exposed",
            "paste",
        ];

        for domain in self.scope_domains() {
            self.policy.wait_for_rate_limit().await;
            let hn_url = format!(
                "https://hn.algolia.com/api/v1/search?query={}&tags=story",
                urlencoding::encode(&domain)
            );
            if let Ok(response) = self.client.get(hn_url).send().await {
                if response.status().is_success() {
                    if let Ok(payload) = response.json::<HnSearchResponse>().await {
                        let mut mentions = Vec::new();
                        let mut suspicious = 0usize;
                        for hit in payload.hits.into_iter().take(25) {
                            let title = hit.title.unwrap_or_else(|| "untitled".to_string());
                            let url = hit.url.unwrap_or_else(|| "no-url".to_string());
                            let normalized =
                                format!("{} {}", title.to_lowercase(), url.to_lowercase());
                            if leak_keywords
                                .iter()
                                .any(|keyword| normalized.contains(keyword))
                            {
                                suspicious += 1;
                            }
                            mentions.push(format!("{} ({})", title, url));
                        }
                        if !mentions.is_empty() {
                            counters.assets_discovered += mentions.len();
                            self.save_finding(
                                &mut counters,
                                "leak-domain-mentions",
                                &domain,
                                "leak-mention-intelligence",
                                "Public domain mentions observed",
                                &format!(
                                    "Found {} public mentions for {} ({} potentially sensitive).",
                                    mentions.len(),
                                    domain,
                                    suspicious
                                ),
                                "Public mention analysis can surface early signals of leaked content or incident chatter.",
                                if suspicious > 0 { "medium" } else { "info" },
                                "hn-mention-search",
                                vec![Evidence {
                                    description: "Mention sample".to_string(),
                                    source: "hn-algolia".to_string(),
                                    data: Some(mentions.into_iter().take(6).collect::<Vec<_>>().join(" | ")),
                                    timestamp: Utc::now().to_rfc3339(),
                                }],
                            )
                            .await?;
                        }
                    }
                }
            }

            if aggressive {
                self.policy.wait_for_rate_limit().await;
                let rss_url = format!(
                    "https://news.google.com/rss/search?q={}",
                    urlencoding::encode(&domain)
                );
                if let Ok(response) = self.client.get(rss_url).send().await {
                    if response.status().is_success() {
                        let body = response.text().await.unwrap_or_default();
                        let items = extract_rss_items(&body, 10);
                        if !items.is_empty() {
                            let suspicious = items
                                .iter()
                                .filter(|item| {
                                    let normalized = item.to_lowercase();
                                    leak_keywords
                                        .iter()
                                        .any(|keyword| normalized.contains(keyword))
                                })
                                .count();
                            counters.assets_discovered += items.len();
                            self.save_finding(
                                &mut counters,
                                "leak-news-signal",
                                &domain,
                                "leak-mention-intelligence",
                                "News and media mention signal discovered",
                                &format!(
                                    "Found {} news mentions for {} ({} potentially sensitive).",
                                    items.len(),
                                    domain,
                                    suspicious
                                ),
                                "Media mention correlation helps triage external incident chatter and brand exposure.",
                                if suspicious > 0 { "medium" } else { "info" },
                                "news-rss-correlation",
                                vec![Evidence {
                                    description: "News mention sample".to_string(),
                                    source: "google-news-rss".to_string(),
                                    data: Some(items.into_iter().take(5).collect::<Vec<_>>().join(" | ")),
                                    timestamp: Utc::now().to_rfc3339(),
                                }],
                            )
                            .await?;
                        }
                    }
                }
            }
        }

        Ok(ModuleSummary {
            module: ToolkitSuite::LeakMentions.label().to_string(),
            assets_discovered: counters.assets_discovered,
            findings_created: counters.findings_created,
            evidence_collected: counters.evidence_collected,
        })
    }

    async fn save_asset(&self, value: &str, asset_type: &str, tags: Vec<String>) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let asset = Asset {
            id: format!(
                "asset-{}-{}-{}",
                sha256_short(&self.scope.id),
                asset_type,
                sha256_short(value)
            ),
            scope_id: self.scope.id.clone(),
            asset_type: asset_type.to_string(),
            value: value.to_string(),
            tags,
            metadata: None,
            first_seen: now.clone(),
            last_seen: now,
        };
        self.storage.save_asset(&asset).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn save_finding(
        &self,
        counters: &mut SuiteCounters,
        prefix: &str,
        asset: &str,
        finding_type: &str,
        title: &str,
        description: &str,
        impact: &str,
        severity: &str,
        method: &str,
        evidence: Vec<Evidence>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let evidence_count = evidence.len();
        let finding = Finding {
            id: self.run_scoped_id(prefix, &format!("{}-{}", asset, title)),
            scope_id: self.scope.id.clone(),
            run_id: self.run_id.clone(),
            asset: asset.to_string(),
            finding_type: finding_type.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            impact: impact.to_string(),
            severity: severity.to_string(),
            confidence: confidence_for_severity(severity),
            status: Some("open".to_string()),
            reproduction: Some(format!("Review source method '{}'", method)),
            source: "osint-toolkit".to_string(),
            method: method.to_string(),
            scope_verified: true,
            evidence,
            created_at: now.clone(),
            updated_at: now,
        };
        self.storage.save_finding(&finding).await?;
        counters.findings_created += 1;
        counters.evidence_collected += evidence_count;
        Ok(())
    }

    fn scope_domains(&self) -> Vec<String> {
        let mut domains = HashSet::new();
        for item in &self.scope.items {
            if !item.in_scope {
                continue;
            }
            match item.item_type {
                ScopeItemType::Domain => {
                    domains.insert(item.value.to_lowercase());
                }
                ScopeItemType::Wildcard => {
                    domains.insert(item.value.trim_start_matches("*.").to_lowercase());
                }
                ScopeItemType::Url => {
                    if let Ok(parsed) = url::Url::parse(&item.value) {
                        if let Some(host) = parsed.host_str() {
                            domains.insert(host.to_lowercase());
                        }
                    }
                }
                _ => {}
            }
        }
        let mut values = domains.into_iter().collect::<Vec<_>>();
        values.sort();
        values
    }

    fn scope_urls(&self) -> Vec<String> {
        let mut urls = HashSet::new();
        for item in &self.scope.items {
            if !item.in_scope {
                continue;
            }
            match item.item_type {
                ScopeItemType::Url => {
                    urls.insert(item.value.clone());
                }
                ScopeItemType::Domain | ScopeItemType::Wildcard => {
                    let domain = item.value.trim_start_matches("*.");
                    urls.insert(format!("https://{}", domain));
                    urls.insert(format!("http://{}", domain));
                }
                _ => {}
            }
        }
        let mut values = urls.into_iter().collect::<Vec<_>>();
        values.sort();
        values
    }

    fn scope_org_candidates(&self) -> Vec<String> {
        let mut raw = HashSet::new();
        if let Some(program) = self.scope.program.as_ref() {
            raw.insert(program.to_string());
        }
        raw.insert(self.scope.name.clone());
        for item in &self.scope.items {
            if item.in_scope && item.item_type == ScopeItemType::Org {
                raw.insert(item.value.clone());
            }
            if item.in_scope
                && matches!(
                    item.item_type,
                    ScopeItemType::Domain | ScopeItemType::Wildcard
                )
            {
                let first = item
                    .value
                    .trim_start_matches("*.")
                    .split('.')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                if !first.is_empty() {
                    raw.insert(first);
                }
            }
        }

        let mut normalized = HashSet::new();
        for value in raw {
            let cleaned = value
                .chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() {
                        ch.to_ascii_lowercase()
                    } else {
                        '-'
                    }
                })
                .collect::<String>()
                .trim_matches('-')
                .replace("--", "-");
            if !cleaned.is_empty() {
                normalized.insert(cleaned);
            }
        }

        let mut values = normalized.into_iter().collect::<Vec<_>>();
        values.sort();
        values.truncate(8);
        values
    }

    fn looks_like_takeover_target(&self, target: &str) -> bool {
        const PROVIDER_MARKERS: [&str; 10] = [
            "github.io",
            "herokudns.com",
            "azurewebsites.net",
            "cloudfront.net",
            "fastly.net",
            "pantheonsite.io",
            "surge.sh",
            "readthedocs.io",
            "zendesk.com",
            "myshopify.com",
        ];
        PROVIDER_MARKERS
            .iter()
            .any(|marker| target.contains(marker))
    }

    fn run_scoped_id(&self, prefix: &str, key: &str) -> String {
        if let Some(run_id) = self.run_id.as_deref() {
            format!("{}-{}-{}", prefix, sha256_short(run_id), sha256_short(key))
        } else {
            format!("{}-{}", prefix, sha256_short(key))
        }
    }

    fn truncate_chars(value: &str, max_chars: usize) -> String {
        let mut chars = value.chars();
        let truncated: String = chars.by_ref().take(max_chars).collect();
        if chars.next().is_some() {
            format!("{}...", truncated)
        } else {
            truncated
        }
    }
}

fn parse_cert_timestamp(value: Option<&str>) -> Option<DateTime<Utc>> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }

    if let Ok(ts) = DateTime::parse_from_rfc3339(value) {
        return Some(ts.with_timezone(&Utc));
    }
    if let Ok(ts) = DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%#z") {
        return Some(ts.with_timezone(&Utc));
    }
    if let Ok(ts) = DateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%#z") {
        return Some(ts.with_timezone(&Utc));
    }
    None
}

fn extract_rss_items(body: &str, limit: usize) -> Vec<String> {
    let mut items = Vec::new();
    let item_re = regex::Regex::new(
        r"(?s)<item>.*?<title>(?P<title>.*?)</title>.*?<link>(?P<link>.*?)</link>.*?</item>",
    );
    if let Ok(re) = item_re {
        for captures in re.captures_iter(body).take(limit) {
            let title = html_unescape(
                captures
                    .name("title")
                    .map(|m| m.as_str())
                    .unwrap_or_default(),
            );
            let link = captures
                .name("link")
                .map(|m| m.as_str())
                .unwrap_or_default()
                .to_string();
            if !title.is_empty() && !link.is_empty() {
                items.push(format!("{} ({})", title, link));
            }
        }
    }
    items
}

fn html_unescape(input: &str) -> String {
    let replacements: HashMap<&str, &str> = HashMap::from([
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#39;", "'"),
    ]);
    let mut output = input.to_string();
    for (from, to) in replacements {
        output = output.replace(from, to);
    }
    output
}

fn is_likely_repo_artifact(path: &str, body: &str) -> bool {
    let lower = body.to_lowercase();
    if path == "/.git/HEAD" {
        return lower.contains("ref: refs/");
    }
    if path == "/.git/config" {
        return lower.contains("[core]") || lower.contains("repositoryformatversion");
    }
    if path == "/.svn/entries" {
        return lower.contains("svn");
    }
    if path == "/.hg/requires" {
        return lower.contains("revlog") || lower.contains("store");
    }
    if path == "/.bzr/README" {
        return lower.contains("bazaar");
    }
    false
}

fn detect_sensitive_keyword(name: &str, description: &str) -> Option<&'static str> {
    let normalized = format!("{} {}", name.to_lowercase(), description.to_lowercase());
    [
        "secret",
        "backup",
        "credential",
        "password",
        "token",
        "internal",
        "private",
        "dump",
        "prod",
    ]
    .into_iter()
    .find(|indicator| normalized.contains(indicator))
}

fn confidence_for_severity(severity: &str) -> i32 {
    match severity {
        "critical" => 95,
        "high" => 90,
        "medium" => 82,
        "low" => 75,
        _ => 68,
    }
}

fn sha256_short(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)[..12].to_string()
}

#[derive(Debug, serde::Deserialize)]
struct GitHubRepoExt {
    name: String,
    html_url: String,
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    archived: Option<bool>,
    #[serde(default)]
    updated_at: Option<String>,
    #[serde(default)]
    stargazers_count: Option<u64>,
}

impl GitHubRepoExt {
    fn looks_stale(&self) -> bool {
        let Some(updated_at) = self.updated_at.as_deref() else {
            return false;
        };
        let Ok(parsed) = DateTime::parse_from_rfc3339(updated_at) else {
            return false;
        };
        (Utc::now() - parsed.with_timezone(&Utc)).num_days() > 540
    }
}

#[derive(Debug, serde::Deserialize, Default)]
struct CtLogIntelEntry {
    #[serde(default)]
    common_name: String,
    #[serde(default)]
    name_value: String,
    #[serde(default)]
    issuer_name: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct HnSearchResponse {
    #[serde(default)]
    hits: Vec<HnHit>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct HnHit {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{sha256_short, ToolkitSuite};

    #[test]
    fn toolkit_suite_labels_are_stable() {
        assert_eq!(
            ToolkitSuite::DnsIntelligence.label(),
            "dns-intelligence-suite"
        );
        assert_eq!(
            ToolkitSuite::RepoIntelligence.label(),
            "repo-intelligence-suite"
        );
        assert_eq!(
            ToolkitSuite::TlsInfrastructure.label(),
            "tls-infra-intelligence-suite"
        );
        assert_eq!(
            ToolkitSuite::LeakMentions.label(),
            "leak-mention-intelligence-suite"
        );
    }

    #[test]
    fn sha256_helper_output_len() {
        assert_eq!(sha256_short("toolkit-test").len(), 12);
    }
}
