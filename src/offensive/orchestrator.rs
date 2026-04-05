//! Offensive OSINT orchestrator
//!
//! Coordinates all offensive reconnaissance modules.

use crate::cli::ScanProfile;
use crate::policy::PolicyEngine;
use crate::scope::Scope;
use crate::storage::{Finding, FindingContext, ModuleSummary, ScanSummary, Storage};
use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use std::collections::HashSet;
use std::time::Instant;

use super::cloud::CloudExposureEngine;
use super::correlation::HistoricalCorrelator;
use super::discovery::DiscoveryEngine;
use super::toolkit::{OsintToolkitEngine, ToolkitSuite};
use super::web::WebReconEngine;

/// Offensive OSINT orchestrator
#[allow(dead_code)]
pub struct OffensiveOrchestrator {
    scope: Scope,
    profile: ScanProfile,
    concurrency: usize,
    policy: PolicyEngine,
    storage: Storage,
}

#[derive(Debug, Default)]
struct OffensiveRunMetrics {
    ct_subdomains: usize,
    dns_records: usize,
    aggressive_subdomains: usize,
    dns_posture_findings: usize,
    asn_mappings: usize,
    service_fingerprints: usize,
    header_issues: usize,
    misconfigs: usize,
    method_findings: usize,
    js_endpoints: usize,
    cloud_exposures: usize,
    related_domains: usize,
    timeline_events: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReconModule {
    CtLogDiscovery,
    DnsEnumeration,
    ServiceFingerprinting,
    WebReconnaissance,
    CloudExposure,
    HistoricalCorrelation,
    DnsIntelligenceSuite,
    RepoIntelligenceSuite,
    TlsInfraIntelligenceSuite,
    LeakMentionIntelligenceSuite,
}

impl ReconModule {
    pub fn label(self) -> &'static str {
        match self {
            ReconModule::CtLogDiscovery => "ct-log-discovery",
            ReconModule::DnsEnumeration => "dns-enumeration",
            ReconModule::ServiceFingerprinting => "service-fingerprinting",
            ReconModule::WebReconnaissance => "web-reconnaissance",
            ReconModule::CloudExposure => "cloud-exposure-check",
            ReconModule::HistoricalCorrelation => "historical-correlation",
            ReconModule::DnsIntelligenceSuite => "dns-intelligence-suite",
            ReconModule::RepoIntelligenceSuite => "repo-intelligence-suite",
            ReconModule::TlsInfraIntelligenceSuite => "tls-infra-intelligence-suite",
            ReconModule::LeakMentionIntelligenceSuite => "leak-mention-intelligence-suite",
        }
    }
}

pub fn modules_for_profile(profile: ScanProfile) -> Vec<ReconModule> {
    match profile {
        ScanProfile::Safe => vec![
            ReconModule::CtLogDiscovery,
            ReconModule::DnsEnumeration,
            ReconModule::WebReconnaissance,
        ],
        ScanProfile::Standard => vec![
            ReconModule::CtLogDiscovery,
            ReconModule::DnsEnumeration,
            ReconModule::ServiceFingerprinting,
            ReconModule::WebReconnaissance,
            ReconModule::CloudExposure,
        ],
        ScanProfile::Thorough | ScanProfile::Aggressive => vec![
            ReconModule::CtLogDiscovery,
            ReconModule::DnsEnumeration,
            ReconModule::ServiceFingerprinting,
            ReconModule::WebReconnaissance,
            ReconModule::CloudExposure,
            ReconModule::HistoricalCorrelation,
            ReconModule::DnsIntelligenceSuite,
            ReconModule::RepoIntelligenceSuite,
            ReconModule::TlsInfraIntelligenceSuite,
            ReconModule::LeakMentionIntelligenceSuite,
        ],
    }
}

impl OffensiveOrchestrator {
    /// Create a new orchestrator
    pub fn new(
        scope: Scope,
        profile: ScanProfile,
        concurrency: usize,
        policy: PolicyEngine,
        storage: Storage,
    ) -> Self {
        Self {
            scope,
            profile,
            concurrency,
            policy,
            storage,
        }
    }

    /// Execute the offensive scan
    pub async fn execute<F>(&self, run_id: &str, mut progress_callback: F) -> Result<ScanSummary>
    where
        F: FnMut(&str, u8),
    {
        let start_time = Instant::now();
        let mut total_assets = 0usize;
        let mut metrics = OffensiveRunMetrics::default();
        let mut module_summaries = Vec::new();
        let enabled = modules_for_profile(self.profile)
            .into_iter()
            .collect::<HashSet<_>>();

        // Update scan status
        self.storage.update_scan_status(run_id, "running").await?;

        progress_callback("Initializing", 5);

        // Phase 1: CT Log Discovery
        if enabled.contains(&ReconModule::CtLogDiscovery) {
            progress_callback("CT Log Discovery", 10);
            let ct_assets = self.run_ct_discovery(&mut metrics).await?;
            total_assets += ct_assets;
            module_summaries.push(ModuleSummary {
                module: ReconModule::CtLogDiscovery.label().to_string(),
                assets_discovered: ct_assets,
                findings_created: 0,
                evidence_collected: 0,
            });
        }

        // Phase 2: DNS Enumeration
        if enabled.contains(&ReconModule::DnsEnumeration) {
            progress_callback("DNS Enumeration", 25);
            let posture_before = metrics.dns_posture_findings;
            let asn_before = metrics.asn_mappings;
            let dns_assets = self
                .run_dns_discovery(run_id, &mut metrics, self.is_aggressive())
                .await?;
            total_assets += dns_assets;
            module_summaries.push(ModuleSummary {
                module: ReconModule::DnsEnumeration.label().to_string(),
                assets_discovered: dns_assets,
                findings_created: metrics.dns_posture_findings.saturating_sub(posture_before),
                evidence_collected: metrics.asn_mappings.saturating_sub(asn_before),
            });
        }

        // Phase 3: Service Fingerprinting (if profile allows)
        if enabled.contains(&ReconModule::ServiceFingerprinting) {
            progress_callback("Service Fingerprinting", 40);
            let service_info = self.run_service_fingerprinting(&mut metrics).await?;
            total_assets += service_info;
            module_summaries.push(ModuleSummary {
                module: ReconModule::ServiceFingerprinting.label().to_string(),
                assets_discovered: service_info,
                findings_created: 0,
                evidence_collected: metrics.service_fingerprints,
            });
        }

        // Phase 4: Web Reconnaissance
        if enabled.contains(&ReconModule::WebReconnaissance) {
            progress_callback("Web Reconnaissance", 55);
            let headers_before = metrics.header_issues;
            let misconfigs_before = metrics.misconfigs;
            let methods_before = metrics.method_findings;
            let endpoints_before = metrics.js_endpoints;
            self.run_web_recon(
                run_id,
                &mut metrics,
                !matches!(self.profile, ScanProfile::Safe),
                true,
            )
            .await?;
            module_summaries.push(ModuleSummary {
                module: ReconModule::WebReconnaissance.label().to_string(),
                assets_discovered: metrics.js_endpoints.saturating_sub(endpoints_before),
                findings_created: metrics
                    .header_issues
                    .saturating_sub(headers_before)
                    .saturating_add(metrics.misconfigs.saturating_sub(misconfigs_before))
                    .saturating_add(metrics.method_findings.saturating_sub(methods_before)),
                evidence_collected: metrics.js_endpoints.saturating_sub(endpoints_before),
            });
        }

        // Phase 5: Cloud Exposure Check (if profile allows)
        if enabled.contains(&ReconModule::CloudExposure) {
            progress_callback("Cloud Exposure Check", 70);
            let cloud_before = metrics.cloud_exposures;
            self.run_cloud_check(run_id, &mut metrics).await?;
            module_summaries.push(ModuleSummary {
                module: ReconModule::CloudExposure.label().to_string(),
                assets_discovered: 0,
                findings_created: metrics.cloud_exposures.saturating_sub(cloud_before),
                evidence_collected: metrics.cloud_exposures.saturating_sub(cloud_before),
            });
        }

        // Phase 6: Historical Correlation (if thorough/aggressive)
        if enabled.contains(&ReconModule::HistoricalCorrelation) {
            progress_callback("Historical Correlation", 88);
            let related_before = metrics.related_domains;
            let timeline_before = metrics.timeline_events;
            self.run_historical_correlation(&mut metrics).await?;
            module_summaries.push(ModuleSummary {
                module: ReconModule::HistoricalCorrelation.label().to_string(),
                assets_discovered: metrics.related_domains.saturating_sub(related_before),
                findings_created: 0,
                evidence_collected: metrics.timeline_events.saturating_sub(timeline_before),
            });
        }

        let toolkit = OsintToolkitEngine::new(
            self.scope.clone(),
            self.policy.clone(),
            self.storage.clone(),
            Some(run_id),
        )?;
        if enabled.contains(&ReconModule::DnsIntelligenceSuite) {
            progress_callback("DNS Intelligence Suite", 78);
            let summary = toolkit
                .run_suite(ToolkitSuite::DnsIntelligence, self.is_aggressive())
                .await?;
            total_assets += summary.assets_discovered;
            module_summaries.push(summary);
        }
        if enabled.contains(&ReconModule::RepoIntelligenceSuite) {
            progress_callback("Repository Intelligence Suite", 82);
            let summary = toolkit
                .run_suite(ToolkitSuite::RepoIntelligence, self.is_aggressive())
                .await?;
            total_assets += summary.assets_discovered;
            module_summaries.push(summary);
        }
        if enabled.contains(&ReconModule::TlsInfraIntelligenceSuite) {
            progress_callback("TLS Infrastructure Intelligence Suite", 86);
            let summary = toolkit
                .run_suite(ToolkitSuite::TlsInfrastructure, self.is_aggressive())
                .await?;
            total_assets += summary.assets_discovered;
            module_summaries.push(summary);
        }
        if enabled.contains(&ReconModule::LeakMentionIntelligenceSuite) {
            progress_callback("Leak Mention Intelligence Suite", 90);
            let summary = toolkit
                .run_suite(ToolkitSuite::LeakMentions, self.is_aggressive())
                .await?;
            total_assets += summary.assets_discovered;
            module_summaries.push(summary);
        }

        self.save_run_summary_finding(run_id, &metrics, &module_summaries)
            .await?;

        let findings_for_run = self
            .storage
            .list_findings(
                None,
                FindingContext {
                    scope: Some(&self.scope.id),
                    run: Some(run_id),
                },
                None,
                None,
                50_000,
                "severity",
            )
            .await?;
        let total_findings = findings_for_run.len();
        self.storage
            .update_scan_findings_count(run_id, total_findings as i32)
            .await?;
        let evidence_count = module_summaries
            .iter()
            .map(|summary| summary.evidence_collected)
            .sum::<usize>();

        // Finalize
        progress_callback("Finalizing", 96);

        let duration = start_time.elapsed();
        let summary = ScanSummary {
            assets_count: total_assets,
            findings_count: total_findings,
            evidence_count,
            duration_secs: duration.as_secs_f64(),
            module_summaries,
        };
        self.storage
            .update_scan_metadata(
                run_id,
                &json!({
                    "assets_count": summary.assets_count,
                    "findings_count": summary.findings_count,
                    "evidence_count": summary.evidence_count,
                    "duration_secs": summary.duration_secs,
                    "module_summaries": summary.module_summaries,
                    "profile": format!("{:?}", self.profile),
                }),
            )
            .await?;
        self.storage.update_scan_status(run_id, "completed").await?;

        progress_callback("Complete", 100);

        Ok(summary)
    }

    async fn run_ct_discovery(&self, metrics: &mut OffensiveRunMetrics) -> Result<usize> {
        let discovery = DiscoveryEngine::new(
            self.scope.clone(),
            self.policy.clone(),
            self.storage.clone(),
        )
        .await?;

        let mut total = 0;

        // Get base domains from scope
        for item in &self.scope.items {
            if item.in_scope {
                if let Some(base_domain) = self.extract_base_domain(&item.value) {
                    match discovery.discover_ct_logs(&base_domain).await {
                        Ok(subdomains) => {
                            total += subdomains.len();
                            metrics.ct_subdomains += subdomains.len();
                        }
                        Err(e) => {
                            tracing::warn!("CT discovery failed for {}: {}", base_domain, e);
                        }
                    }
                }
            }
        }

        Ok(total)
    }

    async fn run_dns_discovery(
        &self,
        run_id: &str,
        metrics: &mut OffensiveRunMetrics,
        aggressive: bool,
    ) -> Result<usize> {
        let discovery = DiscoveryEngine::new(
            self.scope.clone(),
            self.policy.clone(),
            self.storage.clone(),
        )
        .await?;

        let mut total = 0;

        for item in &self.scope.items {
            if item.in_scope {
                if let Some(domain) = self.extract_base_domain(&item.value) {
                    match discovery.discover_dns(&domain).await {
                        Ok(result) => {
                            let count = result.a_records.len()
                                + result.mx_records.len()
                                + result.ns_records.len()
                                + result.txt_records.len();
                            total += result.a_records.len();
                            metrics.dns_records += count;
                            if aggressive {
                                match discovery
                                    .discover_common_subdomains(
                                        &domain,
                                        &Self::aggressive_wordlist(),
                                    )
                                    .await
                                {
                                    Ok(extra_subdomains) => {
                                        total += extra_subdomains.len();
                                        metrics.aggressive_subdomains += extra_subdomains.len();
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Aggressive subdomain checks failed for {}: {}",
                                            domain,
                                            e
                                        );
                                    }
                                }
                            }
                            self.analyze_dns_posture(run_id, &domain, &result, &discovery, metrics)
                                .await?;
                        }
                        Err(e) => {
                            tracing::warn!("DNS discovery failed for {}: {}", domain, e);
                        }
                    }
                }
            }
        }

        Ok(total)
    }

    async fn run_service_fingerprinting(&self, metrics: &mut OffensiveRunMetrics) -> Result<usize> {
        let discovery = DiscoveryEngine::new(
            self.scope.clone(),
            self.policy.clone(),
            self.storage.clone(),
        )
        .await?;

        let mut fingerprinted = 0usize;
        let targets = self
            .storage
            .list_assets(Some(&self.scope.id), Some("ip"), None, 1000)
            .await?;
        let ports = Self::ports_for_profile(self.profile);

        for target in targets {
            for &port in &ports {
                if discovery
                    .fingerprint_service(&target.value, port)
                    .await?
                    .is_some()
                {
                    fingerprinted += 1;
                }
            }
        }
        metrics.service_fingerprints += fingerprinted;
        Ok(fingerprinted)
    }

    async fn analyze_dns_posture(
        &self,
        run_id: &str,
        domain: &str,
        result: &super::discovery::DnsDiscoveryResult,
        discovery: &DiscoveryEngine,
        metrics: &mut OffensiveRunMetrics,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let spf_records: Vec<&String> = result
            .txt_records
            .iter()
            .filter(|value| value.to_ascii_lowercase().contains("v=spf1"))
            .collect();

        if spf_records.is_empty() {
            let finding = Finding {
                id: self.run_scoped_id("dns-missing-spf", domain, run_id),
                scope_id: self.scope.id.clone(),
                run_id: Some(run_id.to_string()),
                asset: domain.to_string(),
                finding_type: "dns-posture".to_string(),
                title: "Missing SPF policy".to_string(),
                description: format!("No SPF TXT record detected for {}", domain),
                impact: "Missing SPF can increase email spoofing risk for the domain.".to_string(),
                severity: "low".to_string(),
                confidence: 80,
                status: Some("open".to_string()),
                reproduction: Some(format!("dig +short TXT {}", domain)),
                source: "dns-discovery".to_string(),
                method: "spf-check".to_string(),
                scope_verified: true,
                evidence: vec![],
                created_at: now.clone(),
                updated_at: now.clone(),
            };
            self.storage.save_finding(&finding).await?;
            metrics.dns_posture_findings += 1;
        } else if spf_records
            .iter()
            .any(|value| value.to_ascii_lowercase().contains("+all"))
        {
            let finding = Finding {
                id: self.run_scoped_id("dns-spf-permissive", domain, run_id),
                scope_id: self.scope.id.clone(),
                run_id: Some(run_id.to_string()),
                asset: domain.to_string(),
                finding_type: "dns-posture".to_string(),
                title: "Permissive SPF policy detected".to_string(),
                description: format!(
                    "SPF policy for {} contains '+all', which is overly permissive.",
                    domain
                ),
                impact: "Overly permissive SPF can allow unauthorized email sources.".to_string(),
                severity: "medium".to_string(),
                confidence: 85,
                status: Some("open".to_string()),
                reproduction: Some(format!("dig +short TXT {}", domain)),
                source: "dns-discovery".to_string(),
                method: "spf-check".to_string(),
                scope_verified: true,
                evidence: vec![],
                created_at: now.clone(),
                updated_at: now.clone(),
            };
            self.storage.save_finding(&finding).await?;
            metrics.dns_posture_findings += 1;
        }

        let dmarc_host = format!("_dmarc.{}", domain);
        let dmarc_records = discovery.lookup_txt_records(&dmarc_host).await?;
        if dmarc_records.is_empty() {
            let finding = Finding {
                id: self.run_scoped_id("dns-missing-dmarc", domain, run_id),
                scope_id: self.scope.id.clone(),
                run_id: Some(run_id.to_string()),
                asset: domain.to_string(),
                finding_type: "dns-posture".to_string(),
                title: "Missing DMARC policy".to_string(),
                description: format!("No DMARC TXT record detected at {}", dmarc_host),
                impact: "Missing DMARC weakens anti-spoofing protections.".to_string(),
                severity: "low".to_string(),
                confidence: 82,
                status: Some("open".to_string()),
                reproduction: Some(format!("dig +short TXT {}", dmarc_host)),
                source: "dns-discovery".to_string(),
                method: "dmarc-check".to_string(),
                scope_verified: true,
                evidence: vec![],
                created_at: now.clone(),
                updated_at: now.clone(),
            };
            self.storage.save_finding(&finding).await?;
            metrics.dns_posture_findings += 1;
        } else if dmarc_records
            .iter()
            .any(|value| value.to_ascii_lowercase().contains("p=none"))
        {
            let finding = Finding {
                id: self.run_scoped_id("dns-dmarc-none", domain, run_id),
                scope_id: self.scope.id.clone(),
                run_id: Some(run_id.to_string()),
                asset: domain.to_string(),
                finding_type: "dns-posture".to_string(),
                title: "DMARC policy is monitor-only".to_string(),
                description: format!("DMARC policy for {} is set to p=none.", domain),
                impact: "Monitor-only DMARC may not block spoofed mail attempts.".to_string(),
                severity: "low".to_string(),
                confidence: 78,
                status: Some("open".to_string()),
                reproduction: Some(format!("dig +short TXT {}", dmarc_host)),
                source: "dns-discovery".to_string(),
                method: "dmarc-check".to_string(),
                scope_verified: true,
                evidence: vec![],
                created_at: now.clone(),
                updated_at: now.clone(),
            };
            self.storage.save_finding(&finding).await?;
            metrics.dns_posture_findings += 1;
        }

        if matches!(
            self.profile,
            ScanProfile::Thorough | ScanProfile::Aggressive
        ) {
            let mut asn_set = HashSet::new();
            for ip in result.a_records.iter().take(16) {
                if let Some(asn_info) = discovery.discover_asn(ip).await? {
                    asn_set.insert(format!(
                        "{} ({}, {})",
                        asn_info.asn, asn_info.prefix, asn_info.country
                    ));
                }
            }

            if !asn_set.is_empty() {
                let mut values = asn_set.into_iter().collect::<Vec<_>>();
                values.sort();
                let finding = Finding {
                    id: self.run_scoped_id("dns-asn-map", domain, run_id),
                    scope_id: self.scope.id.clone(),
                    run_id: Some(run_id.to_string()),
                    asset: domain.to_string(),
                    finding_type: "dns-infrastructure".to_string(),
                    title: "ASN infrastructure mapping discovered".to_string(),
                    description: format!(
                        "Resolved {} ASN mappings for {}: {}",
                        values.len(),
                        domain,
                        values.join("; ")
                    ),
                    impact: "Infrastructure mapping helps identify shared hosting and third-party dependencies.".to_string(),
                    severity: "info".to_string(),
                    confidence: 75,
                    status: Some("open".to_string()),
                    reproduction: Some(format!("dig +short A {}", domain)),
                    source: "dns-discovery".to_string(),
                    method: "asn-lookup".to_string(),
                    scope_verified: true,
                    evidence: vec![],
                    created_at: now.clone(),
                    updated_at: now.clone(),
                };
                self.storage.save_finding(&finding).await?;
                metrics.asn_mappings += values.len();
            }
        }

        Ok(())
    }

    async fn run_web_recon(
        &self,
        run_id: &str,
        metrics: &mut OffensiveRunMetrics,
        include_http_methods: bool,
        include_js: bool,
    ) -> Result<()> {
        let web_engine = WebReconEngine::new(
            self.scope.clone(),
            self.policy.clone(),
            self.storage.clone(),
            Some(run_id),
        )?;

        for item in &self.scope.items {
            if item.in_scope {
                let Some(url) = self.scope_item_to_url(&item.value) else {
                    continue;
                };

                // Analyze headers
                match web_engine.analyze_headers(&url).await {
                    Ok(result) => {
                        metrics.header_issues += result.generated_findings;
                    }
                    Err(e) => {
                        tracing::warn!("Header analysis failed for {}: {}", url, e);
                    }
                }

                // Check for misconfigurations
                match web_engine
                    .check_misconfigurations(&url, self.is_aggressive())
                    .await
                {
                    Ok(misconfigs) => {
                        metrics.misconfigs += misconfigs.len();
                    }
                    Err(e) => {
                        tracing::warn!("Misconfiguration check failed for {}: {}", url, e);
                    }
                }

                if include_http_methods {
                    match web_engine
                        .check_http_methods(&url, self.is_aggressive())
                        .await
                    {
                        Ok(count) => metrics.method_findings += count,
                        Err(e) => tracing::warn!("HTTP method checks failed for {}: {}", url, e),
                    }
                }

                if include_js {
                    match web_engine.discover_js_endpoints(&url).await {
                        Ok(endpoints) => metrics.js_endpoints += endpoints.len(),
                        Err(e) => {
                            tracing::warn!("JS endpoint discovery failed for {}: {}", url, e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn run_cloud_check(&self, run_id: &str, metrics: &mut OffensiveRunMetrics) -> Result<()> {
        let cloud_engine = CloudExposureEngine::new(
            self.scope.clone(),
            self.policy.clone(),
            self.storage.clone(),
            Some(run_id),
        )?;

        for org_name in self.cloud_org_candidates() {
            // Check cloud providers
            match cloud_engine.check_s3_exposure(&org_name).await {
                Ok(s3_findings) => {
                    let count = s3_findings.iter().filter(|f| f.severity != "info").count();
                    metrics.cloud_exposures += count;
                }
                Err(e) => {
                    tracing::warn!("S3 exposure checks failed for {}: {}", org_name, e);
                }
            }

            match cloud_engine.check_azure_exposure(&org_name).await {
                Ok(azure_findings) => {
                    let count = azure_findings
                        .iter()
                        .filter(|f| f.severity != "info")
                        .count();
                    metrics.cloud_exposures += count;
                }
                Err(e) => {
                    tracing::warn!("Azure exposure checks failed for {}: {}", org_name, e);
                }
            }

            match cloud_engine.check_gcp_exposure(&org_name).await {
                Ok(gcp_findings) => {
                    let count = gcp_findings.iter().filter(|f| f.severity != "info").count();
                    metrics.cloud_exposures += count;
                }
                Err(e) => {
                    tracing::warn!("GCP exposure checks failed for {}: {}", org_name, e);
                }
            }

            match cloud_engine.check_github_exposure(&org_name).await {
                Ok(repo_findings) => {
                    let count = repo_findings
                        .iter()
                        .filter(|f| f.severity != "info")
                        .count();
                    metrics.cloud_exposures += count;
                }
                Err(e) => {
                    tracing::warn!("GitHub exposure checks failed for {}: {}", org_name, e);
                }
            }
        }

        Ok(())
    }

    async fn run_historical_correlation(&self, metrics: &mut OffensiveRunMetrics) -> Result<()> {
        let correlator = HistoricalCorrelator::new();

        for item in &self.scope.items {
            if !item.in_scope {
                continue;
            }
            let Some(domain) = self.extract_base_domain(&item.value) else {
                continue;
            };

            let related = correlator.find_related_by_infrastructure(&domain).await?;
            let timeline = correlator.get_domain_timeline(&domain).await?;
            metrics.related_domains += related.len();
            metrics.timeline_events += timeline.events.len();
        }

        Ok(())
    }

    fn extract_base_domain(&self, value: &str) -> Option<String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }

        // URL values
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            if let Ok(url) = url::Url::parse(trimmed) {
                return url.host_str().map(|h| h.to_string());
            }
            return None;
        }

        // Skip obvious non-domain values (CIDR, ASN, paths)
        if trimmed.contains('/') || trimmed.to_ascii_uppercase().starts_with("AS") {
            return None;
        }

        Some(trimmed.strip_prefix("*.").unwrap_or(trimmed).to_string())
    }

    fn scope_item_to_url(&self, value: &str) -> Option<String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            return Some(trimmed.to_string());
        }
        self.extract_base_domain(trimmed)
            .map(|host| format!("https://{}", host))
    }

    fn is_aggressive(&self) -> bool {
        matches!(self.profile, ScanProfile::Aggressive)
    }

    fn aggressive_wordlist() -> Vec<&'static str> {
        vec![
            "admin", "api", "app", "auth", "beta", "cdn", "dev", "git", "internal", "portal",
            "stage", "staging", "status", "test", "vpn", "www",
        ]
    }

    fn ports_for_profile(profile: ScanProfile) -> Vec<u16> {
        match profile {
            ScanProfile::Safe => vec![80, 443],
            ScanProfile::Standard => vec![80, 443, 8080, 8443],
            ScanProfile::Thorough => vec![80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000],
            ScanProfile::Aggressive => vec![
                80, 443, 8080, 8443, 3000, 5000, 7001, 8000, 8081, 8888, 9000, 9443,
            ],
        }
    }

    fn cloud_org_candidates(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut candidates = Vec::new();

        let mut push_candidate = |raw: &str| {
            let normalized = Self::normalize_org_candidate(raw);
            if !normalized.is_empty() && seen.insert(normalized.clone()) {
                candidates.push(normalized);
            }
        };

        if let Some(program) = self.scope.program.as_ref() {
            push_candidate(program);
        }
        push_candidate(&self.scope.name);

        for item in &self.scope.items {
            if !item.in_scope {
                continue;
            }
            if let Some(domain) = self.extract_base_domain(&item.value) {
                let first_label = domain.split('.').next().unwrap_or_default();
                push_candidate(first_label);
            }
        }

        candidates.into_iter().take(6).collect()
    }

    fn normalize_org_candidate(value: &str) -> String {
        value
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
            .replace("--", "-")
    }

    fn run_scoped_id(&self, prefix: &str, key: &str, run_id: &str) -> String {
        format!("{}-{}-{}", prefix, sha256_short(run_id), sha256_short(key))
    }

    async fn save_run_summary_finding(
        &self,
        run_id: &str,
        metrics: &OffensiveRunMetrics,
        module_summaries: &[ModuleSummary],
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let module_overview = module_summaries
            .iter()
            .map(|summary| {
                format!(
                    "{}(assets={}, findings={}, evidence={})",
                    summary.module,
                    summary.assets_discovered,
                    summary.findings_created,
                    summary.evidence_collected
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let description = format!(
            "CT subdomains: {}; DNS records: {}; Aggressive subdomains: {}; DNS posture findings: {}; ASN mappings: {}; Service fingerprints: {}; Header findings: {}; Misconfigs: {}; HTTP method findings: {}; JS endpoints: {}; Cloud exposures: {}; Related domains: {}; Timeline events: {}; Modules: [{}]",
            metrics.ct_subdomains,
            metrics.dns_records,
            metrics.aggressive_subdomains,
            metrics.dns_posture_findings,
            metrics.asn_mappings,
            metrics.service_fingerprints,
            metrics.header_issues,
            metrics.misconfigs,
            metrics.method_findings,
            metrics.js_endpoints,
            metrics.cloud_exposures,
            metrics.related_domains,
            metrics.timeline_events,
            module_overview
        );

        let finding = Finding {
            id: format!("run-summary-{}", run_id),
            scope_id: self.scope.id.clone(),
            run_id: Some(run_id.to_string()),
            asset: self.scope.name.clone(),
            finding_type: "scan-summary".to_string(),
            title: "Offensive scan telemetry summary".to_string(),
            description,
            impact: "Operational telemetry for analyst review.".to_string(),
            severity: "info".to_string(),
            confidence: 100,
            status: Some("open".to_string()),
            reproduction: None,
            source: "orchestrator".to_string(),
            method: "pipeline-summary".to_string(),
            scope_verified: true,
            evidence: vec![],
            created_at: now.clone(),
            updated_at: now,
        };

        self.storage.save_finding(&finding).await
    }
}

fn sha256_short(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)[..12].to_string()
}
