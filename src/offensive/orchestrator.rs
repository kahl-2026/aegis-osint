//! Offensive OSINT orchestrator
//!
//! Coordinates all offensive reconnaissance modules.

use crate::cli::ScanProfile;
use crate::policy::PolicyEngine;
use crate::scope::Scope;
use crate::storage::{Finding, ScanSummary, Storage};
use anyhow::Result;
use chrono::Utc;
use std::time::Instant;

use super::cloud::CloudExposureEngine;
use super::correlation::HistoricalCorrelator;
use super::discovery::DiscoveryEngine;
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
    service_fingerprints: usize,
    header_issues: usize,
    misconfigs: usize,
    cloud_exposures: usize,
    related_domains: usize,
    timeline_events: usize,
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
        let mut total_findings = 0usize;
        let mut metrics = OffensiveRunMetrics::default();

        // Update scan status
        self.storage.update_scan_status(run_id, "running").await?;

        progress_callback("Initializing", 5);

        // Phase 1: CT Log Discovery
        progress_callback("CT Log Discovery", 10);
        let ct_assets = self.run_ct_discovery(&mut metrics).await?;
        total_assets += ct_assets;

        // Phase 2: DNS Enumeration
        progress_callback("DNS Enumeration", 25);
        let dns_assets = self.run_dns_discovery(&mut metrics).await?;
        total_assets += dns_assets;

        // Phase 3: Service Fingerprinting (if profile allows)
        if matches!(self.profile, ScanProfile::Standard | ScanProfile::Thorough) {
            progress_callback("Service Fingerprinting", 40);
            let service_info = self.run_service_fingerprinting(&mut metrics).await?;
            total_assets += service_info;
        }

        // Phase 4: Web Reconnaissance
        progress_callback("Web Reconnaissance", 55);
        let web_findings = self.run_web_recon(&mut metrics).await?;
        total_findings += web_findings;

        // Phase 5: Cloud Exposure Check (if profile allows)
        if matches!(self.profile, ScanProfile::Standard | ScanProfile::Thorough) {
            progress_callback("Cloud Exposure Check", 70);
            let cloud_findings = self.run_cloud_check(&mut metrics).await?;
            total_findings += cloud_findings;
        }

        // Phase 6: Historical Correlation (if thorough)
        if matches!(self.profile, ScanProfile::Thorough) {
            progress_callback("Historical Correlation", 85);
            self.run_historical_correlation(&mut metrics).await?;
        }

        self.save_run_summary_finding(run_id, &metrics).await?;

        // Finalize
        progress_callback("Finalizing", 95);
        self.storage.update_scan_status(run_id, "completed").await?;

        let duration = start_time.elapsed();

        progress_callback("Complete", 100);

        Ok(ScanSummary {
            assets_count: total_assets,
            findings_count: total_findings,
            duration_secs: duration.as_secs_f64(),
        })
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

    async fn run_dns_discovery(&self, metrics: &mut OffensiveRunMetrics) -> Result<usize> {
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
        let ports = [80u16, 443, 8080, 8443];

        for target in targets {
            for port in ports {
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

    async fn run_web_recon(&self, metrics: &mut OffensiveRunMetrics) -> Result<usize> {
        let web_engine = WebReconEngine::new(
            self.scope.clone(),
            self.policy.clone(),
            self.storage.clone(),
        )?;

        let mut findings = 0;

        for item in &self.scope.items {
            if item.in_scope {
                let Some(url) = self.scope_item_to_url(&item.value) else {
                    continue;
                };

                // Analyze headers
                match web_engine.analyze_headers(&url).await {
                    Ok(result) => {
                        let header_issues = result.missing_security_headers.len()
                            + result.misconfigured_headers.len();
                        findings += header_issues;
                        metrics.header_issues += header_issues;
                    }
                    Err(e) => {
                        tracing::warn!("Header analysis failed for {}: {}", url, e);
                    }
                }

                // Check for misconfigurations
                match web_engine.check_misconfigurations(&url).await {
                    Ok(misconfigs) => {
                        findings += misconfigs.len();
                        metrics.misconfigs += misconfigs.len();
                    }
                    Err(e) => {
                        tracing::warn!("Misconfiguration check failed for {}: {}", url, e);
                    }
                }

                if let Err(e) = web_engine.discover_js_endpoints(&url).await {
                    tracing::warn!("JS endpoint discovery failed for {}: {}", url, e);
                }
            }
        }

        Ok(findings)
    }

    async fn run_cloud_check(&self, metrics: &mut OffensiveRunMetrics) -> Result<usize> {
        let cloud_engine = CloudExposureEngine::new(
            self.scope.clone(),
            self.policy.clone(),
            self.storage.clone(),
        )?;

        let mut findings = 0;

        // Extract org name from scope
        if let Some(org) = self.scope.program.as_ref() {
            let org_name = org.to_lowercase().replace(' ', "-");

            // Check cloud providers
            match cloud_engine.check_s3_exposure(&org_name).await {
                Ok(s3_findings) => {
                    let count = s3_findings.iter().filter(|f| f.severity != "info").count();
                    findings += count;
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
                    findings += count;
                    metrics.cloud_exposures += count;
                }
                Err(e) => {
                    tracing::warn!("Azure exposure checks failed for {}: {}", org_name, e);
                }
            }

            match cloud_engine.check_gcp_exposure(&org_name).await {
                Ok(gcp_findings) => {
                    let count = gcp_findings.iter().filter(|f| f.severity != "info").count();
                    findings += count;
                    metrics.cloud_exposures += count;
                }
                Err(e) => {
                    tracing::warn!("GCP exposure checks failed for {}: {}", org_name, e);
                }
            }

            if let Err(e) = cloud_engine.check_github_exposure(&org_name).await {
                tracing::warn!("GitHub exposure checks failed for {}: {}", org_name, e);
            }
        }

        Ok(findings)
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

    async fn save_run_summary_finding(
        &self,
        run_id: &str,
        metrics: &OffensiveRunMetrics,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let description = format!(
            "CT subdomains: {}; DNS records: {}; Service fingerprints: {}; Header issues: {}; Misconfigs: {}; Cloud exposures: {}; Related domains: {}; Timeline events: {}",
            metrics.ct_subdomains,
            metrics.dns_records,
            metrics.service_fingerprints,
            metrics.header_issues,
            metrics.misconfigs,
            metrics.cloud_exposures,
            metrics.related_domains,
            metrics.timeline_events
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
