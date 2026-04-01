//! Web reconnaissance module
//!
//! Implements web-based reconnaissance:
//! - Endpoint and parameter discovery
//! - Header and security posture analysis
//! - Technology fingerprinting
//! - Misconfiguration detection

use crate::policy::PolicyEngine;
use crate::scope::Scope;
use crate::storage::{Evidence, Finding, Storage};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;

/// Web reconnaissance engine
pub struct WebReconEngine {
    scope: Scope,
    policy: PolicyEngine,
    storage: Storage,
    client: reqwest::Client,
}

impl WebReconEngine {
    /// Create a new web recon engine
    pub fn new(scope: Scope, policy: PolicyEngine, storage: Storage) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(false)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;

        Ok(Self {
            scope,
            policy,
            storage,
            client,
        })
    }

    /// Analyze security headers for a URL
    pub async fn analyze_headers(&self, url: &str) -> Result<HeaderAnalysisResult> {
        // Extract host from URL and validate scope
        let parsed = url::Url::parse(url)?;
        let host = parsed.host_str().unwrap_or("");

        let check = self.policy.check_target(host, &self.scope).await?;
        if !check.allowed {
            return Ok(HeaderAnalysisResult::default());
        }

        self.policy.wait_for_rate_limit().await;

        let mut result = HeaderAnalysisResult {
            url: url.to_string(),
            headers: HashMap::new(),
            missing_security_headers: vec![],
            misconfigured_headers: vec![],
            technologies: vec![],
        };

        let mut last_error: Option<(String, reqwest::Error)> = None;
        for candidate_url in self.candidate_urls(url) {
            match self.client.head(&candidate_url).send().await {
                Ok(response) => {
                    result.url = candidate_url.clone();
                // Collect all headers
                for (name, value) in response.headers().iter() {
                    if let Ok(v) = value.to_str() {
                        result.headers.insert(name.to_string(), v.to_string());
                    }
                }

                // Check for missing security headers
                let security_headers = [
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                    "x-xss-protection",
                    "referrer-policy",
                    "permissions-policy",
                ];

                for header in security_headers {
                    if !result.headers.contains_key(header) {
                        result.missing_security_headers.push(header.to_string());
                    }
                }

                // Check for misconfigured headers
                if let Some(csp) = result.headers.get("content-security-policy") {
                    if csp.contains("unsafe-inline") || csp.contains("unsafe-eval") {
                        result.misconfigured_headers.push(HeaderIssue {
                            header: "content-security-policy".to_string(),
                            issue: "Contains unsafe directives".to_string(),
                            severity: "medium".to_string(),
                        });
                    }
                }

                if let Some(cors) = result.headers.get("access-control-allow-origin") {
                    if cors == "*" {
                        result.misconfigured_headers.push(HeaderIssue {
                            header: "access-control-allow-origin".to_string(),
                            issue: "Wildcard CORS policy".to_string(),
                            severity: "medium".to_string(),
                        });
                    }
                }

                // Technology fingerprinting from headers
                if let Some(server) = result.headers.get("server") {
                    result.technologies.push(Technology {
                        name: "Server".to_string(),
                        version: Some(server.clone()),
                        confidence: 90,
                    });
                }

                if let Some(powered) = result.headers.get("x-powered-by") {
                    result.technologies.push(Technology {
                        name: "Framework".to_string(),
                        version: Some(powered.clone()),
                        confidence: 90,
                    });
                }

                // Generate findings for issues
                    self.generate_header_findings(&candidate_url, &result).await?;
                    return Ok(result);
                }
                Err(e) => {
                    last_error = Some((candidate_url, e));
                }
            }
        }

        if let Some((failed_url, e)) = last_error {
            tracing::warn!("Header analysis failed for {}: {}", failed_url, e);
        }

        Ok(result)
    }

    /// Discover endpoints from JavaScript files
    pub async fn discover_js_endpoints(&self, url: &str) -> Result<Vec<DiscoveredEndpoint>> {
        // Extract host and validate scope
        let parsed = url::Url::parse(url)?;
        let host = parsed.host_str().unwrap_or("");

        let check = self.policy.check_target(host, &self.scope).await?;
        if !check.allowed {
            return Ok(vec![]);
        }

        self.policy.wait_for_rate_limit().await;

        let mut endpoints = Vec::new();
        let mut had_successful_response = false;

        let mut last_error: Option<(String, reqwest::Error)> = None;
        for candidate_url in self.candidate_urls(url) {
            match self.client.get(&candidate_url).send().await {
                Ok(response) => {
                    had_successful_response = true;
                    last_error = None;
                if let Ok(body) = response.text().await {
                    // Find script tags and extract URLs
                        let script_urls = self.extract_script_urls(&body, &candidate_url);

                    for script_url in script_urls {
                        if let Ok(parsed) = url::Url::parse(&script_url) {
                            let script_host = parsed.host_str().unwrap_or("");
                            if self.scope.is_in_scope(script_host).in_scope {
                                self.policy.wait_for_rate_limit().await;

                                if let Ok(js_response) = self.client.get(&script_url).send().await {
                                    if let Ok(js_content) = js_response.text().await {
                                            let found =
                                                self.extract_endpoints_from_js(&js_content, &candidate_url);
                                        endpoints.extend(found);
                                    }
                                }
                            }
                        }
                    }

                    // Also extract endpoints from inline scripts
                        let inline_endpoints = self.extract_endpoints_from_js(&body, &candidate_url);
                    endpoints.extend(inline_endpoints);
                }
                    break;
                }
                Err(e) => {
                    last_error = Some((candidate_url, e));
                }
            }
        }

        if !had_successful_response {
            if let Some((failed_url, e)) = last_error {
                tracing::warn!("JS endpoint discovery failed for {}: {}", failed_url, e);
            }
        }

        // Deduplicate
        endpoints.sort_by(|a, b| a.path.cmp(&b.path));
        endpoints.dedup_by(|a, b| a.path == b.path);

        Ok(endpoints)
    }

    /// Check for common misconfigurations
    pub async fn check_misconfigurations(&self, url: &str) -> Result<Vec<MisconfigFinding>> {
        let parsed = url::Url::parse(url)?;
        let host = parsed.host_str().unwrap_or("");

        let check = self.policy.check_target(host, &self.scope).await?;
        if !check.allowed {
            return Ok(vec![]);
        }

        let mut findings = Vec::new();

        // Check for exposed paths
        let paths_to_check = [
            ("/.git/config", "Git repository exposed"),
            ("/.env", "Environment file exposed"),
            ("/robots.txt", "Robots.txt (info disclosure)"),
            ("/.well-known/security.txt", "Security.txt present"),
            ("/server-status", "Apache server-status exposed"),
            ("/phpinfo.php", "PHPInfo exposed"),
            ("/.DS_Store", "macOS DS_Store exposed"),
            ("/web.config", "IIS web.config exposed"),
            ("/crossdomain.xml", "Flash crossdomain.xml present"),
        ];

        let mut seen = std::collections::HashSet::new();
        let mut had_response = false;
        let mut last_error: Option<(String, reqwest::Error)> = None;

        for base_url in self.candidate_urls(url) {
            for (path, description) in paths_to_check {
                self.policy.wait_for_rate_limit().await;

                let check_url = format!("{}{}", base_url.trim_end_matches('/'), path);

                match self.client.head(&check_url).send().await {
                    Ok(response) => {
                        had_response = true;
                        if response.status().is_success() && seen.insert(check_url.clone()) {
                            let severity = self.classify_misconfig_severity(path);

                            findings.push(MisconfigFinding {
                                url: check_url,
                                description: description.to_string(),
                                severity,
                                evidence: format!("HTTP {}", response.status()),
                            });
                        }
                    }
                    Err(e) => {
                        last_error = Some((check_url, e));
                    }
                }
            }
        }

        if !had_response {
            if let Some((failed_url, e)) = last_error {
                tracing::warn!("Misconfiguration checks failed for {}: {}", failed_url, e);
            }
        }

        Ok(findings)
    }

    fn candidate_urls(&self, url: &str) -> Vec<String> {
        let mut candidates = vec![url.to_string()];
        if let Ok(mut parsed) = url::Url::parse(url) {
            if parsed.scheme() == "https" && parsed.set_scheme("http").is_ok() {
                let fallback = parsed.to_string();
                if !candidates.contains(&fallback) {
                    candidates.push(fallback);
                }
            }
        }
        candidates
    }

    fn extract_script_urls(&self, html: &str, base_url: &str) -> Vec<String> {
        let mut urls = Vec::new();

        // Best-effort regex extraction for src attributes
        let patterns = [
            r#"src="([^"]+\.js[^"]*)""#,
            r#"src='([^']+\.js[^']*)'"#,
        ];

        for pattern in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.captures_iter(html) {
                    if let Some(src) = cap.get(1) {
                        let src_str = src.as_str();
                        if src_str.starts_with("http") {
                            urls.push(src_str.to_string());
                        } else if src_str.starts_with("//") {
                            urls.push(format!("https:{}", src_str));
                        } else if src_str.starts_with('/') {
                            if let Ok(base) = url::Url::parse(base_url) {
                                urls.push(format!("{}://{}{}", base.scheme(), base.host_str().unwrap_or(""), src_str));
                            }
                        }
                    }
                }
            }
        }

        urls
    }

    fn extract_endpoints_from_js(&self, js: &str, base_url: &str) -> Vec<DiscoveredEndpoint> {
        let mut endpoints = Vec::new();

        // Extract API paths
        let patterns = [
            r#"["'](/api/[^"'\s]+)["']"#,
            r#"["'](/v\d+/[^"'\s]+)["']"#,
            r#"fetch\(["']([^"']+)["']"#,
            r#"axios\.[a-z]+\(["']([^"']+)["']"#,
            r#"url:\s*["']([^"']+)["']"#,
        ];

        for pattern in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.captures_iter(js) {
                    if let Some(path) = cap.get(1) {
                        let path_str = path.as_str();
                        endpoints.push(DiscoveredEndpoint {
                            path: path_str.to_string(),
                            method: "GET".to_string(),
                            source: base_url.to_string(),
                            parameters: vec![],
                        });
                    }
                }
            }
        }

        endpoints
    }

    fn classify_misconfig_severity(&self, path: &str) -> String {
        match path {
            "/.git/config" | "/.env" => "high".to_string(),
            "/phpinfo.php" | "/server-status" => "medium".to_string(),
            _ => "low".to_string(),
        }
    }

    async fn generate_header_findings(&self, url: &str, result: &HeaderAnalysisResult) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        // Generate findings for missing security headers
        if !result.missing_security_headers.is_empty() {
            let finding = Finding {
                id: format!("header-missing-{}", sha256_short(url)),
                scope_id: self.scope.id.clone(),
                run_id: None,
                asset: url.to_string(),
                finding_type: "security-header".to_string(),
                title: "Missing Security Headers".to_string(),
                description: format!(
                    "The following security headers are missing: {}",
                    result.missing_security_headers.join(", ")
                ),
                impact: "Missing security headers can expose users to various attacks including XSS, clickjacking, and MIME sniffing.".to_string(),
                severity: "low".to_string(),
                confidence: 95,
                status: Some("open".to_string()),
                reproduction: Some(format!("curl -I {}", url)),
                source: "web-recon".to_string(),
                method: "header-analysis".to_string(),
                scope_verified: true,
                evidence: vec![Evidence {
                    description: "Missing headers".to_string(),
                    source: "header-analysis".to_string(),
                    data: Some(result.missing_security_headers.join(", ")),
                    timestamp: now.clone(),
                }],
                created_at: now.clone(),
                updated_at: now.clone(),
            };

            self.storage.save_finding(&finding).await?;
        }

        // Generate findings for misconfigured headers
        for issue in &result.misconfigured_headers {
            let finding = Finding {
                id: format!("header-misconfig-{}-{}", sha256_short(&issue.header), sha256_short(url)),
                scope_id: self.scope.id.clone(),
                run_id: None,
                asset: url.to_string(),
                finding_type: "security-header".to_string(),
                title: format!("Misconfigured {}", issue.header),
                description: issue.issue.clone(),
                impact: "Misconfigured security headers can weaken security protections.".to_string(),
                severity: issue.severity.clone(),
                confidence: 90,
                status: Some("open".to_string()),
                reproduction: Some(format!("curl -I {}", url)),
                source: "web-recon".to_string(),
                method: "header-analysis".to_string(),
                scope_verified: true,
                evidence: vec![Evidence {
                    description: format!("{} header issue", issue.header),
                    source: "header-analysis".to_string(),
                    data: result.headers.get(&issue.header).cloned(),
                    timestamp: now.clone(),
                }],
                created_at: now.clone(),
                updated_at: now.clone(),
            };

            self.storage.save_finding(&finding).await?;
        }

        Ok(())
    }
}

fn sha256_short(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)[..12].to_string()
}

/// Header analysis result
#[derive(Debug, Default)]
pub struct HeaderAnalysisResult {
    pub url: String,
    pub headers: HashMap<String, String>,
    pub missing_security_headers: Vec<String>,
    pub misconfigured_headers: Vec<HeaderIssue>,
    pub technologies: Vec<Technology>,
}

/// Header issue
#[derive(Debug)]
pub struct HeaderIssue {
    pub header: String,
    pub issue: String,
    pub severity: String,
}

/// Detected technology
#[derive(Debug)]
pub struct Technology {
    pub name: String,
    pub version: Option<String>,
    pub confidence: u8,
}

/// Discovered endpoint
#[derive(Debug)]
pub struct DiscoveredEndpoint {
    pub path: String,
    pub method: String,
    pub source: String,
    pub parameters: Vec<String>,
}

/// Misconfiguration finding
#[derive(Debug)]
pub struct MisconfigFinding {
    pub url: String,
    pub description: String,
    pub severity: String,
    pub evidence: String,
}
