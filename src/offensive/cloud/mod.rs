//! Cloud exposure detection module
//!
//! Implements cloud-focused reconnaissance:
//! - Public S3 bucket detection
//! - Azure blob exposure
//! - GCP bucket exposure
//! - Repository leak intelligence

use crate::policy::PolicyEngine;
use crate::scope::Scope;
use crate::storage::{Evidence, Finding, Storage};
use anyhow::Result;
use chrono::Utc;

/// Cloud exposure engine
pub struct CloudExposureEngine {
    scope: Scope,
    policy: PolicyEngine,
    storage: Storage,
    client: reqwest::Client,
    run_id: Option<String>,
}

impl CloudExposureEngine {
    /// Create a new cloud exposure engine
    pub fn new(
        scope: Scope,
        policy: PolicyEngine,
        storage: Storage,
        run_id: Option<&str>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;

        Ok(Self {
            scope,
            policy,
            storage,
            client,
            run_id: run_id.map(str::to_string),
        })
    }

    /// Check for exposed S3 buckets based on naming patterns
    pub async fn check_s3_exposure(&self, org_name: &str) -> Result<Vec<CloudExposureFinding>> {
        let mut findings = Vec::new();

        // Generate potential bucket names based on org name
        let bucket_patterns = [
            org_name.to_string(),
            format!("{}-dev", org_name),
            format!("{}-staging", org_name),
            format!("{}-prod", org_name),
            format!("{}-backup", org_name),
            format!("{}-assets", org_name),
            format!("{}-static", org_name),
            format!("{}-uploads", org_name),
            format!("{}-data", org_name),
            format!("{}-logs", org_name),
        ];

        for bucket_name in bucket_patterns {
            self.policy.wait_for_rate_limit().await;

            // Check S3 bucket
            let s3_url = format!("https://{}.s3.amazonaws.com/", bucket_name);

            match self.client.head(&s3_url).send().await {
                Ok(response) => {
                    let status = response.status();

                    if status.is_success() {
                        findings.push(CloudExposureFinding {
                            provider: "aws".to_string(),
                            resource_type: "s3-bucket".to_string(),
                            resource_name: bucket_name.clone(),
                            url: s3_url,
                            exposure_type: "public-listing".to_string(),
                            severity: "high".to_string(),
                            evidence: format!("HTTP {} - bucket allows public access", status),
                        });
                    } else if status.as_u16() == 403 {
                        // Bucket exists but access denied - still useful info
                        findings.push(CloudExposureFinding {
                            provider: "aws".to_string(),
                            resource_type: "s3-bucket".to_string(),
                            resource_name: bucket_name.clone(),
                            url: s3_url,
                            exposure_type: "bucket-exists".to_string(),
                            severity: "info".to_string(),
                            evidence: "Bucket exists (403 Forbidden)".to_string(),
                        });
                    }
                }
                Err(_) => {
                    // Bucket doesn't exist or network error
                }
            }
        }

        // Save findings
        for finding in &findings {
            if finding.severity != "info" {
                self.save_cloud_finding(finding).await?;
            }
        }

        Ok(findings)
    }

    /// Check for Azure blob exposure
    pub async fn check_azure_exposure(&self, org_name: &str) -> Result<Vec<CloudExposureFinding>> {
        let mut findings = Vec::new();

        let storage_patterns = [
            org_name.to_string(),
            format!("{}storage", org_name),
            format!("{}blob", org_name),
            format!("{}data", org_name),
        ];

        for storage_name in storage_patterns {
            self.policy.wait_for_rate_limit().await;

            // Check Azure blob storage
            let azure_url = format!(
                "https://{}.blob.core.windows.net/?restype=container&comp=list",
                storage_name
            );

            if let Ok(response) = self.client.get(&azure_url).send().await {
                let status = response.status();

                if status.is_success() {
                    findings.push(CloudExposureFinding {
                        provider: "azure".to_string(),
                        resource_type: "blob-storage".to_string(),
                        resource_name: storage_name.clone(),
                        url: azure_url,
                        exposure_type: "public-listing".to_string(),
                        severity: "high".to_string(),
                        evidence: format!("HTTP {} - storage allows public listing", status),
                    });
                }
            }
        }

        for finding in &findings {
            if finding.severity != "info" {
                self.save_cloud_finding(finding).await?;
            }
        }

        Ok(findings)
    }

    /// Check for GCP bucket exposure
    pub async fn check_gcp_exposure(&self, org_name: &str) -> Result<Vec<CloudExposureFinding>> {
        let mut findings = Vec::new();

        let bucket_patterns = [
            org_name.to_string(),
            format!("{}-backup", org_name),
            format!("{}-data", org_name),
            format!("{}-assets", org_name),
        ];

        for bucket_name in bucket_patterns {
            self.policy.wait_for_rate_limit().await;

            let gcp_url = format!("https://storage.googleapis.com/{}", bucket_name);

            if let Ok(response) = self.client.head(&gcp_url).send().await {
                let status = response.status();

                if status.is_success() || status.as_u16() == 403 {
                    let severity = if status.is_success() { "high" } else { "info" };
                    let exposure_type = if status.is_success() {
                        "public-access"
                    } else {
                        "bucket-exists"
                    };

                    findings.push(CloudExposureFinding {
                        provider: "gcp".to_string(),
                        resource_type: "gcs-bucket".to_string(),
                        resource_name: bucket_name.clone(),
                        url: gcp_url,
                        exposure_type: exposure_type.to_string(),
                        severity: severity.to_string(),
                        evidence: format!("HTTP {}", status),
                    });
                }
            }
        }

        for finding in &findings {
            if finding.severity != "info" {
                self.save_cloud_finding(finding).await?;
            }
        }

        Ok(findings)
    }

    /// Check GitHub for exposed repositories/code
    pub async fn check_github_exposure(&self, org_name: &str) -> Result<Vec<RepoExposureFinding>> {
        let mut findings = Vec::new();

        self.policy.wait_for_rate_limit().await;

        // Check for organization repos
        let github_url = format!("https://api.github.com/orgs/{}/repos?type=public", org_name);

        match self
            .client
            .get(&github_url)
            .header("User-Agent", "AegisOSINT")
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(repos) = response.json::<Vec<GitHubRepo>>().await {
                        for repo in repos {
                            let risk_reason =
                                detect_repo_risk(&repo.name, repo.description.as_deref());
                            let severity = if risk_reason.is_some() {
                                "medium".to_string()
                            } else {
                                "info".to_string()
                            };

                            let finding = RepoExposureFinding {
                                platform: "github".to_string(),
                                org: org_name.to_string(),
                                repo_name: repo.name,
                                url: repo.html_url,
                                visibility: "public".to_string(),
                                description: repo.description,
                                severity,
                                risk_reason,
                            };
                            if finding.severity != "info" {
                                self.save_repo_finding(&finding).await?;
                            }
                            findings.push(finding);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("GitHub org check failed for {}: {}", org_name, e);
            }
        }

        Ok(findings)
    }

    async fn save_cloud_finding(&self, finding: &CloudExposureFinding) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        let db_finding = Finding {
            id: format!(
                "cloud-{}-{}-{}",
                finding.provider,
                finding.resource_type,
                sha256_short(&finding.resource_name)
            ),
            scope_id: self.scope.id.clone(),
            run_id: self.run_id.clone(),
            asset: finding.url.clone(),
            finding_type: "cloud-exposure".to_string(),
            title: format!("{} {} Exposure", finding.provider.to_uppercase(), finding.resource_type),
            description: format!(
                "{} resource '{}' is {}",
                finding.provider, finding.resource_name, finding.exposure_type
            ),
            impact: "Exposed cloud resources can lead to data breach, unauthorized access, or resource abuse.".to_string(),
            severity: finding.severity.clone(),
            confidence: 85,
            status: Some("open".to_string()),
            reproduction: Some(format!("curl -I {}", finding.url)),
            source: "cloud-exposure".to_string(),
            method: "bucket-enum".to_string(),
            scope_verified: true,
            evidence: vec![Evidence {
                description: finding.evidence.clone(),
                source: "cloud-exposure".to_string(),
                data: Some(finding.url.clone()),
                timestamp: now.clone(),
            }],
            created_at: now.clone(),
            updated_at: now,
        };

        self.storage.save_finding(&db_finding).await
    }

    async fn save_repo_finding(&self, finding: &RepoExposureFinding) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let title = format!(
            "Potential sensitive public repo: {}/{}",
            finding.org, finding.repo_name
        );
        let description = finding
            .risk_reason
            .clone()
            .unwrap_or_else(|| "Repository is publicly accessible".to_string());

        let db_finding = Finding {
            id: format!("repo-exposure-{}", sha256_short(&finding.url)),
            scope_id: self.scope.id.clone(),
            run_id: self.run_id.clone(),
            asset: finding.url.clone(),
            finding_type: "repo-exposure".to_string(),
            title,
            description,
            impact: "Public repositories may expose sensitive implementation details, secrets, or internal workflows.".to_string(),
            severity: finding.severity.clone(),
            confidence: 75,
            status: Some("open".to_string()),
            reproduction: Some(format!("Visit {}", finding.url)),
            source: "cloud-exposure".to_string(),
            method: "github-org-enumeration".to_string(),
            scope_verified: true,
            evidence: vec![Evidence {
                description: "Public repository metadata".to_string(),
                source: "github-api".to_string(),
                data: Some(format!(
                    "repo={}, visibility={}, reason={}",
                    finding.repo_name,
                    finding.visibility,
                    finding.risk_reason.clone().unwrap_or_else(|| "none".to_string())
                )),
                timestamp: now.clone(),
            }],
            created_at: now.clone(),
            updated_at: now,
        };

        self.storage.save_finding(&db_finding).await
    }
}

fn sha256_short(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)[..12].to_string()
}

/// Cloud exposure finding
#[derive(Debug)]
pub struct CloudExposureFinding {
    pub provider: String,
    pub resource_type: String,
    pub resource_name: String,
    pub url: String,
    pub exposure_type: String,
    pub severity: String,
    pub evidence: String,
}

/// Repository exposure finding
#[derive(Debug)]
pub struct RepoExposureFinding {
    pub platform: String,
    pub org: String,
    pub repo_name: String,
    pub url: String,
    pub visibility: String,
    pub description: Option<String>,
    pub severity: String,
    pub risk_reason: Option<String>,
}

/// GitHub repository response
#[derive(Debug, serde::Deserialize)]
struct GitHubRepo {
    name: String,
    html_url: String,
    description: Option<String>,
}

fn detect_repo_risk(name: &str, description: Option<&str>) -> Option<String> {
    let content = format!(
        "{} {}",
        name.to_lowercase(),
        description.unwrap_or_default().to_lowercase()
    );
    let indicators = [
        "secret",
        "backup",
        "dump",
        "credential",
        "password",
        "token",
        "private-key",
        "key",
        "internal",
    ];
    for indicator in indicators {
        if content.contains(indicator) {
            return Some(format!(
                "Repository metadata contains sensitive keyword '{}'",
                indicator
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_short() {
        let hash = sha256_short("test-bucket");
        assert_eq!(hash.len(), 12);
    }
}
