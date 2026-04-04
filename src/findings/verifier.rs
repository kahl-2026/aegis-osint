//! Finding verification

use crate::storage::{Finding, Storage};
use crate::utils::http::HttpClient;
use anyhow::Result;

/// Finding verifier
pub struct FindingVerifier {
    storage: Storage,
}

impl FindingVerifier {
    /// Create a new verifier
    pub fn new(storage: Storage) -> Self {
        Self { storage }
    }

    /// Verify a finding
    pub async fn verify(&self, finding: &Finding) -> Result<VerificationResult> {
        if self.storage.get_finding(&finding.id).await?.is_none() {
            return Ok(VerificationResult {
                verified: false,
                reason: "Finding no longer exists in storage".to_string(),
                details: None,
            });
        }

        // Verification depends on finding type
        match finding.finding_type.as_str() {
            "security-header" => self.verify_header_finding(finding).await,
            "cloud-exposure" => self.verify_cloud_finding(finding).await,
            "misconfiguration" => self.verify_misconfig_finding(finding).await,
            _ => Ok(VerificationResult {
                verified: true,
                reason: "Manual verification required".to_string(),
                details: None,
            }),
        }
    }

    async fn verify_header_finding(&self, finding: &Finding) -> Result<VerificationResult> {
        let client = HttpClient::new("AegisOSINT-Verifier", 10)?;

        match client.head(&finding.asset).await {
            Ok(response) => {
                // Check if the issue still exists
                let security_headers = [
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                ];

                let mut missing = Vec::new();
                for header in security_headers {
                    if !response.headers().contains_key(header) {
                        missing.push(header.to_string());
                    }
                }

                if missing.is_empty() {
                    Ok(VerificationResult {
                        verified: false,
                        reason: "Headers have been added - finding may be fixed".to_string(),
                        details: None,
                    })
                } else {
                    Ok(VerificationResult {
                        verified: true,
                        reason: "Headers still missing".to_string(),
                        details: Some(format!("Missing: {}", missing.join(", "))),
                    })
                }
            }
            Err(e) => Ok(VerificationResult {
                verified: false,
                reason: format!("Unable to verify: {}", e),
                details: None,
            }),
        }
    }

    async fn verify_cloud_finding(&self, finding: &Finding) -> Result<VerificationResult> {
        let client = HttpClient::new("AegisOSINT-Verifier", 10)?;

        match client.head(&finding.asset).await {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(VerificationResult {
                        verified: true,
                        reason: "Resource still publicly accessible".to_string(),
                        details: Some(format!("HTTP {}", response.status())),
                    })
                } else if response.status().as_u16() == 403 {
                    Ok(VerificationResult {
                        verified: false,
                        reason: "Access denied - may be fixed".to_string(),
                        details: None,
                    })
                } else {
                    Ok(VerificationResult {
                        verified: false,
                        reason: format!("Unexpected status: {}", response.status()),
                        details: None,
                    })
                }
            }
            Err(e) => Ok(VerificationResult {
                verified: false,
                reason: format!("Unable to verify: {}", e),
                details: None,
            }),
        }
    }

    async fn verify_misconfig_finding(&self, finding: &Finding) -> Result<VerificationResult> {
        let client = HttpClient::new("AegisOSINT-Verifier", 10)?;

        match client.head(&finding.asset).await {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(VerificationResult {
                        verified: true,
                        reason: "Resource still accessible".to_string(),
                        details: Some(format!("HTTP {}", response.status())),
                    })
                } else {
                    Ok(VerificationResult {
                        verified: false,
                        reason: "Resource no longer accessible - may be fixed".to_string(),
                        details: None,
                    })
                }
            }
            Err(_) => Ok(VerificationResult {
                verified: false,
                reason: "Resource not reachable".to_string(),
                details: None,
            }),
        }
    }
}

/// Verification result
#[derive(Debug)]
pub struct VerificationResult {
    pub verified: bool,
    pub reason: String,
    pub details: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_result() {
        let result = VerificationResult {
            verified: true,
            reason: "Test".to_string(),
            details: None,
        };
        assert!(result.verified);
    }
}
