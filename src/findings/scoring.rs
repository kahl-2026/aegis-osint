//! Risk scoring and severity calculation

use crate::storage::Finding;

/// Risk scorer for findings
pub struct RiskScorer {
    /// Weights for different factors
    severity_weight: f64,
    confidence_weight: f64,
    exposure_weight: f64,
}

impl RiskScorer {
    /// Create a new risk scorer with default weights
    pub fn new() -> Self {
        Self {
            severity_weight: 0.5,
            confidence_weight: 0.3,
            exposure_weight: 0.2,
        }
    }

    /// Calculate risk score for a finding
    pub fn calculate_score(&self, finding: &Finding) -> RiskScore {
        let severity_score = self.severity_to_score(&finding.severity);
        let confidence_score = finding.confidence as f64 / 100.0;
        let exposure_score = self.calculate_exposure_score(finding);

        let weighted_score = severity_score * self.severity_weight
            + confidence_score * self.confidence_weight
            + exposure_score * self.exposure_weight;

        let normalized_score = (weighted_score * 10.0).round() as u8;

        RiskScore {
            score: normalized_score,
            severity_component: severity_score,
            confidence_component: confidence_score,
            exposure_component: exposure_score,
            rating: self.score_to_rating(normalized_score),
        }
    }

    fn severity_to_score(&self, severity: &str) -> f64 {
        match severity.to_lowercase().as_str() {
            "critical" => 1.0,
            "high" => 0.8,
            "medium" => 0.5,
            "low" => 0.3,
            "info" => 0.1,
            _ => 0.0,
        }
    }

    fn calculate_exposure_score(&self, finding: &Finding) -> f64 {
        // Based on asset type and exposure characteristics
        let mut score: f64 = 0.5; // Base score

        // Web-facing services are more exposed
        if finding.asset.contains("http") || finding.asset.contains("443") {
            score += 0.2;
        }

        // API endpoints
        if finding.asset.contains("/api/") {
            score += 0.15;
        }

        // Authentication/sensitive paths
        if finding.asset.contains("login")
            || finding.asset.contains("admin")
            || finding.asset.contains("auth")
        {
            score += 0.15;
        }

        score.min(1.0)
    }

    fn score_to_rating(&self, score: u8) -> String {
        match score {
            9..=10 => "Critical".to_string(),
            7..=8 => "High".to_string(),
            4..=6 => "Medium".to_string(),
            2..=3 => "Low".to_string(),
            _ => "Informational".to_string(),
        }
    }
}

impl Default for RiskScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Risk score result
#[derive(Debug)]
pub struct RiskScore {
    pub score: u8,
    pub severity_component: f64,
    pub confidence_component: f64,
    pub exposure_component: f64,
    pub rating: String,
}

/// Severity calculator with CVSS-like factors
pub struct SeverityCalculator;

impl SeverityCalculator {
    /// Calculate severity from finding characteristics
    pub fn calculate(
        impact: Impact,
        exploitability: Exploitability,
        scope: Scope,
    ) -> SeverityResult {
        let impact_score = match impact {
            Impact::High => 3.0,
            Impact::Medium => 2.0,
            Impact::Low => 1.0,
            Impact::None => 0.0,
        };

        let exploit_score = match exploitability {
            Exploitability::Easy => 3.0,
            Exploitability::Medium => 2.0,
            Exploitability::Hard => 1.0,
        };

        let scope_multiplier = match scope {
            Scope::Changed => 1.2,
            Scope::Unchanged => 1.0,
        };

        let raw_score: f64 = (impact_score + exploit_score) * scope_multiplier / 7.2 * 10.0;
        let score = raw_score.round() as u8;

        let severity = match score {
            9..=10 => "critical".to_string(),
            7..=8 => "high".to_string(),
            4..=6 => "medium".to_string(),
            1..=3 => "low".to_string(),
            _ => "info".to_string(),
        };

        SeverityResult { score, severity }
    }
}

/// Impact level
#[derive(Debug, Clone, Copy)]
pub enum Impact {
    High,
    Medium,
    Low,
    None,
}

/// Exploitability level
#[derive(Debug, Clone, Copy)]
pub enum Exploitability {
    Easy,
    Medium,
    Hard,
}

/// Scope of impact
#[derive(Debug, Clone, Copy)]
pub enum Scope {
    Changed,
    Unchanged,
}

/// Severity calculation result
#[derive(Debug)]
pub struct SeverityResult {
    pub score: u8,
    pub severity: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_calculator() {
        let result = SeverityCalculator::calculate(
            Impact::High,
            Exploitability::Easy,
            Scope::Changed,
        );
        assert_eq!(result.severity, "critical");

        let result = SeverityCalculator::calculate(
            Impact::Low,
            Exploitability::Hard,
            Scope::Unchanged,
        );
        assert_eq!(result.severity, "low");
    }

    #[test]
    fn test_risk_scorer() {
        let scorer = RiskScorer::new();

        let finding = Finding {
            id: "test".to_string(),
            scope_id: "scope".to_string(),
            run_id: None,
            asset: "https://example.com/api/login".to_string(),
            finding_type: "test".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            impact: "Test".to_string(),
            severity: "high".to_string(),
            confidence: 90,
            status: None,
            reproduction: None,
            source: "test".to_string(),
            method: "test".to_string(),
            scope_verified: true,
            evidence: vec![],
            created_at: String::new(),
            updated_at: String::new(),
        };

        let score = scorer.calculate_score(&finding);
        assert!(score.score >= 7);
    }
}
