//! Drift detection module
//!
//! Detects configuration drift in external attack surface

use chrono::Utc;
use std::collections::HashMap;

/// Drift detector for configuration changes
pub struct DriftDetector {
    baseline: HashMap<String, AssetState>,
}

impl DriftDetector {
    /// Create a new drift detector
    pub fn new() -> Self {
        Self {
            baseline: HashMap::new(),
        }
    }

    /// Set baseline state for an asset
    pub fn set_baseline(&mut self, asset_id: String, state: AssetState) {
        self.baseline.insert(asset_id, state);
    }

    /// Check for drift from baseline
    pub fn check_drift(&self, asset_id: &str, current_state: &AssetState) -> Option<DriftEvent> {
        if let Some(baseline) = self.baseline.get(asset_id) {
            let mut changes = Vec::new();

            // Check DNS changes
            if baseline.dns_records != current_state.dns_records {
                changes.push(DriftChange {
                    field: "dns_records".to_string(),
                    old_value: format!("{:?}", baseline.dns_records),
                    new_value: format!("{:?}", current_state.dns_records),
                });
            }

            // Check open ports
            if baseline.open_ports != current_state.open_ports {
                changes.push(DriftChange {
                    field: "open_ports".to_string(),
                    old_value: format!("{:?}", baseline.open_ports),
                    new_value: format!("{:?}", current_state.open_ports),
                });
            }

            // Check SSL configuration
            if baseline.ssl_config != current_state.ssl_config {
                changes.push(DriftChange {
                    field: "ssl_config".to_string(),
                    old_value: baseline.ssl_config.clone().unwrap_or_default(),
                    new_value: current_state.ssl_config.clone().unwrap_or_default(),
                });
            }

            // Check technologies
            if baseline.technologies != current_state.technologies {
                changes.push(DriftChange {
                    field: "technologies".to_string(),
                    old_value: baseline.technologies.join(", "),
                    new_value: current_state.technologies.join(", "),
                });
            }

            if !changes.is_empty() {
                let severity = self.calculate_severity(&changes);
                return Some(DriftEvent {
                    asset_id: asset_id.to_string(),
                    detected_at: Utc::now().to_rfc3339(),
                    changes,
                    severity,
                });
            }
        }

        None
    }

    fn calculate_severity(&self, changes: &[DriftChange]) -> String {
        for change in changes {
            match change.field.as_str() {
                "open_ports" => return "high".to_string(),
                "ssl_config" => return "medium".to_string(),
                _ => {}
            }
        }
        "low".to_string()
    }
}

impl Default for DriftDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// State of an asset for drift detection
#[derive(Debug, Clone, PartialEq)]
pub struct AssetState {
    pub dns_records: Vec<String>,
    pub open_ports: Vec<u16>,
    pub ssl_config: Option<String>,
    pub technologies: Vec<String>,
    pub headers: HashMap<String, String>,
    pub captured_at: String,
}

impl AssetState {
    pub fn new() -> Self {
        Self {
            dns_records: vec![],
            open_ports: vec![],
            ssl_config: None,
            technologies: vec![],
            headers: HashMap::new(),
            captured_at: Utc::now().to_rfc3339(),
        }
    }
}

impl Default for AssetState {
    fn default() -> Self {
        Self::new()
    }
}

/// A drift event
#[derive(Debug)]
pub struct DriftEvent {
    pub asset_id: String,
    pub detected_at: String,
    pub changes: Vec<DriftChange>,
    pub severity: String,
}

/// A single drift change
#[derive(Debug)]
pub struct DriftChange {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drift_detection() {
        let mut detector = DriftDetector::new();

        let baseline = AssetState {
            dns_records: vec!["1.2.3.4".to_string()],
            open_ports: vec![80, 443],
            ssl_config: Some("TLS 1.2".to_string()),
            technologies: vec!["nginx".to_string()],
            headers: HashMap::new(),
            captured_at: Utc::now().to_rfc3339(),
        };

        detector.set_baseline("asset-1".to_string(), baseline);

        // Current state with drift
        let current = AssetState {
            dns_records: vec!["1.2.3.4".to_string()],
            open_ports: vec![80, 443, 8080], // New port
            ssl_config: Some("TLS 1.2".to_string()),
            technologies: vec!["nginx".to_string()],
            headers: HashMap::new(),
            captured_at: Utc::now().to_rfc3339(),
        };

        let drift = detector.check_drift("asset-1", &current);
        assert!(drift.is_some());

        let event = drift.unwrap();
        assert_eq!(event.severity, "high");
        assert_eq!(event.changes.len(), 1);
        assert_eq!(event.changes[0].field, "open_ports");
    }

    #[test]
    fn test_no_drift() {
        let mut detector = DriftDetector::new();

        let state = AssetState {
            dns_records: vec!["1.2.3.4".to_string()],
            open_ports: vec![80, 443],
            ssl_config: None,
            technologies: vec![],
            headers: HashMap::new(),
            captured_at: Utc::now().to_rfc3339(),
        };

        detector.set_baseline("asset-1".to_string(), state.clone());

        let drift = detector.check_drift("asset-1", &state);
        assert!(drift.is_none());
    }
}
