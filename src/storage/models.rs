//! Storage models and types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Scope summary for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeSummary {
    pub id: String,
    pub name: String,
    pub program: Option<String>,
    pub active: bool,
    pub domain_count: usize,
    pub cidr_count: usize,
    pub wildcard_count: usize,
}

/// Scan run information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRunInfo {
    pub id: String,
    pub program: String,
    pub scope_id: String,
    pub run_type: String,
    pub status: String,
    pub progress: i32,
    pub findings_count: i32,
    pub started_at: String,
    pub ended_at: Option<String>,
}

/// Security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub scope_id: String,
    pub run_id: Option<String>,
    pub asset: String,
    pub finding_type: String,
    pub title: String,
    pub description: String,
    pub impact: String,
    pub severity: String,
    pub confidence: i32,
    pub status: Option<String>,
    pub reproduction: Option<String>,
    pub source: String,
    pub method: String,
    pub scope_verified: bool,
    pub evidence: Vec<Evidence>,
    pub created_at: String,
    pub updated_at: String,
}

/// Evidence for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub description: String,
    pub source: String,
    pub data: Option<String>,
    pub timestamp: String,
}

/// Finding summary for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub id: String,
    pub asset: String,
    pub title: String,
    pub severity: String,
    pub confidence: i32,
    pub status: Option<String>,
}

/// Remediation queue item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationItem {
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub asset: String,
    pub owner: Option<String>,
    pub sla: Option<String>,
}

/// Asset record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    pub scope_id: String,
    pub asset_type: String,
    pub value: String,
    pub tags: Vec<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub first_seen: String,
    pub last_seen: String,
}

/// Asset diff result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetDiff {
    pub added: Vec<AssetDiffItem>,
    pub removed: Vec<AssetDiffItem>,
    pub modified: Vec<AssetDiffItem>,
}

/// Asset diff item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetDiffItem {
    pub id: String,
    pub value: String,
    pub asset_type: String,
}

/// Asset history event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetHistoryEvent {
    pub event_type: String,
    pub description: String,
    pub timestamp: String,
}

/// Monitor information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorInfo {
    pub id: String,
    pub scope_id: String,
    pub status: String,
    pub started_at: String,
    pub last_check: String,
    pub next_check: String,
    pub check_count: i32,
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub destination: String,
    pub min_severity: String,
    pub enabled: bool,
}

/// Attack surface summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceSummary {
    pub domain_count: usize,
    pub subdomain_count: usize,
    pub ip_count: usize,
    pub service_count: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub asset_changes: usize,
    pub assets_added: usize,
    pub assets_removed: usize,
    pub config_changes: usize,
    pub cert_changes: usize,
}

/// Scan execution result summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub assets_count: usize,
    pub findings_count: usize,
    pub duration_secs: f64,
}

/// Defensive scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefensiveScanResult {
    pub assets_count: usize,
    pub changes_count: usize,
    pub exposures_count: usize,
    pub duration_secs: f64,
}
