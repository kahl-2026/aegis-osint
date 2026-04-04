//! Historical correlation module
//!
//! Correlates current findings with historical data from lawful public sources.

use anyhow::Result;
use chrono::Utc;
use std::collections::{HashMap, HashSet};

/// Historical DNS data source
pub struct HistoricalDns;

impl HistoricalDns {
    /// Query historical DNS records
    pub async fn query(&self, domain: &str) -> Result<Vec<HistoricalDnsRecord>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()?;

        let mut records = Vec::new();
        let mut seen = HashSet::new();

        // CT-based historical hostnames
        let ct_url = format!("https://crt.sh/?q=%.{}&output=json", domain);
        if let Ok(resp) = client.get(&ct_url).send().await {
            if resp.status().is_success() {
                if let Ok(entries) = resp.json::<Vec<CtLogEntry>>().await {
                    for entry in entries {
                        for raw in entry.name_value.split('\n') {
                            let host = raw.trim().trim_start_matches("*.").to_lowercase();
                            if host.is_empty() || !host.ends_with(domain) {
                                continue;
                            }
                            let key = format!(
                                "ct:{}:{}",
                                host,
                                entry.not_before.clone().unwrap_or_default()
                            );
                            if seen.insert(key) {
                                records.push(HistoricalDnsRecord {
                                    domain: host.clone(),
                                    record_type: "CT_HOST".to_string(),
                                    value: host,
                                    first_seen: entry
                                        .not_before
                                        .clone()
                                        .unwrap_or_else(|| Utc::now().to_rfc3339()),
                                    last_seen: entry
                                        .not_after
                                        .clone()
                                        .unwrap_or_else(|| Utc::now().to_rfc3339()),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Current DNS snapshots through Google DoH (used as timeline reference points)
        let doh_types = [
            ("A", 1u8),
            ("AAAA", 28u8),
            ("NS", 2u8),
            ("MX", 15u8),
            ("TXT", 16u8),
        ];
        for (kind, t) in doh_types {
            let url = format!(
                "https://dns.google/resolve?name={}&type={}",
                urlencoding::encode(domain),
                t
            );
            if let Ok(resp) = client.get(url).send().await {
                if resp.status().is_success() {
                    if let Ok(payload) = resp.json::<DnsGoogleResponse>().await {
                        for ans in payload.answer.unwrap_or_default() {
                            let key = format!("{}:{}:{}", kind, ans.name, ans.data);
                            if seen.insert(key) {
                                let ts = Utc::now().to_rfc3339();
                                records.push(HistoricalDnsRecord {
                                    domain: ans.name.trim_end_matches('.').to_string(),
                                    record_type: kind.to_string(),
                                    value: ans.data,
                                    first_seen: ts.clone(),
                                    last_seen: ts,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(records)
    }
}

/// Historical DNS record
#[derive(Debug)]
pub struct HistoricalDnsRecord {
    pub domain: String,
    pub record_type: String,
    pub value: String,
    pub first_seen: String,
    pub last_seen: String,
}

/// Historical WHOIS data
pub struct HistoricalWhois;

impl HistoricalWhois {
    /// Query historical WHOIS data
    pub async fn query(&self, domain: &str) -> Result<Vec<HistoricalWhoisRecord>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()?;

        // RDAP is lawful/public and returns registrar-ish ownership metadata
        let rdap_url = format!("https://rdap.org/domain/{}", domain);
        let mut out = Vec::new();

        if let Ok(resp) = client.get(&rdap_url).send().await {
            if resp.status().is_success() {
                if let Ok(rdap) = resp.json::<RdapDomainResponse>().await {
                    let mut emails = Vec::new();
                    let mut registrant = None;

                    for entity in rdap.entities.unwrap_or_default() {
                        if registrant.is_none() {
                            registrant = entity
                                .vcard_array
                                .as_ref()
                                .and_then(|v| extract_vcard_field(v, "fn"));
                        }
                        if let Some(email) = entity
                            .vcard_array
                            .as_ref()
                            .and_then(|v| extract_vcard_field(v, "email"))
                        {
                            emails.push(email);
                        }
                    }

                    let nameservers = rdap
                        .nameservers
                        .unwrap_or_default()
                        .into_iter()
                        .map(|ns| ns.ldh_name)
                        .collect::<Vec<_>>();

                    out.push(HistoricalWhoisRecord {
                        domain: domain.to_string(),
                        registrant,
                        emails,
                        nameservers,
                        snapshot_date: Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        Ok(out)
    }
}

/// Historical WHOIS record
#[derive(Debug)]
pub struct HistoricalWhoisRecord {
    pub domain: String,
    pub registrant: Option<String>,
    pub emails: Vec<String>,
    pub nameservers: Vec<String>,
    pub snapshot_date: String,
}

/// Correlator for historical data
#[allow(dead_code)]
pub struct HistoricalCorrelator {
    dns: HistoricalDns,
    whois: HistoricalWhois,
}

impl HistoricalCorrelator {
    pub fn new() -> Self {
        Self {
            dns: HistoricalDns,
            whois: HistoricalWhois,
        }
    }

    /// Find related domains by shared infrastructure
    pub async fn find_related_by_infrastructure(&self, domain: &str) -> Result<Vec<RelatedDomain>> {
        let dns = self.dns.query(domain).await?;
        let whois = self.whois.query(domain).await?;

        let mut related = Vec::new();
        let mut seen = HashSet::new();

        // Related hostnames from CT history
        for rec in dns.iter().filter(|r| r.record_type == "CT_HOST") {
            if rec.domain != domain && seen.insert(rec.domain.clone()) {
                related.push(RelatedDomain {
                    domain: rec.domain.clone(),
                    relationship: "certificate-transparency".to_string(),
                    confidence: 80,
                });
            }
        }

        // Nameserver-coupled relationships
        for snapshot in &whois {
            for ns in &snapshot.nameservers {
                let ns_root = ns.trim().trim_end_matches('.').to_string();
                if ns_root.is_empty() {
                    continue;
                }
                let key = format!("ns:{}", ns_root);
                if seen.insert(key) {
                    related.push(RelatedDomain {
                        domain: ns_root,
                        relationship: "shared-nameserver".to_string(),
                        confidence: 60,
                    });
                }
            }
        }

        Ok(related)
    }

    /// Timeline of domain changes
    pub async fn get_domain_timeline(&self, domain: &str) -> Result<DomainTimeline> {
        let dns = self.dns.query(domain).await?;
        let whois = self.whois.query(domain).await?;

        let mut events = Vec::new();
        let mut latest_by_type: HashMap<String, String> = HashMap::new();

        for rec in dns {
            let prev = latest_by_type.insert(rec.record_type.clone(), rec.value.clone());
            events.push(TimelineEvent {
                timestamp: rec.first_seen.clone(),
                event_type: format!("dns_{}", rec.record_type.to_lowercase()),
                description: format!("Observed {} record for {}", rec.record_type, rec.domain),
                old_value: prev,
                new_value: Some(rec.value),
            });
        }

        for snapshot in whois {
            events.push(TimelineEvent {
                timestamp: snapshot.snapshot_date.clone(),
                event_type: "whois_snapshot".to_string(),
                description: "WHOIS/RDAP snapshot captured".to_string(),
                old_value: None,
                new_value: Some(format!(
                    "registrant={}; nameservers={}",
                    snapshot
                        .registrant
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    snapshot.nameservers.join(",")
                )),
            });
        }

        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        Ok(DomainTimeline {
            domain: domain.to_string(),
            events,
        })
    }
}

impl Default for HistoricalCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

/// Related domain found through correlation
#[derive(Debug)]
pub struct RelatedDomain {
    pub domain: String,
    pub relationship: String,
    pub confidence: u8,
}

/// Domain change timeline
#[derive(Debug)]
pub struct DomainTimeline {
    pub domain: String,
    pub events: Vec<TimelineEvent>,
}

/// Timeline event
#[derive(Debug)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub event_type: String,
    pub description: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct CtLogEntry {
    name_value: String,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct DnsGoogleResponse {
    #[serde(default)]
    answer: Option<Vec<DnsGoogleAnswer>>,
}

#[derive(Debug, serde::Deserialize)]
struct DnsGoogleAnswer {
    name: String,
    data: String,
}

#[derive(Debug, serde::Deserialize)]
struct RdapDomainResponse {
    #[serde(default)]
    entities: Option<Vec<RdapEntity>>,
    #[serde(default)]
    nameservers: Option<Vec<RdapNameserver>>,
}

#[derive(Debug, serde::Deserialize)]
struct RdapEntity {
    #[serde(default, rename = "vcardArray")]
    vcard_array: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
struct RdapNameserver {
    #[serde(rename = "ldhName")]
    ldh_name: String,
}

fn extract_vcard_field(vcard: &serde_json::Value, field_name: &str) -> Option<String> {
    let arr = vcard.as_array()?;
    let entries = arr.get(1)?.as_array()?;
    for entry in entries {
        let cols = entry.as_array()?;
        if cols.len() >= 4 && cols.first()?.as_str()? == field_name {
            if let Some(v) = cols.get(3) {
                if let Some(s) = v.as_str() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}
