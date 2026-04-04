//! Report generator

use super::templates::TemplateConfig;
use crate::storage::{AttackSurfaceSummary, FindingSummary};
use anyhow::Result;
use chrono::Utc;
use pulldown_cmark::{html, Options, Parser};

/// Report generator for various formats
pub struct ReportGenerator {
    config: TemplateConfig,
}

impl ReportGenerator {
    /// Create a new report generator
    pub fn new() -> Self {
        Self {
            config: TemplateConfig::default(),
        }
    }

    /// Create a report generator with a custom template config
    pub fn with_template_config(config: TemplateConfig) -> Self {
        Self { config }
    }

    /// Generate JSON report
    pub fn generate_json(&self, findings: &[FindingSummary]) -> Result<String> {
        Ok(serde_json::to_string_pretty(findings)?)
    }

    /// Generate Markdown report
    pub fn generate_markdown(&self, findings: &[FindingSummary]) -> Result<String> {
        let mut md = String::new();

        md.push_str("# Security Assessment Report\n\n");
        md.push_str(&format!(
            "Generated: {}\n\n",
            Utc::now().format("%Y-%m-%d %H:%M UTC")
        ));

        // Summary
        md.push_str("## Summary\n\n");
        let critical = findings.iter().filter(|f| f.severity == "critical").count();
        let high = findings.iter().filter(|f| f.severity == "high").count();
        let medium = findings.iter().filter(|f| f.severity == "medium").count();
        let low = findings.iter().filter(|f| f.severity == "low").count();

        md.push_str(&format!("| Severity | Count |\n"));
        md.push_str(&format!("|----------|-------|\n"));
        md.push_str(&format!("| Critical | {} |\n", critical));
        md.push_str(&format!("| High | {} |\n", high));
        md.push_str(&format!("| Medium | {} |\n", medium));
        md.push_str(&format!("| Low | {} |\n", low));
        md.push_str(&format!("| **Total** | **{}** |\n\n", findings.len()));

        // Findings
        md.push_str("## Findings\n\n");

        for (i, finding) in findings.iter().enumerate() {
            md.push_str(&format!("### {}. {}\n\n", i + 1, finding.title));
            md.push_str(&format!(
                "**Severity:** {} | **Confidence:** {}%\n\n",
                finding.severity.to_uppercase(),
                finding.confidence
            ));
            md.push_str(&format!("**Asset:** `{}`\n\n", finding.asset));
            md.push_str("---\n\n");
        }

        Ok(md)
    }

    /// Generate HTML report
    pub fn generate_html(&self, findings: &[FindingSummary]) -> Result<String> {
        let mut html = String::new();

        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("<title>Security Assessment Report</title>\n");
        html.push_str("<style>\n");
        html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }\n");
        html.push_str(".critical { color: #dc3545; }\n");
        html.push_str(".high { color: #fd7e14; }\n");
        html.push_str(".medium { color: #ffc107; }\n");
        html.push_str(".low { color: #28a745; }\n");
        html.push_str("table { border-collapse: collapse; width: 100%; }\n");
        html.push_str("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
        html.push_str("th { background-color: #f4f4f4; }\n");
        html.push_str(".finding { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }\n");
        html.push_str("</style>\n</head>\n<body>\n");

        html.push_str("<h1>Security Assessment Report</h1>\n");
        html.push_str(&format!(
            "<p>Generated: {}</p>\n",
            Utc::now().format("%Y-%m-%d %H:%M UTC")
        ));

        // Summary
        html.push_str("<h2>Summary</h2>\n");
        let critical = findings.iter().filter(|f| f.severity == "critical").count();
        let high = findings.iter().filter(|f| f.severity == "high").count();
        let medium = findings.iter().filter(|f| f.severity == "medium").count();
        let low = findings.iter().filter(|f| f.severity == "low").count();

        html.push_str("<table>\n<tr><th>Severity</th><th>Count</th></tr>\n");
        html.push_str(&format!(
            "<tr><td class='critical'>Critical</td><td>{}</td></tr>\n",
            critical
        ));
        html.push_str(&format!(
            "<tr><td class='high'>High</td><td>{}</td></tr>\n",
            high
        ));
        html.push_str(&format!(
            "<tr><td class='medium'>Medium</td><td>{}</td></tr>\n",
            medium
        ));
        html.push_str(&format!(
            "<tr><td class='low'>Low</td><td>{}</td></tr>\n",
            low
        ));
        html.push_str(&format!(
            "<tr><td><strong>Total</strong></td><td><strong>{}</strong></td></tr>\n",
            findings.len()
        ));
        html.push_str("</table>\n");

        // Findings
        html.push_str("<h2>Findings</h2>\n");

        for finding in findings {
            html.push_str(&format!("<div class='finding'>\n"));
            html.push_str(&format!("<h3>{}</h3>\n", html_escape(&finding.title)));
            html.push_str(&format!(
                "<p><strong>Severity:</strong> <span class='{}'>{}</span></p>\n",
                finding.severity,
                finding.severity.to_uppercase()
            ));
            html.push_str(&format!(
                "<p><strong>Confidence:</strong> {}%</p>\n",
                finding.confidence
            ));
            html.push_str(&format!(
                "<p><strong>Asset:</strong> <code>{}</code></p>\n",
                html_escape(&finding.asset)
            ));
            html.push_str("</div>\n");
        }

        html.push_str("</body>\n</html>");

        Ok(html)
    }

    /// Generate bug bounty submission format
    pub fn generate_bounty_report(&self, findings: &[FindingSummary]) -> Result<String> {
        let mut report = String::new();

        for finding in findings {
            report.push_str(&format!("# {}\n\n", finding.title));
            report.push_str("## Submission Metadata\n");
            report.push_str(&format!("- **Title:** {}\n", finding.title));
            report.push_str(&format!(
                "- **Severity:** {}\n",
                finding.severity.to_uppercase()
            ));
            report.push_str(&format!("- **Confidence:** {}%\n", finding.confidence));
            report.push_str(&format!("- **Primary Asset:** `{}`\n\n", finding.asset));

            report.push_str("## Scope Mapping\n");
            report.push_str(&format!("- In-scope asset observed: `{}`\n", finding.asset));
            report.push_str(
                "- Program scope verification performed by AegisOSINT policy engine.\n\n",
            );

            report.push_str("## Impact\n");
            report.push_str(&format!(
                "Observed issue classified as **{}** severity with **{}%** confidence. \
This finding may increase external attack surface risk for the mapped asset.\n\n",
                finding.severity.to_uppercase(),
                finding.confidence
            ));

            report.push_str("## Reproducibility Notes\n");
            report.push_str("1. Execute authorized scan against approved scope.\n");
            report.push_str("2. Filter findings by the ID below.\n");
            report.push_str(&format!(
                "3. Confirm evidence and response behavior for `{}`.\n\n",
                finding.asset
            ));

            report.push_str("## Evidence Links\n");
            report.push_str(&format!("- Finding ID: `{}`\n", finding.id));
            if self.config.include_evidence {
                report.push_str(
                    "- Review detailed evidence in local AegisOSINT database (`evidence` records).\n",
                );
                report.push_str(
                    "- Export technical context with: `aegis findings show --id <finding-id> --full`\n\n",
                );
            } else {
                report.push('\n');
            }

            if self.config.include_remediation {
                report.push_str("## Suggested Remediation Direction\n");
                report.push_str("Restrict exposure, enforce least-privilege configuration, and re-validate after fix with `aegis findings verify`.\n\n");
            }
            report.push_str("---\n\n");
        }

        Ok(report)
    }

    /// Generate executive HTML summary
    pub fn generate_executive_html(&self, findings: &[FindingSummary]) -> Result<String> {
        let critical = findings.iter().filter(|f| f.severity == "critical").count();
        let high = findings.iter().filter(|f| f.severity == "high").count();
        let medium = findings.iter().filter(|f| f.severity == "medium").count();
        let low = findings.iter().filter(|f| f.severity == "low").count();

        let risk_level = if critical > 0 {
            "Critical"
        } else if high > 0 {
            "High"
        } else if medium > 0 {
            "Medium"
        } else {
            "Low"
        };

        let mut html = String::new();
        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("<title>Executive Security Summary</title>\n");
        html.push_str("<style>\n");
        html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; max-width: 800px; }\n");
        html.push_str(".metric { display: inline-block; padding: 20px 40px; margin: 10px; border-radius: 10px; text-align: center; }\n");
        html.push_str(".critical { background: #dc3545; color: white; }\n");
        html.push_str(".high { background: #fd7e14; color: white; }\n");
        html.push_str(".medium { background: #ffc107; }\n");
        html.push_str(".low { background: #28a745; color: white; }\n");
        html.push_str(".metric-value { font-size: 48px; font-weight: bold; }\n");
        html.push_str(".metric-label { font-size: 14px; }\n");
        html.push_str("</style>\n</head>\n<body>\n");

        html.push_str("<h1>Executive Security Summary</h1>\n");
        html.push_str(&format!(
            "<p>Report Date: {}</p>\n",
            Utc::now().format("%B %d, %Y")
        ));
        html.push_str(&format!(
            "<p><strong>Overall Risk Level:</strong> {}</p>\n",
            risk_level
        ));

        html.push_str("<div>\n");
        html.push_str(&format!("<div class='metric critical'><div class='metric-value'>{}</div><div class='metric-label'>Critical</div></div>\n", critical));
        html.push_str(&format!("<div class='metric high'><div class='metric-value'>{}</div><div class='metric-label'>High</div></div>\n", high));
        html.push_str(&format!("<div class='metric medium'><div class='metric-value'>{}</div><div class='metric-label'>Medium</div></div>\n", medium));
        html.push_str(&format!("<div class='metric low'><div class='metric-value'>{}</div><div class='metric-label'>Low</div></div>\n", low));
        html.push_str("</div>\n");

        html.push_str("<h2>Key Recommendations</h2>\n<ol>\n");
        if critical > 0 {
            html.push_str("<li>Address critical findings immediately</li>\n");
        }
        if high > 0 {
            html.push_str("<li>Prioritize high-severity issues for remediation</li>\n");
        }
        html.push_str("<li>Implement continuous monitoring</li>\n");
        html.push_str("<li>Review security header configurations</li>\n");
        html.push_str("</ol>\n");

        html.push_str("</body>\n</html>");

        Ok(html)
    }

    /// Generate executive markdown summary
    pub fn generate_executive_markdown(&self, findings: &[FindingSummary]) -> Result<String> {
        let critical = findings.iter().filter(|f| f.severity == "critical").count();
        let high = findings.iter().filter(|f| f.severity == "high").count();
        let medium = findings.iter().filter(|f| f.severity == "medium").count();
        let low = findings.iter().filter(|f| f.severity == "low").count();

        let mut md = String::new();
        md.push_str("# Executive Security Summary\n\n");
        md.push_str(&format!(
            "Report Date: {}\n\n",
            Utc::now().format("%B %d, %Y")
        ));

        md.push_str("## Risk Overview\n\n");
        md.push_str(&format!("| Severity | Count |\n|---|---|\n"));
        md.push_str(&format!("| 🔴 Critical | {} |\n", critical));
        md.push_str(&format!("| 🟠 High | {} |\n", high));
        md.push_str(&format!("| 🟡 Medium | {} |\n", medium));
        md.push_str(&format!("| 🟢 Low | {} |\n\n", low));

        md.push_str("## Key Recommendations\n\n");
        md.push_str("1. Address critical findings immediately\n");
        md.push_str("2. Prioritize high-severity issues for remediation\n");
        md.push_str("3. Implement continuous monitoring\n");

        Ok(md)
    }

    /// Generate summary markdown
    pub fn generate_summary_markdown(&self, summary: &AttackSurfaceSummary) -> Result<String> {
        let mut md = String::new();

        md.push_str("# Attack Surface Summary\n\n");
        md.push_str("## Asset Inventory\n\n");
        md.push_str(&format!("| Asset Type | Count |\n|---|---|\n"));
        md.push_str(&format!("| Domains | {} |\n", summary.domain_count));
        md.push_str(&format!("| Subdomains | {} |\n", summary.subdomain_count));
        md.push_str(&format!("| IP Addresses | {} |\n", summary.ip_count));
        md.push_str(&format!("| Services | {} |\n\n", summary.service_count));

        md.push_str("## Risk Summary\n\n");
        md.push_str(&format!("- **Critical:** {}\n", summary.critical_findings));
        md.push_str(&format!("- **High:** {}\n", summary.high_findings));
        md.push_str(&format!("- **Medium:** {}\n", summary.medium_findings));
        md.push_str(&format!("- **Low:** {}\n\n", summary.low_findings));

        md.push_str("## Changes\n\n");
        md.push_str(&format!("- Assets added: {}\n", summary.assets_added));
        md.push_str(&format!("- Assets removed: {}\n", summary.assets_removed));

        Ok(md)
    }

    /// Generate summary HTML
    pub fn generate_summary_html(&self, summary: &AttackSurfaceSummary) -> Result<String> {
        let md = self.generate_summary_markdown(summary)?;
        let parser = Parser::new_ext(&md, Options::all());
        let mut html_output = String::new();
        html::push_html(&mut html_output, parser);
        Ok(format!(
            "<!DOCTYPE html><html><head><title>Attack Surface Summary</title></head><body>{}</body></html>",
            html_output
        ))
    }
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_json() {
        let generator = ReportGenerator::new();
        let findings = vec![FindingSummary {
            id: "test".to_string(),
            asset: "example.com".to_string(),
            title: "Test Finding".to_string(),
            severity: "high".to_string(),
            confidence: 90,
            status: Some("open".to_string()),
        }];

        let json = generator.generate_json(&findings).unwrap();
        assert!(json.contains("Test Finding"));
    }

    #[test]
    fn test_generate_markdown() {
        let generator = ReportGenerator::new();
        let findings = vec![FindingSummary {
            id: "test".to_string(),
            asset: "example.com".to_string(),
            title: "Test Finding".to_string(),
            severity: "critical".to_string(),
            confidence: 95,
            status: Some("open".to_string()),
        }];

        let md = generator.generate_markdown(&findings).unwrap();
        assert!(md.contains("# Security Assessment Report"));
        assert!(md.contains("Test Finding"));
    }
}
