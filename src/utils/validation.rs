//! Input validation utilities

use anyhow::Result;
use regex::Regex;
use std::net::IpAddr;

/// Validate a domain name
pub fn validate_domain(domain: &str) -> Result<bool> {
    if domain.is_empty() || domain.len() > 253 {
        return Ok(false);
    }

    let re = Regex::new(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")?;
    Ok(re.is_match(domain))
}

/// Validate an IP address
pub fn validate_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}

/// Validate a CIDR range
pub fn validate_cidr(cidr: &str) -> bool {
    cidr.parse::<ipnetwork::IpNetwork>().is_ok()
}

/// Validate a URL
pub fn validate_url(url_str: &str) -> bool {
    url::Url::parse(url_str).is_ok()
}

/// Sanitize input string
pub fn sanitize_input(input: &str) -> String {
    input
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .collect()
}

/// Validate ASN format
pub fn validate_asn(asn: &str) -> bool {
    let normalized = asn.to_uppercase();
    let number = normalized.strip_prefix("AS").unwrap_or(&normalized);
    number.parse::<u32>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_domain() {
        assert!(validate_domain("example.com").unwrap());
        assert!(validate_domain("sub.example.com").unwrap());
        assert!(!validate_domain("").unwrap());
        assert!(!validate_domain("-invalid.com").unwrap());
    }

    #[test]
    fn test_validate_ip() {
        assert!(validate_ip("192.168.1.1"));
        assert!(validate_ip("::1"));
        assert!(!validate_ip("invalid"));
    }

    #[test]
    fn test_validate_cidr() {
        assert!(validate_cidr("192.168.1.0/24"));
        assert!(validate_cidr("10.0.0.0/8"));
        assert!(!validate_cidr("invalid"));
    }

    #[test]
    fn test_validate_asn() {
        assert!(validate_asn("AS12345"));
        assert!(validate_asn("as12345"));
        assert!(validate_asn("12345"));
        assert!(!validate_asn("ASINVALID"));
    }
}
