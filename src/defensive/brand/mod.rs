//! Brand monitoring module
//!
//! Monitors for brand abuse, typosquatting, and impersonation

use std::collections::HashSet;

/// Brand monitor for detecting abuse
pub struct BrandMonitor {
    brand_name: String,
    known_domains: HashSet<String>,
}

impl BrandMonitor {
    /// Create a new brand monitor
    pub fn new(brand_name: &str) -> Self {
        Self {
            brand_name: brand_name.to_string(),
            known_domains: HashSet::new(),
        }
    }

    /// Add known legitimate domain
    pub fn add_known_domain(&mut self, domain: &str) {
        self.known_domains.insert(domain.to_lowercase());
    }

    /// Generate typosquat variations
    pub fn generate_typosquats(&self) -> Vec<TyposquatVariation> {
        let mut variations = Vec::new();
        let name = self.brand_name.to_lowercase();
        let chars: Vec<char> = name.chars().collect();
        if chars.is_empty() {
            return variations;
        }

        // Character substitution
        let substitutions = [
            ('a', 'e'), ('e', 'a'), ('i', '1'), ('l', '1'),
            ('o', '0'), ('s', '5'), ('s', 'z'), ('g', '9'),
        ];

        for (from, to) in substitutions {
            if name.contains(from) {
                variations.push(TyposquatVariation {
                    domain: name.replace(from, &to.to_string()),
                    technique: "substitution".to_string(),
                    original_char: from.to_string(),
                    replacement: to.to_string(),
                });
            }
        }

        // Character omission
        for (i, original) in chars.iter().enumerate() {
            let omitted: String = chars
                .iter()
                .enumerate()
                .filter_map(|(idx, c)| if idx == i { None } else { Some(*c) })
                .collect();
            variations.push(TyposquatVariation {
                domain: omitted,
                technique: "omission".to_string(),
                original_char: original.to_string(),
                replacement: String::new(),
            });
        }

        // Character duplication
        for (i, c) in chars.iter().enumerate() {
            if c.is_alphabetic() {
                let mut duplicated_chars = chars.clone();
                duplicated_chars.insert(i, *c);
                let duplicated: String = duplicated_chars.into_iter().collect();
                variations.push(TyposquatVariation {
                    domain: duplicated,
                    technique: "duplication".to_string(),
                    original_char: c.to_string(),
                    replacement: format!("{}{}", c, c),
                });
            }
        }

        // Adjacent key transposition
        for i in 0..chars.len().saturating_sub(1) {
            let mut transposed_chars = chars.clone();
            transposed_chars.swap(i, i + 1);
            let transposed: String = transposed_chars.into_iter().collect();
            variations.push(TyposquatVariation {
                domain: transposed,
                technique: "transposition".to_string(),
                original_char: format!("{}{}", chars[i], chars[i + 1]),
                replacement: format!("{}{}", chars[i + 1], chars[i]),
            });
        }

        // Common TLD variations
        let tlds = ["com", "net", "org", "io", "co", "biz", "info"];
        for tld in tlds {
            variations.push(TyposquatVariation {
                domain: format!("{}.{}", name, tld),
                technique: "tld_variation".to_string(),
                original_char: String::new(),
                replacement: tld.to_string(),
            });
        }

        // Homograph attacks (visual similarity)
        let homographs = [
            ("a", "а"), // Cyrillic а
            ("e", "е"), // Cyrillic е
            ("o", "о"), // Cyrillic о
            ("c", "с"), // Cyrillic с
        ];

        for (ascii, unicode) in homographs {
            if name.contains(ascii) {
                variations.push(TyposquatVariation {
                    domain: name.replace(ascii, unicode),
                    technique: "homograph".to_string(),
                    original_char: ascii.to_string(),
                    replacement: unicode.to_string(),
                });
            }
        }

        variations
    }

    /// Check if a domain is a known legitimate domain
    pub fn is_known(&self, domain: &str) -> bool {
        self.known_domains.contains(&domain.to_lowercase())
    }

    /// Analyze potential impersonation
    pub fn analyze_domain(&self, domain: &str) -> DomainAnalysis {
        let lower_domain = domain.to_lowercase();

        // Check for brand name presence
        let contains_brand = self.domain_contains_brand(&lower_domain);

        // Check similarity
        let similarity = self.calculate_similarity(&lower_domain);

        // Check for common impersonation patterns
        let patterns = self.check_impersonation_patterns(&lower_domain);
        let has_keyword_lure = lower_domain.contains("login")
            || lower_domain.contains("account")
            || lower_domain.contains("secure")
            || lower_domain.contains("support")
            || lower_domain.contains("help");
        let brand_like = similarity >= 0.75;
        let known_domain = self.is_known(domain);

        DomainAnalysis {
            domain: domain.to_string(),
            contains_brand: contains_brand || similarity >= 0.8,
            similarity_score: similarity,
            impersonation_patterns: patterns,
            is_suspicious: !known_domain
                && ((contains_brand && similarity > 0.6)
                    || (brand_like && has_keyword_lure)
                    || similarity >= 0.9),
        }
    }

    fn calculate_similarity(&self, domain: &str) -> f64 {
        let brand = normalize_token(&self.brand_name.to_lowercase());
        let mut best = 0.0;

        for candidate in similarity_candidates(domain) {
            let normalized = normalize_token(&candidate);
            if normalized.is_empty() || brand.is_empty() {
                continue;
            }
            let max_len = std::cmp::max(brand.len(), normalized.len()) as f64;
            let distance = levenshtein_distance(&brand, &normalized) as f64;
            let score = 1.0 - (distance / max_len);
            if score > best {
                best = score;
            }
        }

        best
    }

    fn domain_contains_brand(&self, domain: &str) -> bool {
        let brand = normalize_token(&self.brand_name.to_lowercase());
        similarity_candidates(domain)
            .into_iter()
            .map(|candidate| normalize_token(&candidate))
            .any(|candidate| !candidate.is_empty() && candidate.contains(&brand))
    }

    fn check_impersonation_patterns(&self, domain: &str) -> Vec<String> {
        let mut patterns = Vec::new();
        let brand = self.brand_name.to_lowercase();

        if domain.contains(&format!("{}-", brand)) || domain.contains(&format!("-{}", brand)) {
            patterns.push("hyphenation".to_string());
        }

        if domain.contains(&format!("{}login", brand)) || domain.contains(&format!("{}account", brand)) {
            patterns.push("credential_harvesting".to_string());
        }

        if domain.contains(&format!("{}secure", brand)) || domain.contains(&format!("my{}", brand)) {
            patterns.push("trust_abuse".to_string());
        }

        if domain.contains(&format!("{}support", brand)) || domain.contains(&format!("{}help", brand)) {
            patterns.push("support_impersonation".to_string());
        }

        patterns
    }
}

/// Calculate Levenshtein distance between two strings
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let m = a_chars.len();
    let n = b_chars.len();

    if m == 0 { return n; }
    if n == 0 { return m; }

    let mut dp = vec![vec![0; n + 1]; m + 1];

    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }

    for i in 1..=m {
        for j in 1..=n {
            let cost = if a_chars[i-1] == b_chars[j-1] { 0 } else { 1 };
            dp[i][j] = std::cmp::min(
                std::cmp::min(dp[i-1][j] + 1, dp[i][j-1] + 1),
                dp[i-1][j-1] + cost,
            );
        }
    }

    dp[m][n]
}

fn similarity_candidates(domain: &str) -> Vec<String> {
    let host = domain
        .split('/')
        .next()
        .unwrap_or(domain)
        .trim_end_matches('.')
        .to_lowercase();
    let mut candidates = vec![host.clone()];

    for label in host.split('.') {
        if !label.is_empty() {
            candidates.push(label.to_string());
            for token in label.split(|c: char| !c.is_ascii_alphanumeric()) {
                if !token.is_empty() {
                    candidates.push(token.to_string());
                }
            }
        }
    }

    candidates.sort();
    candidates.dedup();
    candidates
}

fn normalize_token(token: &str) -> String {
    token
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '5' => 's',
            '7' => 't',
            _ => c,
        })
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

/// Typosquat domain variation
#[derive(Debug)]
pub struct TyposquatVariation {
    pub domain: String,
    pub technique: String,
    pub original_char: String,
    pub replacement: String,
}

/// Domain analysis result
#[derive(Debug)]
pub struct DomainAnalysis {
    pub domain: String,
    pub contains_brand: bool,
    pub similarity_score: f64,
    pub impersonation_patterns: Vec<String>,
    pub is_suspicious: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typosquat_generation() {
        let monitor = BrandMonitor::new("example");
        let variations = monitor.generate_typosquats();

        assert!(!variations.is_empty());
        assert!(variations.iter().any(|v| v.technique == "substitution"));
        assert!(variations.iter().any(|v| v.technique == "omission"));
    }

    #[test]
    fn test_domain_analysis() {
        let mut monitor = BrandMonitor::new("example");
        monitor.add_known_domain("example.com");

        let analysis = monitor.analyze_domain("examp1e-login.com");
        assert!(analysis.is_suspicious);

        let analysis = monitor.analyze_domain("example.com");
        assert!(!analysis.is_suspicious);
    }

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("example", "examp1e"), 1);
        assert_eq!(levenshtein_distance("test", "test"), 0);
    }
}
