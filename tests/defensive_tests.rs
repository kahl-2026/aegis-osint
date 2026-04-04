#[cfg(test)]
mod defensive_tests {
    #[test]
    fn test_typosquat_variations() {
        // Test basic typo generation logic
        let domain = "example";

        // Test transposition - swap adjacent characters
        let transposed: Vec<String> = (0..domain.len() - 1)
            .map(|i| {
                let mut chars: Vec<char> = domain.chars().collect();
                chars.swap(i, i + 1);
                chars.iter().collect()
            })
            .collect();

        assert!(
            transposed.contains(&"xeample".to_string())
                || transposed.contains(&"examlpe".to_string())
        );
    }

    #[test]
    fn test_missing_letter_variations() {
        let domain = "test";

        // Generate missing letter variations
        let missing: Vec<String> = (0..domain.len())
            .map(|i| {
                let mut s = domain.to_string();
                s.remove(i);
                s
            })
            .collect();

        assert!(missing.contains(&"tst".to_string()));
        assert!(missing.contains(&"tet".to_string()));
        assert!(missing.contains(&"est".to_string()));
    }
}

#[cfg(test)]
mod brand_monitoring_tests {
    #[test]
    fn test_domain_similarity_scoring() {
        // Test Levenshtein distance-based similarity
        let similarity = calculate_similarity("example.com", "examp1e.com");
        assert!(similarity > 0.8); // Should be highly similar

        let similarity_low = calculate_similarity("example.com", "different.com");
        assert!(similarity_low < 0.5); // Should be dissimilar
    }

    fn calculate_similarity(a: &str, b: &str) -> f64 {
        let len_a = a.len();
        let len_b = b.len();
        let max_len = std::cmp::max(len_a, len_b);

        if max_len == 0 {
            return 1.0;
        }

        let distance = levenshtein_distance(a, b);
        1.0 - (distance as f64 / max_len as f64)
    }

    fn levenshtein_distance(a: &str, b: &str) -> usize {
        let a_chars: Vec<char> = a.chars().collect();
        let b_chars: Vec<char> = b.chars().collect();
        let len_a = a_chars.len();
        let len_b = b_chars.len();

        let mut matrix = vec![vec![0usize; len_b + 1]; len_a + 1];

        for i in 0..=len_a {
            matrix[i][0] = i;
        }
        for j in 0..=len_b {
            matrix[0][j] = j;
        }

        for i in 1..=len_a {
            for j in 1..=len_b {
                let cost = if a_chars[i - 1] == b_chars[j - 1] {
                    0
                } else {
                    1
                };
                matrix[i][j] = std::cmp::min(
                    std::cmp::min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1),
                    matrix[i - 1][j - 1] + cost,
                );
            }
        }

        matrix[len_a][len_b]
    }
}
