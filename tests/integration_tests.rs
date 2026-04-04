use aegis_osint::scope::{Scope, ScopeItem, ScopeItemType};

#[cfg(test)]
mod scope_tests {
    use super::*;

    fn create_test_scope() -> Scope {
        Scope {
            id: "test-scope-1".to_string(),
            name: "Test Scope".to_string(),
            description: Some("Test scope for integration tests".to_string()),
            program: Some("test-program".to_string()),
            items: vec![
                // In-scope wildcard
                ScopeItem {
                    item_type: ScopeItemType::Wildcard,
                    value: "*.example.com".to_string(),
                    in_scope: true,
                    priority: 10,
                    notes: None,
                },
                // In-scope specific domain
                ScopeItem {
                    item_type: ScopeItemType::Domain,
                    value: "api.example.com".to_string(),
                    in_scope: true,
                    priority: 20,
                    notes: None,
                },
                // Out-of-scope exclusion
                ScopeItem {
                    item_type: ScopeItemType::Domain,
                    value: "admin.example.com".to_string(),
                    in_scope: false,
                    priority: 100,
                    notes: Some("Explicitly excluded".to_string()),
                },
                // In-scope CIDR
                ScopeItem {
                    item_type: ScopeItemType::Cidr,
                    value: "203.0.113.0/24".to_string(),
                    in_scope: true,
                    priority: 10,
                    notes: None,
                },
            ],
            active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            rules: None,
            domain_count: 1,
            cidr_count: 1,
            wildcard_count: 1,
        }
    }

    #[test]
    fn test_wildcard_domain_in_scope() {
        let scope = create_test_scope();

        // Any subdomain of example.com should be in scope
        assert!(scope.is_in_scope("test.example.com").in_scope);
        assert!(scope.is_in_scope("sub.test.example.com").in_scope);
        assert!(scope.is_in_scope("www.example.com").in_scope);
    }

    #[test]
    fn test_explicit_exclusion_overrides_wildcard() {
        let scope = create_test_scope();

        // admin.example.com is explicitly excluded (priority 100 > 10)
        assert!(!scope.is_in_scope("admin.example.com").in_scope);
    }

    #[test]
    fn test_out_of_scope_domain() {
        let scope = create_test_scope();

        // Domains not matching any scope item are out of scope
        assert!(!scope.is_in_scope("notexample.com").in_scope);
        assert!(!scope.is_in_scope("example.org").in_scope);
    }

    #[test]
    fn test_cidr_matching() {
        let scope = create_test_scope();

        // IPs in the CIDR range should be in scope
        assert!(scope.is_in_scope("203.0.113.1").in_scope);
        assert!(scope.is_in_scope("203.0.113.254").in_scope);

        // IPs outside the range should be out of scope
        assert!(!scope.is_in_scope("203.0.114.1").in_scope);
        assert!(!scope.is_in_scope("192.168.1.1").in_scope);
    }

    #[test]
    fn test_blocked_patterns() {
        let scope = create_test_scope();

        // These should always be blocked regardless of scope
        assert!(!scope.is_in_scope("localhost").in_scope);
        assert!(!scope.is_in_scope("127.0.0.1").in_scope);
        assert!(!scope.is_in_scope("example.gov").in_scope);
        assert!(!scope.is_in_scope("example.mil").in_scope);
    }
}

#[cfg(test)]
mod policy_tests {
    use aegis_osint::config::Config;
    use aegis_osint::policy::PolicyEngine;
    use aegis_osint::storage::Storage;

    async fn create_test_engine() -> PolicyEngine {
        let mut config = Config::default();
        let test_db = std::env::temp_dir().join(format!(
            "aegis-policy-test-{}.db",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        config.database.db_type = "sqlite".to_string();
        config.database.connection = test_db.to_string_lossy().to_string();

        let storage = Storage::initialize(&config)
            .await
            .expect("failed to initialize test storage");
        PolicyEngine::new(&config, &storage)
            .await
            .expect("failed to initialize policy engine")
    }

    #[tokio::test]
    async fn test_policy_engine_creation() {
        let engine = create_test_engine().await;
        assert!(engine.is_enabled().await);
    }

    #[tokio::test]
    async fn test_kill_switch() {
        let engine = create_test_engine().await;

        // Initially not killed
        assert!(engine.is_enabled().await);

        // Activate kill switch
        engine.activate_kill_switch().await;
        assert!(!engine.is_enabled().await);
    }
}

#[cfg(test)]
mod validation_tests {
    use aegis_osint::utils::validation::*;

    #[test]
    fn test_domain_validation() {
        assert!(validate_domain("example.com").unwrap());
        assert!(validate_domain("sub.example.com").unwrap());
        assert!(validate_domain("a.b.c.example.com").unwrap());

        // Invalid domains
        assert!(!validate_domain("").unwrap());
        assert!(!validate_domain("example").unwrap());
    }

    #[test]
    fn test_ip_validation() {
        // Valid IPv4
        assert!(validate_ip("192.168.1.1"));
        assert!(validate_ip("10.0.0.1"));

        // Valid IPv6
        assert!(validate_ip("::1"));
        assert!(validate_ip("2001:db8::1"));

        // Invalid
        assert!(!validate_ip("invalid"));
        assert!(!validate_ip("256.1.1.1"));
    }

    #[test]
    fn test_cidr_validation() {
        assert!(validate_cidr("192.168.1.0/24"));
        assert!(validate_cidr("10.0.0.0/8"));
        assert!(validate_cidr("2001:db8::/32"));

        assert!(!validate_cidr("invalid"));
        assert!(!validate_cidr("192.168.1.0/33"));
    }

    #[test]
    fn test_url_validation() {
        assert!(validate_url("https://example.com"));
        assert!(validate_url("http://example.com/path?query=1"));

        assert!(!validate_url("not a url"));
        assert!(!validate_url(""));
    }

    #[test]
    fn test_asn_validation() {
        assert!(validate_asn("AS12345"));
        assert!(validate_asn("as12345"));
        assert!(validate_asn("12345"));

        assert!(!validate_asn("ASINVALID"));
        assert!(!validate_asn(""));
    }
}
