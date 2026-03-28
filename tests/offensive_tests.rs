use aegis_osint::scope::{Scope, ScopeItem, ScopeItemType};

#[cfg(test)]
mod offensive_tests {
    use super::*;

    fn create_test_scope() -> Scope {
        Scope {
            id: "offensive-test".to_string(),
            name: "Offensive Test Scope".to_string(),
            description: None,
            program: Some("test".to_string()),
            items: vec![
                ScopeItem {
                    item_type: ScopeItemType::Wildcard,
                    value: "*.example.com".to_string(),
                    in_scope: true,
                    priority: 10,
                    notes: None,
                },
            ],
            active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            rules: None,
            domain_count: 0,
            cidr_count: 0,
            wildcard_count: 1,
        }
    }

    #[test]
    fn test_scope_enforcement_in_discovery() {
        let scope = create_test_scope();
        
        // Verify scope is properly configured
        assert!(scope.is_in_scope("test.example.com"));
        assert!(!scope.is_in_scope("test.notexample.com"));
        assert!(!scope.is_in_scope("example.gov"));
    }
}
