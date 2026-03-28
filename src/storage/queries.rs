//! Database query helpers

// This module contains query builder helpers and common queries.
// Most queries are implemented directly in database.rs, but complex
// query building logic can be extracted here.

/// Query builder for findings
#[allow(dead_code)]
pub struct FindingsQueryBuilder {
    conditions: Vec<String>,
    params: Vec<String>,
    order_by: String,
    limit: usize,
}

#[allow(dead_code)]
impl FindingsQueryBuilder {
    pub fn new() -> Self {
        Self {
            conditions: vec!["1=1".to_string()],
            params: Vec::new(),
            order_by: "created_at DESC".to_string(),
            limit: 50,
        }
    }

    pub fn with_severity(mut self, severity: &str) -> Self {
        self.conditions.push("severity = ?".to_string());
        self.params.push(severity.to_string());
        self
    }

    pub fn with_scope(mut self, scope_id: &str) -> Self {
        self.conditions.push("scope_id = ?".to_string());
        self.params.push(scope_id.to_string());
        self
    }

    pub fn with_status(mut self, status: &str) -> Self {
        self.conditions.push("status = ?".to_string());
        self.params.push(status.to_string());
        self
    }

    pub fn with_asset(mut self, asset: &str) -> Self {
        self.conditions.push("asset LIKE ?".to_string());
        self.params.push(format!("%{}%", asset));
        self
    }

    pub fn order_by_severity(mut self) -> Self {
        self.order_by = "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END".to_string();
        self
    }

    pub fn order_by_confidence(mut self) -> Self {
        self.order_by = "confidence DESC".to_string();
        self
    }

    pub fn order_by_date(mut self) -> Self {
        self.order_by = "created_at DESC".to_string();
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    pub fn build(&self) -> (String, &[String]) {
        let query = format!(
            "SELECT id, asset, title, severity, confidence, status FROM findings WHERE {} ORDER BY {} LIMIT {}",
            self.conditions.join(" AND "),
            self.order_by,
            self.limit
        );
        (query, &self.params)
    }
}

impl Default for FindingsQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Query builder for assets
#[allow(dead_code)]
pub struct AssetsQueryBuilder {
    conditions: Vec<String>,
    params: Vec<String>,
    limit: usize,
}

#[allow(dead_code)]
impl AssetsQueryBuilder {
    pub fn new() -> Self {
        Self {
            conditions: vec!["1=1".to_string()],
            params: Vec::new(),
            limit: 100,
        }
    }

    pub fn with_scope(mut self, scope_id: &str) -> Self {
        self.conditions.push("scope_id = ?".to_string());
        self.params.push(scope_id.to_string());
        self
    }

    pub fn with_type(mut self, asset_type: &str) -> Self {
        self.conditions.push("asset_type = ?".to_string());
        self.params.push(asset_type.to_string());
        self
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        self.conditions.push("tags LIKE ?".to_string());
        self.params.push(format!("%\"{}%", tag));
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    pub fn build(&self) -> (String, &[String]) {
        let query = format!(
            "SELECT id, scope_id, asset_type, value, tags, metadata, first_seen, last_seen FROM assets WHERE {} LIMIT {}",
            self.conditions.join(" AND "),
            self.limit
        );
        (query, &self.params)
    }
}

impl Default for AssetsQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_findings_query_builder() {
        let builder = FindingsQueryBuilder::new()
            .with_severity("critical")
            .with_scope("test-scope")
            .order_by_severity()
            .limit(10);

        let (query, params) = builder.build();
        assert!(query.contains("severity = ?"));
        assert!(query.contains("scope_id = ?"));
        assert!(query.contains("LIMIT 10"));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn test_assets_query_builder() {
        let builder = AssetsQueryBuilder::new()
            .with_scope("test-scope")
            .with_type("domain")
            .limit(50);

        let (query, params) = builder.build();
        assert!(query.contains("scope_id = ?"));
        assert!(query.contains("asset_type = ?"));
        assert_eq!(params.len(), 2);
    }
}
