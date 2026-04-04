//! Database storage implementation

use super::models::*;
use crate::config::Config;
use crate::policy::AuditEntry;
use crate::scope::Scope;
use anyhow::Result;
use chrono::Utc;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::str::FromStr;
use std::sync::Arc;

/// SQLite schema
const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS programs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    platform TEXT,
    url TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scopes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    program_id TEXT,
    active INTEGER DEFAULT 1,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (program_id) REFERENCES programs(id)
);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    value TEXT NOT NULL,
    tags TEXT,
    metadata TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    FOREIGN KEY (scope_id) REFERENCES scopes(id)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    program TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    run_type TEXT NOT NULL,
    status TEXT NOT NULL,
    progress INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    metadata TEXT,
    FOREIGN KEY (scope_id) REFERENCES scopes(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL,
    run_id TEXT,
    asset TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    impact TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    status TEXT DEFAULT 'open',
    reproduction TEXT,
    source TEXT NOT NULL,
    method TEXT NOT NULL,
    scope_verified INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (scope_id) REFERENCES scopes(id),
    FOREIGN KEY (run_id) REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    description TEXT NOT NULL,
    source TEXT NOT NULL,
    data TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE TABLE IF NOT EXISTS remediations (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT,
    sla TEXT,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    scope_id TEXT,
    allowed INTEGER NOT NULL,
    reason TEXT NOT NULL,
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS monitors (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL,
    status TEXT NOT NULL,
    interval_minutes INTEGER NOT NULL,
    drift_detection INTEGER NOT NULL,
    brand_monitoring INTEGER NOT NULL,
    leak_monitoring INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    last_check TEXT,
    next_check TEXT,
    check_count INTEGER DEFAULT 0,
    FOREIGN KEY (scope_id) REFERENCES scopes(id)
);

CREATE TABLE IF NOT EXISTS alert_configs (
    scope_id TEXT PRIMARY KEY,
    destination TEXT NOT NULL,
    min_severity TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    FOREIGN KEY (scope_id) REFERENCES scopes(id)
);

CREATE TABLE IF NOT EXISTS asset_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE INDEX IF NOT EXISTS idx_assets_scope ON assets(scope_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_findings_scope ON findings(scope_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
"#;

/// Storage backend
#[derive(Clone)]
pub struct Storage {
    pool: Arc<SqlitePool>,
    #[cfg(feature = "postgres")]
    pg_pool: Option<Arc<sqlx::PgPool>>,
    db_type: String,
}

impl Storage {
    /// Get a reference to the connection pool
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Get the database type
    pub fn db_type(&self) -> &str {
        &self.db_type
    }

    /// Initialize storage with config
    pub async fn initialize(config: &Config) -> Result<Self> {
        #[cfg(feature = "postgres")]
        if config.is_postgres() {
            return Self::initialize_postgres(config).await;
        }

        Self::initialize_sqlite(config).await
    }

    /// Initialize SQLite backend
    async fn initialize_sqlite(config: &Config) -> Result<Self> {
        let db_path = config.database_url();

        // Create directory if needed
        if let Some(parent) = std::path::Path::new(db_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}?mode=rwc", db_path))?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(config.database.max_connections)
            .connect_with(options)
            .await?;

        let storage = Self {
            pool: Arc::new(pool),
            #[cfg(feature = "postgres")]
            pg_pool: None,
            db_type: "sqlite".to_string(),
        };

        // Run migrations
        storage.migrate().await?;

        Ok(storage)
    }

    /// Initialize Postgres backend
    #[cfg(feature = "postgres")]
    async fn initialize_postgres(config: &Config) -> Result<Self> {
        use sqlx::postgres::PgPoolOptions;

        let connection_string = config.database_url();

        let pg_pool = PgPoolOptions::new()
            .max_connections(config.database.max_connections)
            .connect(connection_string)
            .await?;

        // We still need a SQLite pool for compatibility, but it won't be used
        let temp_db = std::env::temp_dir().join("aegis_temp.db");
        let sqlite_options =
            SqliteConnectOptions::from_str(&format!("sqlite://{}?mode=rwc", temp_db.display()))?
                .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(sqlite_options)
            .await?;

        let storage = Self {
            pool: Arc::new(pool),
            pg_pool: Some(Arc::new(pg_pool)),
            db_type: "postgres".to_string(),
        };

        storage.migrate_postgres().await?;

        Ok(storage)
    }

    /// Run SQLite migrations
    async fn migrate(&self) -> Result<()> {
        sqlx::query(SQLITE_SCHEMA)
            .execute(self.pool.as_ref())
            .await?;
        Ok(())
    }

    /// Run Postgres migrations
    #[cfg(feature = "postgres")]
    async fn migrate_postgres(&self) -> Result<()> {
        if let Some(ref pg_pool) = self.pg_pool {
            // Postgres schema with appropriate types
            let pg_schema = r#"
                CREATE TABLE IF NOT EXISTS programs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    platform TEXT,
                    url TEXT,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scopes (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    program_id TEXT REFERENCES programs(id),
                    active BOOLEAN DEFAULT TRUE,
                    data JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL
                );

                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY,
                    scope_id TEXT NOT NULL REFERENCES scopes(id),
                    asset_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    tags JSONB,
                    metadata JSONB,
                    first_seen TIMESTAMPTZ NOT NULL,
                    last_seen TIMESTAMPTZ NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_runs (
                    id TEXT PRIMARY KEY,
                    program TEXT NOT NULL,
                    scope_id TEXT NOT NULL REFERENCES scopes(id),
                    run_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress INTEGER DEFAULT 0,
                    findings_count INTEGER DEFAULT 0,
                    started_at TIMESTAMPTZ NOT NULL,
                    ended_at TIMESTAMPTZ,
                    metadata JSONB
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scope_id TEXT NOT NULL REFERENCES scopes(id),
                    run_id TEXT REFERENCES scan_runs(id),
                    asset TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    impact TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    status TEXT DEFAULT 'open',
                    reproduction TEXT,
                    source TEXT NOT NULL,
                    method TEXT NOT NULL,
                    scope_verified BOOLEAN NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL REFERENCES findings(id),
                    description TEXT NOT NULL,
                    source TEXT NOT NULL,
                    data TEXT,
                    timestamp TIMESTAMPTZ NOT NULL
                );

                CREATE TABLE IF NOT EXISTS remediations (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL REFERENCES findings(id),
                    status TEXT NOT NULL,
                    owner TEXT,
                    sla TEXT,
                    notes TEXT,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT,
                    scope_id TEXT,
                    allowed BOOLEAN NOT NULL,
                    reason TEXT NOT NULL,
                    metadata JSONB
                );

                CREATE TABLE IF NOT EXISTS monitors (
                    id TEXT PRIMARY KEY,
                    scope_id TEXT NOT NULL REFERENCES scopes(id),
                    status TEXT NOT NULL,
                    interval_minutes INTEGER NOT NULL,
                    drift_detection BOOLEAN NOT NULL,
                    brand_monitoring BOOLEAN NOT NULL,
                    leak_monitoring BOOLEAN NOT NULL,
                    started_at TIMESTAMPTZ NOT NULL,
                    last_check TIMESTAMPTZ,
                    next_check TIMESTAMPTZ,
                    check_count INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS alert_configs (
                    scope_id TEXT PRIMARY KEY REFERENCES scopes(id),
                    destination TEXT NOT NULL,
                    min_severity TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT TRUE
                );

                CREATE TABLE IF NOT EXISTS asset_history (
                    id SERIAL PRIMARY KEY,
                    asset_id TEXT NOT NULL REFERENCES assets(id),
                    event_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    timestamp TIMESTAMPTZ NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_assets_scope ON assets(scope_id);
                CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
                CREATE INDEX IF NOT EXISTS idx_findings_scope ON findings(scope_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            "#;

            sqlx::query(pg_schema).execute(pg_pool.as_ref()).await?;
        }
        Ok(())
    }

    /// Health check
    pub async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(self.pool.as_ref()).await?;
        Ok(())
    }

    // ==================== Scope Operations ====================

    /// Save a scope
    pub async fn save_scope(&self, scope: &Scope) -> Result<()> {
        let data = serde_json::to_string(scope)?;
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO scopes (id, name, description, program_id, active, data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                active = excluded.active,
                data = excluded.data,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&scope.id)
        .bind(&scope.name)
        .bind(&scope.description)
        .bind(&scope.program)
        .bind(scope.active)
        .bind(&data)
        .bind(&now)
        .bind(&now)
        .execute(self.pool.as_ref())
        .await?;

        Ok(())
    }

    /// Get a scope by ID
    pub async fn get_scope(&self, id: &str) -> Result<Option<Scope>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT data FROM scopes WHERE id = ?")
            .bind(id)
            .fetch_optional(self.pool.as_ref())
            .await?;

        match row {
            Some((data,)) => Ok(Some(serde_json::from_str(&data)?)),
            None => Ok(None),
        }
    }

    /// List scopes
    pub async fn list_scopes(&self, program: Option<&str>) -> Result<Vec<ScopeSummary>> {
        let query = match program {
            Some(_) => "SELECT id, name, program_id, active, data FROM scopes WHERE program_id = ?",
            None => "SELECT id, name, program_id, active, data FROM scopes",
        };

        let rows: Vec<(String, String, Option<String>, i32, String)> = match program {
            Some(p) => {
                sqlx::query_as(query)
                    .bind(p)
                    .fetch_all(self.pool.as_ref())
                    .await?
            }
            None => sqlx::query_as(query).fetch_all(self.pool.as_ref()).await?,
        };

        let mut summaries = Vec::new();
        for (id, name, program, active_int, data) in rows {
            let scope: Scope = serde_json::from_str(&data)?;
            summaries.push(ScopeSummary {
                id,
                name,
                program,
                active: active_int != 0,
                domain_count: scope.domain_count,
                cidr_count: scope.cidr_count,
                wildcard_count: scope.wildcard_count,
            });
        }

        Ok(summaries)
    }

    /// Delete a scope
    pub async fn delete_scope(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM scopes WHERE id = ?")
            .bind(id)
            .execute(self.pool.as_ref())
            .await?;
        Ok(())
    }

    /// Count scopes
    pub async fn count_scopes(&self) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM scopes")
            .fetch_one(self.pool.as_ref())
            .await?;
        Ok(count)
    }

    // ==================== Scan Run Operations ====================

    /// Create a scan run
    pub async fn create_scan_run(
        &self,
        program: &str,
        scope_id: &str,
        run_type: &str,
    ) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO scan_runs (id, program, scope_id, run_type, status, started_at)
            VALUES (?, ?, ?, ?, 'running', ?)
            "#,
        )
        .bind(&id)
        .bind(program)
        .bind(scope_id)
        .bind(run_type)
        .bind(&now)
        .execute(self.pool.as_ref())
        .await?;

        Ok(id)
    }

    /// Get a scan run
    pub async fn get_scan_run(&self, id: &str) -> Result<Option<ScanRunInfo>> {
        let row: Option<(String, String, String, String, String, i32, i32, String, Option<String>)> =
            sqlx::query_as(
                r#"
                SELECT id, program, scope_id, run_type, status, progress, findings_count, started_at, ended_at
                FROM scan_runs WHERE id = ?
                "#,
            )
            .bind(id)
            .fetch_optional(self.pool.as_ref())
            .await?;

        match row {
            Some((
                id,
                program,
                scope_id,
                run_type,
                status,
                progress,
                findings_count,
                started_at,
                ended_at,
            )) => Ok(Some(ScanRunInfo {
                id,
                program,
                scope_id,
                run_type,
                status,
                progress,
                findings_count,
                started_at,
                ended_at,
            })),
            None => Ok(None),
        }
    }

    /// Update scan status
    pub async fn update_scan_status(&self, id: &str, status: &str) -> Result<()> {
        let now = if status == "completed" || status == "stopped" || status == "failed" {
            Some(Utc::now().to_rfc3339())
        } else {
            None
        };

        sqlx::query(
            "UPDATE scan_runs SET status = ?, ended_at = COALESCE(?, ended_at) WHERE id = ?",
        )
        .bind(status)
        .bind(&now)
        .bind(id)
        .execute(self.pool.as_ref())
        .await?;

        Ok(())
    }

    /// Update scan progress percentage
    pub async fn update_scan_progress(&self, id: &str, progress: i32) -> Result<()> {
        sqlx::query("UPDATE scan_runs SET progress = ? WHERE id = ?")
            .bind(progress.clamp(0, 100))
            .bind(id)
            .execute(self.pool.as_ref())
            .await?;
        Ok(())
    }

    /// Update findings count for a scan run
    pub async fn update_scan_findings_count(&self, id: &str, findings_count: i32) -> Result<()> {
        sqlx::query("UPDATE scan_runs SET findings_count = ? WHERE id = ?")
            .bind(findings_count.max(0))
            .bind(id)
            .execute(self.pool.as_ref())
            .await?;
        Ok(())
    }

    /// List scan runs
    pub async fn list_scan_runs(
        &self,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ScanRunInfo>> {
        let query = if status.is_some() {
            r#"
            SELECT id, program, scope_id, run_type, status, progress, findings_count, started_at, ended_at
            FROM scan_runs
            WHERE status = ?
            ORDER BY started_at DESC
            LIMIT ?
            "#
        } else {
            r#"
            SELECT id, program, scope_id, run_type, status, progress, findings_count, started_at, ended_at
            FROM scan_runs
            ORDER BY started_at DESC
            LIMIT ?
            "#
        };

        let rows: Vec<(
            String,
            String,
            String,
            String,
            String,
            i32,
            i32,
            String,
            Option<String>,
        )> = if let Some(s) = status {
            sqlx::query_as(query)
                .bind(s)
                .bind(limit as i64)
                .fetch_all(self.pool.as_ref())
                .await?
        } else {
            sqlx::query_as(query)
                .bind(limit as i64)
                .fetch_all(self.pool.as_ref())
                .await?
        };

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    program,
                    scope_id,
                    run_type,
                    status,
                    progress,
                    findings_count,
                    started_at,
                    ended_at,
                )| {
                    ScanRunInfo {
                        id,
                        program,
                        scope_id,
                        run_type,
                        status,
                        progress,
                        findings_count,
                        started_at,
                        ended_at,
                    }
                },
            )
            .collect())
    }

    // ==================== Findings Operations ====================

    /// Save a finding
    pub async fn save_finding(&self, finding: &Finding) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO findings (
                id, scope_id, run_id, asset, finding_type, title, description,
                impact, severity, confidence, status, reproduction, source, method,
                scope_verified, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                scope_id = excluded.scope_id,
                run_id = excluded.run_id,
                asset = excluded.asset,
                finding_type = excluded.finding_type,
                title = excluded.title,
                description = excluded.description,
                impact = excluded.impact,
                severity = excluded.severity,
                confidence = excluded.confidence,
                status = excluded.status,
                reproduction = excluded.reproduction,
                source = excluded.source,
                method = excluded.method,
                scope_verified = excluded.scope_verified,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&finding.id)
        .bind(&finding.scope_id)
        .bind(&finding.run_id)
        .bind(&finding.asset)
        .bind(&finding.finding_type)
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(&finding.impact)
        .bind(&finding.severity)
        .bind(finding.confidence)
        .bind(&finding.status)
        .bind(&finding.reproduction)
        .bind(&finding.source)
        .bind(&finding.method)
        .bind(finding.scope_verified)
        .bind(&now)
        .bind(&now)
        .execute(self.pool.as_ref())
        .await?;

        // Save evidence
        for evidence in &finding.evidence {
            self.save_evidence(&finding.id, evidence).await?;
        }

        Ok(())
    }

    /// Save evidence
    async fn save_evidence(&self, finding_id: &str, evidence: &Evidence) -> Result<()> {
        let id = uuid::Uuid::new_v4().to_string();

        sqlx::query(
            r#"
            INSERT INTO evidence (id, finding_id, description, source, data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(finding_id)
        .bind(&evidence.description)
        .bind(&evidence.source)
        .bind(&evidence.data)
        .bind(&evidence.timestamp)
        .execute(self.pool.as_ref())
        .await?;

        Ok(())
    }

    /// Get a finding with evidence
    pub async fn get_finding(&self, id: &str) -> Result<Option<Finding>> {
        // Use sqlx::Row directly to avoid large tuple limitations
        let row = sqlx::query(
            r#"
            SELECT id, scope_id, run_id, asset, finding_type, title, description,
                   impact, severity, confidence, status, reproduction, source, method,
                   scope_verified, created_at, updated_at
            FROM findings WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool.as_ref())
        .await?;

        match row {
            Some(row) => {
                use sqlx::Row;
                let finding_id: String = row.get("id");

                // Get evidence
                let evidence = self.get_evidence_for_finding(&finding_id).await?;

                // Convert scope_verified from INTEGER to bool
                let scope_verified_int: i32 = row.get("scope_verified");

                Ok(Some(Finding {
                    id: row.get("id"),
                    scope_id: row.get("scope_id"),
                    run_id: row.get("run_id"),
                    asset: row.get("asset"),
                    finding_type: row.get("finding_type"),
                    title: row.get("title"),
                    description: row.get("description"),
                    impact: row.get("impact"),
                    severity: row.get("severity"),
                    confidence: row.get("confidence"),
                    status: row.get("status"),
                    reproduction: row.get("reproduction"),
                    source: row.get("source"),
                    method: row.get("method"),
                    scope_verified: scope_verified_int != 0,
                    evidence,
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                }))
            }
            None => Ok(None),
        }
    }

    /// Get evidence for a finding
    async fn get_evidence_for_finding(&self, finding_id: &str) -> Result<Vec<Evidence>> {
        let rows: Vec<(String, String, Option<String>, String)> = sqlx::query_as(
            "SELECT description, source, data, timestamp FROM evidence WHERE finding_id = ?",
        )
        .bind(finding_id)
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(rows
            .into_iter()
            .map(|(description, source, data, timestamp)| Evidence {
                description,
                source,
                data,
                timestamp,
            })
            .collect())
    }

    /// List findings with filters
    pub async fn list_findings(
        &self,
        severity: Option<String>,
        scope: Option<&str>,
        run: Option<&str>,
        status: Option<String>,
        asset: Option<&str>,
        limit: usize,
        sort: &str,
    ) -> Result<Vec<FindingSummary>> {
        let mut query = String::from(
            "SELECT id, asset, title, severity, confidence, status FROM findings WHERE 1=1",
        );
        let mut params: Vec<String> = Vec::new();

        if let Some(ref s) = severity {
            query.push_str(" AND severity = ?");
            params.push(s.clone());
        }
        if let Some(s) = scope {
            query.push_str(" AND scope_id = ?");
            params.push(s.to_string());
        }
        if let Some(r) = run {
            query.push_str(" AND run_id = ?");
            params.push(r.to_string());
        }
        if let Some(ref st) = status {
            query.push_str(" AND status = ?");
            params.push(st.clone());
        }
        if let Some(a) = asset {
            query.push_str(" AND asset LIKE ?");
            params.push(format!("%{}%", a));
        }

        let order = match sort {
            "severity" => "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END",
            "confidence" => "confidence DESC",
            "date" => "created_at DESC",
            _ => "created_at DESC",
        };

        query.push_str(&format!(" ORDER BY {} LIMIT {}", order, limit));

        // Build and execute query dynamically
        let mut q =
            sqlx::query_as::<_, (String, String, String, String, i32, Option<String>)>(&query);
        for param in &params {
            q = q.bind(param);
        }

        let rows = q.fetch_all(self.pool.as_ref()).await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, asset, title, severity, confidence, status)| FindingSummary {
                    id,
                    asset,
                    title,
                    severity,
                    confidence,
                    status,
                },
            )
            .collect())
    }

    /// Update finding status
    pub async fn update_finding_status(
        &self,
        id: &str,
        status: &str,
        notes: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        sqlx::query("UPDATE findings SET status = ?, updated_at = ? WHERE id = ?")
            .bind(status)
            .bind(&now)
            .bind(id)
            .execute(self.pool.as_ref())
            .await?;

        if let Some(notes) = notes {
            // Add to remediation record
            let rem_id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO remediations (id, finding_id, status, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(&rem_id)
            .bind(id)
            .bind(status)
            .bind(notes)
            .bind(&now)
            .bind(&now)
            .execute(self.pool.as_ref())
            .await?;
        }

        Ok(())
    }

    /// Generate remediation queue
    pub async fn generate_remediation_queue(
        &self,
        scope_id: &str,
        with_owners: bool,
        with_sla: bool,
    ) -> Result<Vec<RemediationItem>> {
        let rows: Vec<(String, String, String, String)> = sqlx::query_as(
            r#"
            SELECT f.id, f.title, f.severity, f.asset
            FROM findings f
            WHERE f.scope_id = ? AND f.status = 'open'
            ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
            "#,
        )
        .bind(scope_id)
        .fetch_all(self.pool.as_ref())
        .await?;

        let mut items = Vec::new();
        for (finding_id, title, severity, asset) in rows {
            let (owner, sla) = if with_owners || with_sla {
                let rem: Option<(Option<String>, Option<String>)> = sqlx::query_as(
                    "SELECT owner, sla FROM remediations WHERE finding_id = ? ORDER BY created_at DESC LIMIT 1",
                )
                .bind(&finding_id)
                .fetch_optional(self.pool.as_ref())
                .await?;
                rem.unwrap_or((None, None))
            } else {
                (None, None)
            };

            items.push(RemediationItem {
                finding_id,
                title,
                severity,
                asset,
                owner,
                sla,
            });
        }

        Ok(items)
    }

    // ==================== Asset Operations ====================

    /// Save an asset
    pub async fn save_asset(&self, asset: &Asset) -> Result<()> {
        let tags = serde_json::to_string(&asset.tags)?;
        let metadata = asset
            .metadata
            .as_ref()
            .map(|m| serde_json::to_string(m))
            .transpose()?;

        sqlx::query(
            r#"
            INSERT INTO assets (id, scope_id, asset_type, value, tags, metadata, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                last_seen = excluded.last_seen,
                tags = excluded.tags,
                metadata = excluded.metadata
            "#,
        )
        .bind(&asset.id)
        .bind(&asset.scope_id)
        .bind(&asset.asset_type)
        .bind(&asset.value)
        .bind(&tags)
        .bind(&metadata)
        .bind(&asset.first_seen)
        .bind(&asset.last_seen)
        .execute(self.pool.as_ref())
        .await?;

        Ok(())
    }

    /// Get an asset
    pub async fn get_asset(&self, id: &str) -> Result<Option<Asset>> {
        let row: Option<(String, String, String, String, String, Option<String>, String, String)> =
            sqlx::query_as(
                "SELECT id, scope_id, asset_type, value, tags, metadata, first_seen, last_seen FROM assets WHERE id = ?",
            )
            .bind(id)
            .fetch_optional(self.pool.as_ref())
            .await?;

        match row {
            Some((id, scope_id, asset_type, value, tags, metadata, first_seen, last_seen)) => {
                Ok(Some(Asset {
                    id,
                    scope_id,
                    asset_type,
                    value,
                    tags: serde_json::from_str(&tags)?,
                    metadata: metadata.map(|m| serde_json::from_str(&m)).transpose()?,
                    first_seen,
                    last_seen,
                }))
            }
            None => Ok(None),
        }
    }

    /// List assets
    pub async fn list_assets(
        &self,
        scope: Option<&str>,
        asset_type: Option<&str>,
        tag: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Asset>> {
        let mut query = String::from(
            "SELECT id, scope_id, asset_type, value, tags, metadata, first_seen, last_seen FROM assets WHERE 1=1",
        );

        if scope.is_some() {
            query.push_str(" AND scope_id = ?");
        }
        if asset_type.is_some() {
            query.push_str(" AND asset_type = ?");
        }
        if tag.is_some() {
            query.push_str(" AND tags LIKE ?");
        }

        query.push_str(&format!(" LIMIT {}", limit));

        let mut q = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                Option<String>,
                String,
                String,
            ),
        >(&query);

        if let Some(s) = scope {
            q = q.bind(s);
        }
        if let Some(t) = asset_type {
            q = q.bind(t);
        }
        if let Some(t) = tag {
            q = q.bind(format!("%{}%", t));
        }

        let rows = q.fetch_all(self.pool.as_ref()).await?;

        let mut assets = Vec::new();
        for (id, scope_id, asset_type, value, tags, metadata, first_seen, last_seen) in rows {
            assets.push(Asset {
                id,
                scope_id,
                asset_type,
                value,
                tags: serde_json::from_str(&tags)?,
                metadata: metadata.map(|m| serde_json::from_str(&m)).transpose()?,
                first_seen,
                last_seen,
            });
        }

        Ok(assets)
    }

    /// Get asset diff
    pub async fn get_asset_diff(
        &self,
        scope_id: &str,
        since: &str,
        _until: Option<&str>,
    ) -> Result<AssetDiff> {
        // Parse the since parameter
        let since_date = self.parse_relative_date(since)?;

        // Get assets added since date
        let added: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT id, value, asset_type FROM assets WHERE scope_id = ? AND first_seen > ?",
        )
        .bind(scope_id)
        .bind(&since_date)
        .fetch_all(self.pool.as_ref())
        .await?;

        // For removed/modified we'd need historical tracking
        Ok(AssetDiff {
            added: added
                .into_iter()
                .map(|(id, value, asset_type)| AssetDiffItem {
                    id,
                    value,
                    asset_type,
                })
                .collect(),
            removed: vec![],
            modified: vec![],
        })
    }

    fn parse_relative_date(&self, date_str: &str) -> Result<String> {
        if let Some(days) = date_str.strip_suffix('d') {
            if let Ok(n) = days.parse::<i64>() {
                let dt = Utc::now() - chrono::Duration::days(n);
                return Ok(dt.to_rfc3339());
            }
        }
        // Assume ISO format if not relative
        Ok(date_str.to_string())
    }

    /// Get asset history
    pub async fn get_asset_history(&self, asset_id: &str) -> Result<Vec<AssetHistoryEvent>> {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT event_type, description, timestamp FROM asset_history WHERE asset_id = ? ORDER BY timestamp DESC",
        )
        .bind(asset_id)
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(rows
            .into_iter()
            .map(|(event_type, description, timestamp)| AssetHistoryEvent {
                event_type,
                description,
                timestamp,
            })
            .collect())
    }

    /// Save an asset history event
    pub async fn save_asset_history_event(
        &self,
        asset_id: &str,
        event_type: &str,
        description: &str,
        timestamp: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO asset_history (asset_id, event_type, description, timestamp)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(asset_id)
        .bind(event_type)
        .bind(description)
        .bind(timestamp)
        .execute(self.pool.as_ref())
        .await?;
        Ok(())
    }

    /// Get findings for an asset
    pub async fn get_findings_for_asset(&self, asset_id: &str) -> Result<Vec<FindingSummary>> {
        // Get asset value first
        let asset = self.get_asset(asset_id).await?;
        let asset_value = asset.map(|a| a.value).unwrap_or_default();

        let rows: Vec<(String, String, String, String, i32, Option<String>)> = sqlx::query_as(
            "SELECT id, asset, title, severity, confidence, status FROM findings WHERE asset = ?",
        )
        .bind(&asset_value)
        .fetch_all(self.pool.as_ref())
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, asset, title, severity, confidence, status)| FindingSummary {
                    id,
                    asset,
                    title,
                    severity,
                    confidence,
                    status,
                },
            )
            .collect())
    }

    /// Add tags to asset
    pub async fn add_asset_tags(&self, asset_id: &str, tags: &[String]) -> Result<()> {
        let asset = self.get_asset(asset_id).await?;
        if let Some(mut asset) = asset {
            for tag in tags {
                if !asset.tags.contains(tag) {
                    asset.tags.push(tag.clone());
                }
            }
            self.save_asset(&asset).await?;
        }
        Ok(())
    }

    /// Remove tags from asset
    pub async fn remove_asset_tags(&self, asset_id: &str, tags: &[String]) -> Result<()> {
        let asset = self.get_asset(asset_id).await?;
        if let Some(mut asset) = asset {
            asset.tags.retain(|t| !tags.contains(t));
            self.save_asset(&asset).await?;
        }
        Ok(())
    }

    // ==================== Monitor Operations ====================

    /// List monitors
    pub async fn list_monitors(&self, scope: Option<&str>) -> Result<Vec<MonitorInfo>> {
        let query = match scope {
            Some(_) => {
                "SELECT id, scope_id, status, started_at, last_check, next_check, check_count FROM monitors WHERE scope_id = ?"
            }
            None => {
                "SELECT id, scope_id, status, started_at, last_check, next_check, check_count FROM monitors"
            }
        };

        let rows: Vec<(
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            i32,
        )> = match scope {
            Some(s) => {
                sqlx::query_as(query)
                    .bind(s)
                    .fetch_all(self.pool.as_ref())
                    .await?
            }
            None => sqlx::query_as(query).fetch_all(self.pool.as_ref()).await?,
        };

        Ok(rows
            .into_iter()
            .map(
                |(id, scope_id, status, started_at, last_check, next_check, check_count)| {
                    MonitorInfo {
                        id,
                        scope_id,
                        status,
                        started_at,
                        last_check: last_check.unwrap_or_else(|| "Never".to_string()),
                        next_check: next_check.unwrap_or_else(|| "Pending".to_string()),
                        check_count,
                    }
                },
            )
            .collect())
    }

    /// Update monitor status
    pub async fn update_monitor_status(&self, id: &str, status: &str) -> Result<()> {
        let clear_next_check = status == "stopped" || status == "failed";
        sqlx::query(
            r#"
            UPDATE monitors
            SET status = ?, next_check = CASE WHEN ? THEN NULL ELSE next_check END
            WHERE id = ?
            "#,
        )
        .bind(status)
        .bind(clear_next_check)
        .bind(id)
        .execute(self.pool.as_ref())
        .await?;
        Ok(())
    }

    // ==================== Alert Operations ====================

    /// Get alert config
    pub async fn get_alert_config(&self, scope_id: &str) -> Result<Option<AlertConfig>> {
        let row: Option<(String, String, i32)> = sqlx::query_as(
            "SELECT destination, min_severity, enabled FROM alert_configs WHERE scope_id = ?",
        )
        .bind(scope_id)
        .fetch_optional(self.pool.as_ref())
        .await?;

        Ok(
            row.map(|(destination, min_severity, enabled_int)| AlertConfig {
                destination,
                min_severity,
                enabled: enabled_int != 0,
            }),
        )
    }

    /// Set alert config
    pub async fn set_alert_config(
        &self,
        scope_id: &str,
        destination: &str,
        min_severity: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO alert_configs (scope_id, destination, min_severity, enabled)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(scope_id) DO UPDATE SET
                destination = excluded.destination,
                min_severity = excluded.min_severity
            "#,
        )
        .bind(scope_id)
        .bind(destination)
        .bind(min_severity)
        .execute(self.pool.as_ref())
        .await?;

        Ok(())
    }

    // ==================== Summary Operations ====================

    /// Get attack surface summary
    pub async fn get_attack_surface_summary(
        &self,
        scope_id: &str,
        period: &str,
    ) -> Result<AttackSurfaceSummary> {
        let since = self.parse_relative_date(period)?;

        // Count assets by type
        let (domain_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM assets WHERE scope_id = ? AND asset_type = 'domain'",
        )
        .bind(scope_id)
        .fetch_one(self.pool.as_ref())
        .await?;

        let (subdomain_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM assets WHERE scope_id = ? AND asset_type = 'subdomain'",
        )
        .bind(scope_id)
        .fetch_one(self.pool.as_ref())
        .await?;

        let (ip_count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM assets WHERE scope_id = ? AND asset_type = 'ip'")
                .bind(scope_id)
                .fetch_one(self.pool.as_ref())
                .await?;

        let (service_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM assets WHERE scope_id = ? AND asset_type = 'service'",
        )
        .bind(scope_id)
        .fetch_one(self.pool.as_ref())
        .await?;

        // Count findings by severity
        let (critical_findings,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM findings WHERE scope_id = ? AND severity = 'critical' AND status = 'open'",
        )
        .bind(scope_id)
        .fetch_one(self.pool.as_ref())
        .await?;

        let (high_findings,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM findings WHERE scope_id = ? AND severity = 'high' AND status = 'open'",
        )
        .bind(scope_id)
        .fetch_one(self.pool.as_ref())
        .await?;

        let (medium_findings,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM findings WHERE scope_id = ? AND severity = 'medium' AND status = 'open'",
        )
        .bind(scope_id)
        .fetch_one(self.pool.as_ref())
        .await?;

        let (low_findings,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM findings WHERE scope_id = ? AND severity = 'low' AND status = 'open'",
        )
        .bind(scope_id)
        .fetch_one(self.pool.as_ref())
        .await?;

        // Count changes in period
        let (assets_added,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM assets WHERE scope_id = ? AND first_seen > ?")
                .bind(scope_id)
                .bind(&since)
                .fetch_one(self.pool.as_ref())
                .await?;

        let (assets_removed,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM asset_history h
            JOIN assets a ON a.id = h.asset_id
            WHERE a.scope_id = ? AND h.timestamp > ? AND h.event_type = 'asset_removed'
            "#,
        )
        .bind(scope_id)
        .bind(&since)
        .fetch_one(self.pool.as_ref())
        .await?;

        let (config_changes,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM asset_history h
            JOIN assets a ON a.id = h.asset_id
            WHERE a.scope_id = ?
              AND h.timestamp > ?
              AND h.event_type IN ('dns_change', 'service_change', 'drift_change')
            "#,
        )
        .bind(scope_id)
        .bind(&since)
        .fetch_one(self.pool.as_ref())
        .await?;

        let (cert_changes,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM asset_history h
            JOIN assets a ON a.id = h.asset_id
            WHERE a.scope_id = ? AND h.timestamp > ? AND h.event_type = 'cert_change'
            "#,
        )
        .bind(scope_id)
        .bind(&since)
        .fetch_one(self.pool.as_ref())
        .await?;

        Ok(AttackSurfaceSummary {
            domain_count: domain_count as usize,
            subdomain_count: subdomain_count as usize,
            ip_count: ip_count as usize,
            service_count: service_count as usize,
            critical_findings: critical_findings as usize,
            high_findings: high_findings as usize,
            medium_findings: medium_findings as usize,
            low_findings: low_findings as usize,
            asset_changes: (assets_added + assets_removed) as usize,
            assets_added: assets_added as usize,
            assets_removed: assets_removed as usize,
            config_changes: config_changes as usize,
            cert_changes: cert_changes as usize,
        })
    }

    // ==================== Audit Operations ====================

    /// Log an audit entry
    pub async fn log_audit_entry(&self, entry: &AuditEntry) -> Result<()> {
        let metadata = entry
            .metadata
            .as_ref()
            .map(|m| serde_json::to_string(m))
            .transpose()?;

        sqlx::query(
            r#"
            INSERT INTO audit_log (timestamp, action, target, scope_id, allowed, reason, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(entry.timestamp.to_rfc3339())
        .bind(&entry.action)
        .bind(&entry.target)
        .bind(&entry.scope_id)
        .bind(entry.allowed)
        .bind(&entry.reason)
        .bind(&metadata)
        .execute(self.pool.as_ref())
        .await?;

        Ok(())
    }
}
