//! Application settings and configuration

use super::{config_dir, data_dir, DatabaseConfig, RateLimitConfig, RetryConfig};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Configuration version
    #[serde(default = "default_version")]
    pub version: u32,

    /// Whether the user has acknowledged the authorization requirement
    #[serde(default)]
    pub authorization_acknowledged: bool,

    /// Database configuration
    #[serde(default)]
    pub database: DatabaseConfig,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Retry configuration
    #[serde(default)]
    pub retry: RetryConfig,

    /// Path to policy file
    #[serde(default)]
    pub policy_path: Option<PathBuf>,

    /// Enable verbose logging
    #[serde(default)]
    pub verbose: bool,

    /// User agent string for HTTP requests
    #[serde(default = "default_user_agent")]
    pub user_agent: String,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,

    /// Data directory path (derived, not stored)
    #[serde(skip)]
    data_path: Option<PathBuf>,

    /// Config file path (derived, not stored)  
    #[serde(skip)]
    config_path: Option<PathBuf>,
}

fn default_version() -> u32 {
    1
}

fn default_user_agent() -> String {
    format!("AegisOSINT/{}", env!("CARGO_PKG_VERSION"))
}

fn default_timeout() -> u64 {
    30
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: default_version(),
            authorization_acknowledged: false,
            database: DatabaseConfig::default(),
            rate_limit: RateLimitConfig::default(),
            retry: RetryConfig::default(),
            policy_path: None,
            verbose: false,
            user_agent: default_user_agent(),
            request_timeout_secs: default_timeout(),
            data_path: None,
            config_path: None,
        }
    }
}

impl Config {
    /// Load configuration from disk, creating default if needed
    pub async fn load_or_create() -> Result<Self> {
        let config_path = Self::config_file_path()?;

        if config_path.exists() {
            Self::load_from(&config_path).await
        } else {
            let mut config = Self::default();
            config.initialize_paths()?;
            config.save().await?;
            Ok(config)
        }
    }

    /// Load configuration from a specific path
    pub async fn load_from(path: &PathBuf) -> Result<Self> {
        let content = tokio::fs::read_to_string(path).await?;
        let mut config: Config = serde_yaml::from_str(&content)?;
        config.initialize_paths()?;
        config.config_path = Some(path.clone());
        Ok(config)
    }

    /// Save configuration to disk
    pub async fn save(&self) -> Result<()> {
        let config_path = self.config_path.clone().unwrap_or(Self::config_file_path()?);

        // Ensure directory exists
        if let Some(parent) = config_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let content = serde_yaml::to_string(self)?;
        tokio::fs::write(&config_path, content).await?;

        Ok(())
    }

    /// Get the default config file path
    fn config_file_path() -> Result<PathBuf> {
        Ok(config_dir()?.join("config.yaml"))
    }

    /// Initialize derived paths
    fn initialize_paths(&mut self) -> Result<()> {
        let derived_data_path = data_dir()?;
        self.data_path = Some(derived_data_path.clone());
        self.config_path = Some(Self::config_file_path()?);

        // Set default database path if not specified
        if self.database.connection.is_empty() {
            let db_path = derived_data_path.join("aegis.db");
            self.database.connection = db_path.to_string_lossy().to_string();
        }

        // Ensure data directory exists
        if let Some(ref data_path) = self.data_path {
            std::fs::create_dir_all(data_path)?;
        }

        Ok(())
    }

    /// Get the data directory path
    pub fn data_path(&self) -> Result<&PathBuf> {
        self.data_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Config data path not initialized"))
    }

    /// Get the database connection string
    pub fn database_url(&self) -> &str {
        &self.database.connection
    }

    /// Check if using PostgreSQL
    pub fn is_postgres(&self) -> bool {
        self.database.db_type == "postgres"
    }

    /// Get HTTP client configuration
    pub fn http_client_config(&self) -> HttpClientConfig {
        HttpClientConfig {
            user_agent: self.user_agent.clone(),
            timeout_secs: self.request_timeout_secs,
            max_retries: self.retry.max_attempts,
        }
    }
}

/// HTTP client configuration
#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    pub user_agent: String,
    pub timeout_secs: u64,
    pub max_retries: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.version, 1);
        assert!(!config.authorization_acknowledged);
        assert_eq!(config.database.db_type, "sqlite");
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.version, config.version);
    }
}
