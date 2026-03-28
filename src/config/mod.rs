//! Configuration management module

mod settings;

pub use settings::Config;

use anyhow::Result;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Get the application data directory
pub fn data_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("io", "aegis", "aegis-osint")
        .ok_or_else(|| anyhow::anyhow!("Could not determine application directories"))?;

    Ok(dirs.data_dir().to_path_buf())
}

/// Get the application config directory
pub fn config_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("io", "aegis", "aegis-osint")
        .ok_or_else(|| anyhow::anyhow!("Could not determine application directories"))?;

    Ok(dirs.config_dir().to_path_buf())
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database type (sqlite or postgres)
    #[serde(default = "default_db_type")]
    pub db_type: String,

    /// Database path (for SQLite) or connection string (for Postgres)
    #[serde(default)]
    pub connection: String,

    /// Maximum connections in pool
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

fn default_db_type() -> String {
    "sqlite".to_string()
}

fn default_max_connections() -> u32 {
    5
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            db_type: default_db_type(),
            connection: String::new(),
            max_connections: default_max_connections(),
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per second
    #[serde(default = "default_rps")]
    pub requests_per_second: u32,

    /// Burst size
    #[serde(default = "default_burst")]
    pub burst_size: u32,
}

fn default_rps() -> u32 {
    10
}

fn default_burst() -> u32 {
    20
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: default_rps(),
            burst_size: default_burst(),
        }
    }
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    #[serde(default = "default_max_retries")]
    pub max_attempts: u32,

    /// Initial backoff in milliseconds
    #[serde(default = "default_backoff")]
    pub backoff_ms: u64,

    /// Maximum backoff in milliseconds
    #[serde(default = "default_max_backoff")]
    pub max_backoff_ms: u64,
}

fn default_max_retries() -> u32 {
    3
}

fn default_backoff() -> u64 {
    1000
}

fn default_max_backoff() -> u64 {
    30000
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_retries(),
            backoff_ms: default_backoff(),
            max_backoff_ms: default_max_backoff(),
        }
    }
}
