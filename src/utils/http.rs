//! HTTP client utilities

use anyhow::Result;
use std::time::Duration;

/// Configured HTTP client
#[allow(dead_code)]
pub struct HttpClient {
    inner: reqwest::Client,
    user_agent: String,
}

impl HttpClient {
    /// Create a new HTTP client
    pub fn new(user_agent: &str, timeout_secs: u64) -> Result<Self> {
        let inner = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent(user_agent)
            .danger_accept_invalid_certs(false)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;

        Ok(Self {
            inner,
            user_agent: user_agent.to_string(),
        })
    }

    /// Get request
    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        Ok(self.inner.get(url).send().await?)
    }

    /// Head request
    pub async fn head(&self, url: &str) -> Result<reqwest::Response> {
        Ok(self.inner.head(url).send().await?)
    }

    /// Get the inner client
    pub fn inner(&self) -> &reqwest::Client {
        &self.inner
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        let user_agent = format!("AegisOSINT/{}", env!("CARGO_PKG_VERSION"));
        Self::new(&user_agent, 30).unwrap_or_else(|_| Self {
            inner: reqwest::Client::new(),
            user_agent,
        })
    }
}
