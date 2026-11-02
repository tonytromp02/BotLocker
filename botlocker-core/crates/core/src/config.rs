use std::collections::HashMap;
use std::fmt;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum ConfigError {
    Parse(toml::de::Error),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Parse(e) => write!(f, "config parse error: {e}"),
            ConfigError::Invalid(msg) => write!(f, "invalid config: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Origin to protect, e.g. `https://www.example.com`. Only the standalone
    /// binary proxies with it. The nginx build sets its origin in nginx itself
    /// (ORIGIN_URL), so the TOML can leave this out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// Path prefix for trap pages. Must start and end with `/`.
    pub maze_prefix: String,
    #[serde(default = "default_challenge_at")]
    pub challenge_at: f64,
    #[serde(default = "default_trap_at")]
    pub trap_at: f64,
    /// When true, every request is proxied to the origin untouched.
    #[serde(default)]
    pub kill_switch: bool,
    /// Insert a hidden link to the maze into origin HTML.
    #[serde(default = "default_true")]
    pub inject_honeypot: bool,
    /// Delay between trap-page chunks. Zero disables slow drip.
    #[serde(default)]
    pub slow_drip_ms: u64,
    #[serde(default = "default_max_trap_bytes")]
    pub max_trap_bytes: usize,
    /// How long a passed challenge stays valid.
    #[serde(default = "default_pass_ttl")]
    pub pass_ttl_secs: u64,
    /// Seconds between background checks for an edited config file (±20% jitter).
    /// Saves from the dashboard Settings page apply at once, whatever this is.
    #[serde(default = "default_reload_poll")]
    pub reload_poll_secs: u64,
    #[serde(default)]
    pub behavior: BehaviorConfig,
    /// Per-signal weight overrides, keyed by signal id (e.g. `client.bot_ua`).
    #[serde(default)]
    pub weights: HashMap<String, f64>,
    /// Lowercase substrings that identify known scraping clients.
    #[serde(default = "default_bad_user_agents")]
    pub bad_user_agents: Vec<String>,
    #[serde(default)]
    pub hosting_asns: Vec<u32>,
    /// TLS fingerprints (JA3/JA4) known to belong to scrapers.
    #[serde(default)]
    pub bad_fingerprints: Vec<String>,
    /// Good crawlers that bypass scoring. Both the UA and the IP must match.
    #[serde(default)]
    pub verified_crawlers: Vec<VerifiedCrawler>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct BehaviorConfig {
    pub window_secs: u64,
    pub max_requests: u32,
    /// HTML page views in a window before the missing-assets check applies.
    pub min_html_for_asset_check: u32,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            window_secs: 60,
            max_requests: 120,
            min_html_for_asset_check: 5,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedCrawler {
    pub name: String,
    pub user_agent_contains: String,
    pub ip_ranges: Vec<IpNet>,
}

fn default_challenge_at() -> f64 {
    3.0
}
fn default_trap_at() -> f64 {
    6.0
}
fn default_true() -> bool {
    true
}
fn default_max_trap_bytes() -> usize {
    64 * 1024
}
fn default_pass_ttl() -> u64 {
    3600
}
fn default_reload_poll() -> u64 {
    15
}
fn default_bad_user_agents() -> Vec<String> {
    [
        "curl/",
        "wget/",
        "python-requests",
        "python-urllib",
        "aiohttp",
        "scrapy",
        "go-http-client",
        "java/",
        "okhttp",
        "libwww-perl",
        "httpclient",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Config {
    /// Serializes the config as TOML, in a form `from_toml` reads back.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("config serializes to TOML")
    }

    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let mut cfg: Config = toml::from_str(text).map_err(ConfigError::Parse)?;
        cfg.bad_user_agents = cfg
            .bad_user_agents
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Checks the values that the rest of the code relies on.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |msg: &str| Err(ConfigError::Invalid(msg.to_string()));

        if let Some(origin) = &self.origin {
            if !(origin.starts_with("http://") || origin.starts_with("https://")) {
                return invalid("origin must start with http:// or https://");
            }
        }
        if !self.maze_prefix.starts_with('/') || !self.maze_prefix.ends_with('/') || self.maze_prefix.len() < 2 {
            return invalid("maze_prefix must start and end with '/' (e.g. \"/maze/\")");
        }
        if self.challenge_at < 0.0 {
            return invalid("challenge_at must be >= 0");
        }
        if self.trap_at <= self.challenge_at {
            return invalid("trap_at must be greater than challenge_at");
        }
        if self.pass_ttl_secs == 0 {
            return invalid("pass_ttl_secs must be > 0");
        }
        if !(5..=300).contains(&self.reload_poll_secs) {
            return invalid("reload_poll_secs must be between 5 and 300");
        }
        if self.behavior.window_secs == 0 {
            return invalid("behavior.window_secs must be > 0");
        }
        if self.weights.values().any(|w| *w < 0.0) {
            return invalid("weights must be >= 0");
        }
        Ok(())
    }
}

#[cfg(test)]
mod origin_tests {
    use super::*;

    #[test]
    fn origin_is_optional_for_the_nginx_build() {
        let cfg = Config::from_toml("maze_prefix = \"/maze/\"\n").unwrap();
        assert!(cfg.origin.is_none());
        assert!(!cfg.to_toml().contains("origin"));
    }

    #[test]
    fn origin_when_given_must_be_http() {
        assert!(Config::from_toml("origin = \"ftp://x\"\nmaze_prefix = \"/maze/\"\n").is_err());
        assert!(Config::from_toml("origin = \"https://x\"\nmaze_prefix = \"/maze/\"\n").is_ok());
    }
}
