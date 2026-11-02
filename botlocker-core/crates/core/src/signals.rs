//! Request-level detection signals. Each signal either fires with evidence
//! or stays silent. Signals that can't be evaluated on a platform stay silent,
//! so missing data is never treated as suspicious.

use crate::behavior::ClientStats;
use crate::config::Config;
use crate::request::NormalizedRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    Headers,
    Client,
    Network,
    Fingerprint,
    Behavior,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub id: &'static str,
    pub family: Family,
    pub weight: f64,
    pub evidence: String,
}

pub trait Signal: Send + Sync {
    fn id(&self) -> &'static str;
    fn family(&self) -> Family;
    fn default_weight(&self) -> f64;
    /// Returns evidence when the signal fires.
    fn evaluate(&self, req: &NormalizedRequest, stats: &ClientStats, cfg: &Config) -> Option<String>;
}

pub fn default_signals() -> Vec<Box<dyn Signal>> {
    vec![
        Box::new(MissingHeader {
            id: "headers.accept_language",
            header: "accept-language",
            weight: 1.5,
        }),
        Box::new(MissingHeader {
            id: "headers.accept",
            header: "accept",
            weight: 1.0,
        }),
        Box::new(BrowserWithoutFetchMetadata),
        Box::new(EmptyUserAgent),
        Box::new(BotUserAgent),
        Box::new(HostingAsn),
        Box::new(KnownBadFingerprint),
        Box::new(HighRate),
        Box::new(NoAssets),
    ]
}

pub struct MissingHeader {
    pub id: &'static str,
    pub header: &'static str,
    pub weight: f64,
}

impl Signal for MissingHeader {
    fn id(&self) -> &'static str {
        self.id
    }
    fn family(&self) -> Family {
        Family::Headers
    }
    fn default_weight(&self) -> f64 {
        self.weight
    }
    fn evaluate(&self, req: &NormalizedRequest, _: &ClientStats, _: &Config) -> Option<String> {
        req.header(self.header)
            .is_none()
            .then(|| format!("no {} header", self.header))
    }
}

/// A Chrome user agent always sends Sec-Fetch-* metadata. Its absence means the
/// UA is spoofed.
pub struct BrowserWithoutFetchMetadata;

impl Signal for BrowserWithoutFetchMetadata {
    fn id(&self) -> &'static str {
        "headers.fetch_metadata"
    }
    fn family(&self) -> Family {
        Family::Headers
    }
    fn default_weight(&self) -> f64 {
        2.0
    }
    fn evaluate(&self, req: &NormalizedRequest, _: &ClientStats, _: &Config) -> Option<String> {
        let claims_chrome = req.user_agent().contains("Chrome/");
        (claims_chrome && req.header("sec-fetch-site").is_none())
            .then(|| "Chrome user agent without Sec-Fetch-Site".to_string())
    }
}

pub struct EmptyUserAgent;

impl Signal for EmptyUserAgent {
    fn id(&self) -> &'static str {
        "client.empty_ua"
    }
    fn family(&self) -> Family {
        Family::Client
    }
    fn default_weight(&self) -> f64 {
        3.0
    }
    fn evaluate(&self, req: &NormalizedRequest, _: &ClientStats, _: &Config) -> Option<String> {
        req.user_agent()
            .trim()
            .is_empty()
            .then(|| "empty User-Agent".to_string())
    }
}

pub struct BotUserAgent;

impl Signal for BotUserAgent {
    fn id(&self) -> &'static str {
        "client.bot_ua"
    }
    fn family(&self) -> Family {
        Family::Client
    }
    fn default_weight(&self) -> f64 {
        4.0
    }
    fn evaluate(&self, req: &NormalizedRequest, _: &ClientStats, cfg: &Config) -> Option<String> {
        let ua = req.user_agent().to_ascii_lowercase();
        cfg.bad_user_agents
            .iter()
            .find(|needle| ua.contains(needle.as_str()))
            .map(|needle| format!("User-Agent matches known scraper \"{needle}\""))
    }
}

pub struct HostingAsn;

impl Signal for HostingAsn {
    fn id(&self) -> &'static str {
        "network.hosting_asn"
    }
    fn family(&self) -> Family {
        Family::Network
    }
    fn default_weight(&self) -> f64 {
        2.0
    }
    fn evaluate(&self, req: &NormalizedRequest, _: &ClientStats, cfg: &Config) -> Option<String> {
        let asn = req.asn?;
        cfg.hosting_asns
            .contains(&asn)
            .then(|| format!("client in hosting ASN {asn}"))
    }
}

pub struct KnownBadFingerprint;

impl Signal for KnownBadFingerprint {
    fn id(&self) -> &'static str {
        "fingerprint.known_bad"
    }
    fn family(&self) -> Family {
        Family::Fingerprint
    }
    fn default_weight(&self) -> f64 {
        5.0
    }
    fn evaluate(&self, req: &NormalizedRequest, _: &ClientStats, cfg: &Config) -> Option<String> {
        let fp = req.tls_fingerprint.as_deref()?;
        cfg.bad_fingerprints
            .iter()
            .any(|bad| bad == fp)
            .then(|| format!("TLS fingerprint {fp} is on the scraper list"))
    }
}

pub struct HighRate;

impl Signal for HighRate {
    fn id(&self) -> &'static str {
        "behavior.rate"
    }
    fn family(&self) -> Family {
        Family::Behavior
    }
    fn default_weight(&self) -> f64 {
        3.0
    }
    fn evaluate(&self, _: &NormalizedRequest, stats: &ClientStats, cfg: &Config) -> Option<String> {
        (stats.requests > cfg.behavior.max_requests).then(|| {
            format!(
                "{} requests in {}s window (limit {})",
                stats.requests, cfg.behavior.window_secs, cfg.behavior.max_requests
            )
        })
    }
}

/// Real browsers load CSS, JS and images with each page. Crawlers usually don't.
pub struct NoAssets;

impl Signal for NoAssets {
    fn id(&self) -> &'static str {
        "behavior.no_assets"
    }
    fn family(&self) -> Family {
        Family::Behavior
    }
    fn default_weight(&self) -> f64 {
        2.0
    }
    fn evaluate(&self, _: &NormalizedRequest, stats: &ClientStats, cfg: &Config) -> Option<String> {
        (stats.html_requests >= cfg.behavior.min_html_for_asset_check && stats.asset_requests == 0)
            .then(|| format!("{} page views and no asset requests", stats.html_requests))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavior::ClientStats;

    fn cfg() -> Config {
        Config::from_toml(
            r#"
            origin = "https://origin.example"
            maze_prefix = "/maze/"
            "#,
        )
        .unwrap()
    }

    fn req(headers: &[(&str, &str)]) -> NormalizedRequest {
        NormalizedRequest {
            method: "GET".into(),
            path: "/".into(),
            query: None,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            client_ip: "203.0.113.7".parse().unwrap(),
            asn: None,
            tls_fingerprint: None,
        }
    }

    #[test]
    fn bot_ua_fires_case_insensitively() {
        let r = req(&[("user-agent", "Python-Requests/2.31")]);
        let e = BotUserAgent.evaluate(&r, &ClientStats::default(), &cfg());
        assert!(e.is_some());
    }

    #[test]
    fn chrome_without_fetch_metadata_fires() {
        let r = req(&[("user-agent", "Mozilla/5.0 Chrome/120.0")]);
        assert!(BrowserWithoutFetchMetadata
            .evaluate(&r, &ClientStats::default(), &cfg())
            .is_some());
        let r = req(&[("user-agent", "Mozilla/5.0 Chrome/120.0"), ("sec-fetch-site", "none")]);
        assert!(BrowserWithoutFetchMetadata
            .evaluate(&r, &ClientStats::default(), &cfg())
            .is_none());
    }

    #[test]
    fn unknown_fingerprint_is_silent() {
        let r = req(&[]);
        assert!(KnownBadFingerprint
            .evaluate(&r, &ClientStats::default(), &cfg())
            .is_none());
    }
}
