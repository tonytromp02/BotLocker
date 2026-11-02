use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::behavior::{is_asset_path, is_html_path, BehaviorTracker, ClientStats};
use crate::challenge::{self, cookie_value, keyed_digest};
use crate::config::{Config, ConfigError};
use crate::maze;
use crate::report::{self, Verdict};
use crate::request::NormalizedRequest;
use crate::scoring::{decide, Action, Score};
use crate::signals::{default_signals, Hit, Signal};
use crate::{PASS_COOKIE, REPORT_PATH};

/// Clients flagged as automated are tracked up to this many, then pruned.
const MAX_FLAGGED: usize = 100_000;

/// IP -> (expiry in Unix seconds, the flags that fired).
type FlaggedClients = HashMap<IpAddr, (u64, Vec<String>)>;

/// Why a request got the action it did. Logged for every decision.
#[derive(Debug, Clone, PartialEq)]
pub enum Reason {
    KillSwitch,
    VerifiedCrawler(String),
    /// The client already holds a valid pass cookie.
    ValidPass,
    /// Requested a path under the maze prefix. No human reaches these.
    Honeypot,
    /// The browser report flagged automation (WebDriver, headless, or zero-size window).
    Automated,
    Scored,
}

impl Reason {
    /// Short, stable name for logs and the dashboard.
    pub fn label(&self) -> String {
        match self {
            Reason::KillSwitch => "kill_switch".to_string(),
            Reason::VerifiedCrawler(name) => format!("verified:{name}"),
            Reason::ValidPass => "valid_pass".to_string(),
            Reason::Honeypot => "honeypot".to_string(),
            Reason::Automated => "automated".to_string(),
            Reason::Scored => "scored".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Classification {
    pub action: Action,
    pub reason: Reason,
    pub score: Score,
    /// Human-readable lines that explain the decision.
    pub evidence: Vec<String>,
}

pub struct Engine {
    cfg: Config,
    secret: Vec<u8>,
    signals: Vec<Box<dyn Signal>>,
    behavior: Arc<Mutex<BehaviorTracker>>,
    /// IP -> expiry time (Unix seconds) for clients whose browser report flagged automation.
    automated: Arc<Mutex<FlaggedClients>>,
}

impl Engine {
    /// `secret` signs pass tokens and maze seeds. Require at least 32 bytes.
    pub fn new(cfg: Config, secret: Vec<u8>) -> Result<Self, ConfigError> {
        if secret.len() < 32 {
            return Err(ConfigError::Invalid(
                "secret must be at least 32 bytes".to_string(),
            ));
        }
        let behavior = Arc::new(Mutex::new(BehaviorTracker::new(cfg.behavior.window_secs)));
        Ok(Self {
            cfg,
            secret,
            signals: default_signals(),
            behavior,
            automated: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Builds an engine for a new config. The behavior counters and the flagged-browser
    /// list move to the new engine, so a settings change does not reset them.
    pub fn reconfigure(&self, cfg: Config) -> Result<Self, ConfigError> {
        let mut next = Engine::new(cfg, self.secret.clone())?;
        next.behavior = Arc::clone(&self.behavior);
        next.automated = Arc::clone(&self.automated);
        Ok(next)
    }

    /// Decides what to do with one request. `now` is Unix seconds.
    pub fn classify(&self, req: &NormalizedRequest, now: u64) -> Classification {
        if self.cfg.kill_switch {
            return self.result(Action::Proxy, Reason::KillSwitch, vec!["kill switch is on; traffic passes through".to_string()]);
        }

        // Good crawlers bypass everything, including the honeypot. A spoofed
        // Googlebot UA from the wrong IP doesn't match.
        if let Some(name) = self.verified_crawler(req) {
            return self.result(Action::Proxy, Reason::VerifiedCrawler(name.clone()), vec![format!("user agent and IP match verified crawler {name}")]);
        }

        if is_maze_path(&self.cfg.maze_prefix, &req.path) {
            return self.result(Action::Trap, Reason::Honeypot, vec!["requested a path under the maze prefix; no human reaches these".to_string()]);
        }

        // A browser report that flagged automation traps the client for the
        // pass lifetime, even if it still holds a cookie from before.
        if self.is_automated(req.client_ip, now) {
            return self.result(Action::Trap, Reason::Automated, self.automated_evidence(req.client_ip));
        }

        let stats = self.track(req, now);

        if let Some(token) = req
            .header("cookie")
            .and_then(|c| cookie_value(c, PASS_COOKIE))
        {
            if challenge::verify_pass(&self.secret, req.client_ip, token, now) {
                return self.result(Action::Proxy, Reason::ValidPass, vec!["valid pass cookie".to_string()]);
            }
        }

        let score = self.score(req, &stats);
        let action = decide(&score, &self.cfg);
        self.scored(action, score)
    }

    /// HTML for a trap page at `path`.
    pub fn maze_html(&self, path: &str) -> String {
        maze::render(&self.secret, path, self.cfg.max_trap_bytes)
    }

    /// Challenge page for `ip`. The browser reports its signals, and on success
    /// is sent to `next`.
    pub fn challenge_html(&self, ip: IpAddr, now: u64, next: Option<&str>) -> String {
        let token = challenge::issue_challenge(&self.secret, ip, now);
        let next = challenge::safe_next(next);
        challenge::page(&token, self.cfg.pass_ttl_secs, &next, REPORT_PATH)
    }

    /// Handles a browser report from the challenge page. Returns the JSON body.
    pub fn report(&self, ip: IpAddr, now: u64, query: &str) -> String {
        let verdict = report::evaluate(&self.secret, ip, now, query, self.cfg.pass_ttl_secs);
        match verdict {
            Verdict::Pass(token) => serde_json::json!({
                "ok": true,
                "token": token,
            })
            .to_string(),
            Verdict::Automated(flags) => {
                self.flag_automated(ip, now, flags);
                serde_json::json!({ "ok": false, "automated": true }).to_string()
            }
            Verdict::Fail => serde_json::json!({ "ok": false }).to_string(),
        }
    }

    fn is_automated(&self, ip: IpAddr, now: u64) -> bool {
        let flagged = self.automated.lock().unwrap_or_else(|e| e.into_inner());
        flagged.get(&ip).is_some_and(|(expires, _)| now < *expires)
    }

    fn flag_automated(&self, ip: IpAddr, now: u64, flags: Vec<String>) {
        let mut flagged = self.automated.lock().unwrap_or_else(|e| e.into_inner());
        if flagged.len() >= MAX_FLAGGED {
            flagged.retain(|_, (expires, _)| now < *expires);
        }
        flagged.insert(ip, (now + self.cfg.pass_ttl_secs, flags));
    }

    /// Why this client is trapped, from the browser report that flagged it.
    fn automated_evidence(&self, ip: IpAddr) -> Vec<String> {
        let flagged = self.automated.lock().unwrap_or_else(|e| e.into_inner());
        match flagged.get(&ip) {
            Some((_, flags)) if !flags.is_empty() => flags.clone(),
            _ => vec!["browser report flagged automation".to_string()],
        }
    }

    /// Hidden link to inject into origin HTML. Any visit to it is a honeypot hit.
    pub fn honeypot_link(&self) -> String {
        let digest = hex::encode(keyed_digest(&self.secret, "honeypot"));
        format!("{}{}", self.cfg.maze_prefix, &digest[..12])
    }

    /// `robots.txt` rule that keeps compliant crawlers out of the maze.
    pub fn robots_rule(&self) -> String {
        format!("User-agent: *\nDisallow: {}\n", self.cfg.maze_prefix)
    }

    fn result(&self, action: Action, reason: Reason, evidence: Vec<String>) -> Classification {
        Classification {
            action,
            reason,
            score: Score::default(),
            evidence,
        }
    }

    /// A scored decision. The first line summarizes the threshold, then one line per signal that fired.
    fn scored(&self, action: Action, score: Score) -> Classification {
        let families = score.families();
        let threshold = match action {
            Action::Trap => self.cfg.trap_at,
            _ => self.cfg.challenge_at,
        };
        let mut evidence = vec![format!(
            "score {:.1} (threshold {:.1}, {} signal {})",
            score.total,
            threshold,
            families,
            if families == 1 { "family" } else { "families" }
        )];
        evidence.extend(score.hits.iter().map(|h| format!("{}: {}", h.id, h.evidence)));
        Classification {
            action,
            reason: Reason::Scored,
            score,
            evidence,
        }
    }

    fn verified_crawler(&self, req: &NormalizedRequest) -> Option<String> {
        let ua = req.user_agent().to_ascii_lowercase();
        self.cfg
            .verified_crawlers
            .iter()
            .find(|c| {
                ua.contains(&c.user_agent_contains.to_ascii_lowercase())
                    && c.ip_ranges.iter().any(|net| net.contains(&req.client_ip))
            })
            .map(|c| c.name.clone())
    }

    fn track(&self, req: &NormalizedRequest, now: u64) -> ClientStats {
        let mut tracker: MutexGuard<'_, BehaviorTracker> =
            self.behavior.lock().unwrap_or_else(|e| e.into_inner());
        tracker.record(
            &req.client_ip.to_string(),
            is_html_path(&req.path),
            is_asset_path(&req.path),
            now,
        )
    }

    fn score(&self, req: &NormalizedRequest, stats: &ClientStats) -> Score {
        let mut hits = Vec::new();
        for signal in &self.signals {
            if let Some(evidence) = signal.evaluate(req, stats, &self.cfg) {
                let weight = self
                    .cfg
                    .weights
                    .get(signal.id())
                    .copied()
                    .unwrap_or_else(|| signal.default_weight());
                hits.push(Hit {
                    id: signal.id(),
                    family: signal.family(),
                    weight,
                    evidence,
                });
            }
        }
        // fold, not sum: an empty f64 sum is -0.0, which logs oddly.
        let total = hits.iter().fold(0.0, |acc, h| acc + h.weight);
        Score { total, hits }
    }
}

fn is_maze_path(prefix: &str, path: &str) -> bool {
    path == prefix.trim_end_matches('/') || path.starts_with(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
    const NOW: u64 = 1_700_000_000;

    fn engine(extra: &str) -> Engine {
        let text = format!(
            "origin = \"https://origin.example\"\nmaze_prefix = \"/maze/\"\n{extra}"
        );
        Engine::new(Config::from_toml(&text).unwrap(), SECRET.to_vec()).unwrap()
    }

    fn req(path: &str, headers: &[(&str, &str)]) -> NormalizedRequest {
        NormalizedRequest {
            method: "GET".into(),
            path: path.into(),
            query: None,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            client_ip: "203.0.113.9".parse().unwrap(),
            asn: None,
            tls_fingerprint: None,
        }
    }

    const BROWSER: &[(&str, &str)] = &[
        ("user-agent", "Mozilla/5.0 (Macintosh) Chrome/120.0 Safari/537.36"),
        ("accept", "text/html"),
        ("accept-language", "en-US"),
        ("sec-fetch-site", "none"),
    ];

    #[test]
    fn browser_is_proxied() {
        let e = engine("");
        let c = e.classify(&req("/", BROWSER), NOW);
        assert_eq!(c.action, Action::Proxy);
        assert_eq!(c.reason, Reason::Scored);
    }

    #[test]
    fn maze_prefix_is_always_trapped() {
        let e = engine("");
        // Even with a browser profile, the honeypot wins.
        assert_eq!(e.classify(&req("/maze/x", BROWSER), NOW).action, Action::Trap);
        assert_eq!(e.classify(&req("/maze", BROWSER), NOW).action, Action::Trap);
    }

    #[test]
    fn scraper_ua_without_browser_headers_is_challenged_not_trapped() {
        let e = engine("");
        // bot_ua (4.0, client) + accept-language missing (1.5, headers) = 5.5
        let c = e.classify(
            &req("/", &[("user-agent", "python-requests/2.31"), ("accept", "*/*")]),
            NOW,
        );
        assert_eq!(c.action, Action::Challenge);
    }

    #[test]
    fn scraper_on_hosting_asn_is_trapped() {
        let e = engine("hosting_asns = [64500]\n");
        let mut r = req("/", &[("user-agent", "python-requests/2.31")]);
        r.asn = Some(64500);
        // bot_ua 4.0 + asn 2.0 + accept-language 1.5 = 7.5 across 3 families
        assert_eq!(e.classify(&r, NOW).action, Action::Trap);
    }

    #[test]
    fn verified_crawler_bypasses_scoring() {
        let e = engine(
            "[[verified_crawlers]]\nname = \"googlebot\"\nuser_agent_contains = \"Googlebot\"\nip_ranges = [\"203.0.113.0/24\"]\n",
        );
        let c = e.classify(&req("/", &[("user-agent", "Googlebot/2.1 python-requests")]), NOW);
        assert_eq!(c.action, Action::Proxy);
        assert_eq!(c.reason, Reason::VerifiedCrawler("googlebot".into()));
    }

    #[test]
    fn spoofed_crawler_from_wrong_ip_is_not_allowlisted() {
        let e = engine(
            "[[verified_crawlers]]\nname = \"googlebot\"\nuser_agent_contains = \"Googlebot\"\nip_ranges = [\"198.51.100.0/24\"]\n",
        );
        let c = e.classify(&req("/", &[("user-agent", "Googlebot/2.1 python-requests")]), NOW);
        assert_ne!(c.reason, Reason::VerifiedCrawler("googlebot".into()));
    }

    #[test]
    fn kill_switch_proxies_everything() {
        let e = engine("kill_switch = true\n");
        let c = e.classify(&req("/maze/x", &[("user-agent", "curl/8.0")]), NOW);
        assert_eq!(c.action, Action::Proxy);
        assert_eq!(c.reason, Reason::KillSwitch);
    }

    #[test]
    fn valid_pass_cookie_proxies_a_challenged_client() {
        let e = engine("");
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let token = challenge::issue_pass(SECRET, ip, NOW, 3600);
        let mut r = req("/", &[("user-agent", "python-requests/2.31")]);
        r.headers.push(("cookie".into(), format!("{PASS_COOKIE}={token}")));
        let c = e.classify(&r, NOW);
        assert_eq!(c.action, Action::Proxy);
        assert_eq!(c.reason, Reason::ValidPass);
    }

    #[test]
    fn honeypot_link_points_inside_maze() {
        let e = engine("");
        assert!(e.honeypot_link().starts_with("/maze/"));
        assert!(e.robots_rule().contains("Disallow: /maze/"));
        assert!(e.challenge_html(
            "203.0.113.9".parse().unwrap(),
            NOW,
            Some("/articles/x")
        )
        .contains("var NEXT = \"/articles/x\";"));
    }

    #[test]
    fn reconfigure_keeps_flagged_browsers() {
        let e = engine("");
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let t = challenge_token(&e, "203.0.113.9");
        e.report(ip, NOW, &format!("t={t}&w=1&h=0&z=0"));
        let e = e.reconfigure(Config::from_toml("origin = \"https://origin.example\"\nmaze_prefix = \"/maze/\"\nchallenge_at = 4.0\n").unwrap()).unwrap();
        assert_eq!(e.config().challenge_at, 4.0);
        let c = e.classify(&req("/", BROWSER), NOW + 5);
        assert_eq!(c.reason, Reason::Automated);
    }

    #[test]
    fn trap_decisions_explain_themselves() {
        let e = engine("hosting_asns = [64500]\n");
        let mut r = req("/", &[("user-agent", "python-requests/2.31")]);
        r.asn = Some(64500);
        let c = e.classify(&r, NOW);
        assert_eq!(c.action, Action::Trap);
        assert_eq!(c.reason, Reason::Scored);
        assert!(c.evidence[0].starts_with("score 8.5 (threshold 6.0, 3 signal families)"), "{:?}", c.evidence);
        assert!(c.evidence.iter().any(|l| l.starts_with("client.bot_ua")));
        assert!(c.evidence.iter().any(|l| l.starts_with("network.hosting_asn")));
    }

    fn challenge_token(e: &Engine, ip: &str) -> String {
        let html = e.challenge_html(ip.parse().unwrap(), NOW, Some("/"));
        let start = html.find("var TOKEN = \"").unwrap() + "var TOKEN = \"".len();
        html[start..].split('"').next().unwrap().to_string()
    }

    #[test]
    fn clean_browser_report_earns_a_pass_cookie() {
        let e = engine("");
        let t = challenge_token(&e, "203.0.113.9");
        let body = e.report("203.0.113.9".parse().unwrap(), NOW, &format!("t={t}&w=0&h=0&z=0"));
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["ok"], true);
        assert!(v["token"].as_str().unwrap().contains('.'));
    }

    #[test]
    fn flagged_browser_is_trapped_even_with_a_pass_cookie() {
        let e = engine("");
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let t = challenge_token(&e, "203.0.113.9");
        let body = e.report(ip, NOW, &format!("t={t}&w=1&h=0&z=0"));
        assert!(body.contains("\"automated\":true"));

        // Even a valid pass issued earlier doesn't help while the flag is active.
        let pass = challenge::issue_pass(SECRET, ip, NOW, 7200);
        let mut r = req("/", &[("user-agent", "Mozilla/5.0 Chrome/120.0")]);
        r.headers.push(("cookie".into(), format!("{PASS_COOKIE}={pass}")));
        let c = e.classify(&r, NOW + 10);
        assert_eq!(c.action, Action::Trap);
        assert_eq!(c.reason, Reason::Automated);

        // After the flag expires, the pass works again.
        let c = e.classify(&r, NOW + 3600 + 1);
        assert_eq!(c.reason, Reason::ValidPass);
    }

    #[test]
    fn report_without_a_valid_token_does_not_flag_or_pass() {
        let e = engine("");
        let body = e.report("203.0.113.9".parse().unwrap(), NOW, "t=1.dead&w=1&h=0&z=0");
        assert_eq!(body, "{\"ok\":false}");
        let c = e.classify(&req("/", BROWSER), NOW);
        assert_ne!(c.reason, Reason::Automated);
    }

    #[test]
    fn short_secret_is_rejected() {
        let cfg = Config::from_toml("origin = \"https://o.example\"\nmaze_prefix = \"/maze/\"\n").unwrap();
        assert!(Engine::new(cfg, b"short".to_vec()).is_err());
    }
}
