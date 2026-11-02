use std::collections::HashMap;

/// Upper bound on tracked clients. Keeps memory bounded under IP churn.
const MAX_TRACKED: usize = 100_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientStats {
    pub requests: u32,
    pub html_requests: u32,
    pub asset_requests: u32,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    started: u64,
    stats: ClientStats,
}

/// Fixed-window per-client counters. Keys are opaque strings (the adapter
/// passes a client identifier such as an IP).
pub struct BehaviorTracker {
    window_secs: u64,
    windows: HashMap<String, Window>,
}

impl BehaviorTracker {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            windows: HashMap::new(),
        }
    }

    /// Records one request and returns the client's stats for the current window.
    pub fn record(&mut self, key: &str, is_html: bool, is_asset: bool, now: u64) -> ClientStats {
        if self.windows.len() >= MAX_TRACKED && !self.windows.contains_key(key) {
            self.evict(now);
        }
        let window_secs = self.window_secs;
        let w = self.windows.entry(key.to_string()).or_insert(Window {
            started: now,
            stats: ClientStats::default(),
        });
        if now.saturating_sub(w.started) >= window_secs {
            w.started = now;
            w.stats = ClientStats::default();
        }
        w.stats.requests += 1;
        if is_html {
            w.stats.html_requests += 1;
        }
        if is_asset {
            w.stats.asset_requests += 1;
        }
        w.stats
    }

    fn evict(&mut self, now: u64) {
        let window_secs = self.window_secs;
        self.windows
            .retain(|_, w| now.saturating_sub(w.started) < window_secs);
        if self.windows.len() >= MAX_TRACKED {
            self.windows.clear();
        }
    }
}

const ASSET_EXTENSIONS: &[&str] = &[
    "css", "js", "mjs", "png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "woff", "woff2",
    "ttf", "map",
];

pub fn is_asset_path(path: &str) -> bool {
    last_extension(path).is_some_and(|ext| ASSET_EXTENSIONS.contains(&ext.as_str()))
}

pub fn is_html_path(path: &str) -> bool {
    if is_asset_path(path) {
        return false;
    }
    if path.ends_with('/') {
        return true;
    }
    match last_extension(path) {
        None => true,
        Some(ext) => ext == "html" || ext == "htm",
    }
}

fn last_extension(path: &str) -> Option<String> {
    let segment = path.rsplit('/').next().unwrap_or("");
    let (_, ext) = segment.rsplit_once('.')?;
    Some(ext.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_resets_after_expiry() {
        let mut t = BehaviorTracker::new(60);
        t.record("a", true, false, 0);
        t.record("a", true, false, 10);
        let s = t.record("a", true, false, 30);
        assert_eq!(s.requests, 3);
        let s = t.record("a", true, false, 60);
        assert_eq!(s.requests, 1);
    }

    #[test]
    fn classifies_paths() {
        assert!(is_asset_path("/static/app.CSS"));
        assert!(!is_asset_path("/articles/css-tips"));
        assert!(is_html_path("/"));
        assert!(is_html_path("/articles/hello"));
        assert!(is_html_path("/index.html"));
        assert!(!is_html_path("/logo.png"));
    }
}
