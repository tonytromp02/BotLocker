//! Local dashboard: an in-memory record of recent decisions, plus an admin
//! server that serves a single-page UI and a small JSON API.
//!
//! The admin server is for the operator only. It exposes visitor IPs and user
//! agents, so it only accepts loopback addresses and loopback `Host` headers.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use axum::extract::{Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use botlocker_core::{Action, Classification, NormalizedRequest};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::settings::{diff, parse_update, read_config, request_reload, to_json, write_config, SettingsCtx};
use crate::unix_now;

/// The header that carries the API key.
pub const API_KEY_HEADER: &str = "x-botlocker-key";

const MAX_EVENTS: usize = 500;
const MAX_AUDIT: usize = 200;
const MAX_UA_CHARS: usize = 200;
const ACTIVE_WINDOW_SECS: u64 = 300;
const GRAPH_CLIENTS: usize = 100;


#[derive(Default)]
struct Totals {
    requests: u64,
    proxied: u64,
    challenged: u64,
    trapped: u64,
}

struct Event {
    ts: u64,
    ip: String,
    user_agent: String,
    method: String,
    path: String,
    action: Action,
    reason: String,
    score: f64,
    evidence: Vec<String>,
}

/// One decision, as the store needs it. Built from the proxy's own classification or from a log line.
pub struct Decision {
    pub ip: String,
    pub user_agent: String,
    pub method: String,
    pub path: String,
    pub action: Action,
    pub reason: String,
    pub score: f64,
    pub evidence: Vec<String>,
}

#[derive(Default)]
struct Client {
    ip: String,
    user_agent: String,
    first_seen: u64,
    last_seen: u64,
    requests: u64,
    proxied: u64,
    challenged: u64,
    trapped: u64,
    max_score: f64,
    top_evidence: Vec<String>,
    /// How many times each trap reason fired for this client.
    trap_reasons: BTreeMap<String, u64>,
    /// Reason and evidence of the most recent trap. This is why the client was captured.
    captured_because: String,
    captured_evidence: Vec<String>,
}

#[derive(Default)]
struct Inner {
    totals: Totals,
    events: VecDeque<Event>,
    clients: HashMap<String, Client>,
    audit: VecDeque<Value>,
}

/// Shared record of decisions. The proxy writes to it and the admin server reads it.
#[derive(Default)]
pub struct Store {
    inner: Mutex<Inner>,
}

impl Store {
    /// Records a decision made by the proxy itself.
    pub fn record(&self, req: &NormalizedRequest, class: &Classification, now: u64) {
        self.push(
            now,
            Decision {
                ip: req.client_ip.to_string(),
                user_agent: req.user_agent().to_string(),
                method: req.method.clone(),
                path: req.path.clone(),
                action: class.action,
                reason: class.reason.label(),
                score: class.score.total,
                evidence: class.evidence.clone(),
            },
        );
    }

    /// Records one decision. Used by the proxy and by the nginx log feed.
    pub fn push(&self, now: u64, d: Decision) {
        let ip = d.ip;
        let user_agent = truncate(&d.user_agent, MAX_UA_CHARS);

        let event = Event {
            ts: now,
            ip: ip.clone(),
            user_agent: user_agent.clone(),
            method: d.method,
            path: d.path,
            action: d.action,
            reason: d.reason.clone(),
            score: d.score,
            evidence: d.evidence.clone(),
        };

        let mut guard = self.lock();
        let inner = &mut *guard;

        inner.totals.requests += 1;
        match d.action {
            Action::Proxy => inner.totals.proxied += 1,
            Action::Challenge => inner.totals.challenged += 1,
            Action::Trap => inner.totals.trapped += 1,
        }

        let client = inner.clients.entry(ip.clone()).or_insert_with(|| Client {
            ip: ip.clone(),
            first_seen: now,
            ..Client::default()
        });
        client.user_agent = user_agent;
        client.last_seen = now;
        client.requests += 1;
        match d.action {
            Action::Proxy => client.proxied += 1,
            Action::Challenge => client.challenged += 1,
            Action::Trap => {
                client.trapped += 1;
                *client.trap_reasons.entry(d.reason.clone()).or_insert(0) += 1;
                client.captured_because = d.reason.clone();
                client.captured_evidence = d.evidence.clone();
            }
        }
        if d.score > client.max_score || client.top_evidence.is_empty() {
            client.max_score = d.score;
            client.top_evidence = d.evidence;
        }

        if inner.events.len() == MAX_EVENTS {
            inner.events.pop_front();
        }
        inner.events.push_back(event);
    }

    pub fn summary(&self, now: u64) -> Value {
        let g = self.lock();
        let captured = g.clients.values().filter(|c| c.trapped > 0).count();
        let active = g
            .clients
            .values()
            .filter(|c| now.saturating_sub(c.last_seen) <= ACTIVE_WINDOW_SECS)
            .count();
        json!({
            "requests": g.totals.requests,
            "proxied": g.totals.proxied,
            "challenged": g.totals.challenged,
            "trapped": g.totals.trapped,
            "clients": g.clients.len(),
            "captured": captured,
            "active": active,
        })
    }

    pub fn clients(&self, now: u64) -> Value {
        let g = self.lock();
        let mut list: Vec<&Client> = g.clients.values().collect();
        list.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.ip.cmp(&b.ip)));
        Value::Array(list.iter().map(|c| client_json(c, now)).collect())
    }

    /// Newest first.
    pub fn events(&self, limit: usize) -> Value {
        let g = self.lock();
        Value::Array(
            g.events
                .iter()
                .rev()
                .take(limit)
                .map(|e| {
                    json!({
                        "ts": e.ts,
                        "ip": e.ip,
                        "user_agent": e.user_agent,
                        "method": e.method,
                        "path": e.path,
                        "action": action_label(e.action),
                        "reason": e.reason,
                        "score": e.score,
                        "evidence": e.evidence,
                    })
                })
                .collect(),
        )
    }

    pub fn graph(&self) -> Value {
        let g = self.lock();
        let mut clients: Vec<&Client> = g.clients.values().collect();
        clients.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.ip.cmp(&b.ip)));
        clients.truncate(GRAPH_CLIENTS);

        let mut nodes = vec![
            json!({"id": "origin", "kind": "origin", "label": "Origin"}),
            json!({"id": "challenge", "kind": "challenge", "label": "Challenge"}),
            json!({"id": "maze", "kind": "maze", "label": "Maze"}),
        ];
        let mut edges = Vec::new();
        for c in &clients {
            nodes.push(json!({
                "id": c.ip,
                "kind": status(c),
                "label": c.ip,
                "requests": c.requests,
                "trapped": c.trapped,
            }));
            if c.proxied > 0 {
                edges.push(json!({"source": c.ip, "target": "origin", "action": "proxy", "count": c.proxied}));
            }
            if c.challenged > 0 {
                edges.push(json!({"source": c.ip, "target": "challenge", "action": "challenge", "count": c.challenged}));
            }
            if c.trapped > 0 {
                edges.push(json!({"source": c.ip, "target": "maze", "action": "trap", "count": c.trapped}));
            }
        }
        json!({"nodes": nodes, "edges": edges})
    }

    /// Records one settings change: the keys that changed, with old and new values.
    pub fn record_audit(&self, now: u64, changes: &[(String, Value, Value)]) {
        let entry = json!({
            "ts": now,
            "changes": changes
                .iter()
                .map(|(key, from, to)| json!({"key": key, "from": from, "to": to}))
                .collect::<Vec<_>>(),
        });
        let mut g = self.lock();
        if g.audit.len() == MAX_AUDIT {
            g.audit.pop_front();
        }
        g.audit.push_back(entry);
    }

    /// Settings changes, newest first.
    pub fn audit(&self) -> Value {
        let g = self.lock();
        Value::Array(g.audit.iter().rev().cloned().collect())
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// What the admin server serves: the store, the settings if a config file is set,
/// the API key every request must send, and the extra `Host` values it accepts.
pub struct AdminState {
    store: Arc<Store>,
    settings: Option<SettingsCtx>,
    api_key: String,
    allowed_hosts: Vec<String>,
}

/// Router for the admin API. Every `/api` route needs the `X-Botlocker-Key` header.
///
/// `allowed_hosts` are extra `Host` values to accept (exact `host:port`), on top of loopback.
pub fn admin_app_full(
    store: Arc<Store>,
    settings: Option<SettingsCtx>,
    api_key: String,
    allowed_hosts: Vec<String>,
) -> Router {
    let state = Arc::new(AdminState {
        store,
        settings,
        api_key,
        allowed_hosts,
    });
    // The API needs the key. The admin front adds it when it forwards a browser request.
    let api = Router::new()
        .route("/api/summary", get(summary))
        .route("/api/clients", get(clients))
        .route("/api/events", get(events))
        .route("/api/graph", get(graph))
        .route("/api/settings", get(get_settings).put(put_settings))
        .route("/api/audit", get(audit))
        .layer(middleware::from_fn_with_state(state.clone(), require_api_key));
    Router::new()
        .route("/", get(ui_index))
        .route("/index.html", get(ui_index))
        .route("/script.js", get(ui_script))
        .route("/style.css", get(ui_style))
        .merge(api)
        // Host check covers the UI and the API alike.
        .layer(middleware::from_fn_with_state(state.clone(), require_dashboard_host))
        .with_state(state)
}

const UI_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'";

/// Builds a UI response. Every asset is compiled into the binary, so there is nothing to mount.
fn ui_asset(content_type: &'static str, body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_SECURITY_POLICY, UI_CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

async fn ui_index() -> Response {
    ui_asset("text/html; charset=utf-8", include_str!("../ui/index.html"))
}

async fn ui_script() -> Response {
    ui_asset("text/javascript; charset=utf-8", include_str!("../ui/script.js"))
}

async fn ui_style() -> Response {
    ui_asset("text/css; charset=utf-8", include_str!("../ui/style.css"))
}

/// Rejects requests without the right `X-Botlocker-Key`. The comparison takes the same
/// time whatever the key, so a wrong key reveals nothing about the right one.
async fn require_api_key(State(state): State<Arc<AdminState>>, req: Request, next: Next) -> Response {
    let sent = req
        .headers()
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if constant_time_eq(sent.as_bytes(), state.api_key.as_bytes()) {
        next.run(req).await
    } else {
        api_error(StatusCode::UNAUTHORIZED, "missing or wrong BOTLOCKER_ADMIN_APIKEY")
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
}

async fn summary(State(state): State<Arc<AdminState>>) -> Json<Value> {
    Json(state.store.summary(unix_now()))
}

async fn clients(State(state): State<Arc<AdminState>>) -> Json<Value> {
    Json(state.store.clients(unix_now()))
}

async fn events(State(state): State<Arc<AdminState>>, Query(q): Query<EventsQuery>) -> Json<Value> {
    Json(state.store.events(q.limit.unwrap_or(100).min(MAX_EVENTS)))
}

async fn graph(State(state): State<Arc<AdminState>>) -> Json<Value> {
    Json(state.store.graph())
}

async fn audit(State(state): State<Arc<AdminState>>) -> Json<Value> {
    Json(state.store.audit())
}

async fn get_settings(State(state): State<Arc<AdminState>>) -> Response {
    let Some(ctx) = &state.settings else {
        return settings_disabled();
    };
    match read_config(&ctx.path) {
        Ok(cfg) => Json(json!({
            "config": to_json(&cfg),
            "path": ctx.path.display().to_string(),
        }))
        .into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

/// Validates, saves, and audits a config change. The proxy picks it up on its next poll.
async fn put_settings(
    State(state): State<Arc<AdminState>>,
    Json(body): Json<Value>,
) -> Response {
    let Some(ctx) = &state.settings else {
        return settings_disabled();
    };

    let before = read_config(&ctx.path).map(|c| to_json(&c)).unwrap_or(Value::Null);
    let cfg = match parse_update(body) {
        Ok(cfg) => cfg,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &e),
    };
    if let Err(e) = write_config(&ctx.path, &cfg) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, &e);
    }
    // The save is already in place. If the trigger fails, the proxy still picks it up on its next check.
    if let Err(e) = request_reload(&ctx.path) {
        tracing::warn!(error = %e, "saved, but could not request an immediate reload");
    }

    let changes = diff(&before, &to_json(&cfg));
    state.store.record_audit(unix_now(), &changes);
    Json(json!({ "ok": true, "changes": changes_json(&changes) })).into_response()
}

fn changes_json(changes: &[(String, Value, Value)]) -> Value {
    Value::Array(
        changes
            .iter()
            .map(|(key, from, to)| json!({"key": key, "from": from, "to": to}))
            .collect(),
    )
}

fn settings_disabled() -> Response {
    api_error(
        StatusCode::NOT_FOUND,
        "settings are not enabled; start with --config pointing at the config file",
    )
}

fn api_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Rejects requests whose Host header is neither loopback nor one of the configured
/// hosts (exact match). This stops DNS-rebinding pages from reading the dashboard API.
async fn require_dashboard_host(
    State(state): State<Arc<AdminState>>,
    req: Request,
    next: Next,
) -> Response {
    if host_allowed(req.headers(), &state.allowed_hosts) {
        next.run(req).await
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}

/// True when the `Host` header is loopback or one of the extra allowed values.
fn host_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    is_loopback_host(host) || allowed.iter().any(|h| h.eq_ignore_ascii_case(host))
}

/// The dashboard front, on the admin port. It serves the UI and forwards `/api` to the
/// keyed API listener, adding the key on the server. The browser never sees the key.
pub struct FrontState {
    api_base: String,
    api_key: String,
    allowed_hosts: Vec<String>,
    http: reqwest::Client,
}

const MAX_FORWARD_BODY: usize = 1024 * 1024;

/// Builds the front router. `api_base` is the internal API address, such as `http://127.0.0.1:9091`.
pub fn front_app(api_base: String, api_key: String, allowed_hosts: Vec<String>) -> Router {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("HTTP client builds with default TLS settings");
    let state = Arc::new(FrontState {
        api_base: api_base.trim_end_matches('/').to_string(),
        api_key,
        allowed_hosts,
        http,
    });
    Router::new()
        .route("/", get(ui_index))
        .route("/index.html", get(ui_index))
        .route("/script.js", get(ui_script))
        .route("/style.css", get(ui_style))
        .route("/api/*rest", any(forward_api))
        .layer(middleware::from_fn_with_state(state.clone(), front_host))
        .with_state(state)
}

async fn front_host(State(state): State<Arc<FrontState>>, req: Request, next: Next) -> Response {
    if host_allowed(req.headers(), &state.allowed_hosts) {
        next.run(req).await
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}

/// Forwards one `/api` request to the internal API, adding the key. The reply comes back unchanged.
async fn forward_api(State(state): State<Arc<FrontState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/api");
    let body = match axum::body::to_bytes(body, MAX_FORWARD_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };

    let mut upstream = state
        .http
        .request(parts.method.clone(), format!("{}{}", state.api_base, path))
        .header(API_KEY_HEADER, state.api_key.as_str())
        .body(body);
    if let Some(ct) = parts.headers.get(header::CONTENT_TYPE) {
        upstream = upstream.header(header::CONTENT_TYPE, ct);
    }

    match upstream.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let content_type = resp.headers().get(header::CONTENT_TYPE).cloned();
            let bytes = resp.bytes().await.unwrap_or_default();
            let mut out = (status, bytes).into_response();
            if let Some(ct) = content_type {
                out.headers_mut().insert(header::CONTENT_TYPE, ct);
            }
            out.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            out
        }
        Err(_) => api_error(StatusCode::BAD_GATEWAY, "dashboard API is not reachable"),
    }
}

pub fn is_loopback_host(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => host.rsplit_once(':').map_or(host, |(name, _)| name),
    };
    matches!(name, "127.0.0.1" | "localhost" | "::1")
}

fn client_json(c: &Client, now: u64) -> Value {
    json!({
        "ip": c.ip,
        "user_agent": c.user_agent,
        "status": status(c),
        "first_seen": c.first_seen,
        "last_seen": c.last_seen,
        "active": now.saturating_sub(c.last_seen) <= ACTIVE_WINDOW_SECS,
        "requests": c.requests,
        "proxied": c.proxied,
        "challenged": c.challenged,
        "trapped": c.trapped,
        "max_score": c.max_score,
        "evidence": c.top_evidence,
        "captured_because": c.captured_because,
        "captured_evidence": c.captured_evidence,
        "trap_reasons": c.trap_reasons,
    })
}

fn status(c: &Client) -> &'static str {
    if c.trapped > 0 {
        "captured"
    } else if c.challenged > 0 {
        "challenged"
    } else {
        "passing"
    }
}

fn action_label(a: Action) -> &'static str {
    match a {
        Action::Proxy => "proxied",
        Action::Challenge => "challenged",
        Action::Trap => "trapped",
    }
}

fn truncate(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts_are_accepted() {
        assert!(is_loopback_host("127.0.0.1:9090"));
        assert!(is_loopback_host("localhost:9090"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("[::1]:9090"));
        assert!(!is_loopback_host("evil.example:9090"));
        assert!(!is_loopback_host("127.0.0.1.evil.example"));
        assert!(!is_loopback_host(""));
    }
}
