//! Native (self-hosted) adapter: an HTTP reverse proxy that applies the
//! `botlocker-core` engine to every request.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use botlocker_core::{Action, Engine, NormalizedRequest, Reason, CHALLENGE_PATH, REPORT_PATH};
use futures_util::StreamExt;

pub mod config_watch;
pub mod dashboard;
pub mod settings;
pub mod tail;

pub use dashboard::{admin_app_full, Store};

/// Largest request body we will buffer and forward.
const MAX_REQUEST_BODY: usize = 1024 * 1024;

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The engine the proxy uses now. A config reload swaps in a new one.
pub struct EngineSlot(RwLock<Arc<Engine>>);

impl EngineSlot {
    pub fn new(engine: Engine) -> Self {
        Self(RwLock::new(Arc::new(engine)))
    }

    pub fn get(&self) -> Arc<Engine> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set(&self, engine: Engine) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(engine);
    }
}

pub struct AppState {
    engine: Arc<EngineSlot>,
    http: reqwest::Client,
    store: Arc<Store>,
}

/// Builds the proxy router. Every request goes through the engine except the
/// challenge endpoint, which is always reachable. Decisions are recorded in `store`.
pub fn app(engine: Engine, store: Arc<Store>) -> Router {
    app_with_slot(Arc::new(EngineSlot::new(engine)), store)
}

/// Like `app`, but the caller keeps a handle to the engine slot, so a config reload can swap the engine.
pub fn app_with_slot(engine: Arc<EngineSlot>, store: Arc<Store>) -> Router {
    let http = reqwest::Client::builder()
        // Redirects belong to the browser, so pass them through unchanged.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client builds with default TLS");
    let state = Arc::new(AppState {
        engine,
        http,
        store,
    });
    Router::new().fallback(handle).with_state(state)
}

async fn handle(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let body = match to_bytes(body, MAX_REQUEST_BODY).await {
        Ok(b) => b,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let now = unix_now();
    let nreq = normalize(&parts, peer.ip());

    if parts.uri.path() == CHALLENGE_PATH {
        let next = url::form_urlencoded::parse(nreq.query.as_deref().unwrap_or("").as_bytes())
            .find(|(k, _)| k == "next")
            .map(|(_, v)| v.into_owned());
        return noindex_html(state.engine.get().challenge_html(peer.ip(), now, next.as_deref()));
    }

    if parts.uri.path() == REPORT_PATH {
        let query = parts.uri.query().unwrap_or("");
        return json_response(state.engine.get().report(peer.ip(), now, query));
    }

    let class = state.engine.get().classify(&nreq, now);
    tracing::info!(
        ip = %peer.ip(),
        path = %nreq.path,
        action = ?class.action,
        reason = ?class.reason,
        score = class.score.total,
        "decision"
    );
    state.store.record(&nreq, &class, now);

    match class.action {
        Action::Proxy => {
            // Every visitor gets the hidden honeypot link, including visitors who
            // already passed the challenge. Verified crawlers are left alone, so a
            // good bot is never trapped by accident.
            let inject = !matches!(class.reason, Reason::VerifiedCrawler(_) | Reason::KillSwitch);
            proxy(&state, &parts, &nreq, body, inject).await
        }
        Action::Challenge => {
            let next = nreq.path_and_query();
            noindex_html(state.engine.get().challenge_html(peer.ip(), now, Some(&next)))
        }
        Action::Trap => trap(&state, &nreq.path).await,
    }
}

fn normalize(parts: &Parts, ip: IpAddr) -> NormalizedRequest {
    NormalizedRequest {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        query: parts.uri.query().map(str::to_string),
        headers: parts
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        client_ip: ip,
        // Native deployments don't have GeoIP or TLS fingerprints unless a
        // database or fronting proxy supplies them. Those signals stay silent.
        asn: None,
        tls_fingerprint: None,
    }
}

async fn proxy(
    state: &AppState,
    parts: &Parts,
    nreq: &NormalizedRequest,
    body: Bytes,
    inject: bool,
) -> Response {
    let engine = state.engine.get();
    let cfg = engine.config();
    let Some(origin) = cfg.origin.as_deref() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "origin not configured").into_response();
    };
    let url = format!("{}{}", origin.trim_end_matches('/'), nreq.path_and_query());

    let mut upstream = state.http.request(parts.method.clone(), url).body(body);
    for (name, value) in &parts.headers {
        let n = name.as_str();
        // Ask for an uncompressed body so the honeypot link can be injected.
        if HOP_BY_HOP.contains(&n)
            || matches!(n, "host" | "accept-encoding" | "content-length" | "x-forwarded-for")
        {
            continue;
        }
        upstream = upstream.header(name.clone(), value.clone());
    }
    let client = nreq.client_ip.to_string();
    let forwarded = match parts.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(prev) => format!("{prev}, {client}"),
        None => client,
    };
    upstream = upstream.header("x-forwarded-for", forwarded);

    let resp = match upstream.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "origin unreachable");
            return (StatusCode::BAD_GATEWAY, "origin unavailable").into_response();
        }
    };
    let status = resp.status();
    let headers = filter_headers(resp.headers());
    let upstream_body = match resp.bytes().await {
        Ok(b) => b.to_vec(),
        Err(e) => {
            tracing::warn!(error = %e, "origin body read failed");
            return (StatusCode::BAD_GATEWAY, "origin unavailable").into_response();
        }
    };

    if nreq.path == "/robots.txt" {
        // Keep the origin's rules and add ours. If the origin has none, serve ours alone.
        let mut text = if status.is_success() {
            upstream_body
        } else {
            Vec::new()
        };
        if !text.is_empty() && !text.ends_with(b"\n") {
            text.push(b'\n');
        }
        text.extend_from_slice(b"\n# Botlocker\n");
        text.extend_from_slice(state.engine.get().robots_rule().as_bytes());
        let mut h = HeaderMap::new();
        h.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        return respond(StatusCode::OK, h, Body::from(text));
    }

    let is_html = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/html"));
    let mut body = upstream_body;
    if inject && is_html {
        let link = hidden_link(&state.engine.get());
        inject_before_body_close(&mut body, &link);
    }
    respond(status, headers, Body::from(body))
}

async fn trap(state: &AppState, path: &str) -> Response {
    let engine = state.engine.get();
    let cfg = engine.config();
    let html = state.engine.get().maze_html(path).into_bytes();
    let headers = noindex_headers();

    if cfg.slow_drip_ms == 0 {
        return respond(StatusCode::OK, headers, Body::from(html));
    }

    let delay = Duration::from_millis(cfg.slow_drip_ms);
    let chunks: Vec<Bytes> = html.chunks(512).map(Bytes::copy_from_slice).collect();
    let stream = futures_util::stream::iter(chunks.into_iter().enumerate()).then(
        move |(i, chunk)| async move {
            if i > 0 {
                tokio::time::sleep(delay).await;
            }
            Ok::<Bytes, std::convert::Infallible>(chunk)
        },
    );
    respond(StatusCode::OK, headers, Body::from_stream(stream))
}

fn hidden_link(engine: &Engine) -> String {
    format!(
        "<a href=\"{}\" rel=\"nofollow\" tabindex=\"-1\" aria-hidden=\"true\" \
         style=\"position:absolute;left:-10000px\">&#8203;</a>",
        engine.honeypot_link()
    )
}

fn inject_before_body_close(html: &mut Vec<u8>, snippet: &str) {
    let lower = html.to_ascii_lowercase();
    if let Some(pos) = lower.windows(7).position(|w| w == b"</body>") {
        html.splice(pos..pos, snippet.bytes());
    }
}

/// Drops hop-by-hop headers and `content-length`, which is stale once the
/// body has been rewritten.
fn filter_headers(upstream: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in upstream {
        let n = name.as_str();
        if HOP_BY_HOP.contains(&n) || n == "content-length" {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn noindex_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, nofollow"),
    );
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h
}

fn json_response(body: String) -> Response {
    let mut h = HeaderMap::new();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    respond(StatusCode::OK, h, Body::from(body))
}

fn noindex_html(body: String) -> Response {
    respond(StatusCode::OK, noindex_headers(), Body::from(body))
}

fn respond(status: StatusCode, headers: HeaderMap, body: Body) -> Response {
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    resp
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
