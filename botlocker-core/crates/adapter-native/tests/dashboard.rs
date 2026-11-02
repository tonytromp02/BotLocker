//! Dashboard tests: traffic goes through the proxy, then the admin API reports it.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::response::Html;
use axum::routing::get;
use axum::Router;
use botlocker::{admin_app_full, app, Store};
use botlocker_core::{Config, Engine};
use serde_json::Value;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const BROWSER_UA: &str = "Mozilla/5.0 (Macintosh) Chrome/120.0 Safari/537.36";
const BOT_UA: &str = "python-requests/2.31";

async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    addr
}

/// Returns (proxy address, admin address) sharing one store.
async fn stack() -> (SocketAddr, SocketAddr) {
    let origin = serve(Router::new().route(
        "/",
        get(|| async { Html("<html><body>Origin</body></html>") }),
    ))
    .await;
    let text = format!("origin = \"http://{origin}\"\nmaze_prefix = \"/maze/\"\n");
    let engine = Engine::new(Config::from_toml(&text).unwrap(), SECRET.to_vec()).unwrap();
    let store = Arc::new(Store::default());
    let proxy = serve(app(engine, store.clone())).await;
    let admin = serve(admin_app_full(store, None, API_KEY.to_string(), Vec::new())).await;
    (proxy, admin)
}

/// Shared API key for the tests. Real deployments set it with BOTLOCKER_ADMIN_APIKEY.
const API_KEY: &str = "test-api-key-0123456789abcdef0123";

fn client() -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("x-botlocker-key", API_KEY.parse().unwrap());
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(headers)
        .build()
        .unwrap()
}

fn client_without_key() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn get_json(admin: SocketAddr, path: &str) -> Value {
    client()
        .get(format!("http://{admin}{path}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn summary_and_clients_reflect_traffic() {
    let (proxy, admin) = stack().await;
    let http = client();

    // Browser: proxied.
    http.get(format!("http://{proxy}/"))
        .header("user-agent", BROWSER_UA)
        .header("accept", "text/html")
        .header("accept-language", "en-US")
        .header("sec-fetch-site", "none")
        .send()
        .await
        .unwrap();
    // Scraper: challenged (bot UA + missing accept-language).
    http.get(format!("http://{proxy}/"))
        .header("user-agent", BOT_UA)
        .header("accept", "*/*")
        .send()
        .await
        .unwrap();
    // Honeypot: trapped.
    http.get(format!("http://{proxy}/maze/x"))
        .header("user-agent", BOT_UA)
        .send()
        .await
        .unwrap();

    let s = get_json(admin, "/api/summary").await;
    assert_eq!(s["requests"], 3);
    assert_eq!(s["proxied"], 1);
    assert_eq!(s["challenged"], 1);
    assert_eq!(s["trapped"], 1);
    assert_eq!(s["clients"], 1);
    assert_eq!(s["captured"], 1);

    let clients = get_json(admin, "/api/clients").await;
    let c = &clients[0];
    assert_eq!(c["status"], "captured");
    assert_eq!(c["user_agent"], BOT_UA);
    assert_eq!(c["captured_because"], "honeypot");
    assert_eq!(c["trap_reasons"]["honeypot"], 1);
    assert!(c["captured_evidence"][0].as_str().unwrap().contains("maze prefix"));
    assert!(c["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e.as_str().unwrap().starts_with("client.bot_ua")));
}

#[tokio::test]
async fn events_are_newest_first_and_limited() {
    let (proxy, admin) = stack().await;
    let http = client();
    for path in ["/one", "/two", "/three"] {
        http.get(format!("http://{proxy}{path}"))
            .header("user-agent", BROWSER_UA)
            .header("accept", "text/html")
            .header("accept-language", "en-US")
            .header("sec-fetch-site", "none")
            .send()
            .await
            .unwrap();
    }
    let events = get_json(admin, "/api/events?limit=2").await;
    let events = events.as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["path"], "/three");
    assert_eq!(events[1]["path"], "/two");
}

#[tokio::test]
async fn graph_has_system_nodes_and_action_edges() {
    let (proxy, admin) = stack().await;
    client()
        .get(format!("http://{proxy}/maze/x"))
        .header("user-agent", BOT_UA)
        .send()
        .await
        .unwrap();

    let g = get_json(admin, "/api/graph").await;
    let nodes = g["nodes"].as_array().unwrap();
    let kinds: Vec<&str> = nodes.iter().map(|n| n["kind"].as_str().unwrap()).collect();
    assert!(kinds.contains(&"origin"));
    assert!(kinds.contains(&"challenge"));
    assert!(kinds.contains(&"maze"));
    assert!(kinds.contains(&"captured"));

    let edges = g["edges"].as_array().unwrap();
    assert!(edges
        .iter()
        .any(|e| e["target"] == "maze" && e["action"] == "trap" && e["count"] == 1));
}

#[tokio::test]
async fn unknown_admin_paths_are_404() {
    let (_proxy, admin) = stack().await;
    let resp = client().get(format!("http://{admin}/no-such-page")).send().await.unwrap();
    assert_eq!(resp.status(), 404);
}



#[tokio::test]
async fn non_loopback_host_header_is_rejected() {
    let (_proxy, admin) = stack().await;
    let resp = client()
        .get(format!("http://{admin}/api/summary"))
        .header("host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn configured_lan_host_is_accepted_and_others_are_not() {
    let store = Arc::new(Store::default());
    let addr = serve(botlocker::admin_app_full(
        store,
        None,
        API_KEY.to_string(),
        vec!["10.0.0.87:9090".to_string()],
    ))
    .await;

    // Exact configured Host value: allowed.
    let ok = client()
        .get(format!("http://{addr}/api/summary"))
        .header("host", "10.0.0.87:9090")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // Loopback is still allowed.
    let loopback = client()
        .get(format!("http://{addr}/api/summary"))
        .send()
        .await
        .unwrap();
    assert_eq!(loopback.status(), 200);

    // A different LAN address or a spoofed name is not in the list.
    for host in ["10.0.1.30:9090", "10.0.0.87:8080", "evil.example:9090"] {
        let resp = client()
            .get(format!("http://{addr}/api/summary"))
            .header("host", host)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "host {host} should be rejected");
    }
}

#[tokio::test]
async fn api_requires_the_key() {
    let (_proxy, admin) = stack().await;
    let none = client_without_key()
        .get(format!("http://{admin}/api/summary"))
        .send()
        .await
        .unwrap();
    assert_eq!(none.status(), 401);

    let wrong = client_without_key()
        .get(format!("http://{admin}/api/summary"))
        .header("x-botlocker-key", "not-the-key")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);

    let right = client_without_key()
        .get(format!("http://{admin}/api/summary"))
        .header("x-botlocker-key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(right.status(), 200);
}

#[tokio::test]
async fn front_serves_ui_and_adds_the_key_on_the_server() {
    let (proxy, admin) = stack().await; // `admin` is the keyed API listener
    let front = serve(botlocker::dashboard::front_app(
        format!("http://{admin}"),
        API_KEY.to_string(),
        Vec::new(),
    ))
    .await;
    let anon = reqwest::Client::new();
    let base = format!("http://{front}");

    let page = anon.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(page.status(), 200);
    assert!(page.headers()["content-security-policy"].to_str().unwrap().contains("default-src 'none'"));
    assert!(page.text().await.unwrap().contains("Botlocker"));
    assert_eq!(anon.get(format!("{base}/script.js")).send().await.unwrap().status(), 200);
    assert_eq!(anon.get(format!("{base}/style.css")).send().await.unwrap().status(), 200);

    // The browser sends no key. The front adds it when it forwards the call.
    assert_eq!(anon.get(format!("{base}/api/summary")).send().await.unwrap().status(), 200);

    // The keyed API itself still refuses requests without the key.
    assert_eq!(anon.get(format!("http://{admin}/api/summary")).send().await.unwrap().status(), 401);

    // A foreign Host (DNS rebinding) is refused at the front.
    let rebound = anon
        .get(format!("{base}/api/summary"))
        .header("host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(rebound.status(), 403);

    // The proxied site is not the dashboard.
    let proxied = anon.get(format!("http://{proxy}/script.js")).send().await.unwrap().text().await.unwrap();
    assert!(!proxied.contains("apiFetch"));
}
