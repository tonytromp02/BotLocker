//! Settings API tests: the admin server with a real config file on disk.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use botlocker::settings::{read_config, SettingsCtx};
use botlocker::{admin_app_full, Store};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{json, Value};

const API_KEY: &str = "test-api-key-0123456789abcdef0123";
const BASE_TOML: &str = "origin = \"https://origin.example\"\nmaze_prefix = \"/maze/\"\n";

async fn serve(app: axum::Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    addr
}

fn temp_config(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bl-settings-api-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("botlocker.toml");
    std::fs::write(&path, BASE_TOML).unwrap();
    path
}

async fn with_settings(name: &str) -> (SocketAddr, PathBuf) {
    let path = temp_config(name);
    let app = admin_app_full(
        Arc::new(Store::default()),
        Some(SettingsCtx { path: path.clone() }),
        API_KEY.to_string(),
        Vec::new(),
    );
    (serve(app).await, path)
}

fn client() -> reqwest::Client {
    let mut headers = HeaderMap::new();
    headers.insert("x-botlocker-key", HeaderValue::from_static(API_KEY));
    reqwest::Client::builder().default_headers(headers).build().unwrap()
}

fn write_headers(key: Option<&str>) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("content-type", HeaderValue::from_static("application/json"));
    if let Some(k) = key {
        h.insert("x-botlocker-key", HeaderValue::from_str(k).unwrap());
    }
    h
}

async fn current_json(addr: SocketAddr) -> Value {
    let body: Value = client()
        .get(format!("http://{addr}/api/settings"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["config"].clone()
}

#[tokio::test]
async fn get_returns_the_current_config() {
    let (addr, _) = with_settings("get").await;
    let cfg = current_json(addr).await;
    assert_eq!(cfg["maze_prefix"], "/maze/");
    assert_eq!(cfg["challenge_at"], 3.0);
}

#[tokio::test]
async fn write_without_the_key_is_refused_and_changes_nothing() {
    let (addr, path) = with_settings("notoken").await;
    let mut body = current_json(addr).await;
    body["challenge_at"] = json!(4.5);
    let resp = reqwest::Client::new()
        .put(format!("http://{addr}/api/settings"))
        .headers(write_headers(None))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert_eq!(read_config(&path).unwrap().challenge_at, 3.0);
}

#[tokio::test]
async fn valid_write_is_saved_and_audited() {
    let (addr, path) = with_settings("valid").await;
    let mut body = current_json(addr).await;
    body["challenge_at"] = json!(4.5);
    body["kill_switch"] = json!(true);
    let resp = client()
        .put(format!("http://{addr}/api/settings"))
        .headers(write_headers(Some(API_KEY)))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let res: Value = resp.json().await.unwrap();
    let keys: Vec<&str> = res["changes"].as_array().unwrap().iter().map(|c| c["key"].as_str().unwrap()).collect();
    assert!(keys.contains(&"challenge_at"));
    assert!(keys.contains(&"kill_switch"));

    let saved = read_config(&path).unwrap();
    assert_eq!(saved.challenge_at, 4.5);
    assert!(saved.kill_switch);

    let audit: Value = client()
        .get(format!("http://{addr}/api/audit"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let first = &audit[0]["changes"][0];
    assert!(first["key"].is_string());
    assert!(audit[0]["changes"].as_array().unwrap().iter().any(|c| c["key"] == "challenge_at" && c["to"] == 4.5));
}

#[tokio::test]
async fn invalid_write_is_rejected_and_the_file_is_untouched() {
    let (addr, path) = with_settings("invalid").await;
    let mut body = current_json(addr).await;
    body["trap_at"] = json!(1.0); // below challenge_at
    let resp = client()
        .put(format!("http://{addr}/api/settings"))
        .headers(write_headers(Some(API_KEY)))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let err: Value = resp.json().await.unwrap();
    assert!(err["error"].as_str().unwrap().contains("trap_at"));
    assert_eq!(read_config(&path).unwrap().trap_at, 6.0);
}

#[tokio::test]
async fn unknown_fields_are_rejected() {
    let (addr, _) = with_settings("unknown").await;
    let mut body = current_json(addr).await;
    body["not_a_setting"] = json!(true);
    let resp = client()
        .put(format!("http://{addr}/api/settings"))
        .headers(write_headers(Some(API_KEY)))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn settings_are_disabled_without_a_config_path() {
    let addr = serve(admin_app_full(Arc::new(Store::default()), None, API_KEY.to_string(), Vec::new())).await;
    let resp = client()
        .get(format!("http://{addr}/api/settings"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
