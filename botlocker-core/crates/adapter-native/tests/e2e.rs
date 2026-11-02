//! End-to-end tests: a fake origin, the proxy in front of it, and real HTTP.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::response::Html;
use axum::routing::get;
use axum::Router;
use botlocker::Store;
use botlocker_core::{Config, Engine};

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const BROWSER_UA: &str = "Mozilla/5.0 (Macintosh) Chrome/120.0 Safari/537.36";
const BOT_UA: &str = "python-requests/2.31";

async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

fn origin_app() -> Router {
    Router::new()
        .route(
            "/",
            get(|| async {
                Html("<html><head></head><body><h1>Origin Hello</h1></body></html>")
            }),
        )
        .route(
            "/articles/x",
            get(|| async { Html("<html><body>Article</body></html>") }),
        )
}

async fn start_proxy(origin: SocketAddr, extra: &str) -> SocketAddr {
    let text = format!(
        "origin = \"http://{origin}\"\nmaze_prefix = \"/maze/\"\n{extra}"
    );
    let engine = Engine::new(Config::from_toml(&text).unwrap(), SECRET.to_vec()).unwrap();
    serve(botlocker::app(engine, Arc::new(Store::default()))).await
}

async fn start_pair(extra: &str) -> SocketAddr {
    let origin = serve(origin_app()).await;
    start_proxy(origin, extra).await
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn browser(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    req.header("user-agent", BROWSER_UA)
        .header("accept", "text/html")
        .header("accept-language", "en-US")
        .header("sec-fetch-site", "none")
}

fn bot(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    req.header("user-agent", BOT_UA).header("accept", "*/*")
}

#[tokio::test]
async fn browser_reaches_origin_with_honeypot_link_injected() {
    let proxy = start_pair("").await;
    let resp = browser(client().get(format!("http://{proxy}/")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Origin Hello"));
    assert!(body.contains("href=\"/maze/"), "honeypot link missing: {body}");
}

#[tokio::test]
async fn honeypot_path_is_trapped_even_for_browsers() {
    let proxy = start_pair("").await;
    let resp = browser(client().get(format!("http://{proxy}/maze/some/path")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("x-robots-tag").unwrap(),
        "noindex, nofollow"
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("<meta name=\"robots\" content=\"noindex,nofollow\">"));
    assert!(!body.contains("Origin Hello"));
}

#[tokio::test]
async fn scraper_is_challenged_then_passes_with_the_cookie() {
    let proxy = start_pair("").await;
    let http = client();

    let challenge = bot(http.get(format!("http://{proxy}/")))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(challenge.contains("document.cookie"));
    assert!(!challenge.contains("Origin Hello"));

    // The page holds a challenge token. Reporting clean signals with it earns the pass.
    let challenge_token = challenge
        .split("var TOKEN = \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("challenge token in page")
        .to_string();
    let report: serde_json::Value = http
        .get(format!("http://{proxy}/.bl/report?t={challenge_token}&w=0&h=0&z=0"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = report["token"].as_str().expect("pass token").to_string();

    let resp = bot(http.get(format!("http://{proxy}/")))
        .header("cookie", format!("bl_pass={token}"))
        .send()
        .await
        .unwrap();
    assert!(resp.text().await.unwrap().contains("Origin Hello"));
}

#[tokio::test]
async fn scraper_that_keeps_crawling_gets_trapped() {
    // Two requests are allowed per window. The third trips the rate signal,
    // which together with the bot UA is two families, so it's trapped.
    let proxy = start_pair("[behavior]\nmax_requests = 2\n").await;
    let http = client();
    for _ in 0..2 {
        let body = bot(http.get(format!("http://{proxy}/")))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(body.contains("document.cookie"), "expected challenge, got: {body}");
    }
    let resp = bot(http.get(format!("http://{proxy}/articles/next")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("x-robots-tag").unwrap(),
        "noindex, nofollow"
    );
}

#[tokio::test]
async fn verified_crawler_is_proxied_and_gets_no_honeypot() {
    let proxy = start_pair(
        "[[verified_crawlers]]\nname = \"googlebot\"\nuser_agent_contains = \"Googlebot\"\nip_ranges = [\"127.0.0.0/8\"]\n",
    )
    .await;
    let body = client()
        .get(format!("http://{proxy}/"))
        .header("user-agent", "Googlebot/2.1 python-requests")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("Origin Hello"));
    assert!(!body.contains("/maze/"));
}

#[tokio::test]
async fn kill_switch_proxies_scrapers_through_to_origin() {
    let proxy = start_pair("kill_switch = true\n").await;
    let resp = bot(client().get(format!("http://{proxy}/maze/x")))
        .send()
        .await
        .unwrap();
    // The origin has no /maze/x, so the 404 proves the request was not trapped.
    assert_eq!(resp.status(), 404);
    assert!(resp.headers().get("x-robots-tag").is_none());
}

#[tokio::test]
async fn robots_txt_gets_the_maze_disallow_rule() {
    let proxy = start_pair("").await;
    let body = browser(client().get(format!("http://{proxy}/robots.txt")))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("Disallow: /maze/"));
}

#[tokio::test]
async fn automated_browser_is_trapped_even_with_a_pass_cookie() {
    let proxy = start_pair("").await;
    let http = client();
    let challenge = bot(http.get(format!("http://{proxy}/")))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let token = challenge
        .split("var TOKEN = \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_string();

    // A browser reporting navigator.webdriver = true is flagged, not given a pass.
    let report: serde_json::Value = http
        .get(format!("http://{proxy}/.bl/report?t={token}&w=1&h=0&z=0"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["automated"], true);
    assert!(report.get("token").is_none());

    let resp = browser(http.get(format!("http://{proxy}/")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("x-robots-tag").unwrap(),
        "noindex, nofollow"
    );
}

#[tokio::test]
async fn pass_holder_still_gets_the_honeypot_link() {
    let proxy = start_pair("").await;
    let http = client();
    let challenge = bot(http.get(format!("http://{proxy}/")))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let challenge_token = challenge
        .split("var TOKEN = \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_string();
    let report: serde_json::Value = http
        .get(format!("http://{proxy}/.bl/report?t={challenge_token}&w=0&h=0&z=0"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = report["token"].as_str().unwrap().to_string();

    let body = bot(http.get(format!("http://{proxy}/")))
        .header("cookie", format!("bl_pass={token}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("Origin Hello"));
    assert!(body.contains("href=\"/maze/"), "pass holder got no honeypot link");
}

#[tokio::test]
async fn challenge_endpoint_redirects_only_to_same_site_paths() {
    let proxy = start_pair("").await;
    let body = client()
        .get(format!("http://{proxy}/.bl/challenge?next=/articles/x"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("var NEXT = \"/articles/x\";"));

    let body = client()
        .get(format!("http://{proxy}/.bl/challenge?next=https://evil.example"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("var NEXT = \"/\";"));
}
