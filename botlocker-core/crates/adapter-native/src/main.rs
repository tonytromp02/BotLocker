use std::future::IntoFuture;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use botlocker::config_watch::watch;
use botlocker::settings::SettingsCtx;
use botlocker::tail::follow;
use botlocker::dashboard::{admin_app_full, front_app};
use botlocker::{app_with_slot, EngineSlot, Store};
use botlocker_core::{Config, Engine};
use clap::Parser;

/// Botlocker: a reverse proxy that traps scrapers in an endless maze.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Extra Host header the dashboard API accepts, as host:port (exact match), e.g. 10.0.0.87:9090.
    /// Needed to reach the dashboard over the LAN. Repeatable. Loopback is always accepted.
    #[arg(long = "dashboard-host", value_name = "HOST:PORT")]
    dashboard_hosts: Vec<String>,
    /// Path to the TOML config file.
    #[arg(long, default_value = "botlocker.toml")]
    config: PathBuf,
    /// Site to proxy to, e.g. https://www.example.com. Overrides `origin` in the config file,
    /// including on reloads. Not written back to the file.
    #[arg(long, value_name = "URL")]
    origin: Option<String>,
    /// Address the proxy listens on.
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: SocketAddr,
    /// Address for the dashboard (UI and the forwarding front). Must be a loopback address unless
    /// --allow-remote-admin is given.
    #[arg(long, default_value = "127.0.0.1:9090")]
    admin: SocketAddr,
    /// Internal address of the dashboard API, which the admin port forwards to. Always loopback,
    /// and not published from a container.
    #[arg(long, default_value = "127.0.0.1:9091")]
    api_listen: SocketAddr,
    /// Allow the dashboard to bind a non-loopback address. Only use this inside
    /// a container whose port is published to 127.0.0.1 on the host.
    #[arg(long)]
    allow_remote_admin: bool,
    /// Follow an nginx access log written in the botlocker_json format and show
    /// its decisions in the dashboard.
    #[arg(long, value_name = "PATH")]
    follow_log: Option<PathBuf>,
    /// Run only the dashboard API, without the proxy. Without --follow-log it shows no live traffic.
    #[arg(long)]
    dashboard_only: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "botlocker=info".into()),
        )
        .init();

    let args = Args::parse();
    if !args.admin.ip().is_loopback() && !args.allow_remote_admin {
        return Err(format!(
            "--admin {} is not a loopback address; the dashboard exposes visitor IPs \
             (pass --allow-remote-admin only inside a container with a loopback-only port)",
            args.admin
        )
        .into());
    }

    if !args.api_listen.ip().is_loopback() {
        return Err(format!("--api-listen {} must be a loopback address", args.api_listen).into());
    }

    let store = Arc::new(Store::default());
    if let Some(path) = args.follow_log.clone() {
        tracing::info!(log = %path.display(), "following nginx access log");
        tokio::spawn(follow(path, store.clone()));
    }

    let api_key = std::env::var("BOTLOCKER_ADMIN_APIKEY")
        .map_err(|_| "BOTLOCKER_ADMIN_APIKEY must be set (at least 32 bytes); the dashboard API needs it")?;
    if api_key.len() < 32 {
        return Err("BOTLOCKER_ADMIN_APIKEY must be at least 32 bytes".into());
    }
    let settings = SettingsCtx {
        path: args.config.clone(),
    };
    // Internal: the keyed API. Only the front below calls it, with the key.
    let api_listener = tokio::net::TcpListener::bind(args.api_listen).await?;
    let api = axum::serve(
        api_listener,
        admin_app_full(store.clone(), Some(settings), api_key.clone(), Vec::new())
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .into_future();
    // The front: the UI, plus /api forwarded with the key. The browser never holds the key.
    let admin_listener = tokio::net::TcpListener::bind(args.admin).await?;
    let front = axum::serve(
        admin_listener,
        front_app(format!("http://{}", args.api_listen), api_key, args.dashboard_hosts.clone())
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .into_future();
    let dashboard = async { tokio::try_join!(api, front).map(|_| ()) };

    if args.dashboard_only {
        tracing::info!(dashboard = %args.admin, "botlocker dashboard only (no proxy)");
        dashboard.await?;
        return Ok(());
    }

    let text = std::fs::read_to_string(&args.config)
        .map_err(|e| format!("cannot read {}: {e}", args.config.display()))?;
    let mut cfg = Config::from_toml(&text)?;
    botlocker::settings::apply_origin(&mut cfg, args.origin.as_deref())?;

    let secret = std::env::var("BOTLOCKER_SECRET")
        .map_err(|_| "BOTLOCKER_SECRET must be set (at least 32 bytes)")?;
    let engine = Engine::new(cfg, secret.into_bytes())?;
    let slot = Arc::new(EngineSlot::new(engine));
    tokio::spawn(watch(args.config.clone(), args.origin.clone(), slot.clone()));

    let proxy_listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(proxy = %args.listen, dashboard = %args.admin, "botlocker listening");

    let proxy = axum::serve(
        proxy_listener,
        app_with_slot(slot, store).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .into_future();

    tokio::try_join!(proxy, dashboard)?;
    Ok(())
}
