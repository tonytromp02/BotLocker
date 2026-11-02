# Botlocker

Botlocker is a reverse proxy that lures abusive scrapers into an endless maze of generated pages, so they waste their own time instead of taking your content. Humans and verified good crawlers pass through untouched.

> **Status:** The native (self-hosted) proxy and detector work and are tested. The Cloudflare Worker adapter is designed but not built yet. See [`architecture.md`](architecture.md).

## How it works

1. Every request goes through Botlocker first.
2. Verified good crawlers (matched by user agent and IP range) go straight to your origin.
3. Everything else is scored from several weak signals: honeypot hits, missing browser headers, known scraper user agents, request rate, and missing asset requests.
4. Low scores proxy to your origin. Mid scores get a challenge page. High scores from two or more signal families go to the maze.

Honeypot hits are different: a request under the maze prefix is always trapped, since no human reaches it. Botlocker injects a hidden link to the maze into your HTML pages to catch crawlers that follow every link.

## Quick start (native)

Requires Rust (stable).

```sh
cd botlocker-core
cargo build --release -p botlocker

cp ../botlocker.example.toml botlocker.toml   # set origin to your site, or pass --origin
export BOTLOCKER_SECRET="$(openssl rand -hex 32)"
export BOTLOCKER_ADMIN_APIKEY="$(openssl rand -hex 32)"
./target/release/botlocker --config botlocker.toml --listen 0.0.0.0:8080 --origin https://www.example.com
```

Point your DNS or load balancer at port 8080. Logs go to stdout; set `RUST_LOG=botlocker=debug` for more detail.

`BOTLOCKER_SECRET` signs challenge cookies and seeds the maze. It must be at least 32 bytes. Changing it invalidates existing pass cookies. Keep it stable across restarts if you want visitors to stay verified. `BOTLOCKER_ADMIN_APIKEY` protects the dashboard API and is required even if you don't open the dashboard.

## Dashboard

The dashboard is part of the `botlocker` binary. It serves the UI and the API on its own admin port, separate from the proxy, so it is never mixed into the proxied site. The default is loopback only:

```sh
export BOTLOCKER_ADMIN_APIKEY="$(openssl rand -hex 32)"
cd botlocker-core && ./target/release/botlocker --config botlocker.toml --admin 127.0.0.1:9090
```

Open `http://localhost:9090`. The page needs no key: the server adds `BOTLOCKER_ADMIN_APIKEY` when it forwards requests to the API, so the browser never holds it. The server refuses requests whose `Host` header isn't loopback (or listed with `--dashboard-host`), which blocks DNS-rebinding pages. Anyone who can reach the admin port can use the dashboard, so keep it on loopback.


- **Graph:** clients as nodes, joined to the origin (proxied), the challenge page, or the maze (trapped). Captured bots glow purple, trap edges animate, and you can drag nodes.
- **Captured:** clients that reached the maze, with user agent, scores, and the signals that fired.
- **Live feed:** the 500 most recent decisions.
- **Inspector:** click any node for its counts, scoring evidence, and recent requests.

The dashboard data lives in memory and resets on restart. The admin port serves the UI and forwards `/api` to an internal API listener (`--api-listen`, loopback only) with the key. Keep the admin port on loopback unless you put access control in front of it, since it has no login and no TLS of its own.

### Captured view

Each captured client shows why it was captured: the trap reason in plain words (honeypot hit, automated browser, or signal score) and the evidence behind it. A score-based trap lists the score, the threshold, the number of signal families, and the signals that fired. A detected bot is always sent to the maze.

### Settings

The dashboard's Settings tab edits the config file (`botlocker.toml`) that the proxy runs on:

- **What you can change:** the thresholds (`challenge_at`, `trap_at`), the kill switch, the honeypot link, the maze limits, the pass lifetime, the nginx file-check interval (`reload_poll_secs`), the behaviour limits, the scraper user-agent list, and the hosting ASN list.
- **What stays in the file:** `maze_prefix` (the robots.txt rule depends on it), verified crawlers, and signal weights. The page shows them read-only.
- **How a save works:** the new values are checked with the same rules as the file. A rejected save changes nothing. An accepted save is written atomically. The nginx build reloads at once. The standalone binary picks it up on its next two-second check. Each save is logged with old and new values under "Recent changes".
- **Who can save:** saves go through the same forwarding path as reads, so they are authorised by the server. The key stays on the server.

## Configuration

See [`botlocker.example.toml`](botlocker.example.toml) for every key with comments. The main ones:

| Key | Purpose |
|---|---|
| `origin` | Site to protect. Standalone binary only; `--origin` overrides it. The nginx build uses `ORIGIN_URL` instead. |
| `maze_prefix` | Path prefix for trap pages. Added to `robots.txt` as a disallow rule. |
| `challenge_at`, `trap_at` | Score thresholds. Trapping also needs two signal families. |
| `kill_switch` | `true` proxies everything untouched. |
| `reload_poll_secs` | How often the nginx build checks for hand edits, 5 to 300 seconds, with jitter. Dashboard saves apply at once. |
| `inject_honeypot` | Insert the hidden maze link into origin HTML. |
| `slow_drip_ms` | Delay between maze chunks, to hold bots longer. |
| `[behavior]` | Window size and request limit for the rate signal. |
| `[[verified_crawlers]]` | Good crawlers that bypass scoring. |

### Changing settings at runtime

Edit the file, or use the dashboard's Settings page. The running proxy reloads on its own:

- **Standalone:** the binary checks the config file every two seconds. A valid change applies, and an invalid one is logged and ignored. The behaviour counters and the flagged-browser list carry over.
- **nginx:** a dashboard save applies at once. Hand edits are checked every `reload_poll_secs` seconds (default 15, with jitter). The entrypoint runs `nginx -s reload` after a change, and a change that fails `nginx -t` is skipped. Reloading nginx resets its per-worker behaviour counters, so the flagged-browser list is also cleared. See the nginx notes below.

Settings that are not in the file (`BOTLOCKER_SECRET`, `BOTLOCKER_ADMIN_APIKEY`, `--origin`, `ORIGIN_URL`, the listen ports, the event log) still need a restart.

## Signals

| Signal | Family | Default weight | Fires when |
|---|---|---|---|
| `headers.accept_language` | headers | 1.5 | No `Accept-Language` |
| `headers.accept` | headers | 1.0 | No `Accept` |
| `headers.fetch_metadata` | headers | 2.0 | Chrome user agent without `Sec-Fetch-Site` |
| `client.empty_ua` | client | 3.0 | Empty user agent |
| `client.bot_ua` | client | 4.0 | User agent matches a known scraper list |
| `behavior.rate` | behavior | 3.0 | More requests than `max_requests` in the window |
| `behavior.no_assets` | behavior | 2.0 | Many page views and no CSS/JS/image requests |
| `network.hosting_asn` | network | 2.0 | Client in a listed ASN (needs an ASN source) |
| `fingerprint.known_bad` | fingerprint | 5.0 | Known-bad TLS fingerprint (needs a TLS-aware front) |

Override any weight in `[weights]`. Signals that can't be evaluated on a deployment stay silent rather than adding suspicion.

## Challenge

The challenge page collects browser signals (`navigator.webdriver`, a `HeadlessChrome` user agent, a zero-size window) and reports them to `/.bl/report` with a short-lived challenge token. Clean browsers get a pass cookie, which is bound to the client IP and expires after `pass_ttl_secs`. Automation flags trap the client for the same period, even if it holds a cookie. Clients that don't run the page never get the cookie. The report is spoofable, so it raises the cost of automation without proving a real browser.

Anyone who lands in the maze by mistake can use the "Not a bot? Verify here." link on any maze page to clear the trap.

## Robots.txt

Botlocker appends this rule to your origin's `robots.txt`, or serves it alone if the origin has none:

```txt
User-agent: *
Disallow: /maze/
```

Compliant crawlers never enter the maze.

## Checking it works

```sh
# Browser profile: should return your site.
curl -A "Mozilla/5.0 Chrome/120.0" -H "Sec-Fetch-Site: none" -H "Accept-Language: en-US" -H "Accept: text/html" http://localhost:8080/

# Bare curl: should return the challenge page (contains document.cookie).
curl -s http://localhost:8080/ | grep -c "document.cookie"

# Maze path: should return a noindex page.
curl -sD - -o /dev/null http://localhost:8080/maze/test | grep -i x-robots-tag
```

## nginx module

Botlocker also runs inside nginx as a native module, so you don't need a separate proxy hop. The module runs the same Rust core through a C ABI (`botlocker-core/crates/ffi`).

```sh
nginx/build.sh                  # builds the Rust core and an nginx 1.31.8 with the module
nginx/test/run.sh               # starts that nginx in front of a test origin and checks 18 behaviors
```

Configuration:

```nginx
http {
    botlocker_config      /etc/botlocker/settings/botlocker.toml;  # same TOML as the standalone binary
    botlocker_secret_file /etc/botlocker/secret;           # >= 32 bytes; trailing newline is trimmed

    log_format bl '$remote_addr action=$botlocker_action status=$status "$request"';

    server {
        listen 80;
        location / {
            botlocker on;
            proxy_pass http://127.0.0.1:8000;
            proxy_set_header Accept-Encoding "";      # sub_filter needs uncompressed HTML

            sub_filter_once on;                       # inject the hidden maze link
            sub_filter '</body>' '<a href="$botlocker_honeypot" rel="nofollow" tabindex="-1" aria-hidden="true" style="position:absolute;left:-10000px">&#8203;</a></body>';
        }
    }
}
```

Variables: `$botlocker_action` (`proxied`, `challenged`, `trapped`, or empty) and `$botlocker_honeypot`.

The module needs the Rust static library at `target/release/libbotlocker_ffi.a`, which `nginx/build.sh` builds. Startup fails if the config or secret is invalid, so `nginx -t` catches mistakes.

Limitations of the nginx build:
- Rate and asset counters are per worker process. With N workers, a client's effective limit is about N times higher.
- The honeypot link goes into every HTML response from a `botlocker on` location, including responses to passing visitors. The standalone binary avoids this.
- ASN and TLS fingerprint signals are unavailable.
- The dashboard works from the nginx access log (`--follow-log`). It shows actions but no scores or evidence. See nginx/README.md.
- Tested with nginx 1.31.8 on macOS. Linux is untested.

## Development

```sh
cd botlocker-core
cargo test --workspace
cargo clippy --workspace --all-targets
```

Layout:

- `botlocker-core/crates/core/`: platform-agnostic detection, scoring, challenge tokens, and maze generation. No I/O.
- `botlocker-core/crates/adapter-native/`: axum server, upstream proxy, dashboard API, and the `botlocker` binary. Integration tests in `tests/` run a fake origin behind the proxy.
- `botlocker-core/crates/ffi/`: the C interface used by the nginx module.
- `botlocker-core/crates/adapter-native/ui/`: the dashboard UI (static HTML, CSS, JavaScript), compiled into the binary.
- `nginx/`: the nginx module and the Docker stack.
- `architecture.md`, `product.md`, `manifest.md`: design documents.

## Known gaps

- Cloudflare Worker adapter not built.
- No ASN database, so `network.hosting_asn` never fires natively.
- No TLS-fingerprint front, so `fingerprint.known_bad` never fires natively.
- Verified-crawler checks use configured IP ranges only. Reverse and forward DNS checks are not implemented.
- The client IP comes from the TCP peer. If a CDN or load balancer sits in front, every visitor looks like the same IP and the rate and challenge logic won't work correctly until real-client-IP handling is added.
- Behavior counters and the dashboard history are in memory and reset on restart.
- The dashboard shows at most 100 clients in the graph and keeps the last 500 decisions.
- Maze word lists are compiled in rather than read from `data/maze/`.
- The settings page edits the file, not origin, maze_prefix, verified crawlers, or signal weights. Those stay in the file.
- The standalone binary checks its config file every two seconds. Only the nginx build reads `reload_poll_secs`.
- The dashboard UI is served over plain HTTP on the admin port, with no TLS.
- nginx reloads reset the per-worker behaviour counters and the flagged-browser list. A browser flagged just before a settings save can get one request through.
