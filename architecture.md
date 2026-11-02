# Botlocker Architecture (Rust)

## Goals and constraints

- **One core, two targets.** The same detection logic runs as a native binary (local or self-hosted) and as WASM on Cloudflare Workers via `workers-rs`.
- **Stateless by default.** State is optional and bounded by TTL.
- **Humans are never harmed.** Gray-zone traffic is challenged before it is trapped. Every trapped visitor has an escape path.
- **Bounded cost per request.** Caps on CPU time, bytes, and maze depth.
- **WASM size budget.** Workers bundle limits apply. Check current Cloudflare limits before committing to a dependency set.

## Workspace layout

```
botlocker/
├── Cargo.toml                 # workspace
├── botlocker-core/   (Cargo workspace: detector, proxy, dashboard)
│   ├── crates/
│   ├── core/                  # platform-agnostic detection logic
│   │   └── src/
│   │       ├── request.rs     # normalized request model
│   │       ├── signals/       # signal trait + implementations
│   │       ├── scoring.rs     # weighted score, thresholds, decisions
│   │       ├── allowlist.rs   # verified-crawler matching
│   │       ├── honeypot.rs    # hidden links, signed honeypot paths, robots.txt
│   │       ├── behavior.rs    # per-client sliding-window counters
│   │       ├── challenge.rs   # signed challenge tokens
│   │       ├── maze.rs        # deterministic maze page generator
│   │       ├── config.rs      # config schema and validation
│   │       └── metrics.rs     # decision events and counters
│   ├── adapter-worker/        # workers-rs entry, KV/Durable Object state, request.cf mapping
│   └── adapter-native/        # axum + hyper server, reqwest upstream, moka cache
├── data/                      # versioned detection artifacts (see below)
├── tests/
│   ├── fixtures/              # recorded traffic, labeled
│   └── golden/               # expected decisions per fixture
└── deploy/                    # wrangler.toml, Dockerfile
```

## Request pipeline

```
request
  → normalize (request.rs)
  → allowlist check ──verified good crawler──→ proxy to origin
  → honeypot / robots hit ──→ trap (score = max)
  → run signals (signals/*)
  → score (scoring.rs)
  → decide:
       pass      → proxy to origin
       challenge → challenge.rs (cookie/JS token)
       trap      → maze.rs
  → record metrics (metrics.rs)
```

## Detection artifacts

Each artifact lists its source, format, update cadence, and owning module.

| Artifact | Source | Format | Update cadence | Module |
|---|---|---|---|---|
| Normalized request | Incoming HTTP request | Rust struct: method, path, query, headers in original order, client IP, ASN, country, TLS/HTTP2 info when available | Per request | `request.rs` |
| Signal registry | Code | Trait `Signal` returning `{id, weight, evidence}` | Per release | `signals/` |
| Header rules | Curated profiles per browser family | TOML in `data/headers/` | Quarterly, or when browsers change | `signals/headers.rs` |
| Header-order profiles | Captured from real browsers | TOML in `data/headers/` | Quarterly | `signals/headers.rs` |
| Known-bot UA list | Public lists plus our own observations | Line-based text in `data/ua/` | Weekly | `signals/user_agent.rs` |
| Hosting/datacenter ASN list | Public ASN databases | CSV in `data/asn/` | Weekly | `signals/asn.rs` |
| IP reputation feed | External feed, optional | Versioned JSON or KV entries | Daily | `signals/reputation.rs` |
| TLS and HTTP/2 fingerprint table | Captured from real clients | TOML in `data/fingerprints/` | Monthly | `signals/fingerprint.rs` |
| Honeypot registry | Generated at runtime | Signed path set, HMAC key from config | On config change | `honeypot.rs` |
| robots.txt | Generated from config | Text | On config change | `honeypot.rs` |
| Behavioral counters | Runtime state | Per-client sliding windows with TTL | Per request | `behavior.rs` |
| Challenge tokens | Runtime | HMAC-signed, with expiry | Per challenge | `challenge.rs` |
| Verified-crawler ranges | Published IP lists from search engines | JSON, cached | Daily | `allowlist.rs` |
| Maze word lists and templates | Authored | Text in `data/maze/` | On change | `maze.rs` |
| Config | Operator | TOML, validated with `serde` | On change | `config.rs` |
| Metrics and decision log | Runtime | `tracing` events, counters | Per decision | `metrics.rs` |
| Test corpus | Recorded and synthetic | HAR and raw request fixtures | Per release | `tests/fixtures/` |

## Signal design

```rust
pub trait Signal: Send + Sync {
    fn id(&self) -> &'static str;
    fn evaluate(&self, req: &NormalizedRequest, ctx: &ClientContext) -> Option<Hit>;
}

pub struct Hit {
    pub weight: f32,
    pub evidence: String,
}
```

- A signal returns `None` when it can't evaluate (for example, a fingerprint on a platform that doesn't expose it). Missing data is never treated as suspicious.
- The scorer sums weights of fired signals and returns the list of hits, so every decision is explainable.

## Scoring and decisions

- Weighted sum of hits, capped at a maximum.
- Thresholds in config: `challenge_at` and `trap_at`. Defaults are conservative.
- A honeypot hit sets the score to the trap threshold directly, since no human should reach it.
- Trap requires at least two independent signal families, unless a honeypot was hit.

## Signal availability by platform

| Signal | Cloudflare Workers | Native |
|---|---|---|
| User-Agent, header rules | Yes | Yes |
| Header order | No (the Worker sees headers as a map) | Yes |
| ASN and country | Yes, via `request.cf` | Yes, via MaxMind or similar DB |
| Bot score | Only on plans that expose it | No |
| JA3/JA4 TLS fingerprint | No, not exposed to Workers | Yes, behind a TLS-aware fronting proxy |
| HTTP/2 fingerprint | No | Yes, behind a TLS-aware fronting proxy |
| Honeypot, robots.txt | Yes | Yes |
| Behavioral counters | Yes, with KV or Durable Objects | Yes, in memory |
| Verified-crawler DNS check | No (ranges only) | Yes (reverse plus forward DNS) |

**Correction to earlier docs:** Workers cannot see raw TLS handshakes, so JA3/JA4 is not available on the edge. `product.md` implies it is. That line should be updated to say the fingerprinting signal depends on deployment mode.

## State and storage

- **Workers:** KV for allowlists, reputation, and signed key rotation metadata. Durable Objects for per-client behavioral counters, since they need consistency.
- **Native:** `moka` in-memory cache with TTL. Optional Redis later, if multiple instances need shared state.

## Maze generator

- Pages are generated from `HMAC(key, path)` as a seed, so the same path always yields the same page with no storage.
- Templates and word lists from `data/maze/`. Each page contains filler text plus N links (N derived from the seed, bounded by config).
- Optional slow-drip mode streams the body with a configurable delay, within a time cap.
- Every trapped response includes `noindex`, and the maze prefix is disallowed in `robots.txt`.

## Safety rails

- Kill switch in config: when set, all traffic passes through.
- Per-request caps on bytes, CPU time, and slow-drip duration.
- `noindex` on all maze responses. `robots.txt` disallows the maze prefix.
- Challenge before trap for gray-zone scores.
- Escape path: a passed challenge clears the client's trap state.

## Security

- HMAC keys stored as secrets (Workers secrets or env var for native), rotated with a key ID so old tokens expire cleanly.
- No user data stored beyond TTL. Only hashed IPs in counters.
- Proxying is to a fixed origin only (no open proxy, no SSRF).
- Limits on header count, header size, and body size.

## Testing and tuning

- **Golden tests:** labeled fixtures run through the pipeline; expected decisions are checked in CI.
- **Property tests (`proptest`):** maze determinism for a given path and key; link count bounded; no maze page links outside the maze prefix.
- **False-positive budget:** a target rate of human traffic challenged or trapped, measured in staging.
- **Offline replay:** logs can be re-scored with new weights to tune thresholds before deploying.

## Build and deploy

- **Workspace:** `cargo` workspace with `core` shared by both adapters.
- **Edge:** `wrangler` with `worker-build` for the WASM bundle.
- **Native:** single static binary, plus a container image.
- **CI:** `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, WASM build, and a bundle size check against budget.

## Settings and live reload

The config file is the source of truth for both builds. The dashboard edits it, and the proxy picks changes up without a restart.

- **Engine slot.** The standalone proxy holds its engine in an `EngineSlot` (`RwLock<Arc<Engine>>`). Each request takes a cheap `Arc` clone of the current engine. A reload builds a new engine with `Engine::reconfigure`, which shares the behaviour counters and the flagged-browser map (both `Arc`), so a settings change does not reset them.
- **Watcher.** `config_watch` polls the config file's modification time every two seconds. A changed file is parsed and validated with the same rules as startup. A rejected file is logged and the running engine stays in place. Each bad version is reported once.
- **Settings API.** `GET /api/settings` returns the config as JSON. `PUT /api/settings` validates the body (`serde` with `deny_unknown_fields`, then `Config::validate`), writes the file atomically (temp file and rename), and records a diff in the audit log. Every `/api` route needs the `X-Botlocker-Key` header, which must match `BOTLOCKER_ADMIN_APIKEY` (at least 32 bytes, compared in constant time). The dashboard UI is compiled into the binary and served on the admin port, never on the proxy. The admin port is a front: it serves the UI and forwards `/api` to the keyed API on a loopback-only internal listener (`--api-listen`, default `127.0.0.1:9091`), adding the key on the server. The browser never holds the key. The front checks the `Host` header against loopback and `--dashboard-host`, which blocks DNS-rebinding pages.
- **nginx build.** The module reads its config only at startup. The entrypoint polls the file and runs `nginx -s reload` after a change that passes `nginx -t`. Reloading resets per-worker state, including the flagged-browser list. That trade-off is documented.
- **Not editable in the UI:** `origin`, `maze_prefix` (the robots.txt rule depends on it), verified crawlers, and signal weights. The UI shows them read-only.

## Open questions and roadmap

- Shared IP reputation across deployments.
- WASM bundle size budget, once Cloudflare's current limits are confirmed.
- Whether to ship a TLS-aware fronting layer for native deployments that want JA3/JA4.
- A dashboard for metrics and decision logs.
- Fingerprints for known LLM crawlers.
