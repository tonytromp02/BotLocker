# Botlocker core

The Rust part of Botlocker: the detector, the reverse proxy, the dashboard (UI and API), and the C interface the nginx module links against. It is a Cargo workspace with three crates:

- `crates/core`: platform-free detection (scoring, challenge tokens, maze generation). No I/O.
- `crates/adapter-native`: the `botlocker` binary. It runs the proxy, the admin port (dashboard UI, API, and Settings), the config watcher, and the nginx log feed. The UI (`crates/adapter-native/ui/`) is compiled into the binary.
- `crates/ffi`: a C interface over the core, used by the nginx module.

## Build and test

```sh
cd botlocker-core
cargo build --release -p botlocker
cargo test --workspace
cargo clippy --workspace --all-targets
```

## Run the proxy

```sh
cp ../botlocker.example.toml botlocker.toml          # then edit it
export BOTLOCKER_SECRET="$(openssl rand -hex 32)"     # at least 32 bytes
export BOTLOCKER_ADMIN_APIKEY="$(openssl rand -hex 32)"     # at least 32 bytes; the dashboard needs it
./target/release/botlocker --config botlocker.toml
```

The proxy listens on `0.0.0.0:8080`. The dashboard listens on `127.0.0.1:9090`.

To set the origin without editing the file, pass it on the command line. The flag overrides `origin` in the file, including on reloads:

```sh
./target/release/botlocker --config botlocker.toml --origin https://www.example.com
```

## Dashboard only

```sh
./target/release/botlocker --dashboard-only --config botlocker.toml --admin 127.0.0.1:9090   # needs BOTLOCKER_ADMIN_APIKEY
```

Open `http://localhost:9090`. Without `--follow-log` it shows no live traffic. Its Settings page still works.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--config` | `botlocker.toml` | The config file. The Settings page edits it. |
| `--origin` | none | Site to proxy to. Overrides `origin` in the file. Not written back. |
| `--listen` | `0.0.0.0:8080` | The proxy address. |
| `--admin` | `127.0.0.1:9090` | The dashboard address (UI, with `/api` forwarded to the API). Must be loopback unless `--allow-remote-admin`. |
| `--api-listen` | `127.0.0.1:9091` | The internal API the admin port forwards to. Always loopback. |
| `--dashboard-host` | none | Extra `Host` value the dashboard accepts, as `host:port`. Repeatable. Needed for LAN access. |
| `--follow-log` | none | Follow an nginx access log written in the `botlocker_json` format. |
| `--dashboard-only` | off | Run only the dashboard, without the proxy. |
| `--allow-remote-admin` | off | Permit a non-loopback `--admin`. Only inside a container with a loopback-only port. |

## Docker

```sh
cd botlocker-core
cp .env.example .env                 # set BOTLOCKER_ADMIN_APIKEY
docker compose up -d --build         # dashboard at http://127.0.0.1:9090
```

The compose file mounts `./settings` as the config folder, so put `botlocker.toml` there. Set `BACKEND_PORT` in `.env` to change the published port. The `nginx` stack in `../nginx` runs the proxy and the same dashboard against live traffic.

## Dashboard API

| Method | Path | Notes |
|---|---|---|
| GET | `/` | The dashboard UI. No key needed. |
| GET | `/api/summary` | Counts. |
| GET | `/api/clients` | Clients, with `captured_because`, `trap_reasons`, and `captured_evidence`. |
| GET | `/api/events?limit=N` | Recent decisions, newest first. |
| GET | `/api/graph` | Nodes and edges for the connections graph. |
| GET | `/api/audit` | Settings changes, newest first. |
| GET | `/api/settings` | The current config. |
| PUT | `/api/settings` | Validates, saves, and audits a config. |

The admin port (`--admin`) serves the UI and forwards `/api` to the API on `--api-listen` (loopback only, default `127.0.0.1:9091`), adding the `X-Botlocker-Key` header on the server. Direct requests to the API need the key. The admin port accepts only loopback `Host` values, or those listed with `--dashboard-host`.
