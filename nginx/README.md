# Run Botlocker in front of your site (nginx + Docker)

This guide puts Botlocker in front of an existing website. Visitors and good crawlers reach your site as before. Scrapers get a challenge, and if they keep crawling they are trapped in a maze of generated pages.

```
 visitors / search engines ──► [ Botlocker (nginx) :8080 ] ──► your site (ORIGIN_URL)
 scrapers                       │ challenge page
                                └ maze pages (never reach your site)
```

## What you need

- Docker with Compose v2 (`docker compose version`)
- Your site running somewhere reachable from the container. That is `http://host.docker.internal:PORT` for a site on the same machine, or the service name for a site in another Compose project or in this file. Without your own site, the stack protects the bundled project page (the `website` service, built from `../webpage`).
- `openssl`, to create the signing secret

## 1. Point it at your site

Run everything in this `nginx/` folder.

```sh
cp .env.example .env
```

Edit `.env`:

| Setting | What to put |
|---|---|
| `SERVER_NAME` | Your domain, e.g. `shop.example.com`. Leave `_` to accept any host name. |
| `HOST_PORT` | The port on your machine that forwards to the proxy (default `8080`) |

Set the site to protect in `docker-compose-nginx.yaml`, in the `botlocker` service, as `ORIGIN_URL`. It defaults to the bundled project page: `http://website:80`. Use `http://host.docker.internal:3000` for a site on this machine, or `http://app:8000` for another compose service.

## 2. Create the signing secret

The secret signs the pass cookies and seeds the maze. Keep it private and do not commit it.

```sh
mkdir -p secrets
openssl rand -hex 32 > secrets/botlocker_secret
```

Changing the secret logs every visitor out of the challenge, which is harmless. Keep the same secret across restarts so passing visitors stay verified.

## 3. Tune detection (optional)

The detector's settings live in `settings/botlocker.toml`. The defaults are conservative. You can change them in two ways:

- **Dashboard (recommended):** open `http://localhost:9090`, go to the Settings tab, edit, and save. Turn on the dashboard first (see "Optional: live dashboard" below).
- **File:** edit `settings/botlocker.toml` directly.

The settings you are most likely to change:

```toml
challenge_at = 3.0         # score that triggers the challenge page
trap_at      = 6.0         # score that sends a visitor into the maze (needs 2+ signal types)
kill_switch  = false       # true = pass everything through, disable trapping instantly

[behavior]
max_requests = 120         # requests per minute per client before the rate signal fires
```

Saves from the dashboard Settings page apply at once. Hand edits to the file are picked up on the next background check, every `reload_poll_secs` seconds (default 15, set it on the Settings page too, range 5 to 300, with random jitter). Nothing needs a restart. A change that fails validation is skipped, and the running config stays in place.

Keep `maze_prefix` in the file, not the dashboard. The `robots.txt` rule depends on it.

## 4. Start it

```sh
docker compose -f docker-compose-nginx.yaml up -d --build
docker compose -f docker-compose-nginx.yaml ps        # STATUS should say "healthy"
```

Open `http://localhost:8080`. You should see your site as usual.

## 5. Check that it works

The test script runs black-box checks against any running URL. It needs only Python 3.

```sh
python3 ../scripts/test_botlocker.py http://localhost:8080
python3 ../scripts/test_botlocker.py https://shop.example.com --maze-prefix /maze/
python3 ../scripts/test_botlocker.py https://localhost:8443 --insecure   # self-signed certificate
```

It exits 0 when every check passes and 1 when one fails. Warnings are not failures. They point to setup you may still need to do, such as the `robots.txt` rule in step 7.

## 6. Send your domain to the proxy

Botlocker listens on port 80 inside the container, with plain HTTP. Put your domain's DNS or load balancer in front of it.

- **HTTPS:** terminate TLS in front of Botlocker. Options include Cloudflare (proxied DNS), a cloud load balancer, or a reverse proxy such as Caddy or Traefik that forwards to `http://<host>:8080`. Botlocker does not handle certificates itself.
- **Client IPs:** if a load balancer or CDN sits in front, Botlocker sees that machine's IP, not the visitor's. Rate limits and challenges then apply to everyone at once. Real-client-IP handling is not implemented yet. Point DNS directly at the proxy, or wait for that support, before relying on the rate signal.

## 7. Tell compliant crawlers to stay out of the maze

The maze path must be disallowed in `robots.txt`, so polite crawlers never enter it. You have two options.

**Option A: serve a robots.txt from this stack.** Copy the example and edit it:

```sh
cp robots/robots.txt.example robots/robots.txt
```

The proxy then serves `robots/robots.txt` at `/robots.txt`. Restart the stack. At startup it warns if the file lacks the maze rule.

**Option B: keep the origin's robots.txt.** If `robots/robots.txt` is absent, `/robots.txt` is proxied from your site. Add this rule to the origin's file, or create one there:

```txt
User-agent: *
Disallow: /maze/
```

Then re-run the test script. The `robots.txt` warning should go away.

## Optional: live dashboard

The dashboard shows the same connections graph, captured-bot list, and live feed as the standalone botlocker. It runs in the same container as nginx. It is off by default. Turn it on in two steps:

```sh
# 1. In nginx/.env, set these (the key must be at least 32 bytes):
BOTLOCKER_DASHBOARD=on
BOTLOCKER_ADMIN_APIKEY=<openssl rand -hex 32>

# 2. Restart the stack:
docker compose -f docker-compose-nginx.yaml up -d --build
```

Open `http://localhost:9090`. The botlocker binary serves the UI and the API on this port, separate from the proxied site. The port is published to 127.0.0.1 only. Change it with `DASHBOARD_PORT` in `.env`.

The page needs no key. The server adds `BOTLOCKER_ADMIN_APIKEY` when it forwards requests to the API, so the browser never holds it. The dashboard only accepts the `Host` values `localhost` and `127.0.0.1`, so to reach it from another machine, use an SSH tunnel.

How it works: nginx writes one JSON line per request to `EVENT_LOG_FILE`, which defaults to `/var/log/botlocker/events.jsonl` when the dashboard is on. The dashboard process inside the same container follows that file. It restarts itself if it stops. Turning the dashboard off means setting `BOTLOCKER_DASHBOARD=off` and restarting the stack.

What the feed does and does not show:
- Shows: every request, its action (`proxied`, `challenged`, `trapped`), the client IP and user agent, and the captured-bot view.
- Captured view: each captured client lists why it was captured (honeypot hit, automated browser, or the signal score) and the evidence lines. The evidence for a score includes the score, the threshold, and the signals that fired.
- Routing: any detected bot is sent to the maze. Challenges are only for visitors who are not yet classified.
- The dashboard shows up to the last 1 MB of the log on start, and then keeps following it.

### Settings page

The Settings tab edits `settings/botlocker.toml`, the same file nginx reads.

- **Saves are checked** with the same rules as the file. A rejected save changes nothing, and the page shows why.
- **Changes apply on their own.** A save applies at once: the dashboard touches a trigger file that the nginx entrypoint checks every second. Hand edits are found on the background check (`reload_poll_secs`). Either way nginx reloads only after a change that passes `nginx -t`.
- **Audit:** "Recent changes" lists every saved change with its old and new values.
- **Read-only here:** `maze_prefix`, verified crawlers, and signal weights. Edit those in `settings/botlocker.toml`. The origin is `ORIGIN_URL` in `docker-compose-nginx.yaml`.
- **Write protection:** saving needs `BOTLOCKER_ADMIN_APIKEY`, the same key the rest of the API needs. The browser holds it for the session only. Writes without the key are refused.

## Day-to-day

| Task | Command |
|---|---|
| See decisions live | `docker compose -f docker-compose-nginx.yaml logs -f` (each line ends `action=proxied`, `action=challenged`, or `action=trapped`) |
| Pass everything through instantly | set `kill_switch = true` on the Settings page, or in `settings/botlocker.toml`. It applies within seconds. |
| Stop | `docker compose -f docker-compose-nginx.yaml down` |
| Update after a code change | `docker compose -f docker-compose-nginx.yaml up -d --build` |

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `host not found` in the container logs | `ORIGIN_URL` names a host the container can't resolve. Check the name in `docker-compose-nginx.yaml`, under the `botlocker` service `environment`. |
| Container exits with `secret not found` | Run step 2 so `secrets/botlocker_secret` exists. |
| Container exits with `config not found` | `settings/botlocker.toml` is missing from `nginx/`. |
| `502 Bad Gateway` | nginx cannot reach `ORIGIN_URL`. Check the address from inside the container: `docker compose -f docker-compose-nginx.yaml exec botlocker curl -sI $ORIGIN_URL`. |
| `host.docker.internal` does not resolve on Linux | The compose file maps it with `host-gateway`. Make sure your site listens on `0.0.0.0`, not only `127.0.0.1`. |
| A real visitor sees the maze | Raise `trap_at` on the Settings page, or in `settings/botlocker.toml`. Watch `action=trapped` lines in the logs, and the Captured view for the reason. |
| Scrapers reach your site unchallenged | Expected for scrapers that send real browser headers. The detector is one layer, not a guarantee. |

## Limits of this build

- **Per-worker counters.** Rate and missing-asset signals count per nginx worker, so the effective limit is higher than the number you set. A settings reload resets them, and it also clears the flagged-browser list, so a browser flagged just before a save can get one request through.
- **Honeypot link on every HTML page** served through the protected location, including to passing visitors.
- **No ASN or TLS-fingerprint signals.** Those need a data source the nginx module does not have.
- **Dashboard without scores.** The optional dashboard (above) shows actions and clients, but not the scores and signals. Only the standalone binary has those.
- **HTTP only inside the container.** Terminate TLS in front of it (step 6).
