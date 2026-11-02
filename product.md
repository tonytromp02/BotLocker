# Botlocker Product

## Overview

Botlocker is a reverse proxy placed in front of an origin website. It classifies each incoming request. Humans and verified good bots pass through to the origin untouched. Suspected abusive bots are routed into an endless maze of generated pages that never ends and never leads to real content.

It is deployable in two ways with the same core logic:

- **Cloudflare Worker** at the edge, stateless by default.
- **Local or self-hosted** native binary (or container image), for running on your own infrastructure.

Both deployments run the same Rust core. See `architecture.md` for the full design.

## Request flow

1. Request arrives at the proxy.
2. **Allowlist check.** Verified good crawlers (for example, search engines) are proxied to the origin.
3. **Score.** Detection signals are combined into a bot score.
4. **Decide.**
   - Score below threshold: proxy to origin.
   - Score at or above threshold: route to the maze.

## Detection signals

- Honeypot links that are hidden from humans and disallowed in `robots.txt`. Following one is a strong signal.
- Request rate and navigation pattern anomalies.
- Missing, inconsistent, or suspicious headers and User-Agent.
- No evidence of JavaScript or cookie handling where a browser would show it.
- Known-bad User-Agent, ASN, or IP lists.
- `robots.txt` violations.
- TLS and HTTP/2 fingerprints (JA3/JA4 and similar) that identify client libraries. These are available only in the native deployment, behind a TLS-aware fronting proxy. Cloudflare Workers do not expose the raw TLS handshake, so this signal is absent there.

Signals are weighted and summed into a score. The threshold is configurable. A signal that a deployment can't evaluate is treated as absent, never as suspicious.

## The maze

- Pages are generated deterministically from a seeded hash of the URL path. The same path always yields the same page, so no storage is needed.
- Each page contains plausible filler text and many links to further generated pages. The maze is effectively infinite and cheap to serve.
- Optional slow-drip responses hold connections open to waste the bot's time.
- The maze lives under a dedicated path prefix.

## Safety rails

- **Verified crawler allowlist** using published IP ranges on both deployments, plus reverse and forward DNS checks on the native deployment only.
- **`robots.txt`** disallows the maze prefix, so compliant crawlers never enter it.
- **`noindex`** headers on all maze pages, so generated content never gets indexed.
- **Resource caps** per trapped request for bandwidth and CPU time.
- **Kill switch** to disable trapping instantly and fall back to pass-through.
- **Escape path** so a misclassified human can clear their own classification.

## Configuration

- Origin URL
- Detection threshold and signal weights
- Good-crawler allowlist
- Maze path prefix
- Delay and slow-drip settings
- Resource caps and kill switch

- **Settings page.** The dashboard's Settings tab edits the config file. Saves are validated, written atomically, and audited. The proxy reloads within seconds. `origin`, `maze_prefix`, verified crawlers, and signal weights stay in the file.

## Observability

- Count of trapped requests
- Estimated time and bytes spent by trapped bots
- Top offending IPs and User-Agents
- Count of allowlisted and passed-through requests, for sanity checks

## Roadmap

- Shared IP reputation across deployments
- A simple dashboard
- Fingerprints for known LLM crawlers
