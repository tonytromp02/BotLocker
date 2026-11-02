#!/usr/bin/env python3
"""Black-box tests for a running Botlocker deployment.

Works against the standalone binary, the nginx module, or the Docker image.
Only the standard library is needed.

Usage:
    python3 scripts/test_botlocker.py https://example.com
    python3 scripts/test_botlocker.py http://localhost:8080 --maze-prefix /maze/

Exit status is 0 when every check passes, 1 when any check fails.
Warnings do not fail the run. They flag things that depend on your setup,
such as robots.txt.
"""

import argparse
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Chrome/120.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": "document",
}
SCRAPER_HEADERS = {
    "User-Agent": "python-requests/2.31.0",
    "Accept": "*/*",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return 3xx responses as they are, instead of following them."""

    # Parameter names must match the base class, so these stay as they are.
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None


class Result:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body


class Tester:
    def __init__(self, base_url, maze_prefix, timeout, verify_tls, check_automation=False):
        self.base = base_url.rstrip("/")
        self.check_automation = check_automation
        self.maze_prefix = maze_prefix
        self.timeout = timeout
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            NoRedirect, urllib.request.HTTPSHandler(context=ctx))
        self.passed = 0
        self.failed = 0
        self.warned = 0

    # ---------- HTTP ----------
    def get(self, path, headers=None):
        url = self.base + path
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return Result(resp.status, resp.headers, body)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return Result(e.code, e.headers, body)

    # ---------- reporting ----------
    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            print(f"PASS  {name}")
        else:
            self.failed += 1
            print(f"FAIL  {name}" + (f"  ({detail})" if detail else ""))

    def warn(self, name, detail=""):
        self.warned += 1
        print(f"WARN  {name}" + (f"  ({detail})" if detail else ""))

    # ---------- checks ----------
    def run(self):
        print(f"Testing {self.base}\n")

        self.check_reachable()
        self.check_browser_passes_through()
        self.check_honeypot_link()
        challenge_token = self.check_scraper_is_challenged()
        self.check_challenge_endpoint()
        self.check_pass_cookie(challenge_token)
        self.check_maze_is_trapped()
        self.check_maze_stays_out_of_search()
        self.check_robots_txt()
        if self.check_automation and challenge_token:
            self.check_automation_flag(challenge_token)

        print()
        print(f"passed: {self.passed}  failed: {self.failed}  warnings: {self.warned}")
        return 0 if self.failed == 0 else 1

    def check_reachable(self):
        try:
            r = self.get("/", BROWSER_HEADERS)
            self.check("server responds", r.status < 500, f"HTTP {r.status}")
        except OSError as e:
            self.check("server responds", False, str(e))
            # Nothing else can pass without a server, so stop here.
            raise SystemExit(self.summary_and_exit())

    def summary_and_exit(self):
        print(f"\npassed: {self.passed}  failed: {self.failed}  warnings: {self.warned}")
        return 1

    def check_browser_passes_through(self):
        r = self.get("/", BROWSER_HEADERS)
        self.check("browser gets the site (no challenge)",
                   r.status < 400 and "document.cookie" not in r.body,
                   f"HTTP {r.status}")
        self.check("browser page is not marked noindex",
                   "noindex" not in r.headers.get("x-robots-tag", ""))

    def check_honeypot_link(self):
        r = self.get("/", BROWSER_HEADERS)
        if "</body>" not in r.body.lower():
            self.warn("honeypot link", "page has no </body>, nothing to check")
            return
        pattern = re.escape(self.maze_prefix) + r"[^\"']+"
        m = re.search(r'href="(' + pattern + r')"', r.body)
        if not m:
            self.warn("honeypot link",
                      "no hidden maze link found; add sub_filter or enable inject_honeypot")
            return
        self.check("honeypot link is present in HTML", True)

        trap = self.get(m.group(1), BROWSER_HEADERS)
        self.check("honeypot link leads to the maze",
                   "noindex" in trap.headers.get("x-robots-tag", ""),
                   f"HTTP {trap.status}")

    def check_scraper_is_challenged(self):
        r = self.get("/", SCRAPER_HEADERS)
        challenged = "document.cookie" in r.body
        self.check("scraper gets the challenge page", challenged,
                   "got the site instead; the detector may be too lenient for this client")
        if not challenged:
            return None
        m = re.search(r'var TOKEN = "([^"]+)"', r.body)
        self.check("challenge page carries a challenge token", m is not None)
        return m.group(1) if m else None

    def check_challenge_endpoint(self):
        r = self.get("/.bl/challenge?next=/articles/x", BROWSER_HEADERS)
        self.check("challenge endpoint returns the redirect page",
                   'var NEXT = "/articles/x";' in r.body, f"HTTP {r.status}")

        r = self.get("/.bl/challenge?next=https://evil.example", BROWSER_HEADERS)
        self.check("challenge endpoint refuses off-site redirects",
                   'var NEXT = "/";' in r.body)

        r = self.get("/.bl/challenge?next=//evil.example", BROWSER_HEADERS)
        self.check("challenge endpoint refuses protocol-relative redirects",
                   'var NEXT = "/";' in r.body)

    def check_pass_cookie(self, challenge_token):
        if not challenge_token:
            self.warn("pass cookie escape", "no challenge token from the page; skipped")
            return
        # Clean browser signals earn the pass token from the report endpoint.
        rep = self.get(f"/.bl/report?t={challenge_token}&w=0&h=0&z=0")
        m = re.search(r'"token":"([^"]+)"', rep.body)
        self.check("clean browser report earns a pass token", m is not None, rep.body[:80])
        if not m:
            return
        token = m.group(1)
        headers = dict(SCRAPER_HEADERS, Cookie=f"bl_pass={token}")
        r = self.get("/", headers)
        self.check("valid pass cookie lets the client through",
                   "document.cookie" not in r.body and r.status < 400,
                   f"HTTP {r.status}")

        forged = dict(SCRAPER_HEADERS, Cookie="bl_pass=9999999999.deadbeef")
        r = self.get("/", forged)
        self.check("forged pass cookie is rejected",
                   "document.cookie" in r.body, f"HTTP {r.status}")

    def check_maze_is_trapped(self):
        r = self.get(self.maze_prefix + "test-trap-path", BROWSER_HEADERS)
        self.check("maze path is served with noindex header",
                   "noindex" in r.headers.get("x-robots-tag", ""))
        self.check("maze page is marked noindex in HTML",
                   'name="robots" content="noindex' in r.body)
        self.check("maze page does not show the real site",
                   "document.cookie" not in r.body and r.status == 200,
                   f"HTTP {r.status}")
        deep = self.get(self.maze_prefix + "a/b/c/d", SCRAPER_HEADERS)
        self.check("maze works for scrapers too",
                   'name="robots" content="noindex' in deep.body and deep.status == 200)

    def check_maze_stays_out_of_search(self):
        r = self.get(self.maze_prefix + "x1", SCRAPER_HEADERS)
        links = re.findall(r'href="([^"]+)"', r.body)
        in_maze = [h for h in links if h.startswith(self.maze_prefix + "x1/")]
        self.check("maze links point deeper into the maze", len(in_maze) >= 2,
                   f"found {len(links)} links")

    def check_automation_flag(self, challenge_token):
        # Flags this client for pass_ttl_secs, so every later check from this IP would
        # see it as automated. That is why this check is opt-in and runs last.
        rep = self.get(f"/.bl/report?t={challenge_token}&w=1&h=0&z=0")
        self.check("navigator.webdriver report flags automation", '"automated":true' in rep.body, rep.body[:80])

    def check_robots_txt(self):
        r = self.get("/robots.txt", BROWSER_HEADERS)
        if r.status != 200:
            self.warn("robots.txt", f"HTTP {r.status}; add 'Disallow: {self.maze_prefix}' yourself")
            return
        if self.maze_prefix in r.body and "Disallow" in r.body:
            self.check("robots.txt disallows the maze", True)
        else:
            self.warn("robots.txt does not disallow the maze",
                      f"add 'Disallow: {self.maze_prefix}' for compliant crawlers")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url", help="base URL of the protected site, e.g. https://example.com")
    parser.add_argument("--maze-prefix", default="/maze/",
                        help="maze path prefix from your config (default: /maze/)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="per-request timeout in seconds (default: 10)")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS certificate verification (self-signed certificates)")
    parser.add_argument("--check-automation", action="store_true",
                        help="also test that a webdriver report flags the client (blocks this IP for pass_ttl; run last)")
    args = parser.parse_args()

    parsed = urllib.parse.urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        parser.error("url must start with http:// or https:// and include a host")
    if not args.maze_prefix.startswith("/") or not args.maze_prefix.endswith("/"):
        parser.error("--maze-prefix must start and end with '/'")

    tester = Tester(args.url, args.maze_prefix, args.timeout, verify_tls=not args.insecure,
                    check_automation=args.check_automation)
    try:
        return tester.run()
    except SystemExit as e:
        return e.code


if __name__ == "__main__":
    sys.exit(main())
