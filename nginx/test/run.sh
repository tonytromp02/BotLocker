#!/bin/sh
# End-to-end test: real nginx with the botlocker module, in front of a plain origin.
# Requires nginx/build.sh to have run first.
set -u

HERE=$(cd "$(dirname "$0")/.." && pwd)
REPO=$(cd "$HERE/.." && pwd)
NGINX="${NGINX:-$HERE/.build/nginx-${NGINX_VERSION:-1.31.8}/objs/nginx}"
PROXY_PORT="${PROXY_PORT:-18080}"
ORIGIN_PORT="${ORIGIN_PORT:-19000}"
TMP=$(mktemp -d /tmp/bl-nginx-test.XXXX)
PASS=0
FAIL=0

if [ ! -x "$NGINX" ]; then
    echo "nginx binary not found at $NGINX; run nginx/build.sh first" >&2
    exit 2
fi

cleanup() {
    if [ -f "$TMP/nginx.pid" ]; then "$NGINX" -c "$TMP/nginx.conf" -s quit >/dev/null 2>&1 || true; fi
    [ -n "${ORIGIN_PID:-}" ] && kill "$ORIGIN_PID" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

check() {
    name="$1"; shift
    if "$@"; then
        echo "PASS  $name"; PASS=$((PASS + 1))
    else
        echo "FAIL  $name"; FAIL=$((FAIL + 1))
    fi
}

# ---------- fixtures ----------
mkdir -p "$TMP/origin" "$TMP/client_body" "$TMP/proxy" "$TMP/logs"
printf '<html><head><title>Shop</title></head><body><h1>Real Origin</h1></body></html>' > "$TMP/origin/index.html"
printf 'x' > "$TMP/origin/app.js"

(cd "$TMP/origin" && exec python3 -I -m http.server "$ORIGIN_PORT" --bind 127.0.0.1 >"$TMP/origin.log" 2>&1) &
ORIGIN_PID=$!

sed "s|^origin = .*|origin = \"http://127.0.0.1:$ORIGIN_PORT\"|" "$REPO/botlocker.example.toml" > "$TMP/botlocker.toml"
openssl rand -hex 32 > "$TMP/secret"

write_conf() {
    # $1 = output file, $2 = secret file path
    cat > "$1" <<EOF
pid $TMP/nginx.pid;
error_log $TMP/error.log info;
events { worker_connections 256; }
http {
    log_format bl_fmt '\$remote_addr action=\$botlocker_action status=\$status "\$request" ua="\$http_user_agent"';
    access_log $TMP/access.log bl_fmt;
    log_format botlocker_json escape=json '{"ip":"\$remote_addr","action":"\$botlocker_action","reason":"\$botlocker_reason","evidence":"\$botlocker_evidence","path":"\$uri","ua":"\$http_user_agent"}';
    access_log $TMP/events.jsonl botlocker_json;
    client_body_temp_path $TMP/client_body;
    proxy_temp_path $TMP/proxy;

    botlocker_config $TMP/botlocker.toml;
    botlocker_secret_file $2;

    server {
        listen 127.0.0.1:$PROXY_PORT;

        location / {
            botlocker on;
            proxy_pass http://127.0.0.1:$ORIGIN_PORT;
            proxy_set_header Accept-Encoding "";

            sub_filter_once on;
            sub_filter '</body>' '<a href="\$botlocker_honeypot" rel="nofollow" tabindex="-1" aria-hidden="true" style="position:absolute;left:-10000px">&#8203;</a></body>';
        }
    }
}
EOF
}

# ---------- config validation ----------
write_conf "$TMP/nginx.conf" "$TMP/secret"
printf 'short' > "$TMP/short-secret"
write_conf "$TMP/bad-secret.conf" "$TMP/short-secret"
write_conf "$TMP/missing-secret.conf" "$TMP/does-not-exist"

check "nginx -t accepts valid config" "$NGINX" -t -c "$TMP/nginx.conf" -p "$TMP/"
check "nginx -t rejects a secret shorter than 32 bytes" sh -c "! '$NGINX' -t -c '$TMP/bad-secret.conf' -p '$TMP/' 2>/dev/null"
check "nginx -t rejects a missing secret file" sh -c "! '$NGINX' -t -c '$TMP/missing-secret.conf' -p '$TMP/' 2>/dev/null"

# ---------- start ----------
"$NGINX" -c "$TMP/nginx.conf" -p "$TMP/" || { echo "nginx failed to start"; cat "$TMP/error.log"; exit 1; }
sleep 1

BASE="http://127.0.0.1:$PROXY_PORT"
BROWSER_UA="Mozilla/5.0 (Macintosh) Chrome/120.0 Safari/537.36"
BROWSER_HDRS="-H Accept:text/html -H Accept-Language:en-US -H Sec-Fetch-Site:none"

browser() { curl -s -A "$BROWSER_UA" -H "Accept: text/html" -H "Accept-Language: en-US" -H "Sec-Fetch-Site: none" "$@"; }
scraper() { curl -s -A "python-requests/2.31" -H "Accept: */*" "$@"; }

# ---------- behavior ----------
HOME_BODY="$TMP/home.html"
browser "$BASE/" > "$HOME_BODY"
check "browser reaches origin" grep -q "Real Origin" "$HOME_BODY"

check "honeypot link is injected for scored visitors" grep -q 'href="/maze/' "$HOME_BODY"

HONEYPOT_HREF=$(grep -o 'href="/maze/[^"]*"' "$HOME_BODY" | head -1 | cut -d'"' -f2)
check "injected honeypot link leads into the maze" sh -c "curl -s -D - -o /dev/null -A '$BROWSER_UA' -H 'Accept: text/html' -H 'Accept-Language: en-US' -H 'Sec-Fetch-Site: none' '$BASE$HONEYPOT_HREF' | grep -qi 'x-robots-tag: noindex, nofollow'"

TRAP_HEADERS="$TMP/trap.headers"
TRAP_BODY="$TMP/trap.html"
browser -D "$TRAP_HEADERS" "$BASE/maze/abc" > "$TRAP_BODY"
check "maze path returns a noindex trap page" grep -qi "x-robots-tag: noindex, nofollow" "$TRAP_HEADERS"
check "maze page does not leak origin content" sh -c "! grep -q 'Real Origin' '$TRAP_BODY'"

CHALLENGE_BODY="$TMP/challenge.html"
scraper "$BASE/" > "$CHALLENGE_BODY"
check "scraper gets the challenge page" grep -q "document.cookie" "$CHALLENGE_BODY"

ENDPOINT_BODY="$TMP/endpoint.html"
browser "$BASE/.bl/challenge?next=/articles/x" > "$ENDPOINT_BODY"
check "challenge endpoint redirects to a safe next path" grep -q 'var NEXT = "/articles/x";' "$ENDPOINT_BODY"

ESCAPE_BODY="$TMP/escape.html"
browser "$BASE/.bl/challenge?next=https://evil.example" > "$ESCAPE_BODY"
check "challenge endpoint refuses an off-site next" grep -q 'var NEXT = "/";' "$ESCAPE_BODY"

CHALLENGE_TOKEN=$(sed -n 's/.*var TOKEN = "\([^"]*\)".*/\1/p' "$CHALLENGE_BODY" | head -1)
check "challenge page carries a challenge token" test -n "$CHALLENGE_TOKEN"
TOKEN=$(curl -s -A 'python-requests/2.31' -H 'Accept: */*' "$BASE/.bl/report?t=$CHALLENGE_TOKEN&w=0&h=0&z=0" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
check "clean browser report earns a pass token" test -n "$TOKEN"
check "pass cookie lets the scraper through to the origin" sh -c "curl -s -A 'python-requests/2.31' -H 'Accept: */*' -H 'Cookie: bl_pass=$TOKEN' '$BASE/' | grep -q 'Real Origin'"

check "static asset passes through to the origin" sh -c "curl -s -A '$BROWSER_UA' -H 'Accept: */*' -H 'Accept-Language: en-US' -H 'Sec-Fetch-Site: same-origin' '$BASE/app.js' | grep -qx 'x'"

# ---------- observability ----------
sleep 1
check "access log records proxied decisions" grep -q "action=proxied" "$TMP/access.log"
check "access log records challenged decisions" grep -q "action=challenged" "$TMP/access.log"
check "access log records trapped decisions" grep -q "action=trapped" "$TMP/access.log"

check "trapped requests never reach the origin" sh -c "! grep -q 'GET /maze/' '$TMP/origin.log'"
check "challenge endpoint never reaches the origin" sh -c "! grep -q 'GET /.bl/' '$TMP/origin.log'"
check "event log records the trap reason" grep -q '"reason":"honeypot"' "$TMP/events.jsonl"
check "event log records the decision evidence" grep -q "maze prefix" "$TMP/events.jsonl"
check "nginx error log has no errors or alerts" sh -c "! grep -qE '\\[(error|crit|alert|emerg)\\]' '$TMP/error.log'"

AUTO_REPORT=$(curl -s "$BASE/.bl/report?t=$CHALLENGE_TOKEN&w=1&h=0&z=0")
check "automation flag is reported" sh -c "echo '$AUTO_REPORT' | grep -q automated"

echo ""
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
