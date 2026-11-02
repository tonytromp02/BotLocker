#!/bin/sh
# Renders the nginx config from the template, checks it, then starts nginx.
#
# Required:
#   ORIGIN_URL            where your site really runs, e.g. http://app:8000
# Optional:
#   SERVER_NAME           host name nginx answers to (default: _, any host)
#   LISTEN_PORT           port inside the container (default: 80)
#   BOTLOCKER_CONFIG     TOML config path (default: /etc/botlocker/settings/botlocker.toml)
#   BOTLOCKER_SECRET_FILE  secret file path (default: /run/secrets/botlocker_secret)
#   BOTLOCKER_DASHBOARD   on | off (default off). on starts the dashboard on port 9090 in this container.
#   BOTLOCKER_ADMIN_APIKEY  required when BOTLOCKER_DASHBOARD=on (at least 32 bytes)
#   EVENT_LOG_FILE        JSON decision log (default /var/log/botlocker/events.jsonl when the dashboard is on)
set -eu

: "${ORIGIN_URL:?set ORIGIN_URL to your site's address, e.g. http://app:8000}"
SERVER_NAME="${SERVER_NAME:-_}"
LISTEN_PORT="${LISTEN_PORT:-80}"
CONFIG_FILE="${BOTLOCKER_CONFIG:-/etc/botlocker/settings/botlocker.toml}"
SECRET_FILE="${BOTLOCKER_SECRET_FILE:-/run/secrets/botlocker_secret}"

if [ ! -r "$CONFIG_FILE" ]; then
    echo "botlocker: config not found at $CONFIG_FILE (mount the settings folder there)" >&2
    exit 1
fi
if [ ! -r "$SECRET_FILE" ]; then
    echo "botlocker: secret not found at $SECRET_FILE (create it and mount it as a secret)" >&2
    exit 1
fi

# Optional dashboard, in this container. Off unless BOTLOCKER_DASHBOARD=on.
DASHBOARD="${BOTLOCKER_DASHBOARD:-off}"
case "$DASHBOARD" in
    on)
        : "${BOTLOCKER_ADMIN_APIKEY:?set BOTLOCKER_ADMIN_APIKEY in .env to turn the dashboard on}"
        # The dashboard reads the JSON decision log, so turning it on turns the log on.
        EVENT_LOG_FILE="${EVENT_LOG_FILE:-/var/log/botlocker/events.jsonl}"
        ;;
    off) ;;
    *)
        echo "botlocker: BOTLOCKER_DASHBOARD must be on or off, not '$DASHBOARD'" >&2
        exit 1
        ;;
esac

# Optional JSON event log, read by the dashboard. Off unless EVENT_LOG_FILE is set.
if [ -n "${EVENT_LOG_FILE:-}" ]; then
    mkdir -p "$(dirname "$EVENT_LOG_FILE")"
    chown nginx:nginx "$(dirname "$EVENT_LOG_FILE")"
    EVENT_LOG_DIRECTIVE="access_log $EVENT_LOG_FILE botlocker_json;"
else
    EVENT_LOG_DIRECTIVE="# event log off (set EVENT_LOG_FILE to feed the dashboard)"
fi

# Optional robots.txt. Mount your file as ./robots/robots.txt on the host.
ROBOTS_FILE="/etc/botlocker/robots/robots.txt"
if [ -r "$ROBOTS_FILE" ]; then
    ROBOTS_LOCATION="location = /robots.txt {
            alias $ROBOTS_FILE;
            default_type text/plain;
            add_header Cache-Control \"public, max-age=3600\";
        }"
    MAZE_PREFIX=$(sed -n 's/^maze_prefix *= *"\(.*\)".*/\1/p' "$CONFIG_FILE" | head -1)
    if [ -n "$MAZE_PREFIX" ] && ! grep -Eq "^[Dd]isallow:[[:space:]]*${MAZE_PREFIX}" "$ROBOTS_FILE"; then
        echo "botlocker: warning: $ROBOTS_FILE does not contain 'Disallow: $MAZE_PREFIX'; compliant crawlers may enter the maze" >&2
    fi
    echo "botlocker: serving /robots.txt from $ROBOTS_FILE"
else
    ROBOTS_LOCATION="# no robots.txt mounted; /robots.txt is proxied from the origin"
fi

# Optional: proxies in front of BotLocker (for example NPM). Their X-Forwarded-For header gives the
# visitor's IP, but only when the TCP peer is one of these networks. Space-separated CIDRs,
# for example "172.16.0.0/12". Empty = the TCP peer is the client.
TRUSTED_PROXY_DIRECTIVES="# no trusted proxies: the TCP peer is the client IP"
if [ -n "${BOTLOCKER_TRUSTED_PROXIES:-}" ]; then
    TRUSTED_PROXY_DIRECTIVES=""
    for net in $BOTLOCKER_TRUSTED_PROXIES; do
        case "$net" in
            *[!0-9a-fA-F.:/]*|"") echo "botlocker: BOTLOCKER_TRUSTED_PROXIES entry '$net' is not an IP or CIDR" >&2; exit 1 ;;
        esac
        TRUSTED_PROXY_DIRECTIVES="${TRUSTED_PROXY_DIRECTIVES}set_real_ip_from $net;
    "
    done
    TRUSTED_PROXY_DIRECTIVES="${TRUSTED_PROXY_DIRECTIVES}real_ip_header X-Forwarded-For;
    real_ip_recursive on;"
    echo "botlocker: trusting X-Forwarded-For from $BOTLOCKER_TRUSTED_PROXIES"
fi

export ORIGIN_URL SERVER_NAME LISTEN_PORT CONFIG_FILE SECRET_FILE EVENT_LOG_DIRECTIVE ROBOTS_LOCATION TRUSTED_PROXY_DIRECTIVES

# Only the variables listed here are substituted. nginx's own $variables are left alone.
envsubst '${ORIGIN_URL} ${SERVER_NAME} ${LISTEN_PORT} ${CONFIG_FILE} ${SECRET_FILE} ${EVENT_LOG_DIRECTIVE} ${ROBOTS_LOCATION} ${TRUSTED_PROXY_DIRECTIVES}' \
    < /etc/botlocker/nginx.conf.template \
    > /usr/local/nginx/conf/nginx.conf

nginx -t

# Reload nginx when the config changes, so settings saved in the dashboard take effect.
# A change that fails `nginx -t` is skipped, and the running config stays in place.
#
# Two triggers:
#   - The dashboard touches $TRIGGER_FILE on every save. Checked every second, so a save applies at once.
#   - Hand edits to the file are found on a background check every reload_poll_secs (default 15),
#     with +/-20% random jitter so the checks do not line up. Read from the file each time, so a change
#     applies without a restart.
TRIGGER_FILE="$(dirname "$CONFIG_FILE")/.reload-now"

poll_secs() {
    p=$(sed -n 's/^reload_poll_secs *= *\([0-9][0-9]*\).*/\1/p' "$CONFIG_FILE" 2>/dev/null | head -1)
    case "$p" in
        ''|*[!0-9]*) echo 15 ;;
        *) if [ "$p" -lt 5 ]; then echo 5; elif [ "$p" -gt 300 ]; then echo 300; else echo "$p"; fi ;;
    esac
}

reload_if_changed() {
    now_file=$(stat -c %.9Y "$CONFIG_FILE" 2>/dev/null || echo 0)
    [ "$now_file" = "$last" ] && return
    last=$now_file
    if nginx -t >/dev/null 2>&1; then
        nginx -s reload && echo "botlocker: config changed; nginx reloaded"
    else
        echo "botlocker: config changed but nginx -t failed; keeping the running config" >&2
        nginx -t >&2 || true
    fi
    # A failed reload must not stop the watcher (set -e is inherited here).
    return 0
}

watch_config() {
    last=$(stat -c %.9Y "$CONFIG_FILE" 2>/dev/null || echo 0)
    last_trigger=$(stat -c %.9Y "$TRIGGER_FILE" 2>/dev/null || echo 0)
    next_check=0
    while sleep 1; do
        trig=$(stat -c %.9Y "$TRIGGER_FILE" 2>/dev/null || echo 0)
        if [ "$trig" != "$last_trigger" ]; then
            last_trigger=$trig
            reload_if_changed
        fi
        now=$(date +%s)
        if [ "$now" -ge "$next_check" ]; then
            base=$(poll_secs)
            # Random wait between 0.8 and 1.2 times the interval.
            next_check=$(awk -v b="$base" -v n="$now" 'BEGIN { srand(); printf "%d", n + b * 0.8 + rand() * b * 0.4 }')
            reload_if_changed
        fi
    done
}
watch_config &

# The dashboard runs beside nginx. If it stops, it restarts. nginx stays in the foreground as PID 1.
if [ "$DASHBOARD" = on ]; then
    (
        while :; do
            /usr/local/bin/botlocker --dashboard-only --config "$CONFIG_FILE" \
                --admin 0.0.0.0:9090 --allow-remote-admin --follow-log "$EVENT_LOG_FILE" || true
            echo "botlocker: dashboard stopped; restarting in 2 seconds" >&2
            sleep 2
        done
    ) &
    echo "botlocker: dashboard on port 9090"
fi

exec "$@"
