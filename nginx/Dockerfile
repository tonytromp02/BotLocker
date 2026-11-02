# Botlocker with nginx, in three stages:
#   1. build the Rust backend (static library for nginx, plus the backend binary)
#   2. build nginx with the botlocker module compiled in
#   3. copy nginx and the backend binary into a slim runtime image
#
# Build from the repository root (the compose file does this for you):
#   docker build -f nginx/Dockerfile -t botlocker-nginx .

ARG NGINX_VERSION=1.31.8

# ---- 1. Rust backend ----
FROM rust:1-bookworm AS rust
WORKDIR /build/botlocker-core
COPY botlocker-core/ ./
RUN cargo build --release -p botlocker-ffi -p botlocker

# ---- 2. nginx + module ----
FROM debian:bookworm-slim AS nginx-build
ARG NGINX_VERSION
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl \
      libpcre2-dev zlib1g-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN curl -sSfL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" | tar xz

# The module's `config` script expects the repository layout:
#   <repo>/nginx (module), <repo>/botlocker-core/crates/ffi, <repo>/botlocker-core/target/release/*.a
WORKDIR /build/repo
COPY nginx ./nginx
COPY botlocker-core/crates ./botlocker-core/crates
COPY --from=rust /build/botlocker-core/target/release/libbotlocker_ffi.a ./botlocker-core/target/release/libbotlocker_ffi.a

RUN cd "/src/nginx-${NGINX_VERSION}" \
 && ./configure \
      --prefix=/usr/local/nginx \
      --with-http_ssl_module \
      --with-http_sub_module \
      --with-http_realip_module \
      --add-module=/build/repo/nginx \
 && make -j"$(nproc)" \
 && make install

# ---- 3. runtime ----
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libpcre2-8-0 zlib1g libssl3 ca-certificates \
      gettext-base curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --no-create-home --shell /usr/sbin/nologin nginx

COPY --from=nginx-build /usr/local/nginx /usr/local/nginx
# The botlocker binary. It runs the dashboard when BOTLOCKER_DASHBOARD=on. The proxy itself is nginx.
COPY --from=rust /build/botlocker-core/target/release/botlocker /usr/local/bin/botlocker
COPY nginx/docker/nginx.conf.template /etc/botlocker/nginx.conf.template
COPY nginx/docker/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod 0755 /docker-entrypoint.sh

ENV PATH=/usr/local/nginx/sbin:$PATH
EXPOSE 80 9090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS -o /dev/null "http://127.0.0.1:${LISTEN_PORT:-80}/.bl/challenge" || exit 1

STOPSIGNAL SIGQUIT
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
