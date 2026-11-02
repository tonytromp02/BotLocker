#!/bin/sh
# Builds the Rust core and an nginx binary with the Botlocker module compiled in.
# Usage: nginx/build.sh            (NGINX_VERSION=1.31.8 by default)
set -eu

NGINX_VERSION="${NGINX_VERSION:-1.31.8}"
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
BUILD="$HERE/.build"
JOBS=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

mkdir -p "$BUILD"

echo "==> building Rust core (botlocker-ffi)"
(cd "$REPO/botlocker-core" && cargo build --release -p botlocker-ffi)

SRC="$BUILD/nginx-$NGINX_VERSION"
if [ ! -d "$SRC" ]; then
    echo "==> fetching nginx $NGINX_VERSION"
    curl -sSfL "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz" -o "$BUILD/nginx.tar.gz"
    tar -xzf "$BUILD/nginx.tar.gz" -C "$BUILD"
    rm -f "$BUILD/nginx.tar.gz"
fi

echo "==> configuring nginx with the botlocker module"
cd "$SRC"
./configure \
    --prefix="$BUILD/install-$NGINX_VERSION" \
    --with-http_ssl_module \
    --with-http_sub_module \
    --add-module="$HERE"

echo "==> compiling (jobs: $JOBS)"
make -j"$JOBS"

echo "==> built: $SRC/objs/nginx"
