# Botlocker backend: the dashboard API (and, with a config, the proxy), built from source.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p botlocker

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/botlocker /usr/local/bin/botlocker
ENTRYPOINT ["/usr/local/bin/botlocker"]
