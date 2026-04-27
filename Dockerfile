# Hermod daemon container.
#
# Builds both `hermodd` (daemon) and `hermod` (CLI) into a single image.
# The default entrypoint runs the daemon; one-shot operator commands like
# `hermod init` are runnable via `docker run --rm hermod hermod init`.
#
# State (identity, TLS, sqlite) lives at /var/lib/hermod — mount a volume.

FROM rust:1.94-slim-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# Cache deps before pulling source.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin hermodd --bin hermod \
 && strip target/release/hermodd target/release/hermod \
 && mkdir -p /out/state

FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/hermodd /usr/local/bin/hermodd
COPY --from=build /src/target/release/hermod  /usr/local/bin/hermod
# Pre-create the state directory with the runtime UID/GID so that a
# volume mount inherits the right ownership on first attach. Docker
# copies the in-image directory's permissions into the freshly-created
# volume; without this, the runtime user can't write under the
# root-owned default.
COPY --from=build --chown=65532:65532 /out/state /var/lib/hermod

ENV HERMOD_HOME=/var/lib/hermod
ENV HERMOD_DAEMON_LOG=info
# Federation TLS+WSS port (opt-in via [daemon] listen_ws).
EXPOSE 7823
# Optional /healthz + /metrics port (opt-in via [daemon] metrics_listen).
EXPOSE 9690

VOLUME ["/var/lib/hermod"]

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/hermodd"]
