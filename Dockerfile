# ---- Build stage ----
FROM rust:1-slim-bookworm AS builder

WORKDIR /app

# build-essential provides the C toolchain needed by the `ring` crypto crate.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
# migrations/ must be present at build time: they are embedded into the binary
# via sqlx::migrate!(), so the runtime image needs no migration files.
COPY migrations ./migrations
COPY src ./src

RUN cargo build --release --bin anony-mail

# ---- Runtime stage ----
FROM debian:bookworm-slim AS runtime

# Links the published GHCR package to the source repo (populates the repo's
# "Packages" sidebar) and surfaces metadata on the package page.
LABEL org.opencontainers.image.source="https://github.com/1mrnewton/anony-mail" \
      org.opencontainers.image.description="Inbound-only disposable email (temp mail) backend: SMTP in, REST + SSE out." \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as a dedicated non-root user: a compromised process can't touch the
# host-mapped socket configs, install packages, or escalate inside the
# container. /data is pre-created and owned so the SQLite volume is writable.
RUN groupadd --system --gid 10001 anonymail \
    && useradd --system --uid 10001 --gid anonymail \
       --home-dir /data --no-create-home --shell /usr/sbin/nologin anonymail \
    && mkdir -p /data \
    && chown anonymail:anonymail /data

COPY --from=builder /app/target/release/anony-mail /usr/local/bin/anony-mail

# SMTP (2525) and HTTP API (8080). SMTP defaults to a high port because a
# non-root process cannot bind 25; publish it as `-p 25:2525` (see
# docker-compose.yml). To bind 25 in-container instead, grant the capability
# and override the address:
#   docker run --cap-add NET_BIND_SERVICE --sysctl net.ipv4.ip_unprivileged_port_start=0 \
#     -e SMTP_BIND_ADDR=0.0.0.0:25 ...
EXPOSE 2525 8080

# Default to the embedded SQLite backend, stored under /data. Mount a volume
# there (see docker-compose.yml) so the database survives container recreation.
ENV SMTP_BIND_ADDR=0.0.0.0:2525 \
    API_BIND_ADDR=0.0.0.0:8080 \
    DATABASE_URL=sqlite:///data/anony-mail.db \
    RUST_LOG=info

VOLUME ["/data"]

USER anonymail

ENTRYPOINT ["/usr/local/bin/anony-mail"]
