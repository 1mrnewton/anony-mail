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

COPY --from=builder /app/target/release/anony-mail /usr/local/bin/anony-mail

# SMTP (25) and HTTP API (8080).
EXPOSE 25 8080

# Default to the embedded SQLite backend, stored under /data. Mount a volume
# there (see docker-compose.yml) so the database survives container recreation.
ENV SMTP_BIND_ADDR=0.0.0.0:25 \
    API_BIND_ADDR=0.0.0.0:8080 \
    DATABASE_URL=sqlite:///data/anony-mail.db \
    RUST_LOG=info

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/anony-mail"]
