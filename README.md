# tempmail-backend

An inbound-only, disposable-email (temp mail) backend written in Rust. It
**receives** email over SMTP for throwaway addresses and exposes it to a
frontend over a REST + Server-Sent-Events HTTP API. It does not send mail.

- Hand-rolled async SMTP receiver on `tokio` (EHLO/HELO, MAIL, RCPT, DATA,
  RSET, NOOP, QUIT, VRFY, HELP, optional STARTTLS).
- Recipients are validated at `RCPT TO` against PostgreSQL, so mail to unknown
  or expired addresses is rejected at the SMTP layer instead of being stored.
- MIME parsing via [`mail-parser`](https://crates.io/crates/mail-parser)
  (subject, from, date, text/html bodies, attachments).
- REST API for creating addresses and reading messages, plus an SSE stream that
  pushes a lightweight event the moment a message arrives.
- Background task purges expired mailboxes (messages/attachments cascade).

## Architecture

```
                        ┌─────────────────────────────┐
  external MTA ──SMTP──▶ │ SMTP receiver (tokio)        │──┐
  (port 25, +STARTTLS)   │  validate RCPT · parse MIME  │  │ save
                         └─────────────────────────────┘  ▼
                                                     ┌───────────┐
  frontend ────REST─────▶ ┌──────────────────────┐   │ Postgres  │
  frontend ────SSE──────▶ │ Axum HTTP API (8080)  │──▶└───────────┘
                          └──────────────────────┘        ▲
                                    ▲                      │ purge expired
                          publish/subscribe        ┌──────────────┐
                          (tokio broadcast)        │ cleanup task │
                                                   └──────────────┘
```

All three run as concurrent tasks in one process sharing a single `PgPool`. New
messages are published on a `tokio::sync::broadcast` channel; the SSE endpoint
subscribes and forwards events for the requested address. SSE is a low-latency
*nudge* — the REST inbox listing remains the source of truth for reconciliation.

## Quick start (Docker Compose)

```bash
cp .env.example .env          # optional: values below can also come from compose
docker compose up --build
```

This starts PostgreSQL and the app, running migrations automatically on boot.
Edit `DOMAINS`/`SMTP_HOSTNAME` in `docker-compose.yml` for your real domains.

Then create an address and watch for mail:

```bash
# Create a random disposable address
curl -s -X POST http://localhost:8080/api/addresses | jq
# => { "address": "a1b2c3d4e5@example.com", "domain": "example.com", ... }

# List its messages (empty until mail arrives)
curl -s http://localhost:8080/api/addresses/a1b2c3d4e5@example.com/messages | jq
```

## Local development (without Docker)

Requires a Rust toolchain (edition 2024, i.e. Rust >= 1.85) and a PostgreSQL
instance.

```bash
export DATABASE_URL=postgres://tempmail:tempmail@localhost:5432/tempmail
export DOMAINS=example.com
# Port 25 needs privileges; use a high port locally:
export SMTP_BIND_ADDR=0.0.0.0:2525

cargo run
```

Migrations in `migrations/` are embedded into the binary and run on startup.

Send a test message with any SMTP client (e.g. `swaks`), after creating the
recipient address via the API:

```bash
swaks --server localhost:2525 --to a1b2c3d4e5@example.com --from me@somewhere.test
```

## Configuration

All configuration is via environment variables (see [.env.example](.env.example)).
`DOMAINS` and `DATABASE_URL` are required; everything else has defaults.

| Variable | Default | Description |
| --- | --- | --- |
| `DOMAINS` | — (required) | Comma-separated domains to accept mail for |
| `DATABASE_URL` | — (required) | PostgreSQL connection string |
| `SMTP_BIND_ADDR` | `0.0.0.0:25` | SMTP listener address |
| `API_BIND_ADDR` | `0.0.0.0:8080` | HTTP API listener address |
| `SMTP_HOSTNAME` | first domain | Hostname announced in the SMTP banner/EHLO |
| `DEFAULT_TTL_SECONDS` | `3600` | Mailbox lifetime |
| `CLEANUP_INTERVAL_SECONDS` | `300` | Expiry purge interval |
| `MAX_MESSAGE_SIZE_BYTES` | `26214400` | Max accepted message size (25 MiB) |
| `MAX_RECIPIENTS` | `100` | Max recipients per SMTP transaction |
| `MAX_CONNECTIONS` | `1024` | Max concurrent SMTP connections |
| `SMTP_SESSION_TIMEOUT_SECONDS` | `60` | Per-connection idle timeout |
| `SMTP_PER_IP_CONNECTIONS_PER_MIN` | `60` | Per-IP new-connection rate limit |
| `TLS_CERT_PATH` / `TLS_KEY_PATH` | unset | Enable STARTTLS (PEM files) |
| `CORS_ALLOWED_ORIGINS` | `*` | Comma-separated CORS origins, or `*` |
| `RUST_LOG` | `info` | `tracing` env-filter directive |

## HTTP API

Base path `/api`. Request/response bodies are JSON. Errors are
`{ "error": "message" }` with an appropriate status code.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/healthz` | Health check |
| `GET` | `/api/domains` | List configured domains |
| `POST` | `/api/addresses` | Create an address (see below) |
| `GET` | `/api/addresses/{address}` | Mailbox info / existence check |
| `POST` | `/api/addresses/{address}/extend` | Extend expiry by the default TTL |
| `DELETE` | `/api/addresses/{address}` | Delete mailbox + all messages |
| `GET` | `/api/addresses/{address}/messages` | List message summaries (newest first) |
| `GET` | `/api/addresses/{address}/messages/{id}` | Full message (bodies + attachment metadata) |
| `GET` | `/api/addresses/{address}/messages/{id}/attachments/{attachment_id}` | Download raw attachment bytes |
| `DELETE` | `/api/addresses/{address}/messages/{id}` | Delete one message |
| `GET` | `/api/addresses/{address}/events` | SSE stream of new-message events |

### Create an address

`POST /api/addresses` with an optional JSON body:

```json
{ "local_part": "my-custom-name", "domain": "example.com" }
```

- Both fields are optional. Omit the body entirely for a random address on the
  first configured domain.
- `local_part` must be 1–64 chars of `[a-z0-9._-]` and not start/end with a
  separator. A taken custom address returns `409 Conflict`.

Returns `201 Created` with the mailbox `{ address, domain, created_at, expires_at }`.

### Live updates (SSE)

```js
const es = new EventSource(
  `/api/addresses/${encodeURIComponent(address)}/events`
);
es.addEventListener("message", (e) => {
  const evt = JSON.parse(e.data); // { address, id, mail_from, subject, received_at, has_attachments }
  // fetch the full message, or refresh the inbox listing
});
```

On reconnect, always re-fetch the message list — SSE events may be missed while
disconnected and are not replayed.

## SMTP behaviour

- `RCPT TO` is accepted (`250`) only when the domain is one of `DOMAINS` **and**
  the mailbox exists and is unexpired. Otherwise `550` (unknown/relay) so the
  sending MTA gets a real bounce.
- `DATA` is capped at `MAX_MESSAGE_SIZE_BYTES`; oversize messages are drained to
  the terminator and rejected with `552`.
- Dot-stuffing/unstuffing and the `<CRLF>.<CRLF>` terminator are handled.
- STARTTLS is advertised only when a certificate is configured; the session
  discards buffered plaintext on upgrade (RFC 3207).
- **Not** implemented (v1): SPF/DKIM/DMARC verification, RBL/blocklist checks,
  and outbound sending.

## Deployment notes

- **MX record:** point an MX record for each domain in `DOMAINS` at this
  server's public IP so other mail servers deliver here.
- **Port 25:** binding it needs root or `CAP_NET_BIND_SERVICE`
  (`setcap 'cap_net_bind_service=+ep' ./tempmail-backend`, or run in a container
  as root). This server only needs **inbound** 25 — the common cloud port-25
  block applies to *outbound* sending and does not affect receiving.
- **TLS:** set `TLS_CERT_PATH`/`TLS_KEY_PATH` to advertise STARTTLS. Senders
  fall back to plaintext when it is not offered, so it is optional but
  recommended.

## Testing

```bash
cargo test
```

Includes unit tests (SMTP command parsing, MIME extraction, address validation)
and an end-to-end test that scripts a real SMTP conversation over a socket and
reads the message back — using the in-memory store, so no database is required.

## Project layout

```
src/
  main.rs            thin binary -> tempmail_backend::run()
  lib.rs             wiring: config, PgPool, migrations, task startup
  config.rs          env-based configuration
  model.rs           Mailbox, StoredMessage, Attachment, ...
  events.rs          broadcast event bus for SSE
  mime.rs            mail-parser -> NewMessage
  cleanup.rs         expired-mailbox purge task
  store/             Store trait + Postgres and in-memory implementations
  smtp/              accept loop, session state machine, commands, STARTTLS
  api/               Axum router, address/message handlers, SSE
migrations/          SQL migrations (embedded at build time)
tests/               end-to-end SMTP delivery test
```

## License

Licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you shall be dual licensed as above, without
any additional terms or conditions.
