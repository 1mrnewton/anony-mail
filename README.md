# anony-mail

An inbound-only, disposable-email (temp mail) backend written in Rust. It
**receives** email over SMTP for throwaway addresses and exposes it to a
frontend over a REST + Server-Sent-Events HTTP API. It does not send mail.

- Hand-rolled async SMTP receiver on `tokio` (EHLO/HELO, MAIL, RCPT, DATA,
  RSET, NOOP, QUIT, VRFY, HELP, optional STARTTLS).
- Recipients are validated at `RCPT TO` against the database, so mail to unknown
  or expired addresses is rejected at the SMTP layer instead of being stored.
  Plus-addressing (`user+tag@`) delivers to the base mailbox; an opt-in
  catch-all can auto-create mailboxes for unknown local parts.
- MIME parsing via [`mail-parser`](https://crates.io/crates/mail-parser)
  (subject, from, date, text/html bodies, attachments), with server-side
  verification-code (OTP) extraction surfaced on SSE and push events.
- REST API for creating addresses and reading messages, plus an SSE stream and
  optional push notifications — **Web Push (VAPID)** for browsers and **APNs**
  for native iOS apps — the moment a message arrives.
- Destructive/lifecycle operations (extend, delete, clear, subscribe) are
  gated by a per-mailbox **owner token** returned once at creation.
- **Custom domains** (on by default): claim a domain you own, prove control
  via DNS (TXT challenge + MX record), and receive mail on it — verified
  domains are re-checked daily with a grace window for DNS hiccups.
- Abuse controls throughout: per-IP rate limits and daily creation quotas,
  request timeouts, SSE concurrency caps, per-mailbox message/byte quotas
  (drop-oldest), reserved local parts, and a disk watermark for SQLite.
- Background task purges expired mailboxes (messages/attachments cascade) and
  reclaims SQLite space incrementally.
- Pluggable storage behind a `Store` trait: **SQLite by default** (zero external
  dependencies), or PostgreSQL by setting a `postgres://` `DATABASE_URL`.

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

All three run as concurrent tasks in one process sharing a single database
connection pool. New messages are published on a `tokio::sync::broadcast`
channel; the SSE endpoint
subscribes and forwards events for the requested address. SSE is a low-latency
*nudge* — the REST inbox listing remains the source of truth for reconciliation.

## Quick start (Docker Compose)

Uses the prebuilt image published to GitHub Container Registry
(`ghcr.io/1mrnewton/anony-mail`), so there is nothing to compile:

```bash
cp .env.example .env          # optional: values below can also come from compose
docker compose pull           # fetch the prebuilt image
docker compose up -d
```

This starts the app with the default SQLite backend, stored on the `maildata`
volume so it survives restarts and redeploys, running migrations automatically
on boot. Edit `DOMAINS`/`SMTP_HOSTNAME` in `docker-compose.yml` for your domains.
Pin a specific version with `ANONY_MAIL_TAG=0.1.0 docker compose up -d`.

To use PostgreSQL instead, start the optional service and switch the app's
`DATABASE_URL` (both shown in `docker-compose.yml`):

```bash
docker compose --profile postgres pull
docker compose --profile postgres up -d
```

Then create an address and watch for mail:

```bash
# Interactive API docs (Scalar)
open http://localhost:8080/docs

# Create a random disposable address
curl -s -X POST http://localhost:8080/api/addresses | jq
# => { "address": "a1b2c3d4e5@example.com", "domain": "example.com",
#      "owner_token": "am_...", ... }   <- store it; shown only here and on rotate

# List its messages (empty until mail arrives)
curl -s http://localhost:8080/api/addresses/a1b2c3d4e5@example.com/messages | jq
```

## Local development (without Docker)

Requires only a Rust toolchain (edition 2024, i.e. Rust >= 1.85); the default
SQLite backend needs no external services.

```bash
export DOMAINS=example.com
# Port 25 needs privileges; use a high port locally:
export SMTP_BIND_ADDR=0.0.0.0:2525
# DATABASE_URL defaults to sqlite://data/anony-mail.db. To use Postgres:
# export DATABASE_URL=postgres://anonymail:anonymail@localhost:5432/anonymail

cargo run
```

Per-backend migrations (`migrations/sqlite`, `migrations/postgres`) are embedded
into the binary and run on startup.

Send a test message with any SMTP client (e.g. `swaks`), after creating the
recipient address via the API:

```bash
swaks --server localhost:2525 --to a1b2c3d4e5@example.com --from me@somewhere.test
```

## Configuration

All configuration is via environment variables (see [.env.example](.env.example)).
Only `DOMAINS` is required; everything else has defaults.

| Variable | Default | Description |
| --- | --- | --- |
| `DOMAINS` | — (required) | Comma-separated domains to accept mail for |
| `DATABASE_URL` | `sqlite://data/anony-mail.db` | DB connection string: `sqlite://<path>` or `postgres://…` |
| `DB_MAX_CONNECTIONS` | `0` | DB pool size; `0` = backend default (Postgres 10, SQLite 5) |
| `SMTP_BIND_ADDR` | `0.0.0.0:25` | SMTP listener address (`0.0.0.0:2525` in the Docker image) |
| `API_BIND_ADDR` | `0.0.0.0:8080` | HTTP API listener address |
| `SMTP_HOSTNAME` | first domain | Hostname announced in the SMTP banner/EHLO |
| `DEFAULT_TTL_SECONDS` | `3600` | Mailbox lifetime |
| `CLEANUP_INTERVAL_SECONDS` | `300` | Expiry purge + maintenance interval |
| `MAX_MESSAGE_SIZE_BYTES` | `26214400` | Max accepted message size (25 MiB) |
| `MAX_RECIPIENTS` | `10` | Max recipients per SMTP transaction |
| `MAX_CONNECTIONS` | `1024` | Max concurrent SMTP connections |
| `SMTP_SESSION_TIMEOUT_SECONDS` | `60` | Per-connection idle timeout |
| `SMTP_PER_IP_CONNECTIONS_PER_MIN` | `60` | Per-IP new-SMTP-connection rate limit |
| `TLS_CERT_PATH` / `TLS_KEY_PATH` | unset | Enable STARTTLS (PEM files) |
| `CORS_ALLOWED_ORIGINS` | `*` | Comma-separated CORS origins, or `*` |
| `RESERVED_LOCAL_PARTS` | unset | Extra local parts to refuse, on top of the built-in list |
| `API_RATE_LIMIT_PER_SECOND` | `20` | General per-IP API rate (req/s, `0` disables) |
| `API_RATE_LIMIT_BURST` | `50` | Burst budget for the general limit |
| `API_CREATE_RATE_LIMIT_PER_MINUTE` | `30` | Per-IP `POST /api/addresses` rate (`0` disables) |
| `API_CREATE_RATE_LIMIT_BURST` | `10` | Burst budget for address creation |
| `MAX_ADDRESSES_PER_IP_PER_DAY` | `200` | Per-IP daily creation quota (`0` disables) |
| `API_REQUEST_TIMEOUT_SECONDS` | `30` | Timeout on non-SSE routes (`0` disables) |
| `API_TRUST_PROXY_HEADERS` | `false` | Trust `X-Forwarded-For` etc. (only behind a proxy) |
| `API_DOCS_ENABLED` | `true` | Serve Scalar at `/docs` and the spec at `/openapi.json` |
| `SSE_MAX_CONCURRENT` | `512` | Global cap on open SSE streams (`0` disables) |
| `SSE_MAX_PER_IP` | `8` | Per-IP cap on open SSE streams (`0` disables) |
| `MAX_MESSAGES_PER_MAILBOX` | `50` | Per-mailbox message cap, drop-oldest (`0` disables) |
| `MAX_MAILBOX_BYTES` | `41943040` | Per-mailbox byte cap (40 MiB), drop-oldest (`0` disables) |
| `MIN_FREE_DISK_BYTES` | `268435456` | Refuse `DATA` below this free space (256 MiB; SQLite; `0` disables) |
| `CATCH_ALL_ENABLED` | `false` | Auto-create mailboxes for unknown local parts |
| `CUSTOM_DOMAINS_ENABLED` | `true` | Bring-your-own-domain endpoints + SMTP acceptance |
| `MAX_CUSTOM_DOMAINS_PER_IP_PER_DAY` | `5` | Per-IP daily domain-claim quota (`0` disables) |
| `CUSTOM_DOMAIN_VERIFY_THROTTLE_SECONDS` | `10` | Min spacing between DNS verify runs per domain (`0` disables) |
| `ENTITLEMENTS_ENFORCED` | `false` | Enforce free/pro tiers server-side (see [Entitlements & tiers](#entitlements--tiers-hosted-instances)) |
| `TOKEN_SIGNING_KEY` | unset | Client-token signing key (base64, ≥32 bytes); required to enforce |
| `REVENUECAT_SECRET_KEY` | unset | Enables pro verification via RevenueCat |
| `REVENUECAT_ENTITLEMENT_ID` | `Anony Mail Pro` | RevenueCat entitlement that marks pro |
| `FREE_*` / `PRO_*` | see `.env.example` | Tier policy: mailbox caps, lifetime ceiling, local parts, domains |
| `APP_ATTEST_TEAM_ID` / `APP_ATTEST_BUNDLE_ID` | unset | Enable App Attest endpoints (both + `TOKEN_SIGNING_KEY` required) |
| `CLIENT_ATTESTATION_REQUIRED` | `false` | Demand an attested client token on every mutating route |
| `APP_ATTEST_ROOT_CA_PATH` | embedded | Override Apple's App Attestation Root CA (PEM) |
| `STORE_RAW_MESSAGE` | `false` | Retain original bytes; serves `GET …/messages/{id}/raw` |
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` | unset | Enable Web Push (both required) |
| `VAPID_SUBJECT` | `mailto:postmaster@<first domain>` | VAPID contact (`mailto:` or URL) |
| `APNS_TEAM_ID` / `APNS_KEY_ID` / `APNS_TOPIC` | unset | Enable APNs / native iOS push (all + a key required) |
| `APNS_KEY_PATH` or `APNS_KEY_BASE64` | unset | The `.p8` signing key: file path, or its base64 inline |
| `APNS_SANDBOX` | `false` | Use Apple's sandbox gateway (Xcode debug builds only) |
| `MAX_SUBSCRIPTIONS_PER_MAILBOX` | `5` | Push subscriptions per mailbox, all kinds (`0` disables cap) |
| `RUST_LOG` | `info` | `tracing` env-filter directive |

## Storage backends

Storage sits behind a `Store` trait, selected at startup from the `DATABASE_URL`
scheme:

- **SQLite (default).** A single file with zero external dependencies — a good
  fit for a single VPS. Selected by a `sqlite://<path>` URL (or by leaving
  `DATABASE_URL` unset). Opened in WAL mode with foreign keys enforced; the file
  and its parent directory are created on first run. SQLite has a single writer,
  so very high inbound volume is the main reason to reach for Postgres.
- **PostgreSQL (optional).** Set a `postgres://…` URL to switch. Suited to high
  write concurrency or when the database must be reachable from other hosts.

### Persistence in Docker

A container's filesystem is ephemeral — it is discarded whenever the container
is recreated (redeploys, image updates). Data persists only on a mounted volume:

- **SQLite:** mount a volume at the directory holding the file and point
  `DATABASE_URL` there. The compose file does this by default (`maildata:/data`
  with `DATABASE_URL=sqlite:///data/anony-mail.db`). WAL creates `-wal`/`-shm`
  sidecar files, so mount the directory, not just the file.
- **PostgreSQL:** the optional `postgres` service mounts `pgdata` at
  `/var/lib/postgresql/data`.

Data then survives restarts and redeploys for as long as the volume exists
(`docker compose down -v` deletes volumes). Back up SQLite by copying the file
(`sqlite3 anony-mail.db ".backup backup.db"`) or Postgres with `pg_dump`. Since
mailboxes expire (`DEFAULT_TTL_SECONDS`) and are purged, persistence here means
surviving restarts — not retaining mail indefinitely.

> **Upgrading an existing deployment:** the image now runs as a non-root user
> (UID/GID `10001`). A `maildata` volume created by an older root-running image
> is owned by root, so fix its ownership once before starting the new version:
> `docker run --rm -v <project>_maildata:/data alpine chown -R 10001:10001 /data`.

## HTTP API

Base path `/api`. Request/response bodies are JSON. Errors are
`{ "error": "message" }` with an appropriate status code. The full contract
lives in [openapi.json](openapi.json); a running instance serves it at
`/openapi.json` and a Scalar UI at `/docs` (disable both with
`API_DOCS_ENABLED=false`). Rows marked **owner** require the
mailbox's owner token as `Authorization: Bearer am_…`; rows marked **claim**
require the custom domain's claim token (`amd_…`).

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/healthz` | — | Liveness check |
| `GET` | `/readyz` | — | Readiness check (pings the database) |
| `GET` | `/docs` | — | Scalar API reference (`API_DOCS_ENABLED`) |
| `GET` | `/openapi.json` | — | OpenAPI 3.1 document (`API_DOCS_ENABLED`) |
| `GET` | `/api/capabilities` | — | Feature flags + tier policy of this instance |
| `GET` | `/api/domains` | — | List configured domains |
| `POST` | `/api/entitlements/verify` | — | Mint a tier token from a RevenueCat purchase check |
| `POST` | `/api/client/challenge` | — | Issue a single-use App Attest challenge (`APP_ATTEST_*`) |
| `POST` | `/api/client/attest` | — | One-time device attestation → attested client token |
| `POST` | `/api/client/assert` | — | Refresh an attested token via an App Attest assertion |
| `POST` | `/api/addresses` | — | Create an address (see below) |
| `GET` | `/api/addresses/{address}` | — | Mailbox info / existence check |
| `POST` | `/api/addresses/{address}/extend` | owner | Extend expiry by the default TTL |
| `POST` | `/api/addresses/{address}/rotate` | owner | Rotate the owner token (returns the new one) |
| `DELETE` | `/api/addresses/{address}` | owner | Delete mailbox + all messages |
| `GET` | `/api/addresses/{address}/messages` | — | List summaries, newest first (`?limit=`, `?since=`) |
| `GET` | `/api/addresses/{address}/messages/{id}` | — | Full message (bodies + attachment metadata) |
| `GET` | `/api/addresses/{address}/messages/{id}/raw` | — | Original `.eml` (only if `STORE_RAW_MESSAGE=true`) |
| `GET` | `/api/addresses/{address}/messages/{id}/attachments/{attachment_id}` | — | Download attachment bytes |
| `POST` | `/api/addresses/{address}/messages/{id}/read` | — | Mark a message as seen |
| `DELETE` | `/api/addresses/{address}/messages/{id}` | owner | Delete one message |
| `DELETE` | `/api/addresses/{address}/messages` | owner | Clear the inbox (mailbox survives) |
| `GET` | `/api/addresses/{address}/events` | — | SSE stream of new-message events |
| `GET` | `/api/push/config` | — | Which push channels are enabled (`webpush`, `apns`) |
| `GET` | `/api/push/vapid-public-key` | — | VAPID public key (`503` if Web Push not configured) |
| `POST` | `/api/addresses/{address}/subscriptions` | owner | Register a push subscription (Web Push or APNs) |
| `DELETE` | `/api/addresses/{address}/subscriptions` | owner | Remove a push subscription (by endpoint or device token) |
| `POST` | `/api/custom-domains` | — | Claim a custom domain (`CUSTOM_DOMAINS_ENABLED`) |
| `GET` | `/api/custom-domains/{domain}` | claim | Claim status + the DNS records to publish |
| `POST` | `/api/custom-domains/{domain}/verify` | claim | Run the DNS checks now |
| `DELETE` | `/api/custom-domains/{domain}` | claim | Release the claim |

### Create an address

`POST /api/addresses` with an optional JSON body:

```json
{ "local_part": "my-custom-name", "domain": "example.com" }
```

- Both fields are optional. Omit the body entirely for a random address on the
  first configured domain.
- `local_part` must be 1–64 chars of `[a-z0-9._-]` and not start/end with a
  separator. A taken custom address returns `409 Conflict`; reserved names
  (`admin`, `postmaster`, `webmaster`, … plus `RESERVED_LOCAL_PARTS`) return
  `400`.
- Rate-limited per IP (`API_CREATE_RATE_LIMIT_PER_MINUTE`,
  `MAX_ADDRESSES_PER_IP_PER_DAY`) — expect `429` under abuse.
- `domain` may also be a **verified custom domain**, in which case the request
  must carry that domain's claim token (`Authorization: Bearer amd_…`) — see
  [Custom domains](#custom-domains).

Returns `201 Created` with the mailbox fields plus a one-time secret:

```json
{
  "address": "a1b2c3d4e5@example.com",
  "domain": "example.com",
  "created_at": "…",
  "expires_at": "…",
  "owner_token": "am_…"
}
```

### Owner tokens

The `owner_token` is the only credential for destructive and lifecycle
operations (extend, rotate, delete mailbox/message, clear inbox, push
subscriptions). It is shown **only** in the create and rotate responses — the
server stores just a SHA-256 hash, so it cannot be recovered later. Send it as
`Authorization: Bearer am_…`; a missing or wrong token yields `401`. Reading
mail stays tokenless: anyone who knows the address can poll the inbox, which is
the normal temp-mail model. If a token leaks, `POST …/rotate` (authenticated
with the current token) invalidates it and returns a fresh one. Mailboxes with
no token on record — created before this feature, or auto-created by the
catch-all — can never pass owner-gated calls (`401`); they simply age out and
expire.

### Custom domains

Receive mail at a domain you own (on by default; `CUSTOM_DOMAINS_ENABLED=false`
to turn off — clients discover the feature via `GET /api/capabilities`):

1. **Claim** — `POST /api/custom-domains` with `{ "domain": "mail.mycorp.com" }`
   returns `201` with the records to publish and a one-time **claim token**
   (`amd_…`) that gates everything else about the domain. The server's own
   domains (and their subdomains) cannot be claimed.
2. **Publish DNS** — a TXT record at `_anonymail.mail.mycorp.com` with the
   returned `txt_record` value, and an MX record for `mail.mycorp.com`
   pointing at the returned `mx_target` (this server's `SMTP_HOSTNAME`).
3. **Verify** — `POST /api/custom-domains/{domain}/verify` runs both lookups
   live and returns per-record results. When both pass the domain is
   `verified`: SMTP accepts mail for it, and `POST /api/addresses` with
   `{ "domain": "mail.mycorp.com" }` works when the claim token is sent as the
   bearer token (so only the domain owner can mint mailboxes on it).

Verified domains are re-checked daily in the background. Broken DNS is
tolerated for a ~48h grace window, then the domain flips to `failed` (mail and
creates stop) until a successful verify restores it. Deleting the claim stops
mail immediately; existing mailboxes live out their TTL. The catch-all never
applies to custom domains — only explicitly created mailboxes receive mail.
Claims are rate-limited per IP (`MAX_CUSTOM_DOMAINS_PER_IP_PER_DAY`), and
verify runs are throttled per domain (`CUSTOM_DOMAIN_VERIFY_THROTTLE_SECONDS`).

### Entitlements & tiers (hosted instances)

By default the server is **fully open**: every feature works for any client,
no tiers, no tokens — the self-host experience. A hosted instance can flip
`ENTITLEMENTS_ENFORCED=true` to enforce a free/pro split server-side.
No accounts are involved; tier is proven by purchase:

1. The app calls `POST /api/entitlements/verify` with its anonymous
   RevenueCat app-user id. The server checks the pro entitlement
   (`REVENUECAT_SECRET_KEY` + `REVENUECAT_ENTITLEMENT_ID`, verdicts cached
   ~10 min) and returns a signed client token (HS256, `TOKEN_SIGNING_KEY`,
   12h TTL) carrying `tier: free|pro`.
2. The app sends that token as `X-Client-Token` on writes. **No token means
   free tier** — never an error. Expired/forged tokens get a `401` with
   `code: client_token_expired` / `client_token_invalid` so the app refreshes.
3. Free-tier requests are gated per the `FREE_*` policy: custom local parts
   (`403 pro_required`), domains beyond `FREE_DOMAIN_COUNT`, custom-domain
   claims, and a total mailbox-lifetime ceiling on extend
   (`FREE_MAX_LIFETIME_SECONDS`, `403 lifetime_cap`).

`GET /api/capabilities` reports `entitlements.enforced` plus the full
`free`/`pro` policy so clients drive their gates and paywall copy from the
server instead of hardcoding numbers; when `enforced` is `false` clients
should unlock everything. Policy errors carry a machine-readable `code`
alongside the standard `error` message. Enforcement without a RevenueCat key
is valid (a "goodwill" tiered instance): everyone is free tier and pro is
unreachable.

### Client attestation / App Attest (hosted instances)

Tier tokens prove a *purchase*; they do not prove the request comes from a
genuine build of the official app. A hosted instance can additionally turn on
**Apple App Attest** — again, off by default so self-hosted servers stay
fully open.

Setting `APP_ATTEST_TEAM_ID` + `APP_ATTEST_BUNDLE_ID` (plus
`TOKEN_SIGNING_KEY`) enables three endpoints:

1. `POST /api/client/challenge` issues a single-use challenge (5 min TTL).
2. `POST /api/client/attest` — once per install — verifies the device's
   attestation **locally** (certificate chain to Apple's App Attestation Root
   CA, embedded in the binary; the server never calls Apple), registers the
   device key, and mints an **attested** client token (it runs the same
   RevenueCat tier check as `/api/entitlements/verify`).
3. `POST /api/client/assert` refreshes the token by verifying an assertion
   signed with the registered key. The signature counter must strictly
   increase, which blocks replay.

Flipping `CLIENT_ATTESTATION_REQUIRED=true` then makes every mutating route
demand an attested token (`401` / `code: attestation_required` otherwise);
reads stay open. With entitlements also enforced, the per-device
`FREE_ACTIVE_MAILBOXES` / `PRO_ACTIVE_MAILBOXES` caps bite on creation
(`403` / `code: mailbox_cap`), since attested requests carry a stable,
hashed device identity. Device records idle for ~180 days are pruned;
such devices simply re-attest.

### Live updates (SSE)

```js
const es = new EventSource(
  `/api/addresses/${encodeURIComponent(address)}/events`
);
es.addEventListener("message", (e) => {
  // { address, id, mail_from, subject, received_at, has_attachments, code }
  const evt = JSON.parse(e.data);
  // `code` is a best-effort verification code (OTP) extracted server-side,
  // or null. Fetch the full message, or refresh the inbox listing.
});
```

On reconnect, always re-fetch the message list — SSE events may be missed while
disconnected and are not replayed. Streams are capped globally and per IP
(`SSE_MAX_CONCURRENT`, `SSE_MAX_PER_IP`); a `429` means too many are open.

### Push notifications

Two optional channels share one subscription API; `GET /api/push/config`
reports which are enabled. Each mailbox holds at most
`MAX_SUBSCRIPTIONS_PER_MAILBOX` subscriptions (all kinds combined), and
subscriptions die with the mailbox.

**Web Push (browsers / PWAs)** — enabled by `VAPID_PUBLIC_KEY` +
`VAPID_PRIVATE_KEY` (generate once with `npx web-push generate-vapid-keys`):

1. `GET /api/push/vapid-public-key` → use as `applicationServerKey` in
   `pushManager.subscribe()`.
2. `POST /api/addresses/{address}/subscriptions` (owner token) with the
   subscription's `{ endpoint, keys: { p256dh, auth } }` → `201`.
3. New mail triggers an encrypted push with
   `{ address, id, from, subject, code }`; expired/revoked endpoints
   (`404`/`410` from the push service) are pruned automatically.
4. `DELETE …/subscriptions` with `{ "endpoint": … }` removes one → `204`.

**APNs (native iOS apps)** — enabled by `APNS_TEAM_ID`, `APNS_KEY_ID`,
`APNS_TOPIC` (the app's bundle ID), and the `.p8` signing key
(`APNS_KEY_PATH` or `APNS_KEY_BASE64`). Create the key once in the Apple
Developer portal under *Certificates, Identifiers & Profiles → Keys* with the
APNs capability; it works for all your apps and does not expire like
certificates do.

1. The app registers for remote notifications and receives a device token.
2. `POST /api/addresses/{address}/subscriptions` (owner token) with
   `{ "device_token": "<hex token>" }` → `201`.
3. New mail triggers an alert push (title = subject, body = extracted code or
   sender, sound default) with the same `{ address, id, from, subject, code }`
   JSON under the `anonymail` custom key for deep-linking. Tokens Apple
   reports as `Unregistered`/`BadDeviceToken` are pruned automatically.
4. `DELETE …/subscriptions` with `{ "device_token": … }` removes one → `204`.

Set `APNS_SANDBOX=true` only when the app is an Xcode debug build; TestFlight
and App Store builds use the production gateway (the default).

### Attachment & HTML safety

- `html_body` is returned **as-is** (untrusted). Render it sandboxed — an
  `<iframe sandbox>` or equivalent — never with script access to your origin.
- Attachment downloads always carry `X-Content-Type-Options: nosniff` and
  `Content-Disposition: attachment`; active types (`text/html`,
  `image/svg+xml`, XML, JS) are served as `application/octet-stream` so
  browsers download rather than execute them.

## SMTP behaviour

- `RCPT TO` is accepted (`250`) only when the domain is one of `DOMAINS` — or a
  **verified custom domain** — **and** the mailbox exists and is unexpired.
  Otherwise `550` (unknown/relay) so the sending MTA gets a real bounce.
- **Plus-addressing:** `user+anything@domain` delivers to `user@domain`; the
  tag is stripped before the mailbox lookup.
- **Catch-all (opt-in):** with `CATCH_ALL_ENABLED=true`, mail to an unknown
  local part on an accepted domain auto-creates a default-TTL mailbox — except
  for reserved local parts, which are still rejected. Custom domains are
  excluded: only explicitly created mailboxes receive mail there.
- `DATA` is capped at `MAX_MESSAGE_SIZE_BYTES`; oversize messages are drained to
  the terminator and rejected with `552`. On the SQLite backend, `DATA` is
  refused with `452` (transient, sender retries) when free disk space falls
  below `MIN_FREE_DISK_BYTES`.
- Per-mailbox quotas apply at save time: beyond `MAX_MESSAGES_PER_MAILBOX` or
  `MAX_MAILBOX_BYTES` the **oldest** messages are dropped, so the newest mail
  (usually the OTP you are waiting for) always lands.
- Dot-stuffing/unstuffing and the `<CRLF>.<CRLF>` terminator are handled.
- STARTTLS is advertised only when a certificate is configured; the session
  discards buffered plaintext on upgrade (RFC 3207).
- **Not** implemented (v1): SPF/DKIM/DMARC verification, RBL/blocklist checks,
  and outbound sending.

## Deployment notes

- **MX record:** point an MX record for each domain in `DOMAINS` at this
  server's public IP so other mail servers deliver here.
- **Port 25:** the Docker image runs as a non-root user and listens on **2525**
  in-container; the compose file publishes it as host port 25 (`"25:2525"`),
  which is all production needs. When running the bare binary, binding 25
  directly needs root or `CAP_NET_BIND_SERVICE`
  (`setcap 'cap_net_bind_service=+ep' ./anony-mail`). To bind 25 inside the
  container instead, grant the capability and override the address:
  `docker run --cap-add NET_BIND_SERVICE --sysctl net.ipv4.ip_unprivileged_port_start=0 -e SMTP_BIND_ADDR=0.0.0.0:25 …`.
  This server only needs **inbound** 25 — the common cloud port-25 block
  applies to *outbound* sending and does not affect receiving.
- **Reverse proxy:** if the HTTP API sits behind nginx/Caddy/a load balancer,
  set `API_TRUST_PROXY_HEADERS=true` so rate limits and SSE caps key on the
  real client IP from `X-Forwarded-For`. Leave it `false` when clients connect
  directly, or IPs could be spoofed.
- **Probes:** wire liveness to `GET /healthz` and readiness to `GET /readyz`
  (the latter pings the database and returns `503` while it is unreachable).
- **TLS:** set `TLS_CERT_PATH`/`TLS_KEY_PATH` to advertise STARTTLS. Senders
  fall back to plaintext when it is not offered, so it is optional but
  recommended.

## Publishing releases (maintainers)

There are two ways to publish; both produce the same multi-arch image on GHCR
and users pick it up with `docker compose pull`.

### Option A — automated on tag (recommended)

Pushing a semver tag triggers `.github/workflows/release.yml`, which builds
`linux/amd64` + `linux/arm64`, pushes `:X.Y.Z` and `:latest` to GHCR, and
creates the matching GitHub Release. It uses the built-in `GITHUB_TOKEN`, so no
secrets to configure:

```bash
make release V=0.1.1      # bump Cargo.toml version, commit, and tag v0.1.1
git push --follow-tags    # push the commit + tag; the workflow does the rest
```

### Option B — build and push locally

Useful when you want to publish without going through CI:

1. Bump `version` in `Cargo.toml` (this is the image tag) and commit.
2. Log in once with a GitHub Personal Access Token that has the `write:packages`
   scope (create at <https://github.com/settings/tokens>):

   ```bash
   export GHCR_TOKEN=ghp_your_token_here
   make docker-login
   ```

3. Build the multi-arch image and push both the version tag and `latest`:

   ```bash
   make publish
   ```

Run `make help` to see all targets; `make docker-build` produces a single-arch
image locally without pushing (handy for testing or building from source).

> On the very first publish, GitHub creates the `anony-mail` package as
> **private**. Set its visibility to **Public** in the package settings so users
> can pull without authenticating. CI-published images auto-link to this repo;
> locally published ones link once the image carries the
> `org.opencontainers.image.source` label (already set in the `Dockerfile`).

## Testing

```bash
cargo test
```

The suite covers several layers, none of which need an external database:

- Unit tests: SMTP command parsing, MIME extraction, address validation, OTP
  patterns, token generation/parsing, attachment header hardening.
- A store conformance suite (`tests/store_conformance.rs`) running one shared
  set of tests — lifecycle, quotas, tokens, subscriptions, pagination, purge
  cascades — against both the in-memory store and a temp-file SQLite store.
- Handler/router tests exercising the HTTP surface in-process, including auth
  failures, pagination, and download header hardening.
- End-to-end SMTP tests that script real socket conversations (delivery,
  plus-addressing, catch-all, oversize, dot-stuffing).
- A drift test asserting `openapi.json` matches the crate version and that
  every router path is documented in the spec.

## Project layout

```
src/
  main.rs            thin binary -> anony_mail::run()
  lib.rs             wiring: config, DB pool/backend, migrations, task startup
  config.rs          env-based configuration
  model.rs           Mailbox, StoredMessage, Attachment, PushSubscription, ...
  events.rs          broadcast event bus for SSE + push
  mime.rs            mail-parser -> NewMessage
  otp.rs             verification-code extraction for the `code` event field
  push.rs            push worker: Web Push (VAPID) + APNs senders, pruning
  cleanup.rs         expired-mailbox purge + store maintenance task
  store/             Store trait + SQLite, Postgres, and in-memory backends
  smtp/              accept loop, session state machine, commands, STARTTLS
  api/               Axum router, handlers, auth, SSE, push, rate limits
migrations/          per-backend SQL migrations: sqlite/, postgres/
tests/               conformance, handler, SMTP e2e, push worker, spec drift
```

## License

Licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you shall be dual licensed as above, without
any additional terms or conditions.
