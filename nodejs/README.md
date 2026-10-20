# Belyfted Secure Webhook Receiver

A production-oriented Node.js + Express webhook receiver that verifies RSA
digital signatures on the raw HTTP request body, validates the payload, and
routes verified events to dedicated handlers.

## Table of Contents

- [Endpoints](#endpoints)
- [Project structure](#project-structure)
- [Digital signature verification](#digital-signature-verification)
- [Request lifecycle](#request-lifecycle)
- [Requirements](#requirements)
- [Setup](#setup)
- [Environment variables](#environment-variables)
- [Running the server](#running-the-server)
- [Running the tests](#running-the-tests)
- [Sample signed webhook request](#sample-signed-webhook-request)
- [Exposing the endpoint over HTTPS](#exposing-the-endpoint-over-https)
- [Reliability & security](#reliability--security)
- [Key rotation](#key-rotation)
- [Provider-specific details requiring confirmation](#provider-specific-details-requiring-confirmation)
- [package.json changes](#packagejson-changes)

## Endpoints

| Method | Path                 | Purpose                                  |
|--------|----------------------|------------------------------------------|
| `POST` | `/webhooks/belyfted` | Verified webhook delivery                |
| `GET`  | `/health`            | Health/liveness check                    |

## Project structure

```
src/
  server.js                       # Server startup + graceful shutdown
  app.js                          # Express app factory
  config.js                       # Env validation + public key loading
  logger.js                       # Structured JSON-lines logger
  middleware/
    verifySignature.js            # RSA-SHA256 signature verification
    errors.js                     # 404 + centralized error handler
  handlers/
    webhookHandler.js             # Payload validation, idempotency, dispatch
    events.js                     # Supported event registry + handlers
  store/
    idempotencyStore.js           # In-memory TTL idempotency store
keys/
  public.pem                      # Provider's RSA public verification key
  dev-private.pem                 # Local dev private key (PKCS#8, git-ignored)
  dev.csr                         # Local dev PKCS#10 CSR
scripts/
  generate-dev-keys.js            # Local dev key pair + PKCS#10 CSR
  sign-example.js                 # Sample signed request generator
  lib/pkcs10.js                   # Pure-Node PKCS#10 CSR builder/verifier
test/
  webhook.test.js                 # Webhook endpoint tests (node:test)
  pkcs10.test.js                  # CSR generation/verification tests
```

## Digital signature verification

The provider signs the exact HTTP request body bytes with its RSA private key:

- Raw message encoding: UTF-8
- Message digest: SHA-256
- Signing algorithm: RSA
- Padding: PKCS#1 v1.5
- Signature encoding: Base64
- Signature header: `DigitalSignature`

Verification uses Node's built-in `crypto` module:

```js
crypto.verify(
  'RSA-SHA256',
  rawBody,
  { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
  signatureBuffer
);
```

The body is read as a raw `Buffer` via [`express.raw()`](src/app.js:1) and is
**never** parsed and re-serialized before verification.

## Request lifecycle

1. `POST /webhooks/belyfted` arrives with `Content-Type: application/json`.
2. [`express.raw()`](src/app.js:1) reads the request body into a raw `Buffer`
   (enforcing the configured size limit). No JSON parser runs before this.
3. [`verifySignature`](src/middleware/verifySignature.js:1) checks the content
   type, requires the `DigitalSignature` header, strictly decodes the Base64
   signature, and calls `crypto.verify` against the raw bytes:
   - Missing/malformed/invalid signature → `401`.
   - Unsupported content type → `415`.
4. [`webhookHandler`](src/handlers/webhookHandler.js:1) decodes the raw bytes as
   UTF-8 and parses JSON:
   - Malformed JSON or invalid payload structure → `400`.
5. Optional replay-window check (disabled by default).
6. Idempotency check on the event identifier (`<type>:<id>`); duplicates are
   acknowledged without re-processing.
7. The event type is looked up in the registry. Unsupported types receive
   `202` with `reason: "unsupported_event_type"`.
8. Supported events are dispatched to a dedicated handler; a `200`
   acknowledgement is returned only after successful processing.

## Requirements

- Node.js `>= 18` (tested on v22).
- Dependencies are already installed (`express`, `dotenv`, `nodemon`).

## Setup

1. Place the provider's RSA **public** key at
   [`keys/public.pem`](keys/public.pem:1). The sender's private key must never
   exist on this server.
2. Configure environment variables (see below). A local [`.env`](.env.example:1)
   is provided from the template:

   ```bash
   copy .env.example .env   # Windows
   # or: cp .env.example .env
   ```

3. For local development only, generate a throwaway key pair and a PKCS#10
   certificate signing request so the server and example signing script can
   run:

   ```bash
   npm run generate:keys
   ```

   This writes three files under [`keys/`](keys/public.pem:1):

   - [`public.pem`](keys/public.pem:1) — RSA public key (SPKI PEM), used for
     signature verification.
   - `dev-private.pem` — RSA private key in **PKCS#8** format (git-ignored;
     never commit or deploy).
   - `dev.csr` — **PKCS#10** certificate signing request whose self-signature
     is verified programmatically before being written.

   The CSR is produced with Node's built-in `crypto` module
   ([`scripts/lib/pkcs10.js`](scripts/lib/pkcs10.js:1)) because the `openssl`
   CLI is not available by default on Windows. For production, replace
   [`public.pem`](keys/public.pem:1) with the provider's real RSA public key.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | HTTP listen port |
| `NODE_ENV` | `development` | Runtime environment |
| `WEBHOOK_PUBLIC_KEY_PATH` | `./keys/public.pem` | Path to the RSA public PEM |
| `WEBHOOK_SIGNATURE_HEADER` | `DigitalSignature` | Header carrying the signature |
| `WEBHOOK_MAX_BODY_SIZE` | `100kb` | Request body size limit |
| `WEBHOOK_EVENT_TYPE_FIELD` | `type` | Payload field holding the event type |
| `WEBHOOK_EVENT_ID_FIELD` | `id` | Payload field holding the event identifier |
| `WEBHOOK_IDEMPOTENCY_ENABLED` | `true` | Enable idempotent processing |
| `WEBHOOK_IDEMPOTENCY_TTL_MS` | `86400000` | Idempotency window (24h) |
| `WEBHOOK_REPLAY_PROTECTION_ENABLED` | `false` | Optional timestamp window check |
| `WEBHOOK_TIMESTAMP_HEADER` | `X-Belyfted-Timestamp` | Timestamp header name |
| `WEBHOOK_TIMESTAMP_TOLERANCE_MS` | `300000` | Allowed clock skew |
| `LOG_LEVEL` | `info` | `error` / `warn` / `info` / `debug` |
| `TRUST_PROXY` | `false` | Set `true` behind an HTTPS-terminating proxy |

Startup fails fast with a descriptive message when the public key is missing,
unreadable, not a valid PEM, or not an RSA key.

## Running the server

```bash
npm start          # node src/server.js
npm run dev        # nodemon src/server.js
```

## Running the tests

```bash
npm test
```

The tests generate their own RSA key pairs at runtime — no committed or
production private keys are used.

## Sample signed webhook request

With local dev keys generated, produce a signed example:

```bash
npm run sign:example
```

It prints the exact header and body plus a ready-to-paste `curl` command
targeting `POST http://localhost:3000/webhooks/belyfted`.

## Exposing the endpoint over HTTPS

For sandbox delivery, expose the local server over HTTPS with ngrok:

```bash
npm start
ngrok http 3000
```

Use the generated `https://…ngrok…` URL as the webhook endpoint in the
Belyfted sandbox. In production, terminate TLS at a reverse proxy/load
balancer and set `TRUST_PROXY=true`. TLS is never disabled.

## Reliability & security

- **Idempotency** — each processed event is keyed by `<eventType>:<eventId>`
  in an in-memory TTL store. Replace with Redis (`SET key val NX EX ttl`) or a
  DB unique constraint for multi-instance durable exactly-once semantics.
- **Request-size limits** — enforced by `express.raw()` via
  `WEBHOOK_MAX_BODY_SIZE`; oversized bodies return `413`.
- **HTTPS** — TLS must terminate at a proxy in production; this app does not
  disable TLS verification and sets `trust proxy` only when configured.
- **Safe errors** — callers receive generic messages only; stack traces and
  cryptographic details are logged server-side, never exposed.
- **Configurable logging** — structured JSON-lines via `LOG_LEVEL`; payloads
  and sensitive data are never logged.
- **Startup validation** — config and the public key are validated before the
  server binds.
- **Graceful shutdown** — `SIGTERM`/`SIGINT` drain in-flight connections.
- **Replay protection** — body-only signatures do **not** prevent replay.
  Event IDs provide idempotency (duplicate suppression), not replay prevention.
  To detect replays you additionally need a provider-signed timestamp/nonce or
  a trusted, server-assigned challenge. The optional timestamp window check is
  off by default and only bounds the window when the provider confirms it emits
  a trustworthy signed timestamp.

## Key rotation

Support both the old and new public keys during rotation: accept a request if
the signature verifies against **any** active key, and only reject after both
are checked. Once the old key is retired, remove it. This prevents rejecting
legitimate deliveries mid-rotation without weakening verification.

## Provider-specific details requiring confirmation

The following must be confirmed against Belyfted's official webhook
documentation before production use:

1. **Exact event type strings** — the values `payment-created`,
   `transaction-created`, and `account-created` in
   [`events.js`](src/handlers/events.js:1) are placeholders.
2. **Payload field names** — `type` and `id` (configurable via
   `WEBHOOK_EVENT_TYPE_FIELD` / `WEBHOOK_EVENT_ID_FIELD`).
3. **Signature header name** — assumed `DigitalSignature` per the spec.
4. **Replay protection** — whether the provider signs a timestamp/nonce in
   addition to the body, and if so, the exact header/field names.

## package.json changes

Only `main`, `description`, and `scripts` were added/updated:

```json
"main": "src/server.js",
"scripts": {
  "start": "node src/server.js",
  "dev": "nodemon src/server.js",
  "test": "node --test",
  "generate:keys": "node scripts/generate-dev-keys.js",
  "sign:example": "node scripts/sign-example.js"
}
```

No dependencies were added or removed.
