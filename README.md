# LOOM Protocol Workspace

This repository tracks **LOOM** (Linked Operations & Orchestrated Messaging).

## Why This Exists

Email infrastructure was designed for human-to-human messages in the 1980s protocol model (SMTP + MIME + IMAP folders). It still works for people, but agent workflows have different requirements:

- deterministic machine-readable semantics, not heuristic text parsing
- verifiable delegated authority for agent actions
- safe scoped permissions, not full mailbox access
- reliable idempotent APIs and replay-safe operations
- cryptographic trust between nodes, not partial trust via headers
- event/state transitions that can be automated without ambiguity

LOOM exists to provide a communication layer where humans and agents can collaborate in the same thread, but with protocol-native structure, trust, and control surfaces.

## Why Traditional Email Breaks For Agents

Traditional email can be integrated with agents, but it fails as the primary protocol when agents are first-class participants at scale.

### 1) Intent Is Ambiguous

- Email body content is mostly unstructured free text and HTML.
- Agents must guess intent from natural language and brittle templates.
- A small formatting change can break automation.

LOOM approach:

- Every envelope carries both human-readable content and structured intent payloads.
- Agents act on explicit `intent + parameters` fields instead of inference alone.

### 2) Authorization Is Coarse

- Mailbox access is usually account-level (all or almost all data).
- Delegation is operationally messy (shared inboxes, forwarding rules, app passwords).
- Hard to prove whether an action came from the owner or a delegated agent.

LOOM approach:

- Capability tokens scope actions to a thread and grant type.
- Delegation chains are signed and revocable.
- Agent actions are attributable and auditable by protocol.

### 3) Thread Semantics Are Not Deterministic

- Email threading depends on client heuristics (`subject`, `In-Reply-To`, `References`).
- Fork/merge/handoff flows are implicit and unreliable.
- Different clients render different conversation histories.

LOOM approach:

- Canonical thread DAG with explicit parent references.
- Deterministic ordering and thread operations (`fork`, `merge`, `delegate`, `resolve`).

### 4) Trust Model Is Weak For Autonomous Systems

- SMTP metadata can be manipulated unless layers of anti-spoof controls align.
- SPF/DKIM/DMARC help but are still email-era compensating controls.
- Cross-system automation needs stronger per-request verification and replay protection.

LOOM approach:

- Signed envelopes and signed federation requests.
- Nonce + timestamp replay protection.
- Explicit federation node trust policies (`trusted`, `quarantine`, `deny`) and abuse automation.

### 5) Delivery Operations Are Not API-First

- Email retry/error handling is fragmented across MTAs and providers.
- Idempotency behavior is not consistent across clients/integrations.
- Operational introspection is limited for real-time agent systems.

LOOM approach:

- API-first outbox queues for email/federation/webhooks.
- Dead-letter queue requeue controls.
- Idempotency-key support on critical write routes.
- Metrics/readiness/admin surfaces for continuous operation.

### 6) State Mutation Over Email Is Unsafe

- Actions like "approve", "close", or "reassign" are implied through message text.
- Parsing these into reliable state transitions is error-prone.

LOOM approach:

- `thread_op` intents are explicit, validated, authorized, and persisted with audit chain.

### Summary

Email remains useful as a bridge transport for legacy users and systems. It is not enough as the core protocol for agent-native collaboration. LOOM keeps compatibility where needed, but moves the source of truth to signed, structured, auditable protocol primitives.

## Current status

- Protocol design docs are available in:
  - `LOOM-protocol-design.md`
  - `LOOM-specification-v1.0.md`
  - `LOOM-Protocol-Spec-v1.1.md`
  - `docs/DEVELOPMENT-PLAN.md`
  - `docs/POSTGRES-OPERATIONS.md`
- A first **Minimum Viable Node (MVN)** implementation with optional disk persistence is in `src/`.

## MVN features implemented

- Envelope shape validation (`loom: "1.1"`, ids, recipients, content checks)
- Canonical JSON serialization (excludes `signature` and `meta`)
- Ed25519 envelope signing and verification
- Thread DAG validation and canonical rendering order
- Proof-of-key auth (`challenge` -> signed nonce -> bearer token)
- Basic capability token issuance/revocation with thread epoch checks
- `thread_op` authorization with owner/capability enforcement
- Agent delegation-chain verification with signature/scope/revocation checks
- Optional disk persistence (`LOOM_DATA_DIR`) with hash-chained audit log
- Signed inbound federation verification with replay protection
- Federation node policies: `trusted`, `quarantine`, `deny`
- Federation node key rotation support (`signing_keys` + `active_key_id`)
- Federation node auto-discovery bootstrap from `/.well-known/loom.json`
- Federation inbound abuse controls: per-node rate limit + max envelopes per delivery
- Federation reputation automation: auto-quarantine/auto-deny for repeatedly failing nodes
- Federation distributed guard support: global inbound rate controls and shared abuse/challenge state via persistence adapter
- Federation challenge escalation + challenge token flow (`/v1/federation/challenge`)
- Signed federation delivery receipts with optional strict verification
- Outbound federation outbox with retry-based store-and-forward processing
- SMTP/IMAP gateway interoperability hardening (address-list parsing, case-insensitive headers, folder aliases)
- Idempotency-key replay protection for key POST mutations
- Admin persistence operations: schema status, backup export, and restore
- In-memory node API:
  - `GET /.well-known/loom.json`
  - `GET /ready`
  - `GET /metrics` (Prometheus format, admin token by default)
  - `POST /v1/identity`
  - `GET /v1/identity/{encoded_loom_uri}`
  - `POST /v1/auth/challenge`
  - `POST /v1/auth/token`
  - `POST /v1/auth/refresh`
  - `POST /v1/envelopes`
  - `POST /v1/threads/{id}/ops`
  - `GET /v1/envelopes/{id}`
  - `GET /v1/threads`
  - `GET /v1/threads/{id}`
  - `GET /v1/threads/{id}/envelopes`
  - `GET /v1/search?q=...&type=...&intent=...`
  - `GET /v1/audit?limit=...`
  - `POST /v1/bridge/email/inbound`
  - `POST /v1/bridge/email/outbound`
  - `POST /v1/bridge/email/send` (queue + immediate relay attempt)
  - `POST /v1/email/outbox`
  - `GET /v1/email/outbox`
  - `POST /v1/email/outbox/process`
  - `POST /v1/email/outbox/{id}/process`
  - `GET /v1/gateway/imap/folders`
  - `GET /v1/gateway/imap/folders/{folder}/messages?limit=...`
  - `POST /v1/gateway/smtp/submit`
  - `POST /v1/blobs`
  - `PUT /v1/blobs/{id}/parts/{n}`
  - `POST /v1/blobs/{id}/complete`
  - `GET /v1/blobs/{id}`
  - `POST /v1/capabilities`
  - `GET /v1/capabilities?thread_id=...`
  - `DELETE /v1/capabilities/{id}`
  - `POST /v1/delegations`
  - `GET /v1/delegations?role=all|delegator|delegate`
  - `DELETE /v1/delegations/{id}`
  - `GET /v1/federation/hello`
  - `POST /v1/federation/nodes`
  - `POST /v1/federation/nodes/bootstrap` (discovery bootstrap)
  - `GET /v1/federation/nodes`
  - `POST /v1/federation/challenge` (signed node challenge token issue)
  - `POST /v1/federation/deliver` (signed wrapper)
  - `POST /v1/federation/outbox`
  - `GET /v1/federation/outbox`
  - `POST /v1/federation/outbox/process`
  - `POST /v1/federation/outbox/{id}/process`
  - `POST /v1/webhooks` (admin token required)
  - `GET /v1/webhooks` (admin token required)
  - `DELETE /v1/webhooks/{id}` (admin token required)
  - `GET /v1/webhooks/outbox` (admin token required)
  - `POST /v1/webhooks/outbox/process` (admin token required)
  - `POST /v1/webhooks/outbox/{id}/process` (admin token required)
  - `GET /v1/outbox/dlq?kind=email|federation|webhook|all` (admin token required)
  - `POST /v1/outbox/dlq/requeue` (admin token required)
  - `GET /v1/admin/status` (admin token required)
  - `GET /v1/admin/persistence/schema` (admin token required)
  - `GET /v1/admin/persistence/backup` (admin token required)
  - `POST /v1/admin/persistence/restore` (admin token required, `confirm=restore`)

## Run

```bash
npm start
```

Server defaults:

- Host: `127.0.0.1`
- Port: `8787`
- Live console UI: `http://127.0.0.1:8787/`
- Node document: `http://127.0.0.1:8787/.well-known/loom.json`

Optional persistence:

- Set `LOOM_DATA_DIR=/absolute/path` to persist state and audit log between restarts.
- Set `LOOM_PG_URL` to enable PostgreSQL-backed state + audit persistence.
  - Optional: `LOOM_PG_STATE_KEY` (default `default`) for multi-tenant/state partitioning.
  - Optional pool/timing tuning: `LOOM_PG_POOL_MAX`, `LOOM_PG_IDLE_TIMEOUT_MS`, `LOOM_PG_CONNECT_TIMEOUT_MS`.
  - Optional TLS: `LOOM_PG_SSL=true`, `LOOM_PG_SSL_REJECT_UNAUTHORIZED=true|false`.
  - On startup, node hydrates from Postgres first when configured.
- Set `LOOM_NODE_SIGNING_PRIVATE_KEY_PEM` and `LOOM_NODE_SIGNING_KEY_ID` to enable outbound signed federation delivery.
- Set `LOOM_MAX_BODY_BYTES` to cap request payload size (default `2097152`).
- Set `LOOM_RATE_LIMIT_WINDOW_MS`, `LOOM_RATE_LIMIT_DEFAULT_MAX`, and `LOOM_RATE_LIMIT_SENSITIVE_MAX` for API rate limits.
- Set `LOOM_OUTBOX_AUTO_PROCESS_INTERVAL_MS` (default `5000`) and `LOOM_OUTBOX_AUTO_PROCESS_BATCH_SIZE` (default `20`) to auto-process federation outbox.
- Set `LOOM_FEDERATION_NODE_RATE_WINDOW_MS` (default `60000`) and `LOOM_FEDERATION_NODE_RATE_MAX` (default `120`) for per-node inbound federation rate limiting.
- Set `LOOM_FEDERATION_GLOBAL_RATE_WINDOW_MS` (default `60000`) and `LOOM_FEDERATION_GLOBAL_RATE_MAX` (default `1000`) for global inbound federation rate limiting.
- Set `LOOM_FEDERATION_INBOUND_MAX_ENVELOPES` (default `100`) to cap envelopes accepted per federation delivery.
- Set `LOOM_FEDERATION_REQUIRE_SIGNED_RECEIPTS=true` to require signed receipt verification for outbound federation delivery.
- Optional federation abuse automation:
  - `LOOM_FEDERATION_ABUSE_AUTO_POLICY_ENABLED=true`
  - `LOOM_FEDERATION_ABUSE_WINDOW_MS` (default `300000`)
  - `LOOM_FEDERATION_ABUSE_QUARANTINE_THRESHOLD` (default `3`)
  - `LOOM_FEDERATION_ABUSE_DENY_THRESHOLD` (default `6`)
  - `LOOM_FEDERATION_AUTO_POLICY_DURATION_MS` (default `1800000`)
- Optional distributed abuse/challenge guards:
  - `LOOM_FEDERATION_DISTRIBUTED_GUARDS_ENABLED=true|false` (default `true`)
  - `LOOM_FEDERATION_CHALLENGE_ESCALATION_ENABLED=true|false` (default `false`)
  - `LOOM_FEDERATION_CHALLENGE_THRESHOLD` (default `3`)
  - `LOOM_FEDERATION_CHALLENGE_DURATION_MS` (default `900000`)
- Set `LOOM_EMAIL_OUTBOX_AUTO_PROCESS_INTERVAL_MS` (default `5000`) and `LOOM_EMAIL_OUTBOX_AUTO_PROCESS_BATCH_SIZE` (default `20`) to auto-process outbound email outbox.
- Set `LOOM_WEBHOOK_OUTBOX_AUTO_PROCESS_INTERVAL_MS` (default `5000`) and `LOOM_WEBHOOK_OUTBOX_AUTO_PROCESS_BATCH_SIZE` (default `20`) to auto-process webhook outbox.
- Set `LOOM_ADMIN_TOKEN` to protect operational endpoints (`/metrics`, `/v1/admin/status`).
- Set `LOOM_METRICS_PUBLIC=true` only if you intentionally want unauthenticated `/metrics`.
- Optional request logging:
  - `LOOM_REQUEST_LOG_ENABLED=true`
  - `LOOM_REQUEST_LOG_FORMAT=json|text` (default `json`)
- Configure relay delivery:
  - `LOOM_SMTP_MODE=disabled|stream|smtp`
  - `LOOM_SMTP_DEFAULT_FROM`
  - `LOOM_SMTP_URL` or (`LOOM_SMTP_HOST`, `LOOM_SMTP_PORT`, `LOOM_SMTP_SECURE`, `LOOM_SMTP_USER`, `LOOM_SMTP_PASS`)
  - Optional TLS tuning: `LOOM_SMTP_REQUIRE_TLS`, `LOOM_SMTP_REJECT_UNAUTHORIZED`

Production baseline:

- Run behind TLS/reverse proxy and forward client IP (`X-Forwarded-For`) for accurate rate limiting.
- Keep `LOOM_DATA_DIR` and/or PostgreSQL storage on durable infrastructure with backups.
- Run process under a supervisor (systemd/pm2/container orchestrator) for restart and lifecycle management.
- Set `LOOM_OUTBOX_AUTO_PROCESS_INTERVAL_MS=0` only if another worker is responsible for outbox processing.
- Idempotency tuning:
  - `LOOM_IDEMPOTENCY_TTL_MS` (default `86400000`)
  - `LOOM_IDEMPOTENCY_MAX_ENTRIES` (default `10000`)

## Test

```bash
npm test
```

## Notes

- This is a protocol-development scaffold, not production-ready.
- Federation abuse/rate-policy hardening is implemented for baseline operations; deeper interoperability coverage can be extended.
- Production hardening included in this MVP baseline: payload-size guard, sensitive-route rate limiting, and automatic outbox worker loop.
- Operational surfaces included: `/ready`, Prometheus `/metrics`, `/v1/admin/status`, outbound email relay outbox with worker automation.
- Optional production persistence backend now included: PostgreSQL (`LOOM_PG_URL`).
- Persistence operations now include admin schema status, backup export, and restore APIs.
- Operational recovery surfaces include admin DLQ inspection + requeue for failed outbox deliveries.
- Signed webhook receipt delivery is supported via webhook subscriptions and webhook outbox processing endpoints.
- For retries from clients, send `Idempotency-Key` header on supported POST mutations (for example: `/v1/envelopes`, `/v1/email/outbox`, `/v1/bridge/email/send`, `/v1/gateway/smtp/submit`, `/v1/federation/outbox`).
