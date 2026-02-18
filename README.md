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

- Current release is `v0.2.7` (see `CHANGELOG.md` for release-level change history).
- Protocol design docs are available in:
  - `CHANGELOG.md`
  - `LOOM-protocol-design.md`
  - `LOOM-specification-v1.0.md`
  - `LOOM-Protocol-Spec-v1.1.md`
  - `docs/CONFORMANCE.md`
  - `docs/DEVELOPMENT-PLAN.md`
  - `docs/STABILITY.md`
  - `docs/RELEASE-POLICY.md`
  - `docs/PRODUCTION-READINESS.md`
  - `docs/DEPLOYMENT-BASELINE.md`
  - `docs/FEDERATION-CONTROLS.md`
  - `docs/FEDERATION-INTEROP-DRILL.md`
  - `docs/INBOUND-BRIDGE-HARDENING.md`
  - `docs/INCIDENT-RESPONSE-ONCALL.md`
  - `docs/OBSERVABILITY-ALERTING.md`
  - `docs/OUTBOX-WORKER-RELIABILITY.md`
  - `docs/RATE-LIMIT-POLICY.md`
  - `docs/RELEASE-CHECKLIST.md`
  - `docs/REQUEST-TRACING.md`
  - `docs/THREAT-MODEL.md`
  - `docs/SECURITY-TESTING-PROGRAM.md`
  - `docs/CAPACITY-CHAOS-TESTS.md`
  - `docs/DISASTER-RECOVERY-PLAN.md`
  - `docs/ACCESS-GOVERNANCE.md`
  - `docs/COMPLIANCE-CONTROLS.md`
  - `docs/IMAP-COMPATIBILITY-MATRIX.md`
  - `docs/SECRETS-KEY-ROTATION.md`
  - `docs/OPEN-SOURCE-STRATEGY.md`
  - `docs/POSTGRES-OPERATIONS.md`
- Community and governance docs:
  - `CONTRIBUTING.md`
  - `CODE_OF_CONDUCT.md`
  - `SUPPORT.md`
- A first **Minimum Viable Node (MVN)** implementation with optional disk persistence is in `src/`.
- Repository baseline now includes:
  - `LICENSE` (Apache-2.0)
  - GitHub Actions CI workflow (`.github/workflows/ci.yml`)

## MVN features implemented

- Envelope shape validation (`loom: "1.1"`, ids, recipients, content checks)
- RFC8785-style canonical JSON serialization (excludes `signature` and `meta`, deterministic member ordering, rejects unsupported/non-finite values)
- Ed25519 envelope signing and verification
- Thread DAG validation and canonical rendering order
- Proof-of-key auth (`challenge` -> signed nonce -> bearer token)
- Optional proof-of-key identity registration (`/v1/identity/challenge` + `registration_proof`)
- Imported remote identities are stored in a read-only remote cache namespace with TTL-based expiry
- Private-by-default mailbox reads: thread/envelope read endpoints require bearer auth unless explicit demo mode is enabled
- Capability token hardening: one-time presentation secret, hashed-at-rest secret tracking, signed portable capability tokens, and `thread_op` authorization via portable payload token or legacy header presentation token
- `thread_op` authorization with owner/capability enforcement
- Agent delegation-chain verification with signature/scope/revocation checks
- Optional disk persistence (`LOOM_DATA_DIR`) with hash-chained audit log
- Signed inbound federation verification with replay protection
- Federation replay nonce persistence in node snapshots (prevents nonce replay after restart when persistence is enabled)
- Federation node policies: `trusted`, `quarantine`, `deny`
- Federation node key rotation support (`signing_keys` + `active_key_id`)
- Federation node auto-discovery bootstrap from `/.well-known/loom.json` with SSRF guards (HTTPS by default, no redirects, response-size cap, private-network block by default)
- Federated sender identity authority checks + remote identity auto-resolution with node-signed identity document verification (`identity_resolve_url` with `{identity}` template support)
- Federation inbound abuse controls: per-node rate limit + max envelopes per delivery
- Federation reputation automation: auto-quarantine/auto-deny for repeatedly failing nodes
- Federation distributed guard support: global inbound rate controls and shared abuse/challenge state via persistence adapter
- Federation challenge escalation + challenge token flow (`/v1/federation/challenge`)
- Signed federation delivery receipts with optional strict verification
- Outbound federation outbox with retry-based store-and-forward processing and per-node deliver URL safety enforcement
- Outbox claim leasing hooks for distributed worker coordination (`email`, `federation`, `webhook`)
- SMTP/IMAP gateway interoperability hardening (address-list parsing, case-insensitive headers, folder aliases)
- Optional wire-level legacy gateway daemon (SMTP submission + IMAP mailbox access) for legacy clients, with optional STARTTLS support and extended IMAP commands (`STATUS`, `SEARCH`, `FETCH`, `STORE`, `APPEND`, `IDLE`, `MOVE`, `UID SEARCH`, `UID FETCH`, `UID STORE`, `UID MOVE`)
- Outbound MIME attachment mapping from LOOM blob-backed envelope attachments
- DSN-style per-recipient delivery status updates for email outbox entries
- Recipient-view delivery wrappers for BCC privacy (`delivery.wrapper@v1`) with per-recipient visible roster
- Per-user mailbox state (`seen`, `flagged`, `archived`, `deleted`) without mutating other participants
- Idempotency-key replay protection for key POST mutations
- Webhook destination hardening (private-network block by default with per-webhook override)
- Admin persistence operations: schema status, backup export, and restore
- In-memory node API:
  - `GET /.well-known/loom.json`
  - `GET /ready`
  - `GET /metrics` (Prometheus format, admin token by default)
  - `POST /v1/identity/challenge` (registration nonce challenge)
  - `POST /v1/identity` (self-service local-domain identities; remote imports require `imported_remote: true` and admin token when configured)
  - `GET /v1/identity/{encoded_loom_uri}`
  - `PATCH /v1/identity/{encoded_loom_uri}` (owner-authenticated local identity update/rotation)
  - `POST /v1/auth/challenge`
  - `POST /v1/auth/token`
  - `POST /v1/auth/refresh`
  - `POST /v1/envelopes`
  - `POST /v1/threads/{id}/ops`
  - `GET /v1/envelopes/{id}` (authenticated)
  - `GET /v1/envelopes/{id}/delivery` (authenticated recipient-view delivery wrapper)
  - `GET /v1/threads`
  - `GET /v1/threads/{id}` (authenticated)
  - `GET /v1/threads/{id}/envelopes` (authenticated)
  - `GET /v1/search?q=...&type=...&intent=...`
  - `GET /v1/audit?limit=...`
  - `POST /v1/bridge/email/inbound`
  - `POST /v1/bridge/email/outbound`
  - `POST /v1/bridge/email/send` (queue + immediate relay attempt)
  - `POST /v1/email/outbox`
  - `GET /v1/email/outbox`
  - `POST /v1/email/outbox/process`
  - `POST /v1/email/outbox/{id}/process`
  - `POST /v1/email/outbox/{id}/dsn`
  - `GET /v1/gateway/imap/folders`
  - `GET /v1/gateway/imap/folders/{folder}/messages?limit=...`
  - `POST /v1/gateway/smtp/submit`
  - `GET /v1/mailbox/threads/{id}/state`
  - `PATCH /v1/mailbox/threads/{id}/state`
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
- Optional keyed audit integrity:
  - `LOOM_AUDIT_HMAC_KEY` signs each audit entry with HMAC-SHA256 (recommended for tamper evidence).
  - `LOOM_AUDIT_REQUIRE_MAC_VALIDATION=true|false` (default `false`; when enabled, loading unsigned audit entries fails).
  - `LOOM_AUDIT_VALIDATE_CHAIN=true|false` (default `true`; validates `prev_hash` + `hash` chain on load/import).
- Set `LOOM_PG_URL` to enable PostgreSQL-backed state + audit persistence.
  - Optional: `LOOM_PG_STATE_KEY` (default `default`) for multi-tenant/state partitioning.
  - Optional pool/timing tuning: `LOOM_PG_POOL_MAX`, `LOOM_PG_IDLE_TIMEOUT_MS`, `LOOM_PG_CONNECT_TIMEOUT_MS`.
  - Optional TLS: `LOOM_PG_SSL=true`, `LOOM_PG_SSL_REJECT_UNAUTHORIZED=true|false`.
  - On startup, node hydrates from Postgres first when configured.
- Set `LOOM_NODE_SIGNING_PRIVATE_KEY_PEM` and `LOOM_NODE_SIGNING_KEY_ID` to enable outbound signed federation delivery.
- Set `LOOM_MAX_BODY_BYTES` to cap request payload size (default `2097152`).
- Set `LOOM_IDENTITY_DOMAIN` to override the local identity authority domain used by `POST /v1/identity` local-domain checks (defaults to `LOOM_NODE_ID` host/domain).
- Set `LOOM_IDENTITY_REQUIRE_PROOF=true` to require registration proof-of-key on self-service identity creation.
- Set `LOOM_IDENTITY_CHALLENGE_TTL_MS` to control identity challenge expiry (default `120000`).
- Set `LOOM_REMOTE_IDENTITY_TTL_MS` to control expiry for imported remote identity cache entries (default `86400000`).
- Federation remote identity resolution controls:
  - `LOOM_FEDERATION_REMOTE_IDENTITY_RESOLVE_ENABLED=true|false` (default `true`)
  - `LOOM_FEDERATION_REQUIRE_SIGNED_REMOTE_IDENTITY=true|false` (default `true`)
  - `LOOM_FEDERATION_REMOTE_IDENTITY_TIMEOUT_MS` (default `5000`)
  - `LOOM_FEDERATION_REMOTE_IDENTITY_MAX_RESPONSE_BYTES` (default `262144`)
- Set `LOOM_DEMO_PUBLIC_READS=true` only for non-production demos that need unauthenticated thread/envelope reads (default `false`).
- Public service safety checks:
  - Set `LOOM_PUBLIC_SERVICE=true` when this node is internet-facing (including reverse-proxy deployments on loopback).
  - `LOOM_REQUIRE_TLS_PROXY=true` (default) refuses public service unless `LOOM_TLS_PROXY_CONFIRMED=true`.
    - Alternatively, set `LOOM_NATIVE_TLS_ENABLED=true` with native TLS material to serve HTTPS directly.
  - `LOOM_REQUIRE_HTTPS_FROM_PROXY=true` (default for public service without native TLS) requires trusted proxy headers and enforces `X-Forwarded-Proto=https`.
  - `LOOM_DEMO_PUBLIC_READS=true` on public service requires `LOOM_DEMO_PUBLIC_READS_CONFIRMED=true`.
- Optional native TLS/HTTP2 server mode:
  - `LOOM_NATIVE_TLS_ENABLED=true|false` (default `false`)
  - `LOOM_NATIVE_TLS_CERT_PEM` or `LOOM_NATIVE_TLS_CERT_FILE`
  - `LOOM_NATIVE_TLS_KEY_PEM` or `LOOM_NATIVE_TLS_KEY_FILE`
  - `LOOM_NATIVE_TLS_ALLOW_HTTP1=true|false` (default `true`)
  - `LOOM_NATIVE_TLS_MIN_VERSION` (must be `TLSv1.3`, default `TLSv1.3`)
- Set per-identity anti-abuse quotas (all default `0`, disabled):
  - `LOOM_ENVELOPE_DAILY_MAX` maximum envelopes ingested per sender identity per UTC day.
  - `LOOM_THREAD_RECIPIENT_MAX` maximum recipients allowed per envelope.
  - `LOOM_BLOB_DAILY_COUNT_MAX` maximum blobs created per identity per UTC day.
  - `LOOM_BLOB_DAILY_BYTES_MAX` maximum completed blob bytes per identity per UTC day.
  - `LOOM_BLOB_IDENTITY_TOTAL_BYTES_MAX` maximum total completed blob bytes retained per identity.
- Set blob limits to control attachment abuse ceilings:
  - `LOOM_BLOB_MAX_BYTES` (default `26214400`)
  - `LOOM_BLOB_MAX_PART_BYTES` (default `2097152`)
  - `LOOM_BLOB_MAX_PARTS` (default `64`)
- Set `LOOM_RATE_LIMIT_WINDOW_MS`, `LOOM_RATE_LIMIT_DEFAULT_MAX`, and `LOOM_RATE_LIMIT_SENSITIVE_MAX` for API rate limits.
- Set `LOOM_TRUST_PROXY=true` only when the node is behind a trusted reverse proxy that sets `X-Forwarded-For`.
- Prefer explicit trusted proxy allowlist with `LOOM_TRUST_PROXY_ALLOWLIST` (comma-separated IP/CIDR values).
- Set identity rate limits for authenticated actors:
  - `LOOM_IDENTITY_RATE_LIMIT_WINDOW_MS` (default `60000`)
  - `LOOM_IDENTITY_RATE_LIMIT_DEFAULT_MAX` (default `2000`)
  - `LOOM_IDENTITY_RATE_LIMIT_SENSITIVE_MAX` (default `400`)
- Set `LOOM_OUTBOX_AUTO_PROCESS_INTERVAL_MS` (default `5000`) and `LOOM_OUTBOX_AUTO_PROCESS_BATCH_SIZE` (default `20`) to auto-process federation outbox.
- Set distributed outbox claim lease controls:
  - `LOOM_OUTBOX_CLAIM_LEASE_MS` (default `60000`)
  - `LOOM_OUTBOX_WORKER_ID` (optional stable worker identity for claim ownership)
- Set `LOOM_FEDERATION_NODE_RATE_WINDOW_MS` (default `60000`) and `LOOM_FEDERATION_NODE_RATE_MAX` (default `120`) for per-node inbound federation rate limiting.
- Set `LOOM_FEDERATION_GLOBAL_RATE_WINDOW_MS` (default `60000`) and `LOOM_FEDERATION_GLOBAL_RATE_MAX` (default `1000`) for global inbound federation rate limiting.
- Set `LOOM_FEDERATION_INBOUND_MAX_ENVELOPES` (default `100`) to cap envelopes accepted per federation delivery.
- Set `LOOM_FEDERATION_REQUIRE_SIGNED_RECEIPTS=true` to require signed receipt verification for outbound federation delivery.
- Outbound host allowlists (comma-separated hostnames, suffixes like `.example.com`, or wildcards like `*.example.com`):
  - `LOOM_FEDERATION_HOST_ALLOWLIST` for federation delivery/outbound federation requests.
  - `LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST` for node discovery bootstrap fetches.
  - `LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST` for federated remote identity document fetches.
  - `LOOM_WEBHOOK_HOST_ALLOWLIST` for webhook callback targets.
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
- Set `LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=true` only if you intentionally want to disable strict outbound host allowlist startup guards on public service.
- Set `LOOM_IDENTITY_SIGNUP_ENABLED=false` to require admin token for `POST /v1/identity`.
- Public-service startup safeguards:
  - Server refuses startup on public service without `LOOM_ADMIN_TOKEN`.
  - Server refuses `LOOM_METRICS_PUBLIC=true` on public service unless `LOOM_ALLOW_PUBLIC_METRICS_ON_PUBLIC_BIND=true`.
  - Server refuses open outbound host fetch configuration on public service unless `LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=true`.
    - Required by default on public service: `LOOM_FEDERATION_HOST_ALLOWLIST`, `LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST`, `LOOM_WEBHOOK_HOST_ALLOWLIST`.
    - If `LOOM_FEDERATION_REMOTE_IDENTITY_RESOLVE_ENABLED=true` (default), `LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST` is also required.
  - Server refuses public service with inbound bridge enabled unless `LOOM_BRIDGE_EMAIL_INBOUND_PUBLIC_CONFIRMED=true`.
  - Server refuses weak public inbound bridge auth policy unless `LOOM_BRIDGE_EMAIL_INBOUND_WEAK_AUTH_POLICY_CONFIRMED=true`.
- For `thread_op` submissions by non-owner participants, authorize with either:
  - `content.structured.parameters.capability_token` (portable signed token; recommended for federation portability)
  - `x-loom-capability-token` (legacy/local presentation secret header)
- Set `LOOM_REQUIRE_PORTABLE_THREAD_OP_CAPABILITY=true` to require portable payload capability tokens for non-owner `thread_op` requests.
- If `LOOM_ADMIN_TOKEN` is configured, enabling `allow_insecure_http=true` or `allow_private_network=true` on federation node registration/bootstrap requests requires `x-loom-admin-token`.
- Optional request logging:
  - `LOOM_REQUEST_LOG_ENABLED=true`
  - `LOOM_REQUEST_LOG_FORMAT=json|text` (default `json`)
- Configure relay delivery:
  - `LOOM_SMTP_MODE=disabled|stream|smtp`
  - `LOOM_SMTP_DEFAULT_FROM`
  - `LOOM_SMTP_URL` or (`LOOM_SMTP_HOST`, `LOOM_SMTP_PORT`, `LOOM_SMTP_SECURE`, `LOOM_SMTP_USER`, `LOOM_SMTP_PASS`)
  - Optional TLS tuning: `LOOM_SMTP_REQUIRE_TLS`, `LOOM_SMTP_REJECT_UNAUTHORIZED`
  - Optional DKIM signing:
    - `LOOM_SMTP_DKIM_DOMAIN_NAME`
    - `LOOM_SMTP_DKIM_KEY_SELECTOR`
    - `LOOM_SMTP_DKIM_PRIVATE_KEY_PEM` or `LOOM_SMTP_DKIM_PRIVATE_KEY_FILE`
    - `LOOM_SMTP_DKIM_HEADER_FIELD_NAMES` (optional override)
- Optional API send-surface kill switches:
  - `LOOM_BRIDGE_EMAIL_INBOUND_ENABLED=true|false` (default `true`)
  - `LOOM_BRIDGE_EMAIL_INBOUND_PUBLIC_CONFIRMED=true|false` (default `false`; required to keep inbound bridge enabled on public service)
  - Inbound bridge authentication policy controls:
    - `LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_ADMIN_TOKEN=true|false` (default `true` on public service, else `false`; requires `x-loom-admin-token` on inbound bridge requests)
    - `LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_AUTH_RESULTS=true|false` (default `true` on public service, else `false`)
    - `LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_DMARC_PASS=true|false` (default `true` on public service, else `false`)
    - `LOOM_BRIDGE_EMAIL_INBOUND_REJECT_ON_AUTH_FAILURE=true|false` (default `true` on public service, else `false`; if `false`, failures can be quarantined instead)
    - `LOOM_BRIDGE_EMAIL_INBOUND_QUARANTINE_ON_AUTH_FAILURE=true|false` (default `true`)
    - `LOOM_BRIDGE_EMAIL_INBOUND_WEAK_AUTH_POLICY_CONFIRMED=true|false` (default `false`; required only if you intentionally weaken public inbound auth policy defaults)
  - `LOOM_BRIDGE_EMAIL_SEND_ENABLED=true|false` (default `true`)
  - `LOOM_GATEWAY_SMTP_SUBMIT_ENABLED=true|false` (default `true`)
- Outbound SSRF hardening:
  - `LOOM_DENY_METADATA_HOSTS=true|false` (default `true`; blocks common cloud metadata endpoints even when private-network targets are otherwise allowed)
  - `LOOM_FEDERATION_DELIVER_TIMEOUT_MS` (default `10000`)
  - `LOOM_FEDERATION_DELIVER_MAX_RESPONSE_BYTES` (default `262144`)
  - `LOOM_WEBHOOK_MAX_RESPONSE_BYTES` (default `262144`)
  - Outbound HTTP requests pin DNS resolution per request (validated address is reused for the actual socket connect to reduce DNS rebinding/TOCTOU risk).
- Optional wire-level legacy gateway daemon:
  - `LOOM_WIRE_GATEWAY_ENABLED=true|false` (default `false`)
  - `LOOM_WIRE_GATEWAY_HOST` (default `127.0.0.1`)
  - `LOOM_WIRE_GATEWAY_REQUIRE_AUTH=true|false` (default `true`)
  - `LOOM_WIRE_ALLOW_INSECURE_AUTH=true|false` (default `false`; allows AUTH before TLS for local/dev only)
  - `LOOM_WIRE_ALLOW_INSECURE_AUTH_ON_PUBLIC_BIND=true|false` (default `false`; required if insecure auth is enabled on public bind)
  - `LOOM_WIRE_SMTP_ENABLED=true|false` (default `true` when wire gateway enabled)
  - `LOOM_WIRE_SMTP_STARTTLS_ENABLED=true|false` (default `true`)
  - `LOOM_WIRE_SMTP_PORT` (default `2525`)
  - `LOOM_WIRE_SMTP_MAX_MESSAGE_BYTES` (default `10485760`)
  - `LOOM_WIRE_LINE_MAX_BYTES` (default `32768`)
  - `LOOM_WIRE_LINE_BUFFER_MAX_BYTES` (default `131072`)
  - `LOOM_WIRE_IDLE_TIMEOUT_MS` (default `120000`)
  - `LOOM_WIRE_AUTH_MAX_FAILURES` (default `5`)
  - `LOOM_WIRE_MAX_CONNECTIONS` (default `500`)
  - `LOOM_WIRE_SMTP_MAX_CONNECTIONS` (default inherits `LOOM_WIRE_MAX_CONNECTIONS`)
  - `LOOM_WIRE_IMAP_MAX_CONNECTIONS` (default inherits `LOOM_WIRE_MAX_CONNECTIONS`)
    - `LOOM_WIRE_MAX_CONNECTIONS` is enforced as a global active-connection cap across SMTP and IMAP combined.
  - `LOOM_WIRE_IMAP_ENABLED=true|false` (default `true` when wire gateway enabled)
  - `LOOM_WIRE_IMAP_STARTTLS_ENABLED=true|false` (default `true`)
  - `LOOM_WIRE_IMAP_PORT` (default `1143`)
  - `LOOM_WIRE_TLS_ENABLED=true|false` (default `false`)
  - TLS material (required when wire TLS is enabled):
    - inline PEMs: `LOOM_WIRE_TLS_CERT_PEM`, `LOOM_WIRE_TLS_KEY_PEM`
    - or file paths: `LOOM_WIRE_TLS_CERT_FILE`, `LOOM_WIRE_TLS_KEY_FILE`
  - Startup safeguards:
    - Refuses authenticated wire gateway startup without TLS unless `LOOM_WIRE_ALLOW_INSECURE_AUTH=true`.
    - Refuses insecure-auth public bind unless `LOOM_WIRE_ALLOW_INSECURE_AUTH_ON_PUBLIC_BIND=true`.

Production baseline:

- Run behind a reverse proxy that enforces TLS 1.3 and HTTP/2 for public traffic (or enable native TLS/HTTP2 mode with TLSv1.3), set `LOOM_PUBLIC_SERVICE=true`, and keep `LOOM_REQUIRE_HTTPS_FROM_PROXY=true` when proxy-terminating TLS.
- Use `LOOM_TRUST_PROXY_ALLOWLIST` so forwarded client IP headers are accepted only from trusted proxy source IP/CIDR ranges.
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

Production env validation:

```bash
npm run check:prod-env -- --env-file .env.production
```

Secret hygiene validation:

```bash
npm run check:secrets
```

PostgreSQL persistence readiness validation:

```bash
npm run check:pg -- --env-file .env.production --expected-schema 3
```

Federation outbound-control validation:

```bash
npm run check:federation -- --env-file .env.production
```

Inbound bridge hardening validation:

```bash
npm run check:inbound-bridge -- --env-file .env.production
```

Focused inbound bridge negative tests:

```bash
npm run test:inbound-bridge-hardening
```

Rate-limit policy validation:

```bash
npm run check:rate-limits -- --env-file .env.production
```

Rate-limit probe run (staging/pre-prod):

```bash
npm run probe:rate-limits -- --base-url https://<loom-host> --expect-default-max 1000 --expect-sensitive-max 160
```

Outbox worker reliability validation:

```bash
npm run check:outbox-workers -- --env-file .env.production
```

Observability and alerting validation:

```bash
npm run check:observability -- --env-file .env.production
```

Request tracing validation:

```bash
npm run check:tracing -- --env-file .env.production
```

Threat model validation:

```bash
npm run check:threat-model
```

Security testing program validation:

```bash
npm run check:security-program
```

Capacity/chaos readiness validation:

```bash
npm run check:capacity-chaos
```

Disaster recovery plan validation:

```bash
npm run check:dr-plan
```

Access governance validation:

```bash
npm run check:access-governance
```

Compliance controls validation:

```bash
npm run check:compliance
```

Compliance runtime evidence drill:

```bash
npm run drill:compliance -- --base-url https://<loom-host> --admin-token <admin-token> --bearer-token <audit-bearer-token>
```

Compliance drill with automatic temporary audit-token bootstrap:

```bash
npm run drill:compliance -- --base-url https://<loom-host> --admin-token <admin-token> --bootstrap-audit-token
```

Compliance gate (static check + runtime drill):

```bash
npm run gate:compliance -- --base-url https://<loom-host> --admin-token <admin-token> --bootstrap-audit-token
```

Incident response/on-call readiness validation:

```bash
npm run check:incident-response
```

Release gate baseline validation:

```bash
npm run check:release-gates
```

End-to-end release gate (runs full pre-deploy validation sequence):

```bash
npm run gate:release -- --env-file .env.production --base-url https://<loom-host> --admin-token <admin-token> --bearer-token <audit-bearer-token> --interop-targets-file ops/federation/interop-targets.json
```

Federation interop drill:

```bash
npm run drill:federation-interop -- --base-url https://<loom-host> --admin-token <admin-token> --remote-node-id <external-node-id>
```

Federation interop matrix drill (staging + pre-prod):

```bash
npm run drill:federation-interop-matrix -- --targets-file ops/federation/interop-targets.json --required-targets staging,preprod
```

Federation interop target config validation (non-local, distinct staging/preprod origins):

```bash
npm run check:federation-targets -- --targets-file ops/federation/interop-targets.json --required-targets staging,preprod
```

Federation interop evidence validation:

```bash
npm run check:federation-interop -- --required-targets staging,preprod --max-age-hours 168 --expected-targets-file ops/federation/interop-targets.json
```

Persistence backup/restore drill:

```bash
npm run drill:persistence -- --base-url https://<loom-host> --execute-restore
```

## Notes

- This is a protocol-development scaffold, not production-ready.
- `package.json` intentionally keeps `"private": true` to prevent accidental npm publication; source remains fully open in this repository under Apache-2.0.
- Legacy compatibility now includes both API-level gateway behavior (`/v1/gateway/*` + bridge/relay) and an optional wire-level gateway daemon (SMTP + IMAP + optional STARTTLS + extended mailbox commands). Full parity with all enterprise IMAP/SMTP extensions is still a separate hardening track.
- Wire SMTP now advertises and accepts the `SMTPUTF8` ESMTP parameter for gateway-compatible flows.
- Inbound internet-email authentication (SPF/DKIM/DMARC verification and policy enforcement) is expected to run in an upstream MTA; the MVN inbound bridge route should remain private unless explicitly confirmed.
- Current wire IMAP limitation: `COPY`/`UID COPY` are intentionally rejected because LOOM mailbox state currently models a single effective folder per thread participant.
- Wire IMAP compatibility profile and extension coverage are tracked in `docs/IMAP-COMPATIBILITY-MATRIX.md`.
- Compliance control mapping (audit export + retention + policy links) is tracked in `docs/COMPLIANCE-CONTROLS.md`.
- Federation abuse/rate-policy hardening is implemented for baseline operations; deeper interoperability coverage can be extended.
- Production hardening included in this MVP baseline: payload-size guard, sensitive-route rate limiting, and automatic outbox worker loop.
- Operational surfaces included: `/ready`, Prometheus `/metrics`, `/v1/admin/status`, outbound email relay outbox with worker automation.
- Optional production persistence backend now included: PostgreSQL (`LOOM_PG_URL`).
- Persistence operations now include admin schema status, backup export, and restore APIs.
- Operational recovery surfaces include admin DLQ inspection + requeue for failed outbox deliveries.
- Signed webhook receipt delivery is supported via webhook subscriptions and webhook outbox processing endpoints.
- For retries from clients, send `Idempotency-Key` header on supported POST mutations (for example: `/v1/envelopes`, `/v1/email/outbox`, `/v1/bridge/email/send`, `/v1/gateway/smtp/submit`, `/v1/federation/outbox`).
