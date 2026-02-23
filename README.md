# LOOM Protocol Workspace

This repository tracks **LOOM** (Linked Operations & Orchestrated Messaging).

## Quick start

Clone and run locally:

```bash
git clone https://github.com/mesutgenai/loom-mvn.git
cd loom-mvn
npm install
npm start
```

Then open:

- Live console UI: `http://127.0.0.1:8787/`
- Ready check: `http://127.0.0.1:8787/ready`
- Node document: `http://127.0.0.1:8787/.well-known/loom.json`

For full account setup and send/receive walkthrough, jump to `Guided local setup (server + accounts + email)` below.

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

Positioning baseline: **LOOM-native when possible, email-compatible always**.

## Current status

- Current release tag is `v0.4.1` (see `CHANGELOG.md` for release-level change history, including unreleased additions).
- Repository package version is `0.4.1` (`package.json`).
- npm publication is intentionally disabled (`"private": true`), so versioning is tracked in git tags/changelog rather than npm registry releases.
- Comprehensive automated tests are included (`npm test`) and also run in CI.
- Protocol modules cover all LOOM v1.1 specification sections plus security, compliance, and operational extensions.
- Protocol design docs are available in:
  - `CHANGELOG.md`
  - `LOOM-protocol-design.md`
  - `LOOM-specification-v1.0.md`
  - `LOOM-Protocol-Spec-v1.1.md`
  - `LOOM-Agent-First-Protocol-v2.0.md` (ground-up reboot draft)
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
  - `docs/NIST-COMPLIANCE.md`
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
  - `docs/LOOM-CORE.md`
  - `docs/EXTENSION-REGISTRY.md`
  - `docs/CONFIG-PROFILES.md`
- Community and governance docs:
  - `CONTRIBUTING.md`
  - `CODE_OF_CONDUCT.md`
  - `SUPPORT.md`
- A first **Minimum Viable Node (MVN)** implementation with optional disk persistence is in `src/`.
- Repository baseline now includes:
  - `LICENSE` (Apache-2.0)
  - GitHub Actions CI workflow (`.github/workflows/ci.yml`)

## Core vs Extensions

To keep independent implementation scope tractable, LOOM now documents a strict core cut-line and extension model in `docs/LOOM-CORE.md`, with formal extension governance in `docs/EXTENSION-REGISTRY.md`.

- **LOOM Core**: identity/addressing, canonical envelopes + signatures, thread DAG semantics, capability token baseline, federation trust wrapper baseline.
- **Extensions**: email bridge, legacy gateway, MCP runtime, workflow orchestration, E2EE profiles, compliance/operational overlays.
- Runtime profile switch: `LOOM_PROTOCOL_PROFILE=loom-core-1` disables extension routes and extension ingest semantics by default.
- Runtime discovery endpoint: `GET /v1/protocol/extensions` returns machine-readable extension enablement state for the active profile.

## Ground-Up Reboot Track (v2.0 Draft)

The repository now includes a v2.0 reboot draft focused on closing protocol gaps identified in the latest evaluation report:

- explicit trust anchors and authority validation (`src/protocol/trust.js`)
- signing-key lifecycle enforcement primitives (`src/protocol/key_lifecycle.js`)
- strict E2EE profile validation plus concrete X25519+HKDF+XChaCha20 payload/attachment encrypt-decrypt, wrapped-key packaging, and replay/commitment metadata enforcement (`src/protocol/e2ee.js`)
- store internals split into explicit protocol core, policy engine, and adapter modules (`src/node/store/protocol_core.js`, `src/node/store/policy_engine.js`, `src/node/store/adapters.js`)
- publishable conformance fixtures for cross-language implementations (`test/fixtures/conformance/`)

See `LOOM-Agent-First-Protocol-v2.0.md` for the structural blueprint.

## MVN features implemented

- Envelope shape validation (`loom: "1.1"`, ids, recipients, content checks)
- RFC 8785 canonical JSON serialization (excludes `signature` and `meta`, deterministic member ordering, explicit JCS number serialization per RFC 8785 Section 3.2.2.3, rejects unsupported/non-finite values and lone surrogates)
- Ed25519 envelope signing and verification with domain-separated signature context prefix (`LOOM-ENVELOPE-SIG-v1\0`); legacy non-prefixed verification accepted during migration window
- Thread DAG validation and canonical rendering order with O(1) queue operations for large threads
- Thread size limits enforced at ingest: configurable `max_envelopes_per_thread` (default 10000) and `max_pending_parents` (default 500), overridable per-ingest via context
- Proof-of-key auth (`challenge` -> signed nonce -> bearer token)
- Optional proof-of-key identity registration (`/v1/identity/challenge` + `registration_proof`)
- Imported remote identities are stored in a read-only remote cache namespace with TTL-based expiry
- Private-by-default mailbox reads: thread/envelope read endpoints require bearer auth unless explicit demo mode is enabled
- Capability token hardening: one-time presentation secret, hashed-at-rest secret tracking, signed portable capability tokens, `thread_op` authorization via portable payload token or legacy header presentation token, and optional Proof-of-Possession (PoP) via `cnf.key_id` binding with `LOOM-CAPABILITY-POP-v1\0` context-prefixed signature verification for sensitive intents
- `thread_op` authorization with owner/capability enforcement
- Agent delegation-chain verification with signature/scope/revocation checks, `created_at` enforcement, configurable max chain depth (default 10), root delegator type binding, and domain-separated delegation signature context (`LOOM-DELEGATION-SIG-v1\0`)
- Optional disk persistence (`LOOM_DATA_DIR`) with hash-chained audit log
- Envelope `from.device_id` support for multi-device replay tracking (1-128 character string, optional)
- Configurable replay protection: `strict` mode (monotonic counter) or `sliding_window` mode (64-entry sliding window allowing out-of-order delivery); replay state keyed by `senderIdentity:deviceId`
- E2EE profile security property labels (`forward_secrecy`, `post_compromise_security`, `confidentiality`) on all profiles, including active MLS profile support (`loom-e2ee-mls-1`) for RFC 9420-grade properties
- Protocol module library covering all LOOM v1.1 specification sections:
  - Intent taxonomy validation (`src/protocol/intents.js`) — validates intent strings against the v1.1 taxonomy
  - Delivery/read/failure receipts (`src/protocol/receipts.js`) — system-generated receipt envelope builders
  - Hash-chained audit log entries (`src/protocol/audit_log.js`) — audit entry creation and chain verification
  - Retention policies (`src/protocol/retention.js`) — policy normalization, expiry resolution, legal hold checks
  - Content deletion and crypto-shredding (`src/protocol/deletion.js`) — erasure records and shred builders
  - Identity discovery (`src/protocol/discovery.js`) — well-known identity resolution helpers
  - Distribution and routing policies (`src/protocol/distribution.js`) — team expansion, moderation checks
  - Autoresponder rules (`src/protocol/autoresponder.js`) — auto-reply generation with loop prevention and frequency limiting
  - Channel automation rules (`src/protocol/channel_rules.js`) — label/quarantine/priority rule evaluation engine
  - Search filtering (`src/protocol/search.js`) — thread and envelope query matching (metadata-only for E2EE)
  - Mailbox import/export (`src/protocol/import_export.js`) — portable mailbox packaging and validation
  - Email bridge validation (`src/protocol/email_bridge.js`) — inbound/outbound bridge parameter validation
  - Legacy gateway transforms (`src/protocol/legacy_gateway.js`) — protocol translation for legacy systems
  - Blob validation (`src/protocol/blob.js`) — blob initiation and chunk validation
  - Real-time event log (`src/protocol/websocket.js`) — event emission, subscription messages, cursor-based retrieval
  - Rate limit headers (`src/protocol/rate_limit.js`) — RFC-compliant `RateLimit-*` header builders
  - Idempotency key validation (`src/protocol/idempotency.js`) — key format and TTL validation
  - MCP tool-use envelopes (`src/protocol/mcp.js`) — MCP request/response envelope validation
  - MLS key packages (`src/protocol/mls.js`) — MLS key package and welcome message validation
  - MLS TLS codec (`src/protocol/mls_codec.js`) — TLS-style encoding/decoding primitives
  - Workflow orchestration (`src/protocol/workflow.js`) — workflow state machine (execute → step_complete → complete/failed)
  - Inference provider identity (`src/protocol/agent_info.js`) — agent_info field validation and normalization
  - Agent card validation (`src/protocol/agent_card.js`) — A2A agent card schema validation and normalization
  - Agent trust scoring (`src/protocol/agent_trust.js`) — event-based trust scoring with decay, threshold enforcement, and level classification
  - Agent loop detection (`src/protocol/loop_protection.js`) — loop detection helpers for agent chains
  - Context window tracking (`src/protocol/context_window.js`) — token budget tracking for agent conversations
  - Prompt injection detection (`src/protocol/prompt_injection.js`) — heuristic scanner for 5 injection categories with configurable thresholds
  - MCP execution sandboxing (`src/protocol/mcp_sandbox.js`) — tool classification, size guards, permission checks, and rate limiting for MCP tools
  - MIME type registry (`src/protocol/mime_registry.js`) — type normalization, dangerous-type detection, configurable allow/deny policies
  - Protocol compliance auditing (`src/protocol/protocol_compliance.js`) — 23 automated compliance checks with scoring and level classification
  - Compression negotiation (`src/protocol/compression.js`) — Accept-Encoding/Content-Encoding negotiation for gzip, brotli, deflate
  - NIST SP 800-53 alignment (`src/protocol/nist_mapping.js`) — 29 controls across 7 families, SP 800-207 zero-trust mapping
  - Key rotation policy (`src/protocol/key_rotation.js`) — federation key rotation scheduling with grace periods, overlap windows, and audit trail
  - Search index (`src/protocol/search_index.js`) — in-memory inverted index with LRU eviction for efficient envelope lookups
- MCP client and server runtime modules (`src/node/mcp_client.js`, `src/node/mcp_server.js`) — tool-use request/response lifecycle with service identity management
- Store-integrated protocol features (all wired into the ingestion pipeline and state management):
  - Post-ingestion event emission for real-time event streams
  - Channel rules evaluation on every ingested envelope (label, quarantine, priority actions)
  - Autoresponder processing with loop prevention and per-sender frequency limiting
  - Workflow state tracking on threads (running → step_complete → complete/failed)
  - System-generated receipts (delivery, read, failure) with signed service identity
  - Content-level envelope deletion with legal hold enforcement
  - Thread-level crypto-shredding
  - Retention policy enforcement with legal hold awareness
  - Distribution routing policies and team recipient expansion
  - Validated search with URL parameter type coercion
  - Full mailbox export/import with thread and envelope preservation
  - Agent identity `agent_info` fields (provider, model, version, capabilities)
  - Agent card registration and discovery for agent-type identities
  - Agent trust scoring with event recording and threshold-based enforcement (warning/quarantine/block)
  - Prompt injection analysis on ingestion with escalation triggers and agent trust event recording
  - MCP sandbox enforcement (rate limits, tool permissions, argument/result size guards)
  - MIME policy enforcement on blob creation (dangerous-type detection, configurable allow/deny)
  - Protocol compliance auditing with 23 automated checks and scoring
  - Transparent response compression via Accept-Encoding negotiation (gzip/br/deflate)
  - NIST SP 800-53 compliance summary cross-referencing 29 controls with audit results
  - Federation key rotation management (assessment, execution, history, serialized policy)
  - Search index with auto-indexing on ingestion, removal on retention sweep, and indexed fast-path in searchEnvelopes
  - Cursor-based event log retrieval
  - Rate limit response headers on 429 errors
- Informational JSON Schema (draft 2020-12) published at `src/protocol/schemas/envelope-v1.1.schema.json`; in-code `validateEnvelopeShape` remains authoritative
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
- Federation protocol-capability negotiation with enforceable trust-mode parity and E2EE-profile overlap policy gates
- Outbound federation outbox with retry-based store-and-forward processing and per-node deliver URL safety enforcement
- Outbox claim leasing hooks for distributed worker coordination (`email`, `federation`, `webhook`)
- Automatic periodic federation trust-anchor revalidation worker with admin/runtime visibility
- SMTP/IMAP gateway interoperability hardening (address-list parsing, case-insensitive headers, folder aliases)
- Optional wire-level legacy gateway daemon (SMTP submission + IMAP mailbox access) for legacy clients, with optional STARTTLS support and extended IMAP commands (`STATUS`, `SEARCH`, `FETCH`, `STORE`, `APPEND` including IMAP literal mode, `IDLE`, `MOVE`, `UID SEARCH`, `UID FETCH`, `UID STORE`, `UID MOVE`, `UID THREAD`, `UID SORT`)
- Inbound bridge content filter with profile-aware policy (`strict|balanced|agent`), profile-labeled decision counters, optional anonymized decision telemetry log, and admin canary/apply/rollback workflow
- Outbound MIME attachment mapping from LOOM blob-backed envelope attachments
- DSN-style per-recipient delivery status updates for email outbox entries
- Recipient-view delivery wrappers for BCC privacy (`delivery.wrapper@v1`) with per-recipient visible roster
- Per-user mailbox state (`seen`, `flagged`, `archived`, `deleted`) without mutating other participants
- Idempotency-key replay protection for key POST mutations
- Webhook destination hardening (private-network block by default with per-webhook override)
- Maintenance sweep support for token/cache cleanup and retention enforcement (`message` + `blob` policies)
- Admin persistence operations: schema status, backup export, and restore
- In-memory node API:
  - Profile note: endpoints marked as extension surfaces are disabled (fail-closed `404`) when `LOOM_PROTOCOL_PROFILE=loom-core-1` unless extension/profile policy enables them; disabled extension routes return `EXTENSION_DISABLED` and can expose or redact machine-readable disable details by policy.
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
  - `GET /v1/search?q=...&type=...&intent=...` (validated search with type coercion)
  - `GET /v1/events?cursor=...` (cursor-based real-time event retrieval)
  - `GET /v1/export` (full mailbox export)
  - `POST /v1/import` (mailbox import with validation)
  - `DELETE /v1/envelopes/{id}/content` (content-level envelope deletion with legal hold enforcement)
  - `POST /v1/admin/retention/enforce` (admin token required; trigger retention policy enforcement)
  - `GET /v1/audit?limit=...`
  - `POST /v1/bridge/email/inbound` (extension: `loom-ext-email-bridge-v1`)
  - `POST /v1/bridge/email/outbound` (extension: `loom-ext-email-bridge-v1`)
  - `POST /v1/bridge/email/send` (queue + immediate relay attempt; extension: `loom-ext-email-bridge-v1`)
  - `POST /v1/email/outbox`
  - `GET /v1/email/outbox`
  - `POST /v1/email/outbox/process`
  - `POST /v1/email/outbox/{id}/process`
  - `POST /v1/email/outbox/{id}/dsn`
  - `GET /v1/gateway/imap/folders` (extension: `loom-ext-legacy-gateway-v1`)
  - `GET /v1/gateway/imap/folders/{folder}/messages?limit=...` (extension: `loom-ext-legacy-gateway-v1`)
  - `POST /v1/gateway/smtp/submit` (extension: `loom-ext-legacy-gateway-v1`)
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
  - `GET /v1/protocol/capabilities` (supported E2EE profiles + federation trust-anchor negotiation posture)
  - `GET /v1/protocol/extensions` (machine-readable extension registry + runtime enablement state)
  - `GET /v1/mcp/tools` (extension: `loom-ext-mcp-runtime-v1`)
  - `GET /v1/mcp/sse` (extension: `loom-ext-mcp-runtime-v1`)
  - `POST /v1/mcp/message` (extension: `loom-ext-mcp-runtime-v1`)
  - `GET /.well-known/loom-capabilities.json` (well-known alias for protocol capabilities)
  - `GET /.well-known/loom-keyset.json` (signed federation keyset)
  - `GET /.well-known/loom-revocations.json` (signed federation key revocations)
  - `GET /.well-known/loom-trust.json` (DNS TXT publication descriptor)
  - `GET /.well-known/loom-trust.txt` (ready-to-publish DNS TXT value)
  - `GET /v1/federation/trust` (admin token required; current trust posture/config)
  - `GET /v1/federation/trust/verify-dns` (admin token required; verifies published DNS TXT trust anchor)
  - `POST /v1/federation/trust` (admin token required; rotate trust epoch/version/revocations)
  - `POST /v1/federation/nodes`
  - `POST /v1/federation/nodes/bootstrap` (discovery bootstrap)
  - `POST /v1/federation/nodes/revalidate` (batch trust-anchor revalidation for known peers)
  - `POST /v1/federation/nodes/{node_id}/revalidate` (single-node trust-anchor revalidation)
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
  - `GET /v1/admin/content-filter/config` (admin token required)
  - `POST /v1/admin/content-filter/config` (admin token required; `mode=canary|apply|rollback`)
  - `GET /v1/admin/persistence/schema` (admin token required)
  - `GET /v1/admin/persistence/backup` (admin token required)
  - `POST /v1/admin/persistence/restore` (admin token required, `confirm=restore`)
  - `GET /v1/admin/agent-trust` (admin token required; agent trust status)
  - `GET /v1/admin/compliance/audit` (admin token required; detailed compliance audit; extension: `loom-ext-compliance-v1`)
  - `GET /v1/admin/nist/summary` (admin token required; NIST compliance summary; extension: `loom-ext-compliance-v1`)
  - `GET /v1/admin/key-rotation/status` (admin token required; key rotation assessment)
  - `POST /v1/admin/key-rotation/rotate` (admin token required; trigger key rotation)
  - `GET /v1/admin/key-rotation/history` (admin token required; rotation audit trail)
  - `GET /v1/admin/search-index/status` (admin token required; search index stats)
  - `GET /v1/protocol/compliance` (protocol compliance score and audit report; extension: `loom-ext-compliance-v1`)
  - `GET /v1/mime/registry` (MIME type registry and policy; extension: `loom-ext-compliance-v1`)
  - `GET /v1/agents` (agent card discovery)

## Run

From a fresh machine:

```bash
git clone https://github.com/mesutgenai/loom-mvn.git
cd loom-mvn
npm install
npm start
```

If you are already in the repository:

```bash
npm start
```

Server defaults:

- Host: `127.0.0.1`
- Port: `8787`
- Live console UI: `http://127.0.0.1:8787/`
- Node document: `http://127.0.0.1:8787/.well-known/loom.json`

### Guided local setup (server + accounts + email)

This walkthrough is intentionally step-by-step so you can run and inspect each phase.

1) Install dependencies (Node 22+ required):

```bash
npm install
```

2) Create a local env file (dev-safe defaults):

```bash
cat > .env.local <<'EOF'
HOST=127.0.0.1
PORT=8787
LOOM_NODE_ID=node.test
LOOM_DOMAIN=127.0.0.1:8787
LOOM_SMTP_MODE=stream
LOOM_SMTP_DEFAULT_FROM=no-reply@node.test
EOF
```

3) Start the server in one terminal:

```bash
set -a
source .env.local
set +a
npm start
```

4) Check readiness from another terminal:

```bash
curl -sS http://127.0.0.1:8787/ready
```

5) Create two local agent accounts (identities + signing keys):

```bash
BASE_URL="http://127.0.0.1:8787"
WORK="${TMPDIR:-/tmp}/loom-quickstart-$(date +%s)"
mkdir -p "$WORK"

WORK="$WORK" node --input-type=module <<'NODE'
import { mkdirSync, writeFileSync } from "node:fs";
import { generateSigningKeyPair } from "./src/protocol/crypto.js";

const work = process.env.WORK;
mkdirSync(work, { recursive: true });

const actors = [
  { name: "alice", identity: "loom://alice@node.test", display: "Alice", keyId: "k_sign_alice_1" },
  { name: "bob", identity: "loom://bob@node.test", display: "Bob", keyId: "k_sign_bob_1" }
];

for (const actor of actors) {
  const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();
  writeFileSync(`${work}/${actor.name}.private.pem`, privateKeyPem);
  writeFileSync(
    `${work}/${actor.name}.identity.json`,
    JSON.stringify(
      {
        id: actor.identity,
        display_name: actor.display,
        signing_keys: [{ key_id: actor.keyId, public_key_pem: publicKeyPem }]
      },
      null,
      2
    )
  );
}
NODE

curl -sS -X POST "$BASE_URL/v1/identity" \
  -H 'content-type: application/json' \
  --data @"$WORK/alice.identity.json" > "$WORK/alice.identity.response.json"

curl -sS -X POST "$BASE_URL/v1/identity" \
  -H 'content-type: application/json' \
  --data @"$WORK/bob.identity.json" > "$WORK/bob.identity.response.json"
```

6) Authenticate both accounts (challenge -> signed nonce -> token):

```bash
curl -sS -X POST "$BASE_URL/v1/auth/challenge" \
  -H 'content-type: application/json' \
  --data '{"identity":"loom://alice@node.test","key_id":"k_sign_alice_1"}' > "$WORK/alice.challenge.json"

curl -sS -X POST "$BASE_URL/v1/auth/challenge" \
  -H 'content-type: application/json' \
  --data '{"identity":"loom://bob@node.test","key_id":"k_sign_bob_1"}' > "$WORK/bob.challenge.json"

WORK="$WORK" node --input-type=module <<'NODE'
import { readFileSync, writeFileSync } from "node:fs";
import { signUtf8Message } from "./src/protocol/crypto.js";

const work = process.env.WORK;

function buildTokenRequest(name, identity, keyId) {
  const challenge = JSON.parse(readFileSync(`${work}/${name}.challenge.json`, "utf8"));
  const privateKeyPem = readFileSync(`${work}/${name}.private.pem`, "utf8");
  const payload = {
    identity,
    key_id: keyId,
    challenge_id: challenge.challenge_id,
    signature: signUtf8Message(privateKeyPem, challenge.nonce)
  };
  writeFileSync(`${work}/${name}.token.request.json`, JSON.stringify(payload, null, 2));
}

buildTokenRequest("alice", "loom://alice@node.test", "k_sign_alice_1");
buildTokenRequest("bob", "loom://bob@node.test", "k_sign_bob_1");
NODE

curl -sS -X POST "$BASE_URL/v1/auth/token" \
  -H 'content-type: application/json' \
  --data @"$WORK/alice.token.request.json" > "$WORK/alice.token.json"

curl -sS -X POST "$BASE_URL/v1/auth/token" \
  -H 'content-type: application/json' \
  --data @"$WORK/bob.token.request.json" > "$WORK/bob.token.json"

ALICE_TOKEN="$(node -e "const fs=require('fs');const j=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));process.stdout.write(j.access_token)" "$WORK/alice.token.json")"
BOB_TOKEN="$(node -e "const fs=require('fs');const j=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));process.stdout.write(j.access_token)" "$WORK/bob.token.json")"
```

7) Send a signed LOOM envelope from Alice to Bob:

```bash
WORK="$WORK" node --input-type=module <<'NODE'
import { readFileSync, writeFileSync } from "node:fs";
import { signEnvelope } from "./src/protocol/crypto.js";
import { generateUlid } from "./src/protocol/ulid.js";

const work = process.env.WORK;
const privateKeyPem = readFileSync(`${work}/alice.private.pem`, "utf8");
const threadId = `thr_${generateUlid()}`;

const envelope = signEnvelope(
  {
    loom: "1.1",
    id: `env_${generateUlid()}`,
    thread_id: threadId,
    parent_id: null,
    type: "message",
    from: {
      identity: "loom://alice@node.test",
      display: "Alice",
      key_id: "k_sign_alice_1",
      type: "agent"
    },
    to: [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: new Date().toISOString(),
    priority: "normal",
    content: {
      human: { text: "Hello Bob from Alice", format: "markdown" },
      structured: { intent: "message.general@v1", parameters: {} },
      encrypted: false
    },
    attachments: []
  },
  privateKeyPem,
  "k_sign_alice_1"
);

writeFileSync(`${work}/alice-to-bob.envelope.json`, JSON.stringify(envelope, null, 2));
NODE

curl -sS -X POST "$BASE_URL/v1/envelopes" \
  -H "authorization: Bearer $ALICE_TOKEN" \
  -H 'content-type: application/json' \
  --data @"$WORK/alice-to-bob.envelope.json" > "$WORK/send.response.json"

THREAD_ID="$(node -e "const fs=require('fs');const j=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));process.stdout.write(j.thread_id)" "$WORK/send.response.json")"
ENVELOPE_ID="$(node -e "const fs=require('fs');const j=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));process.stdout.write(j.id)" "$WORK/send.response.json")"
```

8) Verify Bob can read the thread:

```bash
curl -sS "$BASE_URL/v1/threads/$THREAD_ID/envelopes" \
  -H "authorization: Bearer $BOB_TOKEN" > "$WORK/bob.thread.json"

node -e "const fs=require('fs');const j=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));console.log('thread_id=',j.thread_id,'envelopes=',(j.envelopes||[]).length)" "$WORK/bob.thread.json"
```

9) Send that envelope out through the email relay:

```bash
curl -sS -X POST "$BASE_URL/v1/bridge/email/send" \
  -H "authorization: Bearer $ALICE_TOKEN" \
  -H 'content-type: application/json' \
  --data "{\"envelope_id\":\"$ENVELOPE_ID\",\"to_email\":[\"bob@example.net\"],\"smtp_from\":\"no-reply@node.test\"}" \
  > "$WORK/email.send.response.json"

cat "$WORK/email.send.response.json"
```

Notes:
- `LOOM_SMTP_MODE=stream` is for local testing; it validates the flow without delivering to a real external mailbox.
- For real outbound delivery, switch to `LOOM_SMTP_MODE=smtp` and set SMTP provider credentials (`LOOM_SMTP_HOST`, `LOOM_SMTP_PORT`, `LOOM_SMTP_USER`, `LOOM_SMTP_PASS`, optionally `LOOM_SMTP_SECURE`).

10) Optional gateway-style test (SMTP submit + IMAP view via API):

```bash
curl -sS -X POST "$BASE_URL/v1/gateway/smtp/submit" \
  -H "authorization: Bearer $ALICE_TOKEN" \
  -H 'content-type: application/json' \
  --data '{"to":["bob@node.test"],"text":"hello via gateway api"}'

curl -sS "$BASE_URL/v1/gateway/imap/folders/INBOX/messages?limit=10" \
  -H "authorization: Bearer $BOB_TOKEN"
```

There is no separate mailbox provisioning step for local identities. If an identity exists as `loom://alice@node.test`, gateway-style email addressing resolves as `alice@node.test`.

Optional persistence:

- Set `LOOM_DATA_DIR=/absolute/path` to persist state and audit log between restarts.
- Optional secure-profile defaults:
  - Set `LOOM_CONFIG_PROFILE=secure_public` to apply hardened public-service defaults without setting every individual guard variable.
  - Start from `.env.secure-public.example` for the reduced-surface profile template.
  - Explicit env values and explicit server options always override profile defaults.
- Protocol profile/runtime extension surface:
  - `LOOM_PROTOCOL_PROFILE=loom-v1.1-full|loom-core-1` (default `loom-v1.1-full`).
  - `LOOM_CONFIG_PROFILE=secure_public` does not force `loom-core-1`; set `LOOM_PROTOCOL_PROFILE` explicitly when you want core-only runtime behavior.
  - Optional extension toggles (ignored in `loom-core-1`): `LOOM_EXTENSION_EMAIL_BRIDGE_ENABLED`, `LOOM_EXTENSION_LEGACY_GATEWAY_ENABLED`, `LOOM_EXTENSION_MCP_RUNTIME_ENABLED`, `LOOM_EXTENSION_WORKFLOW_ENABLED`, `LOOM_EXTENSION_E2EE_ENABLED`, `LOOM_EXTENSION_COMPLIANCE_ENABLED`.
  - Route-level toggles (also subject to extension/profile gates): `LOOM_BRIDGE_EMAIL_INBOUND_ENABLED`, `LOOM_BRIDGE_EMAIL_OUTBOUND_ENABLED`, `LOOM_BRIDGE_EMAIL_SEND_ENABLED`, `LOOM_GATEWAY_IMAP_ENABLED`, `LOOM_GATEWAY_SMTP_SUBMIT_ENABLED`, `LOOM_MCP_RUNTIME_ROUTES_ENABLED`, `LOOM_COMPLIANCE_ROUTES_ENABLED`.
  - Optional extension-disable diagnostics policy: `LOOM_EXTENSION_DISABLE_ERROR_DIAGNOSTICS=true|false` (default `false` on public service, else `true`).
- Optional local state-file encryption at rest:
  - `LOOM_STATE_ENCRYPTION_KEY` (32-byte key as base64url/base64/hex)
  - `LOOM_REQUIRE_STATE_ENCRYPTION_AT_REST=true|false` (when `true`, plaintext state files are refused)
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
- Public-service signing key hardening:
  - `LOOM_REQUIRE_EXTERNAL_SIGNING_KEYS=true` is required on public service.
  - `LOOM_SYSTEM_SIGNING_KEY_ID` defines the local bridge/system signing key id (default `k_sign_system_1`).
  - `LOOM_SYSTEM_SIGNING_PRIVATE_KEY_PEM` and `LOOM_NODE_SIGNING_PRIVATE_KEY_PEM` must be externally provisioned (no auto-generated fallback).
  - `LOOM_SYSTEM_SIGNING_PUBLIC_KEY_PEM` is optional (derived from private key when omitted).
  - `LOOM_REQUIRE_DISTINCT_FEDERATION_SIGNING_KEY=true|false` enforces different key material for system vs federation signing.
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
- Set `LOOM_REPLAY_MODE=strict|sliding_window` (default `sliding_window`) to control envelope replay protection mode.
- Set thread size limits to control thread growth:
  - `LOOM_THREAD_MAX_ENVELOPES_PER_THREAD` (default `10000`; set `0` to disable)
  - `LOOM_THREAD_MAX_PENDING_PARENTS` (default `500`; set `0` to disable)
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
- Optional strict federation capability negotiation gates:
  - `LOOM_FEDERATION_REQUIRE_PROTOCOL_CAPABILITIES=true|false` (require remote `/v1/protocol/capabilities` publication)
  - `LOOM_FEDERATION_REQUIRE_E2EE_PROFILE_OVERLAP=true|false` (require negotiated encrypted-profile overlap)
  - `LOOM_FEDERATION_REQUIRE_TRUST_MODE_PARITY=true|false` (require negotiated trust-anchor mode parity)
- Controlled E2EE profile migration policy:
  - `LOOM_E2EE_PROFILE_MIGRATION_ALLOWLIST` (comma/newline list of `fromProfile>toProfile` exceptions)
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
- Set periodic federation trust-anchor revalidation worker controls:
  - `LOOM_FEDERATION_TRUST_REVALIDATE_INTERVAL_MS` (default `900000`; set `0` to disable)
  - `LOOM_FEDERATION_TRUST_REVALIDATE_BATCH_LIMIT` (default `100`; max `1000`)
  - `LOOM_FEDERATION_TRUST_REVALIDATE_INCLUDE_NON_PUBLIC_MODES` (default `false`)
  - `LOOM_FEDERATION_TRUST_REVALIDATE_TIMEOUT_MS` (default `5000`)
  - `LOOM_FEDERATION_TRUST_REVALIDATE_MAX_RESPONSE_BYTES` (default `262144`)
- DNSSEC-backed federation trust-anchor resolution controls:
  - `LOOM_FEDERATION_TRUST_REQUIRE_DNSSEC=true|false` (default `true` on public service with `public_dns_webpki` mode)
  - `LOOM_FEDERATION_TRUST_DNS_RESOLVER_MODE=system|dnssec_doh` (default `system`)
  - `LOOM_FEDERATION_TRUST_DNSSEC_DOH_URL` (default `https://cloudflare-dns.com/dns-query` when `dnssec_doh` mode is used)
  - `LOOM_FEDERATION_TRUST_DNSSEC_DOH_TIMEOUT_MS` (default `5000`)
  - `LOOM_FEDERATION_TRUST_DNSSEC_DOH_MAX_RESPONSE_BYTES` (default `262144`)
  - `LOOM_FEDERATION_TRUST_MAX_CLOCK_SKEW_MS` (default `300000`)
  - `LOOM_FEDERATION_TRUST_KEYSET_MAX_AGE_MS` (default `86400000`)
  - `LOOM_FEDERATION_TRUST_KEYSET_PUBLISH_TTL_MS` (default `86400000`)
  - `LOOM_FEDERATION_TRUST_TRANSPARENCY_MODE` (default `local_append_only`)
  - `LOOM_FEDERATION_TRUST_REQUIRE_TRANSPARENCY=true|false` (default `true` on public service with `public_dns_webpki` mode)
  - `LOOM_FEDERATION_REVOKED_KEY_IDS` (comma-separated historical federation key ids to publish as revoked)
- Retention/maintenance controls:
  - `LOOM_MESSAGE_RETENTION_DAYS` (default `0`, disabled)
  - `LOOM_BLOB_RETENTION_DAYS` (default `0`, disabled)
  - `LOOM_MAINTENANCE_SWEEP_INTERVAL_MS` (default `60000`; set `0` to disable periodic sweeps)
- Compression controls:
  - `LOOM_COMPRESSION_ENABLED=true|false` (default `false`; enable transparent response compression)
  - `LOOM_COMPRESSION_MIN_SIZE` (default `1024`; minimum response size in bytes before compression applies)
  - `LOOM_COMPRESSION_ENCODING` (default `gzip`; preferred encoding: `gzip`, `br`, or `deflate`)
  - `LOOM_COMPRESSION_LEVEL` (default `6`; compression level 1-11)
- Key rotation policy controls:
  - `LOOM_KEY_ROTATION_MAX_AGE_DAYS` (default `90`; maximum federation signing key age before rotation)
  - `LOOM_KEY_ROTATION_GRACE_PERIOD_DAYS` (default `7`; grace period before key expires where rotation is recommended)
  - `LOOM_KEY_ROTATION_OVERLAP_HOURS` (default `24`; overlap window where old key remains valid during transition)
  - `LOOM_KEY_ROTATION_AUTO_ROTATE=true|false` (default `false`; enable automatic key rotation)
- Search index controls:
  - `LOOM_SEARCH_INDEX_ENABLED=true|false` (default `true`; enable in-memory search index for fast envelope lookups)
  - `LOOM_SEARCH_INDEX_MAX_ENTRIES` (default `100000`; maximum indexed envelopes before LRU eviction)
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
  - Server refuses bridged auto-actuation on public service unless explicitly confirmed via `LOOM_BRIDGE_EMAIL_INBOUND_AUTOMATION_CONFIRMED=true`.
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
    - `LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_PAYLOAD_AUTH_RESULTS=true|false` (default `true`; when `false`, only sanitized header auth evidence is trusted)
    - `LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_AUTOMATIC_ACTUATION=true|false` (default `false`; bridged senders remain non-authoritative unless explicitly enabled)
    - `LOOM_BRIDGE_EMAIL_INBOUND_AUTOMATION_CONFIRMED=true|false` (default `false`; required on public service when automatic actuation is enabled)
    - `LOOM_BRIDGE_EMAIL_INBOUND_HEADER_ALLOWLIST` (comma-separated inbound header names to retain in bridge metadata)
    - `LOOM_BRIDGE_EMAIL_INBOUND_WEAK_AUTH_POLICY_CONFIRMED=true|false` (default `false`; required only if you intentionally weaken public inbound auth policy defaults)
  - Inbound content filter controls:
    - `LOOM_INBOUND_CONTENT_FILTER_ENABLED=true|false` (default `true`)
    - `LOOM_INBOUND_CONTENT_FILTER_REJECT_MALWARE=true|false` (default `true`)
    - `LOOM_INBOUND_CONTENT_FILTER_PROFILE_DEFAULT=strict|balanced|agent` (default `balanced`)
    - `LOOM_INBOUND_CONTENT_FILTER_PROFILE_BRIDGE=strict|balanced|agent` (default inherits profile default)
    - `LOOM_INBOUND_CONTENT_FILTER_PROFILE_FEDERATION=strict|balanced|agent` (default `agent`)
    - `LOOM_INBOUND_CONTENT_FILTER_SPAM_THRESHOLD` (default `3`)
    - `LOOM_INBOUND_CONTENT_FILTER_PHISH_THRESHOLD` (default `3`)
    - `LOOM_INBOUND_CONTENT_FILTER_QUARANTINE_THRESHOLD` (default `4`)
    - `LOOM_INBOUND_CONTENT_FILTER_REJECT_THRESHOLD` (default `7`, must remain above quarantine threshold)
    - Optional anonymized decision telemetry:
      - `LOOM_INBOUND_CONTENT_FILTER_DECISION_LOG_ENABLED=true|false` (default `false`)
      - `LOOM_INBOUND_CONTENT_FILTER_DECISION_LOG_FILE` (default `${LOOM_DATA_DIR}/content-filter-decisions.jsonl` when `LOOM_DATA_DIR` is set)
      - `LOOM_INBOUND_CONTENT_FILTER_DECISION_LOG_SALT` (recommended rotated secret)
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

Content-filter corpus tuning (from anonymized decision telemetry or snapshot export):

```bash
npm run build:content-filter-corpus -- --decision-log-file <path-to-content-filter-decisions.jsonl>
```

Alternative corpus inputs:

```bash
npm run build:content-filter-corpus -- --data-dir <loom-data-dir>
npm run build:content-filter-corpus -- --state-file <state.json>
npm run build:content-filter-corpus -- --backup-file <backup.json>
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

Federation trust freshness drill (revalidation cycle + trust-anchor assertions):

```bash
npm run drill:federation-trust
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

Federation trust freshness drill (self-contained local+remote revalidation cycle):

```bash
npm run drill:federation-trust
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
- Wire IMAP supports boolean SEARCH composition (`OR`, `NOT`, grouped criteria) plus server-side `UID THREAD` (`REFERENCES|ORDEREDSUBJECT`) and `UID SORT`.
- Inbound internet-email authentication (SPF/DKIM/DMARC verification and policy enforcement) is expected to run in an upstream MTA; the MVN inbound bridge route should remain private unless explicitly confirmed.
- Current wire IMAP limitation: `COPY`/`UID COPY` are intentionally rejected because LOOM mailbox state currently models a single effective folder per thread participant.
- Wire IMAP compatibility profile and extension coverage are tracked in `docs/IMAP-COMPATIBILITY-MATRIX.md`.
- Compliance control mapping (audit export + retention + policy links) is tracked in `docs/COMPLIANCE-CONTROLS.md`.
- NIST SP 800-53 Rev 5 compliance mapping (29 controls, 7 families) and SP 800-207 zero-trust alignment documented in `docs/NIST-COMPLIANCE.md`.
- Federation signing key rotation policy is enforced via `key_rotation.js` with configurable max age, grace period, and overlap windows. Manual and automated rotation supported via admin API.
- In-memory search index (`search_index.js`) replaces linear-scan search when enabled, providing sub-millisecond lookups via multi-dimensional inverted index with LRU eviction.
- Federation abuse/rate-policy hardening is implemented for baseline operations; deeper interoperability coverage can be extended.
- Federation onboarding can be made fail-closed via strict protocol capability gates (`LOOM_FEDERATION_REQUIRE_PROTOCOL_CAPABILITIES`, `LOOM_FEDERATION_REQUIRE_E2EE_PROFILE_OVERLAP`, `LOOM_FEDERATION_REQUIRE_TRUST_MODE_PARITY`).
- Production hardening included in this MVP baseline: payload-size guard, sensitive-route rate limiting, and automatic outbox worker loop.
- Operational surfaces included: `/ready`, Prometheus `/metrics`, `/v1/admin/status`, outbound email relay outbox with worker automation.
- Optional production persistence backend now included: PostgreSQL (`LOOM_PG_URL`).
- Persistence operations now include admin schema status, backup export, and restore APIs.
- Periodic maintenance sweeps can enforce message/blob retention windows when configured.
- Operational recovery surfaces include admin DLQ inspection + requeue for failed outbox deliveries.
- Signed webhook receipt delivery is supported via webhook subscriptions and webhook outbox processing endpoints.
- For retries from clients, send `Idempotency-Key` header on supported POST mutations (for example: `/v1/envelopes`, `/v1/email/outbox`, `/v1/bridge/email/send`, `/v1/gateway/smtp/submit`, `/v1/federation/outbox`).
