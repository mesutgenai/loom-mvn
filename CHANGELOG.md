# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Extension Route Error Semantics

- Disabled extension routes now return `404` with `EXTENSION_DISABLED` instead of overloading `ENVELOPE_NOT_FOUND`.
- Error details now include machine-readable disable reason (`disabled_by_protocol_profile|disabled_by_extension_toggle|disabled_by_route_toggle`), extension id, and active protocol profile.
- Server tests updated to assert extension-disable semantics for both core-profile and route-toggle disable paths.
- Added diagnostics redaction control (`LOOM_EXTENSION_DISABLE_ERROR_DIAGNOSTICS`) so public deployments can suppress extension/profile metadata on disabled-route responses.

### Compliance Reference Alignment

- Compliance checks now publish canonical `reference` values aligned to v1.1 spec anchors (with `section` retained as a backward-compatible alias).
- Compliance report formatting now emits the canonical reference string for failed checks.
- Restored stable `section` values for compatibility-sensitive consumers while keeping canonical `reference` in all check/audit outputs.

### Bridge Metadata Documentation

- v1.1 spec bridge section now documents `meta.bridge.structured_trust` and structured non-authoritative trust hints (`authoritative=false`, `trust_level`, `auto_actuation_allowed`, reason metadata).
- Error-code registry now documents `EXTENSION_DISABLED`.

### Release/Docs Guardrails

- Added `.gitignore` exception for `.env.secure-public.example` so the secure-profile env template is committed and included in tagged releases.
- Release-gate checks now require `.env.secure-public.example` and verify required artifacts are tracked in git.
- Extension registry docs now include explicit identifier format examples.

## v0.4.1 — 2026-02-22

### Protocol Boundary Hardening

- Bridged sender envelopes are now non-actuating by default at ingest.
  - Bridge identities can submit only `type=message` with `message.general@v1` intent unless explicit opt-in is enabled.
  - New config: `LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_AUTOMATIC_ACTUATION` (default `false`).
  - Public-service safeguard: enabling bridged automatic actuation now also requires `LOOM_BRIDGE_EMAIL_INBOUND_AUTOMATION_CONFIRMED=true`.
- Inbound bridge envelopes now carry explicit non-authoritative structured trust metadata (`meta.bridge.structured_trust` and structured parameter trust hints).

### Naming Clarification

- Added canonical module name `protocol_compliance.js` and kept `atp_compliance.js` as backward-compatible re-export shim.
- Compliance report title updated to `LOOM Protocol Compliance Report`.

### Docs and Positioning

- README clone URLs updated to `mesutgenai/loom-mvn`.
- README and conformance release references aligned with `v0.4.1` / `0.4.1`.
- Added `docs/LOOM-CORE.md` defining `loom-core-1` cut-line and extension boundaries.
- Added `docs/EXTENSION-REGISTRY.md` with formal extension lifecycle + versioning rules.
- Added `docs/CONFIG-PROFILES.md` and `.env.secure-public.example` for reduced-surface secure deployment profile guidance.
- Updated bridge hardening runbook and production env example with explicit bridged auto-actuation controls.
- Updated v1.1 spec identity examples and rules to canonical lowercase identity serialization.
- Updated docs to reflect current runtime profile behavior and extension-gated routes (bridge/gateway/MCP/compliance overlays).
- Updated docs to include `GET /v1/protocol/extensions` as canonical machine-readable extension discovery endpoint.
- Updated docs/spec text to reflect active MLS wire profile status (`loom-e2ee-mls-1`) in the MVN conformance profile.
- Normalized legacy docs (`LOOM-protocol-design.md`, `LOOM-specification-v1.0.md`) to align with canonical lowercase identity rules, versioned intents (`@v1`), and bridge non-authoritative/non-actuating defaults.

### Core Runtime and Extension Discovery

- Added runtime protocol-profile enforcement via `LOOM_PROTOCOL_PROFILE` (`loom-v1.1-full` default, `loom-core-1` core-only).
- Added machine-readable extension registry endpoint: `GET /v1/protocol/extensions`.
- In `loom-core-1`, extension routes now fail closed (`404`) for bridge, gateway, MCP, and compliance overlays.
- In `loom-core-1`, ingest now rejects extension envelopes/intents with `CAPABILITY_DENIED`.
- Protocol capabilities now reflect extension state (MCP/compliance/E2EE advertisements are suppressed when disabled).
- Aligned extension lifecycle state for MLS with runtime behavior: `loom-ext-e2ee-mls-1` now reports `active` in extension discovery.

### Release Metadata

- Bumped repository/package version to `0.4.1` and synced lockfile metadata.
- Updated `LOOM_RELEASE_VERSION` runtime constant to `0.4.1`.

## v0.4.0 — 2026-02-21

Security hardening, compliance, and operational modules addressing
evaluation report gaps. Adds 10 new protocol modules, extends store
integration, and introduces new admin routes and env vars.

### New Protocol Modules

- **prompt_injection.js**: Heuristic prompt injection detection for
  envelope content. Pattern-based scanning across 5 categories
  (instruction override, role manipulation, delimiter injection, data
  exfiltration, encoding evasion) with configurable sender-type
  thresholds and escalation triggers (Section 26.2).
- **mcp_sandbox.js**: Execution sandboxing for MCP tool invocations.
  Tool classification (read/write/admin), argument and result size
  enforcement, permission checks, and rate limiter factory (Section 22.3).
- **agent_card.js**: Agent card schema validation and normalization per
  A2A (Agent-to-Agent) specification. Validates capabilities, auth
  schemes, endpoints, and provider metadata (Section 25.2).
- **agent_trust.js**: Agent trust scoring with event-based decay,
  configurable thresholds for warning/quarantine/block levels, and
  trust level classification. Supports violation recording, score
  computation, and enforcement assertions (Section 25.4).
- **mime_registry.js**: MIME type registry with type normalization,
  dangerous-type detection, and configurable allow/deny policies.
  Covers text, image, document, audio, video, and dangerous type
  categories (Section 14.2).
- **atp_compliance.js**: ATP (Authenticated Transfer Protocol)
  compliance audit engine with 23 automated checks, scoring (0-100),
  and compliance level classification (full/high/partial/low/none).
  Cross-references store capabilities against protocol requirements
  (Section 28).
- **compression.js**: Accept-Encoding/Content-Encoding negotiation
  with gzip, brotli, and deflate support. Quality-value parsing,
  encoding selection, and configurable compression policies with
  minimum size thresholds (Section 29).
- **nist_mapping.js**: NIST SP 800-53 Rev 5 control mapping with 29
  controls across 7 families (AC, AU, IA, SC, SI, CM, IR) and 5
  SP 800-207 zero-trust principle alignments. Coverage computation
  and formatted compliance reporting (Section 30).
- **key_rotation.js**: Formalized rotation scheduling for federation
  signing keys. Policy-based state machine with 7 states (current,
  grace, expired, overlap, retired, revoked, pending), rotation needs
  assessment, action plan generation, and structured audit trail
  (Section 25.5).
- **search_index.js**: In-memory term-based inverted index for
  efficient envelope lookups. Bounded memory via LRU eviction with
  configurable max entries. Multi-dimensional indexing (sender, intent,
  type, thread, date bucket, text terms) with set-intersection query
  strategy (Section 16.7).

### Store Integration

All 10 modules wired into the store and ingestion pipeline:

- **Prompt injection**: Envelope ingestion analyzes content for
  injection signals. High-signal envelopes from agents trigger
  `requires_human_escalation` and `sys.injection` thread labels.
  Violations recorded as agent trust events.
- **MCP sandboxing**: Rate limiting, argument/result size enforcement,
  tool permission checks, and write-tool guards applied to MCP tool
  request processing in both mcp_client and mcp_server.
- **Agent cards**: `registerAgentCard()` and `getAgentCard()` with
  full schema validation and normalization on agent-type identities.
- **Agent trust**: `recordAgentTrustEvent()`, `getAgentTrustScore()`,
  `assertAgentTrustForIngestion()` with configurable decay windows
  and threshold-based enforcement (warning/quarantine/block).
- **MIME policy**: `isDangerousMimeType()` and `isAllowedBlobMimeType()`
  enforcement on blob creation with configurable allow/deny lists.
- **ATP compliance**: `runComplianceAudit()` produces 23-check audit
  reports. `getComplianceScore()` and `getComplianceNodeState()`.
- **Compression**: Transparent response compression via
  `res._compressionCtx` on all `sendJson` call sites. Inbound
  Content-Encoding decompression in `readRawBody`.
- **NIST alignment**: `getNistComplianceSummary()` cross-references
  29 NIST controls with compliance audit results per family.
- **Key rotation**: `assessKeyRotationStatus()` evaluates federation
  signing keys against rotation policy. `executeKeyRotation()`
  generates new key pairs and bumps keyset version. History tracked
  and serialized. Policy configurable via env vars.
- **Search index**: Envelopes auto-indexed on ingestion and removed
  on retention sweep. `searchEnvelopes()` uses indexed fast-path
  with set-intersection when available, falling back to linear scan.
  Index rebuilt from stored envelopes on state load.

### New HTTP Endpoints

- `GET /v1/protocol/compliance` — ATP compliance score and audit
- `GET /v1/mime/registry` — MIME type registry and policy
- `GET /v1/agents` — agent card discovery
- `GET /v1/admin/nist/summary` — NIST compliance summary (admin)
- `GET /v1/admin/agent-trust` — agent trust status (admin)
- `GET /v1/admin/key-rotation/status` — key rotation assessment (admin)
- `POST /v1/admin/key-rotation/rotate` — trigger key rotation (admin)
- `GET /v1/admin/key-rotation/history` — rotation audit trail (admin)
- `GET /v1/admin/search-index/status` — search index stats (admin)

### New Environment Variables

- `LOOM_COMPRESSION_ENABLED` (default: `false`)
- `LOOM_COMPRESSION_MIN_SIZE` (default: `1024`)
- `LOOM_COMPRESSION_ENCODING` (default: `gzip`)
- `LOOM_COMPRESSION_LEVEL` (default: `6`)
- `LOOM_KEY_ROTATION_MAX_AGE_DAYS` (default: `90`)
- `LOOM_KEY_ROTATION_GRACE_PERIOD_DAYS` (default: `7`)
- `LOOM_KEY_ROTATION_OVERLAP_HOURS` (default: `24`)
- `LOOM_KEY_ROTATION_AUTO_ROTATE` (default: `false`)
- `LOOM_SEARCH_INDEX_ENABLED` (default: `true`)
- `LOOM_SEARCH_INDEX_MAX_ENTRIES` (default: `100000`)

### New Documentation

- `docs/NIST-COMPLIANCE.md` — NIST SP 800-53 Rev 5 and SP 800-207
  control mapping with per-family tables, crypto compliance matrix,
  and zero-trust alignment documentation.

### Protocol Capabilities

`getProtocolCapabilities()` now advertises:
- `key_rotation` — enabled status, policy, and status URL
- `search_index` — enabled status, stats, and status URL
- `nist_alignment` — SP 800-53 coverage and SP 800-207 zero-trust
- `compression` — enabled status, supported encodings, min size
- `agents` — agent cards, trust scoring, discovery URL
- `compliance` — compliance URL and MIME policy mode

### Tests

- 112 new unit tests across 10 test files for all protocol modules.
- Extended mcp_client, mcp, and content_filter_corpus integration tests.
- **Total: 1470 tests, 0 failures.**

## v0.3.0 - 2026-02-20

Full LOOM v1.1 specification coverage: 24 new protocol modules, MCP
client/server runtime, store integration for all protocol features,
new HTTP endpoints, and 955 total passing tests.

### New Protocol Modules

All modules are standalone, framework-free, and return `{field, reason}[]`
error arrays. Each module has full unit test coverage.

- **intents.js**: Intent taxonomy validation against the v1.1 intent
  registry (Section 5).
- **receipts.js**: Delivery, read, and failure receipt envelope builders
  with auto-reply suppression (Section 6.4).
- **audit_log.js**: Hash-chained audit log entry creation and chain
  verification (Section 7).
- **retention.js**: Retention policy normalization, per-label expiry
  resolution, and legal hold checks (Section 8).
- **deletion.js**: Content-level erasure records and thread-level
  crypto-shred builders (Section 9).
- **discovery.js**: Well-known identity resolution helpers (Section 10).
- **distribution.js**: Routing policy normalization, team recipient
  expansion, and moderation checks (Section 11).
- **autoresponder.js**: Auto-reply rule validation, loop prevention via
  receipt suppression, and per-sender frequency limiting (Section 12).
- **channel_rules.js**: Channel automation rule engine with label,
  quarantine, and priority actions (Section 13).
- **search.js**: Thread and envelope query filtering; metadata-only
  search for E2EE threads (Section 16.6).
- **import_export.js**: Portable mailbox export packaging and import
  validation with thread/envelope preservation (Section 17).
- **email_bridge.js**: Inbound and outbound email bridge parameter
  validation (Section 18).
- **legacy_gateway.js**: Legacy protocol gateway transform helpers
  (Section 19).
- **blob.js**: Blob initiation and chunk validation (Section 14).
- **websocket.js**: Real-time event log creation, event emission,
  subscription/ack message validation, and cursor-based retrieval
  (Section 15).
- **rate_limit.js**: RFC-compliant `RateLimit-Limit`,
  `RateLimit-Remaining`, `RateLimit-Reset` header builders (Section 20).
- **idempotency.js**: Idempotency key format and TTL validation
  (Section 21).
- **mcp.js**: MCP tool-use request/response envelope validation
  (Section 22).
- **mls.js**: MLS key package and welcome message validation with
  cipher suite and credential type checks (Section 23).
- **mls_codec.js**: TLS-style encoding/decoding primitives for MLS
  wire format (Section 23).
- **workflow.js**: Workflow orchestration state machine with execute,
  step_complete, complete, and failed transitions (Section 24).
- **agent_info.js**: Inference provider `agent_info` field validation
  and normalization for agent-type identities (Section 25).
- **loop_protection.js**: Agent loop detection helpers for chain depth
  and cycle detection (Section 26).
- **context_window.js**: Context window token budget tracking for agent
  conversations (Section 27).

### New Runtime Modules

- **mcp_client.js**: MCP client handles tool-use request/response
  lifecycle with the store, including service identity registration
  and thread participant management.
- **mcp_server.js**: MCP server provides tool discovery and execution
  dispatch for agent-facing MCP endpoints.

### Store Integration

All 16 protocol modules wired into the store ingestion pipeline, identity
lifecycle, and state management:

- **Post-ingestion hooks**: Every ingested envelope triggers event
  emission (`_emitEnvelopeEvent`), channel rule evaluation
  (`_applyChannelRules`), and autoresponder processing
  (`_processAutoresponder`).
- **Receipts**: `generateDeliveryReceipt()`, `generateReadReceipt()`,
  `generateFailureReceipt()` create signed system envelopes.
- **Deletion**: `deleteEnvelopeContent()` with legal hold enforcement;
  `cryptoShredThread()` for thread-level erasure.
- **Retention**: `enforceRetentionPolicies()` collects and removes
  expired envelopes per configured policies.
- **Channel rules**: `setChannelRules()` configures rules;
  `_applyChannelRules()` evaluates on ingestion (label, quarantine,
  priority actions).
- **Autoresponder**: `setAutoresponderRule()` configures per-identity
  rules; `_processAutoresponder()` generates auto-replies with loop
  prevention and frequency limiting.
- **Distribution**: `setIdentityRoutingPolicy()` configures routing;
  `resolveDistributionRecipients()` expands team recipients.
- **Search**: `validateAndSearchEnvelopes()` with full query validation.
- **Import/Export**: `exportMailbox()` and `importMailbox()` for
  portable mailbox backup and restore.
- **Events**: `_emitEnvelopeEvent()` appends to event log;
  `getEventsSince()` supports cursor-based retrieval.
- **Blob**: `validateBlobPayload()` augments existing `createBlob()`.
- **Rate limits**: `buildRateLimitResponseHeaders()` generates RFC
  headers.
- **Identity**: `agent_info` support in `registerIdentity()` and
  `updateIdentity()` for agent-type identities.
- **Workflow**: Workflow state tracking on threads via `protocol_core.js`
  (running → step_complete → complete/failed).
- **State serialization**: `channel_rules`, `retention_policies`,
  `autoresponder_rules`, `autoresponder_sent_history`, and `workflow`
  state survive serialization/deserialization round-trips.
- **System service identity**: `_ensureSystemServiceIdentity()`,
  `_signSystemEnvelope()`, `_ensureServiceParticipant()` pattern for
  system-generated envelopes (receipts, auto-replies).

### New HTTP Endpoints

- `GET /v1/events?cursor=...` — cursor-based real-time event retrieval
- `GET /v1/export` — full mailbox export
- `POST /v1/import` — mailbox import with validation
- `POST /v1/admin/retention/enforce` — trigger retention policy
  enforcement (admin token required)
- `DELETE /v1/envelopes/{id}/content` — content-level envelope deletion
  with legal hold enforcement

### Server Enhancements

- Rate limit headers (`RateLimit-Limit`, `RateLimit-Remaining`,
  `RateLimit-Reset`) on 429 responses.
- Search query validation with URL parameter type coercion (string
  `limit` param converted to number).
- Extended envelope type validation for `workflow`, `mcp_request`,
  `mcp_response` types.

### Protocol Changes

- **constants.js**: New envelope types (`workflow`, `mcp_request`,
  `mcp_response`), intent prefixes, and MLS-related constants.
- **e2ee.js**: Security property labels and MLS group state tracking.
- **envelope.js**: Extended validation for workflow and MCP envelope
  types.

### Tests

- 344 new unit tests across 23 test files for all protocol modules.
- 69 new integration tests across 4 files:
  - `protocol_wiring_integration.test.js` (37 tests): receipts,
    deletion, retention, channel rules, autoresponder, distribution,
    search, import/export, events, state serialization, blob, rate
    limit headers.
  - `workflow_integration.test.js`: workflow state machine through store.
  - `mls_integration.test.js`: MLS key packages through store.
  - `mcp_client.test.js`: MCP client tool-use lifecycle.
- Updated conformance fixture vectors for extended envelope types.
- **Total: 955 tests, 0 failures.**

## v0.2.9 - 2026-02-20

Release-readiness hardening based on deep research protocol assessment.
Addresses interoperability, security, and engineering gaps across
canonical JSON, signatures, delegation, replay, E2EE, and threading.

### Breaking Changes

- **Signature context prefix**: Envelope signatures now include a
  `LOOM-ENVELOPE-SIG-v1\0` context prefix before the canonical payload.
  Verification has a legacy fallback window for envelopes without a
  `signature.context` field. Delegation signatures use
  `LOOM-DELEGATION-SIG-v1\0`. Nodes running < v0.2.9 will reject
  context-prefixed signatures; coordinate upgrades across federated peers.
- **Delegation `created_at` required**: `verifyDelegationLinkOrThrow` now
  rejects links missing `created_at` or with `created_at` more than 5
  minutes in the future. Existing links without `created_at` will fail
  validation.
- **Delegation chain depth limit**: Chains longer than 10 links (default)
  are rejected. Configurable via `options.maxChainLength`.

### New Features

- **RFC 8785 JCS number serialization**: `canonicalizeJson` now handles
  `-0`, integer formatting, and exponent normalization per RFC 8785
  Section 3.2.2.3 for cross-language determinism.
- **Sliding window replay protection**: New `replayMode: "sliding_window"`
  option (default remains `"strict"`) tolerates out-of-order delivery
  within a 64-counter window. Enable via store constructor option
  `replayMode: "sliding_window"` or per-ingest context override.
- **Envelope `from.device_id`**: Optional field (1-128 chars) for
  multi-device replay state partitioning. Replay state is now keyed by
  `senderIdentity:deviceId` instead of `senderIdentity` alone.
- **Capability Proof-of-Possession (PoP)**: Sensitive thread operations
  (`encryption.epoch@v1`, `encryption.rotate@v1`, `delegation.revoked@v1`,
  `capability.revoked@v1`, `thread.delegate@v1`, `thread.link@v1`) require
  a PoP signature when the capability token has a `cnf.key_id` binding.
- **Thread size limits**: Configurable `threadMaxEnvelopesPerThread`
  (default 10000) and `threadMaxPendingParents` (default 500) store
  options. Override per-ingest via `context.threadLimits`.
- **E2EE security property labels**: All E2EE profiles now carry
  `security_properties` metadata (`forward_secrecy`, `post_compromise_security`,
  `confidentiality`). MLS profile `loom-e2ee-mls-1` reserved as
  placeholder with `status: "reserved"`.
- **Envelope JSON Schema**: Published `envelope-v1.1.schema.json`
  (draft 2020-12) as informational reference for cross-language
  implementations.
- **Root delegator type binding**: Delegation chain verification rejects
  chains where the root delegator is an `agent` identity type (configurable
  via `options.enforceRootDelegatorType`).

### Performance

- **Thread DAG O(1) dequeue**: Replaced `queue.shift()` with index pointer
  in `validateThreadDag` and `canonicalThreadOrder`, reducing BFS dequeue
  from O(n) to O(1).

### Upgrade Notes

1. **Signature context**: During the migration window, the verifier tries
   context-prefixed verification first, then falls back to legacy if the
   envelope lacks `signature.context`. Plan to remove the fallback in a
   future release. Regenerate any cached/persisted signatures.
2. **Delegation links**: Ensure all delegation links have a valid
   `created_at` ISO-8601 timestamp. Links without this field will be
   rejected.
3. **Replay mode**: The default replay mode is `"strict"` (monotonically
   increasing counters). If your deployment has store-and-forward delivery
   that may reorder envelopes, set `replayMode: "sliding_window"` in the
   store constructor.
4. **Device ID**: The `from.device_id` field is optional. If present, it
   partitions replay state per-device. Multi-device agents should set this
   field to avoid replay counter conflicts.
5. **Thread limits**: Default limits are generous (10000 envelopes, 500
   pending parents). Override via store constructor or per-ingest context
   if your deployment requires different bounds.
6. **JSON Schema**: The schema file is informational. In-code validation
   remains authoritative via `validateEnvelopeShape`. The schema is
   published for external tooling and cross-language implementations.

### Conformance Vectors Added

- `test/fixtures/conformance/jcs-number-serialization-v1.json`
- `test/fixtures/conformance/signature-context-v1.json`
- `test/fixtures/conformance/delegation-chain-v1.json`
- `test/fixtures/conformance/replay-sliding-window-v1.json`
- `test/fixtures/conformance/capability-pop-v1.json`

## v0.2.8 - 2026-02-20

Agent-first protocol reboot, federation trust hardening, and wire/content-policy upgrades:

- Added v2 reboot spec and implementation foundations:
  - `LOOM-Agent-First-Protocol-v2.0.md`
  - `src/protocol/trust.js`
  - `src/protocol/key_lifecycle.js`
  - `src/protocol/e2ee.js`
  - Store refactor split: `src/node/store/protocol_core.js`, `src/node/store/policy_engine.js`, `src/node/store/adapters.js`
- Added concrete E2EE profile crypto path (X25519 + HKDF-SHA-256 + XChaCha20-Poly1305) including wrapped-key payload validation, attachment-level packaging vectors, replay/downgrade policy enforcement, and profile migration allowlist controls.
- Added federation protocol capability negotiation surfaces and strict policy gates:
  - `GET /v1/protocol/capabilities`
  - `GET /.well-known/loom-capabilities.json`
  - Optional enforcement via `LOOM_FEDERATION_REQUIRE_PROTOCOL_CAPABILITIES`, `LOOM_FEDERATION_REQUIRE_E2EE_PROFILE_OVERLAP`, `LOOM_FEDERATION_REQUIRE_TRUST_MODE_PARITY`.
- Added internet-grade trust-anchor controls and publication flow:
  - Signed keyset/revocation/trust docs: `/.well-known/loom-keyset.json`, `/.well-known/loom-revocations.json`, `/.well-known/loom-trust.json`, `/.well-known/loom-trust.txt`
  - Admin trust APIs: `GET /v1/federation/trust`, `GET /v1/federation/trust/verify-dns`, `POST /v1/federation/trust`
  - DNSSEC/DoH, fail-closed, transparency, trust-epoch/keyset-age controls in runtime and validators.
- Added periodic automatic federation trust revalidation worker and drill tooling:
  - `POST /v1/federation/nodes/revalidate`
  - `POST /v1/federation/nodes/{node_id}/revalidate`
  - `scripts/run_federation_trust_drill.js` and `npm run drill:federation-trust`
  - Expanded `scripts/check_federation_controls.js` runtime validation coverage.
- Added inbound content-policy control plane for agent traffic:
  - Admin config endpoints: `GET/POST /v1/admin/content-filter/config` (`canary|apply|rollback`)
  - Profile-aware filtering + profile-labeled counters + anonymized decision telemetry options
  - Corpus builder for production-like threshold tuning: `scripts/build_content_filter_corpus.js` (`npm run build:content-filter-corpus`)
  - Additional inbound bridge policy knobs (`LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_PAYLOAD_AUTH_RESULTS`, header allowlist).
- Expanded wire gateway compatibility:
  - IMAP SEARCH boolean/group parsing improvements
  - APPEND literal continuation support
  - `UID THREAD` (`REFERENCES`, `ORDEREDSUBJECT`) and `UID SORT` support.
- Added retention and maintenance hardening:
  - `LOOM_MESSAGE_RETENTION_DAYS`, `LOOM_BLOB_RETENTION_DAYS`, `LOOM_MAINTENANCE_SWEEP_INTERVAL_MS`
  - Optional state-at-rest encryption controls: `LOOM_STATE_ENCRYPTION_KEY`, `LOOM_REQUIRE_STATE_ENCRYPTION_AT_REST`.
- Updated release and ops scripts/env/docs to match the new protocol surfaces and production controls:
  - `README.md`, `.env.production.example`, `docs/CONFORMANCE.md`, `docs/FEDERATION-CONTROLS.md`, `docs/INBOUND-BRIDGE-HARDENING.md`, `docs/OBSERVABILITY-ALERTING.md`, `docs/PRODUCTION-READINESS.md`, `docs/DEVELOPMENT-PLAN.md`
  - `scripts/verify_production_env.js`, `scripts/run_release_gate.js`.

## v0.2.7 - 2026-02-18

Governance and trust-signal alignment updates:

- Added contribution/governance docs: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`.
- Added lifecycle policy docs: `docs/STABILITY.md`, `docs/RELEASE-POLICY.md`, `docs/OPEN-SOURCE-STRATEGY.md`.
- Added a production readiness checklist with owners/status/acceptance criteria: `docs/PRODUCTION-READINESS.md`.
- Added deployment baseline artifacts for public-service launch hardening:
  - `docs/DEPLOYMENT-BASELINE.md`
  - `.env.production.example`
  - `scripts/verify_production_env.js` and `npm run check:prod-env`
- Added secrets management hardening artifacts:
  - `docs/SECRETS-KEY-ROTATION.md`
  - `scripts/check_secrets_hygiene.js` and `npm run check:secrets`
  - CI secret-hygiene gate and `.env*` ignore policy with example-file allowlist
- Added persistence readiness hardening artifacts:
  - `scripts/check_postgres_readiness.js` and `npm run check:pg`
  - `docs/POSTGRES-OPERATIONS.md` startup preflight now includes `check:pg`
  - Production env validation now requires `LOOM_PG_URL` for public-service deployments
  - Fixed Postgres-backed audit reload/import stability by using chain-continuity validation mode for persistence round-trips where JSON key ordering can differ
  - Added regression coverage for persistence-audit key-order round-trip behavior (`test/protocol.test.js`)
- Added backup/restore drill automation artifacts:
  - `scripts/run_persistence_drill.js` and `npm run drill:persistence`
  - `docs/POSTGRES-OPERATIONS.md` now includes automated drill workflow and evidence artifact paths
  - Persistence drill now auto-seeds minimal state on fresh databases before restore validation
- Added federation outbound-controls hardening artifacts:
  - `scripts/check_federation_controls.js` and `npm run check:federation`
  - `docs/FEDERATION-CONTROLS.md` runbook for static allowlist policy checks and runtime node audits
  - Production env validation now blocks `LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=true` for hardened public deployments
- Added inbound bridge hardening artifacts:
  - `scripts/check_inbound_bridge_hardening.js` and `npm run check:inbound-bridge`
  - Focused negative-test command: `npm run test:inbound-bridge-hardening`
  - `docs/INBOUND-BRIDGE-HARDENING.md` runbook for strict public inbound auth/DMARC/admin-token policy validation
- Added abuse and rate-limit policy artifacts:
  - `scripts/check_rate_limit_policy.js` and `npm run check:rate-limits`
  - `scripts/run_rate_limit_probe.js` and `npm run probe:rate-limits` for repeatable threshold evidence runs
  - `docs/RATE-LIMIT-POLICY.md` tuned threshold runbook and evidence workflow
  - Added `api_rate_limit_policy` and `identity_rate_limit_policy` to `/ready` and `/v1/admin/status`
- Added outbox worker reliability artifacts:
  - `scripts/check_outbox_workers.js` and `npm run check:outbox-workers`
  - `docs/OUTBOX-WORKER-RELIABILITY.md` for worker cadence, claim-lease, and lag-monitoring checks
  - `.env.production.example` now includes explicit outbox worker lease/identity and batch tuning fields
- Added observability and alerting artifacts:
  - `scripts/check_observability_alerting.js` and `npm run check:observability`
  - `docs/OBSERVABILITY-ALERTING.md` for readiness/metrics/admin scrape checks and evidence capture
  - `ops/alerts/loom-alert-rules.yaml` with baseline readiness, queue-lag, auth-spike, and persistence-failure alerts
- Added incident response and on-call readiness artifacts:
  - `scripts/check_incident_response_readiness.js` and `npm run check:incident-response`
  - `docs/INCIDENT-RESPONSE-ONCALL.md` with severity matrix, escalation flow, and security/availability playbooks
  - `ops/incidents/drills/2026-02-18-sev1-availability-tabletop.md` initial drill note with follow-up actions
- Added release-gate enforcement artifacts:
  - `scripts/check_release_gates.js` and `npm run check:release-gates`
  - `scripts/run_release_gate.js` and `npm run gate:release` for single-command pre-deploy validation orchestration
  - `docs/RELEASE-CHECKLIST.md` with required release gates and rollback template
  - Strengthened release-gate checker coverage for compliance commands (`check:compliance`, `drill:compliance`, `gate:compliance`), `gate:release`, and required package script wiring
  - Strengthened release-gate checker coverage for access-governance command/script/CI wiring (`check:access-governance`)
  - Hardened `gate:release` to require runtime `--base-url`, `--admin-token`, and `--bearer-token` inputs and removed skip-path options for strict production validation
  - `gate:release` now rejects example/template interop target files (`*.example.*`) to prevent accidental release runs against placeholder config
  - Wired release-gate runtime arguments through federation/inbound/rate-limit/outbox/observability/tracing/compliance checks so runtime probes are exercised during release runs
- Added federation interop drill artifacts:
  - `scripts/run_federation_interop_drill.js` and `npm run drill:federation-interop`
  - `docs/FEDERATION-INTEROP-DRILL.md` for challenge + deliver + receipt + replay guard drill workflow
- Added federation interop matrix/evidence artifacts:
  - `scripts/run_federation_interop_matrix.js` and `npm run drill:federation-interop-matrix`
  - `scripts/check_federation_interop_evidence.js` and `npm run check:federation-interop`
  - `scripts/check_federation_interop_targets.js` and `npm run check:federation-targets` for required-target config validation (HTTPS, non-loopback, distinct origins)
  - Interop drill/matrix failures now include detailed network diagnostics (DNS code/syscall/address, timeout, TLS classification) to make environment blockers actionable
  - Federation interop evidence checks now require non-local HTTPS target URLs by default, fail when required targets share the same origin, and can enforce origin matching against an expected targets file
  - Federation interop URL validation now blocks known loopback-alias domains (`nip.io`, `sslip.io`, `localtest.me`, `lvh.me`) in both targets and evidence checks
  - Added concrete production interop target config (`ops/federation/interop-targets.json`) and updated matrix/check defaults to use it
  - Added regression tests for interop evidence target-origin matching and release-gate example-target-file rejection (`test/release_gate_hardening.test.js`)
  - `ops/federation/interop-targets.example.json` target template for staging/pre-prod interop runs
- Added structured request-tracing artifacts:
  - `docs/REQUEST-TRACING.md` runbook and evidence checklist
  - `scripts/check_request_tracing.js` and `npm run check:tracing`
  - API `x-loom-request-id` response headers + request log `request_id`
  - Audit/outbox trace propagation (`trace_id`, `source_request_id`) and worker structured batch logs
- Added formal threat-model artifacts:
  - `docs/THREAT-MODEL.md` STRIDE model with trust boundaries, assumptions, and review cadence
  - `scripts/check_threat_model.js` and `npm run check:threat-model`
- Added security testing program artifacts:
  - `docs/SECURITY-TESTING-PROGRAM.md` with dependency/SAST/pen-test workflow and triage SLAs
  - `.github/workflows/security.yml` for scheduled dependency+secret checks and CodeQL SAST
  - `scripts/check_security_testing_program.js` and `npm run check:security-program`
  - `ops/security/findings-tracker-template.md` for findings ownership/SLA tracking
- Added capacity/chaos readiness artifacts:
  - `docs/CAPACITY-CHAOS-TESTS.md` runbook with SLO criteria and failure-injection scenarios
  - `scripts/check_capacity_chaos_readiness.js` and `npm run check:capacity-chaos`
  - `ops/chaos/reports/2026-02-18-baseline-capacity-chaos.md` baseline drill report
- Added multi-region/disaster recovery artifacts:
  - `docs/DISASTER-RECOVERY-PLAN.md` with RTO/RPO targets and failover runbook
  - `scripts/check_disaster_recovery_plan.js` and `npm run check:dr-plan`
  - `ops/dr/reports/2026-02-18-dr-tabletop.md` DR tabletop record
- Added access governance artifacts:
  - `docs/ACCESS-GOVERNANCE.md` least-privilege and periodic access-review policy
  - `scripts/check_access_governance.js` and `npm run check:access-governance`
  - Access governance checker now ignores template records and requires concrete inventory rows plus resolved reviewer sign-offs
  - `ops/access/reviews/2026-02-18-access-review.md` non-template access review evidence record
  - `ops/access/reviews/2026-02-18-access-review-template.md` review evidence template
- Added compliance controls package artifacts:
  - `docs/COMPLIANCE-CONTROLS.md` audit export + retention policy + control mapping runbook
  - `scripts/check_compliance_controls.js` and `npm run check:compliance`
  - Compliance checker now ignores template records and requires resolved product/security/date sign-offs in latest non-template evidence
  - `scripts/run_compliance_probe.js` and `npm run drill:compliance` for runtime compliance evidence capture
  - `scripts/run_compliance_gate.js` and `npm run gate:compliance` to run compliance check + runtime drill as a single operator gate
  - Compliance drill now supports `--bootstrap-audit-token` to auto-create a temporary local identity + bearer token for `/v1/audit` probing
  - `ops/compliance/checklists/2026-02-18-compliance-checklist-template.md` compliance evidence template
  - `ops/compliance/checklists/2026-02-18-runtime-compliance-probe.md` initial runtime compliance evidence record
- Added SMTPUTF8 wire-profile support for gateway-compatible flows:
  - Wire SMTP now advertises `SMTPUTF8` and `8BITMIME` in EHLO capabilities.
  - Wire SMTP accepts `SMTPUTF8` ESMTP parameters on `MAIL FROM`/`RCPT TO` instead of returning `504`.
  - Updated conformance docs and wire-gateway tests to cover supported SMTPUTF8 behavior.
- Expanded wire IMAP parity profile artifacts:
  - Added `docs/IMAP-COMPATIBILITY-MATRIX.md` with command/extension compatibility target.
  - IMAP `CAPABILITY` now advertises `IDLE`, `MOVE`, and `UNSELECT`.
  - Added `EXPUNGE` command acceptance for client compatibility (compatibility no-op in current mailbox-state model).
  - Updated wire IMAP tests for new capability/EXPUNGE coverage.
- Added GitHub issue templates (`bug report`, `feature request`) and issue config routing users to support/security resources.
- Aligned docs with current release line (`v0.2.7`) in `README.md` and `docs/CONFORMANCE.md`.
- Updated `SECURITY.md` support scope to `0.2.x` + `main` and documented target fix SLAs by severity.

## v0.2.6 - 2026-02-17

Production hardening, memory safety, and operational resilience:

### Critical Fixes
- **Memory leak sweep**: Added periodic `runMaintenanceSweep()` that evicts expired
  access tokens, refresh tokens, auth challenges, stale rate-limit windows, and
  caps the `consumedPortableCapabilityIds` / `revokedDelegationIds` Sets (FIFO).
  Also delegates to all 7 existing cleanup methods. Runs every 60 s by default
  (`LOOM_MAINTENANCE_SWEEP_INTERVAL_MS`).
- **Worker exponential backoff**: All three outbox workers (federation, email,
  webhook) now apply exponential backoff on batch-level failures (10 s → 300 s
  cap) instead of retrying every tick indefinitely.
- **Atomic file persistence**: `persistState()` now writes to a `.tmp` file,
  calls `fsync`, then renames — preventing half-written state on crash.

### High-Risk Fixes
- **Resource limits**: Configurable caps for local identities (10 k default),
  remote identities (50 k), delegations per identity (500), and total
  delegations (100 k). Enforced in `registerIdentity()` and
  `createDelegation()` with `RESOURCE_LIMIT` errors.
  New env vars: `LOOM_MAX_LOCAL_IDENTITIES`, `LOOM_MAX_REMOTE_IDENTITIES`,
  `LOOM_MAX_DELEGATIONS_PER_IDENTITY`, `LOOM_MAX_DELEGATIONS_TOTAL`,
  `LOOM_CONSUMED_CAPABILITY_MAX_ENTRIES`, `LOOM_REVOKED_DELEGATION_MAX_ENTRIES`.

### Security
- **Response headers**: Every HTTP response now includes `x-content-type-options:
  nosniff`, `x-frame-options: DENY`, `cache-control: no-store`.
- **HTTP server timeouts**: `headersTimeout` (30 s), `requestTimeout` (2 min),
  `keepAliveTimeout` (65 s) to mitigate slow-loris and idle-connection attacks.
- **Global error handlers**: `unhandledRejection` logs and continues;
  `uncaughtException` logs and triggers graceful shutdown.

### Maintenance
- **Helper deduplication**: Consolidated `parseBoolean`, `parsePositiveInt`,
  `parsePositiveNumber`, and `parseHostAllowlist` into a single shared module
  (`src/node/env.js`), replacing 6+ duplicated copies across the codebase.
- **ULID monotonicity**: `generateUlid()` now increments the random portion
  within the same millisecond instead of re-seeding, guaranteeing strict
  ordering for same-ms calls.
- **CI enhancements**: Added `--experimental-test-coverage`, a helper
  duplication guard, and an unused-export check to the GitHub Actions workflow.

### Tests
- Added 16 new tests covering maintenance sweep, backoff formula, atomic
  persistence, identity limits, and delegation limits (136 total).

---

## v0.2.5 - 2026-02-17

Security and interoperability updates:

- Added DSN-style per-recipient outbox status ingestion:
  - `POST /v1/email/outbox/{id}/dsn`
  - Recipient-level status merge with validation against queued recipients.
- Added distributed outbox claim leasing for worker coordination:
  - Email, federation, and webhook processors now use claim/release hooks.
  - PostgreSQL adapter now persists claims in `loom_outbox_claims`.
- Hardened wire SMTP behavior for explicit extension handling:
  - `SMTPUTF8` parameters are rejected with `504 5.5.4`.
- Improved outbound email bridge rendering:
  - LOOM blob-backed envelope attachments are mapped to relay MIME attachments.
- Added conformance vectors and expanded test coverage:
  - New `test/conformance_vectors.test.js`.
  - Added DSN, claim-lock, attachment mapping, and SMTPUTF8 tests.
- Repository governance and delivery hardening:
  - Added `LICENSE` (Apache-2.0).
  - Added GitHub Actions CI workflow at `.github/workflows/ci.yml`.
  - Added `docs/CONFORMANCE.md`.
