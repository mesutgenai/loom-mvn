# LOOM Core 1.0 Cut Line

Status: Draft (implementation profile)

## Purpose

Define the smallest mandatory interoperability surface for independent LOOM implementations.

Extension governance reference:

- `docs/EXTENSION-REGISTRY.md`

LOOM positioning baseline:

- LOOM-native when possible.
- Email-compatible always.

Runtime profile switch:

- `LOOM_PROTOCOL_PROFILE=loom-core-1` runs the node in core-only mode.
- `LOOM_PROTOCOL_PROFILE=loom-v1.1-full` keeps the full profile (default).

## Core (Must Implement)

An implementation claiming `loom-core-1` support MUST implement:

1. Identity and addressing
- Canonical identity format (`loom://local@domain`), canonical lowercase normalization, and `bridge://` reserved namespace behavior.

2. Envelope canonicalization and signatures
- Deterministic canonical payload rules.
- Ed25519 signature verification with required context prefix behavior.

3. Thread DAG semantics
- Parent/reference constraints.
- Cycle rejection.
- Deterministic event ordering behavior.

4. Capability authorization baseline
- Capability token structure and validation.
- Thread operation authorization model.

5. Federation trust wrapper baseline
- Signed federation transport wrapper.
- Replay protections (nonce + timestamp).
- Sender authority checks for identity authority ownership.

## Extensions (Out of Core)

Everything below is extension/profile territory and MUST NOT be required for `loom-core-1` conformance:

- `loom-ext-email-bridge-v1` (SMTP bridge and inbound/outbound translation)
- `loom-ext-legacy-gateway-v1` (IMAP/SMTP facade)
- `loom-ext-mcp-runtime-v1` (MCP request/response execution semantics)
- `loom-ext-workflow-v1` (workflow orchestration state machine intents)
- `loom-ext-e2ee-x25519-v1` and `loom-ext-e2ee-x25519-v2`
- `loom-ext-e2ee-mls-1` (MLS-grade E2EE profile support)
- `loom-ext-compliance-v1` (compliance scoring/audit overlays)

Note:

- The extension-id lifecycle (`loom-ext-*`) is tracked separately from wire profile identifiers (`loom-e2ee-*`).
- In this MVN profile, MLS wire profile `loom-e2ee-mls-1` is implemented/negotiated and represented by active extension-id `loom-ext-e2ee-mls-1`.

Extension IDs, status transitions, and versioning behavior are governed by `docs/EXTENSION-REGISTRY.md`.

## Bridge Safety Baseline

When `loom-ext-email-bridge-v1` is enabled:

- Bridged structured extraction is non-authoritative by default.
- Bridged sender envelopes are non-actuating by default.
- Automatic actuation from bridged senders requires explicit operator opt-in.

## Conformance Expectations

For ecosystem progress, "done" means:

1. Independent implementation passes published core vectors.
2. Independent implementation can exchange signed core envelopes with this MVN.
3. Any extension claim is separately testable and does not change core semantics.
4. Any extension claim maps to a registered extension id and version lifecycle state.

## Runtime Behavior (Core Mode)

When `LOOM_PROTOCOL_PROFILE=loom-core-1` is active:

- extension-specific routes fail closed as `404` (`/v1/bridge/*`, `/v1/gateway/*`, `/v1/mcp/*`, `/v1/protocol/compliance`, `/v1/mime/registry`, `/v1/admin/compliance/audit`, `/v1/admin/nist/summary`).
- ingest rejects extension envelopes/intents with `CAPABILITY_DENIED`.
- machine-readable extension state is still discoverable at `GET /v1/protocol/extensions`.
