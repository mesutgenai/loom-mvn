# LOOM Development Plan

## Review Summary

The documents in this workspace establish a progression from concept to normative protocol draft:

- `prior-versions-summary.md`: constraints from prior naming/concept iterations.
- `LOOM-protocol-design.md`: architectural blueprint and migration framing.
- `LOOM-specification-v1.0.md`: broad full spec draft.
- `LOOM-Protocol-Spec-v1.1.md`: tighter normative draft with required behaviors, conformance levels, and MVN scope.

## Key Findings From v1.1

v1.1 is implementation-ready for a Core Level 1 node, with concrete requirements for:

- Envelope model, signing rules, and canonical serialization.
- Thread DAG semantics and canonical rendering order.
- API skeleton for envelopes/threads/identity.
- Discovery document and federation envelope wrapper shape.
- Error code registry and baseline security controls.

## Rapid Build Status (Implemented)

- Production persistence hardening baseline:
  - PostgreSQL schema metadata/versioning.
  - Admin persistence schema/backup/restore APIs.
  - Backup/restore flows covered in API tests.
- SMTP/IMAP interoperability hardening baseline:
  - Edge-case address parsing, case-insensitive header handling, and folder alias support.
- Federation hardening baseline:
  - Rate policy controls, allowlist/trust model, abuse automation, and discovery bootstrap.
- Distributed abuse controls baseline:
  - Global inbound limits, reputation updates, auto-policy gates, and challenge escalation/token flow.

## Immediate Production Actions (Parallel, No Phases)

- Deploy with TLS + reverse proxy and set forwarded client IP headers.
- Configure durable persistence (`LOOM_PG_URL`) and run restore drills against `/v1/admin/persistence/*`.
- Set federation guard env vars for your traffic profile (`LOOM_FEDERATION_*` rates/challenge settings).
- Explicitly configure high-risk email send surfaces (`LOOM_BRIDGE_EMAIL_SEND_ENABLED`, `LOOM_GATEWAY_SMTP_SUBMIT_ENABLED`) for public deployments.
- Run live-node interoperability checks against at least one external node using federation challenge + deliver paths.

## Execution Workstreams (Parallel, Not Phased)

- Core Protocol Engine (implemented)
- Complete schema-level validation and signature tooling.
- Deterministic DAG rules and event sequencing.

- Core Node API (implemented)
- Envelopes, threads, identity resolution, node discovery.
- Stable error responses using protocol error registry.

- Auth + Authorization (implemented)
- Proof-of-key auth challenge/token flow.
- Capability token verification and epoch handling.

- Thread Operations and State Control (implemented baseline)
- `thread_op` intent registry and conflict resolution.
- Preconditions and deterministic mutation handling.

- Federation (implemented baseline)
- Node document keys/policies.
- Signed wrapper delivery and store-and-forward queues.

- Email Replacement Profile (implemented baseline)
- Mailbox semantics (`sys.*` labels).
- Per-user mailbox state controls (`seen`, `flagged`, `archived`, `deleted`) exposed via mailbox state API.
- BCC copy behavior and audience restrictions.
- Legacy gateway and bridge integration.
- Outbound email relay queue + processing automation.
- Wire-level legacy gateway daemon baseline (SMTP submit + IMAP mailbox access) with optional STARTTLS and extended IMAP mailbox commands (`STATUS`, `SEARCH`, `FETCH`, `STORE`, `APPEND`, `IDLE`, `MOVE`, `UID SEARCH`, `UID FETCH`, `UID STORE`, `UID MOVE`).
- Known wire IMAP limitation: `COPY`/`UID COPY` are rejected in the current mailbox-state model.

## Definition of Done for MVN (Current Build Target)

- Signed envelopes accepted/rejected per shape + signature rules.
- Threads can be created, listed, and rendered in canonical order.
- Duplicate IDs and DAG cycles are rejected with normative errors.
- Authenticated envelope submission enforced with proof-of-key login.
- Capability-gated `thread_op` execution for non-owner actors.
- Capability token presentation secret is header-based (`x-loom-capability-token`) and not returned by capability list APIs.
- Agent delegation-chain verification with signature/scope/revocation checks.
- Optional local persistence with hash-chained audit logging.
- Authenticated blob upload/complete/download API for attachments.
- Signed inbound federation delivery with trusted-node verification and replay protection.
- Federation policy enforcement (`trusted`, `quarantine`, `deny`) on inbound delivery.
- Federation trusted-node key rotation support (multiple keys per node with `key_id`-based verification).
- Federation trusted-node bootstrap from remote node discovery documents (`/.well-known/loom.json`).
- Federation inbound abuse controls (per-node rate limit and max envelopes per delivery).
- Federation global inbound abuse controls (global rate window/max).
- Federation reputation automation (auto-quarantine and auto-deny after repeated failures).
- Federation challenge escalation and challenge-token gate (`/v1/federation/challenge`).
- Signed federation delivery receipts with optional strict outbound verification.
- Outbound federation outbox with signed delivery and retry processing.
- Automatic outbox worker loop for continuous federation delivery processing.
- Authenticated email bridge endpoints for inbound envelope creation and outbound render.
- Authenticated legacy gateway endpoints for IMAP folder/message views and SMTP submit.
- SMTP/IMAP gateway edge-case handling for recipient parsing, case-insensitive headers, and folder aliases.
- Request payload-size and route-level rate-limit guards for API hardening.
- Operational readiness + metrics endpoints and admin status surface.
- Outbound email relay mode (`disabled|stream|smtp`) and delivery outbox APIs.
- Dead-letter outbox administration (`/v1/outbox/dlq`, `/v1/outbox/dlq/requeue`) for failed delivery recovery.
- Idempotency-key support for key POST mutations with conflict detection.
- Signed webhook receipt subscriptions and webhook outbox processing (`/v1/webhooks*`).
- Optional PostgreSQL-backed state + audit persistence (`LOOM_PG_URL`) with startup hydration and shutdown flush.
- Distributed federation guard persistence support (rate/reputation/challenge tables via PostgreSQL adapter).
- Admin persistence operations (`/v1/admin/persistence/schema|backup|restore`).
- Node discovery document served at `/.well-known/loom.json`.
- Test suite covers signature validity, duplicate rejection, DAG constraints, ordering, auth flow, capability enforcement, delegation verification, blob APIs, federation ingest/outbox delivery, federation challenge flow, bridge/gateway routes, relay outbox processing, root UI serving, payload limits, rate limiting, persistence backup/restore admin APIs, and operational endpoint auth.
