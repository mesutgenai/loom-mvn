# LOOM Threat Model

Last reviewed: 2026-02-18

## Scope

This model covers LOOM MVN protocol surfaces that handle identity, message delivery, federation trust, and operational control:

- API routes (`/v1/*`, `/ready`, `/metrics`, admin endpoints)
- federation ingress/egress (`/v1/federation/*`)
- email bridge/gateway surfaces (`/v1/bridge/*`, `/v1/gateway/*`, wire SMTP/IMAP)
- persistence and audit chain (disk + PostgreSQL adapter)
- outbox workers (email/federation/webhook)

## Assets

- identity signing keys and node signing keys
- access/refresh tokens and challenge nonces
- envelopes, thread state, and mailbox state
- federation node trust policies and replay caches
- admin token and operational control surfaces
- audit log integrity chain and persistence snapshots

## Trust Boundaries

- external clients -> public API boundary
- remote federation nodes -> federation signature boundary
- upstream MTAs/legacy clients -> bridge/gateway boundary
- worker runtime -> outbound delivery providers
- app process -> persistence backend (filesystem/PostgreSQL)
- operators/automation -> admin and deployment boundary

## STRIDE Analysis

### Spoofing

- Risk: forged actor identity, forged federation sender, forged webhook destination.
- Controls: proof-of-key auth challenge/token flow, envelope signature validation, federation signature + challenge token verification, webhook signing, trusted-node policy.

### Tampering

- Risk: payload mutation in transit, persistence corruption, replayed federation requests.
- Controls: canonical JSON + Ed25519 signatures, audit hash chain (+ optional HMAC), nonce/timestamp replay guard with persistence, idempotency controls.

### Repudiation

- Risk: inability to attribute requests or worker actions.
- Controls: request IDs (`x-loom-request-id`), structured request logging, audit entries with trace context (`request_id`/`trace_id`), worker batch trace logs.

### Information Disclosure

- Risk: unauthorized mailbox/envelope reads, metadata leakage, secret leakage in repo/logs.
- Controls: private-by-default read auth, BCC recipient-view wrappers, host allowlists + metadata host deny rules, secret hygiene checks, admin-token protection for sensitive routes.

### Denial of Service

- Risk: request floods, federation abuse, oversized payloads, outbox overload.
- Controls: IP and identity rate limits, federation node/global rate guards, request body size limit, outbox backpressure and claim-lease workers, replay/abuse auto-policy.

### Elevation Of Privilege

- Risk: non-owner thread mutation, weak admin exposure, unsafe bridge policy.
- Controls: capability/delegation verification, admin token gates, strict inbound bridge auth defaults on public service, startup safeguards for public deployments.

## Mitigation Mapping

- Authentication/authorization hardening: `src/node/server.js`, `src/node/store.js`, `docs/INBOUND-BRIDGE-HARDENING.md`
- Federation trust + replay protection: `docs/FEDERATION-CONTROLS.md`, `docs/FEDERATION-INTEROP-DRILL.md`
- Persistence integrity + recovery: `docs/POSTGRES-OPERATIONS.md`, `docs/SECRETS-KEY-ROTATION.md`
- Observability and incident response: `docs/OBSERVABILITY-ALERTING.md`, `docs/INCIDENT-RESPONSE-ONCALL.md`
- Release and operational gates: `docs/RELEASE-CHECKLIST.md`, `docs/PRODUCTION-READINESS.md`

## Assumptions

- TLS termination is correctly enforced at ingress or native TLS mode.
- secret material is injected from secret manager/KMS, not repository files.
- upstream MTA performs SPF/DKIM/DMARC before public inbound bridge exposure.
- operators maintain least-privilege access to production admin routes.

## Open Risks

- single-region deployment remains a resilience risk until DR plan validation (`P1-05`).
- periodic external penetration testing not yet integrated (`P1-03`).
- large-scale chaos/failure injection coverage pending (`P1-04`).

## Review Cadence

- Review this model on every major protocol surface change affecting auth, federation, bridge/gateway, or persistence.
- Minimum periodic review: quarterly.
- Attach review evidence to release notes and security program records.
