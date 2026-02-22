# LOOM Production Readiness Checklist

This checklist is the working gate from "MVN protocol scaffold" to production service.

## How To Use This Document

- Assign a single owner per item.
- Update status on every sprint/release cut.
- Keep evidence links/notes current.
- Treat all `P0` items as mandatory before public launch.

Status values:

- `NOT_STARTED`
- `IN_PROGRESS`
- `BLOCKED`
- `DONE`

Production-ready minimum gate:

- All `P0` items are `DONE`.
- No open Critical/High security findings without accepted mitigation.
- Restore drill and federation interop drill both pass in the target environment.

## P0 Launch Blockers (Must Be Done)

| ID | Workstream | Owner | Status | Acceptance Criteria | Evidence |
| --- | --- | --- | --- | --- | --- |
| P0-01 | Public TLS deployment topology | Platform | DONE | Internet traffic is TLS-terminated (TLS 1.3), `LOOM_PUBLIC_SERVICE=true`, and startup safeguards are enforced in deployed env. | `docs/DEPLOYMENT-BASELINE.md`, `.env.production.example`, `npm run check:prod-env`, deployment config + startup logs |
| P0-02 | Admin and secrets management | Security | DONE | `LOOM_ADMIN_TOKEN` and signing keys are stored in a secret manager/KMS, never committed, and rotated on a defined schedule. | `docs/SECRETS-KEY-ROTATION.md`, `npm run check:secrets`, CI secret-hygiene gate, secret policy + rotation records |
| P0-03 | Durable persistence | Platform | DONE | `LOOM_PG_URL` in use, schema checks pass, and no production node depends on ephemeral state for core data. | `npm run check:pg`, `docs/POSTGRES-OPERATIONS.md`, `/v1/admin/persistence/schema` output |
| P0-04 | Backup and restore drills | SRE | DONE | Backup export + restore procedure from `docs/POSTGRES-OPERATIONS.md` succeeds in staging on a recurring schedule. | `npm run drill:persistence`, `scripts/output/persistence-drills/*/summary.md`, drill report with timestamps |
| P0-05 | Federation outbound controls | Security | DONE | Host allowlists are configured (`LOOM_FEDERATION_HOST_ALLOWLIST`, `LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST`, `LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST`, `LOOM_WEBHOOK_HOST_ALLOWLIST`), trust mode is fail-closed with DNSSEC/transparency controls, and trust revalidation worker is healthy. | `npm run check:federation`, `docs/FEDERATION-CONTROLS.md`, effective env config + startup validation |
| P0-06 | Inbound bridge hardening | Security | DONE | Public inbound bridge policy uses strict auth-result/DMARC defaults, admin-token enforcement, profile-aware content-policy controls, and non-actuating bridged defaults unless explicitly confirmed. | `docs/INBOUND-BRIDGE-HARDENING.md`, `npm run check:inbound-bridge`, `npm run test:inbound-bridge-hardening` |
| P0-07 | Abuse and rate-limit policy | Platform | DONE | API and federation rate limits are tuned from defaults using traffic tests and documented thresholds. | `docs/RATE-LIMIT-POLICY.md`, `npm run check:rate-limits`, `npm run probe:rate-limits`, env snapshots + probe artifacts |
| P0-08 | Outbox worker reliability | Platform | DONE | Email/federation/webhook outbox processing runs continuously with worker identity/lease tuning and lag alarms. | `docs/OUTBOX-WORKER-RELIABILITY.md`, `npm run check:outbox-workers`, worker config snapshot + lag alert links |
| P0-09 | Observability and alerting | SRE | DONE | `/ready`, `/metrics`, and admin health are scraped; alerts exist for readiness failures, queue lag, auth error spikes, and DB failures. | `docs/OBSERVABILITY-ALERTING.md`, `ops/alerts/loom-alert-rules.yaml`, `npm run check:observability`, dashboard + alert policy links |
| P0-10 | Incident response and on-call | Security + SRE | DONE | On-call rotation, incident severity matrix, and response playbooks (security + availability) are documented and rehearsed. | `docs/INCIDENT-RESPONSE-ONCALL.md`, `ops/incidents/drills/*`, `npm run check:incident-response` |
| P0-11 | Release gates | Release Eng | DONE | Release process requires passing CI/tests, conformance checks, changelog update, and rollback plan before deploy. | `docs/RELEASE-CHECKLIST.md`, `npm run check:release-gates`, `npm run gate:release`, release checklist artifact |
| P0-12 | External federation interop | Protocol | DONE | At least one external-node interop test (challenge + deliver + receipt + replay guard) passes in staging and pre-prod. | `docs/FEDERATION-INTEROP-DRILL.md`, `npm run drill:federation-interop-matrix`, `npm run check:federation-interop`, matrix + drill report artifacts |

## P1 Pre-GA Strong Recommendations

| ID | Workstream | Owner | Status | Acceptance Criteria | Evidence |
| --- | --- | --- | --- | --- | --- |
| P1-01 | Structured request tracing | Platform | DONE | End-to-end request IDs correlate API, worker, and federation events in logs. | `docs/REQUEST-TRACING.md`, `npm run check:tracing`, request/worker log samples |
| P1-02 | Formal threat model | Security | DONE | STRIDE-style or equivalent threat model exists and is reviewed after major protocol changes. | `docs/THREAT-MODEL.md`, `npm run check:threat-model`, review timestamp |
| P1-03 | Security testing program | Security | DONE | Dependency scanning, SAST, and periodic penetration tests are integrated with triage SLAs. | `docs/SECURITY-TESTING-PROGRAM.md`, `.github/workflows/security.yml`, `npm run check:security-program`, findings tracker |
| P1-04 | Capacity and chaos tests | SRE | DONE | Load and failure-injection tests verify SLO behavior under node/DB/network disruption. | `docs/CAPACITY-CHAOS-TESTS.md`, `npm run check:capacity-chaos`, `ops/chaos/reports/*` |
| P1-05 | Multi-region/DR plan | Platform | DONE | Defined RTO/RPO targets with validated failover path and data consistency checks. | `docs/DISASTER-RECOVERY-PLAN.md`, `npm run check:dr-plan`, `ops/dr/reports/*` |
| P1-06 | Access governance | Security | DONE | Production admin/API access is least-privilege with periodic access reviews and audit trails. | `docs/ACCESS-GOVERNANCE.md`, `npm run check:access-governance`, `ops/access/reviews/*` |

## P2 Product Hardening Roadmap

| ID | Workstream | Owner | Status | Acceptance Criteria | Evidence |
| --- | --- | --- | --- | --- | --- |
| P2-01 | SMTPUTF8 wire profile support | Protocol | DONE | Wire SMTP no longer rejects `SMTPUTF8` for supported flows; conformance/tests updated. | `docs/CONFORMANCE.md`, `test/wire_gateway.test.js` SMTPUTF8 coverage |
| P2-02 | Expanded IMAP parity | Protocol | DONE | Documented IMAP compatibility target with additional commands/extensions where needed. | `docs/IMAP-COMPATIBILITY-MATRIX.md`, `test/wire_gateway.test.js` |
| P2-03 | Compliance controls package | Product | DONE | Audit export, retention, and policy controls align with target compliance requirements. | `docs/COMPLIANCE-CONTROLS.md`, `npm run check:compliance`, `npm run drill:compliance`, `npm run gate:compliance`, `ops/compliance/checklists/*` |

## Operational Verification Commands

Use these in staging and production validation runs:

```bash
# Readiness
curl -sS http://127.0.0.1:8787/ready

# Admin status
curl -sS http://127.0.0.1:8787/v1/admin/status \
  -H "x-loom-admin-token: $LOOM_ADMIN_TOKEN"

# Persistence schema status
curl -sS http://127.0.0.1:8787/v1/admin/persistence/schema \
  -H "x-loom-admin-token: $LOOM_ADMIN_TOKEN"

# Metrics (authenticated by default)
curl -sS http://127.0.0.1:8787/metrics \
  -H "x-loom-admin-token: $LOOM_ADMIN_TOKEN"
```

## Related Docs

- `README.md` (deployment env controls and safety gates)
- `docs/CONFIG-PROFILES.md` (secure profile defaults and reduced env surface)
- `docs/POSTGRES-OPERATIONS.md` (backup/restore and schema operations)
- `docs/SECRETS-KEY-ROTATION.md` (secret handling and rotation policy)
- `docs/FEDERATION-CONTROLS.md` (allowlist and federation-node transport policy checks)
- `docs/INBOUND-BRIDGE-HARDENING.md` (public inbound bridge auth policy checks and probes)
- `docs/RATE-LIMIT-POLICY.md` (API/identity/federation rate-limit tuning and probe evidence workflow)
- `docs/OUTBOX-WORKER-RELIABILITY.md` (continuous outbox processing checks and lag monitoring baseline)
- `docs/OBSERVABILITY-ALERTING.md` (endpoint scrape and alert-rule baseline for readiness/lag/auth/persistence)
- `docs/INCIDENT-RESPONSE-ONCALL.md` (on-call rotation, severity matrix, and incident playbooks)
- `docs/RELEASE-CHECKLIST.md` (release gates, rollback template, and pre-deploy checks)
- `docs/REQUEST-TRACING.md` (API + worker trace ID correlation runbook and validation checks)
- `docs/FEDERATION-INTEROP-DRILL.md` (challenge/deliver/receipt/replay interop drill flow)
- `docs/THREAT-MODEL.md` (STRIDE threat model with review cadence and mitigation mapping)
- `docs/SECURITY-TESTING-PROGRAM.md` (dependency/SAST/pen-test workflow and triage SLAs)
- `docs/CAPACITY-CHAOS-TESTS.md` (load/failure-injection scenarios and report cadence)
- `docs/DISASTER-RECOVERY-PLAN.md` (RTO/RPO, failover steps, and DR drill evidence flow)
- `docs/ACCESS-GOVERNANCE.md` (least-privilege controls and access review cadence)
- `docs/COMPLIANCE-CONTROLS.md` (audit export, retention policy, and compliance control mapping)
- `docs/IMAP-COMPATIBILITY-MATRIX.md` (wire IMAP compatibility target and command/extension coverage)
- `docs/CONFORMANCE.md` (protocol conformance surface)
- `docs/EXTENSION-REGISTRY.md` (extension ids, lifecycle, and versioning rules)
- `docs/RELEASE-POLICY.md` (release cadence and security SLAs)
- `SECURITY.md` (vulnerability reporting and response targets)
