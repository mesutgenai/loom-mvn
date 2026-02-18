# Changelog

All notable changes to this project are documented in this file.

## Unreleased

No unreleased changes yet.

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
