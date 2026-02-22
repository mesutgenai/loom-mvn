# LOOM Inbound Bridge Hardening Runbook

This runbook is the implementation artifact for `P0-06` in `docs/PRODUCTION-READINESS.md`.

## Objective

Ensure public inbound email bridge exposure is explicitly confirmed, guarded by strict authentication policy defaults, protected by profile-aware content policy controls, and non-actuating by default.

## Required Environment Controls (Public Service)

- `LOOM_BRIDGE_EMAIL_INBOUND_ENABLED=true` (or disable the surface entirely)
- `LOOM_BRIDGE_EMAIL_INBOUND_PUBLIC_CONFIRMED=true` when inbound bridge remains enabled
- `LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_ADMIN_TOKEN=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_AUTH_RESULTS=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_DMARC_PASS=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_REJECT_ON_AUTH_FAILURE=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_PAYLOAD_AUTH_RESULTS=false` (recommended on public ingress to avoid trusting unsanitized payload evidence)
- `LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_AUTOMATIC_ACTUATION=false` (recommended default: bridged structured extraction stays non-authoritative/read-only)
- `LOOM_ADMIN_TOKEN` configured
- `LOOM_INBOUND_CONTENT_FILTER_ENABLED=true`
- `LOOM_INBOUND_CONTENT_FILTER_REJECT_MALWARE=true`
- `LOOM_INBOUND_CONTENT_FILTER_PROFILE_BRIDGE=strict` (recommended for public ingress)
- `LOOM_INBOUND_CONTENT_FILTER_QUARANTINE_THRESHOLD` and `LOOM_INBOUND_CONTENT_FILTER_REJECT_THRESHOLD` tuned for production traffic

Weak policy overrides require explicit acknowledgment:

- `LOOM_BRIDGE_EMAIL_INBOUND_WEAK_AUTH_POLICY_CONFIRMED=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_AUTOMATION_CONFIRMED=true` (required only when automatic bridged actuation is intentionally enabled on public service)

Profile shortcut:

- `LOOM_CONFIG_PROFILE=secure_public` pre-sets strict inbound bridge defaults (still requires deployment-specific secrets and network allowlists).

Optional telemetry/tuning controls:

- `LOOM_INBOUND_CONTENT_FILTER_DECISION_LOG_ENABLED=true` (anonymized JSONL decision stream)
- `LOOM_INBOUND_CONTENT_FILTER_DECISION_LOG_FILE`
- `LOOM_INBOUND_CONTENT_FILTER_DECISION_LOG_SALT` (rotation secret)
- `LOOM_BRIDGE_EMAIL_INBOUND_HEADER_ALLOWLIST` (retain only explicitly listed headers in bridge metadata)

## Static Policy Validation

Run against production environment configuration:

```bash
npm run check:inbound-bridge -- --env-file .env.production
```

This validates:

- explicit public-service confirmation for inbound bridge exposure
- admin-token gate requirements
- strict public inbound auth/DMARC/reject defaults (or explicit weak-policy confirmation)
- bridged auto-actuation policy confirmation on public service
- safe auth-failure handling (reject and/or quarantine)
- payload auth evidence policy (`LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_PAYLOAD_AUTH_RESULTS`) posture

## Content Filter Admin Workflow

Admin-token protected endpoints expose staged policy rollout:

- `GET /v1/admin/content-filter/config`
- `POST /v1/admin/content-filter/config`
  - `mode=canary`: stage candidate thresholds/profiles
  - `mode=apply`: promote staged canary (or explicit payload) to active config
  - `mode=rollback`: restore prior snapshot

Recommended release flow:

1. stage canary config
2. monitor profile-labeled decision metrics + quarantine/reject drift
3. apply
4. rollback immediately if false-positive rate regresses

## Runtime Admin-Gate Probe (Optional, Recommended)

To verify runtime enforcement on a running service:

```bash
npm run check:inbound-bridge -- \
  --env-file .env.production \
  --base-url https://<loom-host> \
  --bearer-token <actor-bearer-token> \
  --admin-token <admin-token>
```

Runtime probe checks:

- request without `x-loom-admin-token` returns `403` when admin gate is enabled
- same request with valid admin token is not rejected at the admin gate

## Negative Tests

Run the focused inbound bridge hardening tests:

```bash
npm run test:inbound-bridge-hardening
```

Covered cases:

- public inbound bridge requires explicit confirmation
- weak public inbound auth policy is rejected unless explicitly confirmed
- public bridged auto-actuation is rejected unless explicitly confirmed
- admin-token requirement is enforced on inbound bridge requests
- auth-failure handling supports quarantine/reject controls
- profile-aware content filter decisions are enforced and exposed in envelope/thread metadata

## Threshold Tuning Workflow

Use anonymized decision telemetry and corpus tooling to calibrate thresholds:

```bash
npm run build:content-filter-corpus -- --decision-log-file <path-to-jsonl>
```

Alternative corpus sources:

```bash
npm run build:content-filter-corpus -- --data-dir <loom-data-dir>
npm run build:content-filter-corpus -- --state-file <state.json>
npm run build:content-filter-corpus -- --backup-file <backup.json>
```

The generated report includes sample-size guards and recommended threshold deltas by profile (`strict`, `balanced`, `agent`).

## Evidence Required For P0-06

- Sanitized config snapshot with inbound bridge env values.
- `npm run check:inbound-bridge` output from target environment.
- Focused negative-test output from `npm run test:inbound-bridge-hardening`.
- Admin change record for canary/apply/rollback actions and resulting config version.
