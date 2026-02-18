# LOOM Observability And Alerting Runbook

This runbook is the implementation artifact for `P0-09` in `docs/PRODUCTION-READINESS.md`.

## Objective

Ensure `/ready`, `/metrics`, and `/v1/admin/status` are scraped and alert policies cover readiness failures, queue lag, auth error spikes, and persistence/database failures.

## Alert Policy Baseline

- Prometheus alert rules:
  - `ops/alerts/loom-alert-rules.yaml`
- Required alert classes:
  - readiness probe failures (`/ready`)
  - admin health probe failures (`/v1/admin/status`)
  - outbox lag (federation/email/webhook)
  - auth/capability error spikes
  - persistence write failures / active persistence error state

The baseline rules expect blackbox jobs:

- `loom-ready`
- `loom-admin-status`

## Static Validation

```bash
npm run check:observability -- --env-file .env.production
```

Checks include:

- authenticated metrics scrape posture (`LOOM_METRICS_PUBLIC=false` recommended)
- alert rule file presence and required alert names
- availability of admin token for protected metrics/admin health scraping

## Runtime Validation (Recommended)

```bash
npm run check:observability -- \
  --env-file .env.production \
  --base-url https://<loom-host> \
  --admin-token <admin-token>
```

Runtime checks verify:

- `/ready` returns valid readiness payload
- `/metrics` is scrapeable and exposes required operational metrics
- `/v1/admin/status` is scrapeable and includes metrics/outbox health structures

## Required Scrape Targets

Minimum scrape/blackbox coverage:

- `/ready` (readiness/availability probe)
- `/metrics` (Prometheus metrics endpoint)
- `/v1/admin/status` (authenticated admin health snapshot)

## Key Metrics For Alerts

- `loom_federation_outbox_lag_ms`
- `loom_email_outbox_lag_ms`
- `loom_webhook_outbox_lag_ms`
- `loom_errors_total{code=...}` (auth/capability/rate errors)
- `loom_persistence_writes_failed`
- `loom_persistence_last_error`
- `loom_persistence_enabled`

## Evidence Required For P0-09

- Monitoring dashboard links for availability, outbox lag, auth errors, and persistence health.
- Alert policy link/revision for `ops/alerts/loom-alert-rules.yaml` (or deployed equivalent).
- `npm run check:observability` output from target environment.
