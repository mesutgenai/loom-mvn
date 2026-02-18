# LOOM Outbox Worker Reliability Runbook

This runbook is the implementation artifact for `P0-08` in `docs/PRODUCTION-READINESS.md`.

## Objective

Keep federation, email, and webhook outbox workers continuously processing with distributed claim coordination and lag alert thresholds.

## Required Configuration

- Worker loops enabled:
  - `LOOM_OUTBOX_AUTO_PROCESS_INTERVAL_MS`
  - `LOOM_EMAIL_OUTBOX_AUTO_PROCESS_INTERVAL_MS`
  - `LOOM_WEBHOOK_OUTBOX_AUTO_PROCESS_INTERVAL_MS`
- Batch sizes:
  - `LOOM_OUTBOX_AUTO_PROCESS_BATCH_SIZE`
  - `LOOM_EMAIL_OUTBOX_AUTO_PROCESS_BATCH_SIZE`
  - `LOOM_WEBHOOK_OUTBOX_AUTO_PROCESS_BATCH_SIZE`
- Distributed worker coordination (required with PostgreSQL persistence):
  - `LOOM_OUTBOX_WORKER_ID`
  - `LOOM_OUTBOX_CLAIM_LEASE_MS`

## Static Validation

```bash
npm run check:outbox-workers -- --env-file .env.production
```

This validates:

- all worker intervals/batch sizes are configured for continuous processing
- lease settings are compatible with worker cadence
- distributed worker identity is set when Postgres persistence is enabled

## Runtime Validation (Recommended)

```bash
npm run check:outbox-workers -- \
  --env-file .env.production \
  --base-url https://<loom-host> \
  --admin-token <admin-token> \
  --max-lag-ms 60000
```

Runtime checks use `/v1/admin/status` to verify:

- each outbox worker is enabled and not reporting `last_error`
- runtime worker interval/batch values match expected config
- queue lag is within threshold for federation/email/webhook outboxes

## Lag Monitoring Signals

- `/metrics` gauges:
  - `loom_federation_outbox_lag_ms`
  - `loom_email_outbox_lag_ms`
  - `loom_webhook_outbox_lag_ms`
- `/v1/admin/status` snapshot:
  - `outbox.federation.lag_ms`
  - `outbox.email.lag_ms`
  - `outbox.webhook.lag_ms`
  - `runtime.*_outbox_worker.last_error`

## Evidence Required For P0-08

- Sanitized worker config snapshot.
- `npm run check:outbox-workers` output from target environment.
- Dashboard/alert links for outbox lag and worker-error alarms.
