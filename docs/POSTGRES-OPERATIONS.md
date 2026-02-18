# LOOM PostgreSQL Operations (MVP)

This runbook is for operating LOOM with PostgreSQL-backed persistence.

## Required Environment

- `LOOM_PG_URL`
- `LOOM_ADMIN_TOKEN`
- Optional tuning:
  - `LOOM_PG_STATE_KEY`
  - `LOOM_PG_POOL_MAX`
  - `LOOM_PG_IDLE_TIMEOUT_MS`
  - `LOOM_PG_CONNECT_TIMEOUT_MS`
  - `LOOM_PG_SSL`
  - `LOOM_PG_SSL_REJECT_UNAUTHORIZED`
  - `LOOM_OUTBOX_CLAIM_LEASE_MS`
  - `LOOM_OUTBOX_WORKER_ID`
- Resource limits:
  - `LOOM_MAX_LOCAL_IDENTITIES` (default 10000)
  - `LOOM_MAX_REMOTE_IDENTITIES` (default 50000)
  - `LOOM_MAX_DELEGATIONS_PER_IDENTITY` (default 500)
  - `LOOM_MAX_DELEGATIONS_TOTAL` (default 100000)
  - `LOOM_CONSUMED_CAPABILITY_MAX_ENTRIES` (default 50000)
  - `LOOM_REVOKED_DELEGATION_MAX_ENTRIES` (default 50000)
- Maintenance:
  - `LOOM_MAINTENANCE_SWEEP_INTERVAL_MS` (default 60000)

## Startup Checks

0. (Recommended) run direct Postgres readiness preflight:
   - `npm run check:pg -- --env-file .env.production --expected-schema 3`
1. Start LOOM and confirm readiness:
   - `curl -sS http://127.0.0.1:8787/ready`
2. Confirm persistence schema status:
   - `curl -sS http://127.0.0.1:8787/v1/admin/persistence/schema -H "x-loom-admin-token: $LOOM_ADMIN_TOKEN"`
3. Confirm runtime operational status:
   - `curl -sS http://127.0.0.1:8787/v1/admin/status -H "x-loom-admin-token: $LOOM_ADMIN_TOKEN"`
4. Confirm schema version and claim table availability:
   - Current schema target is `3` (`src/node/persistence_postgres.js`).
   - Verify `loom_outbox_claims` exists for distributed outbox workers.

The `check:pg` script validates:

- DB connectivity with `LOOM_PG_URL`
- required LOOM tables
- schema version (`loom_meta.schema_version`)
- presence of state row for configured `LOOM_PG_STATE_KEY` (warn-only if first boot)

## Backup Drill

Automated drill command:

- `npm run drill:persistence -- --base-url https://<loom-host> --execute-restore`

1. Export backup:
   - `curl -sS "http://127.0.0.1:8787/v1/admin/persistence/backup?include_audit=true" -H "x-loom-admin-token: $LOOM_ADMIN_TOKEN" > loom-backup.json`
2. Validate backup file:
   - `node --input-type=module -e "import {readFileSync} from 'node:fs';const b=JSON.parse(readFileSync('loom-backup.json','utf8'));if(!b.state) throw new Error('missing state');console.log('ok', b.schema_version, Array.isArray(b.audit_entries)?b.audit_entries.length:0)"`

## Restore Drill

1. Prepare restore payload:
   - `node --input-type=module -e "import {readFileSync,writeFileSync} from 'node:fs';const b=JSON.parse(readFileSync('loom-backup.json','utf8'));writeFileSync('loom-restore.json', JSON.stringify({confirm:'restore', backup:b, replace_state:true, truncate_audit:false}))"`
2. Run restore:
   - `curl -sS -X POST http://127.0.0.1:8787/v1/admin/persistence/restore -H "x-loom-admin-token: $LOOM_ADMIN_TOKEN" -H "content-type: application/json" --data-binary @loom-restore.json`
3. Re-check status:
   - `curl -sS http://127.0.0.1:8787/v1/admin/status -H "x-loom-admin-token: $LOOM_ADMIN_TOKEN"`

## Drill Evidence Artifacts

- The automated drill writes evidence to `scripts/output/persistence-drills/<drill-id>/`:
  - `report.json` (machine-readable drill result)
  - `summary.md` (human-readable drill summary)
  - `backup.json` (optional; can be disabled with `--write-backup false`)
- Archive `summary.md` and `report.json` in your ops evidence store for each scheduled drill.

## Distributed Outbox Workers

- Outbox claim leasing is persisted in PostgreSQL (`loom_outbox_claims`) and used for `email`, `federation`, and `webhook` outbox processors.
- Use a stable `LOOM_OUTBOX_WORKER_ID` per worker process and tune `LOOM_OUTBOX_CLAIM_LEASE_MS` for expected processing latency.
- Claim rows are auto-cleaned in maintenance sweeps; stale rows older than 6 hours past lease expiry are removed.

## Schema Migration Policy (MVP)

- Current schema version is managed in `loom_meta` (`schema_version`).
- Any schema change must:
  1. Be additive-first when possible.
  2. Bump `CURRENT_SCHEMA_VERSION` in `src/node/persistence_postgres.js`.
  3. Keep backward-safe read paths during rollout.
  4. Be covered by backup/restore drill before production deploy.
