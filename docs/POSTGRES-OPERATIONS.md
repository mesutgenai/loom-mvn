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

## Startup Checks

1. Start LOOM and confirm readiness:
   - `curl -sS http://127.0.0.1:8787/ready`
2. Confirm persistence schema status:
   - `curl -sS http://127.0.0.1:8787/v1/admin/persistence/schema -H "x-loom-admin-token: $LOOM_ADMIN_TOKEN"`
3. Confirm runtime operational status:
   - `curl -sS http://127.0.0.1:8787/v1/admin/status -H "x-loom-admin-token: $LOOM_ADMIN_TOKEN"`

## Backup Drill

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

## Schema Migration Policy (MVP)

- Current schema version is managed in `loom_meta` (`schema_version`).
- Any schema change must:
  1. Be additive-first when possible.
  2. Bump `CURRENT_SCHEMA_VERSION` in `/Users/mesut/Desktop/email++/src/node/persistence_postgres.js`.
  3. Keep backward-safe read paths during rollout.
  4. Be covered by backup/restore drill before production deploy.
