# LOOM Disaster Recovery Plan

This runbook is the implementation artifact for `P1-05` in `docs/PRODUCTION-READINESS.md`.

## DR Objectives

- preserve envelope/thread/audit integrity across regional failure
- restore service within defined RTO targets
- meet data-loss constraints defined by RPO targets

## Targets

| Metric | Target |
| --- | --- |
| RTO (regional service restoration) | 60 minutes |
| RPO (acceptable data loss) | 5 minutes |

## Reference Architecture

- primary region: active write/read serving
- secondary region: warm standby API + worker stack
- PostgreSQL: managed cross-region replication with point-in-time recovery
- object/blob storage: cross-region replication enabled
- DNS/ingress: failover-capable with health-based routing

## Failover Procedure

1. Declare incident and freeze non-essential deploys.
2. Confirm primary-region outage and replication health status.
3. Promote secondary-region datastore to write primary.
4. Update service routing (DNS/load balancer) to secondary region.
5. Validate `/ready`, `/metrics`, `/v1/admin/status`, queue drain behavior.
6. Announce restoration and monitor error/latency for stabilization window.

## Data Consistency Checks

- compare envelope/thread counts between restored and last known checkpoints
- verify audit chain continuity and persistence adapter health
- verify outbox queue states (queued/failed/delivered) for drift
- run targeted federation/email/webhook delivery canary checks

## Drill Cadence

- minimum quarterly DR tabletop or live failover drill
- after significant persistence topology changes, run an additional drill
- store evidence in `ops/dr/reports/`

## Validation Command

```bash
npm run check:dr-plan
```

## Current Drill Record

- `ops/dr/reports/2026-02-18-dr-tabletop.md`
