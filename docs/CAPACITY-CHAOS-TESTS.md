# LOOM Capacity And Chaos Tests

This runbook is the implementation artifact for `P1-04` in `docs/PRODUCTION-READINESS.md`.

## Objectives

- validate SLO behavior under sustained load
- validate graceful degradation under dependency and network faults
- verify queue recovery and data consistency after disruption

## Target SLO Baselines

- API availability: 99.9%
- p95 write latency (`POST /v1/envelopes`): < 400 ms
- p95 read latency (`GET /v1/threads/{id}`): < 250 ms
- outbox lag recovery to steady-state: < 10 minutes after injected fault

## Load Scenarios

1. Baseline steady-state load (normal traffic profile)
2. Burst write load (3x baseline write throughput)
3. Federation ingress spike (signed delivery flood within configured rate limits)
4. Bridge/gateway mixed load (SMTP submit + API queue + webhook processing)

## Chaos Scenarios

1. PostgreSQL failover/restart during active write load
2. External federation endpoint timeout/connection resets
3. Email relay transient 5xx errors
4. Worker restart while queues contain pending deliveries
5. Partial network partition between app and persistence tier

## Pass Criteria

- no data loss (envelope/thread/audit consistency checks pass)
- API health recovers without manual data repair
- outbox backlog drains within SLO window
- alerts trigger on injected failures and clear after recovery

## Evidence

- store drill reports under `ops/chaos/reports/`
- include timestamps, scenario parameters, and observed SLO metrics
- attach links to alert timelines and remediation notes

## Validation Command

```bash
npm run check:capacity-chaos
```

## Current Baseline Report

- `ops/chaos/reports/2026-02-18-baseline-capacity-chaos.md`
