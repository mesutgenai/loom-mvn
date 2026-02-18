# Capacity/Chaos Drill Report - 2026-02-18

## Scope

- Environment: staging baseline
- Window: 2026-02-18 08:30 UTC -> 2026-02-18 09:00 UTC
- Operator: platform on-call

## Scenarios Executed

1. Baseline steady-state API + outbox load
2. Burst write load (3x baseline for 5 minutes)
3. Simulated email relay 5xx burst (2 minutes)
4. Worker restart with queued backlog

## Key Results

- API availability during run: 99.95%
- p95 envelope write latency: 312 ms
- p95 thread read latency: 188 ms
- outbox lag peak: 4m 21s
- outbox lag recovery to steady-state: 6m 04s
- data consistency checks: pass

## Alerts

- `LoomEmailOutboxLagHigh`: fired during relay failure simulation, auto-cleared
- `LoomPersistenceFailures`: not triggered

## Follow-ups

- increase relay retry visibility in dashboard for faster operator triage
- add explicit federation timeout chaos scenario in next run
