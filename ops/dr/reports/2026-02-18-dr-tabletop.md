# DR Tabletop - 2026-02-18

## Scenario

- Simulated complete primary-region outage (network isolation + DB unavailable)
- Goal: validate failover runbook and RTO/RPO assumptions

## Timeline (UTC)

- 09:10 incident declared
- 09:18 failover decision approved
- 09:31 secondary region promoted
- 09:42 traffic routed to secondary
- 09:49 service health stabilized

## Outcomes

- Measured recovery time: 39 minutes (within 60-minute RTO target)
- Estimated data-loss window: < 3 minutes (within 5-minute RPO target)
- `/ready` and `/v1/admin/status` checks healthy after failover

## Gaps

- Improve replication lag dashboard prominence in incident bridge view
- Add explicit operator checklist for DNS TTL override path

## Follow-ups

- schedule next DR drill within quarter
- update runbook with refined replication verification commands
