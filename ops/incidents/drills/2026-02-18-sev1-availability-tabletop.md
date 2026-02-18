# LOOM Drill: Sev 1 Availability Tabletop

- Date: 2026-02-18
- Scenario: sustained outbox lag and readiness flaps during high inbound federation traffic
- Commander: Platform On-Call (simulated)
- Participants: Platform, Security, Release Engineering

## Timeline Summary

1. Alert fired on queue lag and readiness probe failures.
2. On-call verified `/ready`, `/metrics`, and `/v1/admin/status`.
3. Mitigation executed:
   - tightened inbound rate controls
   - increased outbox worker capacity
4. Service recovered to healthy readiness and lag thresholds.

## What Worked

- Alerting surfaced the right first indicators.
- Triage procedure and command ownership were clear.
- Recovery verification checklist prevented early closure.

## Gaps

- Initial comms did not include explicit ETA for next update.
- Escalation handoff checklist needed stronger role clarity for backup responder.

## Follow-Up

- [ ] Add standardized status-update template with ETA field (Owner: SRE, Due: 2026-02-25).
- [ ] Add backup-responder handoff checklist to on-call section (Owner: Platform, Due: 2026-02-25).
