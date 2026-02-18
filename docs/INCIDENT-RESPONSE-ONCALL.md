# LOOM Incident Response And On-Call Runbook

This runbook is the implementation artifact for `P0-10` in `docs/PRODUCTION-READINESS.md`.

## On-Call Rotation

- Primary on-call: single engineer owning initial triage and response coordination.
- Secondary on-call: backup responder when primary does not acknowledge within SLA.
- Escalation manager: engineering lead for Sev 1/Sev 2 incidents.
- Security escalation: security lead for confirmed/suspected compromise events.

Escalation timing targets:

- Sev 1: page immediately, ack within 5 minutes.
- Sev 2: page immediately, ack within 15 minutes.
- Sev 3: ticket within business hours.

## Severity Matrix

| Severity | Definition | Initial Ack | Update Cadence |
| --- | --- | --- | --- |
| Sev 1 | Full outage, active data/security risk, or broad customer-impacting failure. | 5 minutes | Every 15 minutes |
| Sev 2 | Partial outage or serious degradation with significant customer impact. | 15 minutes | Every 30 minutes |
| Sev 3 | Degraded non-critical function or contained defect/workaround available. | 1 business hour | Every 4 hours |
| Sev 4 | Minor issue, no immediate operational impact. | 1 business day | Daily/async |

## Incident Lifecycle

1. Detect and classify severity.
2. Page primary/secondary on-call and assign incident commander.
3. Stabilize service (mitigate blast radius first, then pursue root cause).
4. Communicate status updates on defined cadence.
5. Resolve, validate recovery, and close incident.
6. Publish post-incident review with owners and due dates.

## Security Incident Playbook

1. Preserve evidence (logs, request IDs, audit artifacts, snapshots).
2. Revoke/rotate suspected credentials:
   - `LOOM_ADMIN_TOKEN`
   - node signing keys
   - SMTP/database credentials
3. Reduce exposure:
   - tighten allowlists
   - temporarily disable risky ingress/egress paths if needed
4. Verify integrity:
   - run persistence checks
   - validate federation trust state
5. Document timeline, indicators, containment actions, and residual risk.

## Availability Incident Playbook

1. Confirm readiness/admin status:
   - `/ready`
   - `/v1/admin/status`
   - `/metrics`
2. Triage dominant signal:
   - queue lag
   - auth error spike
   - persistence write failures
3. Mitigate:
   - scale worker capacity or reduce batch intervals
   - isolate abusive traffic patterns
   - fail over/repair database path
4. Recover and verify:
   - lag returns below threshold
   - readiness healthy
   - no active critical alerts

## Communications

- Use a dedicated incident channel and a single incident commander.
- Keep updates concise: impact, scope, mitigation, next update time.
- Send final summary after resolution:
  - root cause
  - customer impact
  - remediation actions
  - follow-up owners/dates

## Drill Program

- Run at least one tabletop drill per month.
- Alternate focus between security and availability scenarios.
- Store drill notes in `ops/incidents/drills/`.
- Require follow-up items with owners and due dates for each drill.

Evidence command:

```bash
npm run check:incident-response
```
