# LOOM Access Governance

This runbook is the implementation artifact for `P1-06` in `docs/PRODUCTION-READINESS.md`.

## Objectives

- enforce least-privilege access for production operations
- ensure admin/API credential use is auditable and periodically reviewed
- reduce standing access through short-lived and role-scoped controls

## Access Model

- production admin access is restricted to named operators in on-call/security groups
- `LOOM_ADMIN_TOKEN` is managed through secret manager/KMS and rotated on schedule
- CI/CD deploy identity is distinct from human operator identity
- break-glass access requires incident ticket reference and post-incident review

## Required Controls

1. Role-based access groups for platform, security, and release operations.
2. Quarterly access review for all production roles and tokens.
3. Joiner/mover/leaver process with same-day deprovisioning.
4. Audit trail retention for admin/API changes and secret rotations.
5. Dual control for privileged secret changes in production.

## Review Cadence

- quarterly scheduled access review
- ad-hoc review after major incident or team/org changes
- immediate review after any unauthorized access event

## Evidence Artifacts

- review records under `ops/access/reviews/`
- secret rotation evidence from `docs/SECRETS-KEY-ROTATION.md`
- incident-linked break-glass logs (`docs/INCIDENT-RESPONSE-ONCALL.md`)

## Validation Command

```bash
npm run check:access-governance
```

## Current Review Template

- `ops/access/reviews/2026-02-18-access-review-template.md`
