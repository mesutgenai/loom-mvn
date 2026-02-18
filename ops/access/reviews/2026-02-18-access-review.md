# Access Review Record - 2026-02-18

## Scope

- Environment: production
- Reviewers: security lead + platform lead
- Coverage: admin token holders, deploy identities, on-call break-glass access

## Access Inventory

| Principal | Role/Group | Access Scope | Last Verified | Status | Notes |
| --- | --- | --- | --- | --- | --- |
| loom.platform.oncall | platform-oncall | Admin endpoints + deploy | 2026-02-18 | Verified | Rotation validated |
| loom.security.lead | security | Policy + audit review | 2026-02-18 | Verified | Quarterly review complete |
| loom.breakglass | emergency | Time-bound break-glass access | 2026-02-18 | Verified | Expiry + alerting confirmed |

## Changes Applied

- Revoked stale deploy token for prior release automation identity.
- Rotated break-glass token and documented expiry in secrets manager.

## Exceptions

- None.

## Sign-off

- Security reviewer: Security Lead
- Platform reviewer: Platform Lead
