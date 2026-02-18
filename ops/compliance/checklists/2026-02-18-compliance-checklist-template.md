# Compliance Checklist Record - 2026-02-18 (Template)

## Scope

- Environment: production
- Reviewers: product owner + security owner
- Framework baseline: SOC 2 style controls + internal policy
- Review window: ______________

## Audit Export Validation

| Control | Evidence | Result | Notes |
| --- | --- | --- | --- |
| `/v1/audit` access with valid bearer token | API sample response attached | Pass/Fail | |
| `/v1/admin/persistence/backup?include_audit=true` export | Backup artifact reference | Pass/Fail | |
| Audit integrity controls (`LOOM_AUDIT_HMAC_KEY`, chain validation) | Config snapshot + startup logs | Pass/Fail | |

## Retention Validation

| Artifact | Policy Target | Observed Evidence | Result | Notes |
| --- | --- | --- | --- | --- |
| Audit entries | 365d hot + 2y cold | | Pass/Fail | |
| Backup snapshots | 90d online + quarterly archive | | Pass/Fail | |
| Access/compliance records | 24 months | | Pass/Fail | |

## Policy Control Validation

| Policy Area | Source Document | Last Reviewed | Result | Notes |
| --- | --- | --- | --- | --- |
| Access governance | `docs/ACCESS-GOVERNANCE.md` | | Pass/Fail | |
| Secrets and key rotation | `docs/SECRETS-KEY-ROTATION.md` | | Pass/Fail | |
| Inbound bridge controls | `docs/INBOUND-BRIDGE-HARDENING.md` | | Pass/Fail | |
| Rate-limit and abuse policy | `docs/RATE-LIMIT-POLICY.md` | | Pass/Fail | |
| Security testing program | `docs/SECURITY-TESTING-PROGRAM.md` | | Pass/Fail | |
| Release + patch SLA policy | `docs/RELEASE-POLICY.md` | | Pass/Fail | |

## Exceptions

- Document any control exceptions, expiration date, and approval ticket.

## Sign-off

- Product owner: ____________________
- Security owner: ____________________
- Date: ____________________
