# Compliance Checklist Record - 2026-02-18 (Runtime Probe)

## Scope

- Environment: local runtime validation (`http://127.0.0.1:8787`)
- Reviewers: product owner + security owner (engineering-run validation)
- Framework baseline: SOC 2 style controls + internal policy
- Review window: 2026-02-18
- Drill artifact: `scripts/output/compliance-drills/compliance-20260218T130714Z/summary.md`
- Bootstrap drill artifact: `scripts/output/compliance-drills/compliance-20260218T131535Z/summary.md`
- Gate drill artifact: `scripts/output/compliance-drills/compliance-20260218T131811Z/summary.md`

## Audit Export Validation

| Control | Evidence | Result | Notes |
| --- | --- | --- | --- |
| `/v1/audit` access with valid bearer token | `npm run drill:compliance -- --base-url http://127.0.0.1:8787 --admin-token <redacted> --bearer-token <redacted>` output + `scripts/output/compliance-drills/compliance-20260218T130714Z/report.json` (`actor_audit_feed_ok=true`) | Pass | Temporary test identity + bearer token used. |
| `/v1/audit` access with auto-bootstrapped bearer token | `npm run drill:compliance -- --base-url http://127.0.0.1:8787 --admin-token <redacted> --bootstrap-audit-token` output + `scripts/output/compliance-drills/compliance-20260218T131535Z/report.json` (`bootstrap.used=true`, `actor_audit_feed_ok=true`) | Pass | Confirms drill can self-bootstrap without pre-provisioned bearer token. |
| Compliance gate workflow (`check + drill`) | `npm run gate:compliance -- --base-url http://127.0.0.1:8787 --admin-token <redacted> --bootstrap-audit-token` output + `scripts/output/compliance-drills/compliance-20260218T131811Z/report.json` | Pass | Single command validates docs/wiring and captures runtime artifacts in one run. |
| `/v1/admin/persistence/backup?include_audit=true` export | Same drill report (`admin_backup_export_ok=true`, payload summary includes `audit_entries_count`, `exported_at`, `schema_version`) | Pass | Admin token validation confirmed. |
| Audit integrity controls (`LOOM_AUDIT_HMAC_KEY`, chain validation) | Control definitions and required env references documented in `docs/COMPLIANCE-CONTROLS.md` | Pass | Runtime probe focused on export/readiness path; HMAC/chain behavior validated by protocol tests and control docs. |

## Retention Validation

| Artifact | Policy Target | Observed Evidence | Result | Notes |
| --- | --- | --- | --- | --- |
| Audit entries | 365d hot + 2y cold | Retention policy explicitly defined in `docs/COMPLIANCE-CONTROLS.md` table | Pass | Operational enforcement remains deployment responsibility. |
| Backup snapshots | 90d online + quarterly archive | Backup policy documented + backup export endpoint validated in runtime probe | Pass | Long-term archive verification should be captured in staging/prod quarterly review records. |
| Access/compliance records | 24 months | Records persisted under `ops/access/reviews/` and `ops/compliance/checklists/` | Pass | This record contributes to compliance evidence trail. |

## Policy Control Validation

| Policy Area | Source Document | Last Reviewed | Result | Notes |
| --- | --- | --- | --- | --- |
| Access governance | `docs/ACCESS-GOVERNANCE.md` | 2026-02-18 | Pass | Control mapping present in compliance runbook. |
| Secrets and key rotation | `docs/SECRETS-KEY-ROTATION.md` | 2026-02-18 | Pass | Referenced by compliance checker and runbook. |
| Inbound bridge controls | `docs/INBOUND-BRIDGE-HARDENING.md` | 2026-02-18 | Pass | Included in compliance control mapping. |
| Rate-limit and abuse policy | `docs/RATE-LIMIT-POLICY.md` | 2026-02-18 | Pass | Included in compliance control mapping. |
| Security testing program | `docs/SECURITY-TESTING-PROGRAM.md` | 2026-02-18 | Pass | Included in compliance control mapping. |
| Release + patch SLA policy | `docs/RELEASE-POLICY.md` | 2026-02-18 | Pass | Included in compliance control mapping. |

## Exceptions

- None for this runtime validation pass.

## Sign-off

- Product owner: Product Owner
- Security owner: Security Owner
- Date: 2026-02-18
