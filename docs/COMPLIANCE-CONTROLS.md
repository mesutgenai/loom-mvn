# LOOM Compliance Controls

This runbook is the implementation artifact for `P2-03` in `docs/PRODUCTION-READINESS.md`.

Last reviewed: 2026-02-18

## Compliance Scope

- target baseline: SOC 2-style control evidence and common data-handling expectations
- this is an implementation control map for operators, not legal advice
- scope includes audit export, retention policy, and operational policy controls

## Audit Export Controls

1. Authenticated user audit feed:
   - `GET /v1/audit?limit=...` for actor-scoped activity review.
2. Admin backup export with audit payload:
   - `GET /v1/admin/persistence/backup?include_audit=true&audit_limit=...`
3. Backup payload controls:
   - includes `exported_at`, `schema_version`, `state`, and `audit_entries`.
4. Audit integrity controls:
   - `LOOM_AUDIT_HMAC_KEY` for entry MAC signing.
   - `LOOM_AUDIT_REQUIRE_MAC_VALIDATION=true` to fail loads without valid MAC.
   - `LOOM_AUDIT_VALIDATE_CHAIN=true` to enforce hash-chain continuity.

## Retention Policy

| Artifact | Retention Target | Storage Class | Owner | Validation Evidence |
| --- | --- | --- | --- | --- |
| Audit entries (`/v1/audit`, backup `audit_entries`) | 365 days hot + 2 years cold archive | Postgres + immutable backup archive | Security | Backup export sample + audit query sample |
| Persistence backups (`/v1/admin/persistence/backup`) | 90 days online + quarterly long-term snapshot | Encrypted object storage | Platform | Backup inventory + restore drill evidence |
| Access/compliance review records (`ops/access`, `ops/compliance`) | 24 months | Git-tracked evidence repository | Security + Product | Review markdown records with sign-off |

Retention windows should be tightened only through formal review and documented exception approvals.

## Policy Control Mapping

- Access governance and least privilege: `docs/ACCESS-GOVERNANCE.md`
- Secret and key rotation policy: `docs/SECRETS-KEY-ROTATION.md`
- Inbound bridge/auth policy hardening: `docs/INBOUND-BRIDGE-HARDENING.md`
- API and federation abuse/rate controls: `docs/RATE-LIMIT-POLICY.md`
- Security testing + triage SLAs: `docs/SECURITY-TESTING-PROGRAM.md`
- Release cadence and security patch SLA policy: `docs/RELEASE-POLICY.md`

## Evidence And Review Cadence

- Create and store quarterly compliance review records under `ops/compliance/checklists/`.
- Include sign-off from product + security owners for each review.
- Confirm latest record age is within policy (`<= 180` days warning threshold in checker).

Checklist template:

- `ops/compliance/checklists/2026-02-18-compliance-checklist-template.md`

## Validation Command

Static checks:

```bash
npm run check:compliance
```

Optional runtime probes:

```bash
npm run check:compliance -- --base-url https://<loom-host> --admin-token <admin-token> --bearer-token <audit-bearer-token>
```

Automated runtime evidence drill:

```bash
npm run drill:compliance -- --base-url https://<loom-host> --admin-token <admin-token> --bearer-token <audit-bearer-token>
```

If an audit bearer token is not pre-provisioned, bootstrap one for the drill:

```bash
npm run drill:compliance -- --base-url https://<loom-host> --admin-token <admin-token> --bootstrap-audit-token
```

Single command gate (check + drill):

```bash
npm run gate:compliance -- --base-url https://<loom-host> --admin-token <admin-token> --bootstrap-audit-token
```

Drill artifacts are written under:

- `scripts/output/compliance-drills/<drill-id>/report.json`
- `scripts/output/compliance-drills/<drill-id>/summary.md`
