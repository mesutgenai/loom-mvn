# LOOM Security Testing Program

This runbook is the implementation artifact for `P1-03` in `docs/PRODUCTION-READINESS.md`.

## Program Scope

- Application/API code (`src/`)
- Protocol and gateway logic (federation, bridge, SMTP/IMAP)
- Build/dependency supply chain (`package.json`, lockfile, CI)
- Secrets exposure prevention (repo and env hygiene)

## Required Controls

1. Dependency scanning
   - `npm audit --audit-level=high` in CI.
   - Weekly scheduled security workflow run.
2. Static analysis (SAST)
   - CodeQL analysis for JavaScript in GitHub Actions (`.github/workflows/security.yml`).
3. Secret hygiene
   - `npm run check:secrets` in CI to block committed secrets and unsafe `.env*` files.
4. Manual security review
   - Threat model review on major protocol changes (`docs/THREAT-MODEL.md`).
5. Periodic penetration testing
   - Minimum quarterly external or independent penetration test.
   - Scope includes auth, federation, bridge/gateway, and admin surfaces.

## Triage SLAs

| Severity | Triage Start | Mitigation Target |
| --- | --- | --- |
| Critical | 24 hours | 72 hours |
| High | 2 business days | 14 days |
| Medium | 5 business days | 30 days |
| Low | 10 business days | Next planned hardening cycle |

## Findings Workflow

1. Record finding in tracker (`ops/security/findings-tracker-template.md`).
2. Assign owner and SLA due date based on severity.
3. Link remediation PR/commit and verification evidence.
4. Close finding only after verification in staging/prod-equivalent.

## Validation Command

```bash
npm run check:security-program
```

## Evidence For P1-03

- `docs/SECURITY-TESTING-PROGRAM.md`
- `.github/workflows/security.yml` (dependency + SAST jobs)
- CI logs for `npm audit`, `check:secrets`, and CodeQL
- Findings tracker records with SLA status
