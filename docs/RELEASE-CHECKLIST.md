# LOOM Release Checklist

This checklist is the implementation artifact for `P0-11` in `docs/PRODUCTION-READINESS.md`.

## Required Gates

- [ ] CI and test suite green
  - `npm test`
  - CI workflow status is green on target branch/tag.
- [ ] Conformance checks passed
  - `docs/CONFORMANCE.md` vectors reviewed.
  - `test/conformance_vectors.test.js` passing in CI.
- [ ] Changelog updated
  - `CHANGELOG.md` includes release notes and date/version heading.
  - `## Unreleased` section retained for follow-on changes.
- [ ] Rollback plan documented
  - Explicit rollback target (version/hash) identified.
  - Operator steps and verification commands recorded.

## Pre-Deploy Validation Commands

Preferred end-to-end gate (runs all checks, compliance drill, interop evidence check, and test suite):

```bash
npm run gate:release -- --env-file .env.production --base-url https://<loom-host> --admin-token <admin-token> --bootstrap-audit-token
```

Expanded/manual sequence (same underlying checks):

```bash
npm run check:release-gates
npm run check:prod-env -- --env-file .env.production
npm run check:secrets
npm run check:pg -- --env-file .env.production --expected-schema 3
npm run check:federation -- --env-file .env.production
npm run check:inbound-bridge -- --env-file .env.production
npm run check:rate-limits -- --env-file .env.production
npm run check:outbox-workers -- --env-file .env.production
npm run check:observability -- --env-file .env.production
npm run check:tracing -- --env-file .env.production
npm run check:threat-model
npm run check:security-program
npm run check:capacity-chaos
npm run check:dr-plan
npm run check:access-governance
npm run check:compliance
npm run drill:compliance -- --base-url https://<loom-host> --admin-token <admin-token> --bearer-token <audit-bearer-token>
# or, if no audit bearer token is pre-provisioned:
# npm run drill:compliance -- --base-url https://<loom-host> --admin-token <admin-token> --bootstrap-audit-token
npm run gate:compliance -- --base-url https://<loom-host> --admin-token <admin-token> --bootstrap-audit-token
npm run check:federation-interop -- --required-targets staging,preprod --max-age-hours 168
```

## Rollback Plan Template

1. Trigger condition:
   - Define objective trigger(s) for rollback (error rate, lag, failed health checks).
2. Rollback target:
   - Previous release tag/commit and deployment artifact ID.
3. Execution:
   - Re-deploy rollback target.
   - Revert config changes introduced by current release if applicable.
4. Verification:
   - `/ready`, `/metrics`, `/v1/admin/status` healthy.
   - Outbox lag and critical alerts return within threshold.
5. Incident record:
   - Log timeline, root cause summary, and follow-up owners.
