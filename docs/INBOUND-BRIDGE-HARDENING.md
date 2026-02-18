# LOOM Inbound Bridge Hardening Runbook

This runbook is the implementation artifact for `P0-06` in `docs/PRODUCTION-READINESS.md`.

## Objective

Ensure public inbound email bridge exposure is explicitly confirmed and guarded by strict authentication policy defaults.

## Required Environment Controls (Public Service)

- `LOOM_BRIDGE_EMAIL_INBOUND_ENABLED=true` (or disable the surface entirely)
- `LOOM_BRIDGE_EMAIL_INBOUND_PUBLIC_CONFIRMED=true` when inbound bridge remains enabled
- `LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_ADMIN_TOKEN=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_AUTH_RESULTS=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_DMARC_PASS=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_REJECT_ON_AUTH_FAILURE=true`
- `LOOM_ADMIN_TOKEN` configured

Weak policy overrides require explicit acknowledgment:

- `LOOM_BRIDGE_EMAIL_INBOUND_WEAK_AUTH_POLICY_CONFIRMED=true`

## Static Policy Validation

Run against production environment configuration:

```bash
npm run check:inbound-bridge -- --env-file .env.production
```

This validates:

- explicit public-service confirmation for inbound bridge exposure
- admin-token gate requirements
- strict public inbound auth/DMARC/reject defaults (or explicit weak-policy confirmation)
- safe auth-failure handling (reject and/or quarantine)

## Runtime Admin-Gate Probe (Optional, Recommended)

To verify runtime enforcement on a running service:

```bash
npm run check:inbound-bridge -- \
  --env-file .env.production \
  --base-url https://<loom-host> \
  --bearer-token <actor-bearer-token> \
  --admin-token <admin-token>
```

Runtime probe checks:

- request without `x-loom-admin-token` returns `403` when admin gate is enabled
- same request with valid admin token is not rejected at the admin gate

## Negative Tests

Run the focused inbound bridge hardening tests:

```bash
npm run test:inbound-bridge-hardening
```

Covered cases:

- public inbound bridge requires explicit confirmation
- weak public inbound auth policy is rejected unless explicitly confirmed
- admin-token requirement is enforced on inbound bridge requests
- auth-failure handling supports quarantine/reject controls

## Evidence Required For P0-06

- Sanitized config snapshot with inbound bridge env values.
- `npm run check:inbound-bridge` output from target environment.
- Focused negative-test output from `npm run test:inbound-bridge-hardening`.
