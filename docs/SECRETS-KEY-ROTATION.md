# LOOM Secrets And Key Rotation Runbook

This runbook is the implementation artifact for `P0-02` in `docs/PRODUCTION-READINESS.md`.

## Secret Classes

Treat these as production secrets:

- `LOOM_ADMIN_TOKEN`
- `LOOM_NODE_SIGNING_PRIVATE_KEY_PEM`
- `LOOM_AUDIT_HMAC_KEY` (if enabled)
- SMTP auth secrets (`LOOM_SMTP_USER`, `LOOM_SMTP_PASS`, provider credentials)
- Database credentials in `LOOM_PG_URL`

Never commit real values to this repository.

## Storage Requirements

- Store all production secrets in a secret manager or KMS-backed vault.
- Inject at runtime (environment, mounted file, or sidecar), not in source.
- Restrict access by least privilege (service identity only).
- Audit access to secret material.

## Rotation Policy

- `LOOM_ADMIN_TOKEN`: rotate every 90 days or immediately after suspected exposure.
- `LOOM_NODE_SIGNING_PRIVATE_KEY_PEM`: rotate every 180 days or immediately after suspected exposure.
- SMTP and DB credentials: rotate per provider policy (recommended every 90 days).
- Emergency rotation: complete within 24 hours for confirmed compromise.

## Node Signing Key Rotation Procedure

1. Generate a new signing key pair in your secure key workflow.
2. Assign a new `LOOM_NODE_SIGNING_KEY_ID`.
3. Update secret manager entry for `LOOM_NODE_SIGNING_PRIVATE_KEY_PEM`.
4. Roll out to staging and validate signed federation delivery and receipts.
5. Coordinate trust updates with federation peers (new key registration/trust).
6. Roll out to production using controlled deployment strategy.
7. Revoke/retire old key material after partner cutover is complete.

## Admin Token Rotation Procedure

1. Generate a new high-entropy token.
2. Update secret manager.
3. Roll restart all nodes/workers that consume the token.
4. Validate admin endpoints with the new token.
5. Invalidate old token and remove from operator tooling.

## Repository Guardrails

Run before merge and in CI:

```bash
npm run check:secrets
```

The scanner blocks:

- Private key PEM blocks in tracked files (except test fixtures).
- Tracked `.env` files (except `*.example`).
- Obvious token leaks (`LOOM_ADMIN_TOKEN=...`, inline admin header values, common key/token formats).

## Evidence Required For P0-02

- Secret inventory and owner mapping.
- Rotation cadence policy and last-rotation timestamps.
- Staging validation logs for latest key/token rotation.
- CI logs showing `npm run check:secrets` passing.
