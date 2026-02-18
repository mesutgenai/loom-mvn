# LOOM Deployment Baseline (Public Service)

This runbook is the baseline for `P0-01` in `docs/PRODUCTION-READINESS.md`.

## Objective

Deploy LOOM as an internet-facing service with enforced TLS and startup safety guards.

## Baseline Controls

1. TLS and ingress:
- Terminate TLS 1.3 at a trusted reverse proxy, or use LOOM native TLS mode.
- Use HTTP/2 at the edge where supported.
- Forward `X-Forwarded-Proto=https` and client IP headers from trusted ingress only.

2. Public-service safeguards:
- `LOOM_PUBLIC_SERVICE=true`
- `LOOM_REQUIRE_TLS_PROXY=true` and `LOOM_TLS_PROXY_CONFIRMED=true` (unless native TLS is enabled)
- `LOOM_REQUIRE_HTTPS_FROM_PROXY=true` for proxy-terminated TLS
- `LOOM_ADMIN_TOKEN` set

3. Trusted proxy configuration:
- Set either `LOOM_TRUST_PROXY=true` or a strict `LOOM_TRUST_PROXY_ALLOWLIST`.
- Prefer `LOOM_TRUST_PROXY_ALLOWLIST` in production.

4. Outbound safety:
- Configure host allowlists for federation/bootstrap/remote-identity/webhooks.
- Do not enable `LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND` unless explicitly required and approved.

## Environment Preparation

1. Start from:
- `.env.production.example`

2. Replace all placeholders with deployment-specific values and secrets from your secret manager.

3. Validate env before deployment:

```bash
npm run check:prod-env -- --env-file .env.production
```

## Startup Validation

After deployment, capture these checks as evidence:

```bash
curl -sS https://<loom-host>/ready
curl -sS https://<loom-host>/v1/admin/status -H "x-loom-admin-token: $LOOM_ADMIN_TOKEN"
```

Expected:
- `/ready` returns healthy status.
- Startup logs show no public-service guard rejections.

## Evidence for P0-01

- Resolved deployment config (sanitized).
- Env validator output from `npm run check:prod-env`.
- Startup logs from target environment.
- `/ready` and `/v1/admin/status` results.
