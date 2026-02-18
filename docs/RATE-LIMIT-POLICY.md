# LOOM Abuse And Rate-Limit Policy Runbook

This runbook is the implementation artifact for `P0-07` in `docs/PRODUCTION-READINESS.md`.

## Objective

Tune API and federation abuse/rate controls from defaults using repeatable traffic probes, then keep those tuned values under change control.

## Tuned Public-Service Baseline (Example)

Current production baseline template in `.env.production.example`:

- `LOOM_RATE_LIMIT_WINDOW_MS=60000`
- `LOOM_RATE_LIMIT_DEFAULT_MAX=1000` (default is 2000)
- `LOOM_RATE_LIMIT_SENSITIVE_MAX=160` (default is 120)
- `LOOM_IDENTITY_RATE_LIMIT_WINDOW_MS=60000`
- `LOOM_IDENTITY_RATE_LIMIT_DEFAULT_MAX=1200` (default is 2000)
- `LOOM_IDENTITY_RATE_LIMIT_SENSITIVE_MAX=240` (default is 400)
- `LOOM_FEDERATION_NODE_RATE_WINDOW_MS=60000`
- `LOOM_FEDERATION_NODE_RATE_MAX=90` (default is 120)
- `LOOM_FEDERATION_GLOBAL_RATE_WINDOW_MS=60000`
- `LOOM_FEDERATION_GLOBAL_RATE_MAX=700` (default is 1000)

Adjust these numbers based on observed workload and false-positive/false-negative behavior.

## Static Policy Validation

Validate env policy before deployment:

```bash
npm run check:rate-limits -- --env-file .env.production
```

This enforces:

- explicit rate-limit env values for public service
- sane relationships (`sensitive <= default`, `node <= global`)
- non-default tuning for primary max thresholds (unless explicitly overridden)

Optional runtime policy snapshot verification:

```bash
npm run check:rate-limits -- \
  --env-file .env.production \
  --base-url https://<loom-host> \
  --admin-token <admin-token>
```

## Traffic Probe (Evidence Run)

Run in staging/pre-prod against deployed config:

```bash
npm run probe:rate-limits -- \
  --base-url https://<loom-host> \
  --expect-default-max 1000 \
  --expect-sensitive-max 160
```

Probe behavior:

- sends a burst to a default bucket route (`/ready`)
- sends a burst to a sensitive route (`/v1/auth/challenge`)
- records where first `429` appears for each bucket
- writes evidence artifacts to `scripts/output/rate-limit-probes/<probe-id>/`

Artifacts:

- `report.json` (machine-readable measurements)
- `summary.md` (human-readable result summary)

## Evidence Required For P0-07

- Sanitized env snapshot with final tuned values.
- `npm run check:rate-limits` output from target environment.
- Probe report artifacts from `scripts/output/rate-limit-probes/*`.
