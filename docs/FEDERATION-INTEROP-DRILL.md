# LOOM Federation Interop Drill

This runbook is the implementation artifact for `P0-12` in `docs/PRODUCTION-READINESS.md`.

## Objective

Execute a repeatable federation interop drill that validates:

- challenge token flow (`/v1/federation/challenge`)
- signed delivery (`/v1/federation/deliver`)
- signed receipt verification
- nonce replay guard rejection

## Drill Command

```bash
npm run drill:federation-interop -- \
  --base-url https://<loom-host> \
  --admin-token <admin-token> \
  --remote-node-id <external-node-id>
```

Output artifacts:

- `scripts/output/federation-interop-drills/<drill-id>/report.json`
- `scripts/output/federation-interop-drills/<drill-id>/summary.md`

## Staging + Pre-Prod Matrix Command

Use the matrix runner for required environment coverage in one command:

```bash
npm run drill:federation-interop-matrix -- \
  --targets-file ops/federation/interop-targets.example.json \
  --required-targets staging,preprod
```

Target config template:

- `ops/federation/interop-targets.example.json`

Recommended token strategy:

- Store per-environment admin tokens in CI/CD secret manager.
- Reference token environment names via `admin_token_env` fields in target config.
- Do not commit token values into repository files.

Matrix output artifacts:

- `scripts/output/federation-interop-matrix/<matrix-id>/report.json`
- `scripts/output/federation-interop-matrix/<matrix-id>/summary.md`
- Per-target drill artifacts under `scripts/output/federation-interop-drills/<drill-id>/`

## How It Works

The drill script emulates an external federation node and performs:

1. Registers a trusted remote node key on target service.
2. Issues a federation challenge token via signed request.
3. Sends a signed federation delivery with challenge token.
4. Verifies the returned signed receipt against target node document keys.
5. Replays the same nonce and expects `401 SIGNATURE_INVALID`.

The evidence checker validates:

- required target names are present (default: `staging`, `preprod`)
- each required target passed
- assertions are explicitly true (`challenge_issue_passed`, `delivery_passed`, `receipt_signature_verified`, `replay_guard_passed`)
- matrix evidence freshness (`--max-age-hours`, default 168h)

Command:

```bash
npm run check:federation-interop -- \
  --required-targets staging,preprod \
  --max-age-hours 168
```

## Staging / Pre-Prod Usage

- Run this drill against each public cluster before promotion.
- Keep one drill report per release candidate.
- Include drill artifact links in release evidence.
- Prefer matrix mode to capture both required environments in one artifact.

## Evidence Required For P0-12

- Drill report from target staging/pre-prod environment.
- Confirmation that challenge + delivery + receipt verification + replay guard all passed.
- External partner node ID and test timestamp.
- `check:federation-interop` output attached to release evidence.
