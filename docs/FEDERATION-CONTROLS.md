# LOOM Federation Outbound Controls Runbook

This runbook is the implementation artifact for `P0-05` in `docs/PRODUCTION-READINESS.md`.

## Objective

Ensure outbound federation/bootstrap/remote-identity/webhook traffic is constrained to explicit allowlists and that trusted federation nodes do not rely on insecure transport flags.

## Required Environment Controls

- `LOOM_FEDERATION_HOST_ALLOWLIST`
- `LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST`
- `LOOM_WEBHOOK_HOST_ALLOWLIST`
- `LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST` (or federation allowlist fallback if remote identity resolve is enabled)
- `LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=false`

For hardened public deployment, open outbound mode is not allowed.

## Static Policy Validation

Run against production env configuration:

```bash
npm run check:federation -- --env-file .env.production
```

This validates:

- allowlists are non-empty where required
- entries are hostname/suffix patterns (not raw URLs)
- no broad wildcard patterns
- open outbound-host mode is disabled

## Runtime Node Audit

To audit registered federation nodes on a running service, provide:

- an actor bearer token with access to `/v1/federation/nodes`
- target base URL

```bash
npm run check:federation -- \
  --env-file .env.production \
  --base-url https://<loom-host> \
  --bearer-token <actor-bearer-token>
```

Runtime checks enforce:

- no `allow_insecure_http=true` or `allow_private_network=true` on trusted nodes
- `deliver_url` and `identity_resolve_url` use `https`
- node URL hosts fit configured allowlists

## Evidence Required For P0-05

- Output from static policy validation in target environment.
- Output from runtime node audit for each public cluster.
- Change-control links for allowlist updates.
