# LOOM Federation Outbound Controls Runbook

This runbook is the implementation artifact for `P0-05` in `docs/PRODUCTION-READINESS.md`.

## Objective

Ensure outbound federation/bootstrap/remote-identity/webhook traffic is constrained to explicit allowlists, trusted federation nodes do not rely on insecure transport flags, and agent-facing trust/capability negotiation remains fail-closed.

## Required Environment Controls

- `LOOM_FEDERATION_HOST_ALLOWLIST`
- `LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST`
- `LOOM_WEBHOOK_HOST_ALLOWLIST`
- `LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST` (or federation allowlist fallback if remote identity resolve is enabled)
- `LOOM_FEDERATION_TRUST_ANCHORS` (recommended for curated federation authority bindings)
- `LOOM_FEDERATION_TRUST_MODE` (`public_dns_webpki` for internet-grade trust)
- `LOOM_FEDERATION_TRUST_FAIL_CLOSED=true`
- `LOOM_FEDERATION_TRUST_REQUIRE_DNSSEC=true`
- `LOOM_FEDERATION_TRUST_DNS_RESOLVER_MODE=dnssec_doh` (or custom resolver integration)
- `LOOM_FEDERATION_TRUST_DNSSEC_DOH_URL`
- `LOOM_FEDERATION_TRUST_DNSSEC_DOH_TIMEOUT_MS`
- `LOOM_FEDERATION_TRUST_DNSSEC_DOH_MAX_RESPONSE_BYTES`
- `LOOM_FEDERATION_TRUST_TRANSPARENCY_MODE=local_append_only`
- `LOOM_FEDERATION_TRUST_REQUIRE_TRANSPARENCY=true`
- `LOOM_FEDERATION_TRUST_MAX_CLOCK_SKEW_MS`
- `LOOM_FEDERATION_TRUST_KEYSET_MAX_AGE_MS`
- `LOOM_FEDERATION_TRUST_KEYSET_PUBLISH_TTL_MS`
- `LOOM_FEDERATION_TRUST_DNS_TXT_LABEL` (default `_loomfed`)
- `LOOM_FEDERATION_TRUST_LOCAL_EPOCH`
- `LOOM_FEDERATION_TRUST_KEYSET_VERSION`
- `LOOM_FEDERATION_REVOKED_KEY_IDS` (recommended when retiring node keys)
- `LOOM_REQUIRE_EXTERNAL_SIGNING_KEYS=true`
- `LOOM_SYSTEM_SIGNING_KEY_ID`
- `LOOM_SYSTEM_SIGNING_PRIVATE_KEY_PEM`
- `LOOM_NODE_SIGNING_PRIVATE_KEY_PEM`
- `LOOM_REQUIRE_DISTINCT_FEDERATION_SIGNING_KEY=true` (recommended for role separation)
- `LOOM_FEDERATION_REQUIRE_PROTOCOL_CAPABILITIES=true` (recommended for strict agent federation)
- `LOOM_FEDERATION_REQUIRE_E2EE_PROFILE_OVERLAP=true` (recommended for encrypted federation)
- `LOOM_FEDERATION_REQUIRE_TRUST_MODE_PARITY=true` (recommended for trust-policy symmetry)
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
- trust mode is internet-grade + fail-closed
- DNSSEC requirements are enabled for internet trust mode
- external signing key requirements are enforced on public service
- trust revalidation worker controls are configured

## Runtime Node Audit

To audit registered federation nodes on a running service, provide:

- an actor bearer token with access to `/v1/federation/nodes`
- target base URL
- admin token (recommended) to verify DNS trust publication via `/v1/federation/trust/verify-dns`

```bash
npm run check:federation -- \
  --env-file .env.production \
  --base-url https://<loom-host> \
  --bearer-token <actor-bearer-token> \
  --admin-token <admin-token>
```

Runtime checks enforce:

- no `allow_insecure_http=true` or `allow_private_network=true` on trusted nodes
- `deliver_url` and `identity_resolve_url` use `https`
- node URL hosts fit configured allowlists
- published federation DNS TXT trust anchor matches local signed trust descriptor (when admin token is provided)
- DNS verification is DNSSEC-validated when DNSSEC is required
- periodic federation trust revalidation worker is enabled and healthy (`runtime.federation_trust_revalidation_worker`)

## Protocol Capability Negotiation

LOOM publishes federation negotiation posture at:

- `GET /v1/protocol/capabilities`
- `GET /.well-known/loom-capabilities.json` (well-known mirror)

This includes:

- supported E2EE profiles (for overlap checks)
- trust-anchor mode + supported trust-anchor modes
- trust fail-closed posture
- DNSSEC and transparency requirements for trust-anchor publication

Use this during federation onboarding to verify profile overlap and trust-mode parity before enabling strict federation policy gates.

Strict negotiation gates:

- `LOOM_FEDERATION_REQUIRE_PROTOCOL_CAPABILITIES=true` blocks peers that do not publish capabilities.
- `LOOM_FEDERATION_REQUIRE_E2EE_PROFILE_OVERLAP=true` blocks peers without encrypted-profile overlap.
- `LOOM_FEDERATION_REQUIRE_TRUST_MODE_PARITY=true` blocks peers that cannot negotiate local trust-anchor mode.

## DNS Trust Anchor Publication

LOOM now exposes publish-ready trust descriptors:

- `GET /.well-known/loom-keyset.json`
- `GET /.well-known/loom-revocations.json`
- `GET /.well-known/loom-trust.json`
- `GET /.well-known/loom-trust.txt`

To generate the exact TXT value to publish:

```bash
curl -fsS https://<loom-host>/.well-known/loom-trust.txt
```

Publish that value as a TXT record at:

`<LOOM_FEDERATION_TRUST_DNS_TXT_LABEL>.<LOOM_NODE_ID>`

Example: `_loomfed.loom-node.example.com`

## Trust Rotation Runbook

Use admin-token protected trust endpoints:

- `GET /v1/federation/trust` to inspect current trust posture.
- `POST /v1/federation/trust` to rotate trust metadata.
- `POST /v1/federation/nodes/{node_id}/revalidate` to refresh remote trust state for a known peer.
- `POST /v1/federation/nodes/revalidate` to refresh multiple known peers in one operation.

Example epoch/version bump:

```bash
curl -fsS -X POST https://<loom-host>/v1/federation/trust \
  -H "content-type: application/json" \
  -H "x-loom-admin-token: <admin-token>" \
  -d '{"bump_trust_epoch":true,"keyset_version":1}'
```

Example key revocation publication:

```bash
curl -fsS -X POST https://<loom-host>/v1/federation/trust \
  -H "content-type: application/json" \
  -H "x-loom-admin-token: <admin-token>" \
  -d '{"append_revoked_key_ids":["k_node_sign_retired_2026_01"],"bump_keyset_version":true}'
```

Example trust revalidation for all known peers in `public_dns_webpki` mode:

```bash
curl -fsS -X POST https://<loom-host>/v1/federation/nodes/revalidate \
  -H "content-type: application/json" \
  -H "authorization: Bearer <actor-bearer-token>" \
  -d '{"limit":100}'
```

## Automatic Revalidation Worker

Enable periodic trust refresh so agents do not depend on manual revalidation calls:

- `LOOM_FEDERATION_TRUST_REVALIDATE_INTERVAL_MS` (default `900000`; set `0` to disable)
- `LOOM_FEDERATION_TRUST_REVALIDATE_BATCH_LIMIT` (default `100`, max `1000`)
- `LOOM_FEDERATION_TRUST_REVALIDATE_INCLUDE_NON_PUBLIC_MODES` (default `false`)
- `LOOM_FEDERATION_TRUST_REVALIDATE_TIMEOUT_MS` (default `5000`)
- `LOOM_FEDERATION_TRUST_REVALIDATE_MAX_RESPONSE_BYTES` (default `262144`)

Runtime visibility:

- `GET /v1/admin/status` -> `runtime.federation_trust_revalidation_worker`
- `GET /metrics` -> `loom_federation_trust_revalidation_worker_*`

End-to-end trust freshness drill (ephemeral local+remote nodes):

```bash
npm run drill:federation-trust
```

## Evidence Required For P0-05

- Output from static policy validation in target environment.
- Output from runtime node audit for each public cluster.
- Change-control links for allowlist updates.
- Capability-negotiation policy snapshot (`LOOM_FEDERATION_REQUIRE_*`) and onboarding decision record.
