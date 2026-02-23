# LOOM Configuration Profiles

Status: Draft (implementation profile; reviewed for v0.4.2)

## Purpose

Reduce environment-variable complexity by bundling safe defaults behind an explicit profile selector.

Set profile with:

- `LOOM_CONFIG_PROFILE=secure_public`

## Available Profiles

### `secure_public`

Target:

- internet-facing deployments that need fail-closed defaults

Default posture applied when values are not otherwise set:

- `LOOM_PUBLIC_SERVICE=true`
- `LOOM_REQUIRE_HTTPS_FROM_PROXY=true`
- `LOOM_REQUIRE_TLS_PROXY=true`
- `LOOM_REQUIRE_EXTERNAL_SIGNING_KEYS=true`
- `LOOM_REQUIRE_DISTINCT_FEDERATION_SIGNING_KEY=true`
- `LOOM_REQUIRE_PORTABLE_THREAD_OP_CAPABILITY=true`
- `LOOM_IDENTITY_REQUIRE_PROOF=true`
- `LOOM_FEDERATION_REQUIRE_SIGNED_RECEIPTS=true`
- `LOOM_FEDERATION_REQUIRE_PROTOCOL_CAPABILITIES=true`
- `LOOM_FEDERATION_REQUIRE_E2EE_PROFILE_OVERLAP=true`
- `LOOM_FEDERATION_REQUIRE_TRUST_MODE_PARITY=true`
- `LOOM_FEDERATION_TRUST_MODE=public_dns_webpki`
- `LOOM_FEDERATION_TRUST_FAIL_CLOSED=true`
- `LOOM_FEDERATION_TRUST_REQUIRE_DNSSEC=true`
- `LOOM_FEDERATION_TRUST_REQUIRE_TRANSPARENCY=true`
- `LOOM_FEDERATION_TRUST_DNS_RESOLVER_MODE=dnssec_doh`
- `LOOM_BRIDGE_EMAIL_INBOUND_ENABLED=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_PUBLIC_CONFIRMED=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_ADMIN_TOKEN=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_AUTH_RESULTS=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_DMARC_PASS=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_REJECT_ON_AUTH_FAILURE=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_QUARANTINE_ON_AUTH_FAILURE=true`
- `LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_PAYLOAD_AUTH_RESULTS=false`
- `LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_AUTOMATIC_ACTUATION=false`
- `LOOM_INBOUND_CONTENT_FILTER_ENABLED=true`
- `LOOM_INBOUND_CONTENT_FILTER_REJECT_MALWARE=true`
- `LOOM_INBOUND_CONTENT_FILTER_PROFILE_DEFAULT=balanced`
- `LOOM_INBOUND_CONTENT_FILTER_PROFILE_BRIDGE=strict`
- `LOOM_INBOUND_CONTENT_FILTER_PROFILE_FEDERATION=agent`
- `LOOM_METRICS_PUBLIC=false`
- `LOOM_DEMO_PUBLIC_READS=false`
- `LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=false`

Profile interaction notes:

- `secure_public` does not set `LOOM_PROTOCOL_PROFILE`; runtime profile remains `loom-v1.1-full` unless explicitly overridden.
- To run core-only mode with secure defaults, set both:
  - `LOOM_CONFIG_PROFILE=secure_public`
  - `LOOM_PROTOCOL_PROFILE=loom-core-1`
- Extension toggles (`LOOM_EXTENSION_*`) and route toggles remain subordinate to `LOOM_PROTOCOL_PROFILE`; in `loom-core-1`, extension surfaces remain disabled even if toggles are set to `true`.
- Disabled extension-route diagnostics default to redacted on public service (`LOOM_EXTENSION_DISABLE_ERROR_DIAGNOSTICS=false` by default when `LOOM_PUBLIC_SERVICE=true`).

## Explicit Values Still Required

Profiles do not inject secrets or deployment-specific network values. You still must provide:

- `LOOM_ADMIN_TOKEN`
- `LOOM_NODE_ID`
- `LOOM_SYSTEM_SIGNING_KEY_ID`
- `LOOM_SYSTEM_SIGNING_PRIVATE_KEY_PEM`
- `LOOM_NODE_SIGNING_KEY_ID`
- `LOOM_NODE_SIGNING_PRIVATE_KEY_PEM`
- `LOOM_PG_URL` (for durable production state)
- `LOOM_TLS_PROXY_CONFIRMED=true` (unless native TLS is enabled)
- proxy trust configuration (`LOOM_TRUST_PROXY=true` or `LOOM_TRUST_PROXY_ALLOWLIST`)
- outbound allowlists (`LOOM_FEDERATION_HOST_ALLOWLIST`, `LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST`, `LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST`, `LOOM_WEBHOOK_HOST_ALLOWLIST`)

## Example

Use:

- `.env.secure-public.example`

Validation commands:

```bash
npm run check:prod-env -- --env-file .env.secure-public.example
npm run check:inbound-bridge -- --env-file .env.secure-public.example
```
