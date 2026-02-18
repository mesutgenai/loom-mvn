# Changelog

All notable changes to this project are documented in this file.

## Unreleased

Governance and trust-signal alignment updates:

- Added contribution/governance docs: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`.
- Added lifecycle policy docs: `docs/STABILITY.md`, `docs/RELEASE-POLICY.md`, `docs/OPEN-SOURCE-STRATEGY.md`.
- Added GitHub issue templates (`bug report`, `feature request`) and issue config routing users to support/security resources.
- Aligned docs with current release line (`v0.2.6`) in `README.md` and `docs/CONFORMANCE.md`.
- Updated `SECURITY.md` support scope to `0.2.x` + `main` and documented target fix SLAs by severity.

## v0.2.6 - 2026-02-17

Production hardening, memory safety, and operational resilience:

### Critical Fixes
- **Memory leak sweep**: Added periodic `runMaintenanceSweep()` that evicts expired
  access tokens, refresh tokens, auth challenges, stale rate-limit windows, and
  caps the `consumedPortableCapabilityIds` / `revokedDelegationIds` Sets (FIFO).
  Also delegates to all 7 existing cleanup methods. Runs every 60 s by default
  (`LOOM_MAINTENANCE_SWEEP_INTERVAL_MS`).
- **Worker exponential backoff**: All three outbox workers (federation, email,
  webhook) now apply exponential backoff on batch-level failures (10 s → 300 s
  cap) instead of retrying every tick indefinitely.
- **Atomic file persistence**: `persistState()` now writes to a `.tmp` file,
  calls `fsync`, then renames — preventing half-written state on crash.

### High-Risk Fixes
- **Resource limits**: Configurable caps for local identities (10 k default),
  remote identities (50 k), delegations per identity (500), and total
  delegations (100 k). Enforced in `registerIdentity()` and
  `createDelegation()` with `RESOURCE_LIMIT` errors.
  New env vars: `LOOM_MAX_LOCAL_IDENTITIES`, `LOOM_MAX_REMOTE_IDENTITIES`,
  `LOOM_MAX_DELEGATIONS_PER_IDENTITY`, `LOOM_MAX_DELEGATIONS_TOTAL`,
  `LOOM_CONSUMED_CAPABILITY_MAX_ENTRIES`, `LOOM_REVOKED_DELEGATION_MAX_ENTRIES`.

### Security
- **Response headers**: Every HTTP response now includes `x-content-type-options:
  nosniff`, `x-frame-options: DENY`, `cache-control: no-store`.
- **HTTP server timeouts**: `headersTimeout` (30 s), `requestTimeout` (2 min),
  `keepAliveTimeout` (65 s) to mitigate slow-loris and idle-connection attacks.
- **Global error handlers**: `unhandledRejection` logs and continues;
  `uncaughtException` logs and triggers graceful shutdown.

### Maintenance
- **Helper deduplication**: Consolidated `parseBoolean`, `parsePositiveInt`,
  `parsePositiveNumber`, and `parseHostAllowlist` into a single shared module
  (`src/node/env.js`), replacing 6+ duplicated copies across the codebase.
- **ULID monotonicity**: `generateUlid()` now increments the random portion
  within the same millisecond instead of re-seeding, guaranteeing strict
  ordering for same-ms calls.
- **CI enhancements**: Added `--experimental-test-coverage`, a helper
  duplication guard, and an unused-export check to the GitHub Actions workflow.

### Tests
- Added 16 new tests covering maintenance sweep, backoff formula, atomic
  persistence, identity limits, and delegation limits (136 total).

---

## v0.2.5 - 2026-02-17

Security and interoperability updates:

- Added DSN-style per-recipient outbox status ingestion:
  - `POST /v1/email/outbox/{id}/dsn`
  - Recipient-level status merge with validation against queued recipients.
- Added distributed outbox claim leasing for worker coordination:
  - Email, federation, and webhook processors now use claim/release hooks.
  - PostgreSQL adapter now persists claims in `loom_outbox_claims`.
- Hardened wire SMTP behavior for explicit extension handling:
  - `SMTPUTF8` parameters are rejected with `504 5.5.4`.
- Improved outbound email bridge rendering:
  - LOOM blob-backed envelope attachments are mapped to relay MIME attachments.
- Added conformance vectors and expanded test coverage:
  - New `test/conformance_vectors.test.js`.
  - Added DSN, claim-lock, attachment mapping, and SMTPUTF8 tests.
- Repository governance and delivery hardening:
  - Added `LICENSE` (Apache-2.0).
  - Added GitHub Actions CI workflow at `.github/workflows/ci.yml`.
  - Added `docs/CONFORMANCE.md`.
