# Changelog

All notable changes to this project are documented in this file.

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
  - Added `LICENSE` (MIT).
  - Added GitHub Actions CI workflow at `.github/workflows/ci.yml`.
  - Added `docs/CONFORMANCE.md`.

