# LOOM MVN v1.1 Conformance Profile (v0.2.6)

This document defines the current conformance surface implemented by this MVN and the test vectors that gate protocol behavior.

## Scope

This profile is for API and protocol behaviors implemented in this repository (`src/`). It is not a full Internet email MTA profile.

Release and governance references:

- Changelog: `CHANGELOG.md`
- CI workflow: `.github/workflows/ci.yml`
- License: `LICENSE`
- Stability policy: `docs/STABILITY.md`
- Release policy: `docs/RELEASE-POLICY.md`

## Normative Surface

- Canonical JSON for signing uses deterministic member ordering with no non-finite values and rejects lone surrogate code points.
- Envelope signatures use Ed25519 and are verified on ingest.
- Envelope schema, thread DAG integrity, and delegation/capability checks are enforced at ingest.
- Federation delivery requires signed requests and nonce/timestamp replay checks.
- Email outbox supports per-recipient DSN-style status updates via `POST /v1/email/outbox/{id}/dsn`.
- Outbound MIME rendering maps LOOM envelope attachments (blob-backed) into SMTP relay attachments.

## Out of Scope (Current)

- SMTPUTF8 wire submission profile (wire SMTP returns `504 5.5.4 SMTPUTF8 not supported`).
- Full enterprise IMAP extension parity.
- Native inbound SPF/DKIM/DMARC verification in MVN (expected upstream MTA responsibility).

## Conformance Vectors

The following tests are the baseline vectors and regression checks:

- `test/conformance_vectors.test.js`
  - Canonical JSON golden-output vectors.
  - Canonical JSON lone-surrogate rejection vector.
  - Envelope canonicalization/signature stability vector.
- `test/protocol.test.js`
  - Envelope validation/signature/delegation/capability/thread semantics.
- `test/server.test.js`
  - API-level protocol routes and DSN outbox update behavior.
- `test/wire_gateway.test.js`
  - Wire SMTP/IMAP behavior, STARTTLS, parser hardening, SMTPUTF8 rejection.

Run all vectors:

```bash
npm test
```
