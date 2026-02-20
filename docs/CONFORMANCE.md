# LOOM MVN v1.1 Conformance Profile (v0.2.7)

This document defines the current conformance surface implemented by this MVN and the test vectors that gate protocol behavior.

## Scope

This profile is for API and protocol behaviors implemented in this repository (`src/`). It is not a full Internet email MTA profile.

Release and governance references:

- Changelog: `CHANGELOG.md`
- CI workflow: `.github/workflows/ci.yml`
- License: `LICENSE`
- Stability policy: `docs/STABILITY.md`
- Release policy: `docs/RELEASE-POLICY.md`
- Compliance controls package: `docs/COMPLIANCE-CONTROLS.md`
- IMAP compatibility matrix: `docs/IMAP-COMPATIBILITY-MATRIX.md`

## Normative Surface

- Canonical JSON for signing uses deterministic member ordering with no non-finite values and rejects lone surrogate code points.
- Envelope signatures use Ed25519 and are verified on ingest.
- Envelope schema, thread DAG integrity, and delegation/capability checks are enforced at ingest.
- Encrypted envelope content must use a supported E2EE profile, replay metadata (`replay_counter`, `profile_commitment`), and valid wrapped-key/ciphertext fields.
- E2EE crypto path is profile-constrained (X25519 + HKDF-SHA-256 + XChaCha20-Poly1305) with deterministic ciphertext package structure checks.
- Supported encrypted profile ids include `loom-e2ee-x25519-xchacha20-v1` and `loom-e2ee-x25519-xchacha20-v2` (aliases `loom-e2ee-1`, `loom-e2ee-2`).
- Thread encryption policy is enforced (encrypted threads require encrypted envelopes with matching profile and epoch).
- Encrypted ingest enforces sender replay monotonicity and epoch reset rules (`replay_counter` increase in-epoch; reset on epoch advance).
- `encryption.epoch@v1` and `encryption.rotate@v1` enforce wrapped-key distribution covering all active thread participants.
- Federation delivery requires signed requests and nonce/timestamp replay checks.
- Federation protocol capabilities are published for negotiation (`/v1/protocol/capabilities`) including trust-anchor posture and supported encrypted profiles.
- Email outbox supports per-recipient DSN-style status updates via `POST /v1/email/outbox/{id}/dsn`.
- Outbound MIME rendering maps LOOM envelope attachments (blob-backed) into SMTP relay attachments.
- Wire SMTP advertises and accepts `SMTPUTF8`/`8BITMIME` ESMTP parameters for gateway-compatible submission flows.
- Wire IMAP supports boolean `SEARCH`/`UID SEARCH` composition (`OR`, `NOT`, grouped criteria), `APPEND` literal continuation mode, and `UID THREAD`/`UID SORT` compatibility commands.
- Inbound content filtering enforces profile-aware decisions (`strict|balanced|agent`) with configurable thresholds and profile-labeled decision counters.

## Out of Scope (Current)

- Full EAI identity mapping parity (for example arbitrary UTF-8 mailbox local-parts that cannot map to valid LOOM identities).
- Full enterprise IMAP extension parity.
- Native inbound SPF/DKIM/DMARC verification in MVN (expected upstream MTA responsibility).

## Conformance Vectors

The following tests are the baseline vectors and regression checks:

- `test/fixtures/conformance/canonical-json-v1.json`
  - Publishable canonical JSON vectors for cross-language implementations.
- `test/fixtures/conformance/envelope-signature-ed25519-v1.json`
  - Publishable canonical envelope signature vector with fixed Ed25519 key material.
- `test/fixtures/conformance/e2ee-profile-v1.json`
  - Publishable E2EE profile vectors for encrypted content shape and profile rules.
- `test/fixtures/conformance/e2ee-epoch-params-v1.json`
  - Publishable E2EE epoch-operation vectors for wrapped-key distribution coverage.
- `test/fixtures/conformance/e2ee-crypto-x25519-xchacha-v1.json`
  - Publishable deterministic E2EE encrypt/decrypt vector for profile crypto interoperability.
- `test/fixtures/conformance/e2ee-attachment-crypto-x25519-xchacha-v1.json`
  - Publishable deterministic attachment-level E2EE encrypt/decrypt vector for profile crypto interoperability.
- `test/conformance_fixture_vectors.test.js`
  - Validates fixture vectors as locked interoperability contracts.
- `test/conformance_vectors.test.js`
  - Canonical JSON golden-output vectors.
  - Canonical JSON lone-surrogate rejection vector.
  - Envelope canonicalization/signature stability vector.
- `test/protocol.test.js`
  - Envelope validation/signature/delegation/capability/thread semantics, federation trust posture controls, and inbound content-filter policy behavior.
- `test/trust_and_key_lifecycle.test.js`
  - Trust-anchor authority resolution and signing key lifecycle state semantics.
- `test/e2ee_profiles.test.js`
  - E2EE profile validation, wrapped-key constraints, replay metadata, and encrypted thread policy enforcement.
- `test/content_filter_corpus.test.js`
  - Content-filter corpus calibration vectors (agent-benign vs malicious distributions).
- `test/server.test.js`
  - API-level protocol routes, DSN outbox update behavior, and admin control surfaces.
- `test/wire_gateway.test.js`
  - Wire SMTP/IMAP behavior, STARTTLS, parser hardening, SMTPUTF8 support, SEARCH boolean grammar, UID SORT/THREAD, and APPEND literals.

Run all vectors:

```bash
npm test
```
