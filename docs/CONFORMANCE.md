# LOOM MVN v1.1 Conformance Profile (v0.2.9)

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

- Canonical JSON for signing uses deterministic member ordering with no non-finite values and rejects lone surrogate code points. Number serialization follows RFC 8785 (JCS) Section 3.2.2.3 with explicit handling of -0, integers, and exponent formatting.
- Envelope signatures use Ed25519 with a domain-separated context prefix (`LOOM-ENVELOPE-SIG-v1\0`) prepended to canonical payload before signing. Legacy (non-prefixed) signatures are accepted during migration window when no `signature.context` field is present.
- Delegation signatures use Ed25519 with a domain-separated context prefix (`LOOM-DELEGATION-SIG-v1\0`). Legacy fallback applies during migration window.
- Envelope schema, thread DAG integrity, and delegation/capability checks are enforced at ingest.
- Envelope `from.device_id` is an optional field (1-128 character string) enabling per-device replay tracking.
- Encrypted envelope content must use a supported E2EE profile, replay metadata (`replay_counter`, `profile_commitment`), and valid wrapped-key/ciphertext fields.
- E2EE crypto path is profile-constrained (X25519 + HKDF-SHA-256 + XChaCha20-Poly1305) with deterministic ciphertext package structure checks.
- Supported encrypted profile ids include `loom-e2ee-x25519-xchacha20-v1` and `loom-e2ee-x25519-xchacha20-v2` (aliases `loom-e2ee-1`, `loom-e2ee-2`). Each profile declares security properties (`forward_secrecy`, `post_compromise_security`, `confidentiality`).
- E2EE profile `loom-e2ee-mls-1` is reserved for future MLS (RFC 9420) implementation and cannot be used for encryption or decryption until it transitions to active status.
- Thread encryption policy is enforced (encrypted threads require encrypted envelopes with matching profile and epoch).
- Encrypted ingest supports configurable replay protection: `strict` mode enforces monotonic `replay_counter` increase per sender per epoch; `sliding_window` mode (default) uses a 64-entry sliding window allowing out-of-order delivery within the window. Replay state is keyed by `senderIdentity:deviceId`.
- Thread size limits are enforced at ingest: `max_envelopes_per_thread` (default 10000) and `max_pending_parents` (default 500). Limits are configurable at store level and overridable per-ingest via context.
- `encryption.epoch@v1` and `encryption.rotate@v1` enforce wrapped-key distribution covering all active thread participants.
- Capability tokens support optional Proof-of-Possession (PoP) hardening via `cnf.key_id` binding. When present, PoP proof (`LOOM-CAPABILITY-POP-v1\0` context-prefixed signature) is required and verified for sensitive intents (`delegation.revoked@v1`, `encryption.epoch@v1`, `encryption.rotate@v1`, `capability.revoked@v1`).
- Delegation chain verification enforces `created_at` presence (ISO-8601), rejects `created_at` more than 5 minutes in the future (configurable via `maxCreatedAtFutureSkewMs`), enforces maximum chain depth (default 10, configurable via `maxChainLength`), and verifies root delegator is not an agent type when `enforceRootDelegatorType` is enabled.
- Federation delivery requires signed requests and nonce/timestamp replay checks.
- Federation protocol capabilities are published for negotiation (`/v1/protocol/capabilities`) including trust-anchor posture and supported encrypted profiles.
- Email outbox supports per-recipient DSN-style status updates via `POST /v1/email/outbox/{id}/dsn`.
- Outbound MIME rendering maps LOOM envelope attachments (blob-backed) into SMTP relay attachments.
- Wire SMTP advertises and accepts `SMTPUTF8`/`8BITMIME` ESMTP parameters for gateway-compatible submission flows.
- Wire IMAP supports boolean `SEARCH`/`UID SEARCH` composition (`OR`, `NOT`, grouped criteria), `APPEND` literal continuation mode, and `UID THREAD`/`UID SORT` compatibility commands.
- Inbound content filtering enforces profile-aware decisions (`strict|balanced|agent`) with configurable thresholds and profile-labeled decision counters.
- An informational JSON Schema (draft 2020-12) is published at `src/protocol/schemas/envelope-v1.1.schema.json`. In-code `validateEnvelopeShape` remains the authoritative validation path.

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
- `test/fixtures/conformance/jcs-number-serialization-v1.json`
  - Publishable RFC 8785 JCS number serialization vectors (zero, -0, pi, subnormals, scientific notation).
- `test/fixtures/conformance/signature-context-v1.json`
  - Publishable signature context prefix vectors with known key pair, envelope, and expected context-prefixed signature.
- `test/fixtures/conformance/delegation-chain-v1.json`
  - Publishable delegation chain negative vectors (missing `created_at`, future skew, expired link, chain depth exceeded).
- `test/fixtures/conformance/replay-sliding-window-v1.json`
  - Publishable sliding window replay vectors (sequential, out-of-order, duplicate, too-old, multi-device).
- `test/fixtures/conformance/capability-pop-v1.json`
  - Publishable capability Proof-of-Possession vectors (valid PoP, wrong key, wrong capability ID).
- `test/conformance_fixture_vectors.test.js`
  - Validates fixture vectors as locked interoperability contracts.
  - Includes JSON Schema divergence guard (verifies schema required/optional fields match `validateEnvelopeShape` behavior).
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
- `test/thread_dag_scalability.test.js`
  - Thread DAG performance bounds (5000-envelope linear chain, wide fan-out, canonical ordering stability, thread size limits).
- `test/replay_sliding_window.test.js`
  - Sliding window replay tracker unit tests (sequential, out-of-order, duplicate, too-old, window advance, multi-device).
- `test/store_integration.test.js`
  - Store-level integration tests for sliding window replay, strict replay, thread limits, and capability PoP verification.
- `test/server.test.js`
  - API-level protocol routes, DSN outbox update behavior, and admin control surfaces.
- `test/wire_gateway.test.js`
  - Wire SMTP/IMAP behavior, STARTTLS, parser hardening, SMTPUTF8 support, SEARCH boolean grammar, UID SORT/THREAD, and APPEND literals.

Run all vectors:

```bash
npm test
```
