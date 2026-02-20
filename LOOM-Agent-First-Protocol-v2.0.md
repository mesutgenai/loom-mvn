# LOOM Agent-First Protocol v2.0 (Ground-Up Reboot Draft)

Status: Draft  
Date: 2026-02-20  
Supersedes planning assumptions in `LOOM-Protocol-Spec-v1.1.md` for future-major work.

## 1. Purpose

This document defines the structural reboot required to make LOOM a true agent-first messaging protocol, not just an email-adjacent transport with bridges.

The target is a protocol that is:

- deterministic for machine actors
- cryptographically verifiable end to end
- resilient under hostile federation conditions
- explicitly interoperable through test vectors and profiles
- safe to bridge with legacy email without inheriting email ambiguity as source of truth

## 2. Hard Requirements (Non-Negotiable)

1. Identity trust anchors must be explicit and auditable.
2. Key lifecycle must include activation, rotation, and revocation semantics.
3. Canonicalization and signature behavior must be lockstep across implementations.
4. End-to-end encryption profiles must be first-class protocol features.
5. Gateway and bridge boundaries must be policy-isolated and fail closed.
6. Abuse resistance must be protocol-native (not only deployment guidance).

## 3. Layered Architecture

### Layer A: Identity and Trust Authority

- Identity namespace remains `loom://local@authority`.
- Authority resolution is explicit, not assumed.
- Default rule: `identity authority == sender node authority`.
- Curated federation override rule: configurable trust-anchor mapping.

Normative requirement:

- Nodes MUST reject federated envelopes when sender node is not authorized for the claimed identity authority.
- Trust-anchor decisions MUST be explainable in machine-readable error details.

### Layer B: Key Lifecycle and Signing

- Signing keys carry lifecycle metadata:
  - `status`: `active | pending | retired | revoked`
  - `not_before`
  - `not_after`
  - `revoked_at`
- Nodes MUST treat revoked/expired/inactive keys as non-verifiable keys.

### Layer C: Envelope Semantics

- Canonical JSON remains the signing input baseline.
- Conformance vectors become normative artifacts, not only test code.
- Envelope verification rules are stable contracts and versioned by vector set.

### Layer D: E2EE Profiles

- Encryption is profile-based and negotiated per thread.
- A profile defines key agreement, content wrapping, attachment wrapping, replay counters, and forward secrecy expectations.
- Unprofiled `encrypted=true` payloads are non-conformant in v2.0.

### Layer E: Federation Transport

- Signed request wrappers with timestamp + nonce remain mandatory.
- Receipts are signed and lifecycle-validated against trusted node keys.
- Retry semantics are explicit and idempotency-aware.

### Layer F: Gateway/Bridge Boundary

- SMTP/IMAP and email relay become adapters only.
- Email auth evidence (SPF/DKIM/DMARC) is treated as input evidence, not protocol truth.
- Bridge ingress is policy-scoped and may quarantine/reject independently from LOOM-native traffic.

## 4. Structural Refactor Plan

The codebase will move from a monolithic store to explicit modules:

1. `protocol-core`
2. `trust-authority`
3. `key-lifecycle`
4. `federation-transport`
5. `mail-bridge-adapters`
6. `policy-engine`

Immediate groundwork in this repository:

- Added trust-anchor primitives: `src/protocol/trust.js`
- Added key lifecycle primitives: `src/protocol/key_lifecycle.js`
- Added strict E2EE profile primitives: `src/protocol/e2ee.js`
- Wired trust-anchor authority checks into federated envelope validation path.
- Added DNSSEC-aware trust-anchor TXT verification + signed trust publication surfaces (`/.well-known/loom-trust*`, `/v1/federation/trust/verify-dns`).
- Added local transparency checkpoint workflow for trust-anchor publication provenance.
- Added protocol capability publication (`/v1/protocol/capabilities`) and federation negotiation policy gates.
- Wired thread-level encryption profile/epoch policy checks into envelope ingest.
- Added participant-covered wrapped-key enforcement for `encryption.epoch@v1` and `encryption.rotate@v1`.
- Added periodic trust-anchor revalidation worker to keep peer trust state fresh without manual operations.
- Added publishable conformance fixtures under `test/fixtures/conformance/`.

## 5. Trust Anchor Policy (v2.0 Baseline)

Environment control:

- `LOOM_FEDERATION_TRUST_ANCHORS`

Format:

- `identity-authority=node-authority-a|node-authority-b`
- multiple mappings separated by `,`, `;`, or newline

Example:

- `agents.example=fed-hub.partner.example|fed-hub-dr.partner.example`

Semantics:

- If no mapping exists for an identity authority, strict authority equality applies.
- If a mapping exists, sender node authority MUST match one of the configured trust anchors.

## 6. Interoperability Contract

The following files are normative vector artifacts for independent implementations:

- `test/fixtures/conformance/canonical-json-v1.json`
- `test/fixtures/conformance/envelope-signature-ed25519-v1.json`

Validation test:

- `test/conformance_fixture_vectors.test.js`

These vectors are intentionally language-neutral and can be imported into non-Node implementations.

## 7. E2EE Profile Direction

v2.0 now includes a concrete baseline profile implementation:

- `loom-e2ee-x25519-xchacha20-v1`
  - recipient key agreement: X25519
  - wrapped-key KDF: HKDF-SHA-256 (`X25519-HKDF-SHA256`)
  - payload + wrapped-key AEAD: XChaCha20-Poly1305
  - deterministic AAD binding to profile/epoch/replay/commitment and wrapped-key routing metadata
  - attachment-level profile packaging (`loom.e2ee.attachment@v1`) with deterministic vectors
  - packaged ciphertext structure validation at ingest (`src/protocol/e2ee.js`, `src/node/store/protocol_core.js`)
  - sender replay monotonicity and epoch-reset enforcement at ingest
- `loom-e2ee-x25519-xchacha20-v2`
  - same algorithm family with higher policy security rank for controlled upgrades
  - negotiated through `/v1/protocol/capabilities` overlap checks

Profile migration hardening in baseline:

- enforced downgrade resistance via profile security ranks (`src/node/store.js`)
- explicit migration allowlist support (`LOOM_E2EE_PROFILE_MIGRATION_ALLOWLIST`) for controlled exceptions
- mandatory epoch increase on profile change with replay-counter reset semantics (`src/node/store/protocol_core.js`)

## 8. Migration Strategy

1. Keep v1.1 runtime stable for existing integrations.
2. Introduce v2.0-capable modules behind compatibility flags.
3. Publish adapter guidance for bridge-only integrations.
4. Require vector conformance for any secondary implementation before federation interop.

## 9. Definition of Progress

The reboot is considered real only when:

1. At least two independent implementations pass the same vector suite.
2. Trust-anchor and key lifecycle policies are enforced on live federation traffic.
3. E2EE profile is implemented and verified end-to-end.
4. Bridge and gateway behavior cannot bypass native protocol policy checks.
