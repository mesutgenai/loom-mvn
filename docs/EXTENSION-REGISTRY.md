# LOOM Extension Registry and Versioning Rules

Status: Draft (normative for this repository profile)

## Purpose

Define how LOOM extensions are named, versioned, negotiated, and retired without changing `loom-core-1` semantics.

Core baseline reference:

- `docs/LOOM-CORE.md`

Conformance baseline reference:

- `docs/CONFORMANCE.md`

## Registry Model

A LOOM extension is any protocol surface outside `loom-core-1`:

- email bridge / legacy gateway
- MCP runtime semantics
- workflow orchestration
- E2EE profiles
- compliance/operational overlays

Each registry entry in runtime documents MUST define:

- `id`: canonical extension identifier (lowercase)
- `status`: `draft | active | deprecated | reserved | retired`
- `owner`: component or workstream owner
- `spec_ref`: canonical spec/doc path
- `description`: concise extension scope summary

Repository governance metadata SHOULD additionally record:

- `vector_ref`: conformance test vector path(s)
- `security_notes`: trust boundary notes and fail-closed expectations

## Identifier Rules

1. Extension IDs MUST be lowercase and immutable.
2. Extension IDs SHOULD follow `loom-ext-<name>-v<major>`.
3. Intent-like wire contracts MUST include explicit major suffixes (for example `message.general@v1`).
4. Reserved identifiers MUST NOT be emitted on wire as active features.
5. Aliases MAY exist for migration, but every alias MUST map to one canonical identifier.

## Versioning Rules

1. Breaking wire/semantic change: create a new major identifier.
- Example: `loom-ext-e2ee-x25519-v1` -> `loom-ext-e2ee-x25519-v2`.

2. Backward-compatible additive changes: keep identifier; update docs/vectors/changelog.
- Example: additional optional metadata fields with unchanged validation of existing messages.

3. Validation tightenings:
- MAY remain in the same major when they reject payloads already non-conformant to the current spec.
- MUST bump major if they invalidate payloads previously declared conformant.

4. Status lifecycle:
- `draft` -> `active` -> `deprecated` -> `retired`
- `reserved` is for pre-allocated ids not yet implementable.

5. Deprecation window:
- Deprecated extensions SHOULD remain accepted for at least two tagged releases before `retired`, unless an active security incident requires faster removal.

## Negotiation and Safety

1. Nodes advertise extension support via protocol capabilities and/or conformance claims.
2. Unknown extensions MUST be stored/relayed safely when possible, and MUST NOT implicitly change core authorization semantics.
3. Bridge-derived or low-trust extension content MUST remain non-actuating by default unless explicit LOOM-native authorization is present.
4. Any extension that affects authorization, encryption, or federation trust MUST ship with conformance vectors and negative tests before `active`.

## Machine-Readable Registry Endpoint

Nodes expose runtime extension state at:

- `GET /v1/protocol/extensions`

Response includes:

- `protocol_profile`
- `protocol_profiles_supported`
- `extensions[]` with `id`, `status`, `enabled`, `reason`, and registry metadata.

ID namespaces:

- Extension lifecycle IDs use `loom-ext-*` (this document).
- Wire cryptographic profile IDs use `loom-e2ee-*` (protocol capabilities and envelope metadata).

## Current Registry Entries (Repository Profile)

| ID | Status | Spec Ref | Runtime Note |
| --- | --- | --- | --- |
| `loom-ext-email-bridge-v1` | active | `docs/INBOUND-BRIDGE-HARDENING.md` | Route-gated by profile + bridge route toggles |
| `loom-ext-legacy-gateway-v1` | active | `docs/IMAP-COMPATIBILITY-MATRIX.md` | Route-gated by profile + gateway toggles |
| `loom-ext-mcp-runtime-v1` | active | `docs/CONFORMANCE.md` | Route-gated by profile + MCP runtime toggles |
| `loom-ext-workflow-v1` | active | `docs/CONFORMANCE.md` | Ingest-gated by profile/extension policy |
| `loom-ext-e2ee-x25519-v1` | active | `LOOM-Protocol-Spec-v1.1.md` | Ingest/profile gated via E2EE extension policy |
| `loom-ext-e2ee-x25519-v2` | active | `LOOM-Protocol-Spec-v1.1.md` | Ingest/profile gated via E2EE extension policy |
| `loom-ext-e2ee-mls-1` | active | `LOOM-Protocol-Spec-v1.1.md` | Ingest/profile gated via E2EE extension policy (MLS wire profile support) |
| `loom-ext-compliance-v1` | active | `docs/COMPLIANCE-CONTROLS.md` | Route-gated by profile + compliance route toggle |

## Registration Checklist

Every new or updated extension entry MUST include all of:

1. Spec delta (`docs/` or protocol spec update).
2. Conformance vectors (`test/fixtures/conformance/...` where applicable).
3. Runtime tests (positive and negative coverage).
4. Changelog entry.
5. Migration note (if deprecating or replacing an existing extension id).
