# NIST Compliance Alignment

## Scope

This document maps LOOM v1.1 protocol features to NIST security standards. The primary frameworks referenced are:

| Standard | Description |
|----------|-------------|
| **SP 800-53 Rev 5** | Security and Privacy Controls for Information Systems |
| **SP 800-207** | Zero Trust Architecture |
| **SP 800-208** | Post-Quantum Cryptography (informational) |
| **SP 800-56A Rev 3** | Key Establishment Schemes |

Machine-readable mappings are available via `GET /v1/admin/nist/summary` and in the source module `src/protocol/nist_mapping.js`.

## SP 800-53 Rev 5 Control Families

### AC — Access Control (7 controls)

| Control | Title | LOOM Feature |
|---------|-------|--------------|
| AC-1 | Policy and Procedures | MIME policy modes (allowlist/denylist/permissive), capability-based access |
| AC-2 | Account Management | Identity types (human/agent/team/service/bridge), identity verification |
| AC-3 | Access Enforcement | Capability tokens with audience constraints, admin token protection |
| AC-4 | Information Flow Enforcement | Channel rules, audience modes, content filtering |
| AC-6 | Least Privilege | Scoped capability tokens, recipient roles (primary/cc/observer/bcc) |
| AC-7 | Unsuccessful Logon Attempts | Rate limiting on authentication endpoints |
| AC-17 | Remote Access | TLS enforcement for federation, webhook signature verification |

### AU — Audit and Accountability (6 controls)

| Control | Title | LOOM Feature |
|---------|-------|--------------|
| AU-2 | Event Logging | Audit log with hash chain integrity, configurable retention |
| AU-3 | Content of Audit Records | Structured entries: actor, action, resource_type, resource_id, timestamp, metadata |
| AU-6 | Audit Review and Reporting | Compliance audit endpoint, automated scoring |
| AU-8 | Time Stamps | ISO 8601 timestamps on envelopes and audit entries |
| AU-9 | Protection of Audit Information | SHA-256 hash chain for tamper detection |
| AU-12 | Audit Record Generation | Automatic logging for envelope ops, blob uploads, admin actions |

### IA — Identification and Authentication (3 controls)

| Control | Title | LOOM Feature |
|---------|-------|--------------|
| IA-2 | User Identification | Ed25519 signing keys per identity, ULID-based unique IDs |
| IA-5 | Authenticator Management | Key rotation support, signing key lifecycle management |
| IA-8 | Non-Organizational Users | Agent identity with trust scoring, bridge identity for cross-system auth |

### SC — System and Communications Protection (6 controls)

| Control | Title | LOOM Feature |
|---------|-------|--------------|
| SC-7 | Boundary Protection | Content filtering, MIME policy enforcement, dangerous type blocking |
| SC-8 | Transmission Confidentiality | E2EE with X25519 + HKDF-SHA-256 + XChaCha20-Poly1305, TLS transport |
| SC-12 | Key Establishment | X25519 key agreement, HKDF-SHA-256 derivation, key rotation |
| SC-13 | Cryptographic Protection | Ed25519 signatures, AES-128-GCM (MLS), SHA-256, HMAC |
| SC-23 | Session Authenticity | Webhook HMAC signatures, capability token audience binding |
| SC-28 | Protection at Rest | Encrypted blob storage, audit chain integrity verification |

### SI — System and Information Integrity (4 controls)

| Control | Title | LOOM Feature |
|---------|-------|--------------|
| SI-3 | Malicious Code Protection | Dangerous MIME blocking, content filter with malware pattern detection |
| SI-4 | System Monitoring | Rate limiting, agent trust scoring, prompt injection detection |
| SI-7 | Integrity Verification | SHA-256 hash chain for audit logs, Ed25519 envelope signatures |
| SI-10 | Input Validation | Envelope schema validation, MIME type validation, content format validation |

### CM — Configuration Management (1 control)

| Control | Title | LOOM Feature |
|---------|-------|--------------|
| CM-3 | Configuration Change Control | Protocol version negotiation, capability advertisement, env-based config |

### IR — Incident Response (2 controls)

| Control | Title | LOOM Feature |
|---------|-------|--------------|
| IR-4 | Incident Handling | Audit log export for investigation, compliance scoring alerts |
| IR-5 | Incident Monitoring | Structured audit log with retention, hash chain integrity for evidence |

## Cryptographic Algorithm Compliance

| Algorithm | Usage | NIST Reference |
|-----------|-------|----------------|
| Ed25519 | Envelope signing, identity verification | FIPS 186-5 (EdDSA) |
| X25519 | Key agreement for E2EE | SP 800-56A Rev 3 |
| HKDF-SHA-256 | Key derivation | SP 800-56C Rev 2 |
| XChaCha20-Poly1305 | Authenticated encryption (E2EE) | — (ChaCha20 accepted per RFC 8439) |
| AES-128-GCM | Group encryption (MLS) | FIPS 197, SP 800-38D |
| SHA-256 | Audit hash chain, content hashing | FIPS 180-4 |
| HMAC-SHA-256 | Webhook signatures | FIPS 198-1 |

## Zero Trust Architecture (SP 800-207)

| Principle | LOOM Alignment |
|-----------|----------------|
| All resources are distinct | Five identity types, each with unique ULID |
| All communication is secured | TLS-required federation, E2EE, webhook HMAC |
| Per-session access grants | Scoped capability tokens with expiration and audience constraints |
| Dynamic policy-driven access | Agent trust scoring adjusts privileges based on behavior |
| Continuous security monitoring | ATP compliance layer, 23 automated checks, hash-chain audit logs |

## Related Documentation

- [THREAT-MODEL.md](THREAT-MODEL.md) — STRIDE threat analysis
- [COMPLIANCE-CONTROLS.md](COMPLIANCE-CONTROLS.md) — SOC 2-style control evidence
- [CONFORMANCE.md](CONFORMANCE.md) — Protocol conformance test vectors
