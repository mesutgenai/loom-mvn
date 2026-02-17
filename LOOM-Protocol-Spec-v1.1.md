# LOOM Protocol Specification v1.1.0  
**Linked Operations & Orchestrated Messaging**  
**The communication layer built for humans and agents together.**

**Status:** Draft Specification  
**Version:** 1.1.0  
**Date:** February 2026  
**Author:** Mesut (CoWork-OS)  
**License:** Open Specification — free to implement, extend, and build upon.

---

## Table of Contents

1. Abstract  
2. Motivation & Problem Statement  
3. Design Principles  
4. Terminology  
5. Architecture Overview  
6. Addressing & Identity  
7. Cryptographic Model  
8. Envelope Specification  
9. Envelope Types & Schemas  
10. Thread Model  
11. Thread Operations  
12. Capability Tokens  
13. Delegation Chains  
14. Transport & Authentication  
15. Node Discovery & Federation  
16. API Specification  
17. Real-Time Protocol (WebSocket)  
18. Agent-Native Features  
19. Composable Workflows  
20. Email-Replacement Semantics  
21. Email Bridge (SMTP ↔ LOOM)  
22. Legacy Client Gateway (IMAP/SMTP façade)  
23. Security Model  
24. Error Handling  
25. Compliance, Audit, Retention & Deletion  
26. Migration Guide  
27. Reference Implementation Notes  
28. Conformance Levels  
Appendix A. LOOM vs Email  
Appendix B. Intent Registry (Core)  
Appendix C. Sequence Diagrams (Selected)  
Appendix D. Wire Format Summary  
Changelog  

---

## 1. Abstract

LOOM (Linked Operations & Orchestrated Messaging) is an open communication protocol designed to replace email as the default asynchronous messaging system for the era of human–agent collaboration. It provides:

- **Structured, typed envelopes** with dual content: **human-readable** text and **machine-parseable** intent payloads  
- **Cryptographic identity** and **non-spoofable sender authenticity** (Ed25519 signatures)  
- **First-class agent support** via **delegation chains** (verifiable authority)  
- **Fine-grained access control** via **capability tokens** (per-thread, per-operation)  
- **Composable conversations** using native thread graphs (fork, merge, link, delegate)  
- **Federation by default** (DNS discovery + HTTP/2 delivery; no central authority)  
- **Optional end-to-end encryption (E2EE)** per thread with membership-aware rekeying  
- **Email replacement parity** through a mailbox model, receipts, BCC, list semantics, rules, and migration tooling  
- **Backwards compatibility** with legacy email through a bidirectional **Email Bridge**, and continuity for existing clients via an **IMAP/SMTP Legacy Gateway**.

This document defines the wire formats, transport mechanisms, identity and cryptographic model, behavioral requirements, and the minimal and extended feature sets required for interoperable LOOM implementations.

---

## 2. Motivation & Problem Statement

### 2.1 Why Email Fails the Agent Era

Email (SMTP/IMAP/POP3) was designed for human-to-human text messaging. Its core assumptions no longer hold:

| Assumption | Reality in 2026 |
|---|---|
| Messages are written and read by humans | A large fraction of business communication is drafted, triaged, and actioned by AI agents |
| Flat text is sufficient | Agents need structured semantics to act safely and reliably |
| Identity is self-asserted | Spoofing, phishing, and impersonation remain endemic; SPF/DKIM/DMARC are bolt-on mitigations |
| Conversations are linear | Modern work forks, delegates, and merges decisions across teams and systems |
| Delivery is fire-and-forget | Agents require receipts, state transitions, and real-time event feeds |

### 2.2 What LOOM Solves

LOOM is designed for a world where each person and organization may operate multiple agents. These agents must be able to communicate with humans and other agents with:

- **Full accountability** (who authorized what)  
- **Explicit permissions** (what actions are allowed)  
- **Structured semantics** (what is being asked)  
- **Auditability and compliance** (who did what, when, with what authority)  
- **Practical migration** from email without breaking the outside world.

### 2.3 Prior Art (Informative)

LOOM draws on lessons from:

- SMTP/IMAP (federation model and addressing)  
- Matrix (federated real-time, E2EE concepts)  
- ActivityPub (federated JSON object exchange)  
- OAuth2/GNAP (capability authorization patterns)  
- Signal/MLS family ideas (E2EE and group membership management)  
- JSON Schema / JSON-LD (typed structured payloads in human contexts)

LOOM is not a chat protocol. It is asynchronous-first “email reimagined” with real-time extensions.

---

## 3. Design Principles

Implementations SHOULD adhere to these principles in spirit and in behavior.

| # | Principle | Implication |
|---|---|---|
| P1 | Agent-native, human-friendly | Agents are first-class participants. Humans never have to learn protocol internals. |
| P2 | Structured by default | Dual content: human + structured, with typed schemas. |
| P3 | Composable conversations | Threads are DAGs; fork/merge/link/delegate are primitives. |
| P4 | Identity & trust built-in | Cryptographic identity + delegation chains + capability tokens are core. |
| P5 | Federated by default | Any domain can run a node. Discovery uses DNS + well-known. |
| P6 | Backwards-compatible migration | Bidirectional email bridge + legacy gateway + import/export. |
| P7 | Privacy by design | Mandatory transport encryption; optional per-thread E2EE; minimize exposed metadata. |
| P8 | Auditability | Signed envelopes + explicit state transitions + tamper-evident audit logs. |
| P9 | Email replacement parity | Mailbox semantics, BCC, receipts, lists, rules, and interoperability. |

---

## 4. Terminology

| Term | Definition |
|---|---|
| Envelope | Fundamental LOOM message object. Replaces an email “message.” |
| Thread | A conversation/workflow represented as a DAG of envelopes plus an authoritative event-log of thread operations. |
| Node | Server hosting identities, storing envelopes/blobs, and participating in federation. |
| Identity | Cryptographic entity (human, agent, team, service, bridge). |
| Delegation | Signed grant from one identity to another (typically human→agent) with bounded scope. |
| Delegation Chain | List of delegations proving authority from root delegator to acting agent. |
| Capability Token | Signed, scoped permission for actions in a thread or on resources. |
| Thread Operation | A signed envelope that modifies thread metadata/membership/state in a replicated, conflict-resolvable way. |
| Relay Mesh | Federated routing layer (node discovery + envelope delivery). |
| Email Bridge | SMTP/MIME gateway translating between email and LOOM. |
| Legacy Gateway | IMAP/SMTP façade allowing classic email clients to interact with LOOM. |
| Blob | Large binary object (attachment content) stored and transferred separately from envelopes. |
| MUST/SHOULD/MAY | As defined in RFC 2119. |

---

## 5. Architecture Overview

### 5.1 System Topology

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              LOOM NETWORK                                    │
│                                                                              │
│   ┌──────────────┐       ┌──────────────┐       ┌──────────────┐            │
│   │  LOOM Node A │◄─────►│  LOOM Node B │◄─────►│  LOOM Node C │            │
│   │ (personal)   │       │ (enterprise) │       │ (agent-farm) │            │
│   │              │       │              │       │              │            │
│   │ • Identities │       │ • Identities │       │ • Identities │            │
│   │ • Env Store  │       │ • Env Store  │       │ • Env Store  │            │
│   │ • Blob Store │       │ • Blob Store │       │ • Blob Store │            │
│   │ • API Server │       │ • API Server │       │ • API Server │            │
│   └──────┬───────┘       └──────┬───────┘       └──────┬───────┘            │
│          │                      │                      │                     │
│   ┌──────┴──────────────────────┴──────────────────────┴───────┐            │
│   │                    RELAY MESH (Federation)                  │            │
│   │         DNS discovery · Signed delivery · Store-and-forward  │            │
│   └──────────────────────────┬─────────────────────────────────┘            │
│                              │                                               │
│   ┌──────────────────────────┴─────────────────────────────────┐            │
│   │     Email Bridge (SMTP ↔ LOOM)  +  Legacy Gateway (IMAP/SMTP)│           │
│   └────────────────────────────────────────────────────────────┘            │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Node Responsibilities

A conforming node MUST:
- Host one or more identities
- Store and index envelopes durably
- Store and serve blobs durably
- Expose the LOOM API over HTTP/2 with TLS 1.3
- Validate signatures on inbound envelopes
- Enforce capability tokens on all state-changing operations
- Verify delegation chains for agent-originated envelopes
- Participate in federation (if federation enabled) using discovery + signed delivery

A conforming node SHOULD:
- Provide WebSocket real-time events with resume
- Provide Email Bridge and Legacy Gateway for migration
- Implement retention policies and deletion APIs
- Support E2EE and key epoch management
- Provide quarantine/spam controls

---

## 6. Addressing & Identity

### 6.1 LOOM URI Format

All LOOM addresses use a URI scheme:

```
loom://{local}@{domain}[#{fragment}]
```

Examples:
- `loom://mesut@cowork-os.com` — human identity  
- `loom://assistant.mesut@cowork-os.com` — agent scoped to human  
- `loom://billing@acme.corp` — role/team identity  
- `loom://mesut@cowork-os.com#thr_01JMKB7W...` — client-side deep link  
- `bridge://alice@gmail.com` — bridged email identity  

Rules:
- Local parts MUST match: `[a-z0-9][a-z0-9._-]{0,63}`
- Agent scoping uses `.` separators (`agent.human`, `subagent.agent.human`)
- Fragment identifiers are **client-side only** and MUST NOT be transmitted in envelopes
- Domain part is case-insensitive; local part is case-sensitive
- `bridge://` scheme is reserved for bridged identities

### 6.2 Identity Document

Each identity resolves to an Identity Document retrievable via the LOOM API and/or well-known endpoints.

```json
{
  "loom": "1.1",
  "id": "loom://mesut@cowork-os.com",
  "type": "human",
  "display_name": "Mesut",
  "node": "cowork-os.com",
  "created_at": "2026-01-15T10:00:00Z",
  "public_keys": {
    "signing": [
      { "algorithm": "Ed25519", "key_id": "k_sign_root_01J...", "public_key": "base64url...", "status": "active", "scope": ["*"] },
      { "algorithm": "Ed25519", "key_id": "k_sign_dev_01J...",  "public_key": "base64url...", "status": "active", "scope": ["send","receive"] }
    ],
    "encryption": [
      { "algorithm": "X25519", "key_id": "k_enc_dev_01J...", "public_key": "base64url...", "status": "active" }
    ]
  },
  "delegations": [],
  "capabilities": ["send", "receive", "create_thread", "delegate"],
  "verified_bridges": { "email": "mesut@cowork-os.com" },
  "aliases": ["loom://m@cowork-os.com"],
  "metadata": { "timezone": "Europe/Lisbon", "locale": "en" }
}
```

### 6.3 Identity Types

| Type | Description | Requirements |
|---|---|---|
| human | Natural person | MUST have at least one signing key |
| agent | AI agent acting on behalf of human/org | MUST have `delegator` and bounded scope; MUST self-identify; MUST include delegation chain in envelopes |
| team | Group address | MUST have members list and routing policy |
| service | Non-agent automated system | MUST have operator field (accountable human/org) |
| bridge | Proxied identity from non-LOOM system | Created by Email Bridge; limited capabilities |
| node | Node identity (for federation signing) | Published in Node Document |

### 6.4 Agent Identity

Agent identities add required fields:

```json
{
  "loom": "1.1",
  "id": "loom://assistant.mesut@cowork-os.com",
  "type": "agent",
  "display_name": "Mesut's Assistant",
  "node": "cowork-os.com",
  "delegator": "loom://mesut@cowork-os.com",
  "agent_info": { "provider": "anthropic", "model": "claude-opus-4", "version": "2026.02" },
  "delegation_scope": ["read.*", "reply.routine", "task.create", "calendar.*"],
  "delegation_expires": "2026-06-01T00:00:00Z",
  "delegation_signature": "base64url...",
  "public_keys": { "signing": [{ "algorithm": "Ed25519", "key_id": "k_sign_agent_...", "public_key": "base64url...", "status": "active", "scope": ["send","receive"] }], "encryption": [] },
  "capabilities": ["send", "receive", "reply"]
}
```

Agent rules:
- Agents MUST set `type: "agent"` in both identity document and envelope `from.type`
- Nodes MUST reject envelopes where `from.type` mismatches identity document
- Agents MUST include full delegation chain in envelopes (Section 13)

---

## 7. Cryptographic Model

### 7.1 Algorithms

| Purpose | Algorithm | Notes |
|---|---|---|
| Envelope signing | Ed25519 | All envelopes MUST be signed |
| Node request signing | Ed25519 | Federation wrapper signatures |
| E2EE key agreement | X25519 | For per-thread membership-wrapped secrets |
| E2EE encryption | XChaCha20-Poly1305 | AEAD for message payloads and blobs |
| KDF | HKDF-SHA-256 | Derive epoch and message keys |
| Hashing | SHA-256 | Integrity hashes for envelopes and blobs |

### 7.2 Canonical JSON Serialization

For signature computation, envelopes are serialized to canonical JSON:
- Keys sorted lexicographically at all nesting levels
- No whitespace (no spaces or newlines)
- UTF-8 encoding
- Numbers without leading zeros or trailing decimal points
- `null` values included (not omitted)
- The `signature` field and `meta` field are excluded from the canonical form
- Any explicitly defined “ephemeral fields” MUST also be excluded (see attachments / URLs)

### 7.3 Envelope Signing (Required)

Signing process:
1. Serialize canonical envelope JSON excluding `signature` and `meta`
2. Sign bytes with Ed25519 signing key referenced by `signature.key_id`
3. Store signature value as base64url

Nodes MUST verify all inbound envelope signatures before delivery or storage.

### 7.4 End-to-End Encryption (E2EE) (Optional per thread)

LOOM defines E2EE profile `loom-e2ee-1` with membership-aware epochs (see Sections 10.6 and 11.7).

Key rules:
- Routing metadata remains in cleartext (`from`, `to`, `thread_id`, `type`) to permit delivery
- Payload (`content`) and attachments MAY be encrypted end-to-end
- Membership changes MUST increment epoch and rekey

---

## 8. Envelope Specification

### 8.1 Envelope Schema (v1.1)

```json
{
  "$schema": "https://loom-protocol.org/schema/envelope/v1.1.json",
  "loom": "1.1",
  "id": "env_{ULID}",
  "thread_id": "thr_{ULID}",
  "parent_id": "env_{ULID} | null",
  "type": "{envelope_type}",
  "from": {
    "identity": "loom://{local}@{domain} | bridge://{email}",
    "display": "{name}",
    "key_id": "k_sign_{...}",
    "type": "human | agent | team | service | bridge",
    "delegation_chain": [ "{delegation_link}", "..."] 
  },
  "to": [
    { "identity": "loom://{local}@{domain} | bridge://{email}", "role": "primary | cc | observer | bcc" }
  ],
  "audience": {
    "mode": "thread | recipients | custom",
    "identities": ["loom://..."]
  },
  "created_at": "{ISO 8601}",
  "expires_at": "{ISO 8601} | null",
  "priority": "low | normal | high | urgent",
  "content": {
    "human": { "text": "{text}", "format": "markdown | plaintext | html", "locale": "{BCP47}" },
    "structured": { "intent": "{namespace.action@vN}", "parameters": {}, "response_schema": "{uri} | null" },
    "encrypted": false,
    "profile": "loom-e2ee-1 | null",
    "epoch": 0,
    "nonce": "base64url | null",
    "ciphertext": "base64url | null"
  },
  "attachments": [
    {
      "id": "att_{ULID}",
      "filename": "{name}",
      "mime_type": "{MIME}",
      "size_bytes": 0,
      "hash": "sha256:{hex}",
      "blob_id": "blob_{ULID}",
      "inline": false,
      "encryption": {
        "encrypted": false,
        "profile": "loom-e2ee-1 | null",
        "wrapped_keys": [
          { "to": "loom://...", "ciphertext": "base64url..." }
        ]
      }
    }
  ],
  "references": {
    "in_reply_to": "env_{ULID} | null",
    "linked_envelopes": ["env_{ULID}"],
    "linked_threads": ["thr_{ULID}"],
    "external": [{ "type": "url | email_message_id | issue | document", "ref": "{value}" }]
  },
  "capabilities": ["reply", "forward", "delegate", "fork", "add_participant", "escalate"],
  "labels": ["{label}"],
  "signature": { "algorithm": "Ed25519", "key_id": "k_sign_{...}", "value": "base64url..." },
  "meta": {
    "node_id": "{origin}",
    "received_at": "{ISO 8601}",
    "event_seq": 0,
    "origin_event_seq": 0,
    "pending_parent": false,
    "bridge": {
      "source": "email | legacy_gateway | null",
      "original_message_id": "{Message-ID} | null",
      "original_headers": {},
      "auth_results": { "spf": "pass|fail|none", "dkim": "pass|fail|none", "dmarc": "pass|fail|none" },
      "extraction_confidence": 0.0
    }
  }
}
```

### 8.2 Field Requirements

| Field | Required | Notes |
|---|---|---|
| loom | MUST | `"1.1"` |
| id | MUST | `env_` + ULID |
| thread_id | MUST | `thr_` + ULID |
| parent_id | SHOULD | `null` for thread roots |
| type | MUST | Defined registry (Section 9) |
| from | MUST | Sender identity + signing key reference |
| to | MUST | At least one `primary` recipient |
| audience | MAY | Defaults to `thread` for native threads |
| created_at | MUST | ISO 8601 |
| content | MUST | At least one of `human` or `structured` must be present in cleartext, unless encrypted |
| signature | MUST | Signature over canonical envelope |
| meta | SHOULD | Node-local metadata; excluded from signature |

### 8.3 Audience and BCC (Email parity)
- `to[].role="bcc"` is allowed but **MUST NOT** reveal bcc identities to other recipients.
- Nodes MUST implement BCC by generating **bcc-copy envelopes** with `audience.mode="custom"` (Section 20.6).
- `audience.mode`:
  - `thread` (default): visible to thread participants per capability rules
  - `recipients`: only sender + explicit recipients may access
  - `custom`: sender + listed identities only

Nodes MUST enforce audience in delivery and retrieval.

### 8.4 ID Format (ULID)
All IDs are ULIDs with type prefixes:
- Envelope: `env_`  
- Thread: `thr_`  
- Attachment: `att_`  
- Blob: `blob_`  
- Capability token: `cap_`  
- Event: `evt_`  
- Keys: `k_sign_`, `k_enc_`, `k_node_sign_`

---

## 9. Envelope Types & Schemas

### 9.1 Core Type Registry (Normative)

| Type | Purpose |
|---|---|
| message | General communication |
| task | Work item with state machine |
| approval | Decision request |
| event | Calendar/scheduling |
| notification | Status update (usually no reply) |
| handoff | Transfer of responsibility/context |
| data | Structured data exchange |
| receipt | Delivery/read/action confirmation |
| workflow | Multi-step workflow definition/execution |
| thread_op | Thread operation (membership/state/metadata control) |

Unknown types:
- Nodes MUST accept unknown `type` values, store them, and relay them.
- Clients MAY render unknown types as generic messages.

### 9.2 Type rules (selected)
- `message`: `content.human` REQUIRED; `content.structured` OPTIONAL  
- `task`: `content.structured` REQUIRED; intent MUST be `task.*@vN`  
- `receipt`: `content.structured` REQUIRED; `content.human` OPTIONAL  
- `thread_op`: `content.structured.intent` MUST be `thread.*@vN` or `capability.*@vN` or `encryption.*@vN` as specified

---

## 10. Thread Model

A Thread is:
1) A DAG of envelopes (conversation)  
2) An authoritative event-log of thread operations (membership/state/metadata)  

### 10.1 Thread Object (API representation)

```json
{
  "id": "thr_{ULID}",
  "root_envelope_id": "env_{ULID}",
  "subject": "Q1 Invoice Request",
  "state": "active | resolved | archived | locked",
  "created_at": "2026-02-16T16:37:00Z",
  "updated_at": "2026-02-16T17:10:00Z",
  "participants": [
    { "identity": "loom://mesut@cowork-os.com", "role": "owner", "joined_at": "2026-02-16T16:37:00Z", "left_at": null }
  ],
  "labels": ["finance", "q1-2026"],
  "forks": [
    { "fork_id": "thr_{ULID}", "forked_from": "env_{ULID}", "state": "active | resolved | merged", "subject": "Legal check" }
  ],
  "linked_threads": [
    { "thread_id": "thr_{ULID}", "relation": "related | blocks | blocked_by | parent | child | merged_from" }
  ],
  "schema": "request.document@v1",
  "cap_epoch": 0,
  "encryption": {
    "enabled": false,
    "profile": null,
    "key_epoch": 0
  }
}
```

### 10.2 DAG Validity Rules (Required)

Nodes MUST enforce:
- **Single parent**: `parent_id` references at most one envelope.
- **No cycles**: envelopes creating cycles MUST be rejected (`ENVELOPE_INVALID`).
- **Out-of-order acceptance**: missing parents MUST NOT cause rejection; mark `meta.pending_parent=true`.
- **Orphan handling**: unresolved parent references remain valid; clients render with an “unknown parent” indicator.

### 10.3 Canonical Rendering Order (Required)

Clients MUST render thread envelopes using stable ordering:
1) Topological by `parent_id`  
2) Within same parent: `created_at` ascending  
3) Tie-break: `id` lexicographic ascending

### 10.4 Thread state machine (Required)

Thread state transitions are applied via `thread_op` envelopes:
- `thread.resolve` transitions `active → resolved`
- `thread.archive` transitions `resolved → archived`
- `thread.lock` transitions `active|resolved → locked`
- `thread.reopen` transitions `resolved|locked → active`

Nodes MUST reject invalid transitions (`STATE_TRANSITION_INVALID`).

### 10.5 Membership and authorization source of truth
Membership changes MUST be expressed as `thread_op` envelopes (Section 11).  
Nodes MUST NOT infer participants from recipients alone (except during bootstrap of new thread creation).

### 10.6 Encryption membership and key epochs
If `thread.encryption.enabled=true`:
- Any membership change MUST increment `thread.encryption.key_epoch`.
- Nodes MUST emit an `encryption.epoch` operation to distribute secrets to current participants (Section 11.8).

---

## 11. Thread Operations (Authoritative Event-Log)

### 11.1 Operation envelope
Thread operations use:
- `type: "thread_op"`
- `content.structured.intent: "thread.*@v1"` (or related registries below)

### 11.2 Required operations (Normative)
Nodes MUST implement:
- `thread.add_participant@v1`
- `thread.remove_participant@v1`
- `thread.update@v1` (subject, labels)
- `thread.resolve@v1`
- `thread.archive@v1`
- `thread.lock@v1`
- `thread.reopen@v1`
- `thread.delegate@v1`
- `thread.fork@v1`
- `thread.merge@v1`
- `thread.link@v1`

### 11.3 Preconditions (Recommended)
Operations MAY include preconditions:
```json
"preconditions": { "thread_state_in": ["active"], "cap_epoch": 3 }
```
Nodes MUST reject if unmet.

### 11.4 Fork, merge, link semantics (Required)

- **Fork** (`thread.fork@v1`):
  - Creates a new thread id `thr_fork`
  - Parent thread adds entry to `forks[]`
  - Fork thread adds `linked_threads[]` relation: `parent`
  - Fork operation references envelope `forked_from`

- **Merge** (`thread.merge@v1`):
  - Does not move envelopes
  - Marks fork thread state `merged`
  - Adds parent thread link `merged_from` → fork thread
  - Clients render merged fork as resolved context attached to parent

- **Link** (`thread.link@v1`):
  - Adds `linked_threads[]` entries in one or both threads (policy controlled)
  - No state change

### 11.5 Operation audience (Required)
Thread operations MUST be delivered to:
- all current participants, including observers, unless restricted by policy.

If a participant is removed, the removal op SHOULD still be delivered to that participant so they can update local state, unless forbidden by explicit policy.

### 11.6 Event sequencing (Required)
Nodes MUST assign `meta.event_seq` to every accepted envelope within a thread, monotonically increasing per thread, to provide stable ordering for replication and client rendering.

`meta.origin_event_seq` SHOULD be set on envelopes created locally and preserved in federation to support debugging and reconciliation.

### 11.7 Conflict resolution (Required)
When conflicting operations occur, nodes MUST apply:
1) Only operations with satisfied preconditions  
2) Otherwise last valid operation wins by event order (`meta.event_seq`), not wall-clock

### 11.8 Encryption operations (Required for E2EE threads)
Encryption is managed via thread operations:
- `encryption.epoch@v1` (distribute new epoch secret)
- `encryption.rotate@v1` (optional explicit rotation trigger)

See Section 7.4 and 12.7 for details.

---

## 12. Capability Tokens

LOOM uses capability tokens for fine-grained authorization. Tokens are designed to be portable across federation: **self-contained, signed, and verifiable offline**.

### 12.1 Token Structure (Required)

```json
{
  "loom": "1.1",
  "id": "cap_{ULID}",
  "issued_by": "loom://{identity}",
  "issued_to": "loom://{identity}",
  "created_at": "{ISO 8601}",
  "expires_at": "{ISO 8601} | null",
  "single_use": false,
  "epoch": 3,
  "grants": ["reply", "add_participant"],
  "scope": {
    "thread_id": "thr_{ULID}",
    "envelope_types": ["message", "task"],
    "max_depth": 50,
    "max_priority": "normal",
    "external_domains": "deny | allow"
  },
  "signature": { "algorithm": "Ed25519", "key_id": "k_sign_{...}", "value": "base64url..." }
}
```

### 12.2 Available Grants (Normative)

| Grant | Description |
|---|---|
| read | Read envelopes in thread |
| reply | Send envelopes to thread |
| forward | Share thread/envelope externally |
| delegate | Transfer thread ownership |
| fork | Create forks |
| merge | Merge forks |
| add_participant | Invite new participants |
| remove_participant | Remove participants |
| escalate | Raise priority / route to supervisor |
| resolve | Resolve thread |
| archive | Archive thread |
| lock | Lock thread |
| label | Add/remove labels |
| admin | Superset of all grants |

### 12.3 Token Epoch and Revocation (Required)

Threads maintain `cap_epoch`.
- Any revocation increments `cap_epoch`.
- Tokens MUST carry `epoch`.
- Nodes MUST reject tokens where `token.epoch != thread.cap_epoch`.

Revocation is recorded via thread operation:
- `intent: "capability.revoked@v1"`

### 12.4 How tokens are presented (Required)
For any action that modifies shared thread state, nodes MUST require authorization proven in one of two ways:

1) **Preferred**: action is expressed as a `thread_op` envelope that includes the capability token in `content.structured.parameters.capability_token`, and the actor signs the envelope.

2) **Legacy**: HTTP header `X-LOOM-Capability: cap_...` plus request body including the signed token.

For federation, only (1) is reliable and portable; therefore nodes MUST treat `thread_op` as the authoritative replicated authorization record.

### 12.5 Single-use tokens (Required)
If `single_use=true`:
- Node MUST mark token spent upon first successful use and broadcast:
  - `capability.spent@v1` (thread_op)

### 12.6 Proof-of-possession hardening (Optional)
Nodes MAY require an actor-signed capability proof bound to the envelope id to mitigate stolen bearer token replay.

---

## 13. Delegation Chains

Delegation chains prove agent authority and scope.

### 13.1 Delegation Object (Required)

```json
{
  "delegator": "loom://mesut@cowork-os.com",
  "delegate": "loom://assistant.mesut@cowork-os.com",
  "scope": ["read.*", "reply.routine", "task.create", "calendar.*"],
  "created_at": "2026-01-15T10:00:00Z",
  "expires_at": "2026-06-01T00:00:00Z",
  "revocable": true,
  "allow_sub_delegation": true,
  "max_sub_delegation_depth": 2,
  "signature": "base64url..."
}
```

### 13.2 Scope syntax (Required)
Dot-separated namespaces with wildcards:
- `read.*`
- `reply.routine`
- `task.create`
- `calendar.schedule`
- `calendar.*`
- `*` only valid for root human→agent delegation

Sub-delegations MUST be strict subsets of parent scope.

### 13.3 Chain verification (Required)
When receiving an envelope from an agent, a node MUST:
1. Verify envelope signature
2. Extract `from.delegation_chain`
3. Verify each link:
   - signature valid
   - not expired
   - not revoked
   - scope is subset of previous link
4. Verify envelope action is within leaf scope
5. Reject on failure with `DELEGATION_INVALID`

### 13.4 Revocation (Required)
Delegation revocation MUST be recorded via thread_op or notification:
- `delegation.revoked@v1` including delegator, delegate, time, reason  
Nodes MUST maintain revocation lists and enforce them.

### 13.5 Agent self-identification (Required)
Agents MUST set:
- `from.type = "agent"`
- include full `delegation_chain`

Nodes MUST reject envelopes where `from.type` mismatches identity type.

---

## 14. Transport & Authentication

### 14.1 Transport requirements (Required)
- HTTP/2 over TLS 1.3 for all API traffic
- TLS 1.2 and below MUST be rejected
- Content type for JSON: `application/json; charset=utf-8`
- WebSocket over TLS (`wss://`) for real-time

### 14.2 Authentication (Required): proof-of-key
No passwords. Authentication is cryptographic proof-of-key.

Flow:
1. Client requests challenge:
   - `POST /v1/auth/challenge { identity, key_id }`
2. Server returns nonce + expiry
3. Client signs nonce with Ed25519 key and exchanges for tokens:
   - `POST /v1/auth/token { identity, key_id, challenge, signature }`
4. Server returns:
   - short-lived `access_token` (1h TTL)
   - long-lived `refresh_token` (30d TTL)

### 14.3 Rate limiting (Required)
Nodes MUST implement rate limits (configurable policy). Suggested defaults:
- POST /v1/envelopes: 100/min per identity
- POST /v1/auth/*: 10/min per IP
- GET /v1/threads/*: 300/min per identity
- WebSocket inbound messages: 60/min per connection
- Federation deliveries: 1000/min per node

Nodes SHOULD return:
- `X-LOOM-RateLimit-Limit`
- `X-LOOM-RateLimit-Remaining`
- `X-LOOM-RateLimit-Reset`

### 14.4 Idempotency (Required)
`POST /v1/envelopes` and other create endpoints MUST support:
- `Idempotency-Key` header
- repeated requests with same key MUST return the same result (or a deterministic error)

---

## 15. Node Discovery & Federation

### 15.1 DNS-based discovery (Required)
Nodes advertise via DNS SRV and TXT:

SRV:
```
_loom._tcp.example.com. 3600 IN SRV 10 0 443 loom.example.com.
```

TXT:
```
_loom.example.com. 3600 IN TXT "v=LOOM1.1; api=https://loom.example.com/v1; ws=wss://loom.example.com/ws; wellknown=https://example.com/.well-known/loom.json"
```

### 15.2 Well-known Node Document (Required)
Every node MUST serve:
```
GET https://{domain}/.well-known/loom.json
```

The Node Document MUST include:
- node_id, domain
- api_url, websocket_url
- federation deliver_url + requirements
- node signing keys
- supported versions and profiles
- federation policy mode (open/quarantine/allowlist)

### 15.3 Federation request signing (Recommended; MAY be required)
Nodes SHOULD sign federation deliveries using **LOOM-HTTP-SIG-1**.

Required headers:
- `X-LOOM-Node`
- `X-LOOM-Timestamp`
- `X-LOOM-Nonce`
- `X-LOOM-Key-Id`
- `X-LOOM-Signature`

Canonical string:
```
method + "\n" + path + "\n" + sha256(body) + "\n" + timestamp + "\n" + nonce
```

Verification:
- TLS server cert must match domain
- signature verified using node signing key from Node Document
- nonce replay prevented (cache 15 min)

### 15.4 Federation delivery endpoint
```
POST /v1/federation/deliver
```

Body:
```json
{
  "loom": "1.1",
  "sender_node": "cowork-os.com",
  "timestamp": "2026-02-16T18:30:00Z",
  "envelopes": [ { ... }, { ... } ]
}
```

Nodes receiving federation deliveries MUST:
- Verify request signature if policy requires
- Verify envelope signatures
- Enforce delegation chains and capability rules
- Store envelopes and generate receipts

### 15.5 Replay protection vs store-and-forward (Resolved)
Freshness checks (±5 minutes) apply to the federation **request wrapper** timestamp, not to envelope `created_at`. Envelopes may arrive late due to store-and-forward.

### 15.6 Store-and-forward (Required)
If recipient node unreachable:
- Sending node queues with exponential backoff
- Default TTL 72 hours (configurable)
- On TTL expiry: generate `receipt.failed` with reason `NODE_UNREACHABLE` or `DELIVERY_TIMEOUT`

### 15.7 Federation handshake (Recommended)
Nodes SHOULD expose:
- `GET /v1/federation/hello` returning signed capabilities and policies to reduce discovery overhead.

---

## 16. API Specification

Base URL:
```
https://{node_domain}/v1
```

### 16.1 Envelopes

| Method | Path | Description |
|---|---|---|
| POST | /v1/envelopes | Send new envelope |
| GET | /v1/envelopes/{id} | Retrieve envelope |
| DELETE | /v1/envelopes/{id} | Retract (policy window) |

Send:
- MUST validate signature and authorization
- MUST assign `meta.event_seq`
- MUST deliver locally and federate as needed

### 16.2 Threads

| Method | Path | Description |
|---|---|---|
| GET | /v1/threads | List threads |
| GET | /v1/threads/{id} | Thread details |
| GET | /v1/threads/{id}/envelopes | Envelopes in thread |
| POST | /v1/threads/{id}/ops | Post thread_op (optional convenience) |

Notes:
- Mutations SHOULD be represented as `thread_op` envelopes posted via `/v1/envelopes`.

### 16.3 Identity

| Method | Path | Description |
|---|---|---|
| GET | /v1/identity/{loom_uri} | Resolve identity |
| GET | /v1/identity/me | Auth identity |
| PATCH | /v1/identity/me | Update metadata |
| POST | /v1/identity/me/keys | Add device key |
| DELETE | /v1/identity/me/keys/{key_id} | Revoke key |

### 16.4 Capabilities

| Method | Path | Description |
|---|---|---|
| POST | /v1/capabilities | Issue capability token |
| GET | /v1/capabilities?thread_id=... | List tokens |
| DELETE | /v1/capabilities/{id} | Revoke (creates thread_op) |

### 16.5 Delegations

| Method | Path | Description |
|---|---|---|
| POST | /v1/delegations | Create delegation |
| GET | /v1/delegations | List delegations |
| DELETE | /v1/delegations/{id} | Revoke delegation |

### 16.6 Search

| Method | Path | Description |
|---|---|---|
| GET | /v1/search | Full-text + structured search |

Nodes MUST support searching:
- cleartext `content.human.text`
- `content.structured.intent` and parameters
- thread metadata (subject, labels, participants)

For E2EE threads, nodes MUST NOT claim decrypted content search.

### 16.7 Blobs (Attachments)

| Method | Path | Description |
|---|---|---|
| POST | /v1/blobs | Initiate upload |
| PUT | /v1/blobs/{id}/parts/{n} | Upload part |
| POST | /v1/blobs/{id}/complete | Finalize |
| GET | /v1/blobs/{id} | Download |

Blob downloads MUST require:
- auth token AND
- thread read capability or explicit blob capability

### 16.8 Events (Catch-up)

| Method | Path | Description |
|---|---|---|
| GET | /v1/events?since=evt_... | Catch up on events |

Servers MUST provide stable event IDs and allow clients to resume (Section 17).

---

## 17. Real-Time Protocol (WebSocket)

Connection:
```
wss://{node_domain}/ws?token={access_token}
```

### 17.1 Subscribe with resume
Client sends:
```json
{ "action": "subscribe", "channels": [{ "type": "all_threads" }], "since": "evt_01J..." }
```

### 17.2 Delivery guarantees
- Server events are **at-least-once**
- Each event MUST contain `event_id` and `cursor`
- Clients MUST dedupe by `event_id`
- Clients SHOULD ack progress:
```json
{ "action": "ack", "cursor": "evt_01J..." }
```

### 17.3 Event types (Core)
- `envelope.new`
- `envelope.retracted`
- `thread.updated`
- `thread.fork`
- `thread.merged`
- `participant.joined`
- `participant.left`
- `presence.update`
- `capability.revoked`
- `delegation.revoked`
- `receipt.delivered`
- `receipt.read`
- `receipt.failed`
- `typing.start` / `typing.stop`

### 17.4 Heartbeat
Clients MUST send `ping` every 30s; server responds `pong`. Connections without ping for 90s MAY be terminated.

### 17.5 Presence privacy
Presence is optional. Nodes SHOULD restrict presence visibility to:
- thread participants with `read` capability, and/or
- explicitly trusted contacts.

---

## 18. Agent-Native Features

### 18.1 Structured intents
Structured payloads use namespaced intents, versioned:
- `task.create@v1`
- `approval.request@v1`
- `schedule.meeting@v1`

The `response_schema` field SHOULD be a URI identifying required reply structure.

### 18.2 Agent self-identification (Required)
Agent-sent envelopes MUST include:
- `from.type="agent"`
- `from.delegation_chain=[...]`

Clients SHOULD visually distinguish agent messages.

### 18.3 Task state machine (Required)
Tasks use `task.*@v1` intents and state updates recorded as envelopes.

Valid states:
- `created`, `assigned`, `accepted`, `in_progress`, `blocked`, `completed`, `failed`, `declined`, `cancelled`

Each transition MUST be recorded as a new envelope:
- `intent: task.state_update@v1`

### 18.4 Agent negotiation (Optional)
Agents MAY negotiate task assignment using structured bids:
- `agent.negotiate@v1` containing fitness score, load, and required capabilities.

### 18.5 Safety defaults (Recommended)
Nodes SHOULD default to:
- do not auto-execute workflows from quarantined threads
- require explicit capability grants for high-risk actions (payments, external forwarding)

---

## 19. Composable Workflows

Workflows are envelopes of `type: "workflow"` with `intent: workflow.execute@v1`.

### 19.1 Workflow envelope (Example)
Workflows define steps with conditional transitions and timeouts, and are tracked via workflow state envelopes.

### 19.2 Workflow state tracking (Required)
Each step transition generates envelopes:
- `workflow.step_complete@v1`
- `workflow.failed@v1`
- `workflow.complete@v1`

Nodes SHOULD provide a dedicated workflow thread view.

---

## 20. Email-Replacement Semantics

LOOM aims to replace the user-visible experience of email while improving trust, structure, and agent interoperability.

### 20.1 Mailbox model (Required for Email-Replacement Nodes)
Nodes MUST implement system labels:

- `sys.inbox`
- `sys.sent`
- `sys.archive`
- `sys.spam`
- `sys.trash`
- `sys.drafts` (optional server-side; may be client-only)
- `sys.quarantine` (for unknown senders)

Rules:
- Delivered envelopes to a human identity default to `sys.inbox`
- Outbound envelopes authored by an identity MUST appear in `sys.sent`
- Archive = remove `sys.inbox`, add `sys.archive`
- Delete = add `sys.trash` (policy governs purge)

### 20.2 To/Cc/Reply semantics (Required)
Recipient roles map to email expectations:
- `primary` → To  
- `cc` → CC  
- `observer` → “FYI / read-only” participant role  
- Reply and Reply-All behavior is client policy but MUST respect:
  - `audience` restrictions
  - thread membership (who is a participant)

### 20.3 Distribution lists / mailing lists (Recommended)
Use `team` identities with routing policies:
- `deliver_to_members`: all | owners_only | on_call
- `reply_policy`: list | sender | all
- `moderation`: none | owners | agent

Email Bridge SHOULD map List-* headers into `meta.bridge` list metadata.

### 20.4 Filters / rules engine (Recommended)
Nodes SHOULD provide rule evaluation using structured intents and metadata:
- match on `intent`, sender, labels, external refs, attachment types
- actions: label, route, delegate, escalate, quarantine

Rules MUST NOT modify signed envelope content; they modify labels/routing.

### 20.5 Autoresponder / Out-of-office (Optional)
Standard intent:
- `notification.autoreply@v1`

Nodes/clients MAY generate, but MUST respect user/agent policies to avoid loops.

### 20.6 BCC (Required)
BCC MUST be implemented as:
- One visible envelope to To/Cc
- One bcc-copy envelope per BCC recipient:
  - same `thread_id`
  - `audience.mode="custom"` with `{sender, bcc_recipient}`
  - references the visible envelope via `references.linked_envelopes`

This preserves BCC privacy while enabling correct reply behaviors.

### 20.7 Recall / Retract (Email parity)
Nodes MAY support retraction within policy window:
- `DELETE /v1/envelopes/{id}`
- emits `envelope.retracted` event
- recipients MUST render retracted state, but policy MAY allow local retention for compliance

### 20.8 Receipts (Email DSN/MDN parity)
Receipts map to:
- delivered / queued / failed (DSN-like)
- read (MDN-like; optional/user-controlled)
- processed (agent/system action confirmation)

---

## 21. Email Bridge (SMTP ↔ LOOM)

### 21.1 Purpose
Bidirectional translation enabling gradual migration and external interoperability.

### 21.2 Inbound: Email → LOOM (Required behaviors)
When email arrives:
- Verify SPF/DKIM/DMARC; store results in `meta.bridge.auth_results`
- Create sender identity: `bridge://{email}`
- Create envelope:
  - `from.type="bridge"`
  - `meta.bridge.source="email"`
  - `meta.bridge.original_headers` preserved
  - `content.human`: body converted to markdown where possible
  - `content.structured`: best-effort intent extraction with:
    - `extracted=true`
    - `extraction_confidence` (0..1)
- Thread mapping:
  - map Message-ID / References / In-Reply-To to thread_id/parent_id

Clients MUST visually label bridged messages and treat extracted structured data as non-authoritative unless verified.

### 21.3 Outbound: LOOM → Email (Required behaviors)
When sending to email recipients:
- Render `content.human` to HTML + plaintext
- Include headers:
  - `X-LOOM-Intent`
  - `X-LOOM-Thread-ID`
  - `X-LOOM-Envelope-ID`
- Preserve threading via In-Reply-To/References mapped from parent/thread ids
- Attach blobs as MIME attachments
- DKIM-sign and align SPF/DMARC for bridge domain
- If sending BCC, MUST send separate SMTP messages without revealing BCC

### 21.4 Bridge identity limitations
Bridge identities:
- cannot delegate
- cannot spawn agents
- cannot participate in E2EE threads (unless content reverts to non-E2EE for the bridged recipient)
- have stricter rate limits

### 21.5 Quarantine integration (Recommended)
Nodes in quarantine mode SHOULD label inbound bridged mail from unknown senders as `sys.quarantine` and suppress agent auto-actions by default.

---

## 22. Legacy Client Gateway (IMAP/SMTP façade)

### 22.1 Goal
Allow users to keep using Outlook/Apple Mail/etc. during migration.

This is distinct from the Email Bridge:
- Bridge connects to the external email world.
- Legacy Gateway exposes LOOM as if it were an email server.

### 22.2 IMAP mapping (Required for Email-Replacement Nodes)
Gateway MUST:
- expose envelopes as RFC822 messages
- map `sys.*` labels to IMAP folders and/or flags
- include headers:
  - `X-LOOM-Thread-ID`
  - `X-LOOM-Envelope-ID`
  - `X-LOOM-Intent`
- include structured payload as either:
  - header(s), and/or
  - MIME part: `application/loom+json`

Limitations:
- fork/merge/link is flattened into References headers and/or special headers
- capability/delegation UI is not representable in standard IMAP clients

### 22.3 SMTP submission mapping (Required)
When legacy client sends via SMTP SUBMIT:
- Gateway converts MIME → envelope
- signs with an authorized device signing key for the identity
- structured intent extraction is best-effort; default to `message.general@v1`

### 22.4 Security (Required)
Legacy gateway MUST:
- require modern auth (OAuth2/OIDC or proof-of-key proxied by node)
- disable plaintext auth and insecure TLS versions

---

## 23. Security Model

### 23.1 Threats & Mitigations (Core)

| Threat | Mitigation |
|---|---|
| Envelope spoofing | Ed25519 signatures verified by nodes |
| Agent impersonation | type enforcement + delegation chain verification |
| MITM | TLS 1.3 mandatory; optional E2EE |
| Replay | envelope dedupe by id; federation wrapper nonce+timestamp |
| Scope escalation | capability tokens + delegation scope enforcement |
| Node compromise | E2EE protects payload confidentiality; key rotation limits blast radius |
| Spam/abuse | rate limits + quarantine + policy allow/deny |
| Phishing | bridged identity labeling + structured intents reduce ambiguity |

### 23.2 Required security controls
Nodes MUST:
- verify envelope signatures
- verify delegation chains for agent envelopes
- enforce capabilities for thread operations and sensitive actions
- reject duplicate envelope IDs
- validate federation wrapper replay protection (nonce cache)
- log security events (signature failures, scope violations)
- support key revocation for device keys and delegations

---

## 24. Error Handling

### 24.1 Error response format (Required)

```json
{
  "error": {
    "code": "ENVELOPE_INVALID",
    "message": "Envelope signature verification failed",
    "details": { "field": "signature.value", "reason": "Ed25519 signature mismatch" },
    "request_id": "req_01J...",
    "timestamp": "2026-02-16T18:40:00Z"
  }
}
```

### 24.2 Error code registry (Core)

| Code | HTTP | Description |
|---|---:|---|
| ENVELOPE_INVALID | 400 | Envelope fails schema or DAG rules |
| SIGNATURE_INVALID | 401 | Signature verification failed |
| DELEGATION_INVALID | 403 | Delegation invalid/expired/revoked |
| CAPABILITY_DENIED | 403 | Missing or invalid capability |
| AUDIENCE_DENIED | 403 | Audience restriction blocks access |
| ENCRYPTION_REQUIRED | 403 | Thread requires encryption but payload not encrypted |
| LEGAL_HOLD_ACTIVE | 403 | Deletion blocked by legal hold |
| IDENTITY_NOT_FOUND | 404 | Identity missing |
| THREAD_NOT_FOUND | 404 | Thread missing |
| ENVELOPE_NOT_FOUND | 404 | Envelope missing |
| ENVELOPE_DUPLICATE | 409 | Duplicate envelope ID |
| THREAD_LOCKED | 409 | Thread locked |
| STATE_TRANSITION_INVALID | 409 | Invalid state transition |
| PAYLOAD_TOO_LARGE | 413 | Size limits exceeded |
| RATE_LIMIT_EXCEEDED | 429 | Too many requests |
| NODE_UNREACHABLE | 502 | Remote node unreachable |
| DELIVERY_TIMEOUT | 504 | Delivery timeout |
| BRIDGE_DELIVERY_FAILED | 502 | Email bridge failure |
| INTERNAL_ERROR | 500 | Unexpected error |

### 24.3 Receipts (Required)
Delivery receipts are envelopes of `type: receipt`.

---

## 25. Compliance, Audit, Retention & Deletion

### 25.1 Audit log is tamper-evident (Required)
Nodes MUST maintain an append-only, hash-chained audit log of:
- envelope events
- thread operations
- capability events
- delegation events
- security events
- bridge and legacy gateway events

“Immutable” means **tamper-evident**, not “undeletable.”

### 25.2 Deletion semantics (Required)
Nodes MUST support:
- deleting envelope content (right-to-erasure) subject to policy
- retaining minimal audit skeleton (id, timestamp, actor, action type, hashes)

Nodes SHOULD support crypto-shredding (destroy encryption keys for erased data).

### 25.3 Legal hold (Required)
If `sys.legal_hold` label present:
- deletion MUST be rejected with `LEGAL_HOLD_ACTIVE`

### 25.4 Retention policy (Recommended)
Nodes SHOULD implement configurable retention by type and label.

---

## 26. Migration Guide

LOOM migration has three surfaces:

1) **Email Bridge** for external interoperability  
2) **Legacy Gateway** for existing clients  
3) **Import/export** for historical mail

### 26.1 Continuous rollout (Recommended)

Nodes SHOULD execute migration as a continuous rollout:
- Enable dual-run immediately: bridge inbound email into LOOM while LOOM is available for live use.
- Default all new internal communication to LOOM immediately.
- Keep email bridge and legacy gateway enabled for external/legacy dependencies as long as needed.
- Reduce legacy pathways only when usage, reliability, and policy gates indicate readiness.

### 26.2 Mailbox import/export (Recommended)
Nodes SHOULD support:
- IMAP import from Gmail/Exchange
- MBOX/EML import/export
Imported messages MUST preserve original headers in `meta.bridge.original_headers` and be labeled `sys.imported`.

---

## 27. Reference Implementation Notes

### 27.1 Recommended stack (Informative)
- Node server: Rust or Go
- Envelope store: PostgreSQL + full-text search
- Blob store: S3-compatible or filesystem + metadata DB
- Crypto: libsodium/ring
- Email Bridge: Postfix + adapter
- Legacy gateway: dovecot-like façade or custom IMAP/SMTP servers backed by LOOM

### 27.2 Minimum Viable Node (MVN)
MVN MUST implement:
- identities, envelope signing/verification
- threads + listing + reply
- HTTP/2 API with TLS 1.3
- discovery document

MVN MAY defer:
- federation
- bridge
- gateway
- E2EE
- WebSocket

---

## 28. Conformance Levels

### 28.1 Core levels
| Level | Name | Requirements |
|---|---|---|
| 1 | Core | Identity, envelopes, threads, signing, API, discovery |
| 2 | Federation | Level 1 + node-to-node delivery + store-and-forward + request signing (recommended) |
| 3 | Bridge | Level 2 + bidirectional email bridge |
| 4 | Full | Level 3 + E2EE + WebSocket + workflows + presence |

### 28.2 Email-Replacement Node (ERN) profile
An ERN MUST implement:
- Level 4 Full
- Mailbox model (`sys.*` labels)
- Legacy Gateway (IMAP/SMTP façade)
- Import/export tooling
- BCC and audience enforcement
- Quarantine mode

---

# Appendix A. LOOM vs Email (Feature Comparison)

| Feature | Email (SMTP/IMAP) | LOOM |
|---|---|---|
| Message format | MIME, mostly unstructured | Dual content + typed intents |
| Threading | heuristic | explicit DAG + thread ops |
| Identity | spoofable | cryptographic identity |
| Agent support | none | first-class agents + delegation chains |
| Access control | mailbox-wide | capability tokens per thread/op |
| Security | optional STARTTLS | mandatory TLS 1.3; optional E2EE |
| Real-time | polling/IDLE | WebSocket + event resume |
| Tasks/workflows | manual | native state machines & workflows |
| Migration | native | email bridge + legacy gateway + import/export |

---

# Appendix B. Intent Registry (Core)

Core intents SHOULD be versioned:
- `message.general@v1`
- `message.question@v1`
- `task.create@v1`
- `task.state_update@v1`
- `approval.request@v1`
- `approval.response@v1`
- `schedule.meeting@v1`
- `schedule.confirm@v1`
- `event.invite@v1`
- `event.rsvp@v1`
- `handoff.transfer@v1`
- `handoff.accept@v1`
- `notification.system@v1`
- `notification.autoreply@v1`
- `delegation.grant@v1`
- `delegation.revoked@v1`
- `capability.revoked@v1`
- `capability.spent@v1`
- `receipt.delivered@v1`
- `receipt.read@v1`
- `receipt.failed@v1`
- `workflow.execute@v1`
- `workflow.complete@v1`
- `workflow.failed@v1`
- `thread.add_participant@v1`
- `thread.remove_participant@v1`
- `thread.update@v1`
- `thread.resolve@v1`
- `thread.archive@v1`
- `thread.lock@v1`
- `thread.reopen@v1`
- `thread.fork@v1`
- `thread.merge@v1`
- `thread.link@v1`
- `encryption.epoch@v1`

---

# Appendix C. Sequence Diagrams (Selected)

## C.1 Human sends message to human (same node)

```
Alice          Node A            Bob
  | POST /envelopes (signed)      |
  |------------------------------>|
  |           verify/store/push   |
  |<------------------------------|
  |            envelope.new WS    |---->
```

## C.2 Agent sends on behalf of human (federated)

```
Agent     Node A         Node B       Sarah
  | POST /envelopes       |            |
  | (signed + delegation) |            |
  |---------------------->|            |
  | verify sig + chain    |            |
  | DNS + well-known      |            |
  | sign federation req   |            |
  | POST /federation/deliver ---------->|
  |                     verify/store    |----> WS push
  |<------------------------------------|
```

---

# Appendix D. Wire Format Summary

| Element | Format |
|---|---|
| Envelope body | JSON UTF-8 (`application/json`) |
| IDs | ULID with prefix (`env_`, `thr_`, `cap_`, `blob_`) |
| Timestamps | ISO 8601 with timezone |
| Signatures | base64url Ed25519 |
| Addressing | `loom://{local}@{domain}` |
| Transport | HTTP/2 + TLS 1.3 |
| Real-time | WebSocket over TLS |
| Discovery | DNS SRV/TXT + `/.well-known/loom.json` |
| Blobs | multipart upload + authorized download |

---

## Changelog

### 1.1.0 — February 2026
- Added authoritative **thread operations** as `thread_op` envelopes
- Defined DAG validity rules, canonical ordering, conflict resolution
- Defined portable **capability tokens** (self-contained signed) + `cap_epoch`
- Clarified federation auth with **Node Document** + **request signing (LOOM-HTTP-SIG-1)**
- Resolved replay vs store-and-forward contradiction
- Added E2EE membership-aware epochs (`loom-e2ee-1`) + attachment encryption rules
- Added blob API and federation blob transfer modes
- Added WebSocket resume/ack + events catch-up API
- Added multi-device key management (key add/revoke events)
- Added audience controls + correct BCC semantics
- Added quarantine/spam/reporting guidance
- Updated compliance language to tamper-evident audit + deletion semantics
- Added **Email-Replacement Node** conformance profile with Legacy Gateway + import/export

---

LOOM — Because communication should be woven, not stacked in an inbox.
