# LOOM Protocol Specification v1.0

### Linked Operations & Orchestrated Messaging

> *The communication layer built for humans and agents together.*

**Status:** Draft Specification  
**Version:** 1.0.0  
**Date:** February 2026  
**Authors:** Almarion (CoWork-OS)  
**License:** Open Specification — free to implement, extend, and build upon.

> Historical specification baseline.
> Canonical behavior now lives in `LOOM-Protocol-Spec-v1.1.md`, `LOOM-Agent-First-Protocol-v2.0.md`, `docs/LOOM-CORE.md`, and `docs/EXTENSION-REGISTRY.md`.
> If this v1.0 draft conflicts with those references, follow the canonical set.

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Motivation & Problem Statement](#2-motivation--problem-statement)
3. [Design Principles](#3-design-principles)
4. [Terminology](#4-terminology)
5. [Architecture Overview](#5-architecture-overview)
6. [Addressing & Identity](#6-addressing--identity)
7. [Cryptographic Model](#7-cryptographic-model)
8. [Envelope Specification](#8-envelope-specification)
9. [Envelope Types & Schemas](#9-envelope-types--schemas)
10. [Thread Model](#10-thread-model)
11. [Capability Tokens](#11-capability-tokens)
12. [Delegation Chains](#12-delegation-chains)
13. [Transport Layer](#13-transport-layer)
14. [Node Discovery & Federation](#14-node-discovery--federation)
15. [API Specification](#15-api-specification)
16. [Real-Time Protocol (WebSocket)](#16-real-time-protocol-websocket)
17. [Agent-Native Features](#17-agent-native-features)
18. [Composable Workflows](#18-composable-workflows)
19. [Email Bridge](#19-email-bridge)
20. [Security Model](#20-security-model)
21. [Error Handling](#21-error-handling)
22. [Compliance & Audit](#22-compliance--audit)
23. [Migration Guide](#23-migration-guide)
24. [Reference Implementation Notes](#24-reference-implementation-notes)
25. [Appendices](#25-appendices)

---

## 1. Abstract

**LOOM** (Linked Operations & Orchestrated Messaging) is an open communication protocol designed to replace email as the default asynchronous messaging system for the era of human-agent collaboration. It provides structured, cryptographically signed message exchange with first-class support for AI agents, composable conversation threading, delegation chains, and capability-based access control — while maintaining full backward compatibility with legacy email via a bidirectional bridge.

This document defines the complete wire format, transport mechanisms, identity model, API surface, and behavioral requirements for conforming LOOM implementations.

---

## 2. Motivation & Problem Statement

### 2.1 Why Email Fails the Agent Era

Email (SMTP/IMAP/POP3) was designed in the 1970s–1980s for human-to-human text communication. Its core assumptions no longer hold:

| Assumption | Reality in 2026 |
|------------|-----------------|
| Messages are written and read by humans | 40%+ of business messages are generated, triaged, or responded to by AI agents |
| Flat text is sufficient | Agents need structured data to act; humans need rich context |
| Identity is self-asserted | Spoofing, phishing, and impersonation are epidemic; SPF/DKIM/DMARC are bolt-on band-aids |
| Conversations are linear reply chains | Modern collaboration involves branching, delegation, multi-party handoffs |
| Delivery is fire-and-forget | Agents need real-time presence, state tracking, and composable workflows |

### 2.2 What LOOM Solves

LOOM is built from the ground up for a world where every person has one or more AI agents acting on their behalf, and where those agents need to communicate with both humans and other agents with full accountability, structured semantics, and cryptographic trust.

### 2.3 Prior Art

LOOM draws on lessons from:

- **SMTP/IMAP** — Federation model (MX/SRV records), universal addressing
- **Matrix** — Decentralized real-time communication, E2EE
- **ActivityPub** — Federated social protocol, JSON-LD linked data
- **OAuth 2.0 / GNAP** — Capability-based authorization, scoped tokens
- **Signal Protocol** — End-to-end encryption, forward secrecy
- **JSON-LD / Schema.org** — Structured linked data in human-readable contexts

LOOM is not a chat protocol. It is an **asynchronous-first, structured exchange protocol** that supports real-time extensions — closer to "email reimagined" than "Slack redesigned."

---

## 3. Design Principles

These principles guide every protocol decision. Implementations SHOULD adhere to these in spirit, not just in letter.

| # | Principle | Implication |
|---|-----------|-------------|
| P1 | **Agent-native, human-friendly** | Agents are first-class protocol participants with their own identity type, delegation rules, and structured intents. Humans never have to learn protocol internals — clients render everything as natural conversation. |
| P2 | **Structured by default** | Every envelope carries dual content: a human-readable layer AND a machine-parseable structured layer. No more regex-parsing HTML to find an invoice. |
| P3 | **Composable conversations** | Threads are directed acyclic graphs, not linear chains. Fork, merge, link, and delegate operations are protocol primitives. |
| P4 | **Identity & trust built-in** | Cryptographic identity, delegation chains, and capability tokens are core protocol — not bolted on after the fact. |
| P5 | **Federated by default** | Any domain can run a LOOM node. Discovery uses DNS. No central authority controls the network. |
| P6 | **Backward-compatible bridge** | LOOM nodes can send to and receive from email addresses during the transition. No one gets left behind. |
| P7 | **Privacy by design** | Mandatory transport encryption. Optional end-to-end encryption per thread. Minimal metadata exposure in federation. |
| P8 | **Audit everything** | Every envelope is signed. Every state change is recorded. Every delegation is traceable. |

---

## 4. Terminology

| Term | Definition |
|------|------------|
| **Envelope** | The fundamental message unit in LOOM. Replaces the email "message." Contains dual content, metadata, cryptographic signature, and capabilities. |
| **Thread** | An ordered, branching graph of envelopes representing a conversation or workflow. Replaces email's heuristic threading. |
| **Node** | A server that hosts LOOM identities, stores envelopes, and participates in federation. Analogous to an email server. |
| **Identity** | A cryptographic keypair + metadata representing a human, agent, team, or service in the LOOM network. |
| **Delegation** | A cryptographically signed grant from one identity to another (typically human → agent), specifying scoped permissions. |
| **Capability Token** | A fine-grained, scoped permission attached to a thread or envelope, controlling what actions a participant can perform. |
| **Intent** | The structured, machine-readable purpose of an envelope (e.g., `schedule.meeting`, `request.approval`). Lives in the `structured` content layer. |
| **Bridge** | A gateway component that translates between LOOM and legacy email (SMTP/IMAP) bidirectionally. |
| **Fork** | A sub-thread branching from a parent thread for side conversation or parallel work. |
| **Handoff** | Transfer of responsibility for a thread or task from one identity to another. |
| **Relay Mesh** | The federated routing layer through which nodes discover and communicate with each other. |
| **Envelope Store** | The persistent storage layer on a node where envelopes are indexed and retained. |
| **MUST / SHOULD / MAY** | As defined in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119). |

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
│   │ • API Server │       │ • API Server │       │ • API Server │            │
│   └──────┬───────┘       └──────┬───────┘       └──────┬───────┘            │
│          │                      │                      │                     │
│   ┌──────┴──────────────────────┴──────────────────────┴───────┐            │
│   │                    RELAY MESH (Federation)                  │            │
│   │         DNS-based discovery · Identity-routed delivery      │            │
│   └──────────────────────────┬─────────────────────────────────┘            │
│                              │                                               │
│   ┌──────────────────────────┴─────────────────────────────────┐            │
│   │                    EMAIL BRIDGE                             │            │
│   │       SMTP ↔ LOOM envelope translation (bidirectional)     │            │
│   └────────────────────────────────────────────────────────────┘            │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Component Responsibilities

#### LOOM Node

A LOOM Node is the fundamental operational unit. A conforming node MUST:

1. Host one or more **identities** (human, agent, team, or service)
2. Store and index **envelopes** in a durable Envelope Store
3. Expose the **LOOM API** over HTTP/2 with TLS 1.3
4. Publish **DNS discovery records** for federation
5. Validate **cryptographic signatures** on all inbound envelopes
6. Enforce **capability tokens** on thread operations
7. Verify **delegation chains** for agent-originated envelopes

A conforming node SHOULD:

1. Support **WebSocket** connections for real-time push
2. Run an **Email Bridge** for legacy interoperability
3. Implement **envelope retention policies** for storage management
4. Support **E2EE** for threads that request it

#### Relay Mesh

The federated routing layer. Nodes discover each other via DNS SRV records and exchange envelopes using identity-based routing. The relay mesh:

- Has **no central authority** — any domain can operate a node
- Routes envelopes by resolving the domain portion of the recipient's LOOM URI
- Supports **store-and-forward** for offline nodes (configurable TTL)
- Uses **mutual TLS** for node-to-node communication

#### Email Bridge

A gateway component (can be standalone or embedded in a node) that translates SMTP ↔ LOOM. Specified fully in [Section 19](#19-email-bridge).

---

## 6. Addressing & Identity

### 6.1 LOOM URI Format

All LOOM addresses use a URI scheme:

```
loom://{local}@{domain}[#{fragment}]
```

**Components:**

| Part | Required | Description | Example |
|------|----------|-------------|---------|
| `loom://` | Yes | Scheme identifier | — |
| `{local}` | Yes | Local part — user, agent, team, or service name | `almarion`, `assistant.almarion`, `billing` |
| `@` | Yes | Separator | — |
| `{domain}` | Yes | Domain of the hosting LOOM node | `cowork-os.com`, `acme.corp` |
| `#{fragment}` | No | Deep-link to a thread, envelope, or object | `#thr_01JMK8W`, `#invoice-q1` |

**Address examples:**

```
loom://almarion@cowork-os.com                    — Human identity
loom://assistant.almarion@cowork-os.com          — Agent scoped to a human
loom://research.assistant.almarion@cowork-os.com — Sub-agent (nested delegation)
loom://billing@acme.corp                      — Team/role address
loom://ci-bot@acme.corp                       — Service identity
loom://almarion@cowork-os.com#thr_01JMK8W        — Deep-link to a specific thread
bridge://alice@gmail.com                      — Bridged email identity
```

**Rules:**

- Local parts MUST match `[a-z0-9][a-z0-9._-]{0,63}`
- Agent scoping uses `.` as the hierarchy separator (e.g., `agent.human`)
- The `bridge://` scheme is reserved for email-bridged identities
- Fragment identifiers are client-side references and are NOT transmitted in envelopes
- Addresses are treated case-insensitively and serialized to canonical lowercase form on wire.

### 6.2 Identity Document

Every LOOM identity resolves to an **Identity Document** — a JSON object published at a well-known endpoint and/or retrievable via the LOOM API.

```json
{
  "loom": "1.0",
  "id": "loom://almarion@cowork-os.com",
  "type": "human",
  "display_name": "Almarion",
  "node": "cowork-os.com",
  "created_at": "2026-01-15T10:00:00Z",
  "public_keys": {
    "signing": {
      "algorithm": "Ed25519",
      "key_id": "k_sign_01JMK...",
      "public_key": "base64url-encoded-public-key",
      "created_at": "2026-01-15T10:00:00Z",
      "expires_at": null
    },
    "encryption": {
      "algorithm": "X25519",
      "key_id": "k_enc_01JMK...",
      "public_key": "base64url-encoded-public-key",
      "created_at": "2026-01-15T10:00:00Z",
      "expires_at": null
    }
  },
  "delegations": [],
  "capabilities": ["send", "receive", "create_thread", "delegate"],
  "verified_bridges": {
    "email": "almarion@cowork-os.com"
  },
  "metadata": {
    "avatar_url": "https://cowork-os.com/avatars/Almarion.png",
    "timezone": "Europe/Lisbon",
    "locale": "en"
  }
}
```

### 6.3 Identity Types

| Type | Description | Requirements |
|------|-------------|--------------|
| `human` | A natural person | MUST have at least one signing keypair |
| `agent` | An AI agent acting on behalf of a human or organization | MUST have `delegator` field. MUST have bounded scope in delegation chain. MUST self-identify as `agent` — spoofing to `human` is a protocol violation. |
| `team` | A group address that routes to multiple identities | MUST have `members` list with roles. Envelopes addressed to a team are delivered to all members according to routing rules. |
| `service` | A non-agent automated system (CI bots, webhooks, etc.) | MUST have `operator` field (human or org responsible). |
| `bridge` | A proxied identity from a non-LOOM system | Created automatically by the Email Bridge. Limited capabilities (no delegation, no agent spawning). |

### 6.4 Agent Identity (Detailed)

Agent identities carry additional required fields:

```json
{
  "loom": "1.0",
  "id": "loom://assistant.almarion@cowork-os.com",
  "type": "agent",
  "display_name": "Almarion's Assistant",
  "node": "cowork-os.com",
  "delegator": "loom://almarion@cowork-os.com",
  "agent_info": {
    "model": "claude-opus-4",
    "provider": "anthropic",
    "version": "2026.02",
    "description": "Personal assistant for scheduling, triage, and communication"
  },
  "delegation_scope": ["read.*", "reply.routine", "task.create", "calendar.*"],
  "delegation_expires": "2026-06-01T00:00:00Z",
  "delegation_signature": "sig_EdDSA_...",
  "public_keys": {
    "signing": {
      "algorithm": "Ed25519",
      "key_id": "k_sign_agent_01JMK...",
      "public_key": "base64url-encoded-public-key"
    },
    "encryption": {
      "algorithm": "X25519",
      "key_id": "k_enc_agent_01JMK...",
      "public_key": "base64url-encoded-public-key"
    }
  },
  "capabilities": ["send", "receive", "reply"],
  "metadata": {
    "avatar_url": "https://cowork-os.com/avatars/assistant.png"
  }
}
```

**Agent identity rules:**

1. Agents MUST have `type: "agent"` — a node MUST reject envelopes from an agent claiming `type: "human"`
2. The `delegator` field MUST point to a valid, non-expired identity
3. The `delegation_signature` MUST be verifiable using the delegator's signing key
4. The `delegation_scope` defines the maximum permissions — the agent cannot exceed these
5. Sub-delegation is permitted: an agent MAY delegate to another agent, but the sub-delegation scope MUST be a strict subset of the parent delegation scope

---

## 7. Cryptographic Model

### 7.1 Algorithms

| Purpose | Algorithm | Key Size | Notes |
|---------|-----------|----------|-------|
| Envelope signing | Ed25519 | 256-bit | All envelopes MUST be signed |
| Identity signing | Ed25519 | 256-bit | Identity documents, delegation chains |
| Key exchange (E2EE) | X25519 | 256-bit | Diffie-Hellman for per-thread E2EE |
| Symmetric encryption (E2EE) | XChaCha20-Poly1305 | 256-bit | Authenticated encryption for E2EE content |
| Key derivation | HKDF-SHA-256 | — | Deriving per-thread symmetric keys |
| Content hashing | SHA-256 | — | Envelope content integrity |

### 7.2 Envelope Signing

Every envelope MUST be signed by the sender's Ed25519 signing key.

**Signing process:**

1. Serialize the envelope to canonical JSON (sorted keys, no whitespace, UTF-8)
2. Exclude the `signature` field itself from the serialized form
3. Sign the serialized bytes using Ed25519
4. Encode the signature as base64url
5. Set `signature.value` to the encoded signature
6. Set `signature.key_id` to the sender's signing key ID
7. Set `signature.algorithm` to `"Ed25519"`

**Verification process:**

1. Extract and remove the `signature` field
2. Re-serialize the envelope to canonical JSON
3. Resolve the sender's identity document
4. Look up the signing key by `key_id`
5. Verify the Ed25519 signature
6. If the sender is an agent, verify the full delegation chain (see [Section 12](#12-delegation-chains))

### 7.3 End-to-End Encryption (E2EE)

E2EE is **optional per thread**. When enabled:

1. Thread creator generates an ephemeral X25519 keypair
2. For each participant, compute a shared secret via X25519 DH
3. Derive a per-thread symmetric key using HKDF-SHA-256
4. Encrypt `content.human` and `content.structured` using XChaCha20-Poly1305
5. Envelope metadata (routing fields: `from`, `to`, `thread_id`, `type`) remains cleartext for routing
6. The encrypted content block replaces the cleartext content in the envelope:

```json
"content": {
  "encrypted": true,
  "algorithm": "XChaCha20-Poly1305",
  "key_exchange": "X25519",
  "sender_ephemeral_key": "base64url...",
  "nonce": "base64url...",
  "ciphertext": "base64url..."
}
```

### 7.4 Key Rotation

- Identities SHOULD rotate signing keys according to security policy and risk posture (for example routine hardening or compromise response)
- Old keys MUST be retained in the identity document (marked `retired`) for signature verification of historical envelopes
- Key rotation is announced via a signed `key_rotation` envelope to all active thread participants
- Nodes MUST cache identity documents and re-fetch when a `key_id` is unknown

---

## 8. Envelope Specification

### 8.1 Full Envelope Schema

```json
{
  "$schema": "https://loom-protocol.org/schema/envelope/v1.0.json",
  "loom": "1.0",
  "id": "env_{ULID}",
  "thread_id": "thr_{ULID}",
  "parent_id": "env_{ULID} | null",
  "type": "{envelope_type}",
  "from": {
    "identity": "loom://{local}@{domain}",
    "display": "{Human-readable name}",
    "key_id": "k_{...}",
    "type": "human | agent | team | service | bridge",
    "delegation_chain": "[ ...chain ] | null"
  },
  "to": [
    {
      "identity": "loom://{local}@{domain}",
      "role": "primary | cc | observer | bcc"
    }
  ],
  "created_at": "{ISO 8601 timestamp}",
  "expires_at": "{ISO 8601 timestamp} | null",
  "priority": "low | normal | high | urgent",
  "content": {
    "human": {
      "text": "{Markdown-formatted text}",
      "format": "markdown | plaintext | html",
      "locale": "en | {BCP 47 tag}"
    },
    "structured": {
      "intent": "{namespace.action}",
      "parameters": {},
      "response_schema": "{schema_ref} | null"
    }
  },
  "attachments": [
    {
      "id": "att_{ULID}",
      "filename": "{name}",
      "mime_type": "{MIME type}",
      "size_bytes": 0,
      "hash": "sha256:{hex}",
      "url": "{download URL}",
      "inline": false
    }
  ],
  "references": {
    "in_reply_to": "env_{ULID} | null",
    "linked_envelopes": ["env_{ULID}"],
    "linked_threads": ["thr_{ULID}"],
    "external": [
      {
        "type": "url | email_message_id | issue | document",
        "ref": "{reference value}"
      }
    ]
  },
  "capabilities": ["reply", "forward", "delegate", "fork", "add_participant", "escalate"],
  "labels": ["{user-defined label}"],
  "signature": {
    "algorithm": "Ed25519",
    "key_id": "k_{...}",
    "value": "base64url..."
  },
  "meta": {
    "node_id": "{originating node}",
    "received_at": "{ISO 8601}",
    "bridge": {
      "source": "email | null",
      "original_message_id": "{Message-ID header} | null",
      "original_headers": {}
    }
  }
}
```

### 8.2 Field Requirements

| Field | Required | Description |
|-------|----------|-------------|
| `loom` | MUST | Protocol version. Currently `"1.0"`. |
| `id` | MUST | Globally unique envelope ID. Format: `env_` + ULID. |
| `thread_id` | MUST | Thread this envelope belongs to. If starting a new thread, generate a new `thr_` ULID. |
| `parent_id` | SHOULD | The envelope this is a direct reply to. `null` for thread roots. |
| `type` | MUST | One of the defined envelope types (see [Section 9](#9-envelope-types--schemas)). |
| `from` | MUST | Sender identity with signing key reference. |
| `to` | MUST | Array of recipients with roles. At least one `primary` recipient. |
| `created_at` | MUST | ISO 8601 timestamp of creation. |
| `expires_at` | MAY | Auto-expiry for ephemeral messages. Nodes SHOULD delete expired envelopes. |
| `priority` | SHOULD | Defaults to `normal` if omitted. |
| `content` | MUST | Dual content block. At minimum, `human` OR `structured` MUST be present. Both SHOULD be present. |
| `content.human` | SHOULD | Human-readable content. MUST be present for `message` type. |
| `content.structured` | SHOULD | Machine-readable intent. MUST be present for `task`, `approval`, `data`, `handoff` types. |
| `attachments` | MAY | Array of file attachments. |
| `references` | MAY | Links to related envelopes, threads, or external resources. |
| `capabilities` | SHOULD | What the sender permits recipients to do with this envelope. Defaults to `["reply"]` if omitted. |
| `labels` | MAY | User/agent-defined labels for categorization. |
| `signature` | MUST | Cryptographic signature over the canonical envelope. |
| `meta` | SHOULD | Node-level metadata. Not included in signature computation. |

### 8.3 ID Format

All LOOM IDs use the **ULID** (Universally Unique Lexicographically Sortable Identifier) format with a type prefix:

| Entity | Prefix | Example |
|--------|--------|---------|
| Envelope | `env_` | `env_01JMKB7X9Q2RVHF3KN4TYZPG` |
| Thread | `thr_` | `thr_01JMKB7W8P1QSGF2JM3SXYOR` |
| Attachment | `att_` | `att_01JMKB8A6D3NMHG5LP6UWBTK` |
| Capability Token | `cap_` | `cap_01JMKB9C4E5RPJH7MQ8VXCWL` |
| Signing Key | `k_sign_` | `k_sign_01JMKBA2F6GSNKJ9NR0WYDM` |
| Encryption Key | `k_enc_` | `k_enc_01JMKBB3G7HTPLK0PS1XZFN` |

### 8.4 Canonical JSON Serialization

For signature computation, envelopes are serialized to **canonical JSON**:

1. Keys sorted lexicographically at all nesting levels
2. No whitespace (no spaces, no newlines)
3. UTF-8 encoding
4. Numbers without leading zeros or trailing decimal points
5. `null` values included (not omitted)
6. The `signature` field and `meta` field are excluded from the canonical form

---

## 9. Envelope Types & Schemas

### 9.1 Type Registry

Each envelope type has a defined schema governing its `structured` content.

#### `message` — General Communication

The default type. Used for freeform conversation.

```json
{
  "type": "message",
  "content": {
    "human": {
      "text": "Hey, how's the Q1 report coming along?",
      "format": "markdown"
    },
    "structured": {
      "intent": "message.general@v1",
      "parameters": {
        "topic": "q1-report",
        "sentiment": "inquiry"
      }
    }
  }
}
```

**Rules:** `content.human` is REQUIRED. `content.structured` is OPTIONAL (but RECOMMENDED for agent interoperability).

#### `task` — Actionable Work Item

Tasks have a built-in state machine (see [Section 17.3](#173-task-state-machine)).

```json
{
  "type": "task",
  "content": {
    "human": {
      "text": "Please review this PR and approve by Friday.",
      "format": "markdown"
    },
    "structured": {
      "intent": "task.create",
      "parameters": {
        "title": "Review PR #247",
        "assignee": "loom://sarah@acme.corp",
        "due_date": "2026-02-20T17:00:00Z",
        "priority": "high",
        "state": "created",
        "linked_resource": "https://github.com/acme/app/pull/247"
      },
      "response_schema": "task.state_update"
    }
  }
}
```

**Rules:** `content.structured` is REQUIRED with `intent` starting with `task.*`. Valid task states: `created`, `assigned`, `accepted`, `in_progress`, `blocked`, `completed`, `failed`, `declined`, `cancelled`.

#### `approval` — Decision Request

```json
{
  "type": "approval",
  "content": {
    "human": {
      "text": "Expense report for $2,340 — client dinner + travel. Approve?",
      "format": "markdown"
    },
    "structured": {
      "intent": "approval.request",
      "parameters": {
        "item": "Expense Report #892",
        "amount": { "value": 2340, "currency": "USD" },
        "category": "client-entertainment",
        "options": ["approved", "rejected", "needs_revision"],
        "deadline": "2026-02-18T12:00:00Z"
      },
      "response_schema": "approval.response"
    }
  }
}
```

**Response schema:**
```json
{
  "intent": "approval.response",
  "parameters": {
    "decision": "approved | rejected | needs_revision",
    "reason": "Optional explanation",
    "conditions": ["Optional conditions if approved with caveats"]
  }
}
```

#### `event` — Calendar / Scheduling

```json
{
  "type": "event",
  "content": {
    "human": {
      "text": "Team sync — Wednesday 3pm. Agenda: Q1 numbers, hiring update.",
      "format": "markdown"
    },
    "structured": {
      "intent": "event.invite",
      "parameters": {
        "title": "Team Sync",
        "start": "2026-02-18T15:00:00Z",
        "end": "2026-02-18T16:00:00Z",
        "timezone": "Europe/Lisbon",
        "location": "https://meet.example.com/team-sync",
        "agenda": ["Q1 numbers review", "Hiring update"],
        "rsvp_options": ["accepted", "declined", "tentative"],
        "recurrence": "RRULE:FREQ=WEEKLY;BYDAY=WE"
      },
      "response_schema": "event.rsvp"
    }
  }
}
```

#### `notification` — Status Update (No Reply Expected)

```json
{
  "type": "notification",
  "content": {
    "human": {
      "text": "✅ Deployment v2.4.1 completed successfully. 0 errors, 3 warnings.",
      "format": "markdown"
    },
    "structured": {
      "intent": "notification.system",
      "parameters": {
        "category": "deployment",
        "status": "success",
        "details": {
          "version": "2.4.1",
          "errors": 0,
          "warnings": 3,
          "duration_seconds": 142
        }
      }
    }
  },
  "capabilities": []
}
```

**Rules:** `capabilities` SHOULD be empty (no reply expected). Clients MAY render these with reduced prominence.

#### `handoff` — Transfer of Responsibility

```json
{
  "type": "handoff",
  "content": {
    "human": {
      "text": "Transferring this customer inquiry to the billing team. Context attached.",
      "format": "markdown"
    },
    "structured": {
      "intent": "handoff.transfer",
      "parameters": {
        "from_identity": "loom://support-agent@acme.corp",
        "to_identity": "loom://billing@acme.corp",
        "reason": "Billing-specific inquiry beyond support scope",
        "context_thread": "thr_01JMKB7W...",
        "preserve_history": true,
        "urgency": "normal"
      }
    }
  }
}
```

#### `data` — Structured Data Exchange

```json
{
  "type": "data",
  "content": {
    "human": {
      "text": "Here's the Q1 revenue breakdown as requested.",
      "format": "markdown"
    },
    "structured": {
      "intent": "data.deliver",
      "parameters": {
        "schema": "finance.revenue_report",
        "data": {
          "period": "Q1-2026",
          "total_revenue": 1250000,
          "currency": "USD",
          "breakdown": [
            { "category": "subscriptions", "amount": 890000 },
            { "category": "services", "amount": 310000 },
            { "category": "other", "amount": 50000 }
          ]
        }
      }
    }
  }
}
```

#### `receipt` — Delivery / Read / Action Confirmation

```json
{
  "type": "receipt",
  "content": {
    "structured": {
      "intent": "receipt.action",
      "parameters": {
        "receipt_type": "delivered | read | processed | failed",
        "envelope_id": "env_01JMKB7X...",
        "timestamp": "2026-02-16T17:05:00Z",
        "details": "Invoice processed and payment queued"
      }
    }
  }
}
```

**Rules:** `content.human` is OPTIONAL for receipts. `content.structured` is REQUIRED.

### 9.2 Custom Types

Implementations MAY define custom envelope types using a namespaced format:

```
x-{vendor}.{type_name}
```

Example: `x-acme.purchase_order`, `x-cowork.agent_heartbeat`

Custom types MUST still conform to the base envelope schema. Nodes that receive unknown types MUST accept them but MAY render them as generic messages.

---

## 10. Thread Model

### 10.1 Thread Structure

A Thread is a **directed acyclic graph (DAG)** of envelopes, rooted at a single root envelope.

```json
{
  "id": "thr_{ULID}",
  "root_envelope_id": "env_{ULID}",
  "subject": "{Thread subject}",
  "state": "active | resolved | archived | locked",
  "created_at": "{ISO 8601}",
  "updated_at": "{ISO 8601}",
  "participants": [
    {
      "identity": "loom://{local}@{domain}",
      "role": "owner | participant | observer",
      "joined_at": "{ISO 8601}",
      "left_at": "{ISO 8601} | null",
      "capabilities": ["reply", "delegate", "fork"]
    }
  ],
  "labels": ["{label}"],
  "forks": [
    {
      "fork_id": "thr_{ULID}",
      "forked_from": "env_{ULID}",
      "state": "active | resolved | merged",
      "subject": "{Fork subject}"
    }
  ],
  "linked_threads": [
    {
      "thread_id": "thr_{ULID}",
      "relation": "related | blocks | blocked_by | parent | child"
    }
  ],
  "schema": "{primary intent schema} | null",
  "encryption": {
    "enabled": false,
    "algorithm": "XChaCha20-Poly1305 | null",
    "key_epoch": 0
  }
}
```

### 10.2 Thread Operations

| Operation | Description | Authorization Required |
|-----------|-------------|----------------------|
| **Create** | Start a new thread by sending a root envelope | `create_thread` capability on sender identity |
| **Reply** | Add an envelope to a thread | `reply` capability token in thread |
| **Fork** | Create a sub-thread branching from an envelope | `fork` capability token in thread |
| **Merge** | Bring a fork's resolution back into the parent thread | `owner` role in parent thread |
| **Link** | Cross-reference another thread without merging | `reply` capability in both threads |
| **Delegate** | Transfer thread ownership to another identity | `owner` role in thread |
| **Add Participant** | Add a new identity to the thread | `add_participant` capability token |
| **Remove Participant** | Remove an identity from the thread | `owner` role in thread |
| **Resolve** | Mark thread as resolved/complete | `owner` or `participant` role |
| **Archive** | Archive a resolved thread | `owner` role in thread |
| **Lock** | Prevent further replies (except by owner) | `owner` role in thread |

### 10.3 Thread State Transitions

```
┌──────────┐     reply/fork     ┌──────────┐     resolve     ┌───────────┐     archive     ┌───────────┐
│  ACTIVE  │ ←──────────────── │  ACTIVE   │ ──────────────► │  RESOLVED  │ ──────────────► │  ARCHIVED  │
└──────────┘                   └──────────┘                  └───────────┘                  └───────────┘
      │                              │                              │
      │           lock               │                              │   reopen
      ▼                              ▼                              ▼
┌──────────┐                   (continued                    ┌──────────┐
│  LOCKED  │                    activity)                    │  ACTIVE   │
└──────────┘                                                └──────────┘
```

### 10.4 Thread Addressing

Threads can be addressed directly using fragment identifiers:

```
loom://almarion@cowork-os.com#thr_01JMKB7W8P
```

This is a client-side convenience — the node resolves the identity and then looks up the thread in the local store.

---

## 11. Capability Tokens

### 11.1 Token Structure

Capability tokens are fine-grained, scoped permissions that control what actions participants can perform on threads and envelopes.

```json
{
  "id": "cap_{ULID}",
  "grants": ["reply", "add_participant"],
  "scope": {
    "thread_id": "thr_{ULID}",
    "envelope_types": ["message", "task"],
    "max_depth": 10
  },
  "issued_by": "loom://{identity}",
  "issued_to": "loom://{identity}",
  "created_at": "{ISO 8601}",
  "expires_at": "{ISO 8601} | null",
  "single_use": false,
  "revoked": false,
  "signature": "sig_EdDSA_..."
}
```

### 11.2 Available Grants

| Grant | Description |
|-------|-------------|
| `reply` | Send envelopes to this thread |
| `forward` | Share this thread/envelope with identities not in the thread |
| `delegate` | Transfer thread ownership |
| `fork` | Create sub-threads from envelopes |
| `add_participant` | Invite new identities to the thread |
| `remove_participant` | Remove identities from the thread |
| `escalate` | Elevate priority or route to a supervisor |
| `resolve` | Mark the thread as resolved |
| `archive` | Archive a resolved thread |
| `read` | Read envelopes in the thread (for observer roles) |
| `label` | Add/remove labels |
| `admin` | Full control (superset of all grants) |

### 11.3 Token Lifecycle

1. **Creation** — The thread owner (or a participant with `admin` grant) creates a capability token
2. **Distribution** — The token is included in the `capabilities` field when adding a participant
3. **Validation** — On every operation, the node validates the actor's capability token against the requested action
4. **Expiry** — Tokens with `expires_at` are automatically invalidated after that time
5. **Revocation** — The issuer can revoke a token at any time; a `capability.revoked` event is broadcast to the thread

---

## 12. Delegation Chains

### 12.1 How Delegation Works

Delegation is the mechanism by which humans authorize agents (and agents authorize sub-agents) to act on their behalf within the LOOM network.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DELEGATION CHAIN                                │
│                                                                        │
│   Human (Almarion)                                                        │
│   loom://almarion@cowork-os.com                                          │
│   scope: * (root authority)                                            │
│        │                                                               │
│        │  DELEGATES (signed)                                           │
│        ▼                                                               │
│   Agent (Almarion's Assistant)                                            │
│   loom://assistant.almarion@cowork-os.com                                │
│   scope: [read.*, reply.routine, task.create, calendar.*]             │
│   expires: 2026-06-01                                                  │
│        │                                                               │
│        │  SUB-DELEGATES (signed, scope ⊂ parent)                      │
│        ▼                                                               │
│   Sub-Agent (Calendar Specialist)                                      │
│   loom://cal.assistant.almarion@cowork-os.com                            │
│   scope: [calendar.schedule, calendar.read]                           │
│   expires: 2026-02-28, single_use: false                              │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### 12.2 Delegation Object

```json
{
  "delegator": "loom://almarion@cowork-os.com",
  "delegate": "loom://assistant.almarion@cowork-os.com",
  "scope": ["read.*", "reply.routine", "task.create", "calendar.*"],
  "created_at": "2026-01-15T10:00:00Z",
  "expires_at": "2026-06-01T00:00:00Z",
  "revocable": true,
  "allow_sub_delegation": true,
  "max_sub_delegation_depth": 2,
  "signature": "sig_EdDSA_..."
}
```

### 12.3 Scope Syntax

Scopes use a dot-separated namespace with wildcard support:

```
read.*              — All read operations
reply.routine       — Reply to routine/non-sensitive threads
reply.*             — Reply to any thread
task.create         — Create new tasks
task.*              — All task operations
calendar.schedule   — Schedule calendar events
calendar.*          — All calendar operations
*                   — Full access (root delegation only)
```

**Rules:**

- Sub-delegations MUST be strict subsets: if an agent has `calendar.*`, it can sub-delegate `calendar.schedule` but NOT `task.create`
- Wildcard `*` at the root level is only valid for the initial human → agent delegation
- Scope violations cause the entire delegation chain to be rejected

### 12.4 Chain Verification

When a node receives an envelope from an agent, it MUST:

1. Extract the `delegation_chain` from the `from` field
2. Verify each link in the chain:
   a. The delegator's signature is valid
   b. The delegation has not expired
   c. The delegation has not been revoked
   d. Each sub-delegation scope is a subset of its parent
3. Verify the envelope's action falls within the leaf delegation's scope
4. If any check fails, reject the envelope with error `DELEGATION_INVALID`

### 12.5 Revocation

Delegation revocations are broadcast via a signed `delegation.revoked` event:

```json
{
  "type": "notification",
  "content": {
    "structured": {
      "intent": "delegation.revoked",
      "parameters": {
        "delegator": "loom://almarion@cowork-os.com",
        "delegate": "loom://assistant.almarion@cowork-os.com",
        "revoked_at": "2026-02-16T18:00:00Z",
        "reason": "Agent compromised"
      }
    }
  }
}
```

Nodes MUST maintain a **revocation list** and check it during delegation chain verification.

---

## 13. Transport Layer

### 13.1 Requirements

| Requirement | Specification |
|-------------|---------------|
| Base protocol | HTTP/2 over TLS 1.3 |
| TLS version | TLS 1.3 REQUIRED. TLS 1.2 and below MUST be rejected. |
| Certificate | Valid certificate from a trusted CA. Self-signed certificates MUST NOT be accepted in production federation. |
| Cipher suites | TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256 |
| Real-time | WebSocket over TLS (wss://) for push, presence, and streaming |
| Content type | `application/json; charset=utf-8` for all API requests/responses |
| Compression | `gzip` or `br` (Brotli) SHOULD be used for bodies > 1KB |

### 13.2 Connection Flow

```
Client                                   Node
  │                                        │
  │──── TLS 1.3 Handshake ───────────────►│
  │◄─── Server Certificate ──────────────│
  │                                        │
  │──── HTTP/2 Connection ───────────────►│
  │     (ALPN: h2)                         │
  │                                        │
  │──── POST /v1/auth/token ────────────►│
  │     { identity, proof_of_key }         │
  │◄─── { access_token, refresh_token } ──│
  │                                        │
  │──── Authenticated API calls ─────────►│
  │     Authorization: Bearer {token}      │
  │                                        │
  │──── Upgrade to WebSocket (optional) ─►│
  │◄──► Real-time bidirectional stream ──►│
```

### 13.3 Authentication

LOOM uses **cryptographic proof-of-key** for authentication (no passwords):

1. Client presents its LOOM identity and signing key ID
2. Server sends a challenge nonce
3. Client signs the nonce with its Ed25519 key
4. Server verifies the signature against the identity's published public key
5. Server issues a short-lived access token (JWT, 1h TTL) and a refresh token (30d TTL)

```json
// POST /v1/auth/challenge
{
  "identity": "loom://almarion@cowork-os.com",
  "key_id": "k_sign_01JMK..."
}

// Response
{
  "challenge": "base64url-random-nonce",
  "expires_in": 60
}

// POST /v1/auth/token
{
  "identity": "loom://almarion@cowork-os.com",
  "key_id": "k_sign_01JMK...",
  "challenge": "base64url-random-nonce",
  "signature": "base64url-ed25519-signature"
}

// Response
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "rt_01JMK..."
}
```

### 13.4 Rate Limiting

Nodes MUST implement rate limiting to prevent abuse:

| Endpoint | Default Limit |
|----------|---------------|
| `POST /v1/envelopes` | 100/minute per identity |
| `POST /v1/auth/*` | 10/minute per IP |
| `GET /v1/threads/*` | 300/minute per identity |
| WebSocket messages | 60/minute per connection |
| Federation relay | 1000/minute per node |

Rate limit headers:

```
X-LOOM-RateLimit-Limit: 100
X-LOOM-RateLimit-Remaining: 87
X-LOOM-RateLimit-Reset: 1708100000
```

---

## 14. Node Discovery & Federation

### 14.1 DNS-Based Discovery

Nodes advertise their presence using DNS records, similar to email's MX records:

**SRV Record:**
```
_loom._tcp.cowork-os.com.  3600  IN  SRV  10 0 443 loom.cowork-os.com.
```

**TXT Record (additional metadata):**
```
_loom.cowork-os.com.  3600  IN  TXT  "v=LOOM1; api=https://loom.cowork-os.com/v1; ws=wss://loom.cowork-os.com/ws; keys=https://loom.cowork-os.com/.well-known/loom-keys"
```

### 14.2 Well-Known Endpoint

Every LOOM node MUST serve a discovery document at:

```
GET https://{domain}/.well-known/loom.json
```

```json
{
  "loom_version": "1.0",
  "node_id": "node_01JMK...",
  "domain": "cowork-os.com",
  "api_url": "https://loom.cowork-os.com/v1",
  "websocket_url": "wss://loom.cowork-os.com/ws",
  "public_keys_url": "https://loom.cowork-os.com/.well-known/loom-keys",
  "capabilities": ["federation", "bridge.email", "e2ee", "webhooks"],
  "admin_contact": "loom://admin@cowork-os.com",
  "federation_policy": {
    "open": true,
    "allowlist": [],
    "denylist": []
  }
}
```

### 14.3 Federation Envelope Routing

When a node receives an envelope destined for a remote identity:

1. Extract the domain from the recipient's LOOM URI
2. Look up `_loom._tcp.{domain}` SRV record
3. Fallback: fetch `https://{domain}/.well-known/loom.json`
4. Establish mutual TLS connection to the remote node
5. POST the envelope to the remote node's federation endpoint
6. Receive delivery receipt or store-and-forward acknowledgment

```
POST /v1/federation/deliver
Authorization: Node-Auth {mutual_tls_identity}

{
  "envelopes": [ ... ],
  "sender_node": "cowork-os.com",
  "timestamp": "2026-02-16T17:00:00Z",
  "signature": "sig_EdDSA_..."
}
```

### 14.4 Store-and-Forward

If the recipient node is temporarily unreachable:

1. The sending node queues the envelope with an exponential backoff retry schedule
2. Default TTL: 72 hours (configurable per node)
3. After TTL expiry, a `delivery.failed` receipt is generated and returned to the sender
4. Nodes SHOULD support a configurable queue depth to prevent resource exhaustion

---

## 15. API Specification

### 15.1 Base URL

```
https://{node_domain}/v1
```

### 15.2 Endpoints

#### Envelopes

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/envelopes` | Send a new envelope |
| `GET` | `/v1/envelopes/{id}` | Retrieve a specific envelope |
| `DELETE` | `/v1/envelopes/{id}` | Retract an envelope (if within retraction window) |

**Send Envelope:**

```http
POST /v1/envelopes
Authorization: Bearer {token}
Content-Type: application/json

{
  "thread_id": "thr_01JMKB7W...",
  "parent_id": "env_01JMKB7X...",
  "type": "message",
  "to": [
    { "identity": "loom://sarah@acme.corp", "role": "primary" }
  ],
  "content": {
    "human": { "text": "Sounds good, let's go with Wednesday.", "format": "markdown" },
    "structured": { "intent": "event.confirm", "parameters": { "date": "2026-02-18" } }
  },
  "capabilities": ["reply", "fork"]
}
```

**Response:**

```http
HTTP/2 201 Created
Location: /v1/envelopes/env_01JMKB9X...

{
  "id": "env_01JMKB9X...",
  "thread_id": "thr_01JMKB7W...",
  "created_at": "2026-02-16T17:10:00Z",
  "status": "delivered",
  "delivery": [
    { "identity": "loom://sarah@acme.corp", "status": "delivered", "node": "acme.corp" }
  ]
}
```

#### Threads

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/threads` | List threads for the authenticated identity |
| `GET` | `/v1/threads/{id}` | Get thread details |
| `GET` | `/v1/threads/{id}/envelopes` | List envelopes in a thread |
| `PATCH` | `/v1/threads/{id}` | Update thread (state, labels, participants) |
| `POST` | `/v1/threads/{id}/fork` | Fork a thread |
| `POST` | `/v1/threads/{id}/merge` | Merge a fork back |
| `POST` | `/v1/threads/{id}/participants` | Add a participant |
| `DELETE` | `/v1/threads/{id}/participants/{identity}` | Remove a participant |

**List Threads:**

```http
GET /v1/threads?state=active&limit=20&offset=0&sort=updated_at&order=desc
Authorization: Bearer {token}
```

**Response:**

```json
{
  "threads": [
    {
      "id": "thr_01JMKB7W...",
      "subject": "Q1 Invoice Request",
      "state": "active",
      "updated_at": "2026-02-16T17:10:00Z",
      "participant_count": 3,
      "envelope_count": 7,
      "unread_count": 2,
      "last_envelope": {
        "id": "env_01JMKB9X...",
        "from": "loom://billing@acme.corp",
        "preview": "Invoice attached. Please review...",
        "created_at": "2026-02-16T17:10:00Z"
      }
    }
  ],
  "pagination": {
    "total": 142,
    "limit": 20,
    "offset": 0,
    "has_more": true
  }
}
```

#### Identity

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/identity/{loom_uri}` | Resolve an identity document |
| `GET` | `/v1/identity/me` | Get authenticated identity |
| `PATCH` | `/v1/identity/me` | Update display name, metadata, etc. |
| `POST` | `/v1/identity/me/keys/rotate` | Rotate signing/encryption keys |

#### Delegations

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/delegations` | Create a new delegation |
| `GET` | `/v1/delegations` | List active delegations |
| `DELETE` | `/v1/delegations/{id}` | Revoke a delegation |

#### Capabilities

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/capabilities` | Issue a new capability token |
| `GET` | `/v1/capabilities?thread_id={id}` | List tokens for a thread |
| `DELETE` | `/v1/capabilities/{id}` | Revoke a capability token |

#### Search

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/search` | Full-text + structured search across threads and envelopes |

```http
GET /v1/search?q=invoice&type=task&state=active&from=loom://billing@acme.corp&after=2026-01-01
```

```json
{
  "results": [
    {
      "type": "envelope",
      "envelope": { "id": "env_...", "preview": "...", "thread_id": "thr_..." },
      "score": 0.95,
      "highlights": ["Please send the Q1 <mark>invoice</mark> when ready."]
    }
  ],
  "total": 3,
  "took_ms": 42
}
```

### 15.3 Pagination

All list endpoints support cursor-based or offset-based pagination:

```
?limit=20&offset=0        — Offset-based (simple, not recommended for large sets)
?limit=20&cursor=eyJ...   — Cursor-based (preferred, consistent under concurrent writes)
```

### 15.4 Filtering & Sorting

Standard query parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | int | Max results (default: 20, max: 100) |
| `offset` | int | Offset for pagination |
| `cursor` | string | Cursor for cursor-based pagination |
| `sort` | string | Field to sort by (e.g., `created_at`, `updated_at`) |
| `order` | string | `asc` or `desc` |
| `state` | string | Filter by state |
| `type` | string | Filter by envelope type |
| `from` | string | Filter by sender identity |
| `after` | ISO 8601 | Only results after this timestamp |
| `before` | ISO 8601 | Only results before this timestamp |

---

## 16. Real-Time Protocol (WebSocket)

### 16.1 Connection

```
wss://{node_domain}/ws?token={access_token}
```

After connection, the client sends a subscription message:

```json
{
  "action": "subscribe",
  "channels": [
    { "type": "thread", "id": "thr_01JMKB7W..." },
    { "type": "identity", "id": "loom://almarion@cowork-os.com" },
    { "type": "all_threads" }
  ]
}
```

### 16.2 Server-Pushed Events

```json
{
  "event": "envelope.new",
  "data": {
    "id": "env_01JMKB9X...",
    "thread_id": "thr_01JMKB7W...",
    "type": "message",
    "from": {
      "identity": "loom://sarah@acme.corp",
      "display": "Sarah"
    },
    "preview": "Invoice attached, please review.",
    "created_at": "2026-02-16T17:10:00Z"
  }
}
```

### 16.3 Event Types

| Event | Description |
|-------|-------------|
| `envelope.new` | New envelope in a subscribed thread |
| `envelope.retracted` | Envelope was retracted by sender |
| `thread.updated` | Thread metadata changed (state, labels, participants) |
| `thread.fork` | A fork was created from a subscribed thread |
| `thread.merged` | A fork was merged back |
| `participant.joined` | New participant added to a thread |
| `participant.left` | Participant removed from a thread |
| `presence.update` | Identity presence/status changed |
| `capability.revoked` | A capability token was revoked |
| `delegation.revoked` | A delegation was revoked |
| `typing.start` | Identity started composing in a thread |
| `typing.stop` | Identity stopped composing |
| `receipt.delivered` | Envelope was delivered to recipient |
| `receipt.read` | Envelope was read by recipient |

### 16.4 Presence

Identities MAY broadcast presence:

```json
{
  "action": "presence.update",
  "data": {
    "identity": "loom://assistant.almarion@cowork-os.com",
    "status": "available | busy | away | offline",
    "response_time": "instant | minutes | hours | days",
    "capabilities_active": ["reply.routine", "task.triage", "calendar.read"],
    "load": 0.3,
    "custom_status": "Processing Q1 reports"
  }
}
```

### 16.5 Heartbeat

Clients MUST send a ping every 30 seconds. The server responds with pong. Connections without a ping for 90 seconds are terminated.

```json
{ "action": "ping", "ts": 1708099800 }
{ "event": "pong", "ts": 1708099800 }
```

---

## 17. Agent-Native Features

### 17.1 Structured Intents

The `structured` content layer uses a namespace-based intent system that enables agents to understand and respond to envelopes without natural language processing:

**Intent namespaces:**

| Namespace | Description | Examples |
|-----------|-------------|---------|
| `message.*` | General messages | `message.general@v1`, `message.question@v1`, `message.reply@v1` |
| `task.*` | Task lifecycle | `task.create@v1`, `task.assign@v1`, `task.update@v1`, `task.complete@v1` |
| `approval.*` | Approval workflows | `approval.request@v1`, `approval.response@v1` |
| `schedule.*` | Scheduling | `schedule.meeting@v1`, `schedule.propose_times@v1`, `schedule.confirm@v1` |
| `event.*` | Calendar events | `event.invite@v1`, `event.rsvp@v1`, `event.cancel@v1` |
| `data.*` | Data exchange | `data.request@v1`, `data.deliver@v1`, `data.query@v1` |
| `handoff.*` | Responsibility transfer | `handoff.transfer@v1`, `handoff.accept@v1`, `handoff.reject@v1` |
| `notification.*` | Status updates | `notification.system@v1`, `notification.alert@v1`, `notification.digest@v1` |
| `delegation.*` | Delegation management | `delegation.grant@v1`, `delegation.revoked@v1`, `delegation.request@v1` |

The `response_schema` field in structured content tells the recipient exactly what format is expected in reply, enabling zero-ambiguity agent-to-agent communication.

### 17.2 Agent Self-Identification

When an agent sends an envelope, the `from` block MUST include:

```json
"from": {
  "identity": "loom://assistant.almarion@cowork-os.com",
  "display": "Almarion's Assistant",
  "key_id": "k_sign_agent_01JMK...",
  "type": "agent",
  "delegation_chain": [
    {
      "delegator": "loom://almarion@cowork-os.com",
      "scope": ["read.*", "reply.routine"],
      "signature": "sig_EdDSA_..."
    }
  ]
}
```

**Protocol rules:**

1. Agents MUST set `type: "agent"` in the `from` block
2. Nodes MUST reject envelopes where the `from.type` doesn't match the identity document's `type`
3. Clients SHOULD visually distinguish agent-sent envelopes from human-sent ones
4. The full delegation chain MUST be included so recipients can verify authority

### 17.3 Task State Machine

`task`-type envelopes have a built-in state machine with defined transitions:

```
                            ┌─────────────┐
                            │   CREATED    │
                            └──────┬──────┘
                                   │
                              assign │
                                   ▼
                            ┌─────────────┐
                      ┌─────│  ASSIGNED    │─────┐
                      │     └──────┬──────┘     │
                 decline│          │ accept      │ cancel
                      │          │              │
                      ▼          ▼              ▼
               ┌──────────┐ ┌─────────────┐ ┌───────────┐
               │ DECLINED  │ │  ACCEPTED   │ │ CANCELLED  │
               └──────────┘ └──────┬──────┘ └───────────┘
                                   │
                              start │
                                   ▼
                            ┌─────────────┐
                      ┌─────│ IN_PROGRESS  │─────┐
                      │     └──────┬──────┘     │
                  block│           │ complete    │ fail
                      │          │              │
                      ▼          ▼              ▼
               ┌──────────┐ ┌─────────────┐ ┌──────────┐
               │  BLOCKED  │ │  COMPLETED  │ │  FAILED   │
               └─────┬────┘ └─────────────┘ └──────────┘
                     │
                unblock
                     │
                     ▼
               ┌─────────────┐
               │ IN_PROGRESS  │
               └─────────────┘
```

**State transition rules:**

| From | To | Trigger | Who Can Trigger |
|------|----|---------|----------------|
| `created` | `assigned` | Assign to identity | Thread owner, task creator |
| `assigned` | `accepted` | Assignee accepts | Assignee |
| `assigned` | `declined` | Assignee declines | Assignee |
| `assigned` | `cancelled` | Creator cancels | Task creator, thread owner |
| `accepted` | `in_progress` | Work begins | Assignee |
| `in_progress` | `completed` | Work finished | Assignee |
| `in_progress` | `failed` | Work cannot complete | Assignee |
| `in_progress` | `blocked` | Dependency blocks progress | Assignee |
| `blocked` | `in_progress` | Block resolved | Assignee, thread owner |

Each transition generates a new envelope in the task's thread with `intent: "task.state_update"`, creating a full audit trail.

### 17.4 Agent Negotiation

When multiple agents are participants in a thread, they can negotiate task assignment using presence and capability data:

```json
{
  "type": "message",
  "content": {
    "structured": {
      "intent": "agent.negotiate",
      "parameters": {
        "task_id": "env_01JMKB...",
        "claim": true,
        "fitness_score": 0.92,
        "estimated_completion": "2026-02-16T18:00:00Z",
        "required_capabilities": ["calendar.schedule"],
        "current_load": 0.3
      }
    }
  }
}
```

This enables **automatic task routing** — a coordinator agent can broadcast a task requirement, and specialist agents bid based on their availability and fitness.

---

## 18. Composable Workflows

### 18.1 Workflow Envelope

Workflows are multi-step processes defined as special envelopes:

```json
{
  "type": "workflow",
  "content": {
    "human": {
      "text": "Expense approval → payment processing → notification workflow",
      "format": "markdown"
    },
    "structured": {
      "intent": "workflow.execute",
      "parameters": {
        "workflow_id": "wf_01JMK...",
        "name": "Expense Approval Pipeline",
        "steps": [
          {
            "id": "step_1",
            "action": "approval.request",
            "to": "loom://manager@acme.corp",
            "parameters": {
              "item": "Expense Report #892",
              "amount": { "value": 2340, "currency": "USD" }
            },
            "on_success": "step_2",
            "on_failure": "step_abort",
            "timeout": "48h"
          },
          {
            "id": "step_2",
            "action": "task.execute",
            "to": "loom://finance-bot@acme.corp",
            "parameters": {
              "action": "process_payment",
              "amount": { "value": 2340, "currency": "USD" },
              "expense_id": "exp_892"
            },
            "on_success": "step_3",
            "on_failure": "step_error_notify"
          },
          {
            "id": "step_3",
            "action": "notification",
            "to": "loom://almarion@cowork-os.com",
            "parameters": {
              "template": "expense_processed",
              "data": { "expense_id": "exp_892", "status": "paid" }
            }
          },
          {
            "id": "step_abort",
            "action": "notification",
            "to": "loom://almarion@cowork-os.com",
            "parameters": {
              "template": "expense_rejected",
              "data": { "expense_id": "exp_892" }
            }
          },
          {
            "id": "step_error_notify",
            "action": "notification",
            "to": ["loom://almarion@cowork-os.com", "loom://finance-admin@acme.corp"],
            "parameters": {
              "template": "payment_failed",
              "data": { "expense_id": "exp_892" }
            }
          }
        ]
      }
    }
  }
}
```

### 18.2 Workflow State Tracking

Each workflow step generates envelopes in a dedicated workflow thread, providing full visibility:

| Step State | Meaning |
|------------|---------|
| `pending` | Not yet started |
| `active` | Currently executing |
| `waiting` | Waiting for external response (e.g., human approval) |
| `completed` | Successfully finished |
| `failed` | Failed (may trigger error branch) |
| `skipped` | Skipped due to conditional logic |
| `timed_out` | Exceeded timeout |

### 18.3 Conditional Logic

Workflow steps support conditions:

```json
{
  "id": "step_2",
  "action": "task.execute",
  "condition": {
    "field": "step_1.result.decision",
    "operator": "eq",
    "value": "approved"
  },
  "to": "loom://finance-bot@acme.corp",
  "on_success": "step_3",
  "on_condition_unmet": "step_abort"
}
```

---

## 19. Email Bridge

### 19.1 Architecture

```
┌─────────────────┐         ┌──────────────────────────┐         ┌─────────────────┐
│   Email World    │         │      EMAIL BRIDGE         │         │   LOOM World    │
│                  │         │                           │         │                 │
│  alice@gmail.com │──SMTP──►│  ┌──────────────────┐   │         │ loom://almarion@   │
│                  │         │  │ Inbound Gateway   │───┼──LOOM──►│ cowork-os.com   │
│                  │         │  │ • SMTP receiver    │   │         │                 │
│                  │         │  │ • SPF/DKIM verify  │   │         │                 │
│                  │         │  │ • MIME → Envelope  │   │         │                 │
│                  │         │  │ • Intent extraction│   │         │                 │
│                  │         │  └──────────────────┘   │         │                 │
│                  │         │                           │         │                 │
│                  │◄──SMTP──│  ┌──────────────────┐   │         │                 │
│                  │         │  │ Outbound Gateway  │◄──┼──LOOM──│                 │
│                  │         │  │ • Envelope → MIME  │   │         │                 │
│                  │         │  │ • HTML rendering   │   │         │                 │
│                  │         │  │ • SPF/DKIM signing │   │         │                 │
│                  │         │  │ • JSON-LD headers  │   │         │                 │
│                  │         │  └──────────────────┘   │         │                 │
│                  │         │                           │         │                 │
└─────────────────┘         └──────────────────────────┘         └─────────────────┘
```

### 19.2 Inbound: Email → LOOM

When an email arrives at the bridge:

1. **Receive** via SMTP on the bridge domain
2. **Verify** SPF, DKIM, DMARC records — results stored in envelope metadata
3. **Parse** MIME structure: extract text/plain, text/html, attachments
4. **Create bridge identity** for the sender: `bridge://alice@gmail.com`
5. **Extract intent** (best-effort, AI-assisted):
   - Analyze subject line and body for structured intent
   - Map to closest LOOM intent namespace
   - If extraction confidence is low, set `intent: "message.general@v1"` with `extraction_confidence: 0.3`
6. **Generate LOOM envelope** with:
   - `from`: bridge identity
   - `content.human`: email body (Markdown-converted)
   - `content.structured`: extracted intent (non-authoritative by default)
   - `meta.bridge.original_headers`: full email headers preserved
   - `meta.bridge.original_message_id`: email Message-ID for threading
   - `meta.bridge.structured_trust`: trust marker (`authoritative=false`, `trust_level=low`)
7. **Thread matching**: Use `In-Reply-To` and `References` headers to map to existing LOOM threads
8. **Deliver** to LOOM recipient normally
9. Bridge-originated envelopes are non-actuating by default unless explicit LOOM-native authorization is granted.

### 19.3 Outbound: LOOM → Email

When a LOOM envelope targets a `bridge://` identity or an email address:

1. **Render** `content.human` to HTML email body
2. **Include structured data** as:
   - `X-LOOM-Intent` header with the structured intent
   - `X-LOOM-Thread-ID` header for thread continuity
   - JSON-LD markup in HTML body (for smart email clients)
3. **Map threading**: Set `In-Reply-To` and `References` from LOOM `thread_id`/`parent_id`
4. **Attach files** as standard MIME attachments
5. **Sign** with SPF/DKIM for the bridge domain
6. **Send** via SMTP

### 19.4 Bridge Identity Limitations

Bridge identities (`bridge://`) have restricted capabilities:

| Capability | Available? |
|------------|-----------|
| Send envelopes | ✅ (via email through bridge) |
| Receive envelopes | ✅ (rendered to email) |
| Create threads | ✅ (by sending email to a LOOM address) |
| Delegation | ❌ |
| Agent spawning | ❌ |
| E2EE | ❌ (email doesn't support it) |
| Capability tokens | ❌ (all bridge participants get default `reply` capability) |
| Real-time presence | ❌ |
| Workflow participation | ⚠️ Read-only/non-actuating by default; explicit opt-in required for actuation |

---

## 20. Security Model

### 20.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| **Envelope spoofing** | All envelopes MUST be signed with Ed25519. Nodes MUST verify signatures before delivery. |
| **Agent impersonation** | Agents MUST declare `type: "agent"`. Nodes MUST cross-check against identity documents. Delegation chains MUST be verified. |
| **Man-in-the-middle** | TLS 1.3 mandatory for all transport. Optional E2EE for content. |
| **Replay attacks** | Envelope IDs are globally unique (ULID). Nodes MUST reject duplicate IDs. Timestamps are checked for freshness (±5 minute window for federation). |
| **Scope escalation** | Capability tokens and delegation scopes are cryptographically bound. Nodes MUST enforce scope checks on every operation. |
| **Node compromise** | E2EE threads remain confidential even if the hosting node is compromised. Key rotation limits blast radius. |
| **Spam / abuse** | Rate limiting per identity and per node. Reputation scoring based on federation history. Bridge identities have stricter rate limits. |
| **Denial of service** | Rate limiting, connection limits, queue depth limits. Federation endpoints require mutual TLS. |
| **Phishing** | Structured intents reduce ambiguity. Agent self-identification prevents impersonation. Bridge-originated envelopes are clearly marked. |

### 20.2 Required Security Controls

Conforming implementations MUST:

1. Verify Ed25519 signatures on all inbound envelopes
2. Reject envelopes with expired or revoked delegation chains
3. Enforce capability tokens on all thread operations
4. Use TLS 1.3 for all transport (reject TLS 1.2 and below)
5. Implement rate limiting on all API endpoints
6. Reject duplicate envelope IDs
7. Validate timestamp freshness (±5 minutes for federated envelopes)
8. Cross-check `from.type` against identity document `type`
9. Maintain a delegation revocation list
10. Log all security-relevant events (failed verifications, scope violations)

### 20.3 Recommended Security Controls

Conforming implementations SHOULD:

1. Support E2EE for sensitive threads
2. Implement key rotation reminders
3. Provide anomaly detection for unusual agent behavior patterns
4. Support IP allowlisting for node-to-node federation
5. Implement content scanning for malicious attachments
6. Support audit log export for compliance reviews

---

## 21. Error Handling

### 21.1 Error Response Format

All API errors use a consistent format:

```json
{
  "error": {
    "code": "ENVELOPE_INVALID",
    "message": "Envelope signature verification failed",
    "details": {
      "field": "signature.value",
      "reason": "Ed25519 signature does not match envelope content"
    },
    "request_id": "req_01JMK...",
    "timestamp": "2026-02-16T17:15:00Z"
  }
}
```

### 21.2 Error Code Registry

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `ENVELOPE_INVALID` | 400 | Envelope fails schema validation |
| `SIGNATURE_INVALID` | 401 | Cryptographic signature verification failed |
| `DELEGATION_INVALID` | 403 | Delegation chain verification failed (expired, revoked, or scope violation) |
| `CAPABILITY_DENIED` | 403 | Actor lacks the required capability token for this operation |
| `IDENTITY_NOT_FOUND` | 404 | The specified LOOM identity does not exist |
| `THREAD_NOT_FOUND` | 404 | The specified thread does not exist |
| `ENVELOPE_NOT_FOUND` | 404 | The specified envelope does not exist |
| `ENVELOPE_DUPLICATE` | 409 | An envelope with this ID already exists |
| `THREAD_LOCKED` | 409 | Thread is locked and does not accept new envelopes |
| `STATE_TRANSITION_INVALID` | 409 | Invalid task/thread state transition |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `NODE_UNREACHABLE` | 502 | Remote node is unreachable for federation delivery |
| `DELIVERY_TIMEOUT` | 504 | Envelope delivery timed out |
| `INTERNAL_ERROR` | 500 | Unexpected server error |
| `ENCRYPTION_REQUIRED` | 403 | Thread requires E2EE but envelope is not encrypted |
| `KEY_EXPIRED` | 401 | The signing key used has expired |
| `BRIDGE_DELIVERY_FAILED` | 502 | Email bridge could not deliver to the email address |

### 21.3 Delivery Receipts

For asynchronous delivery, the sending node receives a delivery receipt:

```json
{
  "type": "receipt",
  "content": {
    "structured": {
      "intent": "receipt.delivery",
      "parameters": {
        "envelope_id": "env_01JMKB9X...",
        "recipient": "loom://sarah@acme.corp",
        "status": "delivered | queued | failed | bounced",
        "timestamp": "2026-02-16T17:10:05Z",
        "failure_reason": null
      }
    }
  }
}
```

---

## 22. Compliance & Audit

### 22.1 Audit Trail

Every LOOM node maintains an immutable audit log of:

1. **Envelope events** — created, delivered, read, retracted
2. **Thread events** — created, forked, merged, resolved, archived, locked
3. **Identity events** — created, key rotated, delegation granted/revoked
4. **Capability events** — token issued, used, revoked, expired
5. **Security events** — signature failures, scope violations, rate limit hits
6. **Bridge events** — email received, email sent, conversion errors

### 22.2 Audit Log Entry Format

```json
{
  "id": "audit_01JMK...",
  "timestamp": "2026-02-16T17:10:00Z",
  "event_type": "envelope.delivered",
  "actor": "loom://almarion@cowork-os.com",
  "target": "env_01JMKB9X...",
  "details": {
    "thread_id": "thr_01JMKB7W...",
    "recipients": ["loom://sarah@acme.corp"],
    "envelope_type": "message"
  },
  "node_id": "node_01JMK...",
  "integrity_hash": "sha256:abc123..."
}
```

### 22.3 Regulatory Compliance

LOOM's architecture supports:

| Regulation | How LOOM Helps |
|------------|---------------|
| **GDPR** | Identity documents include consent records. Envelope deletion APIs support right-to-erasure. E2EE minimizes data exposure. Audit logs track all data access. |
| **SOC 2** | Immutable audit trails. Cryptographic identity verification. Capability-based access control. |
| **HIPAA** | E2EE for sensitive threads. Delegation chains for access accountability. Audit logs for access tracking. |
| **eDiscovery** | Structured envelope format enables precise search. Thread model preserves conversation context. Audit logs provide chain of custody. |

### 22.4 Data Retention

Nodes SHOULD implement configurable retention policies:

```json
{
  "retention_policy": {
    "default": "365d",
    "by_type": {
      "notification": "90d",
      "receipt": "30d",
      "task": "730d"
    },
    "by_label": {
      "legal-hold": "indefinite",
      "ephemeral": "24h"
    }
  }
}
```

---

## 23. Migration Guide

### 23.1 Continuous Migration Execution

| Track | Immediate Execution | What Happens |
|-------|---------------------|--------------|
| **Shadow ingestion** | Bridge inbound email into LOOM immediately | Users and agents can operate in LOOM without waiting for a hard cutover |
| **LOOM-first origination** | Start all new internal conversations in LOOM now | Internal communication becomes LOOM-native as quickly as operations allow |
| **External compatibility** | Keep email bridge enabled for non-LOOM contacts | External dependencies do not slow internal migration |
| **Legacy reduction by readiness** | Decrease legacy usage only when telemetry and policy confirm readiness | Migration speed is driven by live operational signals, not calendar dates |

### 23.2 Developer Migration Map

| Email Concept | LOOM Equivalent |
|---------------|-----------------|
| SMTP `SEND` | `POST /v1/envelopes` |
| IMAP `FETCH` | `GET /v1/threads/{id}/envelopes` |
| IMAP `SEARCH` | `GET /v1/search?q=...` |
| SMTP `AUTH` | Cryptographic proof-of-key + Bearer tokens |
| Webhooks (none) | WebSocket subscription on threads/envelopes |
| Filters (Sieve) | Rules engine with structured intent matching |
| Mailing list | Team identity with member routing |
| CC / BCC | Recipient roles (`cc`, `observer`, `bcc`) |
| `In-Reply-To` | `parent_id` (explicit, not heuristic) |
| `Subject` | `thread.subject` (first-class, not parsed from headers) |
| Attachments (MIME) | `attachments[]` with hash integrity |
| `From` spoofing | Impossible — envelopes are cryptographically signed |

### 23.3 Client Implementation Checklist

For developers building LOOM clients:

- [ ] Implement Ed25519 signing for all outbound envelopes
- [ ] Implement signature verification for all inbound envelopes
- [ ] Support both `human` and `structured` content rendering
- [ ] Display agent-sent envelopes with visual distinction
- [ ] Implement thread graph visualization (not just linear)
- [ ] Support capability token management in thread settings
- [ ] Implement WebSocket connection for real-time updates
- [ ] Handle delegation chain display (show who authorized an agent)
- [ ] Support E2EE key exchange for encrypted threads
- [ ] Implement graceful fallback for unknown envelope types

---

## 24. Reference Implementation Notes

### 24.1 Recommended Technology Stack

| Component | Recommendation | Rationale |
|-----------|---------------|-----------|
| Node server | Rust or Go | Performance-critical, concurrent connections |
| Envelope Store | PostgreSQL + full-text search | Relational integrity + search capabilities |
| Real-time | Native WebSocket (tokio/goroutine) | Low-latency push |
| Cryptography | libsodium / ring | Well-audited Ed25519/X25519 implementations |
| Email Bridge | Postfix (SMTP) + custom LOOM adapter | Battle-tested SMTP handling |
| API framework | Axum (Rust) or Chi (Go) | HTTP/2 native, lightweight |
| Client SDK | TypeScript / Python / Rust | Cover web, scripting, and systems use cases |

### 24.2 Minimum Viable Node

A conforming "Minimum Viable Node" (MVN) MUST implement:

1. Identity management (create, resolve, key rotation)
2. Envelope creation, signing, and delivery (local)
3. Envelope signature verification
4. Thread management (create, list, reply)
5. HTTP/2 API with TLS 1.3
6. DNS-based discovery (`.well-known/loom.json`)
7. Basic rate limiting

A MVN MAY defer:

- Federation (single-node operation)
- Email Bridge
- E2EE
- WebSocket real-time
- Workflows
- Full-text search

### 24.3 Conformance Levels

| Level | Name | Requirements |
|-------|------|--------------|
| **Level 1** | Core | Identity, envelopes, threads, signing, API, discovery |
| **Level 2** | Federation | Level 1 + node-to-node routing, store-and-forward |
| **Level 3** | Bridge | Level 2 + bidirectional email bridge |
| **Level 4** | Full | Level 3 + E2EE, WebSocket, workflows, presence |

---

## 25. Appendices

### Appendix A: LOOM vs Email — Complete Feature Comparison

| Feature | Email (SMTP/IMAP) | LOOM |
|---------|-------------------|------|
| Message format | Flat MIME, unstructured body | Dual: human-readable + structured intent |
| Threading | Heuristic (`Subject` + `In-Reply-To`) | Native DAG (`thread_id`, `parent_id`, forks) |
| Identity | Self-asserted, spoofable | Cryptographic Ed25519, identity documents |
| Authentication | Bolt-on (SPF/DKIM/DMARC) | Built-in (signed envelopes, delegation chains) |
| Agent support | None | First-class (identity type, delegation, scoped capabilities, presence) |
| Real-time | Poll-based (IMAP IDLE hack) | Native WebSocket + push events |
| Task tracking | Manual (flags, labels, forwards) | Built-in state machine with audit trail |
| Transport security | Optional STARTTLS | Mandatory TLS 1.3 |
| End-to-end encryption | No standard (PGP/S/MIME are separate) | Built-in optional E2EE (X25519 + XChaCha20) |
| Composability | Forward/CC (lossy, manual) | Fork/merge/link/delegate (structured, programmable) |
| Access control | All-or-nothing mailbox access | Capability tokens (per-thread, per-operation) |
| Federation | MX records + SMTP relay | SRV records + HTTP/2 relay mesh |
| Search | Server-dependent IMAP SEARCH | Structured intent + full-text search API |
| Workflows | None (manual forwarding chains) | Native multi-step workflows with conditions |
| Audit | Server logs only | Immutable audit trail with cryptographic integrity |
| Spam prevention | Reputation + content filtering | Cryptographic identity + rate limiting + reputation |
| Migration | N/A | Bidirectional bridge with full compatibility |

### Appendix B: Intent Schema Registry

The intent registry is extensible. Core intents ship with the protocol:

Canonical wire format in current specs appends major versions.

```
message.general@v1          — Freeform message
message.question@v1         — Question expecting an answer
message.reply@v1            — Direct reply to a question
task.create@v1              — New task
task.assign@v1              — Assign task to identity
task.update@v1              — Update task state
task.complete@v1            — Mark task complete
task.fail@v1                — Mark task failed
approval.request@v1         — Request yes/no/conditional decision
approval.response@v1        — Respond to approval request
schedule.meeting@v1         — Propose a meeting
schedule.propose_times@v1   — Suggest available times
schedule.confirm@v1         — Confirm a scheduled event
event.invite@v1             — Calendar event invitation
event.rsvp@v1               — RSVP to event
event.cancel@v1             — Cancel event
event.update@v1             — Update event details
data.request@v1             — Request structured data
data.deliver@v1             — Deliver structured data
data.query@v1               — Query for specific data points
handoff.transfer@v1         — Transfer responsibility
handoff.accept@v1           — Accept a handoff
handoff.reject@v1           — Reject a handoff
notification.system@v1      — System notification
notification.alert@v1       — Urgent alert
notification.digest@v1      — Summary/digest notification
delegation.grant@v1         — New delegation issued
delegation.revoked@v1       — Delegation revoked
delegation.request@v1       — Request delegation from a human
receipt.delivered@v1        — Delivery confirmation
receipt.read@v1             — Read confirmation
receipt.processed@v1        — Action/processing confirmation
receipt.failed@v1           — Delivery/processing failure
workflow.execute@v1         — Execute a multi-step workflow
workflow.step_complete@v1   — Workflow step completed
workflow.complete@v1        — Entire workflow completed
workflow.failed@v1          — Workflow failed at a step
agent.negotiate@v1          — Agent capability negotiation
agent.heartbeat@v1          — Agent liveness signal
```

### Appendix C: Sequence Diagrams

#### C.1 Human Sends Message to Human (Same Node)

```
Alice (Human)          Node A              Bob (Human)
     │                    │                     │
     │── POST /v1/envelopes ──►│                     │
     │   (signed envelope)     │                     │
     │                    │── verify signature  │
     │                    │── check capabilities│
     │                    │── store envelope    │
     │                    │── push via WebSocket ────►│
     │◄── 201 Created ───│                     │
     │                    │                     │
```

#### C.2 Agent Sends on Behalf of Human (Federated)

```
Agent (Almarion's)       Node A              Node B           Sarah (Human)
     │                    │                    │                  │
     │── POST /v1/envelopes ──►│                    │                  │
     │   (signed + delegation  │                    │                  │
     │    chain)               │                    │                  │
     │                    │── verify envelope   │                  │
     │                    │   signature          │                  │
     │                    │── verify delegation │                  │
     │                    │   chain (Almarion→Agent)│                  │
     │                    │── check scope       │                  │
     │                    │                    │                  │
     │                    │── DNS lookup ──────►│                  │
     │                    │   _loom._tcp.acme   │                  │
     │                    │◄── SRV record ─────│                  │
     │                    │                    │                  │
     │                    │── POST /v1/federation/deliver ──►│                  │
     │                    │   (mutual TLS)      │                  │
     │                    │                    │── verify all ──►│
     │                    │                    │── store ────────►│
     │                    │                    │── WebSocket push ──►│
     │                    │◄── 200 delivered ──│                  │
     │◄── 201 Created ───│                    │                  │
```

#### C.3 Email → LOOM (Inbound Bridge)

```
alice@gmail.com       SMTP Relay          Email Bridge          Node A
     │                     │                    │                    │
     │── SMTP email ──────►│                    │                    │
     │                     │── SMTP deliver ───►│                    │
     │                     │                    │── verify SPF/DKIM  │
     │                     │                    │── parse MIME       │
     │                     │                    │── extract intent   │
     │                     │                    │── create bridge://  │
     │                     │                    │   identity          │
     │                     │                    │── generate LOOM    │
     │                     │                    │   envelope          │
     │                     │                    │── POST /v1/envelopes ──►│
     │                     │                    │                    │── store
     │                     │                    │                    │── deliver
     │                     │                    │◄── 201 Created ───│
     │                     │◄── 250 OK ────────│                    │
```

### Appendix D: Wire Format Summary

| Element | Format |
|---------|--------|
| Envelope body | JSON (UTF-8), `application/json` |
| IDs | Type prefix + ULID (e.g., `env_01JMKB...`) |
| Timestamps | ISO 8601 with timezone (`2026-02-16T17:00:00Z`) |
| Signatures | Base64url-encoded Ed25519 |
| Public keys | Base64url-encoded |
| Encrypted content | Base64url-encoded XChaCha20-Poly1305 ciphertext |
| Addressing | `loom://{local}@{domain}` URI scheme |
| Transport | HTTP/2 + TLS 1.3 (mandatory) |
| Real-time | WebSocket over TLS (`wss://`) |
| Discovery | DNS SRV + TXT + `.well-known/loom.json` |

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | February 2026 | Initial specification |

---

## License

This specification is released as an **open standard**. Anyone may implement, extend, and build upon it without restriction. Interoperability and openness are core to LOOM's mission.

The LOOM name and protocol specification are maintained by the community. Contributions, feedback, and implementations are welcome.

---

*LOOM — Because communication should be woven, not stacked in an inbox.*
