# LOOM — Linked Operations & Orchestrated Messaging

### *The communication layer built for humans and agents together.*

> Historical design draft.
> Canonical behavior is defined by `LOOM-Protocol-Spec-v1.1.md`, `LOOM-Agent-First-Protocol-v2.0.md`, `docs/LOOM-CORE.md`, and `docs/EXTENSION-REGISTRY.md`.
> If this draft conflicts with those documents, follow the canonical set above.
> Review baseline: synchronized with repository state through `v0.4.2`.

---

## 1. Name & Philosophy

**LOOM** — **L**inked **O**perations & **O**rchestrated **M**essaging

The name captures the core idea: a loom — an interconnected network where messages, tasks, data, and identity are woven together rather than siloed in flat mailboxes. Unlike email's point-to-point letter metaphor, LOOM treats every exchange as a **linked, structured, composable object** that both humans and agents can read, route, act on, and chain.

**Design principles:**
1. **Agent-native, human-friendly** — Agents are first-class participants, not bolt-ons. Humans never feel like they're talking to a machine protocol.
2. **Structured by default** — Every message carries typed, machine-readable payloads alongside human-readable content. No more parsing HTML to find an invoice.
3. **Composable conversations** — Threads can fork, merge, delegate, and link. Not just linear reply chains.
4. **Identity & trust built-in** — Cryptographic identity, delegation chains, and capability tokens are part of the protocol, not afterthoughts (SPF/DKIM/DMARC bolted onto SMTP).
5. **Backwards-compatible bridge** — LOOM can send to and receive from email addresses during the transition era.

---

## 2. Core Architecture

### 2.1 System Components

```
┌─────────────────────────────────────────────────────────┐
│                    LOOM NETWORK                         │
│                                                         │
│  ┌───────────┐    ┌───────────┐    ┌───────────┐       │
│  │  LOOM     │    │  LOOM     │    │  LOOM     │       │
│  │  Node     │◄──►│  Node     │◄──►│  Node     │       │
│  │ (Almarion@)  │    │ (agent@)  │    │ (corp@)   │       │
│  └─────┬─────┘    └─────┬─────┘    └─────┬─────┘       │
│        │                │                │              │
│  ┌─────┴─────┐    ┌─────┴─────┐    ┌─────┴─────┐       │
│  │ Envelope  │    │ Envelope  │    │ Envelope  │       │
│  │ Store     │    │ Store     │    │ Store     │       │
│  └───────────┘    └───────────┘    └───────────┘       │
│                                                         │
│  ┌─────────────────────────────────────────────┐       │
│  │           Relay Mesh (Federation)            │       │
│  └─────────────────────────────────────────────┘       │
│                                                         │
│  ┌─────────────────────────────────────────────┐       │
│  │       Email Bridge (SMTP ↔ LOOM)            │       │
│  └─────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

**LOOM Node** — The fundamental server/client unit. Analogous to an email server, but smarter. Each node:
- Hosts one or more **identities** (users + agents)
- Stores and indexes **envelopes** (the LOOM message unit)
- Participates in **relay mesh** for federation
- Exposes a standard **LOOM API** (HTTP/2 + WebSocket for real-time)

**Relay Mesh** — Federated routing layer. Nodes discover each other via DNS-based records (`_loom.example.com`) and route envelopes using identity-based addressing. No central authority.

**Email Bridge** — A gateway component that translates SMTP ↔ LOOM envelopes bidirectionally, enabling gradual migration.

### 2.2 Addressing

LOOM uses **Universal Resource Identities (URIs)**:

``` 
loom://almarion@cowork-os.com              — human identity
loom://assistant.almarion@cowork-os.com    — agent scoped to a human
loom://billing@acme.corp                — role/team address
loom://billing@acme.corp#invoice-q1     — deep-link to a specific thread/object
```

**Key differences from email addressing:**
- The `loom://` scheme makes addresses unambiguous and routable
- Sub-addressing with `.` separators for agent scoping (no `+` hack like email)
- Fragment identifiers (`#`) for direct thread/object references
- Addresses resolve to **identity documents** (public keys, capabilities, delegation chains)
- Addresses are treated case-insensitively and serialized in canonical lowercase form on wire.

### 2.3 Transport

| Layer | Protocol | Purpose |
|-------|----------|---------|
| Discovery | DNS TXT + `.well-known/loom` | Node discovery, key exchange |
| Transport | HTTP/2 + TLS 1.3 (required) | Envelope delivery, API |
| Real-time | WebSocket over TLS | Live streams, presence, typing indicators |
| Bulk sync | HTTP/2 streaming | Offline sync, batch envelope retrieval |

**No plaintext. Ever.** TLS 1.3 is mandatory at the transport level. End-to-end encryption (E2EE) is available per-thread using identity keys.

---

## 3. Protocol Primitives

These are the atomic building blocks — the "nouns and verbs" of LOOM.

### 3.1 Envelope (the message unit)

The **Envelope** replaces the email message. It's a structured container, not a flat blob.

```json
{
  "loom": "1.0",
  "id": "env_01JMK8X9Q2...",
  "thread_id": "thr_01JMK8W...",
  "parent_id": null,
  "type": "message",
  "from": {
    "identity": "loom://almarion@cowork-os.com",
    "display": "Almarion",
    "key_id": "k_01JMK..."
  },
  "to": [
    { "identity": "loom://billing@acme.corp", "role": "primary" },
    { "identity": "loom://assistant.almarion@cowork-os.com", "role": "observer" }
  ],
  "created_at": "2026-02-16T16:37:00Z",
  "content": {
    "human": {
      "text": "Please send the Q1 invoice when ready.",
      "format": "markdown"
    },
    "structured": {
      "intent": "request.document",
      "parameters": {
        "document_type": "invoice",
        "period": "Q1-2026",
        "urgency": "normal"
      }
    }
  },
  "attachments": [],
  "capabilities": ["reply", "delegate", "fork"],
  "signature": "sig_EdDSA_..."
}
```

**Key design decisions:**
- **Dual content** — Every envelope carries `human` (readable text) AND `structured` (machine-actionable intent). For LOOM-native signed payloads, structured content may drive automation; bridge-extracted structured hints are non-authoritative by default.
- **Thread-native** — `thread_id` and `parent_id` are first-class, not heuristic (no `In-Reply-To` guesswork).
- **Typed** — The `type` field distinguishes messages, tasks, approvals, events, status updates, etc.
- **Signed** — Every envelope is cryptographically signed by the sender's identity key.
- **Capabilities** — The sender explicitly declares what actions recipients can take (reply, delegate, fork, escalate).

### 3.2 Thread

A **Thread** is an ordered, branching graph of envelopes.

```json
{
  "id": "thr_01JMK8W...",
  "root_envelope_id": "env_01JMK8X...",
  "subject": "Q1 Invoice Request",
  "state": "active",
  "participants": [
    { "identity": "loom://almarion@cowork-os.com", "role": "owner", "joined": "2026-02-16T16:37:00Z" },
    { "identity": "loom://billing@acme.corp", "role": "participant", "joined": "2026-02-16T16:37:00Z" },
    { "identity": "loom://assistant.almarion@cowork-os.com", "role": "observer", "joined": "2026-02-16T16:37:00Z" }
  ],
  "labels": ["finance", "q1-2026"],
  "forks": [],
  "linked_threads": [],
  "schema": "request.document"
}
```

**Thread operations:**
- **Fork** — Split a thread into a sub-conversation (e.g., "let me check with legal" forks from the main invoice thread)
- **Merge** — Bring a fork's resolution back into the parent thread
- **Link** — Reference another thread without merging (cross-reference)
- **Delegate** — Transfer thread ownership to another identity (human or agent)
- **Archive / Resolve** — Close a thread with a terminal state

### 3.3 Identity

Every participant — human or agent — holds a **LOOM Identity**.

```json
{
  "id": "loom://almarion@cowork-os.com",
  "type": "human",
  "display_name": "Almarion",
  "node": "cowork-os.com",
  "public_keys": {
    "signing": "ed25519:pk_01JMK...",
    "encryption": "x25519:pk_01JMK..."
  },
  "delegations": [
    {
      "delegate": "loom://assistant.almarion@cowork-os.com",
      "scope": ["read.*", "reply.routine", "task.create"],
      "expires": "2026-06-01T00:00:00Z",
      "revocable": true
    }
  ],
  "capabilities": ["send", "receive", "create_thread", "delegate"],
  "verified_bridges": {
    "email": "almarion@cowork-os.com"
  }
}
```

**Agent identity specifics:**
- Agents have `type: "agent"` and MUST have a `delegator` field (the human or org that authorized them)
- Agent scopes are **explicitly bounded** — an agent can only do what its delegation chain permits
- Delegation chains are **cryptographically verifiable** — you can trace any agent action back to its authorizing human/org
- **No impersonation** — agents always identify as agents in the `from` field; the protocol rejects spoofed type fields

### 3.4 Envelope Types (Message Taxonomy)

| Type | Purpose | Example |
|------|---------|---------|
| `message` | General communication | "Hey, how's the project going?" |
| `task` | Actionable work item with state | "Review this PR by Friday" |
| `approval` | Yes/no/conditional decision request | "Approve this expense report?" |
| `event` | Calendar/scheduling event | "Team sync on Wednesday 3pm" |
| `notification` | System/status update (no reply expected) | "Your deployment completed" |
| `handoff` | Transfer of context/responsibility | "Handing this customer to support agent" |
| `data` | Structured data exchange | "Here's the Q1 revenue JSON" |
| `receipt` | Delivery/read/action confirmation | "Invoice was processed" |

Each type has a **schema** that defines required `structured` fields, valid state transitions, and allowed capabilities.

### 3.5 Capability Tokens

Instead of email's all-or-nothing access, LOOM uses **capability tokens** — fine-grained permissions attached to envelopes and threads.

```json
{
  "token": "cap_01JMK...",
  "grants": ["reply", "add_participant"],
  "scope": "thr_01JMK8W...",
  "issued_by": "loom://almarion@cowork-os.com",
  "issued_to": "loom://contractor@freelance.dev",
  "expires": "2026-03-01T00:00:00Z",
  "single_use": false
}
```

This means you can share a thread with someone and give them **only** reply access — they can't forward, fork, or add participants unless granted. This is how agents get scoped access to conversations without needing full mailbox permissions.

---

## 4. Agent-Native Features

These are the features that make LOOM fundamentally different from email for the agent era.

### 4.1 Delegation Chains

```
Human (Almarion) ──delegates──► Personal Agent ──sub-delegates──► Specialist Agent
     │                              │                               │
     │  scope: *                    │  scope: calendar.*            │  scope: calendar.schedule
     │                              │  expires: 30d                 │  expires: 1h, single_use
```

Every action by an agent carries the full delegation chain in its envelope signature. Any recipient can:
- Verify the chain is cryptographically valid
- Check that each delegation is within scope
- See the human at the root of the chain
- Reject if any link is expired or revoked

### 4.2 Structured Intents

Agents don't parse natural language from email bodies. They read the `structured` field:

```json
"structured": {
  "intent": "schedule.meeting",
  "parameters": {
    "title": "Q1 Review",
    "proposed_times": [
      "2026-02-20T14:00:00Z",
      "2026-02-20T16:00:00Z"
    ],
    "duration_minutes": 60,
    "required_participants": ["loom://sarah@acme.corp"],
    "optional_participants": ["loom://finance-bot@acme.corp"]
  },
  "response_schema": "schedule.meeting.response"
}
```

The `response_schema` field tells the receiving agent exactly what format to reply in — no guesswork, no prompt engineering on email bodies.

### 4.3 Task State Machine

`task`-type envelopes have a built-in state machine:

```
┌──────────┐     ┌────────────┐     ┌─────────────┐     ┌───────────┐
│  CREATED  │────►│  ASSIGNED   │────►│  IN_PROGRESS │────►│ COMPLETED  │
└──────────┘     └────────────┘     └─────────────┘     └───────────┘
                       │                    │                    │
                       ▼                    ▼                    ▼
                 ┌──────────┐        ┌───────────┐       ┌──────────┐
                 │ DECLINED  │        │  BLOCKED   │       │  FAILED   │
                 └──────────┘        └───────────┘       └──────────┘
```

State transitions are recorded as envelopes in the thread, creating a full audit trail. Agents can subscribe to state changes and react automatically.

### 4.4 Presence & Availability

LOOM supports real-time presence (optional, via WebSocket):

```json
{
  "identity": "loom://assistant.almarion@cowork-os.com",
  "status": "available",
  "response_time": "instant",
  "capabilities_active": ["reply.routine", "task.triage", "calendar.read"],
  "load": 0.3
}
```

This lets agents negotiate work — if one agent is overloaded (`load: 0.95`), a coordinator can route to a lighter agent. Humans can see agent availability like a status indicator.

### 4.5 Composable Workflows

Agents can chain envelopes into **workflows** — multi-step processes that execute across participants:

```json
{
  "type": "workflow",
  "steps": [
    {
      "action": "request.approval",
      "to": "loom://manager@acme.corp",
      "condition": "approved",
      "then": "next",
      "else": "abort"
    },
    {
      "action": "task.execute",
      "to": "loom://finance-bot@acme.corp",
      "parameters": { "action": "process_payment", "amount": 5000 }
    },
    {
      "action": "notification",
      "to": "loom://almarion@cowork-os.com",
      "template": "payment_processed"
    }
  ]
}
```

This replaces the fragile email chains where humans manually forward between departments and agents try to parse "FW: FW: RE: FW:" subject lines.

### 4.6 Observability & Audit

Every envelope is signed. Every state change is recorded. Every delegation is traceable. This gives:

- **Full audit trail** — Who said what, when, with what authority
- **Agent accountability** — Every agent action traces back to a human authorizer
- **Compliance** — Structured data + audit trail = regulatory readiness (GDPR, SOC2, etc.)
- **Debugging** — When an agent does something wrong, you can trace the exact chain of events

---

## 5. Migration Path from Email

### 5.1 Strategy: Bridge, Don't Break

LOOM doesn't require the world to switch overnight. The migration is **gradual and bidirectional**.

### 5.2 The Email Bridge

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   Email World    │         │   Email Bridge     │         │   LOOM World    │
│                  │         │                    │         │                 │
│  alice@gmail.com │──SMTP──►│  Inbound Gateway   │──LOOM──►│ Almarion@cowork-os │
│                  │         │  - Parse headers    │         │                 │
│                  │◄──SMTP──│  Outbound Gateway   │◄──LOOM──│                 │
│                  │         │  - Render to HTML   │         │                 │
└─────────────────┘         └──────────────────┘         └─────────────────┘
```

**Inbound (Email → LOOM):**
1. Email arrives at a LOOM node's bridge address (e.g., `almarion@cowork-os.com` via SMTP)
2. Bridge extracts: sender, recipients, subject, body, attachments, headers
3. Bridge creates a LOOM envelope with:
   - `from`: bridged identity (`bridge://alice@gmail.com`)
   - `content.human`: email body
   - `content.structured`: AI-assisted intent extraction (best-effort, tagged non-authoritative)
   - `meta.bridge.original_headers`: preserved for debugging
   - `meta.bridge.structured_trust`: low-trust marker for downstream policy
4. Envelope delivered to LOOM recipient normally
5. Bridge-originated envelopes remain non-actuating by default until explicit LOOM-native authorization is granted.

**Outbound (LOOM → Email):**
1. LOOM envelope addressed to a `bridge://` or email address
2. Bridge renders `content.human` to HTML email
3. Bridge includes structured data as:
   - JSON-LD in email headers (for smart clients)
   - Human-readable summary in the body (for everyone)
4. Sent via SMTP with proper SPF/DKIM/DMARC from the bridge domain

### 5.3 Continuous Migration Execution

| Track | Immediate Execution | Outcome |
|-------|---------------------|---------|
| **Shadow ingestion** | Bridge all inbound email into LOOM threads immediately | Zero interruption while agents and humans can already operate in LOOM |
| **LOOM-first origination** | Start all new internal conversations in LOOM now | Internal traffic shifts to structured, agent-native communication without waiting for a date |
| **External interop always-on** | Keep bidirectional email bridge active for non-LOOM contacts | External dependencies do not block rollout speed |
| **Legacy reduction by telemetry** | Reduce legacy pathways only when usage and reliability data show readiness | Cutover decisions are metric-driven, not calendar-driven |

### 5.4 Compatibility Guarantees

- **Every LOOM identity can have a verified email bridge** — so `loom://almarion@cowork-os.com` can still receive from and send to `alice@gmail.com`
- **Threads started via email bridge preserve full email threading** — `In-Reply-To` and `References` headers are mapped to `thread_id` and `parent_id`
- **Attachments pass through unchanged** — MIME attachments become LOOM attachments and vice versa
- **No data loss** — the bridge preserves original email headers in envelope metadata for compliance/legal holds

### 5.5 Developer Migration

For developers integrating with LOOM:

```
Email (SMTP/IMAP)          →    LOOM API
─────────────────               ────────
SMTP SEND                  →    POST /v1/envelopes
IMAP FETCH                 →    GET  /v1/threads/{id}/envelopes
IMAP SEARCH                →    GET  /v1/search?q=...
SMTP AUTH                  →    OAuth2 + Identity Keys
Webhook (none in email)    →    WebSocket subscription on threads/envelopes
Filters (Sieve)            →    Rules engine with structured intent matching
```

---

## 6. Summary: LOOM vs Email

| Dimension | Email (SMTP/IMAP) | LOOM |
|-----------|-------------------|------|
| **Message format** | Flat MIME, unstructured | Dual: human-readable + structured data |
| **Threading** | Heuristic (subject + headers) | Native graph (thread_id, parent_id, forks) |
| **Identity** | Spoofable, bolt-on auth (SPF/DKIM) | Cryptographic, built-in delegation chains |
| **Agent support** | None (agents hack around email) | First-class: delegation, scoped capabilities, presence |
| **Real-time** | Poll-based (IMAP IDLE is a hack) | Native WebSocket + push |
| **Task tracking** | Manual (flag, label, forward) | Built-in state machine with audit trail |
| **Security** | Optional TLS, no E2EE standard | Mandatory TLS 1.3, optional E2EE per-thread |
| **Composability** | Forward/CC (lossy, manual) | Fork/merge/link/delegate (structured, programmable) |
| **Migration** | N/A | Bidirectional bridge with full compatibility |

---

## 7. What's Next

With the protocol designed, the next step is to write the **full technical specification** — wire formats, API endpoints, error codes, sequence diagrams, and reference implementation guidance. This design document serves as the architectural blueprint that the spec will formalize.

---

*LOOM: Because communication should be woven, not stacked in an inbox.*
