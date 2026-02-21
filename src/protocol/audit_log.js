// ─── Hash-Chained Audit Log — Section 25.1 ──────────────────────────────────
//
// Append-only, tamper-evident audit log with SHA-256 hash chaining.

import { createHash } from "node:crypto";
import { generateUlid } from "./ulid.js";

export const AUDIT_EVENT_TYPES = Object.freeze({
  // Envelope events
  ENVELOPE_CREATE: "envelope.create",
  ENVELOPE_RETRACT: "envelope.retract",
  ENVELOPE_LABEL: "envelope.label",

  // Thread events
  THREAD_CREATE: "thread.create",
  THREAD_OP: "thread.op",
  THREAD_STATE: "thread.state",
  THREAD_FORK: "thread.fork",
  THREAD_MERGE: "thread.merge",

  // Capability events
  CAPABILITY_ISSUE: "capability.issue",
  CAPABILITY_REVOKE: "capability.revoke",
  CAPABILITY_SPEND: "capability.spend",

  // Delegation events
  DELEGATION_CREATE: "delegation.create",
  DELEGATION_REVOKE: "delegation.revoke",
  DELEGATION_EXPIRE: "delegation.expire",

  // Security events
  SECURITY_SIGNATURE_FAILURE: "security.signature_failure",
  SECURITY_SCOPE_VIOLATION: "security.scope_violation",
  SECURITY_KEY_REVOCATION: "security.key_revocation",

  // Identity events
  IDENTITY_REGISTER: "identity.register",
  IDENTITY_UPDATE: "identity.update",

  // Bridge events
  BRIDGE_EMAIL_INBOUND: "bridge.email.inbound",
  BRIDGE_EMAIL_OUTBOUND: "bridge.email.outbound",
  BRIDGE_IMAP_LOGIN: "bridge.imap.login",
  BRIDGE_SMTP_SUBMIT: "bridge.smtp.submit",

  // Deletion events
  DELETION_REQUEST: "deletion.request",
  DELETION_BLOCKED: "deletion.blocked_legal_hold"
});

function computeEntryHash(entry) {
  const payload = JSON.stringify({
    id: entry.id,
    timestamp: entry.timestamp,
    actor: entry.actor,
    action: entry.action,
    resource_id: entry.resource_id,
    resource_type: entry.resource_type,
    details: entry.details,
    previous_hash: entry.previous_hash
  });
  return "sha256:" + createHash("sha256").update(payload, "utf-8").digest("hex");
}

export function createAuditLog() {
  return {
    entries: [],
    head_hash: null
  };
}

export function appendAuditEntry(log, { actor, action, resourceId, resourceType, details = {} }) {
  const entry = {
    id: `evt_${generateUlid()}`,
    timestamp: new Date().toISOString(),
    actor: actor || null,
    action,
    resource_id: resourceId || null,
    resource_type: resourceType || null,
    details,
    previous_hash: log.head_hash
  };

  entry.hash = computeEntryHash(entry);
  log.entries.push(entry);
  log.head_hash = entry.hash;

  return entry;
}

export function verifyAuditChain(log) {
  let expectedPreviousHash = null;

  for (let i = 0; i < log.entries.length; i++) {
    const entry = log.entries[i];

    if (entry.previous_hash !== expectedPreviousHash) {
      return {
        valid: false,
        broken_at_index: i,
        reason: `previous_hash mismatch at entry ${i}: expected ${expectedPreviousHash}, got ${entry.previous_hash}`
      };
    }

    const recomputed = computeEntryHash(entry);
    if (entry.hash !== recomputed) {
      return {
        valid: false,
        broken_at_index: i,
        reason: `hash mismatch at entry ${i}: stored ${entry.hash}, computed ${recomputed}`
      };
    }

    expectedPreviousHash = entry.hash;
  }

  return { valid: true };
}

export function serializeAuditLog(log) {
  return {
    entries: log.entries.map((e) => ({ ...e })),
    head_hash: log.head_hash
  };
}

export function deserializeAuditLog(data) {
  if (!data || typeof data !== "object") {
    return createAuditLog();
  }
  return {
    entries: Array.isArray(data.entries) ? data.entries.map((e) => ({ ...e })) : [],
    head_hash: data.head_hash || null
  };
}
