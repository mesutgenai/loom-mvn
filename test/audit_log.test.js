import test from "node:test";
import assert from "node:assert/strict";

import {
  AUDIT_EVENT_TYPES,
  createAuditLog,
  appendAuditEntry,
  verifyAuditChain,
  serializeAuditLog,
  deserializeAuditLog
} from "../src/protocol/audit_log.js";

// ─── Constants ──────────────────────────────────────────────────────────────

test("AUDIT_EVENT_TYPES has all event categories", () => {
  assert.ok(AUDIT_EVENT_TYPES.ENVELOPE_CREATE);
  assert.ok(AUDIT_EVENT_TYPES.THREAD_CREATE);
  assert.ok(AUDIT_EVENT_TYPES.CAPABILITY_ISSUE);
  assert.ok(AUDIT_EVENT_TYPES.DELEGATION_CREATE);
  assert.ok(AUDIT_EVENT_TYPES.SECURITY_SIGNATURE_FAILURE);
  assert.ok(AUDIT_EVENT_TYPES.IDENTITY_REGISTER);
  assert.ok(AUDIT_EVENT_TYPES.BRIDGE_EMAIL_INBOUND);
  assert.ok(AUDIT_EVENT_TYPES.DELETION_REQUEST);
});

// ─── createAuditLog ─────────────────────────────────────────────────────────

test("createAuditLog creates empty log", () => {
  const log = createAuditLog();
  assert.deepEqual(log.entries, []);
  assert.equal(log.head_hash, null);
});

// ─── appendAuditEntry ───────────────────────────────────────────────────────

test("appendAuditEntry adds entry with hash chain", () => {
  const log = createAuditLog();
  const entry = appendAuditEntry(log, {
    actor: "loom://alice",
    action: AUDIT_EVENT_TYPES.ENVELOPE_CREATE,
    resourceId: "env_1",
    resourceType: "envelope"
  });

  assert.ok(entry.id.startsWith("evt_"));
  assert.ok(entry.timestamp);
  assert.equal(entry.actor, "loom://alice");
  assert.equal(entry.action, "envelope.create");
  assert.equal(entry.resource_id, "env_1");
  assert.equal(entry.previous_hash, null);
  assert.ok(entry.hash.startsWith("sha256:"));
  assert.equal(log.entries.length, 1);
  assert.equal(log.head_hash, entry.hash);
});

test("appendAuditEntry chains hashes", () => {
  const log = createAuditLog();
  const entry1 = appendAuditEntry(log, {
    actor: "alice",
    action: "envelope.create"
  });
  const entry2 = appendAuditEntry(log, {
    actor: "bob",
    action: "thread.create"
  });

  assert.equal(entry2.previous_hash, entry1.hash);
  assert.notEqual(entry1.hash, entry2.hash);
  assert.equal(log.head_hash, entry2.hash);
  assert.equal(log.entries.length, 2);
});

// ─── verifyAuditChain ───────────────────────────────────────────────────────

test("verifyAuditChain: valid chain", () => {
  const log = createAuditLog();
  appendAuditEntry(log, { actor: "a", action: "x" });
  appendAuditEntry(log, { actor: "b", action: "y" });
  appendAuditEntry(log, { actor: "c", action: "z" });

  const result = verifyAuditChain(log);
  assert.equal(result.valid, true);
});

test("verifyAuditChain: empty log is valid", () => {
  const log = createAuditLog();
  assert.equal(verifyAuditChain(log).valid, true);
});

test("verifyAuditChain: detects tampered hash", () => {
  const log = createAuditLog();
  appendAuditEntry(log, { actor: "a", action: "x" });
  appendAuditEntry(log, { actor: "b", action: "y" });

  // Tamper with the first entry's hash
  log.entries[0].hash = "sha256:tampered";

  const result = verifyAuditChain(log);
  assert.equal(result.valid, false);
  assert.equal(result.broken_at_index, 0);
});

test("verifyAuditChain: detects broken previous_hash link", () => {
  const log = createAuditLog();
  appendAuditEntry(log, { actor: "a", action: "x" });
  appendAuditEntry(log, { actor: "b", action: "y" });

  // Break the chain link
  log.entries[1].previous_hash = "sha256:wrong";

  const result = verifyAuditChain(log);
  assert.equal(result.valid, false);
  assert.equal(result.broken_at_index, 1);
});

// ─── Serialization ──────────────────────────────────────────────────────────

test("serializeAuditLog and deserializeAuditLog round-trip", () => {
  const log = createAuditLog();
  appendAuditEntry(log, { actor: "a", action: "x", details: { key: "val" } });
  appendAuditEntry(log, { actor: "b", action: "y" });

  const serialized = serializeAuditLog(log);
  const deserialized = deserializeAuditLog(serialized);

  assert.equal(deserialized.entries.length, 2);
  assert.equal(deserialized.head_hash, log.head_hash);
  assert.equal(verifyAuditChain(deserialized).valid, true);
});

test("deserializeAuditLog handles null", () => {
  const log = deserializeAuditLog(null);
  assert.deepEqual(log.entries, []);
  assert.equal(log.head_hash, null);
});

test("deserializeAuditLog handles invalid data", () => {
  const log = deserializeAuditLog("not an object");
  assert.deepEqual(log.entries, []);
});
