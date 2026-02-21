import test from "node:test";
import assert from "node:assert/strict";

import {
  validateAutoresponderRule,
  isAutoresponderActive,
  shouldAutoRespond,
  buildAutoReplyEnvelope
} from "../src/protocol/autoresponder.js";

// ─── validateAutoresponderRule ──────────────────────────────────────────────

test("validateAutoresponderRule: valid rule", () => {
  const errors = validateAutoresponderRule({
    message: "I'm out of office",
    schedule_start: "2025-06-01T00:00:00Z",
    schedule_end: "2025-06-15T00:00:00Z",
    frequency_limit: "once_per_sender"
  });
  assert.equal(errors.length, 0);
});

test("validateAutoresponderRule: missing message", () => {
  const errors = validateAutoresponderRule({});
  assert.ok(errors.some((e) => e.field === "message"));
});

test("validateAutoresponderRule: invalid schedule_start", () => {
  const errors = validateAutoresponderRule({ message: "ooo", schedule_start: "not-a-date" });
  assert.ok(errors.some((e) => e.field === "schedule_start"));
});

test("validateAutoresponderRule: schedule_end before schedule_start", () => {
  const errors = validateAutoresponderRule({
    message: "ooo",
    schedule_start: "2025-06-15T00:00:00Z",
    schedule_end: "2025-06-01T00:00:00Z"
  });
  assert.ok(errors.some((e) => e.field === "schedule_end"));
});

test("validateAutoresponderRule: invalid frequency_limit", () => {
  const errors = validateAutoresponderRule({ message: "ooo", frequency_limit: "twice" });
  assert.ok(errors.some((e) => e.field === "frequency_limit"));
});

test("validateAutoresponderRule: null input", () => {
  const errors = validateAutoresponderRule(null);
  assert.ok(errors.length > 0);
});

// ─── isAutoresponderActive ─────────────────────────────────────────────────

test("isAutoresponderActive: true when within schedule", () => {
  const now = Date.parse("2025-06-10T12:00:00Z");
  assert.equal(isAutoresponderActive({
    schedule_start: "2025-06-01T00:00:00Z",
    schedule_end: "2025-06-15T00:00:00Z"
  }, now), true);
});

test("isAutoresponderActive: false before schedule_start", () => {
  const now = Date.parse("2025-05-01T00:00:00Z");
  assert.equal(isAutoresponderActive({
    schedule_start: "2025-06-01T00:00:00Z"
  }, now), false);
});

test("isAutoresponderActive: false after schedule_end", () => {
  const now = Date.parse("2025-07-01T00:00:00Z");
  assert.equal(isAutoresponderActive({
    schedule_end: "2025-06-15T00:00:00Z"
  }, now), false);
});

test("isAutoresponderActive: true with no schedule constraints", () => {
  assert.equal(isAutoresponderActive({ message: "ooo" }), true);
});

test("isAutoresponderActive: false for null rule", () => {
  assert.equal(isAutoresponderActive(null), false);
});

// ─── shouldAutoRespond ─────────────────────────────────────────────────────

test("shouldAutoRespond: allows normal message", () => {
  const envelope = {
    from: { identity: "loom://sender" },
    content: { structured: { intent: "message.general@v1" } }
  };
  const rule = { message: "ooo" };
  const result = shouldAutoRespond(envelope, rule);
  assert.equal(result.respond, true);
});

test("shouldAutoRespond: suppresses auto-reply intent", () => {
  const envelope = {
    from: { identity: "loom://sender" },
    content: { structured: { intent: "notification.autoreply@v1" } }
  };
  const result = shouldAutoRespond(envelope, { message: "ooo" });
  assert.equal(result.respond, false);
  assert.equal(result.reason, "suppressed_intent");
});

test("shouldAutoRespond: suppresses receipt", () => {
  const envelope = {
    from: { identity: "loom://sender" },
    content: { structured: { intent: "receipt.delivered@v1" } }
  };
  const result = shouldAutoRespond(envelope, { message: "ooo" });
  assert.equal(result.respond, false);
});

test("shouldAutoRespond: respects once_per_sender frequency", () => {
  const envelope = {
    from: { identity: "loom://sender" },
    content: { structured: { intent: "message.general@v1" } }
  };
  const history = new Map([["loom://sender", new Date().toISOString()]]);
  const result = shouldAutoRespond(envelope, { message: "ooo", frequency_limit: "once_per_sender" }, history);
  assert.equal(result.respond, false);
  assert.equal(result.reason, "already_sent_to_sender");
});

test("shouldAutoRespond: once_per_day allows after 24h", () => {
  const envelope = {
    from: { identity: "loom://sender" },
    content: { structured: { intent: "message.general@v1" } }
  };
  const old = new Date(Date.now() - 2 * 86400000).toISOString(); // 2 days ago
  const history = new Map([["loom://sender", old]]);
  const result = shouldAutoRespond(envelope, { message: "ooo", frequency_limit: "once_per_day" }, history);
  assert.equal(result.respond, true);
});

test("shouldAutoRespond: no sender returns false", () => {
  const envelope = { content: { structured: { intent: "message.general@v1" } } };
  const result = shouldAutoRespond(envelope, { message: "ooo" });
  assert.equal(result.respond, false);
  assert.equal(result.reason, "no_sender");
});

// ─── buildAutoReplyEnvelope ────────────────────────────────────────────────

test("buildAutoReplyEnvelope: creates correct envelope", () => {
  const original = {
    id: "env_1",
    thread_id: "thr_1",
    from: { identity: "loom://sender" }
  };
  const rule = { message: "I'm out of office until next week" };
  const reply = buildAutoReplyEnvelope(original, rule, "loom://responder");

  assert.ok(reply.id.startsWith("env_"));
  assert.equal(reply.thread_id, "thr_1");
  assert.equal(reply.parent_id, "env_1");
  assert.equal(reply.type, "notification");
  assert.equal(reply.from.identity, "loom://responder");
  assert.equal(reply.to[0].identity, "loom://sender");
  assert.equal(reply.content.structured.intent, "notification.autoreply@v1");
  assert.equal(reply.content.human.text, "I'm out of office until next week");
  assert.equal(reply.content.structured.parameters.triggered_by_envelope_id, "env_1");
});
