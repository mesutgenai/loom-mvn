import test from "node:test";
import assert from "node:assert/strict";

import {
  buildDeliveryReceipt,
  buildReadReceipt,
  buildFailureReceipt,
  isAutoReplyIntent,
  shouldSuppressAutoReply
} from "../src/protocol/receipts.js";

const MOCK_ENVELOPE = {
  id: "env_original",
  thread_id: "thr_1",
  from: { identity: "loom://sender@example.com" },
  to: [{ identity: "loom://recipient@example.com", role: "primary" }],
  content: {
    structured: { intent: "message.general@v1" }
  }
};

// ─── buildDeliveryReceipt ───────────────────────────────────────────────────

test("buildDeliveryReceipt creates correct envelope shape", () => {
  const receipt = buildDeliveryReceipt(MOCK_ENVELOPE, {
    fromIdentity: "loom://system@example.com"
  });
  assert.equal(receipt.loom, "1.1");
  assert.ok(receipt.id.startsWith("env_"));
  assert.equal(receipt.thread_id, "thr_1");
  assert.equal(receipt.parent_id, "env_original");
  assert.equal(receipt.type, "receipt");
  assert.equal(receipt.from.identity, "loom://system@example.com");
  assert.equal(receipt.to[0].identity, "loom://sender@example.com");
  assert.equal(receipt.content.structured.intent, "receipt.delivered@v1");
  assert.equal(receipt.content.structured.parameters.original_envelope_id, "env_original");
  assert.ok(receipt.content.structured.parameters.timestamp);
});

test("buildDeliveryReceipt includes node_id when provided", () => {
  const receipt = buildDeliveryReceipt(MOCK_ENVELOPE, {
    fromIdentity: "loom://sys",
    nodeId: "node_abc"
  });
  assert.equal(receipt.content.structured.parameters.node_id, "node_abc");
});

// ─── buildReadReceipt ───────────────────────────────────────────────────────

test("buildReadReceipt creates correct envelope", () => {
  const receipt = buildReadReceipt(MOCK_ENVELOPE, {
    fromIdentity: "loom://reader@example.com"
  });
  assert.equal(receipt.content.structured.intent, "receipt.read@v1");
  assert.ok(receipt.content.structured.parameters.read_at);
  assert.equal(receipt.content.structured.parameters.user_confirmed, true);
});

test("buildReadReceipt includes device_id", () => {
  const receipt = buildReadReceipt(MOCK_ENVELOPE, {
    fromIdentity: "loom://reader",
    deviceId: "device_1"
  });
  assert.equal(receipt.content.structured.parameters.device_id, "device_1");
});

// ─── buildFailureReceipt ────────────────────────────────────────────────────

test("buildFailureReceipt creates correct envelope", () => {
  const receipt = buildFailureReceipt(MOCK_ENVELOPE, {
    fromIdentity: "loom://system",
    reason: "mailbox_full"
  });
  assert.equal(receipt.content.structured.intent, "receipt.failed@v1");
  assert.equal(receipt.content.structured.parameters.reason, "mailbox_full");
  assert.ok(receipt.content.structured.parameters.failed_at);
});

test("buildFailureReceipt includes details and retry_after", () => {
  const receipt = buildFailureReceipt(MOCK_ENVELOPE, {
    fromIdentity: "loom://system",
    reason: "timeout",
    details: "DNS resolution failed",
    retryAfter: "2025-01-01T01:00:00Z"
  });
  assert.equal(receipt.content.structured.parameters.details, "DNS resolution failed");
  assert.equal(receipt.content.structured.parameters.retry_after, "2025-01-01T01:00:00Z");
});

// ─── isAutoReplyIntent ──────────────────────────────────────────────────────

test("isAutoReplyIntent: true for autoreply", () => {
  assert.equal(isAutoReplyIntent("notification.autoreply@v1"), true);
});

test("isAutoReplyIntent: false for other intents", () => {
  assert.equal(isAutoReplyIntent("message.general@v1"), false);
  assert.equal(isAutoReplyIntent("receipt.delivered@v1"), false);
});

// ─── shouldSuppressAutoReply ────────────────────────────────────────────────

test("shouldSuppressAutoReply: suppress for auto-replies", () => {
  const env = { content: { structured: { intent: "notification.autoreply@v1" } } };
  assert.equal(shouldSuppressAutoReply(env), true);
});

test("shouldSuppressAutoReply: suppress for receipts", () => {
  assert.equal(shouldSuppressAutoReply({ content: { structured: { intent: "receipt.delivered@v1" } } }), true);
  assert.equal(shouldSuppressAutoReply({ content: { structured: { intent: "receipt.read@v1" } } }), true);
  assert.equal(shouldSuppressAutoReply({ content: { structured: { intent: "receipt.failed@v1" } } }), true);
});

test("shouldSuppressAutoReply: suppress for system notifications", () => {
  assert.equal(shouldSuppressAutoReply({ content: { structured: { intent: "notification.system@v1" } } }), true);
});

test("shouldSuppressAutoReply: allow for normal messages", () => {
  assert.equal(shouldSuppressAutoReply({ content: { structured: { intent: "message.general@v1" } } }), false);
});

test("shouldSuppressAutoReply: allow for null envelope", () => {
  assert.equal(shouldSuppressAutoReply(null), false);
});
