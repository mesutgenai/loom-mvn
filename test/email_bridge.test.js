import test from "node:test";
import assert from "node:assert/strict";

import {
  buildBridgeIdentity,
  buildInboundBridgeMeta,
  buildInboundEnvelope,
  buildOutboundHeaders,
  renderPlaintext,
  renderHtml,
  splitBccRecipients,
  isBridgeIdentity,
  validateBridgeIdentityRestrictions
} from "../src/protocol/email_bridge.js";

// ─── buildBridgeIdentity ───────────────────────────────────────────────────

test("buildBridgeIdentity: creates bridge:// URI", () => {
  assert.equal(buildBridgeIdentity("Alice@Example.COM"), "bridge://alice@example.com");
});

test("buildBridgeIdentity: trims whitespace", () => {
  assert.equal(buildBridgeIdentity("  user@example.com  "), "bridge://user@example.com");
});

test("buildBridgeIdentity: handles null", () => {
  assert.equal(buildBridgeIdentity(null), "bridge://");
});

// ─── buildInboundBridgeMeta ────────────────────────────────────────────────

test("buildInboundBridgeMeta: creates bridge meta", () => {
  const meta = buildInboundBridgeMeta(
    { "message-id": "<abc@example.com>" },
    { spf: "pass", dkim: "pass", dmarc: "pass" }
  );
  assert.equal(meta.bridge.source, "email");
  assert.equal(meta.bridge.original_message_id, "<abc@example.com>");
  assert.equal(meta.bridge.auth_results.spf, "pass");
  assert.equal(meta.bridge.auth_results.dkim, "pass");
  assert.equal(meta.bridge.auth_results.dmarc, "pass");
});

test("buildInboundBridgeMeta: defaults auth results to none", () => {
  const meta = buildInboundBridgeMeta({});
  assert.equal(meta.bridge.auth_results.spf, "none");
  assert.equal(meta.bridge.auth_results.dkim, "none");
  assert.equal(meta.bridge.auth_results.dmarc, "none");
});

// ─── buildInboundEnvelope ──────────────────────────────────────────────────

test("buildInboundEnvelope: creates valid envelope", () => {
  const env = buildInboundEnvelope({
    from: "alice@example.com",
    to: ["bob@example.com"],
    subject: "Hello",
    body: "Hi Bob",
    emailHeaders: { "message-id": "<msg@ex>" },
    authResults: { spf: "pass" }
  });
  assert.equal(env.loom, "1.1");
  assert.ok(env.id.startsWith("env_"));
  assert.ok(env.thread_id.startsWith("thr_"));
  assert.equal(env.type, "message");
  assert.equal(env.from.identity, "bridge://alice@example.com");
  assert.equal(env.from.type, "bridge");
  assert.equal(env.to[0].identity, "bridge://bob@example.com");
  assert.equal(env.content.human.text, "Hi Bob");
  assert.equal(env.content.structured.intent, "message.general@v1");
  assert.equal(env.content.structured.parameters.subject, "Hello");
  assert.equal(env.meta.bridge.auth_results.spf, "pass");
});

test("buildInboundEnvelope: uses provided threadId and parentId", () => {
  const env = buildInboundEnvelope({
    from: "a@ex",
    to: "b@ex",
    threadId: "thr_existing",
    parentId: "env_parent"
  });
  assert.equal(env.thread_id, "thr_existing");
  assert.equal(env.parent_id, "env_parent");
});

// ─── buildOutboundHeaders ──────────────────────────────────────────────────

test("buildOutboundHeaders: creates X-LOOM headers", () => {
  const envelope = {
    id: "env_1",
    thread_id: "thr_1",
    parent_id: "env_0",
    content: { structured: { intent: "task.create@v1" } }
  };
  const headers = buildOutboundHeaders(envelope);
  assert.equal(headers["X-LOOM-Intent"], "task.create@v1");
  assert.equal(headers["X-LOOM-Thread-ID"], "thr_1");
  assert.equal(headers["X-LOOM-Envelope-ID"], "env_1");
  assert.equal(headers["In-Reply-To"], "<env_0@loom>");
  assert.ok(headers["References"].includes("<thr_1@loom>"));
  assert.ok(headers["References"].includes("<env_0@loom>"));
});

test("buildOutboundHeaders: no In-Reply-To without parent_id", () => {
  const headers = buildOutboundHeaders({ id: "e1", thread_id: "t1", content: {} });
  assert.equal(headers["In-Reply-To"], undefined);
});

// ─── renderPlaintext ───────────────────────────────────────────────────────

test("renderPlaintext: extracts text", () => {
  const text = renderPlaintext({ content: { human: { text: "Hello World" } } });
  assert.equal(text, "Hello World");
});

test("renderPlaintext: returns empty for missing content", () => {
  assert.equal(renderPlaintext({ content: {} }), "");
});

// ─── renderHtml ────────────────────────────────────────────────────────────

test("renderHtml: returns HTML as-is when format is html", () => {
  const html = renderHtml({ content: { human: { text: "<p>Hello</p>", format: "html" } } });
  assert.equal(html, "<p>Hello</p>");
});

test("renderHtml: converts markdown bold and italic", () => {
  const html = renderHtml({ content: { human: { text: "**bold** and *italic*", format: "markdown" } } });
  assert.ok(html.includes("<strong>bold</strong>"));
  assert.ok(html.includes("<em>italic</em>"));
});

test("renderHtml: escapes HTML entities", () => {
  const html = renderHtml({ content: { human: { text: "<script>alert(1)</script>", format: "plaintext" } } });
  assert.ok(html.includes("&lt;script&gt;"));
  assert.ok(!html.includes("<script>"));
});

// ─── splitBccRecipients ────────────────────────────────────────────────────

test("splitBccRecipients: separates visible and bcc", () => {
  const envelope = {
    to: [
      { identity: "loom://alice", role: "primary" },
      { identity: "loom://bob", role: "cc" },
      { identity: "loom://carol", role: "bcc" },
      { identity: "loom://dave", role: "bcc" }
    ]
  };
  const result = splitBccRecipients(envelope);
  assert.equal(result.visible.length, 2);
  assert.equal(result.bcc.length, 2);
  assert.equal(result.bccMessages.length, 2);
  assert.equal(result.bccMessages[0].to[0].identity, "loom://carol");
});

test("splitBccRecipients: no bcc recipients", () => {
  const result = splitBccRecipients({ to: [{ identity: "a", role: "primary" }] });
  assert.equal(result.bcc.length, 0);
  assert.equal(result.bccMessages.length, 0);
});

// ─── Bridge identity restrictions ──────────────────────────────────────────

test("isBridgeIdentity: identifies bridge URIs", () => {
  assert.equal(isBridgeIdentity("bridge://user@example.com"), true);
  assert.equal(isBridgeIdentity("loom://user@example.com"), false);
  assert.equal(isBridgeIdentity(null), false);
});

test("validateBridgeIdentityRestrictions: blocks forbidden operations", () => {
  const forbidden = ["delegate", "spawn_agent", "encryption.epoch", "encryption.rotate"];
  for (const op of forbidden) {
    const errors = validateBridgeIdentityRestrictions("bridge://user@ex.com", op);
    assert.ok(errors.length > 0, `Expected error for ${op}`);
  }
});

test("validateBridgeIdentityRestrictions: allows other operations", () => {
  const errors = validateBridgeIdentityRestrictions("bridge://user@ex.com", "send");
  assert.equal(errors.length, 0);
});

test("validateBridgeIdentityRestrictions: non-bridge identity returns empty", () => {
  const errors = validateBridgeIdentityRestrictions("loom://user@ex.com", "delegate");
  assert.equal(errors.length, 0);
});
