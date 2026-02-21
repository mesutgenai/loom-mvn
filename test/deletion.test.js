import test from "node:test";
import assert from "node:assert/strict";

import {
  DELETION_MODES,
  canDeleteEnvelope,
  eraseEnvelopeContent,
  buildCryptoShredRecord,
  validateDeletionRequest
} from "../src/protocol/deletion.js";

// ─── Constants ──────────────────────────────────────────────────────────────

test("DELETION_MODES has content_erasure and crypto_shred", () => {
  assert.equal(DELETION_MODES.CONTENT_ERASURE, "content_erasure");
  assert.equal(DELETION_MODES.CRYPTO_SHRED, "crypto_shred");
});

// ─── canDeleteEnvelope ─────────────────────────────────────────────────────

test("canDeleteEnvelope: allowed when no legal hold", () => {
  const result = canDeleteEnvelope({}, { labels: ["sys.inbox"] });
  assert.equal(result.allowed, true);
});

test("canDeleteEnvelope: blocked by legal hold", () => {
  const result = canDeleteEnvelope({}, { labels: ["sys.inbox", "sys.legal_hold"] });
  assert.equal(result.allowed, false);
  assert.equal(result.reason, "LEGAL_HOLD_ACTIVE");
});

test("canDeleteEnvelope: allowed when thread has no labels", () => {
  const result = canDeleteEnvelope({}, {});
  assert.equal(result.allowed, true);
});

// ─── eraseEnvelopeContent ──────────────────────────────────────────────────

test("eraseEnvelopeContent: retains audit skeleton", () => {
  const envelope = {
    id: "env_1",
    thread_id: "thr_1",
    from: { identity: "loom://alice" },
    created_at: "2025-01-01T00:00:00Z",
    type: "message",
    content: {
      human: { text: "secret message", format: "plaintext" },
      structured: { intent: "message.general@v1", parameters: { key: "value" } },
      encrypted: false
    },
    attachments: [{ filename: "doc.pdf" }],
    meta: { node_id: "n1" }
  };

  const erased = eraseEnvelopeContent(envelope);
  assert.equal(erased.id, "env_1");
  assert.equal(erased.thread_id, "thr_1");
  assert.equal(erased.content.human.text, "[deleted]");
  assert.deepEqual(erased.content.structured.parameters, {}); // erased
  assert.equal(erased.content.structured.intent, "message.general@v1"); // kept
  assert.deepEqual(erased.attachments, []);
  assert.equal(erased.meta.deleted, true);
  assert.ok(erased.meta.deleted_at);
  assert.equal(erased.meta.node_id, "n1"); // original meta preserved
});

test("eraseEnvelopeContent: handles missing structured content", () => {
  const envelope = {
    id: "env_2",
    content: { human: { text: "test" } },
    attachments: []
  };

  const erased = eraseEnvelopeContent(envelope);
  assert.equal(erased.content.structured, null);
});

// ─── buildCryptoShredRecord ────────────────────────────────────────────────

test("buildCryptoShredRecord: creates shred record", () => {
  const record = buildCryptoShredRecord("thr_1", 3);
  assert.equal(record.thread_id, "thr_1");
  assert.equal(record.key_epoch, 3);
  assert.ok(record.shredded_at);
  assert.equal(record.keys_destroyed, true);
});

// ─── validateDeletionRequest ───────────────────────────────────────────────

test("validateDeletionRequest: valid when allowed", () => {
  const errors = validateDeletionRequest(
    { id: "env_1" },
    { labels: ["sys.inbox"] }
  );
  assert.equal(errors.length, 0);
});

test("validateDeletionRequest: blocked by legal hold", () => {
  const errors = validateDeletionRequest(
    { id: "env_1" },
    { labels: ["sys.legal_hold"] }
  );
  assert.ok(errors.some((e) => e.field === "deletion"));
});

test("validateDeletionRequest: missing envelope id", () => {
  const errors = validateDeletionRequest(
    {},
    { labels: [] }
  );
  assert.ok(errors.some((e) => e.field === "envelope_id"));
});
