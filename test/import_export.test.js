import test from "node:test";
import assert from "node:assert/strict";

import {
  IMPORT_LABEL,
  validateImportPayload,
  buildExportPackage,
  prepareImportEnvelopes,
  prepareImportThreads,
  parseEmailHeaders,
  mapMessageIdToEnvelopeId,
  mapReferencesToParent
} from "../src/protocol/import_export.js";

// ─── Constants ──────────────────────────────────────────────────────────────

test("IMPORT_LABEL is sys.imported", () => {
  assert.equal(IMPORT_LABEL, "sys.imported");
});

// ─── validateImportPayload ─────────────────────────────────────────────────

test("validateImportPayload: valid payload", () => {
  const errors = validateImportPayload({ format: "loom", envelopes: [], threads: [] });
  assert.equal(errors.length, 0);
});

test("validateImportPayload: invalid format", () => {
  const errors = validateImportPayload({ format: "csv" });
  assert.ok(errors.some((e) => e.field === "format"));
});

test("validateImportPayload: envelopes not array", () => {
  const errors = validateImportPayload({ envelopes: "not-array" });
  assert.ok(errors.some((e) => e.field === "envelopes"));
});

test("validateImportPayload: null input", () => {
  const errors = validateImportPayload(null);
  assert.ok(errors.length > 0);
});

test("validateImportPayload: mbox and eml formats are valid", () => {
  assert.equal(validateImportPayload({ format: "mbox" }).length, 0);
  assert.equal(validateImportPayload({ format: "eml" }).length, 0);
});

// ─── buildExportPackage ────────────────────────────────────────────────────

test("buildExportPackage: exports all threads and envelopes", () => {
  const state = {
    threads: [
      { id: "thr_1", envelope_ids: ["e1"], participants: [{ identity: "loom://alice" }] }
    ],
    envelopes: [{ id: "e1", thread_id: "thr_1" }]
  };
  const pkg = buildExportPackage(state);
  assert.equal(pkg.loom, "1.1");
  assert.equal(pkg.format, "loom");
  assert.equal(pkg.thread_count, 1);
  assert.equal(pkg.envelope_count, 1);
  assert.ok(pkg.exported_at);
});

test("buildExportPackage: filters by threadIds", () => {
  const state = {
    threads: [
      { id: "thr_1", envelope_ids: ["e1"] },
      { id: "thr_2", envelope_ids: ["e2"] }
    ],
    envelopes: [
      { id: "e1", thread_id: "thr_1" },
      { id: "e2", thread_id: "thr_2" }
    ]
  };
  const pkg = buildExportPackage(state, { threadIds: ["thr_1"] });
  assert.equal(pkg.thread_count, 1);
  assert.equal(pkg.envelope_count, 1);
  assert.equal(pkg.threads[0].id, "thr_1");
});

test("buildExportPackage: filters by identityFilter", () => {
  const state = {
    threads: [
      { id: "thr_1", participants: [{ identity: "loom://alice" }] },
      { id: "thr_2", participants: [{ identity: "loom://bob" }] }
    ],
    envelopes: [
      { id: "e1", thread_id: "thr_1" },
      { id: "e2", thread_id: "thr_2" }
    ]
  };
  const pkg = buildExportPackage(state, { identityFilter: "loom://alice" });
  assert.equal(pkg.thread_count, 1);
  assert.equal(pkg.threads[0].id, "thr_1");
});

test("buildExportPackage: includes blobs when requested", () => {
  const state = { threads: [], envelopes: [], blobs: ["b1", "b2"] };
  const pkg = buildExportPackage(state, { includeBlobs: true });
  assert.deepEqual(pkg.blobs, ["b1", "b2"]);
});

// ─── prepareImportEnvelopes ────────────────────────────────────────────────

test("prepareImportEnvelopes: marks envelopes as imported", () => {
  const envelopes = [
    { id: "e1", meta: { node_id: "n1" } },
    { id: "e2" }
  ];
  const result = prepareImportEnvelopes(envelopes);
  assert.equal(result.length, 2);
  assert.equal(result[0].meta.imported, true);
  assert.ok(result[0].meta.imported_at);
  assert.equal(result[0].meta.node_id, "n1"); // preserved
  assert.equal(result[1].meta.imported, true);
});

// ─── prepareImportThreads ──────────────────────────────────────────────────

test("prepareImportThreads: adds sys.imported label", () => {
  const threads = [
    { id: "thr_1", labels: ["inbox"] },
    { id: "thr_2", labels: [] }
  ];
  const result = prepareImportThreads(threads);
  assert.ok(result[0].labels.includes("sys.imported"));
  assert.ok(result[0].labels.includes("inbox"));
  assert.ok(result[1].labels.includes("sys.imported"));
});

test("prepareImportThreads: no duplicate labels", () => {
  const threads = [{ id: "thr_1", labels: ["sys.imported"] }];
  const result = prepareImportThreads(threads);
  assert.equal(result[0].labels.filter((l) => l === "sys.imported").length, 1);
});

// ─── parseEmailHeaders ─────────────────────────────────────────────────────

test("parseEmailHeaders: parses standard headers", () => {
  const raw = "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello";
  const headers = parseEmailHeaders(raw);
  assert.equal(headers["from"], "alice@example.com");
  assert.equal(headers["to"], "bob@example.com");
  assert.equal(headers["subject"], "Hello");
});

test("parseEmailHeaders: handles folded headers", () => {
  const raw = "Subject: This is a\r\n very long subject";
  const headers = parseEmailHeaders(raw);
  assert.equal(headers["subject"], "This is a very long subject");
});

test("parseEmailHeaders: keys are lowercase", () => {
  const raw = "Content-Type: text/plain";
  const headers = parseEmailHeaders(raw);
  assert.equal(headers["content-type"], "text/plain");
});

test("parseEmailHeaders: non-string returns empty object", () => {
  assert.deepEqual(parseEmailHeaders(null), {});
});

// ─── mapMessageIdToEnvelopeId ──────────────────────────────────────────────

test("mapMessageIdToEnvelopeId: strips angle brackets", () => {
  assert.equal(mapMessageIdToEnvelopeId("<msg123@example.com>"), "msg123@example.com");
});

test("mapMessageIdToEnvelopeId: handles no brackets", () => {
  assert.equal(mapMessageIdToEnvelopeId("msg123"), "msg123");
});

test("mapMessageIdToEnvelopeId: null returns null", () => {
  assert.equal(mapMessageIdToEnvelopeId(null), null);
});

test("mapMessageIdToEnvelopeId: empty returns null", () => {
  assert.equal(mapMessageIdToEnvelopeId(""), null);
});

// ─── mapReferencesToParent ─────────────────────────────────────────────────

test("mapReferencesToParent: In-Reply-To takes precedence", () => {
  const result = mapReferencesToParent("<parent@ex>", "<ref1@ex> <ref2@ex>");
  assert.equal(result, "parent@ex");
});

test("mapReferencesToParent: falls back to last reference", () => {
  const result = mapReferencesToParent(null, "<ref1@ex> <ref2@ex>");
  assert.equal(result, "ref2@ex");
});

test("mapReferencesToParent: returns null if neither", () => {
  assert.equal(mapReferencesToParent(null, null), null);
});
