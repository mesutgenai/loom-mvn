import test from "node:test";
import assert from "node:assert/strict";

import {
  validateBlobInitiation,
  initiateBlobUpload,
  validatePartUpload,
  recordPartUpload,
  validateBlobCompletion,
  completeBlobUpload,
  serializeBlobState,
  deserializeBlobState
} from "../src/protocol/blob.js";

// ─── validateBlobInitiation ────────────────────────────────────────────────

test("validateBlobInitiation: valid payload", () => {
  const errors = validateBlobInitiation({
    filename: "doc.pdf",
    mime_type: "application/pdf",
    size_bytes: 1024
  });
  assert.equal(errors.length, 0);
});

test("validateBlobInitiation: missing filename", () => {
  const errors = validateBlobInitiation({ mime_type: "text/plain", size_bytes: 100 });
  assert.ok(errors.some((e) => e.field === "filename"));
});

test("validateBlobInitiation: missing mime_type", () => {
  const errors = validateBlobInitiation({ filename: "f.txt", size_bytes: 100 });
  assert.ok(errors.some((e) => e.field === "mime_type"));
});

test("validateBlobInitiation: invalid size_bytes", () => {
  assert.ok(validateBlobInitiation({ filename: "f", mime_type: "t", size_bytes: 0 }).some((e) => e.field === "size_bytes"));
  assert.ok(validateBlobInitiation({ filename: "f", mime_type: "t", size_bytes: -1 }).some((e) => e.field === "size_bytes"));
  assert.ok(validateBlobInitiation({ filename: "f", mime_type: "t", size_bytes: "abc" }).some((e) => e.field === "size_bytes"));
});

test("validateBlobInitiation: size_bytes exceeds max", () => {
  const errors = validateBlobInitiation({
    filename: "big.bin",
    mime_type: "application/octet-stream",
    size_bytes: 600 * 1024 * 1024 // 600 MB
  });
  assert.ok(errors.some((e) => e.field === "size_bytes" && e.reason.includes("exceed")));
});

test("validateBlobInitiation: valid hash", () => {
  const errors = validateBlobInitiation({
    filename: "f",
    mime_type: "t",
    size_bytes: 100,
    hash: "sha256:abc123"
  });
  assert.equal(errors.length, 0);
});

test("validateBlobInitiation: invalid hash prefix", () => {
  const errors = validateBlobInitiation({
    filename: "f",
    mime_type: "t",
    size_bytes: 100,
    hash: "md5:abc"
  });
  assert.ok(errors.some((e) => e.field === "hash"));
});

test("validateBlobInitiation: null input", () => {
  const errors = validateBlobInitiation(null);
  assert.ok(errors.length > 0);
});

// ─── initiateBlobUpload ────────────────────────────────────────────────────

test("initiateBlobUpload: creates correct blob state", () => {
  const state = initiateBlobUpload({
    filename: "report.pdf",
    mime_type: "application/pdf",
    size_bytes: 25 * 1024 * 1024 // 25 MB
  });
  assert.ok(state.blob_id.startsWith("blob_"));
  assert.equal(state.filename, "report.pdf");
  assert.equal(state.mime_type, "application/pdf");
  assert.equal(state.size_bytes, 25 * 1024 * 1024);
  assert.equal(state.part_size, 10 * 1024 * 1024);
  assert.equal(state.total_parts, 3);
  assert.ok(state.uploaded_parts instanceof Set);
  assert.equal(state.uploaded_parts.size, 0);
  assert.equal(state.status, "uploading");
  assert.ok(state.created_at);
  assert.equal(state.completed_at, null);
});

test("initiateBlobUpload: custom part size", () => {
  const state = initiateBlobUpload({ size_bytes: 100 }, 50);
  assert.equal(state.part_size, 50);
  assert.equal(state.total_parts, 2);
});

test("initiateBlobUpload: single part for small file", () => {
  const state = initiateBlobUpload({ size_bytes: 1000 });
  assert.equal(state.total_parts, 1);
});

// ─── validatePartUpload ────────────────────────────────────────────────────

test("validatePartUpload: valid part", () => {
  const state = initiateBlobUpload({ size_bytes: 25 * 1024 * 1024 });
  const errors = validatePartUpload(state, 1, state.part_size);
  assert.equal(errors.length, 0);
});

test("validatePartUpload: part number out of range", () => {
  const state = initiateBlobUpload({ size_bytes: 1000 });
  assert.ok(validatePartUpload(state, 0).some((e) => e.field === "part_number"));
  assert.ok(validatePartUpload(state, 2).some((e) => e.field === "part_number"));
});

test("validatePartUpload: already uploaded part", () => {
  const state = initiateBlobUpload({ size_bytes: 1000 });
  recordPartUpload(state, 1);
  const errors = validatePartUpload(state, 1);
  assert.ok(errors.some((e) => e.field === "part_number" && e.reason.includes("already")));
});

test("validatePartUpload: wrong content length", () => {
  const state = initiateBlobUpload({ size_bytes: 25 * 1024 * 1024 });
  const errors = validatePartUpload(state, 1, 999);
  assert.ok(errors.some((e) => e.field === "content_length"));
});

test("validatePartUpload: not uploading status", () => {
  const state = initiateBlobUpload({ size_bytes: 1000 });
  state.status = "complete";
  const errors = validatePartUpload(state, 1);
  assert.ok(errors.some((e) => e.field === "status"));
});

// ─── recordPartUpload ──────────────────────────────────────────────────────

test("recordPartUpload: adds part to set", () => {
  const state = initiateBlobUpload({ size_bytes: 30 * 1024 * 1024 });
  recordPartUpload(state, 1);
  recordPartUpload(state, 2);
  assert.equal(state.uploaded_parts.size, 2);
  assert.ok(state.uploaded_parts.has(1));
  assert.ok(state.uploaded_parts.has(2));
});

// ─── validateBlobCompletion ────────────────────────────────────────────────

test("validateBlobCompletion: all parts uploaded", () => {
  const state = initiateBlobUpload({ size_bytes: 30 * 1024 * 1024 });
  recordPartUpload(state, 1);
  recordPartUpload(state, 2);
  recordPartUpload(state, 3);
  const errors = validateBlobCompletion(state);
  assert.equal(errors.length, 0);
});

test("validateBlobCompletion: missing parts", () => {
  const state = initiateBlobUpload({ size_bytes: 30 * 1024 * 1024 });
  recordPartUpload(state, 1);
  // Missing parts 2 and 3
  const errors = validateBlobCompletion(state);
  assert.ok(errors.some((e) => e.field === "parts" && e.reason.includes("2")));
});

test("validateBlobCompletion: not uploading status", () => {
  const state = initiateBlobUpload({ size_bytes: 1000 });
  state.status = "complete";
  const errors = validateBlobCompletion(state);
  assert.ok(errors.some((e) => e.field === "status"));
});

// ─── completeBlobUpload ────────────────────────────────────────────────────

test("completeBlobUpload: sets complete status", () => {
  const state = initiateBlobUpload({ size_bytes: 1000 });
  recordPartUpload(state, 1);
  const completed = completeBlobUpload(state);
  assert.equal(completed.status, "complete");
  assert.ok(completed.completed_at);
});

// ─── Serialization ──────────────────────────────────────────────────────────

test("serializeBlobState: converts Set to Array", () => {
  const state = initiateBlobUpload({ size_bytes: 20 * 1024 * 1024 });
  recordPartUpload(state, 1);
  recordPartUpload(state, 2);
  const serialized = serializeBlobState(state);
  assert.ok(Array.isArray(serialized.uploaded_parts));
  assert.deepEqual(serialized.uploaded_parts, [1, 2]);
});

test("deserializeBlobState: converts Array to Set", () => {
  const data = {
    blob_id: "blob_1",
    uploaded_parts: [1, 2, 3],
    status: "uploading"
  };
  const state = deserializeBlobState(data);
  assert.ok(state.uploaded_parts instanceof Set);
  assert.equal(state.uploaded_parts.size, 3);
});

test("deserializeBlobState: handles null", () => {
  assert.equal(deserializeBlobState(null), null);
});

test("serialize/deserialize round-trip", () => {
  const state = initiateBlobUpload({ size_bytes: 20 * 1024 * 1024 });
  recordPartUpload(state, 1);
  const serialized = serializeBlobState(state);
  const deserialized = deserializeBlobState(serialized);
  assert.equal(deserialized.blob_id, state.blob_id);
  assert.ok(deserialized.uploaded_parts.has(1));
});
