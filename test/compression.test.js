import test from "node:test";
import assert from "node:assert/strict";

import {
  SUPPORTED_ENCODINGS,
  ENCODING_PRIORITY,
  DEFAULT_COMPRESSION_POLICY,
  COMPRESSIBLE_CONTENT_TYPES,
  parseAcceptEncoding,
  negotiateEncoding,
  shouldCompress,
  validateCompressionPolicy,
  buildCompressionHeaders
} from "../src/protocol/compression.js";

// ─── Constants ───────────────────────────────────────────────────────────────

test("SUPPORTED_ENCODINGS is frozen", () => {
  assert.ok(Object.isFrozen(SUPPORTED_ENCODINGS));
  assert.ok(SUPPORTED_ENCODINGS.includes("gzip"));
  assert.ok(SUPPORTED_ENCODINGS.includes("br"));
  assert.ok(SUPPORTED_ENCODINGS.includes("deflate"));
  assert.ok(SUPPORTED_ENCODINGS.includes("identity"));
});

test("ENCODING_PRIORITY is frozen with correct order", () => {
  assert.ok(Object.isFrozen(ENCODING_PRIORITY));
  assert.equal(ENCODING_PRIORITY[0], "br");
  assert.equal(ENCODING_PRIORITY[1], "gzip");
  assert.equal(ENCODING_PRIORITY[2], "deflate");
  assert.equal(ENCODING_PRIORITY[3], "identity");
});

test("DEFAULT_COMPRESSION_POLICY is frozen with expected defaults", () => {
  assert.ok(Object.isFrozen(DEFAULT_COMPRESSION_POLICY));
  assert.equal(DEFAULT_COMPRESSION_POLICY.enabled, true);
  assert.equal(DEFAULT_COMPRESSION_POLICY.min_size_bytes, 1024);
  assert.equal(DEFAULT_COMPRESSION_POLICY.preferred_encoding, "gzip");
  assert.equal(DEFAULT_COMPRESSION_POLICY.level, 6);
});

test("COMPRESSIBLE_CONTENT_TYPES is frozen and contains expected types", () => {
  assert.ok(Object.isFrozen(COMPRESSIBLE_CONTENT_TYPES));
  assert.ok(COMPRESSIBLE_CONTENT_TYPES.includes("application/json"));
  assert.ok(COMPRESSIBLE_CONTENT_TYPES.includes("text/plain"));
  assert.ok(COMPRESSIBLE_CONTENT_TYPES.includes("text/html"));
  assert.ok(COMPRESSIBLE_CONTENT_TYPES.includes("image/svg+xml"));
});

// ─── parseAcceptEncoding ─────────────────────────────────────────────────────

test("parseAcceptEncoding returns identity for null header", () => {
  const result = parseAcceptEncoding(null);
  assert.equal(result.length, 1);
  assert.equal(result[0].encoding, "identity");
  assert.equal(result[0].quality, 1.0);
});

test("parseAcceptEncoding returns identity for empty string", () => {
  const result = parseAcceptEncoding("");
  assert.equal(result.length, 1);
  assert.equal(result[0].encoding, "identity");
});

test("parseAcceptEncoding parses single encoding", () => {
  const result = parseAcceptEncoding("gzip");
  assert.equal(result.length, 1);
  assert.equal(result[0].encoding, "gzip");
  assert.equal(result[0].quality, 1.0);
});

test("parseAcceptEncoding parses multiple encodings", () => {
  const result = parseAcceptEncoding("gzip, deflate, br");
  assert.equal(result.length, 3);
  // All have quality 1.0, so should be sorted by priority: br, gzip, deflate
  assert.equal(result[0].encoding, "br");
  assert.equal(result[1].encoding, "gzip");
  assert.equal(result[2].encoding, "deflate");
});

test("parseAcceptEncoding parses quality values", () => {
  const result = parseAcceptEncoding("gzip;q=1.0, deflate;q=0.5, br;q=0.8");
  assert.equal(result[0].encoding, "gzip");
  assert.equal(result[0].quality, 1.0);
  assert.equal(result[1].encoding, "br");
  assert.equal(result[1].quality, 0.8);
  assert.equal(result[2].encoding, "deflate");
  assert.equal(result[2].quality, 0.5);
});

test("parseAcceptEncoding handles wildcard", () => {
  const result = parseAcceptEncoding("*");
  assert.equal(result.length, 1);
  assert.equal(result[0].encoding, "*");
  assert.equal(result[0].quality, 1.0);
});

test("parseAcceptEncoding handles q=0 rejection", () => {
  const result = parseAcceptEncoding("gzip;q=0, deflate");
  assert.equal(result[0].encoding, "deflate");
  assert.equal(result[0].quality, 1.0);
  assert.equal(result[1].encoding, "gzip");
  assert.equal(result[1].quality, 0);
});

test("parseAcceptEncoding normalizes to lowercase", () => {
  const result = parseAcceptEncoding("GZIP, BR");
  assert.equal(result[0].encoding, "br");
  assert.equal(result[1].encoding, "gzip");
});

// ─── negotiateEncoding ──────────────────────────────────────────────────────

test("negotiateEncoding returns identity when disabled", () => {
  assert.equal(negotiateEncoding("gzip, br", { enabled: false }), "identity");
});

test("negotiateEncoding selects gzip from header", () => {
  assert.equal(negotiateEncoding("gzip", {}), "gzip");
});

test("negotiateEncoding selects br when highest quality", () => {
  assert.equal(negotiateEncoding("gzip;q=0.5, br;q=1.0", {}), "br");
});

test("negotiateEncoding respects quality ordering", () => {
  assert.equal(negotiateEncoding("deflate;q=0.5, gzip;q=0.8", {}), "gzip");
});

test("negotiateEncoding wildcard uses preferred encoding", () => {
  assert.equal(negotiateEncoding("*", { preferred_encoding: "br" }), "br");
});

test("negotiateEncoding returns identity for unsupported only", () => {
  assert.equal(negotiateEncoding("compress, sdch", {}), "identity");
});

test("negotiateEncoding returns identity for null header", () => {
  assert.equal(negotiateEncoding(null, {}), "identity");
});

test("negotiateEncoding skips q=0 entries", () => {
  assert.equal(negotiateEncoding("br;q=0, gzip", {}), "gzip");
});

// ─── shouldCompress ─────────────────────────────────────────────────────────

test("shouldCompress returns false when disabled", () => {
  assert.equal(shouldCompress("application/json", 2048, { enabled: false }), false);
});

test("shouldCompress returns false when body too small", () => {
  assert.equal(shouldCompress("application/json", 512, {}), false);
});

test("shouldCompress returns true for application/json above min", () => {
  assert.equal(shouldCompress("application/json", 2048, {}), true);
});

test("shouldCompress returns true for text/plain above min", () => {
  assert.equal(shouldCompress("text/plain", 2048, {}), true);
});

test("shouldCompress returns false for image/png (not compressible)", () => {
  assert.equal(shouldCompress("image/png", 2048, {}), false);
});

test("shouldCompress strips content type parameters", () => {
  assert.equal(shouldCompress("application/json; charset=utf-8", 2048, {}), true);
});

test("shouldCompress returns false for null content type", () => {
  assert.equal(shouldCompress(null, 2048, {}), false);
});

// ─── validateCompressionPolicy ──────────────────────────────────────────────

test("validateCompressionPolicy accepts valid policy", () => {
  const errors = validateCompressionPolicy({
    enabled: true,
    min_size_bytes: 512,
    preferred_encoding: "br",
    level: 4
  });
  assert.equal(errors.length, 0);
});

test("validateCompressionPolicy rejects null", () => {
  const errors = validateCompressionPolicy(null);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, "compression_policy");
});

test("validateCompressionPolicy rejects invalid enabled", () => {
  const errors = validateCompressionPolicy({ enabled: "yes" });
  assert.ok(errors.some((e) => e.field === "compression_policy.enabled"));
});

test("validateCompressionPolicy rejects negative min_size_bytes", () => {
  const errors = validateCompressionPolicy({ min_size_bytes: -1 });
  assert.ok(errors.some((e) => e.field === "compression_policy.min_size_bytes"));
});

test("validateCompressionPolicy rejects unsupported encoding", () => {
  const errors = validateCompressionPolicy({ preferred_encoding: "lz4" });
  assert.ok(errors.some((e) => e.field === "compression_policy.preferred_encoding"));
});

test("validateCompressionPolicy rejects level out of range", () => {
  const errors = validateCompressionPolicy({ level: 0 });
  assert.ok(errors.some((e) => e.field === "compression_policy.level"));
  const errors2 = validateCompressionPolicy({ level: 12 });
  assert.ok(errors2.some((e) => e.field === "compression_policy.level"));
});

test("validateCompressionPolicy accepts empty policy", () => {
  assert.equal(validateCompressionPolicy({}).length, 0);
});

// ─── buildCompressionHeaders ────────────────────────────────────────────────

test("buildCompressionHeaders returns vary only for identity", () => {
  const headers = buildCompressionHeaders("identity");
  assert.equal(headers.vary, "accept-encoding");
  assert.equal(headers["content-encoding"], undefined);
});

test("buildCompressionHeaders returns content-encoding for gzip", () => {
  const headers = buildCompressionHeaders("gzip");
  assert.equal(headers["content-encoding"], "gzip");
  assert.equal(headers.vary, "accept-encoding");
});

test("buildCompressionHeaders returns content-encoding for br", () => {
  const headers = buildCompressionHeaders("br");
  assert.equal(headers["content-encoding"], "br");
  assert.equal(headers.vary, "accept-encoding");
});
