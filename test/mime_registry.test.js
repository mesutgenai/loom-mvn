import test from "node:test";
import assert from "node:assert/strict";

import {
  normalizeMimeType,
  isRegisteredMimeType,
  classifyMimeType,
  isDangerousMimeType,
  isAllowedBlobMimeType,
  validateContentFormat,
  getMimeTypeExtensions,
  guessMimeTypeFromExtension,
  validateMimePolicy,
  VALID_CONTENT_FORMATS,
  MIME_POLICY_MODES,
  MIME_CATEGORIES,
  DEFAULT_MIME_POLICY,
  DANGEROUS_MIME_TYPES,
  TEXT_MIME_TYPES,
  IMAGE_MIME_TYPES,
  DOCUMENT_MIME_TYPES,
  AUDIO_MIME_TYPES,
  VIDEO_MIME_TYPES
} from "../src/protocol/mime_registry.js";

// ─── Constants ───────────────────────────────────────────────────────────────

test("VALID_CONTENT_FORMATS is frozen", () => {
  assert.ok(Object.isFrozen(VALID_CONTENT_FORMATS));
  assert.ok(VALID_CONTENT_FORMATS.includes("plaintext"));
  assert.ok(VALID_CONTENT_FORMATS.includes("markdown"));
  assert.ok(VALID_CONTENT_FORMATS.includes("html"));
});

test("MIME_POLICY_MODES is frozen", () => {
  assert.ok(Object.isFrozen(MIME_POLICY_MODES));
  assert.ok(MIME_POLICY_MODES.includes("allowlist"));
  assert.ok(MIME_POLICY_MODES.includes("denylist"));
  assert.ok(MIME_POLICY_MODES.includes("permissive"));
});

test("DEFAULT_MIME_POLICY is frozen with expected defaults", () => {
  assert.ok(Object.isFrozen(DEFAULT_MIME_POLICY));
  assert.equal(DEFAULT_MIME_POLICY.mode, "denylist");
  assert.deepEqual(DEFAULT_MIME_POLICY.allowed_categories, []);
  assert.deepEqual(DEFAULT_MIME_POLICY.denied_types, []);
  assert.equal(DEFAULT_MIME_POLICY.max_types_per_envelope, 20);
  assert.equal(DEFAULT_MIME_POLICY.require_registered, false);
});

test("DANGEROUS_MIME_TYPES is frozen and contains expected entries", () => {
  assert.ok(Object.isFrozen(DANGEROUS_MIME_TYPES));
  assert.ok(DANGEROUS_MIME_TYPES.includes("application/x-msdownload"));
  assert.ok(DANGEROUS_MIME_TYPES.includes("application/x-dosexec"));
  assert.ok(DANGEROUS_MIME_TYPES.includes("application/x-sh"));
  assert.ok(DANGEROUS_MIME_TYPES.includes("application/x-bat"));
  assert.ok(DANGEROUS_MIME_TYPES.includes("application/java-archive"));
});

test("MIME_CATEGORIES is frozen with expected entries", () => {
  assert.ok(Object.isFrozen(MIME_CATEGORIES));
  assert.equal(MIME_CATEGORIES.length, 7);
  assert.ok(MIME_CATEGORIES.includes("text"));
  assert.ok(MIME_CATEGORIES.includes("unknown"));
});

test("category arrays are all frozen", () => {
  assert.ok(Object.isFrozen(TEXT_MIME_TYPES));
  assert.ok(Object.isFrozen(IMAGE_MIME_TYPES));
  assert.ok(Object.isFrozen(DOCUMENT_MIME_TYPES));
  assert.ok(Object.isFrozen(AUDIO_MIME_TYPES));
  assert.ok(Object.isFrozen(VIDEO_MIME_TYPES));
});

// ─── normalizeMimeType ───────────────────────────────────────────────────────

test("normalizeMimeType lowercases and trims", () => {
  assert.equal(normalizeMimeType("  TEXT/HTML  "), "text/html");
});

test("normalizeMimeType strips charset parameters", () => {
  assert.equal(normalizeMimeType("text/html; charset=utf-8"), "text/html");
});

test("normalizeMimeType strips multiple parameters", () => {
  assert.equal(normalizeMimeType("text/html; charset=utf-8; boundary=something"), "text/html");
});

test("normalizeMimeType returns empty string for null", () => {
  assert.equal(normalizeMimeType(null), "");
});

test("normalizeMimeType returns empty string for non-string", () => {
  assert.equal(normalizeMimeType(123), "");
  assert.equal(normalizeMimeType(undefined), "");
});

test("normalizeMimeType handles already-normalized input", () => {
  assert.equal(normalizeMimeType("application/json"), "application/json");
});

// ─── isRegisteredMimeType ────────────────────────────────────────────────────

test("isRegisteredMimeType returns true for registered text type", () => {
  assert.ok(isRegisteredMimeType("text/plain"));
});

test("isRegisteredMimeType returns true for registered image type", () => {
  assert.ok(isRegisteredMimeType("image/png"));
});

test("isRegisteredMimeType returns true for registered document type", () => {
  assert.ok(isRegisteredMimeType("application/pdf"));
});

test("isRegisteredMimeType returns false for unregistered type", () => {
  assert.equal(isRegisteredMimeType("application/x-custom-binary"), false);
});

test("isRegisteredMimeType handles case normalization", () => {
  assert.ok(isRegisteredMimeType("TEXT/PLAIN"));
  assert.ok(isRegisteredMimeType("Image/PNG"));
});

test("isRegisteredMimeType returns false for null", () => {
  assert.equal(isRegisteredMimeType(null), false);
});

// ─── classifyMimeType ────────────────────────────────────────────────────────

test("classifyMimeType classifies text types", () => {
  assert.equal(classifyMimeType("text/plain"), "text");
  assert.equal(classifyMimeType("text/html"), "text");
});

test("classifyMimeType classifies image types", () => {
  assert.equal(classifyMimeType("image/png"), "image");
  assert.equal(classifyMimeType("image/jpeg"), "image");
});

test("classifyMimeType classifies document types", () => {
  assert.equal(classifyMimeType("application/pdf"), "document");
  assert.equal(classifyMimeType("application/json"), "document");
});

test("classifyMimeType classifies audio types", () => {
  assert.equal(classifyMimeType("audio/mpeg"), "audio");
});

test("classifyMimeType classifies video types", () => {
  assert.equal(classifyMimeType("video/mp4"), "video");
});

test("classifyMimeType classifies dangerous types", () => {
  assert.equal(classifyMimeType("application/x-msdownload"), "dangerous");
  assert.equal(classifyMimeType("application/x-sh"), "dangerous");
});

test("classifyMimeType returns unknown for unregistered", () => {
  assert.equal(classifyMimeType("application/x-custom"), "unknown");
  assert.equal(classifyMimeType("foo/bar"), "unknown");
});

test("classifyMimeType returns unknown for null input", () => {
  assert.equal(classifyMimeType(null), "unknown");
  assert.equal(classifyMimeType(""), "unknown");
});

// ─── isDangerousMimeType ─────────────────────────────────────────────────────

test("isDangerousMimeType detects x-msdownload", () => {
  assert.ok(isDangerousMimeType("application/x-msdownload"));
});

test("isDangerousMimeType detects x-dosexec", () => {
  assert.ok(isDangerousMimeType("application/x-dosexec"));
});

test("isDangerousMimeType detects x-sh", () => {
  assert.ok(isDangerousMimeType("application/x-sh"));
});

test("isDangerousMimeType detects x-bat", () => {
  assert.ok(isDangerousMimeType("application/x-bat"));
});

test("isDangerousMimeType detects x-ms-installer", () => {
  assert.ok(isDangerousMimeType("application/x-ms-installer"));
});

test("isDangerousMimeType returns false for safe types", () => {
  assert.equal(isDangerousMimeType("text/plain"), false);
  assert.equal(isDangerousMimeType("image/png"), false);
  assert.equal(isDangerousMimeType("application/pdf"), false);
});

test("isDangerousMimeType handles case insensitive", () => {
  assert.ok(isDangerousMimeType("APPLICATION/X-MSDOWNLOAD"));
});

test("isDangerousMimeType returns false for null", () => {
  assert.equal(isDangerousMimeType(null), false);
  assert.equal(isDangerousMimeType(""), false);
});

// ─── isAllowedBlobMimeType ───────────────────────────────────────────────────

test("isAllowedBlobMimeType permissive mode allows any type", () => {
  const result = isAllowedBlobMimeType("application/x-msdownload", { mode: "permissive" });
  assert.equal(result.allowed, true);
  assert.equal(result.reason, null);
});

test("isAllowedBlobMimeType allowlist mode allows matching category", () => {
  const result = isAllowedBlobMimeType("text/plain", { mode: "allowlist", allowed_categories: ["text", "image"] });
  assert.equal(result.allowed, true);
});

test("isAllowedBlobMimeType allowlist mode denies non-matching category", () => {
  const result = isAllowedBlobMimeType("video/mp4", { mode: "allowlist", allowed_categories: ["text", "image"] });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes("not in allowed categories"));
});

test("isAllowedBlobMimeType denylist mode allows non-denied type", () => {
  const result = isAllowedBlobMimeType("text/plain", { mode: "denylist" });
  assert.equal(result.allowed, true);
});

test("isAllowedBlobMimeType denylist mode denies explicit type", () => {
  const result = isAllowedBlobMimeType("text/plain", { mode: "denylist", denied_types: ["text/plain"] });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes("explicitly denied"));
});

test("isAllowedBlobMimeType denylist mode denies dangerous types", () => {
  const result = isAllowedBlobMimeType("application/x-msdownload", { mode: "denylist" });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes("dangerous"));
});

test("isAllowedBlobMimeType require_registered blocks unregistered", () => {
  const result = isAllowedBlobMimeType("application/x-custom", { mode: "denylist", require_registered: true });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes("unregistered"));
});

test("isAllowedBlobMimeType require_registered allows registered", () => {
  const result = isAllowedBlobMimeType("text/plain", { mode: "denylist", require_registered: true });
  assert.equal(result.allowed, true);
});

test("isAllowedBlobMimeType with null policy uses defaults", () => {
  const result = isAllowedBlobMimeType("text/plain", null);
  assert.equal(result.allowed, true);
});

test("isAllowedBlobMimeType allows empty mime type", () => {
  const result = isAllowedBlobMimeType("", null);
  assert.equal(result.allowed, true);
});

// ─── validateContentFormat ───────────────────────────────────────────────────

test("validateContentFormat accepts plaintext", () => {
  assert.equal(validateContentFormat("plaintext").length, 0);
});

test("validateContentFormat accepts markdown", () => {
  assert.equal(validateContentFormat("markdown").length, 0);
});

test("validateContentFormat accepts html", () => {
  assert.equal(validateContentFormat("html").length, 0);
});

test("validateContentFormat rejects invalid format", () => {
  const errors = validateContentFormat("rtf");
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, "content.human.format");
  assert.ok(errors[0].reason.includes("must be one of"));
});

test("validateContentFormat returns empty for null", () => {
  assert.equal(validateContentFormat(null).length, 0);
  assert.equal(validateContentFormat(undefined).length, 0);
});

test("validateContentFormat rejects non-string", () => {
  const errors = validateContentFormat(123);
  assert.equal(errors.length, 1);
});

// ─── getMimeTypeExtensions ───────────────────────────────────────────────────

test("getMimeTypeExtensions returns extensions for application/pdf", () => {
  const extensions = getMimeTypeExtensions("application/pdf");
  assert.ok(extensions.includes("pdf"));
});

test("getMimeTypeExtensions returns extensions for image/jpeg", () => {
  const extensions = getMimeTypeExtensions("image/jpeg");
  assert.ok(extensions.includes("jpg"));
  assert.ok(extensions.includes("jpeg"));
});

test("getMimeTypeExtensions returns empty array for unknown type", () => {
  const extensions = getMimeTypeExtensions("application/x-unknown");
  assert.deepEqual(extensions, []);
});

// ─── guessMimeTypeFromExtension ──────────────────────────────────────────────

test("guessMimeTypeFromExtension guesses pdf", () => {
  assert.equal(guessMimeTypeFromExtension("pdf"), "application/pdf");
});

test("guessMimeTypeFromExtension guesses jpg", () => {
  assert.equal(guessMimeTypeFromExtension("jpg"), "image/jpeg");
});

test("guessMimeTypeFromExtension handles leading dot", () => {
  assert.equal(guessMimeTypeFromExtension(".png"), "image/png");
});

test("guessMimeTypeFromExtension returns null for unknown", () => {
  assert.equal(guessMimeTypeFromExtension("xyz"), null);
});

test("guessMimeTypeFromExtension is case insensitive", () => {
  assert.equal(guessMimeTypeFromExtension("PDF"), "application/pdf");
  assert.equal(guessMimeTypeFromExtension(".JPG"), "image/jpeg");
});

test("guessMimeTypeFromExtension returns null for null/empty", () => {
  assert.equal(guessMimeTypeFromExtension(null), null);
  assert.equal(guessMimeTypeFromExtension(""), null);
});

// ─── validateMimePolicy ──────────────────────────────────────────────────────

test("validateMimePolicy accepts valid policy", () => {
  const errors = validateMimePolicy({
    mode: "denylist",
    allowed_categories: ["text", "image"],
    denied_types: ["application/x-msdownload"],
    max_types_per_envelope: 10,
    require_registered: false
  });
  assert.equal(errors.length, 0);
});

test("validateMimePolicy rejects invalid mode", () => {
  const errors = validateMimePolicy({ mode: "invalid" });
  assert.ok(errors.some((e) => e.field === "policy.mode"));
});

test("validateMimePolicy rejects invalid allowed_categories entry", () => {
  const errors = validateMimePolicy({ allowed_categories: ["text", "invalid_cat"] });
  assert.ok(errors.some((e) => e.field.startsWith("policy.allowed_categories")));
});

test("validateMimePolicy rejects non-string denied_types entry", () => {
  const errors = validateMimePolicy({ denied_types: [123] });
  assert.ok(errors.some((e) => e.field.startsWith("policy.denied_types")));
});

test("validateMimePolicy rejects null input", () => {
  const errors = validateMimePolicy(null);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, "policy");
});

test("validateMimePolicy accepts empty policy", () => {
  const errors = validateMimePolicy({});
  assert.equal(errors.length, 0);
});

test("validateMimePolicy rejects invalid max_types_per_envelope", () => {
  const errors = validateMimePolicy({ max_types_per_envelope: 0 });
  assert.ok(errors.some((e) => e.field === "policy.max_types_per_envelope"));
});

test("validateMimePolicy rejects non-boolean require_registered", () => {
  const errors = validateMimePolicy({ require_registered: "yes" });
  assert.ok(errors.some((e) => e.field === "policy.require_registered"));
});
