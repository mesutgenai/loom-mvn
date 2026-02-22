// ─── MIME Type Registry ── Section 16.7 ──────────────────────────────────────
//
// Formal MIME type registry, normalization, classification, and policy
// validation. Pure-function module with no store or server dependencies.

// ─── MIME Type Categories ────────────────────────────────────────────────────

export const TEXT_MIME_TYPES = Object.freeze([
  "text/plain",
  "text/html",
  "text/markdown",
  "text/csv",
  "text/xml",
  "text/css"
]);

export const IMAGE_MIME_TYPES = Object.freeze([
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "image/svg+xml",
  "image/bmp",
  "image/tiff"
]);

export const DOCUMENT_MIME_TYPES = Object.freeze([
  "application/pdf",
  "application/json",
  "application/xml",
  "application/rtf",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation"
]);

export const AUDIO_MIME_TYPES = Object.freeze([
  "audio/mpeg",
  "audio/ogg",
  "audio/wav",
  "audio/webm",
  "audio/flac",
  "audio/aac"
]);

export const VIDEO_MIME_TYPES = Object.freeze([
  "video/mp4",
  "video/webm",
  "video/ogg",
  "video/quicktime"
]);

export const DANGEROUS_MIME_TYPES = Object.freeze([
  "application/x-msdownload",
  "application/x-dosexec",
  "application/x-ms-installer",
  "application/x-sh",
  "application/x-bat",
  "application/x-msi",
  "application/x-executable",
  "application/vnd.ms-excel.sheet.macroenabled.12",
  "application/vnd.ms-word.document.macroenabled.12",
  "application/vnd.ms-powerpoint.presentation.macroenabled.12",
  "application/java-archive",
  "application/x-java-archive"
]);

export const VALID_CONTENT_FORMATS = Object.freeze(["plaintext", "markdown", "html"]);

export const MIME_POLICY_MODES = Object.freeze(["allowlist", "denylist", "permissive"]);

export const MIME_CATEGORIES = Object.freeze([
  "text", "image", "document", "audio", "video", "dangerous", "unknown"
]);

export const DEFAULT_MIME_POLICY = Object.freeze({
  mode: "denylist",
  allowed_categories: [],
  denied_types: [],
  max_types_per_envelope: 20,
  require_registered: false
});

// ─── Internal Lookup Maps ────────────────────────────────────────────────────

const _CATEGORY_ENTRIES = [
  ["text", TEXT_MIME_TYPES],
  ["image", IMAGE_MIME_TYPES],
  ["document", DOCUMENT_MIME_TYPES],
  ["audio", AUDIO_MIME_TYPES],
  ["video", VIDEO_MIME_TYPES],
  ["dangerous", DANGEROUS_MIME_TYPES]
];

const _REGISTRY_SET = new Set();
const _CATEGORY_MAP = new Map();

for (const [category, types] of _CATEGORY_ENTRIES) {
  for (const type of types) {
    _REGISTRY_SET.add(type);
    _CATEGORY_MAP.set(type, category);
  }
}

const _MIME_TO_EXTENSIONS = new Map([
  ["text/plain", ["txt"]],
  ["text/html", ["html", "htm"]],
  ["text/markdown", ["md", "markdown"]],
  ["text/csv", ["csv"]],
  ["text/xml", ["xml"]],
  ["text/css", ["css"]],
  ["image/png", ["png"]],
  ["image/jpeg", ["jpg", "jpeg"]],
  ["image/gif", ["gif"]],
  ["image/webp", ["webp"]],
  ["image/svg+xml", ["svg"]],
  ["image/bmp", ["bmp"]],
  ["image/tiff", ["tiff", "tif"]],
  ["application/pdf", ["pdf"]],
  ["application/json", ["json"]],
  ["application/xml", ["xml"]],
  ["application/rtf", ["rtf"]],
  ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", ["docx"]],
  ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ["xlsx"]],
  ["application/vnd.openxmlformats-officedocument.presentationml.presentation", ["pptx"]],
  ["audio/mpeg", ["mp3"]],
  ["audio/ogg", ["ogg"]],
  ["audio/wav", ["wav"]],
  ["audio/webm", ["weba"]],
  ["audio/flac", ["flac"]],
  ["audio/aac", ["aac"]],
  ["video/mp4", ["mp4"]],
  ["video/webm", ["webm"]],
  ["video/ogg", ["ogv"]],
  ["video/quicktime", ["mov"]]
]);

const _EXTENSION_TO_MIME = new Map();
for (const [mime, extensions] of _MIME_TO_EXTENSIONS) {
  for (const ext of extensions) {
    if (!_EXTENSION_TO_MIME.has(ext)) {
      _EXTENSION_TO_MIME.set(ext, mime);
    }
  }
}

// ─── Normalization ───────────────────────────────────────────────────────────

export function normalizeMimeType(mimeType) {
  if (!mimeType || typeof mimeType !== "string") {
    return "";
  }
  return mimeType.trim().toLowerCase().split(";")[0].trim();
}

// ─── Registry Lookup ─────────────────────────────────────────────────────────

export function isRegisteredMimeType(mimeType) {
  const normalized = normalizeMimeType(mimeType);
  if (!normalized) return false;
  return _REGISTRY_SET.has(normalized);
}

export function classifyMimeType(mimeType) {
  const normalized = normalizeMimeType(mimeType);
  if (!normalized) return "unknown";
  return _CATEGORY_MAP.get(normalized) || "unknown";
}

export function isDangerousMimeType(mimeType) {
  const normalized = normalizeMimeType(mimeType);
  if (!normalized) return false;
  // Exact match against dangerous set
  if (_CATEGORY_MAP.get(normalized) === "dangerous") return true;
  // Substring match for backward compatibility with content filter behavior
  for (const dangerous of DANGEROUS_MIME_TYPES) {
    if (normalized.includes(dangerous)) return true;
  }
  return false;
}

// ─── Policy Enforcement ──────────────────────────────────────────────────────

export function isAllowedBlobMimeType(mimeType, policy) {
  const effectivePolicy = { ...DEFAULT_MIME_POLICY, ...(policy || {}) };
  const normalized = normalizeMimeType(mimeType);

  if (!normalized) {
    return { allowed: true, reason: null };
  }

  // Permissive mode always allows
  if (effectivePolicy.mode === "permissive") {
    return { allowed: true, reason: null };
  }

  // Check require_registered
  if (effectivePolicy.require_registered && !_REGISTRY_SET.has(normalized)) {
    return { allowed: false, reason: `unregistered MIME type: ${normalized}` };
  }

  const category = _CATEGORY_MAP.get(normalized) || "unknown";

  if (effectivePolicy.mode === "allowlist") {
    const allowedCategories = Array.isArray(effectivePolicy.allowed_categories)
      ? effectivePolicy.allowed_categories
      : [];
    if (allowedCategories.length > 0 && !allowedCategories.includes(category)) {
      return { allowed: false, reason: `MIME category "${category}" not in allowed categories` };
    }
    // Also check explicit deny list
    const deniedTypes = Array.isArray(effectivePolicy.denied_types) ? effectivePolicy.denied_types : [];
    if (deniedTypes.includes(normalized)) {
      return { allowed: false, reason: `MIME type explicitly denied: ${normalized}` };
    }
    return { allowed: true, reason: null };
  }

  // Denylist mode
  if (effectivePolicy.mode === "denylist") {
    // Check explicit deny list
    const deniedTypes = Array.isArray(effectivePolicy.denied_types) ? effectivePolicy.denied_types : [];
    if (deniedTypes.includes(normalized)) {
      return { allowed: false, reason: `MIME type explicitly denied: ${normalized}` };
    }
    // Dangerous types are always denied in denylist mode
    if (category === "dangerous") {
      return { allowed: false, reason: `dangerous MIME type denied: ${normalized}` };
    }
    return { allowed: true, reason: null };
  }

  return { allowed: true, reason: null };
}

// ─── Content Format Validation ───────────────────────────────────────────────

export function validateContentFormat(format) {
  if (format === undefined || format === null) {
    return [];
  }
  if (typeof format !== "string" || !VALID_CONTENT_FORMATS.includes(format)) {
    return [{ field: "content.human.format", reason: `must be one of: ${VALID_CONTENT_FORMATS.join(", ")}` }];
  }
  return [];
}

// ─── Extension Mapping ───────────────────────────────────────────────────────

export function getMimeTypeExtensions(mimeType) {
  const normalized = normalizeMimeType(mimeType);
  if (!normalized) return [];
  return _MIME_TO_EXTENSIONS.get(normalized) || [];
}

export function guessMimeTypeFromExtension(extension) {
  if (!extension || typeof extension !== "string") return null;
  const normalized = extension.trim().toLowerCase().replace(/^\./, "");
  if (!normalized) return null;
  return _EXTENSION_TO_MIME.get(normalized) || null;
}

// ─── Policy Validation ───────────────────────────────────────────────────────

export function validateMimePolicy(policy) {
  const errors = [];
  if (!policy || typeof policy !== "object") {
    return [{ field: "policy", reason: "must be an object" }];
  }

  if (policy.mode !== undefined && policy.mode !== null) {
    if (!MIME_POLICY_MODES.includes(policy.mode)) {
      errors.push({ field: "policy.mode", reason: `must be one of: ${MIME_POLICY_MODES.join(", ")}` });
    }
  }

  if (policy.allowed_categories !== undefined && policy.allowed_categories !== null) {
    if (!Array.isArray(policy.allowed_categories)) {
      errors.push({ field: "policy.allowed_categories", reason: "must be an array" });
    } else {
      for (let i = 0; i < policy.allowed_categories.length; i++) {
        if (!MIME_CATEGORIES.includes(policy.allowed_categories[i])) {
          errors.push({ field: `policy.allowed_categories[${i}]`, reason: `must be one of: ${MIME_CATEGORIES.join(", ")}` });
          break;
        }
      }
    }
  }

  if (policy.denied_types !== undefined && policy.denied_types !== null) {
    if (!Array.isArray(policy.denied_types)) {
      errors.push({ field: "policy.denied_types", reason: "must be an array" });
    } else {
      for (let i = 0; i < policy.denied_types.length; i++) {
        if (typeof policy.denied_types[i] !== "string") {
          errors.push({ field: `policy.denied_types[${i}]`, reason: "must be a string" });
          break;
        }
      }
    }
  }

  if (policy.max_types_per_envelope !== undefined && policy.max_types_per_envelope !== null) {
    if (typeof policy.max_types_per_envelope !== "number" || !Number.isInteger(policy.max_types_per_envelope) || policy.max_types_per_envelope < 1) {
      errors.push({ field: "policy.max_types_per_envelope", reason: "must be a positive integer" });
    }
  }

  if (policy.require_registered !== undefined && policy.require_registered !== null) {
    if (typeof policy.require_registered !== "boolean") {
      errors.push({ field: "policy.require_registered", reason: "must be a boolean" });
    }
  }

  return errors;
}
