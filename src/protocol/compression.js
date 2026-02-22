// ─── Adaptive Communication Compression ── Section 16.9 ─────────────────────
//
// Accept-Encoding / Content-Encoding negotiation for JSON responses.
// Pure-function module with no node:zlib or server dependencies.

// ─── Constants ──────────────────────────────────────────────────────────────

export const SUPPORTED_ENCODINGS = Object.freeze([
  "gzip", "br", "deflate", "identity"
]);

export const ENCODING_PRIORITY = Object.freeze([
  "br", "gzip", "deflate", "identity"
]);

export const DEFAULT_COMPRESSION_POLICY = Object.freeze({
  enabled: true,
  min_size_bytes: 1024,
  preferred_encoding: "gzip",
  level: 6
});

export const COMPRESSIBLE_CONTENT_TYPES = Object.freeze([
  "application/json",
  "text/plain",
  "text/html",
  "text/css",
  "text/xml",
  "text/csv",
  "text/markdown",
  "application/xml",
  "application/javascript",
  "application/rtf",
  "image/svg+xml"
]);

// ─── Accept-Encoding Parsing ────────────────────────────────────────────────

export function parseAcceptEncoding(header) {
  if (!header || typeof header !== "string") {
    return [{ encoding: "identity", quality: 1.0 }];
  }

  const parts = header.split(",").map((p) => p.trim()).filter(Boolean);
  const entries = [];

  for (const part of parts) {
    const segments = part.split(";").map((s) => s.trim());
    const encoding = segments[0].toLowerCase();
    if (!encoding) continue;

    let quality = 1.0;
    for (let i = 1; i < segments.length; i++) {
      const match = segments[i].match(/^q\s*=\s*([\d.]+)$/);
      if (match) {
        quality = Math.min(1.0, Math.max(0, parseFloat(match[1])));
        if (Number.isNaN(quality)) quality = 0;
        break;
      }
    }

    entries.push({ encoding, quality });
  }

  if (entries.length === 0) {
    return [{ encoding: "identity", quality: 1.0 }];
  }

  // Sort by quality descending, then by ENCODING_PRIORITY index for ties
  entries.sort((a, b) => {
    if (b.quality !== a.quality) return b.quality - a.quality;
    const ai = ENCODING_PRIORITY.indexOf(a.encoding);
    const bi = ENCODING_PRIORITY.indexOf(b.encoding);
    const aIdx = ai === -1 ? ENCODING_PRIORITY.length : ai;
    const bIdx = bi === -1 ? ENCODING_PRIORITY.length : bi;
    return aIdx - bIdx;
  });

  return entries;
}

// ─── Encoding Negotiation ───────────────────────────────────────────────────

export function negotiateEncoding(header, policy) {
  const effectivePolicy = { ...DEFAULT_COMPRESSION_POLICY, ...(policy || {}) };

  if (!effectivePolicy.enabled) {
    return "identity";
  }

  const entries = parseAcceptEncoding(header);

  // Find the best supported encoding
  for (const { encoding, quality } of entries) {
    if (quality === 0) continue;

    // Wildcard matches preferred encoding
    if (encoding === "*") {
      if (SUPPORTED_ENCODINGS.includes(effectivePolicy.preferred_encoding)) {
        return effectivePolicy.preferred_encoding;
      }
      return "gzip";
    }

    if (SUPPORTED_ENCODINGS.includes(encoding)) {
      return encoding;
    }
  }

  // Check if identity was explicitly rejected (q=0)
  const identityEntry = entries.find((e) => e.encoding === "identity" || e.encoding === "*");
  if (identityEntry && identityEntry.quality === 0) {
    // Client rejects identity; try preferred encoding anyway
    return effectivePolicy.preferred_encoding;
  }

  return "identity";
}

// ─── Compression Decision ───────────────────────────────────────────────────

export function shouldCompress(contentType, bodySize, policy) {
  const effectivePolicy = { ...DEFAULT_COMPRESSION_POLICY, ...(policy || {}) };

  if (!effectivePolicy.enabled) return false;

  if (typeof bodySize !== "number" || bodySize < effectivePolicy.min_size_bytes) {
    return false;
  }

  if (!contentType || typeof contentType !== "string") return false;

  // Normalize content type (strip parameters)
  const normalized = contentType.toLowerCase().split(";")[0].trim();
  return COMPRESSIBLE_CONTENT_TYPES.includes(normalized);
}

// ─── Header Construction ────────────────────────────────────────────────────

export function buildCompressionHeaders(encoding) {
  if (!encoding || encoding === "identity") {
    return { vary: "accept-encoding" };
  }

  return {
    "content-encoding": encoding,
    vary: "accept-encoding"
  };
}

// ─── Policy Validation ──────────────────────────────────────────────────────

export function validateCompressionPolicy(policy) {
  const errors = [];

  if (!policy || typeof policy !== "object") {
    return [{ field: "compression_policy", reason: "must be an object" }];
  }

  if (policy.enabled !== undefined && policy.enabled !== null) {
    if (typeof policy.enabled !== "boolean") {
      errors.push({ field: "compression_policy.enabled", reason: "must be a boolean" });
    }
  }

  if (policy.min_size_bytes !== undefined && policy.min_size_bytes !== null) {
    if (typeof policy.min_size_bytes !== "number" || !Number.isInteger(policy.min_size_bytes) || policy.min_size_bytes < 0) {
      errors.push({ field: "compression_policy.min_size_bytes", reason: "must be a non-negative integer" });
    }
  }

  if (policy.preferred_encoding !== undefined && policy.preferred_encoding !== null) {
    if (typeof policy.preferred_encoding !== "string" || !SUPPORTED_ENCODINGS.includes(policy.preferred_encoding)) {
      errors.push({
        field: "compression_policy.preferred_encoding",
        reason: `must be one of: ${SUPPORTED_ENCODINGS.join(", ")}`
      });
    }
  }

  if (policy.level !== undefined && policy.level !== null) {
    if (typeof policy.level !== "number" || !Number.isInteger(policy.level) || policy.level < 1 || policy.level > 11) {
      errors.push({ field: "compression_policy.level", reason: "must be an integer between 1 and 11" });
    }
  }

  return errors;
}
