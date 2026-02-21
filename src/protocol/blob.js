// ─── Blob API — Section 16.7 ────────────────────────────────────────────────
//
// Multipart blob upload validation and state tracking.

import { generateUlid } from "./ulid.js";

const DEFAULT_PART_SIZE = 10 * 1024 * 1024; // 10 MB
const MAX_BLOB_SIZE = 500 * 1024 * 1024; // 500 MB

export function validateBlobInitiation(payload) {
  const errors = [];
  if (!payload || typeof payload !== "object") {
    errors.push({ field: "payload", reason: "must be an object" });
    return errors;
  }

  if (!payload.filename || typeof payload.filename !== "string") {
    errors.push({ field: "filename", reason: "required non-empty string" });
  }

  if (!payload.mime_type || typeof payload.mime_type !== "string") {
    errors.push({ field: "mime_type", reason: "required non-empty string" });
  }

  if (!Number.isInteger(payload.size_bytes) || payload.size_bytes <= 0) {
    errors.push({ field: "size_bytes", reason: "required positive integer" });
  } else if (payload.size_bytes > MAX_BLOB_SIZE) {
    errors.push({ field: "size_bytes", reason: `must not exceed ${MAX_BLOB_SIZE} bytes` });
  }

  if (payload.hash !== undefined) {
    if (typeof payload.hash !== "string" || !payload.hash.startsWith("sha256:")) {
      errors.push({ field: "hash", reason: 'must be a string starting with "sha256:"' });
    }
  }

  return errors;
}

export function initiateBlobUpload(payload, partSize = DEFAULT_PART_SIZE) {
  const totalParts = Math.ceil(payload.size_bytes / partSize);

  return {
    blob_id: `blob_${generateUlid()}`,
    filename: payload.filename,
    mime_type: payload.mime_type,
    size_bytes: payload.size_bytes,
    hash: payload.hash || null,
    part_size: partSize,
    total_parts: totalParts,
    uploaded_parts: new Set(),
    status: "uploading",
    created_at: new Date().toISOString(),
    completed_at: null
  };
}

export function validatePartUpload(blobState, partNumber, contentLength) {
  const errors = [];

  if (blobState.status !== "uploading") {
    errors.push({ field: "status", reason: `blob is ${blobState.status}, not uploading` });
    return errors;
  }

  if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > blobState.total_parts) {
    errors.push({ field: "part_number", reason: `must be between 1 and ${blobState.total_parts}` });
  }

  if (blobState.uploaded_parts.has(partNumber)) {
    errors.push({ field: "part_number", reason: "part already uploaded" });
  }

  // Last part may be smaller
  const isLastPart = partNumber === blobState.total_parts;
  const expectedSize = isLastPart
    ? blobState.size_bytes - (blobState.total_parts - 1) * blobState.part_size
    : blobState.part_size;

  if (contentLength !== undefined && contentLength !== expectedSize) {
    errors.push({ field: "content_length", reason: `expected ${expectedSize} bytes for part ${partNumber}` });
  }

  return errors;
}

export function recordPartUpload(blobState, partNumber) {
  blobState.uploaded_parts.add(partNumber);
}

export function validateBlobCompletion(blobState) {
  const errors = [];

  if (blobState.status !== "uploading") {
    errors.push({ field: "status", reason: `blob is ${blobState.status}` });
    return errors;
  }

  const missing = [];
  for (let i = 1; i <= blobState.total_parts; i++) {
    if (!blobState.uploaded_parts.has(i)) {
      missing.push(i);
    }
  }

  if (missing.length > 0) {
    errors.push({ field: "parts", reason: `missing parts: ${missing.join(", ")}` });
  }

  return errors;
}

export function completeBlobUpload(blobState) {
  blobState.status = "complete";
  blobState.completed_at = new Date().toISOString();
  return blobState;
}

export function serializeBlobState(blobState) {
  return {
    ...blobState,
    uploaded_parts: [...blobState.uploaded_parts]
  };
}

export function deserializeBlobState(data) {
  if (!data || typeof data !== "object") return null;
  return {
    ...data,
    uploaded_parts: new Set(data.uploaded_parts || [])
  };
}
