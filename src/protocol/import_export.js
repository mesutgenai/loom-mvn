// ─── Import/Export — Section 26.2 ───────────────────────────────────────────
//
// Mailbox import/export serialization with sys.imported labeling.

export const IMPORT_LABEL = "sys.imported";

export function validateImportPayload(payload) {
  const errors = [];
  if (!payload || typeof payload !== "object") {
    errors.push({ field: "payload", reason: "must be an object" });
    return errors;
  }

  if (payload.format !== undefined) {
    const validFormats = ["loom", "mbox", "eml"];
    if (!validFormats.includes(payload.format)) {
      errors.push({ field: "format", reason: `must be one of: ${validFormats.join(", ")}` });
    }
  }

  if (payload.envelopes !== undefined && !Array.isArray(payload.envelopes)) {
    errors.push({ field: "envelopes", reason: "must be an array if provided" });
  }

  if (payload.threads !== undefined && !Array.isArray(payload.threads)) {
    errors.push({ field: "threads", reason: "must be an array if provided" });
  }

  return errors;
}

export function buildExportPackage(state, options = {}) {
  const { threadIds = null, identityFilter = null, includeBlobs = false } = options;

  let threads = state.threads || [];
  let envelopes = state.envelopes || [];

  if (threadIds && Array.isArray(threadIds)) {
    const threadIdSet = new Set(threadIds);
    threads = threads.filter((t) => threadIdSet.has(t.id));
    const envelopeIds = new Set(threads.flatMap((t) => t.envelope_ids || []));
    envelopes = envelopes.filter((e) => envelopeIds.has(e.id));
  }

  if (identityFilter) {
    threads = threads.filter((t) =>
      (t.participants || []).some((p) => p.identity === identityFilter)
    );
    const threadIdSet = new Set(threads.map((t) => t.id));
    envelopes = envelopes.filter((e) => threadIdSet.has(e.thread_id));
  }

  const exportPackage = {
    loom: "1.1",
    format: "loom",
    exported_at: new Date().toISOString(),
    thread_count: threads.length,
    envelope_count: envelopes.length,
    threads,
    envelopes
  };

  if (includeBlobs && state.blobs) {
    exportPackage.blobs = state.blobs;
  }

  return exportPackage;
}

export function prepareImportEnvelopes(envelopes) {
  // Mark all imported envelopes so they can be identified
  return envelopes.map((env) => ({
    ...env,
    meta: {
      ...(env.meta || {}),
      imported: true,
      imported_at: new Date().toISOString(),
      original_headers: env.meta?.original_headers || null
    }
  }));
}

export function prepareImportThreads(threads) {
  return threads.map((thread) => ({
    ...thread,
    labels: [...new Set([...(thread.labels || []), IMPORT_LABEL])]
  }));
}

// ─── Email-format helpers ───────────────────────────────────────────────────

export function parseEmailHeaders(rawHeaders) {
  if (typeof rawHeaders !== "string") return {};
  const headers = {};
  const lines = rawHeaders.split(/\r?\n/);
  let currentKey = null;
  let currentValue = "";

  for (const line of lines) {
    if (/^\s/.test(line) && currentKey) {
      // Continuation of previous header
      currentValue += " " + line.trim();
    } else {
      if (currentKey) {
        headers[currentKey.toLowerCase()] = currentValue;
      }
      const colonIdx = line.indexOf(":");
      if (colonIdx > 0) {
        currentKey = line.slice(0, colonIdx).trim();
        currentValue = line.slice(colonIdx + 1).trim();
      } else {
        currentKey = null;
        currentValue = "";
      }
    }
  }
  if (currentKey) {
    headers[currentKey.toLowerCase()] = currentValue;
  }

  return headers;
}

export function mapMessageIdToEnvelopeId(messageId) {
  // Strip angle brackets from Message-ID
  const cleaned = String(messageId || "")
    .replace(/^</, "")
    .replace(/>$/, "")
    .trim();
  return cleaned || null;
}

export function mapReferencesToParent(inReplyTo, references) {
  // In-Reply-To maps to parent_id
  if (inReplyTo) {
    return mapMessageIdToEnvelopeId(inReplyTo);
  }
  // Fall back to last reference
  if (typeof references === "string") {
    const refs = references.split(/\s+/).filter(Boolean);
    if (refs.length > 0) {
      return mapMessageIdToEnvelopeId(refs[refs.length - 1]);
    }
  }
  return null;
}
