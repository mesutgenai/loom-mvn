// ─── Idempotency — Section 14.4 ─────────────────────────────────────────────
//
// Idempotency-Key header tracking for POST /v1/envelopes.

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export function createIdempotencyStore(ttlMs = DEFAULT_TTL_MS) {
  return {
    entries: new Map(),
    ttl_ms: ttlMs
  };
}

export function checkIdempotencyKey(store, key) {
  if (!key || typeof key !== "string") {
    return { found: false };
  }

  const entry = store.entries.get(key);
  if (!entry) {
    return { found: false };
  }

  // Check TTL
  const now = Date.now();
  if (now - entry.created_at > store.ttl_ms) {
    store.entries.delete(key);
    return { found: false };
  }

  return {
    found: true,
    result: entry.result,
    status: entry.status
  };
}

export function recordIdempotencyResult(store, key, result, status = 200) {
  if (!key || typeof key !== "string") return;

  store.entries.set(key, {
    result,
    status,
    created_at: Date.now()
  });
}

export function pruneIdempotencyStore(store, now = Date.now()) {
  for (const [key, entry] of store.entries) {
    if (now - entry.created_at > store.ttl_ms) {
      store.entries.delete(key);
    }
  }
}

export function validateIdempotencyKey(key) {
  if (!key || typeof key !== "string") {
    return { valid: false, reason: "Idempotency-Key header is required" };
  }
  if (key.length < 8 || key.length > 128) {
    return { valid: false, reason: "Idempotency-Key must be 8-128 characters" };
  }
  return { valid: true };
}
