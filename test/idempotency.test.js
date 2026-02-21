import test from "node:test";
import assert from "node:assert/strict";

import {
  createIdempotencyStore,
  checkIdempotencyKey,
  recordIdempotencyResult,
  pruneIdempotencyStore,
  validateIdempotencyKey
} from "../src/protocol/idempotency.js";

// ─── createIdempotencyStore ────────────────────────────────────────────────

test("createIdempotencyStore: creates store with default TTL", () => {
  const store = createIdempotencyStore();
  assert.ok(store.entries instanceof Map);
  assert.equal(store.entries.size, 0);
  assert.equal(store.ttl_ms, 24 * 60 * 60 * 1000);
});

test("createIdempotencyStore: custom TTL", () => {
  const store = createIdempotencyStore(3600000);
  assert.equal(store.ttl_ms, 3600000);
});

// ─── checkIdempotencyKey ───────────────────────────────────────────────────

test("checkIdempotencyKey: not found for new key", () => {
  const store = createIdempotencyStore();
  const result = checkIdempotencyKey(store, "key-12345678");
  assert.equal(result.found, false);
});

test("checkIdempotencyKey: returns stored result", () => {
  const store = createIdempotencyStore();
  recordIdempotencyResult(store, "key-12345678", { id: "env_1" }, 201);
  const result = checkIdempotencyKey(store, "key-12345678");
  assert.equal(result.found, true);
  assert.deepEqual(result.result, { id: "env_1" });
  assert.equal(result.status, 201);
});

test("checkIdempotencyKey: expired entry returns not found", () => {
  const store = createIdempotencyStore(1000); // 1 second TTL
  store.entries.set("old-key-12345678", {
    result: {},
    status: 200,
    created_at: Date.now() - 5000 // 5 seconds ago
  });
  const result = checkIdempotencyKey(store, "old-key-12345678");
  assert.equal(result.found, false);
  assert.equal(store.entries.size, 0); // cleaned up
});

test("checkIdempotencyKey: null key returns not found", () => {
  const store = createIdempotencyStore();
  assert.equal(checkIdempotencyKey(store, null).found, false);
  assert.equal(checkIdempotencyKey(store, "").found, false);
});

// ─── recordIdempotencyResult ───────────────────────────────────────────────

test("recordIdempotencyResult: stores entry", () => {
  const store = createIdempotencyStore();
  recordIdempotencyResult(store, "my-key-12345678", { data: "test" }, 200);
  assert.equal(store.entries.size, 1);
  const entry = store.entries.get("my-key-12345678");
  assert.deepEqual(entry.result, { data: "test" });
  assert.equal(entry.status, 200);
  assert.ok(entry.created_at);
});

test("recordIdempotencyResult: null key does not store", () => {
  const store = createIdempotencyStore();
  recordIdempotencyResult(store, null, {});
  assert.equal(store.entries.size, 0);
});

test("recordIdempotencyResult: default status is 200", () => {
  const store = createIdempotencyStore();
  recordIdempotencyResult(store, "key-12345678", {});
  assert.equal(store.entries.get("key-12345678").status, 200);
});

// ─── pruneIdempotencyStore ─────────────────────────────────────────────────

test("pruneIdempotencyStore: removes expired entries", () => {
  const store = createIdempotencyStore(1000);
  store.entries.set("expired-key", {
    result: {},
    status: 200,
    created_at: Date.now() - 5000
  });
  store.entries.set("fresh-key-12", {
    result: {},
    status: 200,
    created_at: Date.now()
  });

  pruneIdempotencyStore(store);
  assert.equal(store.entries.size, 1);
  assert.ok(store.entries.has("fresh-key-12"));
});

test("pruneIdempotencyStore: keeps all when none expired", () => {
  const store = createIdempotencyStore();
  recordIdempotencyResult(store, "key1-abcdefgh", {});
  recordIdempotencyResult(store, "key2-abcdefgh", {});
  pruneIdempotencyStore(store);
  assert.equal(store.entries.size, 2);
});

// ─── validateIdempotencyKey ────────────────────────────────────────────────

test("validateIdempotencyKey: valid key", () => {
  const result = validateIdempotencyKey("abcdefgh-1234-5678-9012");
  assert.equal(result.valid, true);
});

test("validateIdempotencyKey: too short", () => {
  const result = validateIdempotencyKey("abc");
  assert.equal(result.valid, false);
  assert.ok(result.reason.includes("8-128"));
});

test("validateIdempotencyKey: too long", () => {
  const result = validateIdempotencyKey("a".repeat(200));
  assert.equal(result.valid, false);
});

test("validateIdempotencyKey: null", () => {
  const result = validateIdempotencyKey(null);
  assert.equal(result.valid, false);
});

test("validateIdempotencyKey: empty string", () => {
  const result = validateIdempotencyKey("");
  assert.equal(result.valid, false);
});

test("validateIdempotencyKey: exactly 8 chars is valid", () => {
  const result = validateIdempotencyKey("12345678");
  assert.equal(result.valid, true);
});

test("validateIdempotencyKey: exactly 128 chars is valid", () => {
  const result = validateIdempotencyKey("a".repeat(128));
  assert.equal(result.valid, true);
});

// ─── Integration: full idempotency flow ────────────────────────────────────

test("idempotency flow: first request → store → replay", () => {
  const store = createIdempotencyStore();
  const key = "req-abc12345678";

  // First attempt: not found
  const first = checkIdempotencyKey(store, key);
  assert.equal(first.found, false);

  // Process and record
  const result = { envelope_id: "env_new" };
  recordIdempotencyResult(store, key, result, 201);

  // Replay: found with same result
  const replay = checkIdempotencyKey(store, key);
  assert.equal(replay.found, true);
  assert.deepEqual(replay.result, { envelope_id: "env_new" });
  assert.equal(replay.status, 201);
});
