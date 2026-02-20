import test from "node:test";
import assert from "node:assert/strict";
import { validateThreadDag, canonicalThreadOrder } from "../src/protocol/thread.js";
import { assertThreadLimitsOrThrow } from "../src/protocol/thread_limits.js";

function padId(n, len = 26) {
  return String(n).padStart(len, "0");
}

test("thread DAG: handles 5000 envelopes linear chain without excessive time", () => {
  const envelopes = [];
  for (let i = 0; i < 5000; i++) {
    envelopes.push({
      id: `env_${padId(i)}`,
      parent_id: i > 0 ? `env_${padId(i - 1)}` : null,
      created_at: new Date(Date.now() + i * 1000).toISOString()
    });
  }
  const start = performance.now();
  const result = validateThreadDag(envelopes);
  const elapsed = performance.now() - start;
  assert.equal(result.valid, true);
  assert.ok(elapsed < 5000, `DAG validation took ${elapsed}ms, expected < 5000ms`);
});

test("thread DAG: handles wide fan-out DAG", () => {
  const root = {
    id: `env_${padId(0)}`,
    parent_id: null,
    created_at: new Date().toISOString()
  };
  const envelopes = [root];
  for (let i = 1; i <= 2000; i++) {
    envelopes.push({
      id: `env_${padId(i)}`,
      parent_id: root.id,
      created_at: new Date(Date.now() + i).toISOString()
    });
  }
  const result = validateThreadDag(envelopes);
  assert.equal(result.valid, true);
});

test("thread DAG: canonical ordering for large chain is stable", () => {
  const envelopes = [];
  for (let i = 0; i < 500; i++) {
    envelopes.push({
      id: `env_${padId(i)}`,
      parent_id: i > 0 ? `env_${padId(i - 1)}` : null,
      created_at: new Date(Date.now() + i * 1000).toISOString()
    });
  }
  const ordered = canonicalThreadOrder(envelopes);
  assert.equal(ordered.length, 500);
  assert.equal(ordered[0].id, `env_${padId(0)}`);
  assert.equal(ordered[499].id, `env_${padId(499)}`);
});

test("thread limits: rejects when envelope count exceeds max", () => {
  assert.throws(
    () => assertThreadLimitsOrThrow(10001, { max_envelopes_per_thread: 10000 }),
    (err) => err.code === "ENVELOPE_INVALID"
  );
});

test("thread limits: accepts when under limit", () => {
  assertThreadLimitsOrThrow(100, { max_envelopes_per_thread: 10000 });
});

test("thread limits: disabled when limit is 0", () => {
  assertThreadLimitsOrThrow(999999, { max_envelopes_per_thread: 0 });
});

test("thread limits: rejects when pending parent count exceeds max", () => {
  assert.throws(
    () => assertThreadLimitsOrThrow(10, {}, 501),
    (err) => err.code === "ENVELOPE_INVALID"
  );
});

test("thread limits: accepts pending parents under limit", () => {
  assertThreadLimitsOrThrow(10, {}, 100);
});
