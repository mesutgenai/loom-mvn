import test from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_RATE_LIMITS,
  createRateLimiter,
  checkRateLimit,
  recordRequest,
  buildRateLimitHeaders,
  createRateLimiterRegistry,
  getRateLimiter
} from "../src/protocol/rate_limit.js";

// ─── Constants ──────────────────────────────────────────────────────────────

test("DEFAULT_RATE_LIMITS has standard limits", () => {
  assert.equal(DEFAULT_RATE_LIMITS.envelopes_per_minute, 100);
  assert.equal(DEFAULT_RATE_LIMITS.auth_per_minute, 10);
  assert.equal(DEFAULT_RATE_LIMITS.reads_per_minute, 300);
  assert.equal(DEFAULT_RATE_LIMITS.ws_messages_per_minute, 60);
  assert.equal(DEFAULT_RATE_LIMITS.federation_per_minute, 1000);
});

// ─── createRateLimiter ─────────────────────────────────────────────────────

test("createRateLimiter: creates limiter with defaults", () => {
  const limiter = createRateLimiter(100);
  assert.equal(limiter.max_requests, 100);
  assert.equal(limiter.window_ms, 60000);
  assert.deepEqual(limiter.timestamps, []);
});

test("createRateLimiter: custom window", () => {
  const limiter = createRateLimiter(50, 30000);
  assert.equal(limiter.window_ms, 30000);
});

// ─── checkRateLimit ────────────────────────────────────────────────────────

test("checkRateLimit: allows when under limit", () => {
  const limiter = createRateLimiter(10);
  const result = checkRateLimit(limiter);
  assert.equal(result.allowed, true);
  assert.equal(result.limit, 10);
  assert.equal(result.remaining, 10);
  assert.ok(result.reset);
});

test("checkRateLimit: denies when at limit", () => {
  const limiter = createRateLimiter(3);
  const now = Date.now();
  limiter.timestamps = [now - 1000, now - 500, now - 100];
  const result = checkRateLimit(limiter, now);
  assert.equal(result.allowed, false);
  assert.equal(result.remaining, 0);
});

test("checkRateLimit: prunes expired timestamps", () => {
  const limiter = createRateLimiter(3, 60000);
  const now = Date.now();
  limiter.timestamps = [
    now - 120000, // expired (2 minutes ago)
    now - 30000   // recent
  ];
  const result = checkRateLimit(limiter, now);
  assert.equal(result.allowed, true);
  assert.equal(result.remaining, 2);
  assert.equal(limiter.timestamps.length, 1); // expired one pruned
});

// ─── recordRequest ─────────────────────────────────────────────────────────

test("recordRequest: adds timestamp", () => {
  const limiter = createRateLimiter(10);
  const now = Date.now();
  recordRequest(limiter, now);
  assert.equal(limiter.timestamps.length, 1);
  assert.equal(limiter.timestamps[0], now);
});

// ─── buildRateLimitHeaders ─────────────────────────────────────────────────

test("buildRateLimitHeaders: creates correct headers", () => {
  const headers = buildRateLimitHeaders({
    limit: 100,
    remaining: 95,
    reset: "2025-06-01T12:01:00Z"
  });
  assert.equal(headers["X-LOOM-RateLimit-Limit"], "100");
  assert.equal(headers["X-LOOM-RateLimit-Remaining"], "95");
  assert.equal(headers["X-LOOM-RateLimit-Reset"], "2025-06-01T12:01:00Z");
});

// ─── Rate limiter registry ─────────────────────────────────────────────────

test("createRateLimiterRegistry: creates registry with defaults", () => {
  const registry = createRateLimiterRegistry();
  assert.equal(registry.limits, DEFAULT_RATE_LIMITS);
  assert.equal(registry.limiters.size, 0);
});

test("getRateLimiter: creates and caches limiter", () => {
  const registry = createRateLimiterRegistry();
  const limiter1 = getRateLimiter(registry, "loom://alice", "/v1/envelopes");
  const limiter2 = getRateLimiter(registry, "loom://alice", "/v1/envelopes");
  assert.equal(limiter1, limiter2); // same instance
  assert.equal(registry.limiters.size, 1);
});

test("getRateLimiter: different endpoints get different limiters", () => {
  const registry = createRateLimiterRegistry();
  const limiter1 = getRateLimiter(registry, "loom://alice", "/v1/envelopes");
  const limiter2 = getRateLimiter(registry, "loom://alice", "/v1/threads");
  assert.notEqual(limiter1, limiter2);
  assert.equal(registry.limiters.size, 2);
});

test("getRateLimiter: resolves correct limits per endpoint", () => {
  const registry = createRateLimiterRegistry();
  const envLimiter = getRateLimiter(registry, "alice", "/v1/envelopes");
  assert.equal(envLimiter.max_requests, 100);

  const authLimiter = getRateLimiter(registry, "alice", "/v1/auth/login");
  assert.equal(authLimiter.max_requests, 10);

  const readLimiter = getRateLimiter(registry, "alice", "/v1/threads/thr_1");
  assert.equal(readLimiter.max_requests, 300);

  const wsLimiter = getRateLimiter(registry, "alice", "websocket");
  assert.equal(wsLimiter.max_requests, 60);

  const fedLimiter = getRateLimiter(registry, "alice", "/v1/federation/push");
  assert.equal(fedLimiter.max_requests, 1000);
});

// ─── Integration: check + record flow ──────────────────────────────────────

test("rate limit flow: allows then denies", () => {
  const limiter = createRateLimiter(3);
  const now = Date.now();

  for (let i = 0; i < 3; i++) {
    const result = checkRateLimit(limiter, now + i);
    assert.equal(result.allowed, true);
    recordRequest(limiter, now + i);
  }

  const blocked = checkRateLimit(limiter, now + 3);
  assert.equal(blocked.allowed, false);
});
