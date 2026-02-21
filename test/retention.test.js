import test from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_RETENTION_POLICIES,
  validateRetentionPolicy,
  normalizeRetentionPolicies,
  resolveRetentionDays,
  isExpiredByRetention,
  isLegalHoldActive,
  collectExpiredEnvelopes
} from "../src/protocol/retention.js";

// ─── Constants ──────────────────────────────────────────────────────────────

test("DEFAULT_RETENTION_POLICIES has standard entries", () => {
  assert.ok(DEFAULT_RETENTION_POLICIES.length >= 7);
  assert.ok(DEFAULT_RETENTION_POLICIES.some((p) => p.label === "sys.inbox"));
  assert.ok(DEFAULT_RETENTION_POLICIES.some((p) => p.label === "sys.trash" && p.retention_days === 30));
  assert.ok(DEFAULT_RETENTION_POLICIES.some((p) => p.label === "compliance" && p.retention_days === -1));
});

// ─── validateRetentionPolicy ────────────────────────────────────────────────

test("validateRetentionPolicy: valid label-based", () => {
  const errors = validateRetentionPolicy({ label: "sys.inbox", retention_days: 365 });
  assert.equal(errors.length, 0);
});

test("validateRetentionPolicy: valid intent-based", () => {
  const errors = validateRetentionPolicy({ intent: "notification.system@v1", retention_days: 90 });
  assert.equal(errors.length, 0);
});

test("validateRetentionPolicy: missing label and intent", () => {
  const errors = validateRetentionPolicy({ retention_days: 30 });
  assert.ok(errors.some((e) => e.field === "policy"));
});

test("validateRetentionPolicy: invalid retention_days", () => {
  const errors = validateRetentionPolicy({ label: "test", retention_days: "thirty" });
  assert.ok(errors.some((e) => e.field === "retention_days"));
});

test("validateRetentionPolicy: null input", () => {
  const errors = validateRetentionPolicy(null);
  assert.ok(errors.length > 0);
});

// ─── normalizeRetentionPolicies ────────────────────────────────────────────

test("normalizeRetentionPolicies: normalizes valid array", () => {
  const result = normalizeRetentionPolicies([
    { label: "test", retention_days: 30 },
    { intent: "x", retention_days: 60 }
  ]);
  assert.equal(result.length, 2);
  assert.equal(result[0].label, "test");
  assert.equal(result[0].intent, null);
  assert.equal(result[1].intent, "x");
  assert.equal(result[1].label, null);
});

test("normalizeRetentionPolicies: non-array returns empty", () => {
  assert.deepEqual(normalizeRetentionPolicies("not array"), []);
});

// ─── resolveRetentionDays ──────────────────────────────────────────────────

test("resolveRetentionDays: matches by label", () => {
  const policies = [{ label: "sys.inbox", retention_days: 2555 }];
  assert.equal(resolveRetentionDays(policies, { labels: ["sys.inbox"] }), 2555);
});

test("resolveRetentionDays: matches by intent", () => {
  const policies = [{ intent: "notification.system@v1", retention_days: 90 }];
  assert.equal(resolveRetentionDays(policies, { intent: "notification.system@v1" }), 90);
});

test("resolveRetentionDays: returns longest match", () => {
  const policies = [
    { label: "a", retention_days: 30 },
    { label: "a", retention_days: 365 }
  ];
  assert.equal(resolveRetentionDays(policies, { labels: ["a"] }), 365);
});

test("resolveRetentionDays: returns -1 for indefinite", () => {
  const policies = [
    { label: "compliance", retention_days: -1 },
    { label: "compliance", retention_days: 365 }
  ];
  assert.equal(resolveRetentionDays(policies, { labels: ["compliance"] }), -1);
});

test("resolveRetentionDays: returns null for no match", () => {
  const policies = [{ label: "a", retention_days: 30 }];
  assert.equal(resolveRetentionDays(policies, { labels: ["b"] }), null);
});

// ─── isExpiredByRetention ──────────────────────────────────────────────────

test("isExpiredByRetention: not expired within window", () => {
  const now = Date.now();
  const createdAt = new Date(now - 10 * 86400000).toISOString(); // 10 days ago
  assert.equal(isExpiredByRetention(30, createdAt, now), false);
});

test("isExpiredByRetention: expired past window", () => {
  const now = Date.now();
  const createdAt = new Date(now - 40 * 86400000).toISOString(); // 40 days ago
  assert.equal(isExpiredByRetention(30, createdAt, now), true);
});

test("isExpiredByRetention: indefinite never expires", () => {
  const now = Date.now();
  const createdAt = new Date(0).toISOString();
  assert.equal(isExpiredByRetention(-1, createdAt, now), false);
});

test("isExpiredByRetention: null retentionDays does not expire", () => {
  assert.equal(isExpiredByRetention(null, "2020-01-01T00:00:00Z"), false);
});

// ─── isLegalHoldActive ─────────────────────────────────────────────────────

test("isLegalHoldActive: true when label present", () => {
  assert.equal(isLegalHoldActive(["sys.inbox", "sys.legal_hold"]), true);
});

test("isLegalHoldActive: false when label absent", () => {
  assert.equal(isLegalHoldActive(["sys.inbox"]), false);
});

test("isLegalHoldActive: false for non-array", () => {
  assert.equal(isLegalHoldActive(null), false);
});

// ─── collectExpiredEnvelopes ───────────────────────────────────────────────

test("collectExpiredEnvelopes: collects expired, skips legal hold", () => {
  const now = Date.now();
  const oldDate = new Date(now - 100 * 86400000).toISOString();
  const threads = new Map([
    ["thr_1", { labels: ["sys.trash"] }],
    ["thr_2", { labels: ["sys.trash", "sys.legal_hold"] }]
  ]);
  const envelopes = [
    { id: "e1", thread_id: "thr_1", created_at: oldDate, content: {} },
    { id: "e2", thread_id: "thr_2", created_at: oldDate, content: {} }
  ];
  const policies = [{ label: "sys.trash", retention_days: 30 }];

  const expired = collectExpiredEnvelopes(envelopes, threads, policies, now);
  assert.deepEqual(expired, ["e1"]); // e2 blocked by legal hold
});
