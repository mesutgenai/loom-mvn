import test from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_ROTATION_POLICY,
  ROTATION_STATES,
  KEY_ROTATION_AUDIT_EVENTS,
  validateRotationPolicy,
  normalizeRotationPolicy,
  getKeyRotationState,
  assessKeyRotationNeeds,
  generateRotationPlan,
  buildRotationAuditEntry
} from "../src/protocol/key_rotation.js";

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

function isoAgo(ms) {
  return new Date(Date.now() - ms).toISOString();
}

function isoFuture(ms) {
  return new Date(Date.now() + ms).toISOString();
}

// ─── Constants ───────────────────────────────────────────────────────────────

test("DEFAULT_ROTATION_POLICY is frozen with expected defaults", () => {
  assert.ok(Object.isFrozen(DEFAULT_ROTATION_POLICY));
  assert.equal(DEFAULT_ROTATION_POLICY.max_key_age_ms, 90 * DAY_MS);
  assert.equal(DEFAULT_ROTATION_POLICY.grace_period_ms, 7 * DAY_MS);
  assert.equal(DEFAULT_ROTATION_POLICY.overlap_window_ms, 24 * HOUR_MS);
  assert.equal(DEFAULT_ROTATION_POLICY.min_key_age_ms, 24 * HOUR_MS);
  assert.equal(DEFAULT_ROTATION_POLICY.auto_rotate, false);
});

test("ROTATION_STATES is frozen with 7 states", () => {
  assert.ok(Object.isFrozen(ROTATION_STATES));
  assert.equal(Object.keys(ROTATION_STATES).length, 7);
});

test("KEY_ROTATION_AUDIT_EVENTS is frozen with 6 events", () => {
  assert.ok(Object.isFrozen(KEY_ROTATION_AUDIT_EVENTS));
  assert.equal(Object.keys(KEY_ROTATION_AUDIT_EVENTS).length, 6);
  assert.ok(KEY_ROTATION_AUDIT_EVENTS.ROTATION_INITIATED.startsWith("key_rotation."));
});

// ─── validateRotationPolicy ─────────────────────────────────────────────────

test("validateRotationPolicy accepts valid policy", () => {
  const errors = validateRotationPolicy({
    max_key_age_ms: 30 * DAY_MS,
    grace_period_ms: 5 * DAY_MS,
    overlap_window_ms: 12 * HOUR_MS,
    min_key_age_ms: 1 * HOUR_MS,
    auto_rotate: true
  });
  assert.equal(errors.length, 0);
});

test("validateRotationPolicy rejects null", () => {
  const errors = validateRotationPolicy(null);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, "rotation_policy");
});

test("validateRotationPolicy rejects non-object", () => {
  assert.equal(validateRotationPolicy("string").length, 1);
  assert.equal(validateRotationPolicy(123).length, 1);
});

test("validateRotationPolicy rejects negative max_key_age_ms", () => {
  const errors = validateRotationPolicy({ max_key_age_ms: -1 });
  assert.ok(errors.some((e) => e.field === "rotation_policy.max_key_age_ms"));
});

test("validateRotationPolicy rejects negative grace_period_ms", () => {
  const errors = validateRotationPolicy({ grace_period_ms: -1 });
  assert.ok(errors.some((e) => e.field === "rotation_policy.grace_period_ms"));
});

test("validateRotationPolicy rejects non-boolean auto_rotate", () => {
  const errors = validateRotationPolicy({ auto_rotate: "yes" });
  assert.ok(errors.some((e) => e.field === "rotation_policy.auto_rotate"));
});

test("validateRotationPolicy rejects grace >= max_key_age", () => {
  const errors = validateRotationPolicy({ max_key_age_ms: 10000, grace_period_ms: 10000 });
  assert.ok(errors.some((e) => e.field === "rotation_policy.grace_period_ms"));
});

test("validateRotationPolicy accepts empty policy", () => {
  assert.equal(validateRotationPolicy({}).length, 0);
});

// ─── normalizeRotationPolicy ────────────────────────────────────────────────

test("normalizeRotationPolicy fills defaults for null", () => {
  const policy = normalizeRotationPolicy(null);
  assert.deepEqual(policy, DEFAULT_ROTATION_POLICY);
  assert.ok(Object.isFrozen(policy));
});

test("normalizeRotationPolicy fills defaults for empty", () => {
  const policy = normalizeRotationPolicy({});
  assert.equal(policy.max_key_age_ms, DEFAULT_ROTATION_POLICY.max_key_age_ms);
  assert.equal(policy.auto_rotate, false);
});

test("normalizeRotationPolicy allows partial override", () => {
  const policy = normalizeRotationPolicy({ max_key_age_ms: 30 * DAY_MS, auto_rotate: true });
  assert.equal(policy.max_key_age_ms, 30 * DAY_MS);
  assert.equal(policy.auto_rotate, true);
  assert.equal(policy.grace_period_ms, DEFAULT_ROTATION_POLICY.grace_period_ms);
});

test("normalizeRotationPolicy returns frozen object", () => {
  const policy = normalizeRotationPolicy({ max_key_age_ms: 1000 });
  assert.ok(Object.isFrozen(policy));
});

test("normalizeRotationPolicy handles undefined", () => {
  const policy = normalizeRotationPolicy(undefined);
  assert.deepEqual(policy, DEFAULT_ROTATION_POLICY);
});

// ─── getKeyRotationState ────────────────────────────────────────────────────

test("getKeyRotationState returns CURRENT for fresh key", () => {
  const key = { key_id: "k1", not_before: isoAgo(1 * DAY_MS), status: "active" };
  assert.equal(getKeyRotationState(key, DEFAULT_ROTATION_POLICY), ROTATION_STATES.CURRENT);
});

test("getKeyRotationState returns GRACE when approaching max age", () => {
  // Key is 85 days old, grace starts at 83 days (90 - 7)
  const key = { key_id: "k1", not_before: isoAgo(85 * DAY_MS), status: "active" };
  assert.equal(getKeyRotationState(key, DEFAULT_ROTATION_POLICY), ROTATION_STATES.GRACE);
});

test("getKeyRotationState returns CURRENT just before grace period", () => {
  // Key is 82 days old, grace starts at 83 days
  const key = { key_id: "k1", not_before: isoAgo(82 * DAY_MS), status: "active" };
  assert.equal(getKeyRotationState(key, DEFAULT_ROTATION_POLICY), ROTATION_STATES.CURRENT);
});

test("getKeyRotationState returns EXPIRED past max age", () => {
  const key = { key_id: "k1", not_before: isoAgo(91 * DAY_MS), status: "active" };
  assert.equal(getKeyRotationState(key, DEFAULT_ROTATION_POLICY), ROTATION_STATES.EXPIRED);
});

test("getKeyRotationState returns REVOKED for revoked key", () => {
  const key = { key_id: "k1", not_before: isoAgo(10 * DAY_MS), revoked_at: isoAgo(1 * DAY_MS) };
  assert.equal(getKeyRotationState(key, DEFAULT_ROTATION_POLICY), ROTATION_STATES.REVOKED);
});

test("getKeyRotationState returns PENDING for future key", () => {
  const key = { key_id: "k1", not_before: isoFuture(1 * DAY_MS), status: "active" };
  assert.equal(getKeyRotationState(key, DEFAULT_ROTATION_POLICY), ROTATION_STATES.PENDING);
});

test("getKeyRotationState returns OVERLAP when in overlap window", () => {
  const key = {
    key_id: "k1",
    not_before: isoAgo(85 * DAY_MS),
    status: "active",
    _overlap_until: isoFuture(12 * HOUR_MS)
  };
  assert.equal(getKeyRotationState(key, DEFAULT_ROTATION_POLICY), ROTATION_STATES.OVERLAP);
});

test("getKeyRotationState returns RETIRED for retired status", () => {
  const key = { key_id: "k1", not_before: isoAgo(100 * DAY_MS), status: "retired" };
  assert.equal(getKeyRotationState(key, DEFAULT_ROTATION_POLICY), ROTATION_STATES.RETIRED);
});

test("getKeyRotationState handles valid_from alias", () => {
  const key = { key_id: "k1", valid_from: isoAgo(1 * DAY_MS), status: "active" };
  assert.equal(getKeyRotationState(key, DEFAULT_ROTATION_POLICY), ROTATION_STATES.CURRENT);
});

test("getKeyRotationState handles created_at alias", () => {
  const key = { key_id: "k1", created_at: isoAgo(1 * DAY_MS), status: "active" };
  assert.equal(getKeyRotationState(key, DEFAULT_ROTATION_POLICY), ROTATION_STATES.CURRENT);
});

test("getKeyRotationState returns CURRENT for key with no timestamps", () => {
  const key = { key_id: "k1", public_key_pem: "test", status: "active" };
  assert.equal(getKeyRotationState(key, DEFAULT_ROTATION_POLICY), ROTATION_STATES.CURRENT);
});

test("getKeyRotationState handles custom policy", () => {
  // With 10-day max and 3-day grace, key at 8 days should be GRACE
  const policy = { max_key_age_ms: 10 * DAY_MS, grace_period_ms: 3 * DAY_MS };
  const key = { key_id: "k1", not_before: isoAgo(8 * DAY_MS), status: "active" };
  assert.equal(getKeyRotationState(key, policy), ROTATION_STATES.GRACE);
});

test("getKeyRotationState returns EXPIRED for null key", () => {
  assert.equal(getKeyRotationState(null, DEFAULT_ROTATION_POLICY), ROTATION_STATES.EXPIRED);
});

test("getKeyRotationState returns RETIRED for disabled status", () => {
  const key = { key_id: "k1", not_before: isoAgo(10 * DAY_MS), status: "disabled" };
  assert.equal(getKeyRotationState(key, DEFAULT_ROTATION_POLICY), ROTATION_STATES.RETIRED);
});

test("getKeyRotationState returns EXPIRED for key with not_after in past", () => {
  const key = { key_id: "k1", not_before: isoAgo(30 * DAY_MS), not_after: isoAgo(1 * DAY_MS), status: "active" };
  assert.equal(getKeyRotationState(key, DEFAULT_ROTATION_POLICY), ROTATION_STATES.EXPIRED);
});

// ─── assessKeyRotationNeeds ─────────────────────────────────────────────────

test("assessKeyRotationNeeds returns no rotation for current keys", () => {
  const keys = [{ key_id: "k1", not_before: isoAgo(10 * DAY_MS), status: "active" }];
  const result = assessKeyRotationNeeds(keys, DEFAULT_ROTATION_POLICY);
  assert.equal(result.needs_rotation, false);
  assert.equal(result.active_key_count, 1);
  assert.equal(result.grace_keys.length, 0);
  assert.equal(result.expired_keys.length, 0);
});

test("assessKeyRotationNeeds detects grace key", () => {
  const keys = [{ key_id: "k1", not_before: isoAgo(85 * DAY_MS), status: "active" }];
  const result = assessKeyRotationNeeds(keys, DEFAULT_ROTATION_POLICY);
  assert.equal(result.needs_rotation, true);
  assert.deepEqual(result.grace_keys, ["k1"]);
});

test("assessKeyRotationNeeds detects expired key", () => {
  const keys = [{ key_id: "k1", not_before: isoAgo(100 * DAY_MS), status: "active" }];
  const result = assessKeyRotationNeeds(keys, DEFAULT_ROTATION_POLICY);
  assert.equal(result.needs_rotation, true);
  assert.deepEqual(result.expired_keys, ["k1"]);
});

test("assessKeyRotationNeeds handles empty key list", () => {
  const result = assessKeyRotationNeeds([], DEFAULT_ROTATION_POLICY);
  assert.equal(result.needs_rotation, true);
  assert.equal(result.active_key_count, 0);
  assert.ok(result.summary.includes("No signing keys"));
});

test("assessKeyRotationNeeds handles null input", () => {
  const result = assessKeyRotationNeeds(null, DEFAULT_ROTATION_POLICY);
  assert.equal(result.needs_rotation, true);
});

test("assessKeyRotationNeeds no rotation if pending key exists", () => {
  const keys = [
    { key_id: "k1", not_before: isoAgo(85 * DAY_MS), status: "active" },
    { key_id: "k2", not_before: isoFuture(1 * DAY_MS), status: "active" }
  ];
  const result = assessKeyRotationNeeds(keys, DEFAULT_ROTATION_POLICY);
  assert.equal(result.needs_rotation, false);
});

test("assessKeyRotationNeeds mixed current and grace", () => {
  const keys = [
    { key_id: "k1", not_before: isoAgo(10 * DAY_MS), status: "active" },
    { key_id: "k2", not_before: isoAgo(85 * DAY_MS), status: "active" }
  ];
  const result = assessKeyRotationNeeds(keys, DEFAULT_ROTATION_POLICY);
  // Has a CURRENT key so active_key_count >= 1, but also has grace key
  assert.equal(result.needs_rotation, true);
  assert.equal(result.active_key_count, 2);
  assert.deepEqual(result.grace_keys, ["k2"]);
});

test("assessKeyRotationNeeds includes key state details", () => {
  const keys = [{ key_id: "k1", not_before: isoAgo(10 * DAY_MS), status: "active" }];
  const result = assessKeyRotationNeeds(keys, DEFAULT_ROTATION_POLICY);
  assert.equal(result.keys.length, 1);
  assert.equal(result.keys[0].key_id, "k1");
  assert.equal(result.keys[0].state, "current");
  assert.ok(result.keys[0].age_ms > 0);
});

test("assessKeyRotationNeeds revoked keys excluded from active count", () => {
  const keys = [{ key_id: "k1", not_before: isoAgo(10 * DAY_MS), revoked_at: isoAgo(1 * DAY_MS) }];
  const result = assessKeyRotationNeeds(keys, DEFAULT_ROTATION_POLICY);
  assert.equal(result.active_key_count, 0);
});

test("assessKeyRotationNeeds generates summary string", () => {
  const keys = [{ key_id: "k1", not_before: isoAgo(10 * DAY_MS), status: "active" }];
  const result = assessKeyRotationNeeds(keys, DEFAULT_ROTATION_POLICY);
  assert.ok(typeof result.summary === "string");
  assert.ok(result.summary.length > 0);
});

test("assessKeyRotationNeeds expired summary mentions immediate rotation", () => {
  const keys = [{ key_id: "k1", not_before: isoAgo(100 * DAY_MS), status: "active" }];
  const result = assessKeyRotationNeeds(keys, DEFAULT_ROTATION_POLICY);
  assert.ok(result.summary.includes("immediate"));
});

// ─── generateRotationPlan ───────────────────────────────────────────────────

test("generateRotationPlan returns empty actions when no rotation needed", () => {
  const keys = [{ key_id: "k1", not_before: isoAgo(10 * DAY_MS), status: "active" }];
  const plan = generateRotationPlan(keys, DEFAULT_ROTATION_POLICY);
  assert.equal(plan.actions.length, 0);
  assert.ok(plan.summary.includes("No rotation"));
});

test("generateRotationPlan generates new key for empty list", () => {
  const plan = generateRotationPlan([], DEFAULT_ROTATION_POLICY);
  assert.ok(plan.actions.some((a) => a.type === "generate_new_key"));
  assert.ok(plan.actions[0].reason.includes("no signing keys"));
});

test("generateRotationPlan generates new key and overlap for grace key", () => {
  const keys = [{ key_id: "k1", not_before: isoAgo(85 * DAY_MS), status: "active" }];
  const plan = generateRotationPlan(keys, DEFAULT_ROTATION_POLICY);
  assert.ok(plan.actions.some((a) => a.type === "generate_new_key"));
  assert.ok(plan.actions.some((a) => a.type === "begin_overlap" && a.key_id === "k1"));
});

test("generateRotationPlan retires expired key", () => {
  const keys = [{ key_id: "k1", not_before: isoAgo(100 * DAY_MS), status: "active" }];
  const plan = generateRotationPlan(keys, DEFAULT_ROTATION_POLICY);
  assert.ok(plan.actions.some((a) => a.type === "generate_new_key"));
  assert.ok(plan.actions.some((a) => a.type === "retire_key" && a.key_id === "k1"));
});

test("generateRotationPlan archives retired keys", () => {
  const keys = [
    { key_id: "k1", not_before: isoAgo(10 * DAY_MS), status: "active" },
    { key_id: "k_old", not_before: isoAgo(200 * DAY_MS), status: "retired" }
  ];
  const plan = generateRotationPlan(keys, DEFAULT_ROTATION_POLICY);
  assert.ok(plan.actions.some((a) => a.type === "archive_key" && a.key_id === "k_old"));
});

test("generateRotationPlan no new key if current key exists with grace key", () => {
  const keys = [
    { key_id: "k1", not_before: isoAgo(10 * DAY_MS), status: "active" },
    { key_id: "k2", not_before: isoAgo(85 * DAY_MS), status: "active" }
  ];
  const plan = generateRotationPlan(keys, DEFAULT_ROTATION_POLICY);
  // k1 is CURRENT so hasCurrentOrPending = true, no new key generated
  assert.ok(!plan.actions.some((a) => a.type === "generate_new_key"));
});

test("generateRotationPlan summary lists action types", () => {
  const plan = generateRotationPlan([], DEFAULT_ROTATION_POLICY);
  assert.ok(plan.summary.includes("generate_new_key"));
});

test("generateRotationPlan actions have required fields", () => {
  const plan = generateRotationPlan([], DEFAULT_ROTATION_POLICY);
  for (const action of plan.actions) {
    assert.ok("type" in action);
    assert.ok("key_id" in action);
    assert.ok("reason" in action);
    assert.ok(typeof action.reason === "string");
  }
});

// ─── buildRotationAuditEntry ────────────────────────────────────────────────

test("buildRotationAuditEntry returns correct structure", () => {
  const entry = buildRotationAuditEntry(KEY_ROTATION_AUDIT_EVENTS.ROTATION_INITIATED, { key_id: "k1" });
  assert.equal(entry.action, "key_rotation.initiated");
  assert.equal(entry.details.key_id, "k1");
  assert.ok(entry.details.timestamp);
});

test("buildRotationAuditEntry includes timestamp", () => {
  const entry = buildRotationAuditEntry("test.event", {});
  assert.ok(entry.details.timestamp);
  assert.ok(Date.parse(entry.details.timestamp) > 0);
});

test("buildRotationAuditEntry passes through event type", () => {
  const entry = buildRotationAuditEntry("custom.event", { foo: "bar" });
  assert.equal(entry.action, "custom.event");
  assert.equal(entry.details.foo, "bar");
});

test("buildRotationAuditEntry handles null details", () => {
  const entry = buildRotationAuditEntry("test", null);
  assert.ok(entry.details.timestamp);
});
