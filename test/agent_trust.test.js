import test from "node:test";
import assert from "node:assert/strict";

import {
  AGENT_TRUST_EVENT_TYPES,
  AGENT_TRUST_LEVELS,
  DEFAULT_AGENT_TRUST_POLICY,
  validateAgentTrustPolicy,
  computeAgentTrustScore,
  classifyAgentTrust,
  assertAgentTrustOrThrow,
  buildAgentTrustSummary
} from "../src/protocol/agent_trust.js";

const NOW = Date.now();

// ─── Constants ───────────────────────────────────────────────────────────────

test("AGENT_TRUST_EVENT_TYPES is frozen", () => {
  assert.ok(Object.isFrozen(AGENT_TRUST_EVENT_TYPES));
});

test("AGENT_TRUST_LEVELS is frozen", () => {
  assert.ok(Object.isFrozen(AGENT_TRUST_LEVELS));
  assert.equal(AGENT_TRUST_LEVELS.TRUSTED, "trusted");
  assert.equal(AGENT_TRUST_LEVELS.BLOCKED, "blocked");
});

test("DEFAULT_AGENT_TRUST_POLICY is frozen with expected defaults", () => {
  assert.ok(Object.isFrozen(DEFAULT_AGENT_TRUST_POLICY));
  assert.equal(DEFAULT_AGENT_TRUST_POLICY.decay_window_ms, 86_400_000);
  assert.equal(DEFAULT_AGENT_TRUST_POLICY.warning_threshold, 10);
  assert.equal(DEFAULT_AGENT_TRUST_POLICY.quarantine_threshold, 25);
  assert.equal(DEFAULT_AGENT_TRUST_POLICY.block_threshold, 50);
  assert.equal(DEFAULT_AGENT_TRUST_POLICY.max_events_per_agent, 200);
  assert.equal(DEFAULT_AGENT_TRUST_POLICY.good_behavior_decay, true);
});

test("AGENT_TRUST_EVENT_TYPES has expected weights", () => {
  assert.equal(AGENT_TRUST_EVENT_TYPES.successful_operation, -1);
  assert.equal(AGENT_TRUST_EVENT_TYPES.injection_detected, 5);
  assert.equal(AGENT_TRUST_EVENT_TYPES.sandbox_violation, 3);
  assert.equal(AGENT_TRUST_EVENT_TYPES.rate_limit_hit, 2);
  assert.equal(AGENT_TRUST_EVENT_TYPES.loop_escalation, 4);
  assert.equal(AGENT_TRUST_EVENT_TYPES.content_filter_flag, 3);
  assert.equal(AGENT_TRUST_EVENT_TYPES.delegation_violation, 5);
  assert.equal(AGENT_TRUST_EVENT_TYPES.authentication_failure, 2);
});

// ─── validateAgentTrustPolicy ────────────────────────────────────────────────

test("validateAgentTrustPolicy accepts valid policy", () => {
  const errors = validateAgentTrustPolicy({
    decay_window_ms: 3_600_000,
    warning_threshold: 5,
    quarantine_threshold: 15,
    block_threshold: 30,
    max_events_per_agent: 100
  });
  assert.equal(errors.length, 0);
});

test("validateAgentTrustPolicy accepts empty policy (defaults)", () => {
  const errors = validateAgentTrustPolicy({});
  assert.equal(errors.length, 0);
});

test("validateAgentTrustPolicy rejects null", () => {
  const errors = validateAgentTrustPolicy(null);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, "policy");
});

test("validateAgentTrustPolicy rejects decay_window_ms below 60000", () => {
  const errors = validateAgentTrustPolicy({ decay_window_ms: 1000 });
  assert.ok(errors.some((e) => e.field === "decay_window_ms"));
});

test("validateAgentTrustPolicy rejects warning_threshold below 1", () => {
  const errors = validateAgentTrustPolicy({ warning_threshold: 0 });
  assert.ok(errors.some((e) => e.field === "warning_threshold"));
});

test("validateAgentTrustPolicy rejects quarantine_threshold below 2", () => {
  const errors = validateAgentTrustPolicy({ quarantine_threshold: 1 });
  assert.ok(errors.some((e) => e.field === "quarantine_threshold"));
});

test("validateAgentTrustPolicy rejects block_threshold below 3", () => {
  const errors = validateAgentTrustPolicy({ block_threshold: 2 });
  assert.ok(errors.some((e) => e.field === "block_threshold"));
});

test("validateAgentTrustPolicy rejects max_events_per_agent below 10", () => {
  const errors = validateAgentTrustPolicy({ max_events_per_agent: 5 });
  assert.ok(errors.some((e) => e.field === "max_events_per_agent"));
});

test("validateAgentTrustPolicy rejects threshold ordering violation", () => {
  const errors = validateAgentTrustPolicy({
    warning_threshold: 30,
    quarantine_threshold: 20,
    block_threshold: 50
  });
  assert.ok(errors.some((e) => e.field === "warning_threshold" && e.reason.includes("less than")));
});

test("validateAgentTrustPolicy rejects quarantine >= block", () => {
  const errors = validateAgentTrustPolicy({
    warning_threshold: 5,
    quarantine_threshold: 50,
    block_threshold: 50
  });
  assert.ok(errors.some((e) => e.field === "quarantine_threshold" && e.reason.includes("less than")));
});

// ─── computeAgentTrustScore ──────────────────────────────────────────────────

test("computeAgentTrustScore returns 0 for empty events", () => {
  const result = computeAgentTrustScore([], null, NOW);
  assert.equal(result.score, 0);
  assert.equal(result.event_count, 0);
  assert.equal(result.active_event_count, 0);
  assert.equal(result.oldest_event, null);
});

test("computeAgentTrustScore returns 0 for null events", () => {
  const result = computeAgentTrustScore(null, null, NOW);
  assert.equal(result.score, 0);
  assert.equal(result.event_count, 0);
});

test("computeAgentTrustScore computes single injection event", () => {
  const events = [{ type: "injection_detected", timestamp: NOW - 1000 }];
  const result = computeAgentTrustScore(events, null, NOW);
  assert.equal(result.score, 5);
  assert.equal(result.event_count, 1);
  assert.equal(result.active_event_count, 1);
});

test("computeAgentTrustScore computes multiple events", () => {
  const events = [
    { type: "injection_detected", timestamp: NOW - 1000 },  // +5
    { type: "sandbox_violation", timestamp: NOW - 2000 },    // +3
    { type: "rate_limit_hit", timestamp: NOW - 3000 }        // +2
  ];
  const result = computeAgentTrustScore(events, null, NOW);
  assert.equal(result.score, 10);
  assert.equal(result.active_event_count, 3);
});

test("computeAgentTrustScore applies decay window", () => {
  const events = [
    { type: "injection_detected", timestamp: NOW - 1000 },              // active +5
    { type: "sandbox_violation", timestamp: NOW - 86_400_001 }          // decayed
  ];
  const result = computeAgentTrustScore(events, null, NOW);
  assert.equal(result.score, 5);
  assert.equal(result.active_event_count, 1);
  assert.equal(result.decayed_count, 1);
});

test("computeAgentTrustScore uses custom decay window", () => {
  const events = [
    { type: "injection_detected", timestamp: NOW - 1000 },          // active
    { type: "sandbox_violation", timestamp: NOW - 70000 }           // decayed with 60s window
  ];
  const result = computeAgentTrustScore(events, { decay_window_ms: 60000 }, NOW);
  assert.equal(result.score, 5);
  assert.equal(result.decayed_count, 1);
});

test("computeAgentTrustScore reduces score with successful_operation", () => {
  const events = [
    { type: "injection_detected", timestamp: NOW - 3000 },          // +5
    { type: "successful_operation", timestamp: NOW - 2000 },        // -1
    { type: "successful_operation", timestamp: NOW - 1000 }         // -1
  ];
  const result = computeAgentTrustScore(events, null, NOW);
  assert.equal(result.score, 3);
});

test("computeAgentTrustScore floor at 0 (no negative scores)", () => {
  const events = [
    { type: "successful_operation", timestamp: NOW - 3000 },
    { type: "successful_operation", timestamp: NOW - 2000 },
    { type: "successful_operation", timestamp: NOW - 1000 }
  ];
  const result = computeAgentTrustScore(events, null, NOW);
  assert.equal(result.score, 0);
});

test("computeAgentTrustScore ignores unknown event types", () => {
  const events = [
    { type: "injection_detected", timestamp: NOW - 2000 },   // +5
    { type: "unknown_event", timestamp: NOW - 1000 }          // ignored
  ];
  const result = computeAgentTrustScore(events, null, NOW);
  assert.equal(result.score, 5);
  assert.equal(result.active_event_count, 1);
});

test("computeAgentTrustScore skips good behavior when disabled", () => {
  const events = [
    { type: "injection_detected", timestamp: NOW - 2000 },          // +5
    { type: "successful_operation", timestamp: NOW - 1000 }         // would be -1
  ];
  const result = computeAgentTrustScore(events, { good_behavior_decay: false }, NOW);
  assert.equal(result.score, 5);
  assert.equal(result.active_event_count, 1); // only 1 counted
});

test("computeAgentTrustScore tracks oldest and newest events", () => {
  const events = [
    { type: "rate_limit_hit", timestamp: NOW - 5000 },
    { type: "injection_detected", timestamp: NOW - 1000 }
  ];
  const result = computeAgentTrustScore(events, null, NOW);
  assert.equal(result.oldest_event, NOW - 5000);
  assert.equal(result.newest_event, NOW - 1000);
});

// ─── classifyAgentTrust ──────────────────────────────────────────────────────

test("classifyAgentTrust returns trusted for score 0", () => {
  assert.equal(classifyAgentTrust(0, null), "trusted");
});

test("classifyAgentTrust returns trusted for score below warning", () => {
  assert.equal(classifyAgentTrust(9, null), "trusted");
});

test("classifyAgentTrust returns warning at threshold", () => {
  assert.equal(classifyAgentTrust(10, null), "warning");
});

test("classifyAgentTrust returns quarantined at threshold", () => {
  assert.equal(classifyAgentTrust(25, null), "quarantined");
});

test("classifyAgentTrust returns blocked at threshold", () => {
  assert.equal(classifyAgentTrust(50, null), "blocked");
});

test("classifyAgentTrust returns blocked for very high score", () => {
  assert.equal(classifyAgentTrust(100, null), "blocked");
});

test("classifyAgentTrust uses custom thresholds", () => {
  const policy = { warning_threshold: 5, quarantine_threshold: 10, block_threshold: 20 };
  assert.equal(classifyAgentTrust(4, policy), "trusted");
  assert.equal(classifyAgentTrust(5, policy), "warning");
  assert.equal(classifyAgentTrust(10, policy), "quarantined");
  assert.equal(classifyAgentTrust(20, policy), "blocked");
});

// ─── assertAgentTrustOrThrow ─────────────────────────────────────────────────

test("assertAgentTrustOrThrow passes for trusted agent", () => {
  const result = assertAgentTrustOrThrow(0, null);
  assert.equal(result.score, 0);
  assert.equal(result.level, "trusted");
});

test("assertAgentTrustOrThrow passes for warning-level agent", () => {
  const result = assertAgentTrustOrThrow(10, null);
  assert.equal(result.level, "warning");
});

test("assertAgentTrustOrThrow throws AGENT_QUARANTINED", () => {
  try {
    assertAgentTrustOrThrow(25, null);
    assert.fail("should have thrown");
  } catch (err) {
    assert.equal(err.code, "AGENT_QUARANTINED");
    assert.equal(err.status, 403);
    assert.equal(err.details.trust_score, 25);
    assert.equal(err.details.trust_level, "quarantined");
  }
});

test("assertAgentTrustOrThrow throws AGENT_BLOCKED", () => {
  try {
    assertAgentTrustOrThrow(50, null);
    assert.fail("should have thrown");
  } catch (err) {
    assert.equal(err.code, "AGENT_BLOCKED");
    assert.equal(err.status, 403);
    assert.equal(err.details.trust_score, 50);
    assert.equal(err.details.trust_level, "blocked");
  }
});

test("assertAgentTrustOrThrow throws AGENT_BLOCKED for high score", () => {
  try {
    assertAgentTrustOrThrow(100, null);
    assert.fail("should have thrown");
  } catch (err) {
    assert.equal(err.code, "AGENT_BLOCKED");
  }
});

test("assertAgentTrustOrThrow uses custom policy thresholds", () => {
  const policy = { quarantine_threshold: 5, block_threshold: 10 };
  try {
    assertAgentTrustOrThrow(5, policy);
    assert.fail("should have thrown");
  } catch (err) {
    assert.equal(err.code, "AGENT_QUARANTINED");
  }
});

// ─── buildAgentTrustSummary ──────────────────────────────────────────────────

test("buildAgentTrustSummary for empty events", () => {
  const summary = buildAgentTrustSummary([], null, NOW);
  assert.equal(summary.score, 0);
  assert.equal(summary.level, "trusted");
  assert.equal(summary.event_count, 0);
  assert.deepEqual(summary.breakdown, {});
});

test("buildAgentTrustSummary computes full summary", () => {
  const events = [
    { type: "injection_detected", timestamp: NOW - 1000 },
    { type: "injection_detected", timestamp: NOW - 2000 },
    { type: "sandbox_violation", timestamp: NOW - 3000 },
    { type: "successful_operation", timestamp: NOW - 500 }
  ];
  const summary = buildAgentTrustSummary(events, null, NOW);
  assert.equal(summary.score, 12);  // 5+5+3-1
  assert.equal(summary.level, "warning");
  assert.equal(summary.event_count, 4);
  assert.equal(summary.active_event_count, 4);
  assert.equal(summary.breakdown.injection_detected.count, 2);
  assert.equal(summary.breakdown.injection_detected.total_weight, 10);
  assert.equal(summary.breakdown.sandbox_violation.count, 1);
  assert.equal(summary.breakdown.successful_operation.count, 1);
});

test("buildAgentTrustSummary excludes decayed events from breakdown", () => {
  const events = [
    { type: "injection_detected", timestamp: NOW - 1000 },
    { type: "injection_detected", timestamp: NOW - 86_400_001 }  // decayed
  ];
  const summary = buildAgentTrustSummary(events, null, NOW);
  assert.equal(summary.score, 5);
  assert.equal(summary.decayed_count, 1);
  assert.equal(summary.breakdown.injection_detected.count, 1);
});

test("buildAgentTrustSummary shows blocked level", () => {
  const events = [];
  for (let i = 0; i < 10; i++) {
    events.push({ type: "injection_detected", timestamp: NOW - (i + 1) * 1000 });
  }
  const summary = buildAgentTrustSummary(events, null, NOW);
  assert.equal(summary.score, 50);
  assert.equal(summary.level, "blocked");
});

test("buildAgentTrustSummary handles null events", () => {
  const summary = buildAgentTrustSummary(null, null, NOW);
  assert.equal(summary.score, 0);
  assert.equal(summary.level, "trusted");
  assert.deepEqual(summary.breakdown, {});
});
