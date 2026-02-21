import test from "node:test";
import assert from "node:assert/strict";

import {
  RULE_ACTIONS,
  validateChannelRule,
  normalizeChannelRules,
  matchesCondition,
  evaluateRules,
  applyRuleActions
} from "../src/protocol/channel_rules.js";

// ─── Constants ──────────────────────────────────────────────────────────────

test("RULE_ACTIONS has all action types", () => {
  assert.equal(RULE_ACTIONS.LABEL, "label");
  assert.equal(RULE_ACTIONS.ROUTE, "route");
  assert.equal(RULE_ACTIONS.DELEGATE, "delegate");
  assert.equal(RULE_ACTIONS.ESCALATE, "escalate");
  assert.equal(RULE_ACTIONS.QUARANTINE, "quarantine");
});

// ─── validateChannelRule ───────────────────────────────────────────────────

test("validateChannelRule: valid rule", () => {
  const errors = validateChannelRule({
    condition: { intent: "message.general@v1" },
    action: { type: "label", add: "important" }
  });
  assert.equal(errors.length, 0);
});

test("validateChannelRule: missing condition", () => {
  const errors = validateChannelRule({ action: { type: "label" } });
  assert.ok(errors.some((e) => e.field === "condition"));
});

test("validateChannelRule: missing action", () => {
  const errors = validateChannelRule({ condition: { intent: "x" } });
  assert.ok(errors.some((e) => e.field === "action"));
});

test("validateChannelRule: action missing type", () => {
  const errors = validateChannelRule({
    condition: { intent: "x" },
    action: { add: "label" }
  });
  assert.ok(errors.some((e) => e.field === "action.type"));
});

test("validateChannelRule: invalid priority type", () => {
  const errors = validateChannelRule({
    condition: {},
    action: { type: "label" },
    priority: "high"
  });
  assert.ok(errors.some((e) => e.field === "priority"));
});

test("validateChannelRule: null input", () => {
  const errors = validateChannelRule(null);
  assert.ok(errors.length > 0);
});

// ─── normalizeChannelRules ─────────────────────────────────────────────────

test("normalizeChannelRules: sorts by priority descending", () => {
  const rules = normalizeChannelRules([
    { condition: {}, action: { type: "label" }, priority: 1 },
    { condition: {}, action: { type: "route" }, priority: 10 },
    { condition: {}, action: { type: "escalate" }, priority: 5 }
  ]);
  assert.equal(rules[0].priority, 10);
  assert.equal(rules[1].priority, 5);
  assert.equal(rules[2].priority, 1);
});

test("normalizeChannelRules: filters invalid entries", () => {
  const rules = normalizeChannelRules([
    null,
    { condition: {}, action: { type: "label" } },
    "invalid"
  ]);
  assert.equal(rules.length, 1);
});

test("normalizeChannelRules: defaults priority to 0 and enabled to true", () => {
  const rules = normalizeChannelRules([{ condition: {}, action: { type: "label" } }]);
  assert.equal(rules[0].priority, 0);
  assert.equal(rules[0].enabled, true);
});

test("normalizeChannelRules: non-array returns empty", () => {
  assert.deepEqual(normalizeChannelRules("not array"), []);
});

// ─── matchesCondition ──────────────────────────────────────────────────────

test("matchesCondition: matches exact intent", () => {
  const envelope = { content: { structured: { intent: "task.create@v1" } } };
  assert.equal(matchesCondition(envelope, { intent: "task.create@v1" }), true);
});

test("matchesCondition: matches intent with wildcard", () => {
  const envelope = { content: { structured: { intent: "task.create@v1" } } };
  assert.equal(matchesCondition(envelope, { intent: "task.*" }), true);
});

test("matchesCondition: rejects non-matching intent", () => {
  const envelope = { content: { structured: { intent: "message.general@v1" } } };
  assert.equal(matchesCondition(envelope, { intent: "task.create@v1" }), false);
});

test("matchesCondition: matches sender", () => {
  const envelope = { from: { identity: "loom://alice" } };
  assert.equal(matchesCondition(envelope, { sender: "loom://alice" }), true);
  assert.equal(matchesCondition(envelope, { sender: "loom://bob" }), false);
});

test("matchesCondition: matches labels", () => {
  const envelope = {};
  assert.equal(matchesCondition(envelope, { labels: ["important"], _thread_labels: ["important", "urgent"] }), true);
  assert.equal(matchesCondition(envelope, { labels: ["missing"], _thread_labels: ["important"] }), false);
});

test("matchesCondition: matches priority", () => {
  const envelope = { priority: "high" };
  assert.equal(matchesCondition(envelope, { priority: "high" }), true);
  assert.equal(matchesCondition(envelope, { priority: "low" }), false);
});

test("matchesCondition: matches attachment types", () => {
  const envelope = { attachments: [{ mime_type: "image/png" }] };
  assert.equal(matchesCondition(envelope, { attachment_types: ["image/png"] }), true);
  assert.equal(matchesCondition(envelope, { attachment_types: ["application/pdf"] }), false);
});

test("matchesCondition: empty condition matches all", () => {
  assert.equal(matchesCondition({}, {}), true);
});

// ─── evaluateRules ─────────────────────────────────────────────────────────

test("evaluateRules: returns matching actions", () => {
  const envelope = { content: { structured: { intent: "task.create@v1" } } };
  const rules = [
    { condition: { intent: "task.*" }, action: { type: "label", add: "task" }, enabled: true },
    { condition: { intent: "message.*" }, action: { type: "label", add: "msg" }, enabled: true }
  ];
  const results = evaluateRules(envelope, rules);
  assert.equal(results.length, 1);
  assert.equal(results[0].type, "label");
});

test("evaluateRules: skips disabled rules", () => {
  const envelope = { content: { structured: { intent: "task.create@v1" } } };
  const rules = [
    { condition: { intent: "task.*" }, action: { type: "label" }, enabled: false }
  ];
  const results = evaluateRules(envelope, rules);
  assert.equal(results.length, 0);
});

test("evaluateRules: passes thread labels", () => {
  const envelope = {};
  const rules = [
    { condition: { labels: ["urgent"] }, action: { type: "escalate" }, enabled: true }
  ];
  const results = evaluateRules(envelope, rules, ["urgent"]);
  assert.equal(results.length, 1);
});

// ─── applyRuleActions ──────────────────────────────────────────────────────

test("applyRuleActions: label action", () => {
  const result = applyRuleActions([{ type: "label", add: "important", remove: "pending" }]);
  assert.deepEqual(result.labels_to_add, ["important"]);
  assert.deepEqual(result.labels_to_remove, ["pending"]);
});

test("applyRuleActions: label action with arrays", () => {
  const result = applyRuleActions([{ type: "label", add: ["a", "b"], remove: ["c"] }]);
  assert.deepEqual(result.labels_to_add, ["a", "b"]);
  assert.deepEqual(result.labels_to_remove, ["c"]);
});

test("applyRuleActions: route action", () => {
  const result = applyRuleActions([{ type: "route", target: "loom://team" }]);
  assert.equal(result.route_to, "loom://team");
});

test("applyRuleActions: delegate action", () => {
  const result = applyRuleActions([{ type: "delegate", target: "loom://agent" }]);
  assert.equal(result.delegate_to, "loom://agent");
});

test("applyRuleActions: escalate action", () => {
  const result = applyRuleActions([{ type: "escalate" }]);
  assert.equal(result.escalate, true);
});

test("applyRuleActions: quarantine action adds label", () => {
  const result = applyRuleActions([{ type: "quarantine" }]);
  assert.equal(result.quarantine, true);
  assert.ok(result.labels_to_add.includes("sys.quarantine"));
});

test("applyRuleActions: combines multiple actions", () => {
  const result = applyRuleActions([
    { type: "label", add: "flagged" },
    { type: "escalate" },
    { type: "route", target: "loom://admin" }
  ]);
  assert.deepEqual(result.labels_to_add, ["flagged"]);
  assert.equal(result.escalate, true);
  assert.equal(result.route_to, "loom://admin");
});
