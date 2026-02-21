import test from "node:test";
import assert from "node:assert/strict";

import {
  validateRoutingPolicy,
  normalizeRoutingPolicy,
  resolveTeamRecipients,
  resolveReplyTarget,
  requiresModeration
} from "../src/protocol/distribution.js";

// ─── validateRoutingPolicy ─────────────────────────────────────────────────

test("validateRoutingPolicy: valid policy", () => {
  const errors = validateRoutingPolicy({
    deliver_to_members: "all",
    reply_policy: "list",
    moderation: "none"
  });
  assert.equal(errors.length, 0);
});

test("validateRoutingPolicy: invalid deliver_to_members", () => {
  const errors = validateRoutingPolicy({ deliver_to_members: "some" });
  assert.ok(errors.some((e) => e.field.includes("deliver_to_members")));
});

test("validateRoutingPolicy: invalid reply_policy", () => {
  const errors = validateRoutingPolicy({ reply_policy: "nobody" });
  assert.ok(errors.some((e) => e.field.includes("reply_policy")));
});

test("validateRoutingPolicy: invalid moderation", () => {
  const errors = validateRoutingPolicy({ moderation: "strict" });
  assert.ok(errors.some((e) => e.field.includes("moderation")));
});

test("validateRoutingPolicy: null input", () => {
  const errors = validateRoutingPolicy(null);
  assert.ok(errors.length > 0);
});

// ─── normalizeRoutingPolicy ────────────────────────────────────────────────

test("normalizeRoutingPolicy: fills defaults for null", () => {
  const result = normalizeRoutingPolicy(null);
  assert.equal(result.deliver_to_members, "all");
  assert.equal(result.reply_policy, "list");
  assert.equal(result.moderation, "none");
});

test("normalizeRoutingPolicy: keeps valid values", () => {
  const result = normalizeRoutingPolicy({
    deliver_to_members: "owners_only",
    reply_policy: "sender",
    moderation: "agent"
  });
  assert.equal(result.deliver_to_members, "owners_only");
  assert.equal(result.reply_policy, "sender");
  assert.equal(result.moderation, "agent");
});

test("normalizeRoutingPolicy: defaults invalid values", () => {
  const result = normalizeRoutingPolicy({ deliver_to_members: "invalid" });
  assert.equal(result.deliver_to_members, "all");
});

// ─── resolveTeamRecipients ─────────────────────────────────────────────────

test("resolveTeamRecipients: deliver_to_members=all returns all", () => {
  const team = {
    members: [
      { identity: "loom://a", role: "owner" },
      { identity: "loom://b", role: "member" }
    ]
  };
  const result = resolveTeamRecipients(team, { deliver_to_members: "all" });
  assert.equal(result.length, 2);
});

test("resolveTeamRecipients: owners_only filters by role", () => {
  const team = {
    members: [
      { identity: "loom://a", role: "owner" },
      { identity: "loom://b", role: "member" },
      { identity: "loom://c", role: "owner" }
    ]
  };
  const result = resolveTeamRecipients(team, { deliver_to_members: "owners_only" });
  assert.equal(result.length, 2);
  assert.ok(result.every((m) => m.role === "owner"));
});

test("resolveTeamRecipients: on_call filters by on_call flag", () => {
  const team = {
    members: [
      { identity: "loom://a", on_call: true },
      { identity: "loom://b", on_call: false },
      { identity: "loom://c", on_call: true }
    ]
  };
  const result = resolveTeamRecipients(team, { deliver_to_members: "on_call" });
  assert.equal(result.length, 2);
});

test("resolveTeamRecipients: empty members", () => {
  const result = resolveTeamRecipients({ members: [] }, { deliver_to_members: "all" });
  assert.equal(result.length, 0);
});

// ─── resolveReplyTarget ────────────────────────────────────────────────────

test("resolveReplyTarget: reply_policy=list returns team id", () => {
  const envelope = { from: { identity: "loom://sender" } };
  const team = { id: "loom://team" };
  const result = resolveReplyTarget(envelope, team, { reply_policy: "list" });
  assert.deepEqual(result, ["loom://team"]);
});

test("resolveReplyTarget: reply_policy=sender returns sender", () => {
  const envelope = { from: { identity: "loom://sender" } };
  const team = { id: "loom://team" };
  const result = resolveReplyTarget(envelope, team, { reply_policy: "sender" });
  assert.deepEqual(result, ["loom://sender"]);
});

test("resolveReplyTarget: reply_policy=all returns both", () => {
  const envelope = { from: { identity: "loom://sender" } };
  const team = { id: "loom://team" };
  const result = resolveReplyTarget(envelope, team, { reply_policy: "all" });
  assert.deepEqual(result, ["loom://sender", "loom://team"]);
});

// ─── requiresModeration ────────────────────────────────────────────────────

test("requiresModeration: true for owners mode", () => {
  assert.equal(requiresModeration({ moderation: "owners" }), true);
});

test("requiresModeration: true for agent mode", () => {
  assert.equal(requiresModeration({ moderation: "agent" }), true);
});

test("requiresModeration: false for none mode", () => {
  assert.equal(requiresModeration({ moderation: "none" }), false);
});
