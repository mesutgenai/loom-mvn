import test from "node:test";
import assert from "node:assert/strict";

import {
  AGENT_CARD_SCHEMA_VERSION,
  VALID_AUTHENTICATION_SCHEMES,
  VALID_INPUT_MODES,
  VALID_OUTPUT_MODES,
  isValidSkillDefinition,
  validateAgentCard,
  normalizeAgentCard,
  buildAgentCardFromInfo
} from "../src/protocol/agent_card.js";

// ─── Constants ───────────────────────────────────────────────────────────────

test("AGENT_CARD_SCHEMA_VERSION is '1.0'", () => {
  assert.equal(AGENT_CARD_SCHEMA_VERSION, "1.0");
});

test("VALID_AUTHENTICATION_SCHEMES is frozen", () => {
  assert.ok(Object.isFrozen(VALID_AUTHENTICATION_SCHEMES));
  assert.ok(VALID_AUTHENTICATION_SCHEMES.includes("loom_capability"));
  assert.ok(VALID_AUTHENTICATION_SCHEMES.includes("bearer"));
  assert.ok(VALID_AUTHENTICATION_SCHEMES.includes("none"));
});

test("VALID_INPUT_MODES is frozen", () => {
  assert.ok(Object.isFrozen(VALID_INPUT_MODES));
  assert.ok(VALID_INPUT_MODES.includes("text"));
  assert.ok(VALID_INPUT_MODES.includes("structured"));
  assert.ok(VALID_INPUT_MODES.includes("multimodal"));
});

test("VALID_OUTPUT_MODES is frozen", () => {
  assert.ok(Object.isFrozen(VALID_OUTPUT_MODES));
  assert.ok(VALID_OUTPUT_MODES.includes("text"));
  assert.ok(VALID_OUTPUT_MODES.includes("file"));
});

// ─── isValidSkillDefinition ──────────────────────────────────────────────────

test("isValidSkillDefinition returns true for valid skill", () => {
  assert.ok(isValidSkillDefinition({ id: "summarize", name: "Summarize" }));
});

test("isValidSkillDefinition returns true for skill with description and intents", () => {
  assert.ok(isValidSkillDefinition({
    id: "translate",
    name: "Translate",
    description: "Translates text between languages",
    supported_intents: ["translate.text", "translate.document"]
  }));
});

test("isValidSkillDefinition returns false for null", () => {
  assert.equal(isValidSkillDefinition(null), false);
});

test("isValidSkillDefinition returns false for missing id", () => {
  assert.equal(isValidSkillDefinition({ name: "Test" }), false);
});

test("isValidSkillDefinition returns false for missing name", () => {
  assert.equal(isValidSkillDefinition({ id: "test" }), false);
});

test("isValidSkillDefinition returns false for non-string description", () => {
  assert.equal(isValidSkillDefinition({ id: "test", name: "Test", description: 123 }), false);
});

test("isValidSkillDefinition returns false for non-array supported_intents", () => {
  assert.equal(isValidSkillDefinition({ id: "test", name: "Test", supported_intents: "not_array" }), false);
});

test("isValidSkillDefinition returns false for non-string intent in array", () => {
  assert.equal(isValidSkillDefinition({ id: "test", name: "Test", supported_intents: [123] }), false);
});

// ─── validateAgentCard — base field delegation ───────────────────────────────

test("validateAgentCard rejects null", () => {
  const errors = validateAgentCard(null);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, "agent_card");
});

test("validateAgentCard rejects array", () => {
  const errors = validateAgentCard([]);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, "agent_card");
});

test("validateAgentCard reports missing provider", () => {
  const errors = validateAgentCard({ model: "gpt-4" });
  assert.ok(errors.some((e) => e.field === "agent_info.provider"));
});

test("validateAgentCard reports missing model", () => {
  const errors = validateAgentCard({ provider: "openai" });
  assert.ok(errors.some((e) => e.field === "agent_info.model"));
});

test("validateAgentCard accepts valid minimal card", () => {
  const errors = validateAgentCard({ provider: "anthropic", model: "claude-sonnet-4-20250514" });
  assert.equal(errors.length, 0);
});

// ─── validateAgentCard — extension validation ────────────────────────────────

test("validateAgentCard accepts full valid card", () => {
  const errors = validateAgentCard({
    provider: "anthropic",
    model: "claude-sonnet-4-20250514",
    version: "1.0",
    capabilities: ["chat"],
    skills: [{ id: "chat", name: "Chat" }],
    supported_intents: ["chat.message"],
    authentication: [{ scheme: "loom_capability" }],
    default_input_modes: ["text", "structured"],
    default_output_modes: ["text"],
    url: "https://agent.example.com",
    documentation_url: "https://docs.example.com"
  });
  assert.equal(errors.length, 0);
});

test("validateAgentCard rejects non-array skills", () => {
  const errors = validateAgentCard({
    provider: "anthropic", model: "claude-sonnet-4-20250514",
    skills: "not_array"
  });
  assert.ok(errors.some((e) => e.field === "agent_card.skills"));
});

test("validateAgentCard rejects invalid skill entry", () => {
  const errors = validateAgentCard({
    provider: "anthropic", model: "claude-sonnet-4-20250514",
    skills: [{ id: 123, name: "Bad" }]
  });
  assert.ok(errors.some((e) => e.field === "agent_card.skills[0]"));
});

test("validateAgentCard rejects non-array supported_intents", () => {
  const errors = validateAgentCard({
    provider: "anthropic", model: "claude-sonnet-4-20250514",
    supported_intents: "not_array"
  });
  assert.ok(errors.some((e) => e.field === "agent_card.supported_intents"));
});

test("validateAgentCard rejects non-string intent in array", () => {
  const errors = validateAgentCard({
    provider: "anthropic", model: "claude-sonnet-4-20250514",
    supported_intents: [123]
  });
  assert.ok(errors.some((e) => e.field.startsWith("agent_card.supported_intents")));
});

test("validateAgentCard rejects non-array authentication", () => {
  const errors = validateAgentCard({
    provider: "anthropic", model: "claude-sonnet-4-20250514",
    authentication: "not_array"
  });
  assert.ok(errors.some((e) => e.field === "agent_card.authentication"));
});

test("validateAgentCard rejects invalid auth scheme", () => {
  const errors = validateAgentCard({
    provider: "anthropic", model: "claude-sonnet-4-20250514",
    authentication: [{ scheme: "invalid_scheme" }]
  });
  assert.ok(errors.some((e) => e.field.includes("authentication") && e.field.includes("scheme")));
});

test("validateAgentCard rejects missing auth scheme", () => {
  const errors = validateAgentCard({
    provider: "anthropic", model: "claude-sonnet-4-20250514",
    authentication: [{ description: "no scheme" }]
  });
  assert.ok(errors.some((e) => e.field.includes("authentication")));
});

test("validateAgentCard rejects non-array default_input_modes", () => {
  const errors = validateAgentCard({
    provider: "anthropic", model: "claude-sonnet-4-20250514",
    default_input_modes: "text"
  });
  assert.ok(errors.some((e) => e.field === "agent_card.default_input_modes"));
});

test("validateAgentCard rejects invalid input mode", () => {
  const errors = validateAgentCard({
    provider: "anthropic", model: "claude-sonnet-4-20250514",
    default_input_modes: ["text", "invalid_mode"]
  });
  assert.ok(errors.some((e) => e.field.includes("default_input_modes")));
});

test("validateAgentCard rejects invalid output mode", () => {
  const errors = validateAgentCard({
    provider: "anthropic", model: "claude-sonnet-4-20250514",
    default_output_modes: ["binary"]
  });
  assert.ok(errors.some((e) => e.field.includes("default_output_modes")));
});

test("validateAgentCard rejects non-string url", () => {
  const errors = validateAgentCard({
    provider: "anthropic", model: "claude-sonnet-4-20250514",
    url: 123
  });
  assert.ok(errors.some((e) => e.field === "agent_card.url"));
});

test("validateAgentCard rejects non-string documentation_url", () => {
  const errors = validateAgentCard({
    provider: "anthropic", model: "claude-sonnet-4-20250514",
    documentation_url: { href: "test" }
  });
  assert.ok(errors.some((e) => e.field === "agent_card.documentation_url"));
});

// ─── normalizeAgentCard ──────────────────────────────────────────────────────

test("normalizeAgentCard returns null for null input", () => {
  assert.equal(normalizeAgentCard(null), null);
});

test("normalizeAgentCard returns null for invalid base (missing provider)", () => {
  assert.equal(normalizeAgentCard({ model: "test" }), null);
});

test("normalizeAgentCard normalizes minimal card", () => {
  const result = normalizeAgentCard({ provider: "anthropic", model: "claude-sonnet-4-20250514" });
  assert.equal(result.provider, "anthropic");
  assert.equal(result.model, "claude-sonnet-4-20250514");
  assert.equal(result.card_version, "1.0");
  assert.deepEqual(result.skills, []);
  assert.deepEqual(result.supported_intents, []);
  assert.deepEqual(result.authentication, []);
  assert.deepEqual(result.default_input_modes, []);
  assert.deepEqual(result.default_output_modes, []);
  assert.equal(result.url, null);
  assert.equal(result.documentation_url, null);
});

test("normalizeAgentCard normalizes full card", () => {
  const result = normalizeAgentCard({
    provider: "anthropic",
    model: "claude-sonnet-4-20250514",
    version: "2.0",
    capabilities: ["chat", "tool_use"],
    skills: [
      { id: "summarize", name: "Summarize", description: "Summarizes text" },
      { id: "bad_skill" } // missing name — filtered out
    ],
    supported_intents: ["chat.message", 123], // 123 filtered out
    authentication: [
      { scheme: "loom_capability", description: "Cap token" },
      { scheme: "invalid" } // filtered out
    ],
    default_input_modes: ["text", "invalid"], // invalid filtered out
    default_output_modes: ["structured", "file"],
    url: "https://agent.test",
    documentation_url: "https://docs.test"
  });

  assert.equal(result.provider, "anthropic");
  assert.equal(result.version, "2.0");
  assert.deepEqual(result.capabilities, ["chat", "tool_use"]);
  assert.equal(result.skills.length, 1);
  assert.equal(result.skills[0].id, "summarize");
  assert.equal(result.skills[0].description, "Summarizes text");
  assert.deepEqual(result.supported_intents, ["chat.message"]);
  assert.equal(result.authentication.length, 1);
  assert.equal(result.authentication[0].scheme, "loom_capability");
  assert.equal(result.authentication[0].description, "Cap token");
  assert.deepEqual(result.default_input_modes, ["text"]);
  assert.deepEqual(result.default_output_modes, ["structured", "file"]);
  assert.equal(result.url, "https://agent.test");
  assert.equal(result.documentation_url, "https://docs.test");
  assert.equal(result.card_version, "1.0");
});

test("normalizeAgentCard preserves base fields from agent_info", () => {
  const result = normalizeAgentCard({
    provider: "openai",
    model: "gpt-4",
    version: "1.0",
    capabilities: ["completion"]
  });
  assert.equal(result.provider, "openai");
  assert.equal(result.model, "gpt-4");
  assert.equal(result.version, "1.0");
  assert.deepEqual(result.capabilities, ["completion"]);
});

test("normalizeAgentCard handles null optional fields", () => {
  const result = normalizeAgentCard({
    provider: "anthropic",
    model: "claude-sonnet-4-20250514",
    skills: null,
    supported_intents: null,
    authentication: null,
    default_input_modes: null,
    default_output_modes: null,
    url: null,
    documentation_url: null
  });
  assert.deepEqual(result.skills, []);
  assert.deepEqual(result.supported_intents, []);
  assert.deepEqual(result.authentication, []);
  assert.equal(result.url, null);
});

test("normalizeAgentCard filters invalid auth entries", () => {
  const result = normalizeAgentCard({
    provider: "anthropic",
    model: "claude-sonnet-4-20250514",
    authentication: [null, "bad", { scheme: "bearer" }, { scheme: "unknown" }]
  });
  assert.equal(result.authentication.length, 1);
  assert.equal(result.authentication[0].scheme, "bearer");
});

test("normalizeAgentCard normalizes skill supported_intents", () => {
  const result = normalizeAgentCard({
    provider: "anthropic",
    model: "claude-sonnet-4-20250514",
    skills: [{
      id: "test",
      name: "Test",
      supported_intents: ["valid", "also_valid"]
    }]
  });
  assert.equal(result.skills.length, 1);
  assert.deepEqual(result.skills[0].supported_intents, ["valid", "also_valid"]);
});

// ─── buildAgentCardFromInfo ──────────────────────────────────────────────────

test("buildAgentCardFromInfo returns null for null agentInfo", () => {
  assert.equal(buildAgentCardFromInfo(null), null);
});

test("buildAgentCardFromInfo returns null for invalid agentInfo", () => {
  assert.equal(buildAgentCardFromInfo({ model: "missing_provider" }), null);
});

test("buildAgentCardFromInfo upgrades minimal agent_info", () => {
  const result = buildAgentCardFromInfo({ provider: "anthropic", model: "claude-sonnet-4-20250514" });
  assert.equal(result.provider, "anthropic");
  assert.equal(result.model, "claude-sonnet-4-20250514");
  assert.equal(result.card_version, "1.0");
  assert.deepEqual(result.skills, []);
});

test("buildAgentCardFromInfo merges extensions", () => {
  const result = buildAgentCardFromInfo(
    { provider: "anthropic", model: "claude-sonnet-4-20250514", version: "1.0", capabilities: ["chat"] },
    {
      skills: [{ id: "summarize", name: "Summarize" }],
      url: "https://agent.test",
      authentication: [{ scheme: "loom_capability" }]
    }
  );
  assert.equal(result.skills.length, 1);
  assert.equal(result.skills[0].id, "summarize");
  assert.equal(result.url, "https://agent.test");
  assert.equal(result.authentication.length, 1);
});

test("buildAgentCardFromInfo with empty extensions", () => {
  const result = buildAgentCardFromInfo(
    { provider: "anthropic", model: "claude-sonnet-4-20250514" },
    {}
  );
  assert.equal(result.provider, "anthropic");
  assert.equal(result.card_version, "1.0");
});
