import test from "node:test";
import assert from "node:assert/strict";

import { validateAgentInfo, normalizeAgentInfo } from "../src/protocol/agent_info.js";
import { generateSigningKeyPair, signEnvelope } from "../src/protocol/crypto.js";
import { generateUlid } from "../src/protocol/ulid.js";
import { LoomStore } from "../src/node/store.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Unit Tests: validateAgentInfo
// ═══════════════════════════════════════════════════════════════════════════════

test("agent_info: validateAgentInfo accepts valid agent_info", () => {
  const errors = validateAgentInfo({
    provider: "anthropic",
    model: "claude-opus-4",
    version: "2026.02",
    capabilities: ["tool_use", "vision"]
  });
  assert.equal(errors.length, 0);
});

test("agent_info: validateAgentInfo accepts minimal agent_info (provider + model only)", () => {
  const errors = validateAgentInfo({ provider: "openai", model: "gpt-4" });
  assert.equal(errors.length, 0);
});

test("agent_info: validateAgentInfo rejects null", () => {
  const errors = validateAgentInfo(null);
  assert.ok(errors.length > 0);
  assert.ok(errors.some((e) => e.field === "agent_info"));
});

test("agent_info: validateAgentInfo rejects non-object", () => {
  const errors = validateAgentInfo("string");
  assert.ok(errors.some((e) => e.field === "agent_info"));
});

test("agent_info: validateAgentInfo rejects array", () => {
  const errors = validateAgentInfo([1, 2]);
  assert.ok(errors.some((e) => e.field === "agent_info"));
});

test("agent_info: validateAgentInfo rejects missing provider", () => {
  const errors = validateAgentInfo({ model: "gpt-4" });
  assert.ok(errors.some((e) => e.field === "agent_info.provider"));
});

test("agent_info: validateAgentInfo rejects missing model", () => {
  const errors = validateAgentInfo({ provider: "openai" });
  assert.ok(errors.some((e) => e.field === "agent_info.model"));
});

test("agent_info: validateAgentInfo rejects non-string provider", () => {
  const errors = validateAgentInfo({ provider: 42, model: "gpt-4" });
  assert.ok(errors.some((e) => e.field === "agent_info.provider"));
});

test("agent_info: validateAgentInfo rejects non-string version", () => {
  const errors = validateAgentInfo({ provider: "a", model: "b", version: 123 });
  assert.ok(errors.some((e) => e.field === "agent_info.version"));
});

test("agent_info: validateAgentInfo rejects non-array capabilities", () => {
  const errors = validateAgentInfo({ provider: "a", model: "b", capabilities: "tool_use" });
  assert.ok(errors.some((e) => e.field === "agent_info.capabilities"));
});

test("agent_info: validateAgentInfo rejects non-string capability entries", () => {
  const errors = validateAgentInfo({ provider: "a", model: "b", capabilities: [42] });
  assert.ok(errors.some((e) => e.field.includes("capabilities")));
});

test("agent_info: validateAgentInfo accepts null version and capabilities", () => {
  const errors = validateAgentInfo({ provider: "a", model: "b", version: null, capabilities: null });
  assert.equal(errors.length, 0);
});

// ═══════════════════════════════════════════════════════════════════════════════
// Unit Tests: normalizeAgentInfo
// ═══════════════════════════════════════════════════════════════════════════════

test("agent_info: normalizeAgentInfo returns null for null input", () => {
  assert.equal(normalizeAgentInfo(null), null);
});

test("agent_info: normalizeAgentInfo returns null for undefined input", () => {
  assert.equal(normalizeAgentInfo(undefined), null);
});

test("agent_info: normalizeAgentInfo returns null for invalid object", () => {
  assert.equal(normalizeAgentInfo({ model: "x" }), null); // missing provider
  assert.equal(normalizeAgentInfo("string"), null);
});

test("agent_info: normalizeAgentInfo normalizes valid agent_info", () => {
  const result = normalizeAgentInfo({
    provider: "anthropic",
    model: "claude-opus-4",
    version: "2026.02",
    capabilities: ["tool_use"],
    extra_field: "ignored"
  });
  assert.deepEqual(result, {
    provider: "anthropic",
    model: "claude-opus-4",
    version: "2026.02",
    capabilities: ["tool_use"]
  });
});

test("agent_info: normalizeAgentInfo defaults version to null and capabilities to empty", () => {
  const result = normalizeAgentInfo({ provider: "a", model: "b" });
  assert.deepEqual(result, {
    provider: "a",
    model: "b",
    version: null,
    capabilities: []
  });
});

test("agent_info: normalizeAgentInfo filters non-string capabilities", () => {
  const result = normalizeAgentInfo({ provider: "a", model: "b", capabilities: ["ok", 42, "fine"] });
  assert.deepEqual(result.capabilities, ["ok", "fine"]);
});

// ═══════════════════════════════════════════════════════════════════════════════
// Integration Tests: Store identity lifecycle with agent_info
// ═══════════════════════════════════════════════════════════════════════════════

function setupStore() {
  const keys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });
  return { store, keys };
}

test("agent_info integration: register agent identity with agent_info", () => {
  const { store, keys } = setupStore();
  store.registerIdentity({
    id: "loom://agent-1@node.test",
    type: "agent",
    display_name: "Agent One",
    signing_keys: [{ key_id: "k_agent_1", public_key_pem: keys.publicKeyPem }],
    agent_info: {
      provider: "anthropic",
      model: "claude-opus-4",
      version: "2026.02",
      capabilities: ["tool_use"]
    }
  });

  const identity = store.identities.get("loom://agent-1@node.test");
  assert.ok(identity.agent_info);
  assert.equal(identity.agent_info.provider, "anthropic");
  assert.equal(identity.agent_info.model, "claude-opus-4");
  assert.equal(identity.agent_info.version, "2026.02");
  assert.deepEqual(identity.agent_info.capabilities, ["tool_use"]);
});

test("agent_info integration: register agent identity without agent_info has null", () => {
  const { store, keys } = setupStore();
  store.registerIdentity({
    id: "loom://agent-2@node.test",
    type: "agent",
    display_name: "Agent Two",
    signing_keys: [{ key_id: "k_agent_2", public_key_pem: keys.publicKeyPem }]
  });

  const identity = store.identities.get("loom://agent-2@node.test");
  assert.equal(identity.agent_info, null);
});

test("agent_info integration: register human identity with agent_info is rejected", () => {
  const { store, keys } = setupStore();
  assert.throws(
    () => {
      store.registerIdentity({
        id: "loom://human-1@node.test",
        type: "human",
        display_name: "Human One",
        signing_keys: [{ key_id: "k_human_1", public_key_pem: keys.publicKeyPem }],
        agent_info: { provider: "anthropic", model: "claude-opus-4" }
      });
    },
    (err) => err.code === "ENVELOPE_INVALID" && err.message.includes("agent_info")
  );
});

test("agent_info integration: register agent with invalid agent_info is rejected", () => {
  const { store, keys } = setupStore();
  assert.throws(
    () => {
      store.registerIdentity({
        id: "loom://agent-3@node.test",
        type: "agent",
        display_name: "Agent Three",
        signing_keys: [{ key_id: "k_agent_3", public_key_pem: keys.publicKeyPem }],
        agent_info: { provider: 42 } // invalid
      });
    },
    (err) => err.code === "ENVELOPE_INVALID"
  );
});

test("agent_info integration: update agent identity agent_info", () => {
  const { store, keys } = setupStore();
  store.registerIdentity({
    id: "loom://agent-upd@node.test",
    type: "agent",
    display_name: "Updatable Agent",
    signing_keys: [{ key_id: "k_agent_upd", public_key_pem: keys.publicKeyPem }],
    agent_info: { provider: "old", model: "old-model" }
  });

  store.updateIdentity("loom://agent-upd@node.test", {
    agent_info: { provider: "new", model: "new-model", version: "2.0", capabilities: ["vision"] }
  }, { identity: "loom://agent-upd@node.test", key_id: "k_agent_upd" });

  const identity = store.identities.get("loom://agent-upd@node.test");
  assert.equal(identity.agent_info.provider, "new");
  assert.equal(identity.agent_info.model, "new-model");
  assert.equal(identity.agent_info.version, "2.0");
  assert.deepEqual(identity.agent_info.capabilities, ["vision"]);
});

test("agent_info integration: update agent identity to clear agent_info", () => {
  const { store, keys } = setupStore();
  store.registerIdentity({
    id: "loom://agent-clear@node.test",
    type: "agent",
    display_name: "Clearable Agent",
    signing_keys: [{ key_id: "k_agent_clear", public_key_pem: keys.publicKeyPem }],
    agent_info: { provider: "x", model: "y" }
  });

  store.updateIdentity("loom://agent-clear@node.test", {
    agent_info: null
  }, { identity: "loom://agent-clear@node.test", key_id: "k_agent_clear" });

  const identity = store.identities.get("loom://agent-clear@node.test");
  assert.equal(identity.agent_info, null);
});

test("agent_info integration: update human identity with agent_info is rejected", () => {
  const { store, keys } = setupStore();
  store.registerIdentity({
    id: "loom://human-upd@node.test",
    type: "human",
    display_name: "Human",
    signing_keys: [{ key_id: "k_human_upd", public_key_pem: keys.publicKeyPem }]
  });

  assert.throws(
    () => {
      store.updateIdentity("loom://human-upd@node.test", {
        agent_info: { provider: "a", model: "b" }
      }, { identity: "loom://human-upd@node.test", key_id: "k_human_upd" });
    },
    (err) => err.code === "ENVELOPE_INVALID" && err.message.includes("agent_info")
  );
});

test("agent_info integration: getIdentityDocument returns agent_info", () => {
  const { store, keys } = setupStore();
  store.registerIdentity({
    id: "loom://agent-doc@node.test",
    type: "agent",
    display_name: "Doc Agent",
    signing_keys: [{ key_id: "k_agent_doc", public_key_pem: keys.publicKeyPem }],
    agent_info: { provider: "anthropic", model: "claude-opus-4", version: "2026.02" }
  });

  const doc = store.getIdentityDocument("loom://agent-doc@node.test");
  assert.ok(doc.agent_info);
  assert.equal(doc.agent_info.provider, "anthropic");
  assert.equal(doc.agent_info.model, "claude-opus-4");
});

test("agent_info integration: buildIdentityRegistrationDocument includes agent_info for agents", () => {
  const { store, keys } = setupStore();
  store.registerIdentity({
    id: "loom://agent-canon@node.test",
    type: "agent",
    display_name: "Canon Agent",
    signing_keys: [{ key_id: "k_agent_canon", public_key_pem: keys.publicKeyPem }],
    agent_info: { provider: "anthropic", model: "claude-opus-4" }
  });

  const doc = store.getIdentityDocument("loom://agent-canon@node.test");
  // agent_info should be in the document
  assert.ok(doc.agent_info);
  assert.equal(doc.agent_info.provider, "anthropic");
});

test("agent_info integration: state serialization preserves agent_info", () => {
  const { store, keys } = setupStore();
  store.registerIdentity({
    id: "loom://agent-ser@node.test",
    type: "agent",
    display_name: "Serial Agent",
    signing_keys: [{ key_id: "k_agent_ser", public_key_pem: keys.publicKeyPem }],
    agent_info: { provider: "anthropic", model: "claude-opus-4", capabilities: ["tool_use"] }
  });

  const state = store.toSerializableState();
  const store2 = new LoomStore({ nodeId: "node.test" });
  store2.loadStateFromObject(state);

  const identity = store2.identities.get("loom://agent-ser@node.test");
  assert.ok(identity.agent_info);
  assert.equal(identity.agent_info.provider, "anthropic");
  assert.equal(identity.agent_info.model, "claude-opus-4");
  assert.deepEqual(identity.agent_info.capabilities, ["tool_use"]);
});

test("agent_info integration: loadStateFromObject normalizes corrupted agent_info to null", () => {
  const { store, keys } = setupStore();
  store.registerIdentity({
    id: "loom://agent-corrupt@node.test",
    type: "agent",
    display_name: "Corrupt Agent",
    signing_keys: [{ key_id: "k_agent_corrupt", public_key_pem: keys.publicKeyPem }]
  });

  const state = store.toSerializableState();
  // Corrupt the agent_info
  const identityEntry = state.identities.find((i) => i.id === "loom://agent-corrupt@node.test");
  identityEntry.agent_info = "not-an-object";

  const store2 = new LoomStore({ nodeId: "node.test" });
  store2.loadStateFromObject(state);

  const identity = store2.identities.get("loom://agent-corrupt@node.test");
  assert.equal(identity.agent_info, null);
});
