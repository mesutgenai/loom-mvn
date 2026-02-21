import test from "node:test";
import assert from "node:assert/strict";
import { generateSigningKeyPair, signEnvelope, signUtf8Message } from "../src/protocol/crypto.js";
import { generateUlid } from "../src/protocol/ulid.js";
import { LoomStore } from "../src/node/store.js";
import { canonicalizeDelegationLink } from "../src/protocol/delegation.js";
import {
  validateHopCount,
  computeConversationHash,
  detectPingPongPattern,
  assertAgentThreadRateOrThrow,
  DEFAULT_LOOP_LIMITS,
  MAX_HOP_COUNT_ABSOLUTE
} from "../src/protocol/loop_protection.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function envId() {
  return `env_${generateUlid()}`;
}

function thrId() {
  return `thr_${generateUlid()}`;
}

function makeEnvelope(overrides = {}) {
  return {
    loom: "1.1",
    id: envId(),
    thread_id: thrId(),
    parent_id: null,
    type: "message",
    from: {
      identity: "loom://alice@node.test",
      display: "Alice",
      key_id: "k_sign_alice_1",
      type: "human"
    },
    to: [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: new Date().toISOString(),
    priority: "normal",
    content: {
      human: { text: "hello", format: "markdown" },
      structured: { intent: "message.general@v1", parameters: {} },
      encrypted: false
    },
    attachments: [],
    ...overrides
  };
}

function setupStore(opts = {}) {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const agentKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test", ...opts });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    type: "human",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: aliceKeys.publicKeyPem }]
  });

  store.registerIdentity({
    id: "loom://bob@node.test",
    display_name: "Bob",
    type: "human",
    signing_keys: [{ key_id: "k_sign_bob_1", public_key_pem: bobKeys.publicKeyPem }]
  });

  store.registerIdentity({
    id: "loom://assistant.alice@node.test",
    display_name: "Assistant",
    type: "agent",
    signing_keys: [{ key_id: "k_sign_agent_1", public_key_pem: agentKeys.publicKeyPem }]
  });

  // Create a delegation from alice to assistant
  const delegationUnsigned = {
    id: `dlg_${generateUlid()}`,
    delegator: "loom://alice@node.test",
    delegate: "loom://assistant.alice@node.test",
    scope: ["message.general@v1"],
    created_at: new Date(Date.now() - 60000).toISOString(),
    expires_at: new Date(Date.now() + 86400000).toISOString(),
    revocable: true,
    allow_sub_delegation: false,
    max_sub_delegation_depth: 0,
    key_id: "k_sign_alice_1"
  };
  const delegation = {
    ...delegationUnsigned,
    signature: signUtf8Message(aliceKeys.privateKeyPem, canonicalizeDelegationLink(delegationUnsigned))
  };

  return { store, aliceKeys, bobKeys, agentKeys, delegation };
}

function signHumanEnvelope(keys, overrides = {}) {
  const env = makeEnvelope(overrides);
  return signEnvelope(env, keys.privateKeyPem, env.from.key_id);
}

function signAgentEnvelope(agentKeys, delegation, overrides = {}) {
  const env = makeEnvelope({
    from: {
      identity: "loom://assistant.alice@node.test",
      display: "Assistant",
      key_id: "k_sign_agent_1",
      type: "agent",
      delegation_chain: [delegation]
    },
    ...overrides
  });
  return signEnvelope(env, agentKeys.privateKeyPem, "k_sign_agent_1");
}

// ─── Protocol Layer: validateHopCount ──────────────────────────────────────────

test("validateHopCount: accepts undefined/null (optional field)", () => {
  assert.deepEqual(validateHopCount(undefined), []);
  assert.deepEqual(validateHopCount(null), []);
});

test("validateHopCount: accepts 0", () => {
  assert.deepEqual(validateHopCount(0), []);
});

test("validateHopCount: accepts valid integers", () => {
  assert.deepEqual(validateHopCount(1), []);
  assert.deepEqual(validateHopCount(20), []);
  assert.deepEqual(validateHopCount(255), []);
});

test("validateHopCount: rejects negative values", () => {
  const errors = validateHopCount(-1);
  assert.ok(errors.some((e) => e.field === "hop_count" && /non-negative/.test(e.reason)));
});

test("validateHopCount: rejects values exceeding 255", () => {
  const errors = validateHopCount(256);
  assert.ok(errors.some((e) => e.field === "hop_count" && /exceed/.test(e.reason)));
});

test("validateHopCount: rejects non-integer numbers", () => {
  const errors = validateHopCount(1.5);
  assert.ok(errors.some((e) => e.field === "hop_count" && /integer/.test(e.reason)));
});

test("validateHopCount: rejects strings", () => {
  const errors = validateHopCount("10");
  assert.ok(errors.some((e) => e.field === "hop_count" && /integer/.test(e.reason)));
});

// ─── Protocol Layer: computeConversationHash ────────────────────────────────

test("computeConversationHash: produces deterministic output", () => {
  const h1 = computeConversationHash("loom://a@x", ["loom://b@x"], "message.general@v1");
  const h2 = computeConversationHash("loom://a@x", ["loom://b@x"], "message.general@v1");
  assert.equal(h1, h2);
  assert.equal(typeof h1, "string");
  assert.equal(h1.length, 64); // SHA-256 hex
});

test("computeConversationHash: different inputs produce different hashes", () => {
  const h1 = computeConversationHash("loom://a@x", ["loom://b@x"], "message.general@v1");
  const h2 = computeConversationHash("loom://a@x", ["loom://c@x"], "message.general@v1");
  assert.notEqual(h1, h2);
});

test("computeConversationHash: symmetric — sender/recipient swap produces same hash", () => {
  const h1 = computeConversationHash("loom://a@x", ["loom://b@x"], "message.general@v1");
  const h2 = computeConversationHash("loom://b@x", ["loom://a@x"], "message.general@v1");
  assert.equal(h1, h2);
});

test("computeConversationHash: participant order does not matter", () => {
  const h1 = computeConversationHash("loom://a@x", ["loom://b@x", "loom://c@x"], "intent");
  const h2 = computeConversationHash("loom://a@x", ["loom://c@x", "loom://b@x"], "intent");
  assert.equal(h1, h2);
});

test("computeConversationHash: handles missing values gracefully", () => {
  const h = computeConversationHash(null, null, null);
  assert.equal(typeof h, "string");
  assert.equal(h.length, 64);
});

// ─── Protocol Layer: detectPingPongPattern ──────────────────────────────────

function buildMockEnvelopesMap(envelopes) {
  const map = new Map();
  for (const env of envelopes) {
    map.set(env.id, env);
  }
  return map;
}

function mockEnvelope(id, sender, recipients, intent) {
  return {
    id,
    from: { identity: sender, type: "agent" },
    to: recipients.map((r) => ({ identity: r })),
    content: { structured: { intent } },
    created_at: new Date().toISOString()
  };
}

test("detectPingPongPattern: returns false for too few envelopes", () => {
  const result = detectPingPongPattern(["e1", "e2"], new Map(), "sender", ["recip"], "intent");
  assert.equal(result.detected, false);
});

test("detectPingPongPattern: detects alternating 2-sender pattern", () => {
  const envs = [
    mockEnvelope("e1", "loom://a@x", ["loom://b@x"], "message.general@v1"),
    mockEnvelope("e2", "loom://b@x", ["loom://a@x"], "message.general@v1"),
    mockEnvelope("e3", "loom://a@x", ["loom://b@x"], "message.general@v1"),
    mockEnvelope("e4", "loom://b@x", ["loom://a@x"], "message.general@v1")
  ];
  const map = buildMockEnvelopesMap(envs);
  const ids = envs.map((e) => e.id);

  // Current envelope would be from a@x to b@x again — continuing the ping-pong
  const result = detectPingPongPattern(ids, map, "loom://a@x", ["loom://b@x"], "message.general@v1");
  assert.equal(result.detected, true);
  assert.ok(result.senders.includes("loom://a@x"));
  assert.ok(result.senders.includes("loom://b@x"));
  assert.equal(typeof result.conversation_hash, "string");
});

test("detectPingPongPattern: no false positive for varied senders", () => {
  const envs = [
    mockEnvelope("e1", "loom://a@x", ["loom://b@x"], "message.general@v1"),
    mockEnvelope("e2", "loom://c@x", ["loom://d@x"], "message.general@v1"),
    mockEnvelope("e3", "loom://e@x", ["loom://f@x"], "message.general@v1"),
    mockEnvelope("e4", "loom://g@x", ["loom://h@x"], "message.general@v1")
  ];
  const map = buildMockEnvelopesMap(envs);
  const ids = envs.map((e) => e.id);
  const result = detectPingPongPattern(ids, map, "loom://i@x", ["loom://j@x"], "message.general@v1");
  assert.equal(result.detected, false);
});

test("detectPingPongPattern: no false positive for different intents", () => {
  const envs = [
    mockEnvelope("e1", "loom://a@x", ["loom://b@x"], "message.general@v1"),
    mockEnvelope("e2", "loom://b@x", ["loom://a@x"], "task.assign@v1"),
    mockEnvelope("e3", "loom://a@x", ["loom://b@x"], "approval.request@v1"),
    mockEnvelope("e4", "loom://b@x", ["loom://a@x"], "receipt.read@v1")
  ];
  const map = buildMockEnvelopesMap(envs);
  const ids = envs.map((e) => e.id);
  const result = detectPingPongPattern(ids, map, "loom://a@x", ["loom://b@x"], "message.general@v1");
  assert.equal(result.detected, false);
});

// ─── Protocol Layer: assertAgentThreadRateOrThrow ──────────────────────────

test("assertAgentThreadRateOrThrow: passes when under limit", () => {
  const now = Date.now();
  const envs = [
    { id: "e1", from: { identity: "loom://a@x", type: "agent" }, meta: { received_at: new Date(now - 5000).toISOString() } },
    { id: "e2", from: { identity: "loom://a@x", type: "agent" }, meta: { received_at: new Date(now - 3000).toISOString() } }
  ];
  const map = buildMockEnvelopesMap(envs);

  // Should not throw with default limits (50 per 60s)
  assertAgentThreadRateOrThrow(["e1", "e2"], map, "loom://a@x", now);
});

test("assertAgentThreadRateOrThrow: throws when limit exceeded", () => {
  const now = Date.now();
  const envs = [];
  const ids = [];
  for (let i = 0; i < 5; i++) {
    const id = `e${i}`;
    envs.push({
      id,
      from: { identity: "loom://a@x", type: "agent" },
      meta: { received_at: new Date(now - 1000).toISOString() }
    });
    ids.push(id);
  }
  const map = buildMockEnvelopesMap(envs);

  assert.throws(
    () => assertAgentThreadRateOrThrow(ids, map, "loom://a@x", now, { max_agent_envelopes_per_thread_window: 5, agent_window_ms: 60000 }),
    (err) => err?.code === "LOOP_DETECTED"
  );
});

test("assertAgentThreadRateOrThrow: ignores envelopes outside window", () => {
  const now = Date.now();
  const envs = [];
  const ids = [];
  for (let i = 0; i < 10; i++) {
    const id = `e${i}`;
    envs.push({
      id,
      from: { identity: "loom://a@x", type: "agent" },
      meta: { received_at: new Date(now - 120000).toISOString() } // 2 minutes ago, outside 60s window
    });
    ids.push(id);
  }
  const map = buildMockEnvelopesMap(envs);

  // Should not throw — all envelopes are outside the window
  assertAgentThreadRateOrThrow(ids, map, "loom://a@x", now, { max_agent_envelopes_per_thread_window: 5, agent_window_ms: 60000 });
});

test("assertAgentThreadRateOrThrow: only counts envelopes from same sender", () => {
  const now = Date.now();
  const envs = [
    { id: "e1", from: { identity: "loom://a@x", type: "agent" }, meta: { received_at: new Date(now - 1000).toISOString() } },
    { id: "e2", from: { identity: "loom://b@x", type: "agent" }, meta: { received_at: new Date(now - 1000).toISOString() } },
    { id: "e3", from: { identity: "loom://a@x", type: "agent" }, meta: { received_at: new Date(now - 1000).toISOString() } },
    { id: "e4", from: { identity: "loom://b@x", type: "agent" }, meta: { received_at: new Date(now - 1000).toISOString() } }
  ];
  const map = buildMockEnvelopesMap(envs);

  // Only 2 from a@x, limit is 3 — should pass
  assertAgentThreadRateOrThrow(["e1", "e2", "e3", "e4"], map, "loom://a@x", now, { max_agent_envelopes_per_thread_window: 3, agent_window_ms: 60000 });
});

// ─── Ingestion Layer: hop_count ─────────────────────────────────────────────

test("ingestion: agent envelope with hop_count=0 stores hop_count=1", () => {
  const { store, agentKeys, delegation } = setupStore();
  const threadId = thrId();

  // First, create the thread with a human message
  const humanEnv = signHumanEnvelope(setupStore().aliceKeys, {
    thread_id: threadId,
    from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" }
  });
  // We need to use the same store's alice keys
  const { store: s2, aliceKeys: ak2 } = setupStore();
  // Let's just use the original store directly
  const initEnv = signEnvelope(
    makeEnvelope({
      thread_id: threadId,
      from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" }
    }),
    setupStore().aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );
  // This won't work because the signing keys don't match. Let me use the proper store.

  // Use a fresh, clean setup
  const setup = setupStore();
  const tid = thrId();

  // Create thread with human envelope
  const humanMsg = signEnvelope(
    makeEnvelope({
      thread_id: tid,
      from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" },
      to: [{ identity: "loom://assistant.alice@node.test", role: "primary" }]
    }),
    setup.aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );
  setup.store.ingestEnvelope(humanMsg);

  // Agent sends with hop_count=0
  const agentEnv = signEnvelope(
    makeEnvelope({
      thread_id: tid,
      parent_id: humanMsg.id,
      hop_count: 0,
      from: {
        identity: "loom://assistant.alice@node.test",
        display: "Assistant",
        key_id: "k_sign_agent_1",
        type: "agent",
        delegation_chain: [setup.delegation]
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }]
    }),
    setup.agentKeys.privateKeyPem,
    "k_sign_agent_1"
  );
  const stored = setup.store.ingestEnvelope(agentEnv);
  assert.equal(stored.meta.loop_detection.hop_count, 1);
});

test("ingestion: agent envelope with hop_count >= max_hop_count is rejected", () => {
  const setup = setupStore({ loopMaxHopCount: 5 });
  const tid = thrId();

  // Create thread
  const humanMsg = signEnvelope(
    makeEnvelope({
      thread_id: tid,
      from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" },
      to: [{ identity: "loom://assistant.alice@node.test", role: "primary" }]
    }),
    setup.aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );
  setup.store.ingestEnvelope(humanMsg);

  // Agent sends with hop_count at the limit
  const agentEnv = signEnvelope(
    makeEnvelope({
      thread_id: tid,
      parent_id: humanMsg.id,
      hop_count: 5,
      from: {
        identity: "loom://assistant.alice@node.test",
        display: "Assistant",
        key_id: "k_sign_agent_1",
        type: "agent",
        delegation_chain: [setup.delegation]
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }]
    }),
    setup.agentKeys.privateKeyPem,
    "k_sign_agent_1"
  );

  assert.throws(
    () => setup.store.ingestEnvelope(agentEnv),
    (err) => err?.code === "LOOP_DETECTED"
  );
});

test("ingestion: human envelope with high hop_count is accepted and not auto-incremented", () => {
  const setup = setupStore({ loopMaxHopCount: 20 });
  const tid = thrId();

  const humanMsg = signEnvelope(
    makeEnvelope({
      thread_id: tid,
      hop_count: 15,
      from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" },
      to: [{ identity: "loom://bob@node.test", role: "primary" }]
    }),
    setup.aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );
  const stored = setup.store.ingestEnvelope(humanMsg);
  // Human senders: hop_count preserved as-is (not incremented)
  assert.equal(stored.meta.loop_detection.hop_count, 15);
});

test("ingestion: envelope without hop_count is accepted (backward compat)", () => {
  const setup = setupStore();
  const env = signEnvelope(
    makeEnvelope({
      from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" },
      to: [{ identity: "loom://bob@node.test", role: "primary" }]
    }),
    setup.aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );
  const stored = setup.store.ingestEnvelope(env);
  assert.equal(stored.meta.loop_detection.hop_count, 0);
  assert.ok(stored.meta.loop_detection);
});

// ─── Ingestion Layer: Agent Rate Limiting ───────────────────────────────────

test("ingestion: agent rate limit triggers LOOP_DETECTED after N envelopes in window", () => {
  const setup = setupStore({ loopAgentWindowMax: 3, loopAgentWindowMs: 60000 });
  const tid = thrId();

  // Create thread with human message
  const humanMsg = signEnvelope(
    makeEnvelope({
      thread_id: tid,
      from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" },
      to: [{ identity: "loom://assistant.alice@node.test", role: "primary" }]
    }),
    setup.aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );
  setup.store.ingestEnvelope(humanMsg);

  // Send 3 agent envelopes (should succeed)
  let lastId = humanMsg.id;
  for (let i = 0; i < 3; i++) {
    const agentEnv = signEnvelope(
      makeEnvelope({
        thread_id: tid,
        parent_id: lastId,
        from: {
          identity: "loom://assistant.alice@node.test",
          display: "Assistant",
          key_id: "k_sign_agent_1",
          type: "agent",
          delegation_chain: [setup.delegation]
        },
        to: [{ identity: "loom://alice@node.test", role: "primary" }]
      }),
      setup.agentKeys.privateKeyPem,
      "k_sign_agent_1"
    );
    const stored = setup.store.ingestEnvelope(agentEnv);
    lastId = stored.id;
  }

  // 4th agent envelope should be rejected
  const rejected = signEnvelope(
    makeEnvelope({
      thread_id: tid,
      parent_id: lastId,
      from: {
        identity: "loom://assistant.alice@node.test",
        display: "Assistant",
        key_id: "k_sign_agent_1",
        type: "agent",
        delegation_chain: [setup.delegation]
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }]
    }),
    setup.agentKeys.privateKeyPem,
    "k_sign_agent_1"
  );

  assert.throws(
    () => setup.store.ingestEnvelope(rejected),
    (err) => err?.code === "LOOP_DETECTED"
  );
});

// ─── Ingestion Layer: Ping-Pong Detection & Escalation ──────────────────────

test("ingestion: ping-pong detection sets requires_human_escalation on thread", () => {
  const aliceKeys = generateSigningKeyPair();
  const agentAKeys = generateSigningKeyPair();
  const agentBKeys = generateSigningKeyPair();

  const store = new LoomStore({ nodeId: "node.test" });

  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    type: "human",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: aliceKeys.publicKeyPem }]
  });

  store.registerIdentity({
    id: "loom://agent-a.alice@node.test",
    display_name: "Agent A",
    type: "agent",
    signing_keys: [{ key_id: "k_sign_agent_a_1", public_key_pem: agentAKeys.publicKeyPem }]
  });

  store.registerIdentity({
    id: "loom://agent-b.alice@node.test",
    display_name: "Agent B",
    type: "agent",
    signing_keys: [{ key_id: "k_sign_agent_b_1", public_key_pem: agentBKeys.publicKeyPem }]
  });

  const delAUnsigned = {
    id: `dlg_${generateUlid()}`,
    delegator: "loom://alice@node.test",
    delegate: "loom://agent-a.alice@node.test",
    scope: ["message.general@v1"],
    created_at: new Date(Date.now() - 60000).toISOString(),
    expires_at: new Date(Date.now() + 86400000).toISOString(),
    revocable: true,
    allow_sub_delegation: false,
    max_sub_delegation_depth: 0,
    key_id: "k_sign_alice_1"
  };
  const delA = {
    ...delAUnsigned,
    signature: signUtf8Message(aliceKeys.privateKeyPem, canonicalizeDelegationLink(delAUnsigned))
  };

  const delBUnsigned = {
    id: `dlg_${generateUlid()}`,
    delegator: "loom://alice@node.test",
    delegate: "loom://agent-b.alice@node.test",
    scope: ["message.general@v1"],
    created_at: new Date(Date.now() - 60000).toISOString(),
    expires_at: new Date(Date.now() + 86400000).toISOString(),
    revocable: true,
    allow_sub_delegation: false,
    max_sub_delegation_depth: 0,
    key_id: "k_sign_alice_1"
  };
  const delB = {
    ...delBUnsigned,
    signature: signUtf8Message(aliceKeys.privateKeyPem, canonicalizeDelegationLink(delBUnsigned))
  };

  const tid = thrId();

  // Create thread with human message, adding both agents as participants
  const humanMsg = signEnvelope(
    makeEnvelope({
      thread_id: tid,
      from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" },
      to: [
        { identity: "loom://agent-a.alice@node.test", role: "primary" },
        { identity: "loom://agent-b.alice@node.test", role: "cc" }
      ]
    }),
    aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );
  store.ingestEnvelope(humanMsg);

  // Agent A ↔ Agent B ping-pong — send messages until escalation is detected
  let lastId = humanMsg.id;
  let escalationDetected = false;

  for (let i = 0; i < 5 && !escalationDetected; i++) {
    // Agent A → Agent B
    const envA = signEnvelope(
      makeEnvelope({
        thread_id: tid,
        parent_id: lastId,
        from: {
          identity: "loom://agent-a.alice@node.test",
          display: "Agent A",
          key_id: "k_sign_agent_a_1",
          type: "agent",
          delegation_chain: [delA]
        },
        to: [{ identity: "loom://agent-b.alice@node.test", role: "primary" }]
      }),
      agentAKeys.privateKeyPem,
      "k_sign_agent_a_1"
    );
    try {
      const storedA = store.ingestEnvelope(envA);
      lastId = storedA.id;
    } catch (err) {
      if (err.code === "HUMAN_ESCALATION_REQUIRED") {
        escalationDetected = true;
        break;
      }
      throw err;
    }

    // Agent B → Agent A
    const envB = signEnvelope(
      makeEnvelope({
        thread_id: tid,
        parent_id: lastId,
        from: {
          identity: "loom://agent-b.alice@node.test",
          display: "Agent B",
          key_id: "k_sign_agent_b_1",
          type: "agent",
          delegation_chain: [delB]
        },
        to: [{ identity: "loom://agent-a.alice@node.test", role: "primary" }]
      }),
      agentBKeys.privateKeyPem,
      "k_sign_agent_b_1"
    );
    try {
      const storedB = store.ingestEnvelope(envB);
      lastId = storedB.id;
    } catch (err) {
      if (err.code === "HUMAN_ESCALATION_REQUIRED") {
        escalationDetected = true;
        break;
      }
      throw err;
    }
  }

  // Thread should have requires_human_escalation set (either via detection or the rejection confirms it)
  const thread = store.threadsById.get(tid);
  assert.equal(thread.requires_human_escalation, true);

  // Thread should have sys.escalation label
  assert.ok(thread.labels.some((l) => (typeof l === "string" ? l : l.name) === "sys.escalation"));
});

test("ingestion: agent rejected when thread.requires_human_escalation is true", () => {
  const setup = setupStore();
  const tid = thrId();

  // Create thread
  const humanMsg = signEnvelope(
    makeEnvelope({
      thread_id: tid,
      from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" },
      to: [{ identity: "loom://assistant.alice@node.test", role: "primary" }]
    }),
    setup.aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );
  setup.store.ingestEnvelope(humanMsg);

  // Manually set requires_human_escalation
  const thread = setup.store.threadsById.get(tid);
  thread.requires_human_escalation = true;

  // Agent should be rejected
  const agentEnv = signEnvelope(
    makeEnvelope({
      thread_id: tid,
      parent_id: humanMsg.id,
      from: {
        identity: "loom://assistant.alice@node.test",
        display: "Assistant",
        key_id: "k_sign_agent_1",
        type: "agent",
        delegation_chain: [setup.delegation]
      },
      to: [{ identity: "loom://alice@node.test", role: "primary" }]
    }),
    setup.agentKeys.privateKeyPem,
    "k_sign_agent_1"
  );

  assert.throws(
    () => setup.store.ingestEnvelope(agentEnv),
    (err) => err?.code === "HUMAN_ESCALATION_REQUIRED"
  );
});

test("ingestion: human envelope on escalated thread clears the flag", () => {
  const setup = setupStore();
  const tid = thrId();

  // Create thread
  const humanMsg1 = signEnvelope(
    makeEnvelope({
      thread_id: tid,
      from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" },
      to: [{ identity: "loom://bob@node.test", role: "primary" }]
    }),
    setup.aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );
  setup.store.ingestEnvelope(humanMsg1);

  // Set escalation
  const thread = setup.store.threadsById.get(tid);
  thread.requires_human_escalation = true;

  // Human sends another message — should clear the flag
  const humanMsg2 = signEnvelope(
    makeEnvelope({
      thread_id: tid,
      parent_id: humanMsg1.id,
      from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" },
      to: [{ identity: "loom://bob@node.test", role: "primary" }]
    }),
    setup.aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );
  setup.store.ingestEnvelope(humanMsg2);

  assert.equal(thread.requires_human_escalation, false);
});

// ─── Ingestion Layer: conversation_hash in meta ────────────────────────────

test("ingestion: stored envelope contains loop_detection meta", () => {
  const setup = setupStore();
  const env = signEnvelope(
    makeEnvelope({
      from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" },
      to: [{ identity: "loom://bob@node.test", role: "primary" }]
    }),
    setup.aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );
  const stored = setup.store.ingestEnvelope(env);

  assert.ok(stored.meta.loop_detection);
  assert.equal(typeof stored.meta.loop_detection.conversation_hash, "string");
  assert.equal(stored.meta.loop_detection.conversation_hash.length, 64);
  assert.equal(typeof stored.meta.loop_detection.hop_count, "number");
  assert.equal(stored.meta.loop_detection.escalation_triggered, false);
});

// ─── Store config defaults ──────────────────────────────────────────────────

test("store: loopProtection config has correct defaults", () => {
  const store = new LoomStore({ nodeId: "node.test" });
  assert.equal(store.loopProtection.max_hop_count, 20);
  assert.equal(store.loopProtection.max_agent_envelopes_per_thread_window, 50);
  assert.equal(store.loopProtection.agent_window_ms, 60000);
});

test("store: loopProtection config accepts overrides", () => {
  const store = new LoomStore({
    nodeId: "node.test",
    loopMaxHopCount: 10,
    loopAgentWindowMax: 25,
    loopAgentWindowMs: 30000
  });
  assert.equal(store.loopProtection.max_hop_count, 10);
  assert.equal(store.loopProtection.max_agent_envelopes_per_thread_window, 25);
  assert.equal(store.loopProtection.agent_window_ms, 30000);
});

// ─── Envelope validation layer ──────────────────────────────────────────────

test("envelope validation: rejects hop_count = -1", () => {
  const setup = setupStore();
  const env = signEnvelope(
    makeEnvelope({
      hop_count: -1,
      from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" },
      to: [{ identity: "loom://bob@node.test", role: "primary" }]
    }),
    setup.aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );

  assert.throws(
    () => setup.store.ingestEnvelope(env),
    (err) => err?.code === "ENVELOPE_INVALID"
  );
});

test("envelope validation: rejects hop_count = 256", () => {
  const setup = setupStore();
  const env = signEnvelope(
    makeEnvelope({
      hop_count: 256,
      from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_1", type: "human" },
      to: [{ identity: "loom://bob@node.test", role: "primary" }]
    }),
    setup.aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );

  assert.throws(
    () => setup.store.ingestEnvelope(env),
    (err) => err?.code === "ENVELOPE_INVALID"
  );
});
