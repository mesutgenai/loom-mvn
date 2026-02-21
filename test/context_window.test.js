import test from "node:test";
import assert from "node:assert/strict";
import { generateSigningKeyPair, signEnvelope } from "../src/protocol/crypto.js";
import { generateUlid } from "../src/protocol/ulid.js";
import { LoomStore } from "../src/node/store.js";
import { createMcpToolRegistry, handleMcpRequest } from "../src/node/mcp_server.js";
import {
  validateContextVector,
  validateContextWindowBudget,
  validateSnapshotParameters,
  CONTEXT_VECTOR_MIN_DIMENSIONS,
  CONTEXT_VECTOR_MAX_DIMENSIONS,
  TOKEN_LIMIT_MIN,
  TOKEN_LIMIT_MAX
} from "../src/protocol/context_window.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function envId() {
  return `env_${generateUlid()}`;
}

function thrId() {
  return `thr_${generateUlid()}`;
}

function setupStore() {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });

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

  return { store, aliceKeys, bobKeys };
}

function signBase(privateKeyPem, keyId, overrides = {}) {
  const env = {
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
  return signEnvelope(env, privateKeyPem, keyId);
}

function ingestRoot(store, aliceKeys, threadId) {
  const root = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  store.ingestEnvelope(root, { actorIdentity: "loom://alice@node.test" });
  return root;
}

function ingestReply(store, aliceKeys, threadId, parentId) {
  const reply = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: parentId,
    created_at: new Date().toISOString()
  });
  store.ingestEnvelope(reply, { actorIdentity: "loom://alice@node.test" });
  return reply;
}

function makeThreadOp(intent, parameters, overrides = {}) {
  return {
    loom: "1.1",
    id: envId(),
    thread_id: "placeholder",
    parent_id: "placeholder",
    type: "thread_op",
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
      structured: { intent, parameters },
      encrypted: false
    },
    attachments: [],
    ...overrides
  };
}

// ─── Protocol Layer: validateContextVector ───────────────────────────────────

test("validateContextVector: accepts valid 128-element array", () => {
  const vec = new Array(128).fill(0.5);
  assert.deepEqual(validateContextVector(vec), []);
});

test("validateContextVector: accepts minimum-size array", () => {
  const vec = new Array(CONTEXT_VECTOR_MIN_DIMENSIONS).fill(0);
  assert.deepEqual(validateContextVector(vec), []);
});

test("validateContextVector: accepts maximum-size array", () => {
  const vec = new Array(CONTEXT_VECTOR_MAX_DIMENSIONS).fill(0);
  assert.deepEqual(validateContextVector(vec), []);
});

test("validateContextVector: rejects non-array", () => {
  const errors = validateContextVector("not-an-array");
  assert.ok(errors.length > 0);
  assert.ok(errors[0].reason.includes("array"));
});

test("validateContextVector: rejects array with too few dimensions", () => {
  const vec = [1, 2, 3];
  const errors = validateContextVector(vec);
  assert.ok(errors.length > 0);
  assert.ok(errors[0].reason.includes("at least"));
});

test("validateContextVector: rejects array exceeding max dimensions", () => {
  const vec = new Array(CONTEXT_VECTOR_MAX_DIMENSIONS + 1).fill(0);
  const errors = validateContextVector(vec);
  assert.ok(errors.length > 0);
  assert.ok(errors[0].reason.includes("exceed"));
});

test("validateContextVector: rejects NaN elements", () => {
  const vec = new Array(16).fill(0);
  vec[5] = NaN;
  const errors = validateContextVector(vec);
  assert.ok(errors.length > 0);
  assert.ok(errors[0].reason.includes("finite"));
});

test("validateContextVector: rejects Infinity elements", () => {
  const vec = new Array(16).fill(0);
  vec[0] = Infinity;
  const errors = validateContextVector(vec);
  assert.ok(errors.length > 0);
  assert.ok(errors[0].reason.includes("finite"));
});

test("validateContextVector: rejects string elements", () => {
  const vec = new Array(16).fill(0);
  vec[3] = "oops";
  const errors = validateContextVector(vec);
  assert.ok(errors.length > 0);
  assert.ok(errors[0].reason.includes("finite"));
});

// ─── Protocol Layer: validateContextWindowBudget ─────────────────────────────

test("validateContextWindowBudget: accepts valid budget", () => {
  assert.deepEqual(validateContextWindowBudget({ token_limit: 4096 }), []);
});

test("validateContextWindowBudget: accepts minimum token_limit", () => {
  assert.deepEqual(validateContextWindowBudget({ token_limit: TOKEN_LIMIT_MIN }), []);
});

test("validateContextWindowBudget: accepts maximum token_limit", () => {
  assert.deepEqual(validateContextWindowBudget({ token_limit: TOKEN_LIMIT_MAX }), []);
});

test("validateContextWindowBudget: rejects non-object", () => {
  const errors = validateContextWindowBudget("string");
  assert.ok(errors.length > 0);
  assert.ok(errors[0].reason.includes("object"));
});

test("validateContextWindowBudget: rejects null", () => {
  const errors = validateContextWindowBudget(null);
  assert.ok(errors.length > 0);
});

test("validateContextWindowBudget: rejects non-integer token_limit", () => {
  const errors = validateContextWindowBudget({ token_limit: 1.5 });
  assert.ok(errors.length > 0);
  assert.ok(errors[0].reason.includes("integer"));
});

test("validateContextWindowBudget: rejects token_limit below minimum", () => {
  const errors = validateContextWindowBudget({ token_limit: 0 });
  assert.ok(errors.length > 0);
});

test("validateContextWindowBudget: rejects token_limit above maximum", () => {
  const errors = validateContextWindowBudget({ token_limit: TOKEN_LIMIT_MAX + 1 });
  assert.ok(errors.length > 0);
});

test("validateContextWindowBudget: rejects missing token_limit", () => {
  const errors = validateContextWindowBudget({});
  assert.ok(errors.length > 0);
});

// ─── Protocol Layer: validateSnapshotParameters ──────────────────────────────

test("validateSnapshotParameters: accepts valid parameters", () => {
  const errors = validateSnapshotParameters({
    cutoff_envelope_id: "env_01ARZ3NDEKTSV4RRFFQ69G5FE0",
    summary_text: "Thread summary so far"
  });
  assert.deepEqual(errors, []);
});

test("validateSnapshotParameters: rejects missing cutoff_envelope_id", () => {
  const errors = validateSnapshotParameters({
    summary_text: "text"
  });
  assert.ok(errors.some((e) => e.field.includes("cutoff_envelope_id")));
});

test("validateSnapshotParameters: rejects invalid cutoff_envelope_id prefix", () => {
  const errors = validateSnapshotParameters({
    cutoff_envelope_id: "thr_wrong_prefix",
    summary_text: "text"
  });
  assert.ok(errors.some((e) => e.field.includes("cutoff_envelope_id")));
});

test("validateSnapshotParameters: rejects missing summary_text", () => {
  const errors = validateSnapshotParameters({
    cutoff_envelope_id: "env_01ARZ3NDEKTSV4RRFFQ69G5FE0"
  });
  assert.ok(errors.some((e) => e.field.includes("summary_text")));
});

test("validateSnapshotParameters: rejects empty summary_text", () => {
  const errors = validateSnapshotParameters({
    cutoff_envelope_id: "env_01ARZ3NDEKTSV4RRFFQ69G5FE0",
    summary_text: "   "
  });
  assert.ok(errors.some((e) => e.field.includes("summary_text")));
});

test("validateSnapshotParameters: rejects non-object", () => {
  const errors = validateSnapshotParameters(null);
  assert.ok(errors.length > 0);
});

// ─── Envelope Validation: context_vector ─────────────────────────────────────

test("envelope with valid meta.context_vector passes ingestion", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const vec = new Array(64).fill(0.1);

  const env = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    meta: { context_vector: vec }
  });
  store.ingestEnvelope(env, { actorIdentity: "loom://alice@node.test" });

  const stored = store.getEnvelope(env.id);
  assert.ok(stored);
  assert.ok(Array.isArray(stored.meta.context_vector));
  assert.equal(stored.meta.context_vector.length, 64);
});

test("envelope without meta.context_vector passes (backward compat)", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  const env = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", { thread_id: threadId });
  store.ingestEnvelope(env, { actorIdentity: "loom://alice@node.test" });

  const stored = store.getEnvelope(env.id);
  assert.ok(stored);
});

test("envelope with invalid meta.context_vector is rejected", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  const env = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    meta: { context_vector: [1, 2] }
  });

  assert.throws(
    () => store.ingestEnvelope(env, { actorIdentity: "loom://alice@node.test" }),
    (error) => error?.code === "ENVELOPE_INVALID"
  );
});

// ─── workflow.thread_summary@v1 ──────────────────────────────────────────────

test("workflow envelope with workflow.thread_summary@v1 intent ingests normally", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  const root = ingestRoot(store, aliceKeys, threadId);

  const summaryEnv = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "workflow",
    content: {
      human: { text: "Summary of conversation so far", format: "markdown" },
      structured: {
        intent: "workflow.thread_summary@v1",
        parameters: {
          covers_up_to_envelope_id: root.id,
          token_count: 1500
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(summaryEnv, { actorIdentity: "loom://alice@node.test" });

  const stored = store.getEnvelope(summaryEnv.id);
  assert.ok(stored);
  assert.equal(stored.type, "workflow");
  assert.equal(stored.content.structured.intent, "workflow.thread_summary@v1");
  assert.equal(stored.content.structured.parameters.covers_up_to_envelope_id, root.id);
  assert.equal(stored.content.structured.parameters.token_count, 1500);
});

test("workflow.thread_summary@v1 preserves summary content in stored envelope", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  const root = ingestRoot(store, aliceKeys, threadId);

  const summaryEnv = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "workflow",
    content: {
      human: { text: "Alice asked about project deadlines. Bob replied with Q3 targets.", format: "markdown" },
      structured: {
        intent: "workflow.thread_summary@v1",
        parameters: {
          covers_up_to_envelope_id: root.id,
          token_count: 250
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(summaryEnv, { actorIdentity: "loom://alice@node.test" });

  const stored = store.getEnvelope(summaryEnv.id);
  assert.ok(stored.content.human.text.includes("project deadlines"));
});

// ─── thread.snapshot@v1 ──────────────────────────────────────────────────────

test("thread.snapshot@v1 sets thread.snapshot with correct cutoff_index", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  const root = ingestRoot(store, aliceKeys, threadId);
  const reply1 = ingestReply(store, aliceKeys, threadId, root.id);
  const reply2 = ingestReply(store, aliceKeys, threadId, reply1.id);

  // Alice is the thread owner — she has implicit admin
  const snapshotOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: reply2.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.snapshot@v1",
        parameters: {
          cutoff_envelope_id: reply1.id,
          summary_text: "Discussion about project goals"
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(snapshotOp, { actorIdentity: "loom://alice@node.test" });

  const thread = store.getThread(threadId);
  assert.ok(thread.snapshot);
  assert.equal(thread.snapshot.envelope_id, snapshotOp.id);
  assert.equal(thread.snapshot.cutoff_envelope_id, reply1.id);
  assert.equal(typeof thread.snapshot.cutoff_index, "number");
  assert.equal(thread.snapshot.summary_text, "Discussion about project goals");
  assert.ok(thread.snapshot.created_at);
});

test("thread.snapshot@v1 appears in toThreadSummary output", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  const root = ingestRoot(store, aliceKeys, threadId);

  const snapshotOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.snapshot@v1",
        parameters: {
          cutoff_envelope_id: root.id,
          summary_text: "Initial message"
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(snapshotOp, { actorIdentity: "loom://alice@node.test" });

  const threads = store.listThreadsForIdentity("loom://alice@node.test");
  const threadSummary = threads.find((t) => t.id === threadId);
  assert.ok(threadSummary.snapshot);
  assert.equal(threadSummary.snapshot.summary_text, "Initial message");
});

test("thread.snapshot@v1 rejects missing cutoff_envelope_id", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);

  const snapshotOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.snapshot@v1",
        parameters: {
          summary_text: "Summary"
        }
      },
      encrypted: false
    }
  });

  assert.throws(
    () => store.ingestEnvelope(snapshotOp, { actorIdentity: "loom://alice@node.test" }),
    (error) => error?.code === "ENVELOPE_INVALID"
  );
});

test("thread.snapshot@v1 rejects nonexistent cutoff envelope", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);

  const snapshotOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.snapshot@v1",
        parameters: {
          cutoff_envelope_id: "env_nonexistent00000000000",
          summary_text: "Summary"
        }
      },
      encrypted: false
    }
  });

  assert.throws(
    () => store.ingestEnvelope(snapshotOp, { actorIdentity: "loom://alice@node.test" }),
    (error) => error?.code === "ENVELOPE_INVALID"
  );
});

test("thread.snapshot@v1 rejects missing summary_text", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);

  const snapshotOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.snapshot@v1",
        parameters: {
          cutoff_envelope_id: root.id
        }
      },
      encrypted: false
    }
  });

  assert.throws(
    () => store.ingestEnvelope(snapshotOp, { actorIdentity: "loom://alice@node.test" }),
    (error) => error?.code === "ENVELOPE_INVALID"
  );
});

test("thread.snapshot@v1 rejects snapshot on archived thread", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);

  // Resolve then archive the thread
  const resolveOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: { intent: "thread.resolve@v1", parameters: {} },
      encrypted: false
    }
  });
  store.ingestEnvelope(resolveOp, { actorIdentity: "loom://alice@node.test" });

  const archiveOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: resolveOp.id,
    type: "thread_op",
    content: {
      structured: { intent: "thread.archive@v1", parameters: {} },
      encrypted: false
    }
  });
  store.ingestEnvelope(archiveOp, { actorIdentity: "loom://alice@node.test" });

  const snapshotOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: archiveOp.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.snapshot@v1",
        parameters: {
          cutoff_envelope_id: root.id,
          summary_text: "Summary"
        }
      },
      encrypted: false
    }
  });

  assert.throws(
    () => store.ingestEnvelope(snapshotOp, { actorIdentity: "loom://alice@node.test" }),
    (error) => error?.code === "STATE_TRANSITION_INVALID"
  );
});

test("thread.snapshot@v1 second snapshot overwrites the first", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);
  const reply1 = ingestReply(store, aliceKeys, threadId, root.id);
  const reply2 = ingestReply(store, aliceKeys, threadId, reply1.id);

  const snapshot1 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: reply1.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.snapshot@v1",
        parameters: {
          cutoff_envelope_id: root.id,
          summary_text: "First snapshot"
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(snapshot1, { actorIdentity: "loom://alice@node.test" });

  const snapshot2 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: reply2.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.snapshot@v1",
        parameters: {
          cutoff_envelope_id: reply1.id,
          summary_text: "Second snapshot"
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(snapshot2, { actorIdentity: "loom://alice@node.test" });

  const thread = store.getThread(threadId);
  assert.equal(thread.snapshot.summary_text, "Second snapshot");
  assert.equal(thread.snapshot.cutoff_envelope_id, reply1.id);
  assert.equal(thread.snapshot.envelope_id, snapshot2.id);
});

test("thread.snapshot@v1 requires admin capability for non-owner", () => {
  const { store, aliceKeys, bobKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);

  // Bob tries to snapshot without a capability
  const snapshotOp = signBase(bobKeys.privateKeyPem, "k_sign_bob_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "thread_op",
    from: {
      identity: "loom://bob@node.test",
      display: "Bob",
      key_id: "k_sign_bob_1",
      type: "human"
    },
    content: {
      structured: {
        intent: "thread.snapshot@v1",
        parameters: {
          cutoff_envelope_id: root.id,
          summary_text: "Bob's summary"
        }
      },
      encrypted: false
    }
  });

  assert.throws(
    () => store.ingestEnvelope(snapshotOp, { actorIdentity: "loom://bob@node.test" }),
    (error) => error?.code === "CAPABILITY_DENIED"
  );
});

// ─── Snapshot-Aware Read ─────────────────────────────────────────────────────

test("getThreadEnvelopesForIdentity without after_snapshot returns all envelopes", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);
  const reply1 = ingestReply(store, aliceKeys, threadId, root.id);
  const reply2 = ingestReply(store, aliceKeys, threadId, reply1.id);

  const snapshotOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: reply2.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.snapshot@v1",
        parameters: {
          cutoff_envelope_id: reply1.id,
          summary_text: "Snapshot summary"
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(snapshotOp, { actorIdentity: "loom://alice@node.test" });

  const allEnvelopes = store.getThreadEnvelopesForIdentity(threadId, "loom://alice@node.test");
  // root + reply1 + reply2 + snapshotOp = 4
  assert.equal(allEnvelopes.length, 4);
});

test("getThreadEnvelopesForIdentity with after_snapshot returns only post-cutoff + snapshot", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);
  const reply1 = ingestReply(store, aliceKeys, threadId, root.id);
  const reply2 = ingestReply(store, aliceKeys, threadId, reply1.id);

  const snapshotOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: reply2.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.snapshot@v1",
        parameters: {
          cutoff_envelope_id: reply1.id,
          summary_text: "Snapshot summary"
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(snapshotOp, { actorIdentity: "loom://alice@node.test" });

  const filtered = store.getThreadEnvelopesForIdentity(threadId, "loom://alice@node.test", {
    after_snapshot: true
  });
  // Should include: snapshotOp (the snapshot envelope) + reply2 (post-cutoff)
  // root and reply1 should be excluded (at or before cutoff)
  assert.ok(filtered.length >= 2);
  const ids = filtered.map((e) => e.envelope.id);
  assert.ok(ids.includes(snapshotOp.id), "should include the snapshot envelope");
  assert.ok(ids.includes(reply2.id), "should include post-cutoff envelope");
  assert.ok(!ids.includes(root.id), "should exclude pre-cutoff root");
});

test("after_snapshot with no snapshot returns all envelopes", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);
  ingestReply(store, aliceKeys, threadId, root.id);

  const all = store.getThreadEnvelopesForIdentity(threadId, "loom://alice@node.test");
  const filtered = store.getThreadEnvelopesForIdentity(threadId, "loom://alice@node.test", {
    after_snapshot: true
  });
  assert.equal(all.length, filtered.length);
});

// ─── thread.context_budget@v1 ────────────────────────────────────────────────

test("thread.context_budget@v1 sets thread.context_budgets for participant", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);

  const budgetOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.context_budget@v1",
        parameters: {
          identity: "loom://bob@node.test",
          context_window_budget: { token_limit: 8192 }
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(budgetOp, { actorIdentity: "loom://alice@node.test" });

  const thread = store.getThread(threadId);
  assert.ok(thread.context_budgets);
  assert.ok(thread.context_budgets["loom://bob@node.test"]);
  assert.equal(thread.context_budgets["loom://bob@node.test"].token_limit, 8192);
  assert.ok(thread.context_budgets["loom://bob@node.test"].updated_at);
});

test("thread.context_budget@v1 appears in toThreadSummary output", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);

  const budgetOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.context_budget@v1",
        parameters: {
          identity: "loom://bob@node.test",
          context_window_budget: { token_limit: 4096 }
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(budgetOp, { actorIdentity: "loom://alice@node.test" });

  const threads = store.listThreadsForIdentity("loom://alice@node.test");
  const threadSummary = threads.find((t) => t.id === threadId);
  assert.ok(threadSummary.context_budgets);
  assert.equal(threadSummary.context_budgets["loom://bob@node.test"].token_limit, 4096);
});

test("thread.context_budget@v1 rejects non-participant identity", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);

  const budgetOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.context_budget@v1",
        parameters: {
          identity: "loom://charlie@node.test",
          context_window_budget: { token_limit: 4096 }
        }
      },
      encrypted: false
    }
  });

  assert.throws(
    () => store.ingestEnvelope(budgetOp, { actorIdentity: "loom://alice@node.test" }),
    (error) => error?.code === "ENVELOPE_INVALID"
  );
});

test("thread.context_budget@v1 rejects invalid token_limit", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);

  const budgetOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.context_budget@v1",
        parameters: {
          identity: "loom://bob@node.test",
          context_window_budget: { token_limit: -5 }
        }
      },
      encrypted: false
    }
  });

  assert.throws(
    () => store.ingestEnvelope(budgetOp, { actorIdentity: "loom://alice@node.test" }),
    (error) => error?.code === "ENVELOPE_INVALID"
  );
});

test("thread.context_budget@v1 requires admin capability for non-owner", () => {
  const { store, aliceKeys, bobKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);

  const budgetOp = signBase(bobKeys.privateKeyPem, "k_sign_bob_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "thread_op",
    from: {
      identity: "loom://bob@node.test",
      display: "Bob",
      key_id: "k_sign_bob_1",
      type: "human"
    },
    content: {
      structured: {
        intent: "thread.context_budget@v1",
        parameters: {
          identity: "loom://bob@node.test",
          context_window_budget: { token_limit: 4096 }
        }
      },
      encrypted: false
    }
  });

  assert.throws(
    () => store.ingestEnvelope(budgetOp, { actorIdentity: "loom://bob@node.test" }),
    (error) => error?.code === "CAPABILITY_DENIED"
  );
});

test("thread.context_budget@v1 updates existing budget", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);

  const budget1 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: root.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.context_budget@v1",
        parameters: {
          identity: "loom://bob@node.test",
          context_window_budget: { token_limit: 4096 }
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(budget1, { actorIdentity: "loom://alice@node.test" });

  const budget2 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: budget1.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.context_budget@v1",
        parameters: {
          identity: "loom://bob@node.test",
          context_window_budget: { token_limit: 16384 }
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(budget2, { actorIdentity: "loom://alice@node.test" });

  const thread = store.getThread(threadId);
  assert.equal(thread.context_budgets["loom://bob@node.test"].token_limit, 16384);
});

// ─── MCP Integration ─────────────────────────────────────────────────────────

test("mcp: loom_read_thread with after_snapshot returns filtered results", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);
  const reply1 = ingestReply(store, aliceKeys, threadId, root.id);
  const reply2 = ingestReply(store, aliceKeys, threadId, reply1.id);

  const snapshotOp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_1", {
    thread_id: threadId,
    parent_id: reply2.id,
    type: "thread_op",
    content: {
      structured: {
        intent: "thread.snapshot@v1",
        parameters: {
          cutoff_envelope_id: reply1.id,
          summary_text: "Thread summary"
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(snapshotOp, { actorIdentity: "loom://alice@node.test" });

  const registry = createMcpToolRegistry(store);
  const context = { actorIdentity: "loom://alice@node.test" };

  // Without after_snapshot — should return all
  const allResponse = handleMcpRequest(
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "loom_read_thread", arguments: { thread_id: threadId } } },
    registry,
    context
  );
  const allParsed = JSON.parse(allResponse.result.content[0].text);
  assert.equal(allParsed.envelopes.length, 4);

  // With after_snapshot — should return only post-cutoff + snapshot
  const filteredResponse = handleMcpRequest(
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "loom_read_thread", arguments: { thread_id: threadId, after_snapshot: true } } },
    registry,
    context
  );
  const filteredParsed = JSON.parse(filteredResponse.result.content[0].text);
  assert.ok(filteredParsed.envelopes.length < 4, "should return fewer envelopes after snapshot");
  assert.ok(filteredParsed.envelopes.length >= 2, "should include snapshot + post-cutoff");
});

// ─── State Restore ───────────────────────────────────────────────────────────

test("loadStateFromObject normalizes invalid snapshot to null", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);

  // Build state object with invalid snapshot
  const thread = store.threadsById.get(threadId);
  const envelopes = Array.from(store.envelopesById.values());
  const identities = Array.from(store.identities.values());
  const state = {
    identities,
    envelopes,
    threads: [{ ...thread, snapshot: "not-an-object" }],
    capabilities: []
  };

  const store2 = new LoomStore({ nodeId: "node.test" });
  store2.loadStateFromObject(state);

  const restored = store2.threadsById.get(threadId);
  assert.equal(restored.snapshot, null);
});

test("loadStateFromObject normalizes invalid context_budgets to empty object", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const root = ingestRoot(store, aliceKeys, threadId);

  // Build state object with invalid context_budgets
  const thread = store.threadsById.get(threadId);
  const envelopes = Array.from(store.envelopesById.values());
  const identities = Array.from(store.identities.values());
  const state = {
    identities,
    envelopes,
    threads: [{ ...thread, context_budgets: "not-an-object" }],
    capabilities: []
  };

  const store2 = new LoomStore({ nodeId: "node.test" });
  store2.loadStateFromObject(state);

  const restored = store2.threadsById.get(threadId);
  assert.deepEqual(restored.context_budgets, {});
});
