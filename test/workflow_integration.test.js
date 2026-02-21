import test from "node:test";
import assert from "node:assert/strict";

import { generateSigningKeyPair, signEnvelope } from "../src/protocol/crypto.js";
import { generateUlid } from "../src/protocol/ulid.js";
import { LoomStore } from "../src/node/store.js";
import { WORKFLOW_INTENTS, WORKFLOW_STATES } from "../src/protocol/workflow.js";

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
    signing_keys: [{ key_id: "k_sign_alice_wf_1", public_key_pem: aliceKeys.publicKeyPem }]
  });
  store.registerIdentity({
    id: "loom://bob@node.test",
    display_name: "Bob",
    signing_keys: [{ key_id: "k_sign_bob_wf_1", public_key_pem: bobKeys.publicKeyPem }]
  });
  return { store, aliceKeys, bobKeys };
}

function makeWorkflowEnvelope(overrides = {}) {
  const threadId = overrides.thread_id || thrId();
  return {
    loom: "1.1",
    id: envId(),
    thread_id: threadId,
    parent_id: overrides.parent_id || null,
    type: "workflow",
    from: {
      identity: "loom://alice@node.test",
      display: "Alice",
      key_id: "k_sign_alice_wf_1",
      type: "human"
    },
    to: [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: new Date().toISOString(),
    priority: "normal",
    content: {
      human: { text: "workflow envelope", format: "plaintext" },
      structured: {
        intent: WORKFLOW_INTENTS.EXECUTE,
        parameters: {
          workflow_id: "wf_test_1",
          definition: { steps: [{ step_id: "s1" }, { step_id: "s2" }] }
        }
      },
      encrypted: false
    },
    attachments: [],
    ...overrides
  };
}

function signBase(privateKeyPem, keyId, overrides = {}) {
  const envelope = makeWorkflowEnvelope(overrides);
  return signEnvelope(envelope, privateKeyPem, keyId);
}

// ─── workflow.execute@v1 ────────────────────────────────────────────────────

test("workflow integration: execute creates thread.workflow state", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  const signed = signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
    thread_id: threadId,
    content: {
      human: { text: "start workflow", format: "plaintext" },
      structured: {
        intent: WORKFLOW_INTENTS.EXECUTE,
        parameters: {
          workflow_id: "wf_001",
          definition: { steps: [{ step_id: "fetch_data" }, { step_id: "process" }] }
        }
      },
      encrypted: false
    }
  });

  store.ingestEnvelope(signed, { actorIdentity: "loom://alice@node.test" });
  const thread = store.threadsById.get(threadId);

  assert.ok(thread.workflow, "thread should have workflow state");
  assert.equal(thread.workflow.workflow_id, "wf_001");
  assert.equal(thread.workflow.status, WORKFLOW_STATES.RUNNING);
  assert.deepEqual(thread.workflow.definition.steps.length, 2);
  assert.deepEqual(thread.workflow.step_states, {});
  assert.ok(thread.workflow.started_at);
  assert.equal(thread.workflow.completed_at, null);
  assert.equal(thread.workflow.failed_at, null);
});

// ─── workflow.step_complete@v1 ──────────────────────────────────────────────

test("workflow integration: step_complete updates step_states", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  // Start workflow
  const execSigned = signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
    thread_id: threadId,
    content: {
      human: { text: "start", format: "plaintext" },
      structured: {
        intent: WORKFLOW_INTENTS.EXECUTE,
        parameters: {
          workflow_id: "wf_step",
          definition: { steps: [{ step_id: "s1" }] }
        }
      },
      encrypted: false
    }
  });
  const execStored = store.ingestEnvelope(execSigned, { actorIdentity: "loom://alice@node.test" });

  // Step complete
  const stepSigned = signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
    thread_id: threadId,
    parent_id: execStored.id,
    content: {
      human: { text: "step done", format: "plaintext" },
      structured: {
        intent: WORKFLOW_INTENTS.STEP_COMPLETE,
        parameters: {
          workflow_id: "wf_step",
          step_id: "s1",
          result: { rows: 42 }
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(stepSigned, { actorIdentity: "loom://alice@node.test" });

  const thread = store.threadsById.get(threadId);
  assert.equal(thread.workflow.status, WORKFLOW_STATES.RUNNING);
  assert.ok(thread.workflow.step_states.s1);
  assert.equal(thread.workflow.step_states.s1.status, "completed");
  assert.deepEqual(thread.workflow.step_states.s1.result, { rows: 42 });
});

// ─── workflow.complete@v1 ───────────────────────────────────────────────────

test("workflow integration: complete marks workflow completed", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  // Start
  const execStored = store.ingestEnvelope(
    signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
      thread_id: threadId,
      content: {
        human: { text: "start", format: "plaintext" },
        structured: {
          intent: WORKFLOW_INTENTS.EXECUTE,
          parameters: { workflow_id: "wf_done", definition: { steps: [{ step_id: "s1" }] } }
        },
        encrypted: false
      }
    }),
    { actorIdentity: "loom://alice@node.test" }
  );

  // Complete
  store.ingestEnvelope(
    signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
      thread_id: threadId,
      parent_id: execStored.id,
      content: {
        human: { text: "workflow done", format: "plaintext" },
        structured: {
          intent: WORKFLOW_INTENTS.COMPLETE,
          parameters: { workflow_id: "wf_done", result: "success" }
        },
        encrypted: false
      }
    }),
    { actorIdentity: "loom://alice@node.test" }
  );

  const thread = store.threadsById.get(threadId);
  assert.equal(thread.workflow.status, WORKFLOW_STATES.COMPLETED);
  assert.ok(thread.workflow.completed_at);
});

// ─── workflow.failed@v1 ─────────────────────────────────────────────────────

test("workflow integration: failed marks workflow failed", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  // Start
  const execStored = store.ingestEnvelope(
    signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
      thread_id: threadId,
      content: {
        human: { text: "start", format: "plaintext" },
        structured: {
          intent: WORKFLOW_INTENTS.EXECUTE,
          parameters: { workflow_id: "wf_fail", definition: { steps: [{ step_id: "s1" }] } }
        },
        encrypted: false
      }
    }),
    { actorIdentity: "loom://alice@node.test" }
  );

  // Fail
  store.ingestEnvelope(
    signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
      thread_id: threadId,
      parent_id: execStored.id,
      content: {
        human: { text: "workflow failed", format: "plaintext" },
        structured: {
          intent: WORKFLOW_INTENTS.FAILED,
          parameters: { workflow_id: "wf_fail", error: { message: "timeout" } }
        },
        encrypted: false
      }
    }),
    { actorIdentity: "loom://alice@node.test" }
  );

  const thread = store.threadsById.get(threadId);
  assert.equal(thread.workflow.status, WORKFLOW_STATES.FAILED);
  assert.ok(thread.workflow.failed_at);
  assert.equal(thread.workflow.error.message, "timeout");
});

// ─── MCP pass-through ───────────────────────────────────────────────────────

test("workflow integration: MCP intents pass through without affecting workflow state", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  // First, start a workflow
  store.ingestEnvelope(
    signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
      thread_id: threadId,
      content: {
        human: { text: "start", format: "plaintext" },
        structured: {
          intent: WORKFLOW_INTENTS.EXECUTE,
          parameters: { workflow_id: "wf_mcp", definition: { steps: [{ step_id: "s1" }] } }
        },
        encrypted: false
      }
    }),
    { actorIdentity: "loom://alice@node.test" }
  );

  const threadBefore = store.threadsById.get(threadId);
  const workflowBefore = JSON.parse(JSON.stringify(threadBefore.workflow));

  // Now ingest MCP tool request — should NOT modify workflow state
  const mcpEnv = signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
    thread_id: threadId,
    parent_id: threadBefore.envelope_ids[0],
    content: {
      human: { text: "MCP request", format: "plaintext" },
      structured: {
        intent: "mcp.tool_request@v1",
        parameters: {
          tool_name: "some_tool",
          arguments: {}
        }
      },
      encrypted: false
    }
  });
  store.ingestEnvelope(mcpEnv, { actorIdentity: "loom://alice@node.test" });

  const threadAfter = store.threadsById.get(threadId);
  assert.equal(threadAfter.workflow.workflow_id, workflowBefore.workflow_id);
  assert.equal(threadAfter.workflow.status, workflowBefore.status);
  assert.deepEqual(threadAfter.workflow.step_states, workflowBefore.step_states);
});

// ─── Thread Summary ─────────────────────────────────────────────────────────

test("workflow integration: thread summary includes workflow state", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  store.ingestEnvelope(
    signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
      thread_id: threadId,
      content: {
        human: { text: "start", format: "plaintext" },
        structured: {
          intent: WORKFLOW_INTENTS.EXECUTE,
          parameters: { workflow_id: "wf_summary", definition: { steps: [{ step_id: "s1" }] } }
        },
        encrypted: false
      }
    }),
    { actorIdentity: "loom://alice@node.test" }
  );

  const threads = store.listThreads();
  const threadSummary = threads.find((t) => t.id === threadId);
  assert.ok(threadSummary.workflow, "thread summary should include workflow");
  assert.equal(threadSummary.workflow.workflow_id, "wf_summary");
  assert.equal(threadSummary.workflow.status, "running");
});

test("workflow integration: thread summary has null workflow when no workflow started", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  // Ingest a normal message, not a workflow
  const msgEnv = {
    loom: "1.1",
    id: envId(),
    thread_id: threadId,
    parent_id: null,
    type: "message",
    from: { identity: "loom://alice@node.test", display: "Alice", key_id: "k_sign_alice_wf_1", type: "human" },
    to: [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: new Date().toISOString(),
    priority: "normal",
    content: {
      human: { text: "hello", format: "plaintext" },
      structured: { intent: "message.general@v1", parameters: {} },
      encrypted: false
    },
    attachments: []
  };
  const signed = signEnvelope(msgEnv, aliceKeys.privateKeyPem, "k_sign_alice_wf_1");
  store.ingestEnvelope(signed, { actorIdentity: "loom://alice@node.test" });

  const threads = store.listThreads();
  const threadSummary = threads.find((t) => t.id === threadId);
  assert.equal(threadSummary.workflow, null);
});

// ─── State Serialization ────────────────────────────────────────────────────

test("workflow integration: workflow state survives serialization round-trip", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  store.ingestEnvelope(
    signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
      thread_id: threadId,
      content: {
        human: { text: "start", format: "plaintext" },
        structured: {
          intent: WORKFLOW_INTENTS.EXECUTE,
          parameters: { workflow_id: "wf_serial", definition: { steps: [{ step_id: "s1" }] } }
        },
        encrypted: false
      }
    }),
    { actorIdentity: "loom://alice@node.test" }
  );

  const state = store.toSerializableState();
  const store2 = new LoomStore({ nodeId: "node.test" });
  store2.loadStateFromObject(state);

  const thread = store2.threadsById.get(threadId);
  assert.ok(thread.workflow);
  assert.equal(thread.workflow.workflow_id, "wf_serial");
  assert.equal(thread.workflow.status, "running");
});

// ─── Invalid workflow parameters: envelope still ingested ───────────────────

test("workflow integration: invalid execute parameters produce warnings but envelope is ingested", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  const signed = signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
    thread_id: threadId,
    content: {
      human: { text: "bad workflow", format: "plaintext" },
      structured: {
        intent: WORKFLOW_INTENTS.EXECUTE,
        parameters: {
          // Missing workflow_id and definition
        }
      },
      encrypted: false
    }
  });

  // Should not throw
  const stored = store.ingestEnvelope(signed, { actorIdentity: "loom://alice@node.test" });
  assert.ok(stored.id);
  assert.ok(Array.isArray(stored.meta.workflow_warnings));
  assert.ok(stored.meta.workflow_warnings.length > 0);

  // Thread should NOT have workflow state set
  const thread = store.threadsById.get(threadId);
  assert.equal(thread.workflow, undefined);
});

// ─── step_complete on non-running workflow ───────────────────────────────────

test("workflow integration: step_complete on non-running workflow produces warning", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  // Start and complete a workflow
  const execStored = store.ingestEnvelope(
    signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
      thread_id: threadId,
      content: {
        human: { text: "start", format: "plaintext" },
        structured: {
          intent: WORKFLOW_INTENTS.EXECUTE,
          parameters: { workflow_id: "wf_closed", definition: { steps: [{ step_id: "s1" }] } }
        },
        encrypted: false
      }
    }),
    { actorIdentity: "loom://alice@node.test" }
  );

  store.ingestEnvelope(
    signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
      thread_id: threadId,
      parent_id: execStored.id,
      content: {
        human: { text: "done", format: "plaintext" },
        structured: {
          intent: WORKFLOW_INTENTS.COMPLETE,
          parameters: { workflow_id: "wf_closed" }
        },
        encrypted: false
      }
    }),
    { actorIdentity: "loom://alice@node.test" }
  );

  // Now try step_complete on completed workflow
  const stepStored = store.ingestEnvelope(
    signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
      thread_id: threadId,
      parent_id: execStored.id,
      content: {
        human: { text: "late step", format: "plaintext" },
        structured: {
          intent: WORKFLOW_INTENTS.STEP_COMPLETE,
          parameters: { workflow_id: "wf_closed", step_id: "s1", result: "late" }
        },
        encrypted: false
      }
    }),
    { actorIdentity: "loom://alice@node.test" }
  );

  assert.ok(stepStored.id);
  assert.ok(stepStored.meta.workflow_warnings.some((w) => w.includes("not running")));
  // Workflow status should remain completed
  const thread = store.threadsById.get(threadId);
  assert.equal(thread.workflow.status, WORKFLOW_STATES.COMPLETED);
});

// ─── workflow_id mismatch ───────────────────────────────────────────────────

test("workflow integration: step_complete with mismatched workflow_id produces warning", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  const execStored = store.ingestEnvelope(
    signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
      thread_id: threadId,
      content: {
        human: { text: "start", format: "plaintext" },
        structured: {
          intent: WORKFLOW_INTENTS.EXECUTE,
          parameters: { workflow_id: "wf_original", definition: { steps: [{ step_id: "s1" }] } }
        },
        encrypted: false
      }
    }),
    { actorIdentity: "loom://alice@node.test" }
  );

  const stepStored = store.ingestEnvelope(
    signBase(aliceKeys.privateKeyPem, "k_sign_alice_wf_1", {
      thread_id: threadId,
      parent_id: execStored.id,
      content: {
        human: { text: "wrong wf", format: "plaintext" },
        structured: {
          intent: WORKFLOW_INTENTS.STEP_COMPLETE,
          parameters: { workflow_id: "wf_wrong", step_id: "s1", result: "mismatch" }
        },
        encrypted: false
      }
    }),
    { actorIdentity: "loom://alice@node.test" }
  );

  assert.ok(stepStored.meta.workflow_warnings.some((w) => w.includes("mismatch")));
});
