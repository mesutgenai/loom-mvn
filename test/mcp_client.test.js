import test from "node:test";
import assert from "node:assert/strict";

import { generateSigningKeyPair, signEnvelope } from "../src/protocol/crypto.js";
import { generateUlid } from "../src/protocol/ulid.js";
import { MCP_INTENTS } from "../src/protocol/mcp.js";
import { LoomStore } from "../src/node/store.js";
import {
  isMcpToolRequestEnvelope,
  buildMcpResponseEnvelope,
  processMcpToolRequest,
  createMcpToolRateLimiter
} from "../src/node/mcp_client.js";
import { createMcpToolRegistry } from "../src/node/mcp_server.js";

// ─── Helpers ────────────────────────────────────────────────────────────────

function envId() {
  return `env_${generateUlid()}`;
}
function thrId() {
  return `thr_${generateUlid()}`;
}

function setupStore(opts = {}) {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test", ...opts });
  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_1", public_key_pem: aliceKeys.publicKeyPem }]
  });
  store.registerIdentity({
    id: "loom://bob@node.test",
    display_name: "Bob",
    signing_keys: [{ key_id: "k_sign_bob_1", public_key_pem: bobKeys.publicKeyPem }]
  });
  return { store, aliceKeys, bobKeys };
}

function makeToolRequestEnvelope(overrides = {}) {
  const threadId = overrides.thread_id || thrId();
  return {
    loom: "1.1",
    id: envId(),
    thread_id: threadId,
    parent_id: overrides.parent_id || null,
    type: "workflow",
    from: overrides.from || {
      identity: "loom://alice@node.test",
      display: "Alice",
      key_id: "k_sign_alice_1",
      type: "human"
    },
    to: overrides.to || [{ identity: "loom://bob@node.test", role: "primary" }],
    created_at: new Date().toISOString(),
    priority: "normal",
    content: {
      human: { text: "Tool request", format: "plaintext" },
      structured: {
        intent: MCP_INTENTS.TOOL_REQUEST,
        parameters: {
          tool_name: "loom_list_threads",
          request_id: `mcp_req_${generateUlid()}`,
          arguments: {},
          ...(overrides.parameters || {})
        }
      },
      encrypted: false
    },
    attachments: [],
    ...overrides
  };
}

function signAndIngestSeed(store, keys, overrides = {}) {
  const threadId = overrides.thread_id || thrId();
  const seed = signEnvelope(
    {
      loom: "1.1",
      id: envId(),
      thread_id: threadId,
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
        human: { text: "seed", format: "plaintext" },
        structured: { intent: "message.general@v1", parameters: {} },
        encrypted: false
      },
      attachments: []
    },
    keys.privateKeyPem,
    "k_sign_alice_1"
  );
  store.ingestEnvelope(seed, { actorIdentity: "loom://alice@node.test" });
  return { threadId, seedId: seed.id };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Predicate: isMcpToolRequestEnvelope
// ═══════════════════════════════════════════════════════════════════════════════

test("isMcpToolRequestEnvelope: returns true for workflow + tool_request intent", () => {
  const env = makeToolRequestEnvelope();
  assert.equal(isMcpToolRequestEnvelope(env), true);
});

test("isMcpToolRequestEnvelope: returns false for message type", () => {
  const env = makeToolRequestEnvelope();
  env.type = "message";
  assert.equal(isMcpToolRequestEnvelope(env), false);
});

test("isMcpToolRequestEnvelope: returns false for different intent", () => {
  const env = makeToolRequestEnvelope();
  env.content.structured.intent = "workflow.general@v1";
  assert.equal(isMcpToolRequestEnvelope(env), false);
});

test("isMcpToolRequestEnvelope: returns false for null/undefined", () => {
  assert.equal(isMcpToolRequestEnvelope(null), false);
  assert.equal(isMcpToolRequestEnvelope(undefined), false);
  assert.equal(isMcpToolRequestEnvelope({}), false);
});

test("isMcpToolRequestEnvelope: returns false for tool_response intent", () => {
  const env = makeToolRequestEnvelope();
  env.content.structured.intent = MCP_INTENTS.TOOL_RESPONSE;
  assert.equal(isMcpToolRequestEnvelope(env), false);
});

// ═══════════════════════════════════════════════════════════════════════════════
// buildMcpResponseEnvelope
// ═══════════════════════════════════════════════════════════════════════════════

test("buildMcpResponseEnvelope: builds correct success response", () => {
  const reqEnv = makeToolRequestEnvelope();
  const resp = buildMcpResponseEnvelope(
    reqEnv,
    {
      request_id: "mcp_req_123",
      tool_name: "loom_list_threads",
      result: { threads: [] },
      is_error: false,
      executionTrace: {
        tool_name: "loom_list_threads",
        invoked_at: "2025-01-01T00:00:00.000Z",
        duration_ms: 5,
        request_id: "mcp_req_123"
      }
    },
    {
      serviceIdentity: "loom://mcp-service@node.test",
      serviceKeyId: "k_sign_mcp_service_1"
    }
  );

  assert.equal(resp.type, "workflow");
  assert.equal(resp.thread_id, reqEnv.thread_id);
  assert.equal(resp.parent_id, reqEnv.id);
  assert.equal(resp.from.identity, "loom://mcp-service@node.test");
  assert.equal(resp.from.type, "service");
  assert.equal(resp.content.structured.intent, MCP_INTENTS.TOOL_RESPONSE);
  assert.equal(resp.content.structured.parameters.request_id, "mcp_req_123");
  assert.deepEqual(resp.content.structured.parameters.result, { threads: [] });
  assert.equal(resp.content.structured.parameters.is_error, false);
  assert.ok(resp.meta.mcp_execution_trace);
  assert.equal(resp.to[0].identity, reqEnv.from.identity);
});

test("buildMcpResponseEnvelope: builds correct error response", () => {
  const reqEnv = makeToolRequestEnvelope();
  const resp = buildMcpResponseEnvelope(
    reqEnv,
    {
      request_id: "mcp_req_456",
      tool_name: "bad_tool",
      result: null,
      is_error: true,
      error_message: "Tool not found",
      executionTrace: null
    },
    {
      serviceIdentity: "loom://mcp-service@node.test",
      serviceKeyId: "k_sign_mcp_service_1"
    }
  );

  assert.equal(resp.content.structured.parameters.is_error, true);
  assert.equal(resp.content.structured.parameters.error_message, "Tool not found");
  assert.equal(resp.content.structured.parameters.result, null);
  assert.deepEqual(resp.meta, {});
  assert.ok(resp.content.human.text.includes("error"));
});

// ═══════════════════════════════════════════════════════════════════════════════
// processMcpToolRequest (unit tests with mock registry)
// ═══════════════════════════════════════════════════════════════════════════════

function makeProcessorOptions(store, overrides = {}) {
  const serviceKeys = store.ensureMcpServiceIdentity();
  return {
    mcpToolRegistry: store.getMcpToolRegistry(),
    serviceIdentity: serviceKeys.serviceIdentity,
    serviceKeyId: serviceKeys.serviceKeyId,
    servicePrivateKeyPem: serviceKeys.privateKeyPem,
    ...overrides
  };
}

test("processMcpToolRequest: returns processed=false for non-tool-request envelope", () => {
  const { store } = setupStore();
  const options = makeProcessorOptions(store);
  const env = makeToolRequestEnvelope();
  env.type = "message";
  const result = processMcpToolRequest(store, env, options);
  assert.equal(result.processed, false);
});

test("processMcpToolRequest: returns processed=false for target_node mismatch", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const options = makeProcessorOptions(store);

  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: { target_node: "other.node" }
  });
  // Rebuild content since makeToolRequestEnvelope spreads overrides at top level
  const result = processMcpToolRequest(store, env, options);
  assert.equal(result.processed, false);
});

test("processMcpToolRequest: executes loom_list_threads and produces response", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const options = makeProcessorOptions(store);

  const requestId = `mcp_req_${generateUlid()}`;
  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: { tool_name: "loom_list_threads", request_id: requestId, arguments: {} }
  });
  // Sign it so it can be recognized (processor uses storedEnvelope, we pass raw)
  const result = processMcpToolRequest(store, env, options);

  assert.equal(result.processed, true);
  assert.equal(result.is_error, false);
  assert.ok(result.response_envelope_id);

  // Verify the response was stored
  const respEnv = store.getEnvelope(result.response_envelope_id);
  assert.ok(respEnv);
  assert.equal(respEnv.type, "workflow");
  assert.equal(respEnv.parent_id, env.id);
  assert.equal(respEnv.thread_id, threadId);
  assert.equal(respEnv.content.structured.intent, MCP_INTENTS.TOOL_RESPONSE);
  assert.equal(respEnv.content.structured.parameters.request_id, requestId);
  assert.equal(respEnv.content.structured.parameters.is_error, false);
  assert.ok(respEnv.content.structured.parameters.result);
});

test("processMcpToolRequest: response has mcp_execution_trace in meta", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const options = makeProcessorOptions(store);

  const requestId = `mcp_req_${generateUlid()}`;
  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: { tool_name: "loom_list_threads", request_id: requestId, arguments: {} }
  });

  const result = processMcpToolRequest(store, env, options);
  const respEnv = store.getEnvelope(result.response_envelope_id);

  assert.ok(respEnv.meta.mcp_execution_trace);
  assert.ok(respEnv.meta.mcp_execution_trace.steps);
  assert.equal(respEnv.meta.mcp_execution_trace.steps.length, 1);
  const step = respEnv.meta.mcp_execution_trace.steps[0];
  assert.equal(step.tool_name, "loom_list_threads");
  assert.equal(step.request_id, requestId);
  assert.equal(typeof step.duration_ms, "number");
  assert.ok(step.invoked_at);
});

test("processMcpToolRequest: response signed by service identity", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const options = makeProcessorOptions(store);

  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: { tool_name: "loom_list_threads", request_id: `mcp_req_${generateUlid()}`, arguments: {} }
  });

  const result = processMcpToolRequest(store, env, options);
  const respEnv = store.getEnvelope(result.response_envelope_id);

  assert.equal(respEnv.from.identity, `loom://mcp-service@node.test`);
  assert.equal(respEnv.from.type, "service");
  assert.equal(respEnv.from.key_id, "k_sign_mcp_service_1");
  assert.ok(respEnv.signature, "response envelope should be signed");
});

test("processMcpToolRequest: error response for nonexistent tool", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const options = makeProcessorOptions(store);

  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: {
      tool_name: "nonexistent_tool",
      request_id: `mcp_req_${generateUlid()}`,
      arguments: {}
    }
  });

  const result = processMcpToolRequest(store, env, options);

  assert.equal(result.processed, true);
  assert.equal(result.is_error, true);

  const respEnv = store.getEnvelope(result.response_envelope_id);
  assert.equal(respEnv.content.structured.parameters.is_error, true);
  assert.ok(respEnv.content.structured.parameters.error_message.includes("not found"));
});

test("processMcpToolRequest: error response for invalid parameters (missing tool_name)", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const options = makeProcessorOptions(store);

  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId
  });
  // Remove tool_name from parameters
  delete env.content.structured.parameters.tool_name;

  const result = processMcpToolRequest(store, env, options);

  assert.equal(result.processed, true);
  assert.equal(result.is_error, true);

  const respEnv = store.getEnvelope(result.response_envelope_id);
  assert.equal(respEnv.content.structured.parameters.is_error, true);
  assert.ok(respEnv.content.structured.parameters.error_message.includes("Invalid request"));
});

test("processMcpToolRequest: target_node match processes normally", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const options = makeProcessorOptions(store);

  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: {
      tool_name: "loom_list_threads",
      request_id: `mcp_req_${generateUlid()}`,
      arguments: {},
      target_node: "node.test" // matches store.nodeId
    }
  });

  const result = processMcpToolRequest(store, env, options);
  assert.equal(result.processed, true);
  assert.equal(result.is_error, false);
});

test("processMcpToolRequest: absent target_node processes (local execution)", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const options = makeProcessorOptions(store);

  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: {
      tool_name: "loom_list_threads",
      request_id: `mcp_req_${generateUlid()}`,
      arguments: {}
      // No target_node
    }
  });

  const result = processMcpToolRequest(store, env, options);
  assert.equal(result.processed, true);
  assert.equal(result.is_error, false);
});

test("processMcpToolRequest: service identity added as thread participant", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const options = makeProcessorOptions(store);

  const thread = store.threadsById.get(threadId);
  const serviceId = `loom://mcp-service@node.test`;
  const beforeParticipants = thread.participants.filter((p) => p.identity === serviceId);
  assert.equal(beforeParticipants.length, 0, "service not yet a participant");

  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: {
      tool_name: "loom_list_threads",
      request_id: `mcp_req_${generateUlid()}`,
      arguments: {}
    }
  });

  processMcpToolRequest(store, env, options);

  const afterParticipants = thread.participants.filter((p) => p.identity === serviceId);
  assert.equal(afterParticipants.length, 1, "service should now be a participant");
  assert.equal(afterParticipants[0].role, "participant");
  assert.equal(afterParticipants[0].left_at, null);
});

test("processMcpToolRequest: requester identity used as actorIdentity in tool context", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);

  // Create a custom registry that captures the context
  let capturedContext = null;
  const mockRegistry = {
    hasTool: () => true,
    callTool: (_name, _args, context) => {
      capturedContext = context;
      return { content: [{ type: "text", text: "ok" }] };
    }
  };

  const serviceKeys = store.ensureMcpServiceIdentity();
  const options = {
    mcpToolRegistry: mockRegistry,
    serviceIdentity: serviceKeys.serviceIdentity,
    serviceKeyId: serviceKeys.serviceKeyId,
    servicePrivateKeyPem: serviceKeys.privateKeyPem
  };

  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: {
      tool_name: "loom_list_threads",
      request_id: `mcp_req_${generateUlid()}`,
      arguments: {}
    }
  });

  processMcpToolRequest(store, env, options);

  assert.ok(capturedContext);
  assert.equal(capturedContext.actorIdentity, "loom://alice@node.test");
});

// ═══════════════════════════════════════════════════════════════════════════════
// End-to-end via store.ingestEnvelope (auto-execution)
// ═══════════════════════════════════════════════════════════════════════════════

test("e2e: ingesting tool_request auto-produces response in same thread", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);

  const requestId = `mcp_req_${generateUlid()}`;
  const toolReq = signEnvelope(
    makeToolRequestEnvelope({
      thread_id: threadId,
      parent_id: seedId,
      parameters: {
        tool_name: "loom_list_threads",
        request_id: requestId,
        arguments: {}
      }
    }),
    aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );

  store.ingestEnvelope(toolReq, { actorIdentity: "loom://alice@node.test" });

  // Should now have 3 envelopes in thread: seed, request, response
  const thread = store.threadsById.get(threadId);
  assert.ok(thread);
  assert.equal(thread.envelope_ids.length, 3);

  // Find the response
  const envelopes = Array.from(store.envelopesById.values()).filter(
    (e) => e.thread_id === threadId && e.content?.structured?.intent === MCP_INTENTS.TOOL_RESPONSE
  );
  assert.equal(envelopes.length, 1);

  const respEnv = envelopes[0];
  assert.equal(respEnv.parent_id, toolReq.id);
  assert.equal(respEnv.content.structured.parameters.request_id, requestId);
  assert.equal(respEnv.content.structured.parameters.is_error, false);
  assert.equal(respEnv.from.type, "service");
});

test("e2e: mcpClientEnabled=false disables auto-execution", () => {
  const { store, aliceKeys } = setupStore({ mcpClientEnabled: false });
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);

  const toolReq = signEnvelope(
    makeToolRequestEnvelope({
      thread_id: threadId,
      parent_id: seedId,
      parameters: {
        tool_name: "loom_list_threads",
        request_id: `mcp_req_${generateUlid()}`,
        arguments: {}
      }
    }),
    aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );

  store.ingestEnvelope(toolReq, { actorIdentity: "loom://alice@node.test" });

  // Should only have 2 envelopes: seed and request, no auto-response
  const thread = store.threadsById.get(threadId);
  assert.equal(thread.envelope_ids.length, 2);
});

test("e2e: no infinite recursion (response does not trigger another execution)", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);

  const toolReq = signEnvelope(
    makeToolRequestEnvelope({
      thread_id: threadId,
      parent_id: seedId,
      parameters: {
        tool_name: "loom_list_threads",
        request_id: `mcp_req_${generateUlid()}`,
        arguments: {}
      }
    }),
    aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );

  // This should not throw or cause infinite recursion
  store.ingestEnvelope(toolReq, { actorIdentity: "loom://alice@node.test" });

  // Exactly 3: seed + request + one response (not more)
  const thread = store.threadsById.get(threadId);
  assert.equal(thread.envelope_ids.length, 3);

  const responses = Array.from(store.envelopesById.values()).filter(
    (e) =>
      e.thread_id === threadId &&
      e.content?.structured?.intent === MCP_INTENTS.TOOL_RESPONSE
  );
  assert.equal(responses.length, 1, "exactly one response, no recursion");
});

test("e2e: multiple tool requests produce separate responses", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);

  // First request
  const req1 = signEnvelope(
    makeToolRequestEnvelope({
      thread_id: threadId,
      parent_id: seedId,
      parameters: {
        tool_name: "loom_list_threads",
        request_id: `mcp_req_${generateUlid()}`,
        arguments: {}
      }
    }),
    aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );
  const stored1 = store.ingestEnvelope(req1, { actorIdentity: "loom://alice@node.test" });

  // Second request (chained after first)
  const req2 = signEnvelope(
    makeToolRequestEnvelope({
      thread_id: threadId,
      parent_id: stored1.id,
      parameters: {
        tool_name: "loom_list_threads",
        request_id: `mcp_req_${generateUlid()}`,
        arguments: {}
      }
    }),
    aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );
  store.ingestEnvelope(req2, { actorIdentity: "loom://alice@node.test" });

  // Should have: seed + req1 + resp1 + req2 + resp2 = 5
  const thread = store.threadsById.get(threadId);
  assert.equal(thread.envelope_ids.length, 5);

  const responses = Array.from(store.envelopesById.values()).filter(
    (e) =>
      e.thread_id === threadId &&
      e.content?.structured?.intent === MCP_INTENTS.TOOL_RESPONSE
  );
  assert.equal(responses.length, 2);

  // Each response has different parent_id
  const parentIds = responses.map((r) => r.parent_id);
  assert.ok(parentIds.includes(req1.id));
  assert.ok(parentIds.includes(req2.id));
});

test("e2e: service identity added as thread participant during auto-execution", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);

  const toolReq = signEnvelope(
    makeToolRequestEnvelope({
      thread_id: threadId,
      parent_id: seedId,
      parameters: {
        tool_name: "loom_list_threads",
        request_id: `mcp_req_${generateUlid()}`,
        arguments: {}
      }
    }),
    aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );

  store.ingestEnvelope(toolReq, { actorIdentity: "loom://alice@node.test" });

  const thread = store.threadsById.get(threadId);
  const serviceParticipant = thread.participants.find(
    (p) => p.identity === "loom://mcp-service@node.test"
  );
  assert.ok(serviceParticipant, "service identity should be a participant");
  assert.equal(serviceParticipant.role, "participant");
});

test("e2e: response envelope passes full envelope validation (stored successfully)", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);

  const requestId = `mcp_req_${generateUlid()}`;
  const toolReq = signEnvelope(
    makeToolRequestEnvelope({
      thread_id: threadId,
      parent_id: seedId,
      parameters: {
        tool_name: "loom_list_threads",
        request_id: requestId,
        arguments: {}
      }
    }),
    aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );

  store.ingestEnvelope(toolReq, { actorIdentity: "loom://alice@node.test" });

  // Find the auto-generated response
  const responses = Array.from(store.envelopesById.values()).filter(
    (e) =>
      e.thread_id === threadId &&
      e.content?.structured?.intent === MCP_INTENTS.TOOL_RESPONSE
  );
  assert.equal(responses.length, 1);

  const resp = responses[0];
  // Verify all required envelope fields
  assert.ok(resp.id.startsWith("env_"));
  assert.equal(resp.loom, "1.1");
  assert.equal(resp.thread_id, threadId);
  assert.equal(resp.parent_id, toolReq.id);
  assert.equal(resp.type, "workflow");
  assert.ok(resp.from);
  assert.ok(resp.to);
  assert.ok(resp.content);
  assert.ok(resp.content.human);
  assert.ok(resp.content.structured);
  assert.ok(resp.created_at);
  assert.ok(resp.signature);
  assert.equal(resp.content.encrypted, false);
});

// ═══════════════════════════════════════════════════════════════════════════════
// Store integration: ensureMcpServiceIdentity / getMcpToolRegistry
// ═══════════════════════════════════════════════════════════════════════════════

test("ensureMcpServiceIdentity: registers service identity with correct properties", () => {
  const { store } = setupStore();
  const keys = store.ensureMcpServiceIdentity();

  assert.equal(keys.serviceIdentity, "loom://mcp-service@node.test");
  assert.equal(keys.serviceKeyId, "k_sign_mcp_service_1");
  assert.ok(keys.privateKeyPem);
  assert.ok(keys.publicKeyPem);

  // Verify identity is registered
  const identity = store.identities.get("loom://mcp-service@node.test");
  assert.ok(identity);
  assert.equal(identity.display_name, "MCP Service");
});

test("ensureMcpServiceIdentity: returns cached keys on second call", () => {
  const { store } = setupStore();
  const keys1 = store.ensureMcpServiceIdentity();
  const keys2 = store.ensureMcpServiceIdentity();
  assert.equal(keys1, keys2, "should return same cached object");
});

test("getMcpToolRegistry: returns tool registry with expected tools", () => {
  const { store } = setupStore();
  const registry = store.getMcpToolRegistry();

  assert.ok(registry);
  assert.ok(registry.hasTool("loom_list_threads"));
  assert.ok(registry.hasTool("loom_send_envelope"));
  assert.ok(registry.hasTool("loom_read_thread"));
  assert.ok(registry.hasTool("loom_search"));
  assert.ok(registry.hasTool("loom_manage_capability"));
  assert.ok(registry.hasTool("loom_thread_operation"));
});

test("getMcpToolRegistry: caches registry on subsequent calls", () => {
  const { store } = setupStore();
  const reg1 = store.getMcpToolRegistry();
  const reg2 = store.getMcpToolRegistry();
  assert.equal(reg1, reg2);
});

// ═══════════════════════════════════════════════════════════════════════════════
// Edge cases
// ═══════════════════════════════════════════════════════════════════════════════

test("processMcpToolRequest: tool execution exception produces error response (not throw)", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);

  // Create a mock registry with a failing tool
  const mockRegistry = {
    hasTool: (name) => name === "failing_tool",
    callTool: () => {
      throw new Error("Tool crashed hard");
    }
  };

  const serviceKeys = store.ensureMcpServiceIdentity();
  const options = {
    mcpToolRegistry: mockRegistry,
    serviceIdentity: serviceKeys.serviceIdentity,
    serviceKeyId: serviceKeys.serviceKeyId,
    servicePrivateKeyPem: serviceKeys.privateKeyPem
  };

  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: {
      tool_name: "failing_tool",
      request_id: `mcp_req_${generateUlid()}`,
      arguments: {}
    }
  });

  // Should NOT throw
  const result = processMcpToolRequest(store, env, options);

  assert.equal(result.processed, true);
  assert.equal(result.is_error, true);

  const respEnv = store.getEnvelope(result.response_envelope_id);
  assert.equal(respEnv.content.structured.parameters.is_error, true);
  assert.ok(respEnv.content.structured.parameters.error_message.includes("crashed hard"));
});

test("e2e: auto-execution error for nonexistent tool produces error response in thread", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);

  const toolReq = signEnvelope(
    makeToolRequestEnvelope({
      thread_id: threadId,
      parent_id: seedId,
      parameters: {
        tool_name: "nonexistent_tool",
        request_id: `mcp_req_${generateUlid()}`,
        arguments: {}
      }
    }),
    aliceKeys.privateKeyPem,
    "k_sign_alice_1"
  );

  // Should not throw
  store.ingestEnvelope(toolReq, { actorIdentity: "loom://alice@node.test" });

  const thread = store.threadsById.get(threadId);
  assert.equal(thread.envelope_ids.length, 3); // seed + request + error response

  const responses = Array.from(store.envelopesById.values()).filter(
    (e) =>
      e.thread_id === threadId &&
      e.content?.structured?.intent === MCP_INTENTS.TOOL_RESPONSE
  );
  assert.equal(responses.length, 1);
  assert.equal(responses[0].content.structured.parameters.is_error, true);
});

// ═══════════════════════════════════════════════════════════════════════════════
// MCP Client Sandbox Enforcement
// ═══════════════════════════════════════════════════════════════════════════════

test("sandbox: processMcpToolRequest enforces argument size limit", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const options = makeProcessorOptions(store, {
    sandboxPolicy: { max_argument_bytes: 32 }
  });

  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: { tool_name: "loom_list_threads", request_id: `mcp_req_${generateUlid()}`, arguments: { data: "x".repeat(200) } }
  });

  const result = processMcpToolRequest(store, env, options);
  assert.equal(result.processed, true);
  assert.equal(result.is_error, true);

  const respEnv = store.getEnvelope(result.response_envelope_id);
  assert.ok(respEnv.content.structured.parameters.error_message.includes("size limit"));
});

test("sandbox: processMcpToolRequest enforces rate limit", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const rateLimiter = createMcpToolRateLimiter(2, 60000);
  const options = makeProcessorOptions(store, { mcpRateLimiter: rateLimiter });

  // First two calls should succeed
  for (let i = 0; i < 2; i++) {
    const env = makeToolRequestEnvelope({
      thread_id: threadId,
      parent_id: seedId,
      parameters: { tool_name: "loom_list_threads", request_id: `mcp_req_${generateUlid()}`, arguments: {} }
    });
    const result = processMcpToolRequest(store, env, options);
    assert.equal(result.processed, true);
    assert.equal(result.is_error, false);
  }

  // Third call should be rate limited
  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: { tool_name: "loom_list_threads", request_id: `mcp_req_${generateUlid()}`, arguments: {} }
  });
  const result = processMcpToolRequest(store, env, options);
  assert.equal(result.processed, true);
  assert.equal(result.is_error, true);

  const respEnv = store.getEnvelope(result.response_envelope_id);
  assert.ok(respEnv.content.structured.parameters.error_message.includes("Rate limit"));
});

test("sandbox: processMcpToolRequest returns error envelope (not exception) on sandbox violation", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const options = makeProcessorOptions(store, {
    sandboxPolicy: { max_argument_bytes: 16 }
  });

  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: { tool_name: "loom_list_threads", request_id: `mcp_req_${generateUlid()}`, arguments: { big: "x".repeat(100) } }
  });

  // Should not throw — should return error response
  const result = processMcpToolRequest(store, env, options);
  assert.equal(result.processed, true);
  assert.equal(result.is_error, true);
  assert.ok(result.response_envelope_id);
});

test("sandbox: processMcpToolRequest passes sandbox metrics in execution trace", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const options = makeProcessorOptions(store, {
    sandboxPolicy: { execution_timeout_ms: 10000 }
  });

  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: { tool_name: "loom_list_threads", request_id: `mcp_req_${generateUlid()}`, arguments: {} }
  });

  const result = processMcpToolRequest(store, env, options);
  const respEnv = store.getEnvelope(result.response_envelope_id);
  const trace = respEnv.meta.mcp_execution_trace.steps[0];
  assert.ok(trace.sandbox);
  assert.equal(typeof trace.sandbox.argument_bytes, "number");
  assert.equal(trace.sandbox.timeout_ms, 10000);
  assert.equal(trace.sandbox.timed_out, false);
});

test("sandbox: onSandboxViolation callback is called on arg size violation", () => {
  const { store, aliceKeys } = setupStore();
  const { threadId, seedId } = signAndIngestSeed(store, aliceKeys);
  const violations = [];
  const options = makeProcessorOptions(store, {
    sandboxPolicy: { max_argument_bytes: 16 },
    onSandboxViolation: (v) => violations.push(v)
  });

  const env = makeToolRequestEnvelope({
    thread_id: threadId,
    parent_id: seedId,
    parameters: { tool_name: "loom_list_threads", request_id: `mcp_req_${generateUlid()}`, arguments: { big: "x".repeat(100) } }
  });

  processMcpToolRequest(store, env, options);
  assert.equal(violations.length, 1);
  assert.equal(violations[0].type, "argument_size_exceeded");
  assert.equal(violations[0].tool_name, "loom_list_threads");
});

// ═══════════════════════════════════════════════════════════════════════════════
// createMcpToolRateLimiter
// ═══════════════════════════════════════════════════════════════════════════════

test("createMcpToolRateLimiter: creates limiter with defaults", () => {
  const limiter = createMcpToolRateLimiter();
  const result = limiter.check("loom://alice@test");
  assert.equal(result.allowed, true);
  assert.equal(result.limit, 60);
  assert.equal(result.remaining, 60);
  assert.equal(result.window_ms, 60000);
});

test("createMcpToolRateLimiter: tracks per-actor independently", () => {
  const limiter = createMcpToolRateLimiter(2, 60000);
  limiter.record("loom://alice@test");
  limiter.record("loom://alice@test");
  // Alice exhausted
  assert.equal(limiter.check("loom://alice@test").allowed, false);
  // Bob still has capacity
  assert.equal(limiter.check("loom://bob@test").allowed, true);
  assert.equal(limiter.check("loom://bob@test").remaining, 2);
});

test("createMcpToolRateLimiter: check returns accurate remaining count", () => {
  const limiter = createMcpToolRateLimiter(5, 60000);
  limiter.record("actor1");
  limiter.record("actor1");
  limiter.record("actor1");
  const result = limiter.check("actor1");
  assert.equal(result.allowed, true);
  assert.equal(result.remaining, 2);
});
