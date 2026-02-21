import test from "node:test";
import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";

import { generateSigningKeyPair, signEnvelope } from "../src/protocol/crypto.js";
import { generateUlid } from "../src/protocol/ulid.js";
import { LoomStore } from "../src/node/store.js";
import {
  validateToolDefinition,
  validateToolRequestParameters,
  validateToolResponseParameters,
  validateMcpExecutionTrace,
  parseJsonRpcRequest,
  jsonrpcResponse,
  jsonrpcError,
  JSONRPC_ERRORS,
  MCP_PROTOCOL_VERSION,
  MCP_INTENTS
} from "../src/protocol/mcp.js";
import {
  createMcpToolRegistry,
  handleMcpRequest,
  startMcpStdioTransport
} from "../src/node/mcp_server.js";

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
      key_id: "k_sign_alice_mcp_1",
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

function signBase(privateKeyPem, keyId, overrides = {}) {
  const envelope = makeEnvelope(overrides);
  return signEnvelope(envelope, privateKeyPem, keyId);
}

function setupStore() {
  const aliceKeys = generateSigningKeyPair();
  const bobKeys = generateSigningKeyPair();
  const store = new LoomStore({ nodeId: "node.test" });
  store.registerIdentity({
    id: "loom://alice@node.test",
    display_name: "Alice",
    signing_keys: [{ key_id: "k_sign_alice_mcp_1", public_key_pem: aliceKeys.publicKeyPem }]
  });
  store.registerIdentity({
    id: "loom://bob@node.test",
    display_name: "Bob",
    signing_keys: [{ key_id: "k_sign_bob_mcp_1", public_key_pem: bobKeys.publicKeyPem }]
  });
  return { store, aliceKeys, bobKeys };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Protocol Layer: mcp.js validation functions
// ═══════════════════════════════════════════════════════════════════════════════

test("mcp: validateToolDefinition accepts valid tool", () => {
  const errors = validateToolDefinition({
    name: "loom_send_envelope",
    description: "Send an envelope",
    inputSchema: { type: "object" }
  });
  assert.equal(errors.length, 0);
});

test("mcp: validateToolDefinition accepts tool with only name", () => {
  const errors = validateToolDefinition({ name: "my_tool" });
  assert.equal(errors.length, 0);
});

test("mcp: validateToolDefinition rejects missing name", () => {
  const errors = validateToolDefinition({ description: "no name" });
  assert.ok(errors.some((e) => e.field === "tool.name"));
});

test("mcp: validateToolDefinition rejects invalid name pattern", () => {
  const errors = validateToolDefinition({ name: "UPPERCASE_NAME" });
  assert.ok(errors.some((e) => e.field === "tool.name"));
});

test("mcp: validateToolDefinition rejects non-object", () => {
  const errors = validateToolDefinition("string");
  assert.ok(errors.some((e) => e.field === "tool"));
});

test("mcp: validateToolDefinition rejects non-string description", () => {
  const errors = validateToolDefinition({ name: "tool", description: 42 });
  assert.ok(errors.some((e) => e.field === "tool.description"));
});

test("mcp: validateToolRequestParameters validates required fields", () => {
  const errors = validateToolRequestParameters({});
  assert.ok(errors.some((e) => e.field === "parameters.tool_name"));
  assert.ok(errors.some((e) => e.field === "parameters.request_id"));
});

test("mcp: validateToolRequestParameters accepts valid params", () => {
  const errors = validateToolRequestParameters({
    tool_name: "loom_search",
    request_id: "mcp_req_123",
    arguments: { q: "test" }
  });
  assert.equal(errors.length, 0);
});

test("mcp: validateToolRequestParameters rejects non-object arguments", () => {
  const errors = validateToolRequestParameters({
    tool_name: "tool",
    request_id: "req_1",
    arguments: "not_an_object"
  });
  assert.ok(errors.some((e) => e.field === "parameters.arguments"));
});

test("mcp: validateToolResponseParameters validates request_id", () => {
  const errors = validateToolResponseParameters({ is_error: true, error_message: "fail" });
  assert.ok(errors.some((e) => e.field === "parameters.request_id"));
});

test("mcp: validateToolResponseParameters accepts valid response", () => {
  const errors = validateToolResponseParameters({
    request_id: "req_1",
    result: { data: "ok" },
    is_error: false
  });
  assert.equal(errors.length, 0);
});

test("mcp: validateToolResponseParameters rejects non-boolean is_error", () => {
  const errors = validateToolResponseParameters({
    request_id: "req_1",
    is_error: "yes"
  });
  assert.ok(errors.some((e) => e.field === "parameters.is_error"));
});

test("mcp: validateMcpExecutionTrace accepts valid trace", () => {
  const errors = validateMcpExecutionTrace({
    steps: [
      {
        tool_name: "loom_search",
        invoked_at: new Date().toISOString(),
        duration_ms: 42
      }
    ]
  });
  assert.equal(errors.length, 0);
});

test("mcp: validateMcpExecutionTrace rejects missing steps array", () => {
  const errors = validateMcpExecutionTrace({});
  assert.ok(errors.some((e) => e.field === "meta.mcp_execution_trace.steps"));
});

test("mcp: validateMcpExecutionTrace rejects >50 steps", () => {
  const steps = Array.from({ length: 51 }, (_, i) => ({
    tool_name: `tool_${i}`,
    invoked_at: new Date().toISOString()
  }));
  const errors = validateMcpExecutionTrace({ steps });
  assert.ok(errors.some((e) => e.reason.includes("max 50")));
});

test("mcp: validateMcpExecutionTrace rejects step without tool_name", () => {
  const errors = validateMcpExecutionTrace({
    steps: [{ invoked_at: new Date().toISOString() }]
  });
  assert.ok(errors.some((e) => e.field.includes("tool_name")));
});

test("mcp: validateMcpExecutionTrace rejects step without invoked_at", () => {
  const errors = validateMcpExecutionTrace({
    steps: [{ tool_name: "tool" }]
  });
  assert.ok(errors.some((e) => e.field.includes("invoked_at")));
});

test("mcp: validateMcpExecutionTrace rejects negative duration_ms", () => {
  const errors = validateMcpExecutionTrace({
    steps: [{ tool_name: "tool", invoked_at: new Date().toISOString(), duration_ms: -1 }]
  });
  assert.ok(errors.some((e) => e.field.includes("duration_ms")));
});

// ═══════════════════════════════════════════════════════════════════════════════
// JSON-RPC 2.0 helpers
// ═══════════════════════════════════════════════════════════════════════════════

test("mcp: parseJsonRpcRequest rejects non-2.0 version", () => {
  const result = parseJsonRpcRequest({ jsonrpc: "1.0", method: "test", id: 1 });
  assert.equal(result.valid, false);
});

test("mcp: parseJsonRpcRequest rejects missing method", () => {
  const result = parseJsonRpcRequest({ jsonrpc: "2.0", id: 1 });
  assert.equal(result.valid, false);
});

test("mcp: parseJsonRpcRequest accepts valid request", () => {
  const result = parseJsonRpcRequest({ jsonrpc: "2.0", method: "tools/list", id: 1 });
  assert.equal(result.valid, true);
  assert.equal(result.method, "tools/list");
  assert.equal(result.id, 1);
});

test("mcp: parseJsonRpcRequest defaults params to empty object", () => {
  const result = parseJsonRpcRequest({ jsonrpc: "2.0", method: "ping", id: 1 });
  assert.deepEqual(result.params, {});
});

test("mcp: jsonrpcResponse produces valid response", () => {
  const r = jsonrpcResponse(1, { ok: true });
  assert.equal(r.jsonrpc, "2.0");
  assert.equal(r.id, 1);
  assert.deepEqual(r.result, { ok: true });
});

test("mcp: jsonrpcError produces valid error response", () => {
  const r = jsonrpcError(1, JSONRPC_ERRORS.PARSE_ERROR, "bad");
  assert.equal(r.jsonrpc, "2.0");
  assert.equal(r.id, 1);
  assert.equal(r.error.code, -32700);
  assert.equal(r.error.data, "bad");
});

test("mcp: jsonrpcError uses null id when id is undefined", () => {
  const r = jsonrpcError(undefined, JSONRPC_ERRORS.INTERNAL_ERROR);
  assert.equal(r.id, null);
});

// ═══════════════════════════════════════════════════════════════════════════════
// MCP Server Layer: handleMcpRequest
// ═══════════════════════════════════════════════════════════════════════════════

test("mcp: handleMcpRequest responds to initialize", () => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);
  const context = { actorIdentity: "loom://alice@node.test" };

  const response = handleMcpRequest({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, registry, context);
  assert.equal(response.jsonrpc, "2.0");
  assert.equal(response.id, 1);
  assert.equal(response.result.protocolVersion, MCP_PROTOCOL_VERSION);
  assert.ok(response.result.capabilities.tools);
  assert.equal(response.result.serverInfo.name, "loom-mcp-server");
});

test("mcp: handleMcpRequest returns null for initialized notification", () => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);
  const response = handleMcpRequest({ jsonrpc: "2.0", method: "initialized" }, registry, {});
  assert.equal(response, null);
});

test("mcp: handleMcpRequest lists tools", () => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);
  const context = { actorIdentity: "loom://alice@node.test" };

  const response = handleMcpRequest({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, registry, context);
  assert.ok(Array.isArray(response.result.tools));
  assert.ok(response.result.tools.length >= 6);

  const names = response.result.tools.map((t) => t.name);
  assert.ok(names.includes("loom_send_envelope"));
  assert.ok(names.includes("loom_read_thread"));
  assert.ok(names.includes("loom_list_threads"));
  assert.ok(names.includes("loom_search"));
  assert.ok(names.includes("loom_manage_capability"));
  assert.ok(names.includes("loom_thread_operation"));

  for (const tool of response.result.tools) {
    assert.equal(typeof tool.name, "string");
    assert.equal(typeof tool.description, "string");
  }
});

test("mcp: ping returns empty result", () => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);
  const response = handleMcpRequest({ jsonrpc: "2.0", id: 7, method: "ping", params: {} }, registry, {});
  assert.deepEqual(response.result, {});
});

test("mcp: unknown method returns METHOD_NOT_FOUND", () => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);
  const response = handleMcpRequest(
    { jsonrpc: "2.0", id: 6, method: "resources/list", params: {} },
    registry,
    {}
  );
  assert.equal(response.error.code, JSONRPC_ERRORS.METHOD_NOT_FOUND.code);
});

test("mcp: invalid JSON-RPC version returns error", () => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);
  const response = handleMcpRequest({ jsonrpc: "1.0", id: 1, method: "ping" }, registry, {});
  assert.ok(response.error);
  assert.equal(response.error.code, JSONRPC_ERRORS.INVALID_REQUEST.code);
});

// ═══════════════════════════════════════════════════════════════════════════════
// MCP Tool Calls
// ═══════════════════════════════════════════════════════════════════════════════

test("mcp: tools/call loom_list_threads returns threads", () => {
  const { store, aliceKeys } = setupStore();
  const envelope = signBase(aliceKeys.privateKeyPem, "k_sign_alice_mcp_1");
  store.ingestEnvelope(envelope, { actorIdentity: "loom://alice@node.test" });

  const registry = createMcpToolRegistry(store);
  const context = { actorIdentity: "loom://alice@node.test" };

  const response = handleMcpRequest(
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "loom_list_threads", arguments: {} } },
    registry,
    context
  );
  assert.ok(response.result.content);
  const parsed = JSON.parse(response.result.content[0].text);
  assert.ok(Array.isArray(parsed.threads));
  assert.ok(parsed.threads.length >= 1);
});

test("mcp: tools/call loom_list_threads respects limit", () => {
  const { store, aliceKeys } = setupStore();
  for (let i = 0; i < 5; i++) {
    const env = signBase(aliceKeys.privateKeyPem, "k_sign_alice_mcp_1");
    store.ingestEnvelope(env, { actorIdentity: "loom://alice@node.test" });
  }

  const registry = createMcpToolRegistry(store);
  const context = { actorIdentity: "loom://alice@node.test" };

  const response = handleMcpRequest(
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "loom_list_threads", arguments: { limit: 2 } } },
    registry,
    context
  );
  const parsed = JSON.parse(response.result.content[0].text);
  assert.equal(parsed.threads.length, 2);
});

test("mcp: tools/call loom_send_envelope ingests envelope", () => {
  const { store, aliceKeys } = setupStore();
  const registry = createMcpToolRegistry(store);
  const context = { actorIdentity: "loom://alice@node.test" };

  const envelope = signBase(aliceKeys.privateKeyPem, "k_sign_alice_mcp_1");
  const response = handleMcpRequest(
    { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "loom_send_envelope", arguments: { envelope } } },
    registry,
    context
  );
  assert.ok(response.result.content);
  const parsed = JSON.parse(response.result.content[0].text);
  assert.equal(parsed.envelope_id, envelope.id);
  assert.equal(parsed.thread_id, envelope.thread_id);

  const stored = store.getEnvelope(envelope.id);
  assert.ok(stored);
});

test("mcp: tools/call loom_read_thread returns envelopes", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const env1 = signBase(aliceKeys.privateKeyPem, "k_sign_alice_mcp_1", { thread_id: threadId });
  store.ingestEnvelope(env1, { actorIdentity: "loom://alice@node.test" });

  const registry = createMcpToolRegistry(store);
  const context = { actorIdentity: "loom://alice@node.test" };

  const response = handleMcpRequest(
    { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "loom_read_thread", arguments: { thread_id: threadId } } },
    registry,
    context
  );
  const parsed = JSON.parse(response.result.content[0].text);
  assert.equal(parsed.thread_id, threadId);
  assert.ok(Array.isArray(parsed.envelopes));
  assert.ok(parsed.envelopes.length >= 1);
});

test("mcp: tools/call loom_read_thread returns error for missing thread", () => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);
  const context = { actorIdentity: "loom://alice@node.test" };

  const response = handleMcpRequest(
    { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "loom_read_thread", arguments: { thread_id: thrId() } } },
    registry,
    context
  );
  assert.ok(response.error);
  assert.equal(response.error.code, JSONRPC_ERRORS.INTERNAL_ERROR.code);
});

test("mcp: tools/call loom_search works", () => {
  const { store, aliceKeys } = setupStore();
  const envelope = signBase(aliceKeys.privateKeyPem, "k_sign_alice_mcp_1");
  store.ingestEnvelope(envelope, { actorIdentity: "loom://alice@node.test" });

  const registry = createMcpToolRegistry(store);
  const context = { actorIdentity: "loom://alice@node.test" };

  const response = handleMcpRequest(
    { jsonrpc: "2.0", id: 8, method: "tools/call", params: { name: "loom_search", arguments: { q: "hello" } } },
    registry,
    context
  );
  assert.ok(response.result.content);
  const parsed = JSON.parse(response.result.content[0].text);
  assert.ok(typeof parsed.total === "number");
  assert.ok(Array.isArray(parsed.results));
});

test("mcp: tools/call unknown tool returns error", () => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);
  const context = { actorIdentity: "loom://alice@node.test" };

  const response = handleMcpRequest(
    { jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "nonexistent_tool", arguments: {} } },
    registry,
    context
  );
  assert.ok(response.error);
  assert.equal(response.error.code, JSONRPC_ERRORS.INTERNAL_ERROR.code);
});

test("mcp: tools/call without tool name returns INVALID_PARAMS", () => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);
  const response = handleMcpRequest(
    { jsonrpc: "2.0", id: 10, method: "tools/call", params: {} },
    registry,
    {}
  );
  assert.ok(response.error);
  assert.equal(response.error.code, JSONRPC_ERRORS.INVALID_PARAMS.code);
});

test("mcp: tools/call loom_manage_capability list returns empty for new thread", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();
  const env = signBase(aliceKeys.privateKeyPem, "k_sign_alice_mcp_1", { thread_id: threadId });
  store.ingestEnvelope(env, { actorIdentity: "loom://alice@node.test" });

  const registry = createMcpToolRegistry(store);
  const context = { actorIdentity: "loom://alice@node.test" };

  const response = handleMcpRequest(
    {
      jsonrpc: "2.0",
      id: 11,
      method: "tools/call",
      params: { name: "loom_manage_capability", arguments: { action: "list", thread_id: threadId } }
    },
    registry,
    context
  );
  const parsed = JSON.parse(response.result.content[0].text);
  assert.ok(Array.isArray(parsed.capabilities));
});

// ═══════════════════════════════════════════════════════════════════════════════
// MCP Tool Registry Direct API
// ═══════════════════════════════════════════════════════════════════════════════

test("mcp: registry.hasTool returns true for registered tools", () => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);
  assert.ok(registry.hasTool("loom_send_envelope"));
  assert.ok(registry.hasTool("loom_read_thread"));
  assert.ok(!registry.hasTool("nonexistent"));
});

test("mcp: registry.getToolNames returns all tool names", () => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);
  const names = registry.getToolNames();
  assert.ok(names.includes("loom_send_envelope"));
  assert.ok(names.includes("loom_read_thread"));
  assert.ok(names.includes("loom_list_threads"));
  assert.ok(names.includes("loom_search"));
  assert.ok(names.includes("loom_manage_capability"));
  assert.ok(names.includes("loom_thread_operation"));
  assert.equal(names.length, 6);
});

// ═══════════════════════════════════════════════════════════════════════════════
// Stdio Transport
// ═══════════════════════════════════════════════════════════════════════════════

test("mcp: stdio transport processes newline-delimited JSON-RPC", (t, done) => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);

  const mockStdin = new Readable({ read() {} });
  const chunks = [];
  const mockStdout = new Writable({
    write(chunk, enc, cb) {
      chunks.push(chunk.toString());
      cb();
    }
  });

  const transport = startMcpStdioTransport(
    registry,
    { actorIdentity: "loom://alice@node.test" },
    { stdin: mockStdin, stdout: mockStdout }
  );

  mockStdin.push(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) + "\n");

  setTimeout(() => {
    assert.ok(chunks.length >= 1);
    const response = JSON.parse(chunks[0]);
    assert.equal(response.id, 1);
    assert.deepEqual(response.result, {});
    transport.close();
    done();
  }, 50);
});

test("mcp: stdio transport handles multiple messages in single chunk", (t, done) => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);

  const mockStdin = new Readable({ read() {} });
  const chunks = [];
  const mockStdout = new Writable({
    write(chunk, enc, cb) {
      chunks.push(chunk.toString());
      cb();
    }
  });

  const transport = startMcpStdioTransport(registry, { actorIdentity: "loom://alice@node.test" }, {
    stdin: mockStdin,
    stdout: mockStdout
  });

  const msg1 = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" });
  const msg2 = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  mockStdin.push(msg1 + "\n" + msg2 + "\n");

  setTimeout(() => {
    assert.ok(chunks.length >= 2);
    const r1 = JSON.parse(chunks[0]);
    const r2 = JSON.parse(chunks[1]);
    assert.equal(r1.id, 1);
    assert.equal(r2.id, 2);
    assert.ok(r2.result.tools);
    transport.close();
    done();
  }, 50);
});

test("mcp: stdio transport handles parse errors gracefully", (t, done) => {
  const { store } = setupStore();
  const registry = createMcpToolRegistry(store);

  const mockStdin = new Readable({ read() {} });
  const chunks = [];
  const mockStdout = new Writable({
    write(chunk, enc, cb) {
      chunks.push(chunk.toString());
      cb();
    }
  });

  const transport = startMcpStdioTransport(registry, {}, { stdin: mockStdin, stdout: mockStdout });
  mockStdin.push("not valid json\n");

  setTimeout(() => {
    assert.ok(chunks.length >= 1);
    const response = JSON.parse(chunks[0]);
    assert.equal(response.error.code, JSONRPC_ERRORS.PARSE_ERROR.code);
    transport.close();
    done();
  }, 50);
});

// ═══════════════════════════════════════════════════════════════════════════════
// Envelope Ingestion with MCP Intents
// ═══════════════════════════════════════════════════════════════════════════════

test("mcp: workflow envelope with mcp.tool_request@v1 intent ingests correctly", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  const msg = signBase(aliceKeys.privateKeyPem, "k_sign_alice_mcp_1", { thread_id: threadId });
  store.ingestEnvelope(msg, { actorIdentity: "loom://alice@node.test" });

  const toolReq = signBase(aliceKeys.privateKeyPem, "k_sign_alice_mcp_1", {
    thread_id: threadId,
    parent_id: msg.id,
    type: "workflow",
    content: {
      human: { text: "Requesting tool invocation", format: "markdown" },
      structured: {
        intent: MCP_INTENTS.TOOL_REQUEST,
        parameters: {
          tool_name: "loom_search",
          request_id: `mcp_req_${generateUlid()}`,
          arguments: { q: "test" }
        }
      },
      encrypted: false
    }
  });

  const stored = store.ingestEnvelope(toolReq, { actorIdentity: "loom://alice@node.test" });
  assert.equal(stored.type, "workflow");
  assert.equal(stored.content.structured.intent, "mcp.tool_request@v1");
});

test("mcp: workflow envelope with mcp.tool_response@v1 intent ingests correctly", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  const msg = signBase(aliceKeys.privateKeyPem, "k_sign_alice_mcp_1", { thread_id: threadId });
  store.ingestEnvelope(msg, { actorIdentity: "loom://alice@node.test" });

  const toolResp = signBase(aliceKeys.privateKeyPem, "k_sign_alice_mcp_1", {
    thread_id: threadId,
    parent_id: msg.id,
    type: "workflow",
    content: {
      human: { text: "Tool response", format: "markdown" },
      structured: {
        intent: MCP_INTENTS.TOOL_RESPONSE,
        parameters: {
          request_id: `mcp_req_${generateUlid()}`,
          result: { data: "search results" },
          is_error: false
        }
      },
      encrypted: false
    }
  });

  const stored = store.ingestEnvelope(toolResp, { actorIdentity: "loom://alice@node.test" });
  assert.equal(stored.type, "workflow");
  assert.equal(stored.content.structured.intent, "mcp.tool_response@v1");
});

test("mcp: envelope with mcp_execution_trace metadata ingests correctly", () => {
  const { store, aliceKeys } = setupStore();

  const env = signBase(aliceKeys.privateKeyPem, "k_sign_alice_mcp_1", {
    meta: {
      mcp_execution_trace: {
        steps: [
          {
            tool_name: "loom_search",
            invoked_at: new Date().toISOString(),
            duration_ms: 42,
            request_id: `mcp_req_${generateUlid()}`
          }
        ]
      }
    }
  });

  const stored = store.ingestEnvelope(env, { actorIdentity: "loom://alice@node.test" });
  assert.ok(stored.meta.mcp_execution_trace);
  assert.equal(stored.meta.mcp_execution_trace.steps.length, 1);
  assert.equal(stored.meta.mcp_execution_trace.steps[0].tool_name, "loom_search");
});

test("mcp: mcp intent on non-workflow type is rejected", () => {
  const { store, aliceKeys } = setupStore();
  const threadId = thrId();

  const msg = signBase(aliceKeys.privateKeyPem, "k_sign_alice_mcp_1", { thread_id: threadId });
  store.ingestEnvelope(msg, { actorIdentity: "loom://alice@node.test" });

  assert.throws(
    () => {
      const bad = signBase(aliceKeys.privateKeyPem, "k_sign_alice_mcp_1", {
        thread_id: threadId,
        parent_id: msg.id,
        type: "message",
        content: {
          human: { text: "bad", format: "markdown" },
          structured: { intent: "mcp.tool_request@v1", parameters: {} },
          encrypted: false
        }
      });
      store.ingestEnvelope(bad, { actorIdentity: "loom://alice@node.test" });
    },
    (err) => {
      assert.equal(err.code, "ENVELOPE_INVALID");
      return true;
    }
  );
});

// ═══════════════════════════════════════════════════════════════════════════════
// Protocol Capabilities
// ═══════════════════════════════════════════════════════════════════════════════

test("mcp: getProtocolCapabilities includes mcp section", () => {
  const { store } = setupStore();
  const caps = store.getProtocolCapabilities("example.com");
  assert.ok(caps.mcp);
  assert.equal(caps.mcp.supported, true);
  assert.equal(caps.mcp.protocol_version, "2024-11-05");
  assert.ok(Array.isArray(caps.mcp.transports));
  assert.ok(caps.mcp.transports.includes("sse"));
  assert.ok(caps.mcp.transports.includes("stdio"));
  assert.equal(caps.mcp.tools_url, "https://example.com/v1/mcp/tools");
  assert.equal(caps.mcp.sse_url, "https://example.com/v1/mcp/sse");
});

test("mcp: getProtocolCapabilities mcp urls are null without domain", () => {
  const { store } = setupStore();
  const caps = store.getProtocolCapabilities();
  assert.equal(caps.mcp.tools_url, null);
  assert.equal(caps.mcp.sse_url, null);
});
