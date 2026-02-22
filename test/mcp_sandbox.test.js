import test from "node:test";
import assert from "node:assert/strict";

import {
  MCP_TOOL_CLASSIFICATIONS,
  classifyTool,
  DEFAULT_MCP_SANDBOX_POLICY,
  validateSandboxPolicy,
  checkArgumentSize,
  checkResultSize,
  checkToolPermission,
  assertArgumentSizeOrThrow,
  assertResultSizeOrThrow,
  assertToolPermissionOrThrow,
  buildSandboxExecutionContext
} from "../src/protocol/mcp_sandbox.js";

// ─── Tool Classification ────────────────────────────────────────────────────

test("MCP_TOOL_CLASSIFICATIONS is frozen", () => {
  assert.ok(Object.isFrozen(MCP_TOOL_CLASSIFICATIONS));
});

test("classifyTool returns read for loom_read_thread", () => {
  assert.equal(classifyTool("loom_read_thread"), "read");
});

test("classifyTool returns read for loom_list_threads", () => {
  assert.equal(classifyTool("loom_list_threads"), "read");
});

test("classifyTool returns read for loom_search", () => {
  assert.equal(classifyTool("loom_search"), "read");
});

test("classifyTool returns write for loom_send_envelope", () => {
  assert.equal(classifyTool("loom_send_envelope"), "write");
});

test("classifyTool returns write for loom_manage_capability", () => {
  assert.equal(classifyTool("loom_manage_capability"), "write");
});

test("classifyTool returns write for loom_thread_operation", () => {
  assert.equal(classifyTool("loom_thread_operation"), "write");
});

test("classifyTool returns unknown for unregistered tool", () => {
  assert.equal(classifyTool("evil_tool"), "unknown");
  assert.equal(classifyTool(""), "unknown");
  assert.equal(classifyTool(undefined), "unknown");
});

// ─── DEFAULT_MCP_SANDBOX_POLICY ─────────────────────────────────────────────

test("DEFAULT_MCP_SANDBOX_POLICY is frozen", () => {
  assert.ok(Object.isFrozen(DEFAULT_MCP_SANDBOX_POLICY));
});

test("DEFAULT_MCP_SANDBOX_POLICY has expected defaults", () => {
  assert.equal(DEFAULT_MCP_SANDBOX_POLICY.max_argument_bytes, 256 * 1024);
  assert.equal(DEFAULT_MCP_SANDBOX_POLICY.max_result_bytes, 1024 * 1024);
  assert.equal(DEFAULT_MCP_SANDBOX_POLICY.execution_timeout_ms, 5000);
  assert.equal(DEFAULT_MCP_SANDBOX_POLICY.rate_limit_per_actor, 60);
  assert.equal(DEFAULT_MCP_SANDBOX_POLICY.rate_limit_window_ms, 60000);
  assert.equal(DEFAULT_MCP_SANDBOX_POLICY.allow_write_tools, true);
  assert.equal(DEFAULT_MCP_SANDBOX_POLICY.enforce_timeout, true);
});

// ─── validateSandboxPolicy ──────────────────────────────────────────────────

test("validateSandboxPolicy accepts valid policy", () => {
  const errors = validateSandboxPolicy({
    max_argument_bytes: 2048,
    max_result_bytes: 4096,
    execution_timeout_ms: 1000,
    rate_limit_per_actor: 10,
    rate_limit_window_ms: 5000
  });
  assert.equal(errors.length, 0);
});

test("validateSandboxPolicy accepts empty policy (all defaults)", () => {
  const errors = validateSandboxPolicy({});
  assert.equal(errors.length, 0);
});

test("validateSandboxPolicy rejects non-object policy", () => {
  const errors = validateSandboxPolicy(null);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, "policy");
});

test("validateSandboxPolicy rejects max_argument_bytes below minimum", () => {
  const errors = validateSandboxPolicy({ max_argument_bytes: 512 });
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, "max_argument_bytes");
});

test("validateSandboxPolicy rejects max_result_bytes below minimum", () => {
  const errors = validateSandboxPolicy({ max_result_bytes: 100 });
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, "max_result_bytes");
});

test("validateSandboxPolicy rejects execution_timeout_ms below minimum", () => {
  const errors = validateSandboxPolicy({ execution_timeout_ms: 50 });
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, "execution_timeout_ms");
});

test("validateSandboxPolicy rejects rate_limit_per_actor below 1", () => {
  const errors = validateSandboxPolicy({ rate_limit_per_actor: 0 });
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, "rate_limit_per_actor");
});

test("validateSandboxPolicy rejects rate_limit_window_ms below 1000", () => {
  const errors = validateSandboxPolicy({ rate_limit_window_ms: 500 });
  assert.equal(errors.length, 1);
  assert.equal(errors[0].field, "rate_limit_window_ms");
});

// ─── checkArgumentSize ──────────────────────────────────────────────────────

test("checkArgumentSize allows null args", () => {
  const result = checkArgumentSize(null, 1024);
  assert.equal(result.allowed, true);
  assert.equal(result.byte_count, 0);
});

test("checkArgumentSize allows undefined args", () => {
  const result = checkArgumentSize(undefined, 1024);
  assert.equal(result.allowed, true);
  assert.equal(result.byte_count, 0);
});

test("checkArgumentSize allows empty object args", () => {
  const result = checkArgumentSize({}, 1024);
  assert.equal(result.allowed, true);
  assert.equal(result.byte_count, 0);
});

test("checkArgumentSize allows args within limit", () => {
  const args = { thread_id: "thr_test123" };
  const result = checkArgumentSize(args, 1024);
  assert.equal(result.allowed, true);
  assert.ok(result.byte_count > 0);
  assert.ok(result.byte_count <= 1024);
});

test("checkArgumentSize rejects args exceeding limit", () => {
  const args = { data: "x".repeat(2048) };
  const result = checkArgumentSize(args, 1024);
  assert.equal(result.allowed, false);
  assert.ok(result.byte_count > 1024);
});

test("checkArgumentSize measures multi-byte chars accurately", () => {
  // Each emoji is 4 bytes in UTF-8, 100 emojis = 400 bytes + JSON overhead ~11 = ~411 bytes
  const args = { text: "\u{1F600}".repeat(100) };
  const result = checkArgumentSize(args, 256);
  assert.equal(result.allowed, false);
  assert.ok(result.byte_count > 256);
});

test("checkArgumentSize uses default limit when maxBytes is null", () => {
  const result = checkArgumentSize({ x: "hello" }, null);
  assert.equal(result.allowed, true);
  assert.equal(result.limit, DEFAULT_MCP_SANDBOX_POLICY.max_argument_bytes);
});

// ─── checkResultSize ────────────────────────────────────────────────────────

test("checkResultSize allows null result", () => {
  const result = checkResultSize(null, 1024);
  assert.equal(result.allowed, true);
  assert.equal(result.byte_count, 0);
});

test("checkResultSize allows result within limit", () => {
  const data = { content: [{ type: "text", text: "ok" }] };
  const result = checkResultSize(data, 1024);
  assert.equal(result.allowed, true);
});

test("checkResultSize rejects result exceeding limit", () => {
  const data = { content: [{ type: "text", text: "x".repeat(2048) }] };
  const result = checkResultSize(data, 1024);
  assert.equal(result.allowed, false);
  assert.ok(result.byte_count > 1024);
});

// ─── assertArgumentSizeOrThrow ──────────────────────────────────────────────

test("assertArgumentSizeOrThrow does not throw for valid args", () => {
  const check = assertArgumentSizeOrThrow({ x: 1 }, 1024);
  assert.equal(check.allowed, true);
});

test("assertArgumentSizeOrThrow throws PAYLOAD_TOO_LARGE with correct fields", () => {
  const args = { data: "x".repeat(2048) };
  try {
    assertArgumentSizeOrThrow(args, 1024);
    assert.fail("should have thrown");
  } catch (err) {
    assert.equal(err.code, "PAYLOAD_TOO_LARGE");
    assert.equal(err.status, 413);
    assert.equal(err.details.field, "arguments");
    assert.ok(err.details.byte_count > 1024);
    assert.equal(err.details.limit, 1024);
  }
});

// ─── assertResultSizeOrThrow ────────────────────────────────────────────────

test("assertResultSizeOrThrow does not throw for valid result", () => {
  const check = assertResultSizeOrThrow({ ok: true }, 1024);
  assert.equal(check.allowed, true);
});

test("assertResultSizeOrThrow throws PAYLOAD_TOO_LARGE with correct fields", () => {
  const result = { data: "x".repeat(2048) };
  try {
    assertResultSizeOrThrow(result, 1024);
    assert.fail("should have thrown");
  } catch (err) {
    assert.equal(err.code, "PAYLOAD_TOO_LARGE");
    assert.equal(err.status, 413);
    assert.equal(err.details.field, "result");
    assert.ok(err.details.byte_count > 1024);
    assert.equal(err.details.limit, 1024);
  }
});

// ─── checkToolPermission ────────────────────────────────────────────────────

test("checkToolPermission allows read tool in read-only session", () => {
  const result = checkToolPermission("loom_read_thread", { allow_write_tools: false });
  assert.equal(result.allowed, true);
  assert.equal(result.classification, "read");
});

test("checkToolPermission allows read tool in read-write session", () => {
  const result = checkToolPermission("loom_list_threads", { allow_write_tools: true });
  assert.equal(result.allowed, true);
});

test("checkToolPermission allows write tool in read-write session", () => {
  const result = checkToolPermission("loom_send_envelope", { allow_write_tools: true });
  assert.equal(result.allowed, true);
  assert.equal(result.classification, "write");
});

test("checkToolPermission denies write tool in read-only session", () => {
  const result = checkToolPermission("loom_send_envelope", { allow_write_tools: false });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes("read-only"));
  assert.equal(result.classification, "write");
});

test("checkToolPermission denies unknown tool", () => {
  const result = checkToolPermission("evil_tool", { allow_write_tools: true });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes("no classification"));
  assert.equal(result.classification, "unknown");
});

test("checkToolPermission allows write tool when sessionPermissions is empty", () => {
  const result = checkToolPermission("loom_send_envelope", {});
  assert.equal(result.allowed, true);
});

test("checkToolPermission allows write tool when sessionPermissions is null", () => {
  const result = checkToolPermission("loom_send_envelope", null);
  assert.equal(result.allowed, true);
});

// ─── assertToolPermissionOrThrow ────────────────────────────────────────────

test("assertToolPermissionOrThrow does not throw for allowed tool", () => {
  const check = assertToolPermissionOrThrow("loom_read_thread", { allow_write_tools: false });
  assert.equal(check.allowed, true);
});

test("assertToolPermissionOrThrow throws CAPABILITY_DENIED for denied write tool", () => {
  try {
    assertToolPermissionOrThrow("loom_send_envelope", { allow_write_tools: false });
    assert.fail("should have thrown");
  } catch (err) {
    assert.equal(err.code, "CAPABILITY_DENIED");
    assert.equal(err.status, 403);
    assert.equal(err.details.tool_name, "loom_send_envelope");
    assert.equal(err.details.classification, "write");
  }
});

test("assertToolPermissionOrThrow throws CAPABILITY_DENIED for unknown tool", () => {
  try {
    assertToolPermissionOrThrow("evil_tool", {});
    assert.fail("should have thrown");
  } catch (err) {
    assert.equal(err.code, "CAPABILITY_DENIED");
    assert.equal(err.status, 403);
    assert.equal(err.details.tool_name, "evil_tool");
    assert.equal(err.details.classification, "unknown");
  }
});

// ─── buildSandboxExecutionContext ───────────────────────────────────────────

test("buildSandboxExecutionContext builds context with defaults", () => {
  const ctx = buildSandboxExecutionContext("loom_read_thread", {}, null);
  assert.equal(ctx.tool_name, "loom_read_thread");
  assert.equal(ctx.classification, "read");
  assert.equal(ctx.policy.max_argument_bytes, DEFAULT_MCP_SANDBOX_POLICY.max_argument_bytes);
  assert.equal(ctx.policy.execution_timeout_ms, DEFAULT_MCP_SANDBOX_POLICY.execution_timeout_ms);
  assert.equal(ctx.actor_identity, null);
  assert.equal(ctx.started_at, null);
  assert.equal(ctx.duration_ms, null);
  assert.equal(ctx.violation, null);
});

test("buildSandboxExecutionContext merges custom policy over defaults", () => {
  const ctx = buildSandboxExecutionContext("loom_send_envelope", {}, {
    max_argument_bytes: 4096,
    execution_timeout_ms: 1000
  });
  assert.equal(ctx.policy.max_argument_bytes, 4096);
  assert.equal(ctx.policy.execution_timeout_ms, 1000);
  // Defaults preserved for unspecified
  assert.equal(ctx.policy.max_result_bytes, DEFAULT_MCP_SANDBOX_POLICY.max_result_bytes);
});

test("buildSandboxExecutionContext populates tool_name and classification", () => {
  const ctx = buildSandboxExecutionContext("loom_manage_capability", {});
  assert.equal(ctx.tool_name, "loom_manage_capability");
  assert.equal(ctx.classification, "write");
});

test("buildSandboxExecutionContext accepts actorIdentity option", () => {
  const ctx = buildSandboxExecutionContext("loom_search", {}, null, {
    actorIdentity: "loom://alice@node.test"
  });
  assert.equal(ctx.actor_identity, "loom://alice@node.test");
});
