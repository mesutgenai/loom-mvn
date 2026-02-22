// ─── MCP Execution Sandboxing for LOOM Protocol ─────────────────────────────
//
// Pure-function protocol module. No store or server dependencies.
// Provides tool classification, sandbox policy validation, argument/result
// size enforcement, permission checks, and execution context building for
// MCP tool invocations.

import { LoomError } from "./errors.js";

// ─── Tool Classification ────────────────────────────────────────────────────

export const MCP_TOOL_CLASSIFICATIONS = Object.freeze({
  loom_send_envelope: "write",
  loom_read_thread: "read",
  loom_list_threads: "read",
  loom_search: "read",
  loom_manage_capability: "write",
  loom_thread_operation: "write"
});

export function classifyTool(toolName) {
  return MCP_TOOL_CLASSIFICATIONS[toolName] || "unknown";
}

// ─── Default Sandbox Policy ─────────────────────────────────────────────────

export const DEFAULT_MCP_SANDBOX_POLICY = Object.freeze({
  max_argument_bytes: 256 * 1024,    // 256 KB
  max_result_bytes: 1024 * 1024,     // 1 MB
  execution_timeout_ms: 5000,        // 5 seconds
  rate_limit_per_actor: 60,          // calls per window
  rate_limit_window_ms: 60_000,      // 1 minute
  allow_write_tools: true,
  enforce_timeout: true
});

// ─── Policy Validation ──────────────────────────────────────────────────────

export function validateSandboxPolicy(policy) {
  const errors = [];
  if (!policy || typeof policy !== "object") {
    return [{ field: "policy", reason: "must be an object" }];
  }
  if (policy.max_argument_bytes != null) {
    if (typeof policy.max_argument_bytes !== "number" || policy.max_argument_bytes < 1024) {
      errors.push({ field: "max_argument_bytes", reason: "must be a number >= 1024" });
    }
  }
  if (policy.max_result_bytes != null) {
    if (typeof policy.max_result_bytes !== "number" || policy.max_result_bytes < 1024) {
      errors.push({ field: "max_result_bytes", reason: "must be a number >= 1024" });
    }
  }
  if (policy.execution_timeout_ms != null) {
    if (typeof policy.execution_timeout_ms !== "number" || policy.execution_timeout_ms < 100) {
      errors.push({ field: "execution_timeout_ms", reason: "must be a number >= 100" });
    }
  }
  if (policy.rate_limit_per_actor != null) {
    if (typeof policy.rate_limit_per_actor !== "number" || policy.rate_limit_per_actor < 1) {
      errors.push({ field: "rate_limit_per_actor", reason: "must be a positive integer" });
    }
  }
  if (policy.rate_limit_window_ms != null) {
    if (typeof policy.rate_limit_window_ms !== "number" || policy.rate_limit_window_ms < 1000) {
      errors.push({ field: "rate_limit_window_ms", reason: "must be >= 1000" });
    }
  }
  return errors;
}

// ─── Argument Size Check ────────────────────────────────────────────────────

export function checkArgumentSize(args, maxBytes) {
  const limit = maxBytes ?? DEFAULT_MCP_SANDBOX_POLICY.max_argument_bytes;
  if (args == null || (typeof args === "object" && Object.keys(args).length === 0)) {
    return { allowed: true, byte_count: 0, limit };
  }
  const serialized = JSON.stringify(args);
  const byteCount = Buffer.byteLength(serialized, "utf-8");
  if (byteCount > limit) {
    return { allowed: false, byte_count: byteCount, limit };
  }
  return { allowed: true, byte_count: byteCount, limit };
}

// ─── Result Size Check ──────────────────────────────────────────────────────

export function checkResultSize(result, maxBytes) {
  const limit = maxBytes ?? DEFAULT_MCP_SANDBOX_POLICY.max_result_bytes;
  if (result == null) {
    return { allowed: true, byte_count: 0, limit };
  }
  const serialized = JSON.stringify(result);
  const byteCount = Buffer.byteLength(serialized, "utf-8");
  if (byteCount > limit) {
    return { allowed: false, byte_count: byteCount, limit };
  }
  return { allowed: true, byte_count: byteCount, limit };
}

// ─── Permission Check ───────────────────────────────────────────────────────

export function checkToolPermission(toolName, sessionPermissions) {
  const classification = classifyTool(toolName);

  if (classification === "unknown") {
    return {
      allowed: false,
      reason: `Tool '${toolName}' has no classification — denied by default`,
      classification
    };
  }

  if (classification === "write" && sessionPermissions?.allow_write_tools === false) {
    return {
      allowed: false,
      reason: `Write tool '${toolName}' denied: session is read-only`,
      classification
    };
  }

  return { allowed: true, classification };
}

// ─── Assertion Wrappers ─────────────────────────────────────────────────────

export function assertArgumentSizeOrThrow(args, maxBytes) {
  const check = checkArgumentSize(args, maxBytes);
  if (!check.allowed) {
    throw new LoomError("PAYLOAD_TOO_LARGE",
      `Tool arguments exceed size limit: ${check.byte_count} bytes > ${check.limit} bytes`,
      413, {
        byte_count: check.byte_count,
        limit: check.limit,
        field: "arguments"
      });
  }
  return check;
}

export function assertResultSizeOrThrow(result, maxBytes) {
  const check = checkResultSize(result, maxBytes);
  if (!check.allowed) {
    throw new LoomError("PAYLOAD_TOO_LARGE",
      `Tool result exceeds size limit: ${check.byte_count} bytes > ${check.limit} bytes`,
      413, {
        byte_count: check.byte_count,
        limit: check.limit,
        field: "result"
      });
  }
  return check;
}

export function assertToolPermissionOrThrow(toolName, sessionPermissions) {
  const check = checkToolPermission(toolName, sessionPermissions);
  if (!check.allowed) {
    throw new LoomError("CAPABILITY_DENIED", check.reason, 403, {
      tool_name: toolName,
      classification: check.classification
    });
  }
  return check;
}

// ─── Execution Context Builder ──────────────────────────────────────────────

export function buildSandboxExecutionContext(toolName, args, policy, options = {}) {
  const effectivePolicy = {
    ...DEFAULT_MCP_SANDBOX_POLICY,
    ...(policy || {})
  };

  return {
    tool_name: toolName,
    classification: classifyTool(toolName),
    policy: effectivePolicy,
    actor_identity: options.actorIdentity || null,
    started_at: null,
    byte_count_args: null,
    byte_count_result: null,
    duration_ms: null,
    violation: null
  };
}
