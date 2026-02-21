import { LoomError } from "./errors.js";

// ─── MCP Protocol Constants ──────────────────────────────────────────────────

export const MCP_PROTOCOL_VERSION = "2024-11-05";

export const MCP_INTENTS = {
  TOOL_REQUEST: "mcp.tool_request@v1",
  TOOL_RESPONSE: "mcp.tool_response@v1"
};

// ─── JSON-RPC 2.0 ───────────────────────────────────────────────────────────

export const JSONRPC_VERSION = "2.0";

export const JSONRPC_ERRORS = {
  PARSE_ERROR: { code: -32700, message: "Parse error" },
  INVALID_REQUEST: { code: -32600, message: "Invalid Request" },
  METHOD_NOT_FOUND: { code: -32601, message: "Method not found" },
  INVALID_PARAMS: { code: -32602, message: "Invalid params" },
  INTERNAL_ERROR: { code: -32603, message: "Internal error" }
};

export function jsonrpcResponse(id, result) {
  return { jsonrpc: JSONRPC_VERSION, id, result };
}

export function jsonrpcError(id, errorObj, data) {
  return {
    jsonrpc: JSONRPC_VERSION,
    id: id ?? null,
    error: {
      code: errorObj.code,
      message: errorObj.message,
      ...(data !== undefined ? { data } : {})
    }
  };
}

export function parseJsonRpcRequest(raw) {
  if (!raw || typeof raw !== "object") {
    return { valid: false, error: JSONRPC_ERRORS.INVALID_REQUEST };
  }
  if (raw.jsonrpc !== JSONRPC_VERSION) {
    return { valid: false, error: JSONRPC_ERRORS.INVALID_REQUEST };
  }
  if (typeof raw.method !== "string" || raw.method.length === 0) {
    return { valid: false, error: JSONRPC_ERRORS.METHOD_NOT_FOUND };
  }
  return { valid: true, id: raw.id ?? null, method: raw.method, params: raw.params || {} };
}

// ─── MCP Tool Definition Validation ─────────────────────────────────────────

const TOOL_NAME_PATTERN = /^[a-z][a-z0-9_.-]{0,127}$/;

export function validateToolDefinition(tool) {
  const errors = [];
  if (!tool || typeof tool !== "object") {
    return [{ field: "tool", reason: "must be an object" }];
  }
  if (typeof tool.name !== "string" || tool.name.length === 0 || tool.name.length > 128) {
    errors.push({ field: "tool.name", reason: "must be a non-empty string (max 128 chars)" });
  } else if (!TOOL_NAME_PATTERN.test(tool.name)) {
    errors.push({ field: "tool.name", reason: "must match [a-z][a-z0-9_.-]* pattern" });
  }
  if (tool.description != null && typeof tool.description !== "string") {
    errors.push({ field: "tool.description", reason: "must be a string when present" });
  }
  if (tool.inputSchema != null && typeof tool.inputSchema !== "object") {
    errors.push({ field: "tool.inputSchema", reason: "must be a JSON Schema object when present" });
  }
  return errors;
}

// ─── Envelope Intent Parameter Validation ────────────────────────────────────

export function validateToolRequestParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    return [{ field: "parameters", reason: "must be an object" }];
  }
  if (typeof parameters.tool_name !== "string" || parameters.tool_name.length === 0) {
    errors.push({ field: "parameters.tool_name", reason: "must be a non-empty string" });
  }
  if (typeof parameters.request_id !== "string" || parameters.request_id.length === 0) {
    errors.push({ field: "parameters.request_id", reason: "must be a non-empty string" });
  }
  if (parameters.arguments != null && typeof parameters.arguments !== "object") {
    errors.push({ field: "parameters.arguments", reason: "must be an object when present" });
  }
  if (parameters.target_node != null && typeof parameters.target_node !== "string") {
    errors.push({ field: "parameters.target_node", reason: "must be a string when present" });
  }
  return errors;
}

export function validateToolResponseParameters(parameters) {
  const errors = [];
  if (!parameters || typeof parameters !== "object") {
    return [{ field: "parameters", reason: "must be an object" }];
  }
  if (typeof parameters.request_id !== "string" || parameters.request_id.length === 0) {
    errors.push({ field: "parameters.request_id", reason: "must be a non-empty string" });
  }
  if (parameters.result != null && typeof parameters.result !== "object") {
    errors.push({ field: "parameters.result", reason: "must be an object when present" });
  }
  if (parameters.is_error != null && typeof parameters.is_error !== "boolean") {
    errors.push({ field: "parameters.is_error", reason: "must be a boolean when present" });
  }
  if (parameters.error_message != null && typeof parameters.error_message !== "string") {
    errors.push({ field: "parameters.error_message", reason: "must be a string when present" });
  }
  return errors;
}

// ─── MCP Execution Trace Validation ──────────────────────────────────────────

const MAX_TRACE_STEPS = 50;

export function validateMcpExecutionTrace(trace) {
  const errors = [];
  if (!trace || typeof trace !== "object") {
    return [{ field: "meta.mcp_execution_trace", reason: "must be an object" }];
  }
  if (!Array.isArray(trace.steps)) {
    errors.push({ field: "meta.mcp_execution_trace.steps", reason: "must be an array" });
    return errors;
  }
  if (trace.steps.length > MAX_TRACE_STEPS) {
    errors.push({ field: "meta.mcp_execution_trace.steps", reason: `max ${MAX_TRACE_STEPS} steps` });
  }
  for (let i = 0; i < trace.steps.length; i++) {
    const step = trace.steps[i];
    if (!step || typeof step !== "object") {
      errors.push({ field: `meta.mcp_execution_trace.steps[${i}]`, reason: "must be an object" });
      continue;
    }
    if (typeof step.tool_name !== "string" || step.tool_name.length === 0) {
      errors.push({ field: `meta.mcp_execution_trace.steps[${i}].tool_name`, reason: "required non-empty string" });
    }
    if (typeof step.invoked_at !== "string" || step.invoked_at.length === 0) {
      errors.push({ field: `meta.mcp_execution_trace.steps[${i}].invoked_at`, reason: "must be ISO-8601 string" });
    }
    if (step.duration_ms != null && (typeof step.duration_ms !== "number" || step.duration_ms < 0)) {
      errors.push({ field: `meta.mcp_execution_trace.steps[${i}].duration_ms`, reason: "must be a non-negative number when present" });
    }
    if (step.request_id != null && typeof step.request_id !== "string") {
      errors.push({ field: `meta.mcp_execution_trace.steps[${i}].request_id`, reason: "must be a string when present" });
    }
  }
  return errors;
}
