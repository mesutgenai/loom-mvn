import { MCP_INTENTS, validateToolRequestParameters } from "../protocol/mcp.js";
import { signEnvelope, generateSigningKeyPair } from "../protocol/crypto.js";
import { generateUlid } from "../protocol/ulid.js";
import { DEFAULT_MCP_SANDBOX_POLICY } from "../protocol/mcp_sandbox.js";

// ─── Predicate ──────────────────────────────────────────────────────────────

export function isMcpToolRequestEnvelope(envelope) {
  return (
    envelope?.type === "workflow" &&
    envelope?.content?.structured?.intent === MCP_INTENTS.TOOL_REQUEST
  );
}

// ─── Response Envelope Builder ──────────────────────────────────────────────

export function buildMcpResponseEnvelope(requestEnvelope, responseParams, options) {
  return {
    loom: "1.1",
    id: `env_${generateUlid()}`,
    thread_id: requestEnvelope.thread_id,
    parent_id: requestEnvelope.id,
    type: "workflow",
    from: {
      identity: options.serviceIdentity,
      display: "MCP Service",
      key_id: options.serviceKeyId,
      type: "service"
    },
    to: [
      {
        identity: requestEnvelope.from.identity,
        role: "primary"
      }
    ],
    created_at: new Date().toISOString(),
    priority: requestEnvelope.priority || "normal",
    content: {
      human: {
        text: responseParams.is_error
          ? `MCP tool error: ${responseParams.error_message}`
          : `Tool response for ${responseParams.tool_name || "unknown"}`,
        format: "plaintext"
      },
      structured: {
        intent: MCP_INTENTS.TOOL_RESPONSE,
        parameters: {
          request_id: responseParams.request_id,
          result: responseParams.result ?? null,
          is_error: responseParams.is_error || false,
          ...(responseParams.error_message ? { error_message: responseParams.error_message } : {})
        }
      },
      encrypted: false
    },
    meta: responseParams.executionTrace
      ? { mcp_execution_trace: { steps: [responseParams.executionTrace] } }
      : {},
    attachments: []
  };
}

// ─── Main Processor ─────────────────────────────────────────────────────────

export function processMcpToolRequest(store, storedEnvelope, options) {
  if (!isMcpToolRequestEnvelope(storedEnvelope)) {
    return { processed: false };
  }

  const parameters = storedEnvelope.content.structured.parameters;

  // Check target_node — if specified, must match this node
  if (parameters.target_node && parameters.target_node !== store.nodeId) {
    return { processed: false };
  }

  const requestId = parameters.request_id || `mcp_req_${generateUlid()}`;
  const toolName = parameters.tool_name;

  // Validate request parameters
  const validationErrors = validateToolRequestParameters(parameters);
  if (validationErrors.length > 0) {
    const errorMsg = validationErrors.map((e) => `${e.field}: ${e.reason}`).join("; ");
    return ingestErrorResponse(store, storedEnvelope, requestId, toolName, `Invalid request: ${errorMsg}`, options);
  }

  // ── Sandbox: Rate limit check ─────────────────────────────────────────────
  const sandboxPolicy = options.sandboxPolicy || {};
  if (options.mcpRateLimiter) {
    const actorIdentity = storedEnvelope.from?.identity;
    const rateLimitResult = options.mcpRateLimiter.check(actorIdentity);
    if (!rateLimitResult.allowed) {
      if (options.onSandboxViolation) {
        options.onSandboxViolation({ type: "rate_limit_exceeded", tool_name: toolName, actor: actorIdentity, request_id: requestId });
      }
      return ingestErrorResponse(store, storedEnvelope, requestId, toolName,
        `Rate limit exceeded: ${rateLimitResult.remaining} remaining in window`, options);
    }
    options.mcpRateLimiter.record(actorIdentity);
  }

  // ── Sandbox: Argument size check ────────────────────────────────────────
  const maxArgBytes = sandboxPolicy.max_argument_bytes || DEFAULT_MCP_SANDBOX_POLICY.max_argument_bytes;
  const argsSerialized = JSON.stringify(parameters.arguments || {});
  const argByteCount = Buffer.byteLength(argsSerialized, "utf-8");
  if (argByteCount > maxArgBytes) {
    if (options.onSandboxViolation) {
      options.onSandboxViolation({ type: "argument_size_exceeded", tool_name: toolName, actor: storedEnvelope.from?.identity, request_id: requestId, details: { byte_count: argByteCount, limit: maxArgBytes } });
    }
    return ingestErrorResponse(store, storedEnvelope, requestId, toolName,
      `Arguments exceed size limit: ${argByteCount} bytes > ${maxArgBytes} bytes`, options);
  }

  // Check tool exists
  const registry = options.mcpToolRegistry;
  if (!registry.hasTool(toolName)) {
    return ingestErrorResponse(store, storedEnvelope, requestId, toolName, `Tool '${toolName}' not found`, options);
  }

  // Execute the tool
  const invokedAt = new Date().toISOString();
  const startMs = Date.now();
  let toolResult;
  let isError = false;
  let errorMessage;

  try {
    toolResult = registry.callTool(toolName, parameters.arguments || {}, {
      actorIdentity: storedEnvelope.from.identity
    });
  } catch (err) {
    isError = true;
    errorMessage = err?.message || "Tool execution failed";
    toolResult = null;
  }

  const durationMs = Date.now() - startMs;

  // ── Sandbox: Post-execution timeout check ───────────────────────────────
  const timeoutMs = sandboxPolicy.execution_timeout_ms || DEFAULT_MCP_SANDBOX_POLICY.execution_timeout_ms;
  if (!isError && durationMs > timeoutMs) {
    isError = true;
    errorMessage = `Tool execution exceeded timeout: ${durationMs}ms > ${timeoutMs}ms`;
    toolResult = null;
    if (options.onSandboxViolation) {
      options.onSandboxViolation({ type: "timeout_exceeded", tool_name: toolName, actor: storedEnvelope.from?.identity, request_id: requestId, details: { duration_ms: durationMs, timeout_ms: timeoutMs } });
    }
  }

  // ── Sandbox: Result size check ──────────────────────────────────────────
  if (!isError && toolResult != null) {
    const maxResultBytes = sandboxPolicy.max_result_bytes || DEFAULT_MCP_SANDBOX_POLICY.max_result_bytes;
    const resultSerialized = JSON.stringify(toolResult);
    const resultByteCount = Buffer.byteLength(resultSerialized, "utf-8");
    if (resultByteCount > maxResultBytes) {
      isError = true;
      errorMessage = `Result exceeds size limit: ${resultByteCount} bytes > ${maxResultBytes} bytes`;
      toolResult = null;
      if (options.onSandboxViolation) {
        options.onSandboxViolation({ type: "result_size_exceeded", tool_name: toolName, actor: storedEnvelope.from?.identity, request_id: requestId, details: { byte_count: resultByteCount, limit: maxResultBytes } });
      }
    }
  }

  // Ensure service identity is a thread participant
  ensureServiceParticipant(store, storedEnvelope.thread_id, options.serviceIdentity);

  // Build and sign the response
  const responseEnvelope = buildMcpResponseEnvelope(storedEnvelope, {
    request_id: requestId,
    tool_name: toolName,
    result: isError ? null : toolResult,
    is_error: isError,
    error_message: errorMessage,
    executionTrace: {
      tool_name: toolName,
      invoked_at: invokedAt,
      duration_ms: durationMs,
      request_id: requestId,
      sandbox: {
        argument_bytes: argByteCount,
        timeout_ms: timeoutMs,
        timed_out: durationMs > timeoutMs
      }
    }
  }, options);

  const signed = signEnvelope(responseEnvelope, options.servicePrivateKeyPem, options.serviceKeyId);

  const stored = store.ingestEnvelope(signed, {
    actorIdentity: options.serviceIdentity,
    _mcpClientResponse: true
  });

  return {
    processed: true,
    response_envelope_id: stored.id,
    is_error: isError
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function ensureServiceParticipant(store, threadId, serviceIdentity) {
  const thread = store.threadsById.get(threadId);
  if (thread && !store.isActiveParticipant(thread, serviceIdentity)) {
    thread.participants.push({
      identity: serviceIdentity,
      role: "participant",
      joined_at: new Date().toISOString(),
      left_at: null
    });
  }
}

function ingestErrorResponse(store, requestEnvelope, requestId, toolName, errorMessage, options) {
  ensureServiceParticipant(store, requestEnvelope.thread_id, options.serviceIdentity);

  const responseEnvelope = buildMcpResponseEnvelope(requestEnvelope, {
    request_id: requestId,
    tool_name: toolName,
    result: null,
    is_error: true,
    error_message: errorMessage,
    executionTrace: null
  }, options);

  const signed = signEnvelope(responseEnvelope, options.servicePrivateKeyPem, options.serviceKeyId);

  const stored = store.ingestEnvelope(signed, {
    actorIdentity: options.serviceIdentity,
    _mcpClientResponse: true
  });

  return {
    processed: true,
    response_envelope_id: stored.id,
    is_error: true
  };
}

// ─── MCP Tool Call Rate Limiter ──────────────────────────────────────────────

export function createMcpToolRateLimiter(maxPerWindow, windowMs) {
  const max = maxPerWindow || DEFAULT_MCP_SANDBOX_POLICY.rate_limit_per_actor;
  const window = windowMs || DEFAULT_MCP_SANDBOX_POLICY.rate_limit_window_ms;
  const actors = new Map();

  return {
    check(actorIdentity) {
      const key = String(actorIdentity || "anonymous");
      const now = Date.now();
      const cutoff = now - window;

      let timestamps = actors.get(key);
      if (timestamps) {
        timestamps = timestamps.filter((ts) => ts > cutoff);
        actors.set(key, timestamps);
      } else {
        timestamps = [];
      }

      const remaining = max - timestamps.length;
      return {
        allowed: remaining > 0,
        limit: max,
        remaining: Math.max(0, remaining),
        window_ms: window
      };
    },

    record(actorIdentity) {
      const key = String(actorIdentity || "anonymous");
      if (!actors.has(key)) {
        actors.set(key, []);
      }
      actors.get(key).push(Date.now());
    }
  };
}
