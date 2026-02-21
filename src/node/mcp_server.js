import {
  JSONRPC_ERRORS,
  jsonrpcResponse,
  jsonrpcError,
  parseJsonRpcRequest,
  MCP_PROTOCOL_VERSION
} from "../protocol/mcp.js";
import { LoomError } from "../protocol/errors.js";
import { LOOM_RELEASE_VERSION } from "../protocol/constants.js";
import { generateUlid } from "../protocol/ulid.js";

// ─── MCP Tool Registry ──────────────────────────────────────────────────────

export function createMcpToolRegistry(store, options = {}) {
  const tools = new Map();

  tools.set("loom_send_envelope", {
    name: "loom_send_envelope",
    description: "Submit a signed LOOM envelope to the node for ingestion into a thread.",
    inputSchema: {
      type: "object",
      properties: {
        envelope: {
          type: "object",
          description: "Complete signed LOOM v1.1 envelope"
        }
      },
      required: ["envelope"]
    },
    handler(params, context) {
      if (!params.envelope || typeof params.envelope !== "object") {
        throw new LoomError("ENVELOPE_INVALID", "envelope parameter is required", 400, {
          field: "envelope"
        });
      }
      const stored = store.ingestEnvelope(params.envelope, {
        actorIdentity: context.actorIdentity,
        capabilityPresentationToken: context.capabilityPresentationToken || null
      });
      return {
        content: [{ type: "text", text: JSON.stringify({ envelope_id: stored.id, thread_id: stored.thread_id }) }]
      };
    }
  });

  tools.set("loom_read_thread", {
    name: "loom_read_thread",
    description: "Read all envelopes in a thread, returned in canonical DAG order.",
    inputSchema: {
      type: "object",
      properties: {
        thread_id: { type: "string", description: "Thread ID (thr_...)" },
        after_snapshot: { type: "boolean", description: "When true, return only envelopes after the latest snapshot cutoff (plus the snapshot envelope itself). Defaults to false." }
      },
      required: ["thread_id"]
    },
    handler(params, context) {
      if (typeof params.thread_id !== "string" || params.thread_id.length === 0) {
        throw new LoomError("ENVELOPE_INVALID", "thread_id is required", 400, {
          field: "thread_id"
        });
      }
      const result = store.getThreadEnvelopesForIdentity(params.thread_id, context.actorIdentity, {
        capabilityTokenValue: context.capabilityPresentationToken || null,
        after_snapshot: params.after_snapshot === true
      });
      if (!result) {
        throw new LoomError("THREAD_NOT_FOUND", `Thread not found: ${params.thread_id}`, 404, {
          thread_id: params.thread_id
        });
      }
      return {
        content: [{ type: "text", text: JSON.stringify({ thread_id: params.thread_id, envelopes: result }) }]
      };
    }
  });

  tools.set("loom_list_threads", {
    name: "loom_list_threads",
    description: "List threads visible to the authenticated identity.",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "number", description: "Max threads to return (default 50, max 200)" }
      }
    },
    handler(params, context) {
      const threads = context.actorIdentity
        ? store.listThreadsForIdentity(context.actorIdentity)
        : store.listThreads();
      const limit = Math.max(1, Math.min(Number(params.limit) || 50, 200));
      return {
        content: [{ type: "text", text: JSON.stringify({ threads: threads.slice(0, limit) }) }]
      };
    }
  });

  tools.set("loom_search", {
    name: "loom_search",
    description: "Search envelopes by query, type, intent, sender, or time range.",
    inputSchema: {
      type: "object",
      properties: {
        q: { type: "string", description: "Full-text search query" },
        from: { type: "string", description: "Filter by sender identity" },
        type: { type: "string", description: "Filter by envelope type" },
        intent: { type: "string", description: "Filter by structured intent" },
        thread_id: { type: "string", description: "Filter by thread ID" },
        after: { type: "string", description: "ISO-8601 lower bound" },
        before: { type: "string", description: "ISO-8601 upper bound" },
        limit: { type: "number", description: "Max results (default 50, max 200)" }
      }
    },
    handler(params, context) {
      const result = store.searchEnvelopes(params, context.actorIdentity);
      return {
        content: [{ type: "text", text: JSON.stringify(result) }]
      };
    }
  });

  tools.set("loom_manage_capability", {
    name: "loom_manage_capability",
    description: "Issue, list, or revoke capability tokens for a thread.",
    inputSchema: {
      type: "object",
      properties: {
        action: { type: "string", enum: ["issue", "list", "revoke"], description: "Capability operation" },
        thread_id: { type: "string", description: "Thread ID (required for issue/list)" },
        issued_to: { type: "string", description: "Identity to issue to (for issue)" },
        grants: { type: "array", items: { type: "string" }, description: "Grant names (for issue)" },
        capability_id: { type: "string", description: "Capability ID (for revoke)" },
        single_use: { type: "boolean", description: "Single-use token (for issue)" },
        expires_at: { type: "string", description: "ISO-8601 expiry (for issue)" }
      },
      required: ["action"]
    },
    handler(params, context) {
      const action = String(params.action || "").trim();
      switch (action) {
        case "issue": {
          const token = store.issueCapabilityToken(
            {
              thread_id: params.thread_id,
              issued_to: params.issued_to,
              grants: params.grants || [],
              single_use: params.single_use || false,
              expires_at: params.expires_at || null
            },
            context.actorIdentity
          );
          return { content: [{ type: "text", text: JSON.stringify(token) }] };
        }
        case "list": {
          const tokens = store.listCapabilities(params.thread_id, context.actorIdentity);
          return { content: [{ type: "text", text: JSON.stringify({ capabilities: tokens }) }] };
        }
        case "revoke": {
          const result = store.revokeCapabilityToken(params.capability_id, context.actorIdentity);
          return { content: [{ type: "text", text: JSON.stringify(result) }] };
        }
        default:
          throw new LoomError("ENVELOPE_INVALID", `Unknown capability action: ${action}`, 400, {
            field: "action"
          });
      }
    }
  });

  tools.set("loom_thread_operation", {
    name: "loom_thread_operation",
    description:
      "Execute a thread operation (resolve, archive, lock, add/remove participant, etc.) by submitting a signed thread_op envelope.",
    inputSchema: {
      type: "object",
      properties: {
        envelope: {
          type: "object",
          description: "Signed thread_op envelope with content.structured.intent set to the desired operation"
        }
      },
      required: ["envelope"]
    },
    handler(params, context) {
      if (!params.envelope || typeof params.envelope !== "object") {
        throw new LoomError("ENVELOPE_INVALID", "envelope parameter is required", 400, {
          field: "envelope"
        });
      }
      if (params.envelope.type !== "thread_op") {
        throw new LoomError("ENVELOPE_INVALID", "loom_thread_operation requires type=thread_op", 400, {
          field: "type"
        });
      }
      const stored = store.ingestEnvelope(params.envelope, {
        actorIdentity: context.actorIdentity,
        capabilityPresentationToken: context.capabilityPresentationToken || null
      });
      return {
        content: [{ type: "text", text: JSON.stringify({ envelope_id: stored.id, thread_id: stored.thread_id }) }]
      };
    }
  });

  return {
    listTools() {
      return Array.from(tools.values()).map(({ name, description, inputSchema }) => ({
        name,
        description,
        inputSchema
      }));
    },

    callTool(name, args, context) {
      const tool = tools.get(name);
      if (!tool) {
        throw new LoomError("ENVELOPE_INVALID", `Unknown MCP tool: ${name}`, 400, {
          tool_name: name
        });
      }
      return tool.handler(args || {}, context || {});
    },

    hasTool(name) {
      return tools.has(name);
    },

    getToolNames() {
      return Array.from(tools.keys());
    }
  };
}

// ─── MCP JSON-RPC Message Handler ────────────────────────────────────────────

export function handleMcpRequest(request, registry, sessionContext) {
  const parsed = parseJsonRpcRequest(request);
  if (!parsed.valid) {
    return jsonrpcError(request?.id ?? null, parsed.error);
  }

  const { id, method, params } = parsed;
  const isNotification = id === undefined || id === null;

  try {
    switch (method) {
      case "initialize": {
        const result = {
          protocolVersion: MCP_PROTOCOL_VERSION,
          capabilities: {
            tools: { listChanged: false }
          },
          serverInfo: {
            name: "loom-mcp-server",
            version: LOOM_RELEASE_VERSION
          }
        };
        return isNotification ? null : jsonrpcResponse(id, result);
      }

      case "initialized":
        return null;

      case "tools/list": {
        const toolList = registry.listTools();
        return isNotification ? null : jsonrpcResponse(id, { tools: toolList });
      }

      case "tools/call": {
        const toolName = params?.name;
        const toolArgs = params?.arguments || {};
        if (!toolName || typeof toolName !== "string") {
          return jsonrpcError(id, JSONRPC_ERRORS.INVALID_PARAMS, "Missing or invalid tool name");
        }
        const result = registry.callTool(toolName, toolArgs, sessionContext);
        return isNotification ? null : jsonrpcResponse(id, result);
      }

      case "ping":
        return isNotification ? null : jsonrpcResponse(id, {});

      default:
        return jsonrpcError(id, JSONRPC_ERRORS.METHOD_NOT_FOUND, `Unknown method: ${method}`);
    }
  } catch (error) {
    if (error instanceof LoomError) {
      return jsonrpcError(id, JSONRPC_ERRORS.INTERNAL_ERROR, {
        code: error.code,
        message: error.message,
        details: error.details
      });
    }
    return jsonrpcError(id, JSONRPC_ERRORS.INTERNAL_ERROR, error?.message || "Unknown error");
  }
}

// ─── Stdio Transport ─────────────────────────────────────────────────────────

export function startMcpStdioTransport(registry, sessionContext, options = {}) {
  const stdin = options.stdin || process.stdin;
  const stdout = options.stdout || process.stdout;
  let buffer = "";

  function sendResponse(response) {
    if (response) {
      stdout.write(JSON.stringify(response) + "\n");
    }
  }

  stdin.setEncoding("utf-8");

  function onData(chunk) {
    buffer += chunk;
    let newlineIdx;
    while ((newlineIdx = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, newlineIdx).trim();
      buffer = buffer.slice(newlineIdx + 1);
      if (!line) {
        continue;
      }

      let request;
      try {
        request = JSON.parse(line);
      } catch {
        sendResponse(jsonrpcError(null, JSONRPC_ERRORS.PARSE_ERROR));
        continue;
      }

      const response = handleMcpRequest(request, registry, sessionContext);
      sendResponse(response);
    }
  }

  stdin.on("data", onData);

  return {
    close() {
      stdin.removeListener("data", onData);
    }
  };
}

// ─── SSE Transport ───────────────────────────────────────────────────────────

export function createMcpSseSession(options) {
  const registry = options.registry;
  const sessionContext = options.sessionContext;
  const sessionId = `mcp_${generateUlid()}`;
  let sseRes = null;

  function handleSse(req, res) {
    res.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
      "x-loom-mcp-session": sessionId
    });
    res.write(`event: endpoint\ndata: /v1/mcp/message?session_id=${sessionId}\n\n`);
    sseRes = res;

    req.on("close", () => {
      sseRes = null;
    });
  }

  function handleMessage(jsonRpcRequest) {
    const response = handleMcpRequest(jsonRpcRequest, registry, sessionContext);
    if (response && sseRes && !sseRes.writableEnded) {
      sseRes.write(`event: message\ndata: ${JSON.stringify(response)}\n\n`);
    }
    return response;
  }

  return { handleSse, handleMessage, sessionId };
}
