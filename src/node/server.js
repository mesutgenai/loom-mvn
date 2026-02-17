import { createServer } from "node:http";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { BlockList, isIP } from "node:net";

import { toErrorResponse, LoomError } from "../protocol/errors.js";
import { LoomStore } from "./store.js";
import { renderDashboardHtml } from "./ui.js";

const DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024;
const DEFAULT_RATE_LIMIT_WINDOW_MS = 60 * 1000;
const DEFAULT_RATE_LIMIT_DEFAULT_MAX = 2000;
const DEFAULT_RATE_LIMIT_SENSITIVE_MAX = 120;

function parsePositiveNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function parseBoolean(value, fallback = false) {
  if (value == null) {
    return fallback;
  }

  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }

  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }

  return fallback;
}

function normalizeLogFormat(value, fallback = "json") {
  const normalized = String(value || fallback)
    .trim()
    .toLowerCase();
  if (normalized === "text") {
    return "text";
  }
  return "json";
}

function getIdempotencyKey(req) {
  const key =
    req.headers["idempotency-key"] ||
    req.headers["x-idempotency-key"] ||
    req.headers["x-loom-idempotency-key"];

  if (Array.isArray(key)) {
    return key[0] || null;
  }

  if (typeof key !== "string") {
    return null;
  }

  const trimmed = key.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function computeRequestPayloadHash(method, path, payload) {
  return createHash("sha256")
    .update(`${method}\n${path}\n${JSON.stringify(payload || {})}`, "utf-8")
    .digest("hex");
}

function createIdempotencyContext(req, store, actorIdentity, method, path, payload) {
  const key = getIdempotencyKey(req);
  if (!key || !actorIdentity) {
    return null;
  }

  const scope = `actor:${actorIdentity}:${method}:${path}`;
  const requestHash = computeRequestPayloadHash(method, path, payload);
  const replay = store.getIdempotencyResponse(scope, key, requestHash);
  return {
    key,
    scope,
    request_hash: requestHash,
    replay
  };
}

function maybeSendIdempotentReplay(res, context) {
  if (!context?.replay) {
    return false;
  }

  res.setHeader("x-loom-idempotency-replay", "true");
  sendJson(res, context.replay.status, context.replay.body);
  return true;
}

function storeIdempotentResult(store, context, status, body) {
  if (!context) {
    return;
  }

  store.storeIdempotencyResponse(context.scope, context.key, context.request_hash, status, body);
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body).toString()
  });
  res.end(body);
}

function sendHtml(res, status, html) {
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": Buffer.byteLength(html).toString()
  });
  res.end(html);
}

function sendText(res, status, text, contentType = "text/plain; version=0.0.4; charset=utf-8") {
  res.writeHead(status, {
    "content-type": contentType,
    "content-length": Buffer.byteLength(text).toString()
  });
  res.end(text);
}

async function readJson(req, maxBodyBytes) {
  const raw = await readRawBody(req, maxBodyBytes);
  if (!raw) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw new LoomError("ENVELOPE_INVALID", "Request body must be valid JSON", 400, {
      field: "body"
    });
  }
}

async function readRawBody(req, maxBodyBytes = DEFAULT_MAX_BODY_BYTES) {
  const chunks = [];
  let totalBytes = 0;
  for await (const chunk of req) {
    chunks.push(chunk);
    totalBytes += chunk.length;

    if (maxBodyBytes > 0 && totalBytes > maxBodyBytes) {
      throw new LoomError("PAYLOAD_TOO_LARGE", `Request body exceeds ${maxBodyBytes} bytes`, 413, {
        max_body_bytes: maxBodyBytes
      });
    }
  }

  if (chunks.length === 0) {
    return "";
  }

  return Buffer.concat(chunks).toString("utf-8");
}

function requestPath(req) {
  return new URL(req.url, `http://${req.headers.host || "localhost"}`).pathname;
}

function requestUrl(req) {
  return new URL(req.url, `http://${req.headers.host || "localhost"}`);
}

function methodIs(req, method) {
  return req.method?.toUpperCase() === method;
}

function resolveDelegationRequiredActionsForRoute(path, envelope) {
  const type = typeof envelope?.type === "string" ? envelope.type.trim() : "";
  if (path === "/v1/envelopes") {
    if (!type) {
      return ["message.send@v1", "message.general@v1"];
    }
    if (type === "thread_op") {
      return ["thread.op.execute@v1"];
    }
    return [`${type}.send@v1`, `${type}.general@v1`];
  }

  if (path.startsWith("/v1/threads/") && path.endsWith("/ops")) {
    return ["thread.op.execute@v1"];
  }

  return [];
}

function normalizeIpLiteral(value) {
  const raw = String(value || "")
    .trim()
    .replace(/^\[|\]$/g, "")
    .split("%")[0]
    .trim()
    .toLowerCase();
  if (!raw) {
    return "";
  }
  if (raw.startsWith("::ffff:")) {
    const mapped = raw.slice("::ffff:".length);
    if (isIP(mapped) === 4) {
      return mapped;
    }
  }
  return raw;
}

function parseTrustedProxyAllowlist(value) {
  if (value == null) {
    return [];
  }

  if (Array.isArray(value)) {
    return value
      .map((entry) => String(entry || "").trim())
      .filter(Boolean);
  }

  return String(value)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function buildTrustedProxyBlockList(entries) {
  const blockList = new BlockList();

  for (const entry of entries) {
    const [rawAddress, rawPrefix] = entry.split("/");
    const address = normalizeIpLiteral(rawAddress);
    const family = isIP(address);

    if (!family) {
      throw new Error(`Invalid LOOM_TRUST_PROXY_ALLOWLIST entry: ${entry}`);
    }

    const type = family === 6 ? "ipv6" : "ipv4";
    if (rawPrefix != null && rawPrefix !== "") {
      const prefix = Number(rawPrefix);
      const maxPrefix = family === 6 ? 128 : 32;
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
        throw new Error(`Invalid LOOM_TRUST_PROXY_ALLOWLIST CIDR prefix: ${entry}`);
      }
      blockList.addSubnet(address, prefix, type);
      continue;
    }

    blockList.addAddress(address, type);
  }

  return blockList;
}

function resolveTrustedProxyConfig(options = {}) {
  const rawTrustProxy = options.trustProxy;
  const rawAllowlist = options.trustProxyAllowlist;
  const allowlistFromTrustProxy =
    typeof rawTrustProxy === "string" && !["1", "true", "yes", "on", "0", "false", "no", "off"].includes(rawTrustProxy.trim().toLowerCase())
      ? rawTrustProxy
      : null;
  const enabled = parseBoolean(rawTrustProxy, false) || Boolean(allowlistFromTrustProxy);
  const allowlist = [
    ...parseTrustedProxyAllowlist(allowlistFromTrustProxy),
    ...parseTrustedProxyAllowlist(rawAllowlist)
  ];

  if (!enabled) {
    return {
      enabled: false,
      trustAll: false,
      allowlist: [],
      blockList: null
    };
  }

  if (allowlist.length === 0) {
    return {
      enabled: true,
      trustAll: true,
      allowlist: [],
      blockList: null
    };
  }

  return {
    enabled: true,
    trustAll: false,
    allowlist,
    blockList: buildTrustedProxyBlockList(allowlist)
  };
}

function canTrustProxyHeaders(req, trustProxyConfig) {
  if (!trustProxyConfig?.enabled) {
    return false;
  }

  if (trustProxyConfig.trustAll) {
    return true;
  }

  const remoteAddress = normalizeIpLiteral(req.socket?.remoteAddress || "");
  const family = isIP(remoteAddress);
  if (!family) {
    return false;
  }

  return trustProxyConfig.blockList.check(remoteAddress, family === 6 ? "ipv6" : "ipv4");
}

function extractForwardedClientIp(req) {
  const forwardedFor = req.headers["x-forwarded-for"];
  if (typeof forwardedFor !== "string" || !forwardedFor.trim()) {
    return null;
  }

  const [first] = forwardedFor.split(",");
  if (!first || !first.trim()) {
    return null;
  }

  let candidate = first.trim().replace(/^for=/i, "");
  if (candidate.startsWith('"') && candidate.endsWith('"')) {
    candidate = candidate.slice(1, -1);
  }

  if (candidate.startsWith("[") && candidate.includes("]")) {
    const closing = candidate.indexOf("]");
    candidate = candidate.slice(1, closing);
  } else {
    const maybeIpv4Port = candidate.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/);
    if (maybeIpv4Port) {
      candidate = maybeIpv4Port[1];
    }
  }

  const normalized = normalizeIpLiteral(candidate);
  return isIP(normalized) > 0 ? normalized : null;
}

function resolveClientIp(req, options = {}) {
  const directIp = normalizeIpLiteral(req.socket?.remoteAddress || "") || "unknown";
  const trustProxy = options.trustProxyConfig || null;

  if (!canTrustProxyHeaders(req, trustProxy)) {
    return directIp;
  }

  const forwardedIp = extractForwardedClientIp(req);
  return forwardedIp || directIp;
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") {
    return false;
  }

  const leftBuffer = Buffer.from(left, "utf-8");
  const rightBuffer = Buffer.from(right, "utf-8");
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

function isSensitiveRoute(method, path) {
  if (method !== "POST") {
    return false;
  }

  if (
    path === "/v1/identity" ||
    path === "/v1/auth/challenge" ||
    path === "/v1/auth/token" ||
    path === "/v1/auth/refresh" ||
    path === "/v1/bridge/email/inbound" ||
    path === "/v1/bridge/email/send" ||
    path === "/v1/gateway/smtp/submit" ||
    path === "/v1/email/outbox" ||
    path === "/v1/email/outbox/process" ||
    path === "/v1/outbox/dlq/requeue" ||
    path === "/v1/admin/persistence/restore" ||
    path === "/v1/webhooks" ||
    path === "/v1/webhooks/outbox/process" ||
    path === "/v1/federation/deliver" ||
    path === "/v1/federation/challenge" ||
    path === "/v1/federation/outbox/process" ||
    path === "/v1/federation/nodes/bootstrap" ||
    path.startsWith("/v1/mailbox/threads/") ||
    path === "/v1/envelopes"
  ) {
    return true;
  }

  if (path.startsWith("/v1/threads/") && path.endsWith("/ops")) {
    return true;
  }

  if (path.startsWith("/v1/federation/outbox/") && path.endsWith("/process")) {
    return true;
  }

  if (path.startsWith("/v1/email/outbox/") && path.endsWith("/process")) {
    return true;
  }

  if (path.startsWith("/v1/webhooks/outbox/") && path.endsWith("/process")) {
    return true;
  }

  return false;
}

function createRateLimiter(config) {
  const stateByKey = new Map();
  let requestCounter = 0;

  const windowMs = parsePositiveNumber(config.windowMs, DEFAULT_RATE_LIMIT_WINDOW_MS);
  const defaultMax = parsePositiveNumber(config.defaultMax, DEFAULT_RATE_LIMIT_DEFAULT_MAX);
  const sensitiveMax = parsePositiveNumber(config.sensitiveMax, DEFAULT_RATE_LIMIT_SENSITIVE_MAX);
  const trustProxyConfig = config.trustProxyConfig || {
    enabled: false,
    trustAll: false,
    allowlist: [],
    blockList: null
  };
  const enabled = windowMs > 0 && (defaultMax > 0 || sensitiveMax > 0);

  function sweep(nowMs) {
    const staleThreshold = nowMs - windowMs * 2;
    for (const [key, entry] of stateByKey.entries()) {
      if (entry.window_started_at < staleThreshold) {
        stateByKey.delete(key);
      }
    }
  }

  return {
    enabled,
    enforce(req, path) {
      if (!enabled) {
        return;
      }

      const method = String(req.method || "GET").toUpperCase();
      const sensitive = isSensitiveRoute(method, path);
      const max = sensitive ? sensitiveMax : defaultMax;
      if (max <= 0) {
        return;
      }

      const ip = resolveClientIp(req, { trustProxyConfig });
      const bucket = sensitive ? "sensitive" : "default";
      const key = `${bucket}:${ip}`;
      const now = Date.now();
      const current = stateByKey.get(key);

      if (!current || now - current.window_started_at >= windowMs) {
        stateByKey.set(key, {
          count: 1,
          window_started_at: now
        });
      } else if (current.count >= max) {
        const retryAfterMs = Math.max(1, current.window_started_at + windowMs - now);
        throw new LoomError("RATE_LIMIT_EXCEEDED", "Rate limit exceeded", 429, {
          limit: max,
          window_ms: windowMs,
          retry_after_ms: retryAfterMs,
          scope: bucket
        });
      } else {
        current.count += 1;
      }

      requestCounter += 1;
      if (requestCounter % 200 === 0) {
        sweep(now);
      }
    }
  };
}

function getBearerToken(req) {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return null;
  }

  const [scheme, token] = String(authorization).split(" ");
  if (!scheme || scheme.toLowerCase() !== "bearer" || !token) {
    return null;
  }

  return token;
}

function getCapabilityPresentationToken(req) {
  const raw = req.headers["x-loom-capability-token"];
  if (Array.isArray(raw)) {
    return raw[0] || null;
  }
  if (typeof raw !== "string") {
    return null;
  }
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function requireActorIdentity(req, store) {
  const token = getBearerToken(req);
  const session = store.authenticateAccessToken(token);
  return session.identity;
}

function resolveOptionalActorIdentity(req, store) {
  const token = getBearerToken(req);
  if (!token) {
    return null;
  }
  const session = store.authenticateAccessToken(token);
  return session.identity;
}

function getAdminToken(req) {
  const value = req.headers["x-loom-admin-token"];
  if (Array.isArray(value)) {
    return value[0] || null;
  }
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function requireAdminToken(req, adminToken) {
  if (!adminToken) {
    throw new LoomError("ENVELOPE_NOT_FOUND", "Route not found", 404, {
      method: req.method,
      path: requestPath(req)
    });
  }

  const provided = getAdminToken(req);
  if (!provided || !constantTimeEqual(provided, adminToken)) {
    throw new LoomError("CAPABILITY_DENIED", "Admin token required", 403, {
      field: "x-loom-admin-token"
    });
  }
}

function assertRouteEnabled(enabled, req, path) {
  if (enabled) {
    return;
  }

  throw new LoomError("ENVELOPE_NOT_FOUND", "Route not found", 404, {
    method: req.method,
    path
  });
}

function statusClass(status) {
  const value = Number(status);
  if (!Number.isFinite(value) || value < 100) {
    return "unknown";
  }
  return `${Math.floor(value / 100)}xx`;
}

function createOperationalMetrics() {
  const startedAtMs = Date.now();
  let requestsTotal = 0;
  let inFlight = 0;
  let durationMsTotal = 0;
  let durationMsMax = 0;

  const statusCounts = new Map();
  const errorCounts = new Map();

  return {
    onRequestStart() {
      requestsTotal += 1;
      inFlight += 1;
    },

    onRequestFinish({ status, errorCode, durationMs }) {
      inFlight = Math.max(0, inFlight - 1);

      const classLabel = statusClass(status);
      statusCounts.set(classLabel, (statusCounts.get(classLabel) || 0) + 1);

      if (errorCode) {
        errorCounts.set(errorCode, (errorCounts.get(errorCode) || 0) + 1);
      }

      const duration = Number(durationMs);
      if (Number.isFinite(duration) && duration >= 0) {
        durationMsTotal += duration;
        if (duration > durationMsMax) {
          durationMsMax = duration;
        }
      }
    },

    snapshot() {
      const uptimeMs = Math.max(0, Date.now() - startedAtMs);
      const requestsCompleted = Array.from(statusCounts.values()).reduce((sum, value) => sum + value, 0);

      return {
        started_at: new Date(startedAtMs).toISOString(),
        uptime_ms: uptimeMs,
        uptime_s: Math.floor(uptimeMs / 1000),
        requests_total: requestsTotal,
        requests_in_flight: inFlight,
        requests_completed: requestsCompleted,
        status_counts: Object.fromEntries(statusCounts),
        error_counts: Object.fromEntries(errorCounts),
        request_duration_ms_sum: durationMsTotal,
        request_duration_ms_count: requestsCompleted,
        request_duration_ms_max: durationMsMax
      };
    }
  };
}

function formatMetricsPrometheus(
  snapshot,
  federationOutbox,
  emailOutbox,
  webhookOutbox,
  idempotencyStatus,
  federationInboundPolicy,
  runtimeStatus,
  emailRelayStatus = null
) {
  const lines = [];
  lines.push("# HELP loom_requests_total Total number of HTTP requests.");
  lines.push("# TYPE loom_requests_total counter");
  lines.push(`loom_requests_total ${snapshot.requests_total}`);

  lines.push("# HELP loom_requests_in_flight Number of requests currently in flight.");
  lines.push("# TYPE loom_requests_in_flight gauge");
  lines.push(`loom_requests_in_flight ${snapshot.requests_in_flight}`);

  lines.push("# HELP loom_responses_total Total number of responses by status class.");
  lines.push("# TYPE loom_responses_total counter");
  for (const [classLabel, count] of Object.entries(snapshot.status_counts || {})) {
    lines.push(`loom_responses_total{status_class="${classLabel}"} ${count}`);
  }

  lines.push("# HELP loom_errors_total Total number of error responses by protocol error code.");
  lines.push("# TYPE loom_errors_total counter");
  for (const [code, count] of Object.entries(snapshot.error_counts || {})) {
    lines.push(`loom_errors_total{code="${code}"} ${count}`);
  }

  lines.push("# HELP loom_request_duration_ms_sum Cumulative request duration in milliseconds.");
  lines.push("# TYPE loom_request_duration_ms_sum counter");
  lines.push(`loom_request_duration_ms_sum ${snapshot.request_duration_ms_sum}`);

  lines.push("# HELP loom_request_duration_ms_count Number of completed requests with duration.");
  lines.push("# TYPE loom_request_duration_ms_count counter");
  lines.push(`loom_request_duration_ms_count ${snapshot.request_duration_ms_count}`);

  lines.push("# HELP loom_request_duration_ms_max Max request duration in milliseconds.");
  lines.push("# TYPE loom_request_duration_ms_max gauge");
  lines.push(`loom_request_duration_ms_max ${snapshot.request_duration_ms_max}`);

  lines.push("# HELP loom_uptime_seconds Process uptime in seconds.");
  lines.push("# TYPE loom_uptime_seconds gauge");
  lines.push(`loom_uptime_seconds ${snapshot.uptime_s}`);

  lines.push("# HELP loom_federation_outbox_total Total federation outbox items.");
  lines.push("# TYPE loom_federation_outbox_total gauge");
  lines.push(`loom_federation_outbox_total ${federationOutbox.total}`);
  lines.push(`loom_federation_outbox_queued ${federationOutbox.queued}`);
  lines.push(`loom_federation_outbox_delivered ${federationOutbox.delivered}`);
  lines.push(`loom_federation_outbox_failed ${federationOutbox.failed}`);
  lines.push(`loom_federation_outbox_retry_scheduled ${federationOutbox.retry_scheduled}`);

  lines.push("# HELP loom_email_outbox_total Total outbound email outbox items.");
  lines.push("# TYPE loom_email_outbox_total gauge");
  lines.push(`loom_email_outbox_total ${emailOutbox.total}`);
  lines.push(`loom_email_outbox_queued ${emailOutbox.queued}`);
  lines.push(`loom_email_outbox_delivered ${emailOutbox.delivered}`);
  lines.push(`loom_email_outbox_failed ${emailOutbox.failed}`);
  lines.push(`loom_email_outbox_retry_scheduled ${emailOutbox.retry_scheduled}`);

  lines.push("# HELP loom_webhook_outbox_total Total webhook outbox items.");
  lines.push("# TYPE loom_webhook_outbox_total gauge");
  lines.push(`loom_webhook_outbox_total ${webhookOutbox.total}`);
  lines.push(`loom_webhook_outbox_queued ${webhookOutbox.queued}`);
  lines.push(`loom_webhook_outbox_delivered ${webhookOutbox.delivered}`);
  lines.push(`loom_webhook_outbox_failed ${webhookOutbox.failed}`);
  lines.push(`loom_webhook_outbox_retry_scheduled ${webhookOutbox.retry_scheduled}`);

  if (idempotencyStatus) {
    lines.push("# HELP loom_idempotency_entries Number of active idempotency records.");
    lines.push("# TYPE loom_idempotency_entries gauge");
    lines.push(`loom_idempotency_entries ${Number(idempotencyStatus.entries || 0)}`);
    lines.push(`loom_idempotency_ttl_ms ${Number(idempotencyStatus.ttl_ms || 0)}`);
    lines.push(`loom_idempotency_max_entries ${Number(idempotencyStatus.max_entries || 0)}`);
  }

  if (federationInboundPolicy) {
    lines.push("# HELP loom_federation_inbound_tracked_nodes Number of nodes in federation inbound limiter state.");
    lines.push("# TYPE loom_federation_inbound_tracked_nodes gauge");
    lines.push(`loom_federation_inbound_tracked_nodes ${Number(federationInboundPolicy.tracked_nodes || 0)}`);
    lines.push(`loom_federation_inbound_rate_limit_window_ms ${Number(federationInboundPolicy.rate_limit_window_ms || 0)}`);
    lines.push(`loom_federation_inbound_rate_limit_max ${Number(federationInboundPolicy.rate_limit_max || 0)}`);
    lines.push(
      `loom_federation_inbound_global_rate_limit_window_ms ${Number(
        federationInboundPolicy.global_rate_limit_window_ms || 0
      )}`
    );
    lines.push(
      `loom_federation_inbound_global_rate_limit_max ${Number(federationInboundPolicy.global_rate_limit_max || 0)}`
    );
    lines.push(
      `loom_federation_inbound_max_envelopes_per_delivery ${Number(
        federationInboundPolicy.max_envelopes_per_delivery || 0
      )}`
    );
    lines.push(
      `loom_federation_inbound_abuse_auto_policy_enabled ${federationInboundPolicy.abuse_auto_policy_enabled ? 1 : 0}`
    );
    lines.push(`loom_federation_inbound_abuse_window_ms ${Number(federationInboundPolicy.abuse_window_ms || 0)}`);
    lines.push(
      `loom_federation_inbound_abuse_quarantine_threshold ${Number(
        federationInboundPolicy.abuse_quarantine_threshold || 0
      )}`
    );
    lines.push(
      `loom_federation_inbound_abuse_deny_threshold ${Number(federationInboundPolicy.abuse_deny_threshold || 0)}`
    );
    lines.push(
      `loom_federation_inbound_abuse_policy_duration_ms ${Number(
        federationInboundPolicy.abuse_policy_duration_ms || 0
      )}`
    );
    lines.push(`loom_federation_inbound_abuse_tracked_nodes ${Number(federationInboundPolicy.abuse_tracked_nodes || 0)}`);
    lines.push(`loom_federation_inbound_active_auto_policies ${Number(federationInboundPolicy.active_auto_policies || 0)}`);
    lines.push(
      `loom_federation_inbound_challenge_escalation_enabled ${federationInboundPolicy.challenge_escalation_enabled ? 1 : 0}`
    );
    lines.push(`loom_federation_inbound_challenge_threshold ${Number(federationInboundPolicy.challenge_threshold || 0)}`);
    lines.push(`loom_federation_inbound_challenge_duration_ms ${Number(federationInboundPolicy.challenge_duration_ms || 0)}`);
    lines.push(`loom_federation_inbound_active_challenges ${Number(federationInboundPolicy.active_challenges || 0)}`);
    lines.push(`loom_federation_inbound_high_reputation_nodes ${Number(federationInboundPolicy.high_reputation_nodes || 0)}`);
    lines.push(
      `loom_federation_inbound_distributed_guards_enabled ${federationInboundPolicy.distributed_guards_enabled ? 1 : 0}`
    );
    lines.push(
      `loom_federation_require_signed_receipts ${federationInboundPolicy.require_signed_receipts ? 1 : 0}`
    );
  }

  if (emailRelayStatus) {
    lines.push("# HELP loom_email_relay_enabled Whether email relay is enabled (1 or 0).");
    lines.push("# TYPE loom_email_relay_enabled gauge");
    lines.push(`loom_email_relay_enabled ${emailRelayStatus.enabled ? 1 : 0}`);
  }

  if (runtimeStatus?.federation_outbox_worker) {
    const worker = runtimeStatus.federation_outbox_worker;
    lines.push("# HELP loom_federation_outbox_worker_enabled Whether federation outbox worker is enabled (1 or 0).");
    lines.push("# TYPE loom_federation_outbox_worker_enabled gauge");
    lines.push(`loom_federation_outbox_worker_enabled ${worker.enabled ? 1 : 0}`);
    lines.push(`loom_federation_outbox_worker_in_progress ${worker.in_progress ? 1 : 0}`);
    lines.push(`loom_federation_outbox_worker_runs_total ${Number(worker.runs_total || 0)}`);
    lines.push(`loom_federation_outbox_worker_last_processed_count ${Number(worker.last_processed_count || 0)}`);
    lines.push(`loom_federation_outbox_worker_last_error ${worker.last_error ? 1 : 0}`);
  }

  if (runtimeStatus?.email_outbox_worker) {
    const worker = runtimeStatus.email_outbox_worker;
    lines.push("# HELP loom_email_outbox_worker_enabled Whether email outbox worker is enabled (1 or 0).");
    lines.push("# TYPE loom_email_outbox_worker_enabled gauge");
    lines.push(`loom_email_outbox_worker_enabled ${worker.enabled ? 1 : 0}`);
    lines.push(`loom_email_outbox_worker_in_progress ${worker.in_progress ? 1 : 0}`);
    lines.push(`loom_email_outbox_worker_runs_total ${Number(worker.runs_total || 0)}`);
    lines.push(`loom_email_outbox_worker_last_processed_count ${Number(worker.last_processed_count || 0)}`);
    lines.push(`loom_email_outbox_worker_last_error ${worker.last_error ? 1 : 0}`);
  }

  if (runtimeStatus?.webhook_outbox_worker) {
    const worker = runtimeStatus.webhook_outbox_worker;
    lines.push("# HELP loom_webhook_outbox_worker_enabled Whether webhook outbox worker is enabled (1 or 0).");
    lines.push("# TYPE loom_webhook_outbox_worker_enabled gauge");
    lines.push(`loom_webhook_outbox_worker_enabled ${worker.enabled ? 1 : 0}`);
    lines.push(`loom_webhook_outbox_worker_in_progress ${worker.in_progress ? 1 : 0}`);
    lines.push(`loom_webhook_outbox_worker_runs_total ${Number(worker.runs_total || 0)}`);
    lines.push(`loom_webhook_outbox_worker_last_processed_count ${Number(worker.last_processed_count || 0)}`);
    lines.push(`loom_webhook_outbox_worker_last_error ${worker.last_error ? 1 : 0}`);
  }

  if (runtimeStatus?.persistence) {
    const persistence = runtimeStatus.persistence;
    lines.push("# HELP loom_persistence_enabled Whether external persistence is enabled (1 or 0).");
    lines.push("# TYPE loom_persistence_enabled gauge");
    lines.push(`loom_persistence_enabled ${persistence.enabled ? 1 : 0}`);
    lines.push(`loom_persistence_queue_length ${Number(persistence.queue_length || 0)}`);
    lines.push(`loom_persistence_writes_total ${Number(persistence.writes_total || 0)}`);
    lines.push(`loom_persistence_writes_succeeded ${Number(persistence.writes_succeeded || 0)}`);
    lines.push(`loom_persistence_writes_failed ${Number(persistence.writes_failed || 0)}`);
    lines.push(`loom_persistence_last_error ${persistence.last_error ? 1 : 0}`);
  }

  lines.push("");
  return lines.join("\n");
}

export function createLoomServer(options = {}) {
  const idempotencyTtlMs = parsePositiveNumber(
    options.idempotencyTtlMs ?? process.env.LOOM_IDEMPOTENCY_TTL_MS,
    24 * 60 * 60 * 1000
  );
  const idempotencyMaxEntries = parsePositiveNumber(
    options.idempotencyMaxEntries ?? process.env.LOOM_IDEMPOTENCY_MAX_ENTRIES,
    10000
  );
  const federationNodeRateWindowMs = parsePositiveNumber(
    options.federationNodeRateWindowMs ?? process.env.LOOM_FEDERATION_NODE_RATE_WINDOW_MS,
    60 * 1000
  );
  const federationNodeRateMax = parsePositiveNumber(
    options.federationNodeRateMax ?? process.env.LOOM_FEDERATION_NODE_RATE_MAX,
    120
  );
  const federationGlobalRateWindowMs = parsePositiveNumber(
    options.federationGlobalRateWindowMs ?? process.env.LOOM_FEDERATION_GLOBAL_RATE_WINDOW_MS,
    60 * 1000
  );
  const federationGlobalRateMax = parsePositiveNumber(
    options.federationGlobalRateMax ?? process.env.LOOM_FEDERATION_GLOBAL_RATE_MAX,
    1000
  );
  const federationInboundMaxEnvelopes = parsePositiveNumber(
    options.federationInboundMaxEnvelopes ?? process.env.LOOM_FEDERATION_INBOUND_MAX_ENVELOPES,
    100
  );
  const federationAbuseWindowMs = parsePositiveNumber(
    options.federationAbuseWindowMs ?? process.env.LOOM_FEDERATION_ABUSE_WINDOW_MS,
    5 * 60 * 1000
  );
  const federationAbuseQuarantineThreshold = parsePositiveNumber(
    options.federationAbuseQuarantineThreshold ?? process.env.LOOM_FEDERATION_ABUSE_QUARANTINE_THRESHOLD,
    3
  );
  const federationAbuseDenyThreshold = parsePositiveNumber(
    options.federationAbuseDenyThreshold ?? process.env.LOOM_FEDERATION_ABUSE_DENY_THRESHOLD,
    6
  );
  const federationAutoPolicyDurationMs = parsePositiveNumber(
    options.federationAutoPolicyDurationMs ?? process.env.LOOM_FEDERATION_AUTO_POLICY_DURATION_MS,
    30 * 60 * 1000
  );
  const federationAbuseAutoPolicyEnabled = parseBoolean(
    options.federationAbuseAutoPolicyEnabled ?? process.env.LOOM_FEDERATION_ABUSE_AUTO_POLICY_ENABLED,
    true
  );
  const federationRequireSignedReceipts = parseBoolean(
    options.federationRequireSignedReceipts ?? process.env.LOOM_FEDERATION_REQUIRE_SIGNED_RECEIPTS,
    false
  );
  const federationDistributedGuardsEnabled = parseBoolean(
    options.federationDistributedGuardsEnabled ?? process.env.LOOM_FEDERATION_DISTRIBUTED_GUARDS_ENABLED,
    true
  );
  const federationChallengeEscalationEnabled = parseBoolean(
    options.federationChallengeEscalationEnabled ?? process.env.LOOM_FEDERATION_CHALLENGE_ESCALATION_ENABLED,
    false
  );
  const federationChallengeThreshold = parsePositiveNumber(
    options.federationChallengeThreshold ?? process.env.LOOM_FEDERATION_CHALLENGE_THRESHOLD,
    3
  );
  const federationChallengeDurationMs = parsePositiveNumber(
    options.federationChallengeDurationMs ?? process.env.LOOM_FEDERATION_CHALLENGE_DURATION_MS,
    15 * 60 * 1000
  );
  const store =
    options.store ||
    new LoomStore({
      nodeId: options.nodeId,
      dataDir: options.dataDir,
      federationSigningKeyId: options.federationSigningKeyId,
      federationSigningPrivateKeyPem: options.federationSigningPrivateKeyPem,
      persistenceAdapter: options.persistenceAdapter,
      idempotencyTtlMs,
      idempotencyMaxEntries,
      federationNodeRateWindowMs,
      federationNodeRateMax,
      federationGlobalRateWindowMs,
      federationGlobalRateMax,
      federationInboundMaxEnvelopes,
      federationAbuseWindowMs,
      federationAbuseQuarantineThreshold,
      federationAbuseDenyThreshold,
      federationAutoPolicyDurationMs,
      federationAbuseAutoPolicyEnabled,
      federationRequireSignedReceipts,
      federationDistributedGuardsEnabled,
      federationChallengeEscalationEnabled,
      federationChallengeThreshold,
      federationChallengeDurationMs
    });
  const domain = options.domain || "localhost";
  const maxBodyBytes = parsePositiveNumber(
    options.maxBodyBytes ?? process.env.LOOM_MAX_BODY_BYTES,
    DEFAULT_MAX_BODY_BYTES
  );
  const trustProxyConfig = resolveTrustedProxyConfig({
    trustProxy: options.trustProxy ?? process.env.LOOM_TRUST_PROXY,
    trustProxyAllowlist:
      options.trustProxyAllowlist ?? process.env.LOOM_TRUST_PROXY_ALLOWLIST ?? null
  });
  const blobMaxBytes = parsePositiveNumber(options.blobMaxBytes ?? process.env.LOOM_BLOB_MAX_BYTES, 25 * 1024 * 1024);
  const blobMaxPartBytes = parsePositiveNumber(
    options.blobMaxPartBytes ?? process.env.LOOM_BLOB_MAX_PART_BYTES,
    2 * 1024 * 1024
  );
  const blobMaxParts = parsePositiveNumber(options.blobMaxParts ?? process.env.LOOM_BLOB_MAX_PARTS, 64);
  store.blobMaxBytes = blobMaxBytes;
  store.blobMaxPartBytes = blobMaxPartBytes;
  store.blobMaxParts = blobMaxParts;
  const rateLimiter = createRateLimiter({
    windowMs: options.rateLimitWindowMs ?? process.env.LOOM_RATE_LIMIT_WINDOW_MS,
    defaultMax: options.rateLimitDefaultMax ?? process.env.LOOM_RATE_LIMIT_DEFAULT_MAX,
    sensitiveMax: options.rateLimitSensitiveMax ?? process.env.LOOM_RATE_LIMIT_SENSITIVE_MAX,
    trustProxyConfig
  });
  const metrics = createOperationalMetrics();
  const adminToken = options.adminToken ?? process.env.LOOM_ADMIN_TOKEN ?? null;
  const metricsPublic = parseBoolean(options.metricsPublic ?? process.env.LOOM_METRICS_PUBLIC, false);
  const identitySignupEnabled = parseBoolean(
    options.identitySignupEnabled ?? process.env.LOOM_IDENTITY_SIGNUP_ENABLED,
    true
  );
  const bridgeInboundEnabled = parseBoolean(
    options.bridgeInboundEnabled ?? process.env.LOOM_BRIDGE_EMAIL_INBOUND_ENABLED,
    true
  );
  const bridgeSendEnabled = parseBoolean(options.bridgeSendEnabled ?? process.env.LOOM_BRIDGE_EMAIL_SEND_ENABLED, true);
  const gatewaySmtpSubmitEnabled = parseBoolean(
    options.gatewaySmtpSubmitEnabled ?? process.env.LOOM_GATEWAY_SMTP_SUBMIT_ENABLED,
    true
  );
  const requestLogEnabled = parseBoolean(options.requestLogEnabled ?? process.env.LOOM_REQUEST_LOG_ENABLED, false);
  const requestLogFormat = normalizeLogFormat(
    options.requestLogFormat ?? process.env.LOOM_REQUEST_LOG_FORMAT ?? "json"
  );
  const runtimeStatusProvider = typeof options.runtimeStatusProvider === "function" ? options.runtimeStatusProvider : null;
  const emailRelay = options.emailRelay || null;

  const server = createServer(async (req, res) => {
    const reqId = `req_${randomUUID()}`;
    const startedAt = Date.now();
    const method = String(req.method || "GET").toUpperCase();
    const clientIp = resolveClientIp(req, { trustProxyConfig });
    let path = "unknown";
    let errorCode = null;
    metrics.onRequestStart();

    res.once("finish", () => {
      const durationMs = Date.now() - startedAt;
      metrics.onRequestFinish({
        status: res.statusCode || 500,
        errorCode,
        durationMs
      });

      if (requestLogEnabled) {
        const entry = {
          timestamp: new Date().toISOString(),
          req_id: reqId,
          method,
          path,
          status: res.statusCode || 500,
          duration_ms: durationMs,
          client_ip: clientIp,
          error_code: errorCode || null
        };

        if (requestLogFormat === "text") {
          // eslint-disable-next-line no-console
          console.log(
            `[${entry.timestamp}] ${entry.method} ${entry.path} status=${entry.status} duration_ms=${entry.duration_ms} req_id=${entry.req_id}`
          );
        } else {
          // eslint-disable-next-line no-console
          console.log(JSON.stringify(entry));
        }
      }
    });

    try {
      path = requestPath(req);
      rateLimiter.enforce(req, path);

      if (methodIs(req, "GET") && path === "/") {
        sendHtml(res, 200, renderDashboardHtml());
        return;
      }

      if (methodIs(req, "GET") && path === "/favicon.ico") {
        res.writeHead(204);
        res.end();
        return;
      }

      if (methodIs(req, "GET") && path === "/health") {
        sendJson(res, 200, { ok: true, service: "loom-mvn", timestamp: new Date().toISOString() });
        return;
      }

      if (methodIs(req, "GET") && path === "/ready") {
        const runtimeStatus = runtimeStatusProvider ? runtimeStatusProvider() : null;
        const federationOutbox = store.getFederationOutboxStats();
        const emailOutbox = store.getEmailOutboxStats();
        const webhookOutbox = store.getWebhookOutboxStats();
        const federationInboundPolicy = store.getFederationInboundPolicyStatus();
        sendJson(res, 200, {
          ok: true,
          service: "loom-mvn",
          timestamp: new Date().toISOString(),
          uptime_s: metrics.snapshot().uptime_s,
          checks: {
            http: "ok",
            store: "ok"
          },
          outbox: {
            federation: federationOutbox,
            email: emailOutbox,
            webhook: webhookOutbox
          },
          federation_inbound_policy: federationInboundPolicy,
          idempotency: store.getIdempotencyStatus(),
          email_relay: typeof emailRelay?.getStatus === "function" ? emailRelay.getStatus() : null,
          runtime: runtimeStatus
        });
        return;
      }

      if (methodIs(req, "GET") && path === "/metrics") {
        if (!metricsPublic) {
          requireAdminToken(req, adminToken);
        }
        const snapshot = metrics.snapshot();
        const federationOutbox = store.getFederationOutboxStats();
        const emailOutbox = store.getEmailOutboxStats();
        const webhookOutbox = store.getWebhookOutboxStats();
        const idempotencyStatus = store.getIdempotencyStatus();
        const federationInboundPolicy = store.getFederationInboundPolicyStatus();
        const runtimeStatus = runtimeStatusProvider ? runtimeStatusProvider() : null;
        const emailRelayStatus = typeof emailRelay?.getStatus === "function" ? emailRelay.getStatus() : null;
        const payload = formatMetricsPrometheus(
          snapshot,
          federationOutbox,
          emailOutbox,
          webhookOutbox,
          idempotencyStatus,
          federationInboundPolicy,
          runtimeStatus,
          emailRelayStatus
        );
        sendText(res, 200, payload);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/admin/status") {
        requireAdminToken(req, adminToken);
        const snapshot = metrics.snapshot();
        const federationOutbox = store.getFederationOutboxStats();
        const emailOutbox = store.getEmailOutboxStats();
        const webhookOutbox = store.getWebhookOutboxStats();
        const federationInboundPolicy = store.getFederationInboundPolicyStatus();
        const federationGuards = await store.getFederationGuardStatus();
        const persistenceSchema = await store.getPersistenceSchemaStatus();
        const runtimeStatus = runtimeStatusProvider ? runtimeStatusProvider() : null;
        sendJson(res, 200, {
          service: "loom-mvn",
          timestamp: new Date().toISOString(),
          metrics: snapshot,
          outbox: {
            federation: federationOutbox,
            email: emailOutbox,
            webhook: webhookOutbox
          },
          federation_inbound_policy: federationInboundPolicy,
          federation_guards: federationGuards,
          idempotency: store.getIdempotencyStatus(),
          email_relay: typeof emailRelay?.getStatus === "function" ? emailRelay.getStatus() : null,
          persistence_schema: persistenceSchema,
          runtime: runtimeStatus
        });
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/admin/persistence/schema") {
        requireAdminToken(req, adminToken);
        const schema = await store.getPersistenceSchemaStatus();
        sendJson(res, 200, schema);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/admin/persistence/backup") {
        requireAdminToken(req, adminToken);
        const url = requestUrl(req);
        const includeAudit = url.searchParams.get("include_audit");
        const auditLimit = url.searchParams.get("audit_limit");
        const backup = await store.exportPersistenceBackup({
          includeAudit: includeAudit == null ? true : parseBoolean(includeAudit, true),
          auditLimit
        });
        sendJson(res, 200, backup);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/admin/persistence/restore") {
        requireAdminToken(req, adminToken);
        const body = await readJson(req, maxBodyBytes);
        if (body.confirm !== "restore") {
          throw new LoomError("ENVELOPE_INVALID", "Set confirm='restore' to execute persistence restore", 400, {
            field: "confirm"
          });
        }
        const result = await store.importPersistenceBackup(body.backup || body, {
          replaceState: body.replace_state !== false,
          truncateAudit: body.truncate_audit === true
        });
        sendJson(res, 200, result);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/outbox/dlq") {
        requireAdminToken(req, adminToken);
        const url = requestUrl(req);
        const entries = store.listDeadLetterOutbox({
          kind: url.searchParams.get("kind"),
          limit: url.searchParams.get("limit")
        });
        sendJson(res, 200, { entries });
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/outbox/dlq/requeue") {
        requireAdminToken(req, adminToken);
        const body = await readJson(req, maxBodyBytes);
        const kind = String(body.kind || "")
          .trim()
          .toLowerCase();
        const outboxId = String(body.id || body.outbox_id || "").trim();

        if (!outboxId) {
          throw new LoomError("ENVELOPE_INVALID", "outbox id is required", 400, {
            field: "id"
          });
        }

        if (kind !== "email" && kind !== "federation" && kind !== "webhook") {
          throw new LoomError("ENVELOPE_INVALID", "kind must be 'email', 'federation', or 'webhook'", 400, {
            field: "kind"
          });
        }

        let item;
        if (kind === "email") {
          item = store.requeueEmailOutboxItem(outboxId, "admin");
        } else if (kind === "federation") {
          item = store.requeueFederationOutboxItem(outboxId, "admin");
        } else {
          item = store.requeueWebhookOutboxItem(outboxId, "admin");
        }

        sendJson(res, 200, {
          kind,
          item
        });
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/webhooks") {
        requireAdminToken(req, adminToken);
        const body = await readJson(req, maxBodyBytes);
        const webhook = store.registerWebhook(body, "admin");
        sendJson(res, 201, webhook);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/webhooks") {
        requireAdminToken(req, adminToken);
        sendJson(res, 200, { webhooks: store.listWebhooks() });
        return;
      }

      if (methodIs(req, "DELETE") && path.startsWith("/v1/webhooks/")) {
        requireAdminToken(req, adminToken);
        const webhookId = path.slice("/v1/webhooks/".length);
        const removed = store.deleteWebhook(webhookId, "admin");
        sendJson(res, 200, removed);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/webhooks/outbox") {
        requireAdminToken(req, adminToken);
        const url = requestUrl(req);
        const outbox = store.listWebhookOutbox({
          status: url.searchParams.get("status"),
          webhook_id: url.searchParams.get("webhook_id"),
          event_type: url.searchParams.get("event_type"),
          limit: url.searchParams.get("limit")
        });
        sendJson(res, 200, { outbox });
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/webhooks/outbox/process") {
        requireAdminToken(req, adminToken);
        const body = await readJson(req, maxBodyBytes);
        const result = await store.processWebhookOutboxBatch(body.limit || 10, "admin");
        sendJson(res, 200, result);
        return;
      }

      if (methodIs(req, "POST") && path.startsWith("/v1/webhooks/outbox/") && path.endsWith("/process")) {
        requireAdminToken(req, adminToken);
        const outboxId = path.slice("/v1/webhooks/outbox/".length, -"/process".length);
        const result = await store.processWebhookOutboxItem(outboxId, "admin");
        sendJson(res, 200, result);
        return;
      }

      if (methodIs(req, "GET") && path === "/.well-known/loom.json") {
        sendJson(res, 200, store.getNodeDocument(domain));
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/identity") {
        if (!identitySignupEnabled) {
          requireAdminToken(req, adminToken);
        }
        const body = await readJson(req, maxBodyBytes);
        const identity = store.registerIdentity(body);
        sendJson(res, 201, identity);
        return;
      }

      if (methodIs(req, "GET") && path.startsWith("/v1/identity/")) {
        const encodedIdentity = path.slice("/v1/identity/".length);
        const identityUri = decodeURIComponent(encodedIdentity);
        const identity = store.resolveIdentity(identityUri);
        if (!identity) {
          throw new LoomError("IDENTITY_NOT_FOUND", `Identity not found: ${identityUri}`, 404, {
            identity: identityUri
          });
        }
        sendJson(res, 200, identity);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/auth/challenge") {
        const body = await readJson(req, maxBodyBytes);
        const challenge = store.createAuthChallenge(body);
        sendJson(res, 200, challenge);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/auth/token") {
        const body = await readJson(req, maxBodyBytes);
        const tokens = store.exchangeAuthToken(body);
        sendJson(res, 200, tokens);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/auth/refresh") {
        const body = await readJson(req, maxBodyBytes);
        const tokens = store.refreshAuthToken(body);
        sendJson(res, 200, tokens);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/envelopes") {
        const actorIdentity = requireActorIdentity(req, store);
        const capabilityPresentationToken = getCapabilityPresentationToken(req);
        const envelope = await readJson(req, maxBodyBytes);
        const requiredActions = Array.from(
          new Set([
            ...resolveDelegationRequiredActionsForRoute(path, envelope),
            ...store.resolveDelegationRequiredActions(envelope)
          ])
        );
        const idempotency = createIdempotencyContext(req, store, actorIdentity, method, path, envelope);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }
        const stored = store.ingestEnvelope(envelope, {
          actorIdentity,
          requiredActions,
          capabilityPresentationToken
        });
        storeIdempotentResult(store, idempotency, 201, stored);
        sendJson(res, 201, stored);
        return;
      }

      if (methodIs(req, "POST") && path.startsWith("/v1/threads/") && path.endsWith("/ops")) {
        const actorIdentity = requireActorIdentity(req, store);
        const capabilityPresentationToken = getCapabilityPresentationToken(req);
        const threadId = path.slice("/v1/threads/".length, -"/ops".length);
        const envelope = await readJson(req, maxBodyBytes);
        const requiredActions = Array.from(
          new Set([
            ...resolveDelegationRequiredActionsForRoute(path, envelope),
            ...store.resolveDelegationRequiredActions(envelope)
          ])
        );

        if (!envelope.thread_id) {
          throw new LoomError("ENVELOPE_INVALID", "Signed thread_op envelopes must include thread_id", 400, {
            field: "thread_id"
          });
        }

        if (envelope.thread_id !== threadId) {
          throw new LoomError("ENVELOPE_INVALID", "thread_id must match path thread id", 400, {
            field: "thread_id",
            path_thread_id: threadId,
            body_thread_id: envelope.thread_id
          });
        }

        if (envelope.type !== "thread_op") {
          throw new LoomError("ENVELOPE_INVALID", "/v1/threads/{id}/ops requires type=thread_op", 400, {
            field: "type"
          });
        }

        const idempotency = createIdempotencyContext(req, store, actorIdentity, method, path, envelope);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }
        const stored = store.ingestEnvelope(envelope, {
          actorIdentity,
          requiredActions,
          capabilityPresentationToken
        });
        storeIdempotentResult(store, idempotency, 201, stored);
        sendJson(res, 201, stored);
        return;
      }

      if (methodIs(req, "GET") && path.startsWith("/v1/envelopes/") && path.endsWith("/delivery")) {
        const actorIdentity = requireActorIdentity(req, store);
        const envelopeId = path.slice("/v1/envelopes/".length, -"/delivery".length);
        const envelope = store.getEnvelope(envelopeId);
        if (!envelope) {
          throw new LoomError("ENVELOPE_NOT_FOUND", `Envelope not found: ${envelopeId}`, 404, {
            envelope_id: envelopeId
          });
        }

        const view = store.getEnvelopeForIdentity(envelopeId, actorIdentity);
        if (!view?.delivery_wrapper) {
          throw new LoomError("ENVELOPE_INVALID", "Envelope does not require delivery wrapper for this identity", 400, {
            envelope_id: envelopeId,
            actor: actorIdentity
          });
        }
        sendJson(res, 200, {
          envelope: view.envelope,
          delivery_wrapper: view.delivery_wrapper
        });
        return;
      }

      if (methodIs(req, "GET") && path.startsWith("/v1/envelopes/")) {
        const envelopeId = path.slice("/v1/envelopes/".length);
        const envelope = store.getEnvelope(envelopeId);
        if (!envelope) {
          throw new LoomError("ENVELOPE_NOT_FOUND", `Envelope not found: ${envelopeId}`, 404, {
            envelope_id: envelopeId
          });
        }

        if (store.requiresRecipientDeliveryWrapper(envelope) || store.envelopeContainsCapabilitySecret(envelope)) {
          const actorIdentity = resolveOptionalActorIdentity(req, store);
          if (!actorIdentity) {
            throw new LoomError("CAPABILITY_DENIED", "Authentication required for protected envelope view", 403, {
              envelope_id: envelopeId
            });
          }
          const view = store.getEnvelopeForIdentity(envelopeId, actorIdentity);
          sendJson(res, 200, {
            ...view.envelope,
            delivery_wrapper: view.delivery_wrapper
          });
          return;
        }

        sendJson(res, 200, envelope);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/capabilities") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const idempotency = createIdempotencyContext(req, store, actorIdentity, method, path, body);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }
        const token = store.issueCapabilityToken(body, actorIdentity);
        storeIdempotentResult(store, idempotency, 201, token);
        sendJson(res, 201, token);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/delegations") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const idempotency = createIdempotencyContext(req, store, actorIdentity, method, path, body);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }
        const delegation = store.createDelegation(body, actorIdentity);
        storeIdempotentResult(store, idempotency, 201, delegation);
        sendJson(res, 201, delegation);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/federation/hello") {
        sendJson(res, 200, {
          node_id: store.nodeId,
          domain,
          version: "1.1",
          deliver_url: `https://${domain}/v1/federation/deliver`,
          timestamp: new Date().toISOString()
        });
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/federation/nodes") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const idempotency = createIdempotencyContext(req, store, actorIdentity, method, path, body);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }
        const node = store.registerFederationNode(body, actorIdentity);
        storeIdempotentResult(store, idempotency, 201, node);
        sendJson(res, 201, node);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/federation/nodes") {
        requireActorIdentity(req, store);
        sendJson(res, 200, { nodes: store.listFederationNodes() });
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/federation/nodes/bootstrap") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const idempotency = createIdempotencyContext(req, store, actorIdentity, method, path, body);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }
        const result = await store.bootstrapFederationNode(body, actorIdentity);
        storeIdempotentResult(store, idempotency, 201, result);
        sendJson(res, 201, result);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/federation/challenge") {
        const rawBody = await readRawBody(req, maxBodyBytes);
        const idempotencyPayload = rawBody ? { raw: rawBody } : {};
        const idempotency = createIdempotencyContext(req, store, "federation.challenge", method, path, idempotencyPayload);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }

        let verifiedNode = null;
        try {
          verifiedNode = await store.verifyFederationRequest({
            method: req.method || "POST",
            path,
            headers: req.headers,
            rawBody,
            bypassChallenge: true
          });

          const issued = await store.issueFederationChallengeToken(verifiedNode.node_id, "system");
          storeIdempotentResult(store, idempotency, 200, issued);
          sendJson(res, 200, issued);
          return;
        } catch (error) {
          await store.recordFederationInboundFailureFromRequest(req.headers, verifiedNode, error);
          throw error;
        }
      }

      if (methodIs(req, "POST") && path === "/v1/federation/deliver") {
        const rawBody = await readRawBody(req, maxBodyBytes);
        let wrapper;
        try {
          wrapper = rawBody ? JSON.parse(rawBody) : {};
        } catch {
          throw new LoomError("ENVELOPE_INVALID", "Federation body must be valid JSON", 400, {
            field: "body"
          });
        }

        let verifiedNode = null;
        try {
          verifiedNode = await store.verifyFederationRequest({
            method: req.method || "POST",
            path,
            headers: req.headers,
            rawBody
          });

          const result = store.ingestFederationDelivery(wrapper, verifiedNode);
          await store.recordFederationInboundSuccess(verifiedNode.node_id);
          sendJson(res, 202, result);
          return;
        } catch (error) {
          await store.recordFederationInboundFailureFromRequest(req.headers, verifiedNode, error);
          throw error;
        }
      }

      if (methodIs(req, "POST") && path === "/v1/federation/outbox") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const idempotency = createIdempotencyContext(req, store, actorIdentity, method, path, body);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }
        const outbox = store.queueFederationOutbox(body, actorIdentity);
        storeIdempotentResult(store, idempotency, 201, outbox);
        sendJson(res, 201, outbox);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/federation/outbox") {
        requireActorIdentity(req, store);
        const url = requestUrl(req);
        const outbox = store.listFederationOutbox({
          status: url.searchParams.get("status"),
          recipient_node: url.searchParams.get("recipient_node"),
          limit: url.searchParams.get("limit")
        });
        sendJson(res, 200, { outbox });
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/federation/outbox/process") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const result = await store.processFederationOutboxBatch(body.limit || 10, actorIdentity);
        sendJson(res, 200, result);
        return;
      }

      if (methodIs(req, "POST") && path.startsWith("/v1/federation/outbox/") && path.endsWith("/process")) {
        const actorIdentity = requireActorIdentity(req, store);
        const outboxId = path.slice("/v1/federation/outbox/".length, -"/process".length);
        const result = await store.processFederationOutboxItem(outboxId, actorIdentity);
        sendJson(res, 200, result);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/delegations") {
        const actorIdentity = requireActorIdentity(req, store);
        const role = requestUrl(req).searchParams.get("role") || "all";
        const delegations = store.listDelegations(actorIdentity, role);
        sendJson(res, 200, { delegations });
        return;
      }

      if (methodIs(req, "DELETE") && path.startsWith("/v1/delegations/")) {
        const actorIdentity = requireActorIdentity(req, store);
        const delegationId = path.slice("/v1/delegations/".length);
        const revoked = store.revokeDelegation(delegationId, actorIdentity);
        sendJson(res, 200, revoked);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/blobs") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const created = store.createBlob(body, actorIdentity);
        sendJson(res, 201, created);
        return;
      }

      if (methodIs(req, "PUT") && path.startsWith("/v1/blobs/") && path.includes("/parts/")) {
        const actorIdentity = requireActorIdentity(req, store);
        const remainder = path.slice("/v1/blobs/".length);
        const [blobId, partSegment, partNumberRaw] = remainder.split("/");

        if (partSegment !== "parts") {
          throw new LoomError("ENVELOPE_NOT_FOUND", "Route not found", 404, {
            method: req.method,
            path
          });
        }

        const partNumber = Number(partNumberRaw);
        if (!Number.isInteger(partNumber) || partNumber <= 0) {
          throw new LoomError("ENVELOPE_INVALID", "Blob part number must be a positive integer", 400, {
            field: "part_number"
          });
        }

        const body = await readJson(req, maxBodyBytes);
        const uploaded = store.putBlobPart(blobId, partNumber, body, actorIdentity);
        sendJson(res, 200, uploaded);
        return;
      }

      if (methodIs(req, "POST") && path.startsWith("/v1/blobs/") && path.endsWith("/complete")) {
        const actorIdentity = requireActorIdentity(req, store);
        const blobId = path.slice("/v1/blobs/".length, -"/complete".length);
        const complete = store.completeBlob(blobId, actorIdentity);
        sendJson(res, 200, complete);
        return;
      }

      if (methodIs(req, "GET") && path.startsWith("/v1/blobs/")) {
        const actorIdentity = requireActorIdentity(req, store);
        const blobId = path.slice("/v1/blobs/".length);
        const blob = store.getBlob(blobId, actorIdentity);
        if (!blob) {
          throw new LoomError("ENVELOPE_NOT_FOUND", `Blob not found: ${blobId}`, 404, {
            blob_id: blobId
          });
        }
        sendJson(res, 200, blob);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/capabilities") {
        const actorIdentity = requireActorIdentity(req, store);
        const threadId = requestUrl(req).searchParams.get("thread_id");
        if (!threadId) {
          throw new LoomError("ENVELOPE_INVALID", "thread_id query parameter is required", 400, {
            field: "thread_id"
          });
        }

        const capabilities = store.listCapabilities(threadId, actorIdentity);
        sendJson(res, 200, { thread_id: threadId, capabilities });
        return;
      }

      if (methodIs(req, "DELETE") && path.startsWith("/v1/capabilities/")) {
        const actorIdentity = requireActorIdentity(req, store);
        const capabilityId = path.slice("/v1/capabilities/".length);
        const revoked = store.revokeCapabilityToken(capabilityId, actorIdentity);
        sendJson(res, 200, revoked);
        return;
      }

      if (path.startsWith("/v1/mailbox/threads/") && path.endsWith("/state")) {
        const actorIdentity = requireActorIdentity(req, store);
        const threadId = path.slice("/v1/mailbox/threads/".length, -"/state".length);

        if (methodIs(req, "GET")) {
          const state = store.getThreadMailboxState(threadId, actorIdentity);
          sendJson(res, 200, state);
          return;
        }

        if (methodIs(req, "PATCH")) {
          const body = await readJson(req, maxBodyBytes);
          const updated = store.updateThreadMailboxState(threadId, actorIdentity, body);
          sendJson(res, 200, updated);
          return;
        }
      }

      if (methodIs(req, "GET") && path === "/v1/threads") {
        sendJson(res, 200, { threads: store.listThreads() });
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/audit") {
        requireActorIdentity(req, store);
        const limit = requestUrl(req).searchParams.get("limit") || 100;
        const entries = store.getAuditEntries(limit);
        sendJson(res, 200, { entries });
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/search") {
        const actorIdentity = requireActorIdentity(req, store);
        const url = requestUrl(req);
        const result = store.searchEnvelopes(
          {
            q: url.searchParams.get("q") || "",
            from: url.searchParams.get("from"),
            type: url.searchParams.get("type"),
            intent: url.searchParams.get("intent"),
            thread_id: url.searchParams.get("thread_id"),
            after: url.searchParams.get("after"),
            before: url.searchParams.get("before"),
            limit: url.searchParams.get("limit")
          },
          actorIdentity
        );
        sendJson(res, 200, result);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/bridge/email/inbound") {
        assertRouteEnabled(bridgeInboundEnabled, req, path);
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const idempotency = createIdempotencyContext(req, store, actorIdentity, method, path, body);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }
        const accepted = store.createBridgeInboundEnvelope(body, actorIdentity);
        storeIdempotentResult(store, idempotency, 201, accepted);
        sendJson(res, 201, accepted);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/bridge/email/outbound") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const rendered = store.renderBridgeOutboundEmail(body, actorIdentity);
        sendJson(res, 200, rendered);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/bridge/email/send") {
        assertRouteEnabled(bridgeSendEnabled, req, path);
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const idempotency = createIdempotencyContext(req, store, actorIdentity, method, path, body);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }
        const queued = store.queueEmailOutbox(body, actorIdentity);
        const processed = await store.processEmailOutboxItem(queued.id, emailRelay, actorIdentity);
        const status = processed.status === "delivered" ? 200 : 202;
        storeIdempotentResult(store, idempotency, status, processed);
        sendJson(res, status, processed);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/email/outbox") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const idempotency = createIdempotencyContext(req, store, actorIdentity, method, path, body);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }
        const outbox = store.queueEmailOutbox(body, actorIdentity);
        storeIdempotentResult(store, idempotency, 201, outbox);
        sendJson(res, 201, outbox);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/email/outbox") {
        requireActorIdentity(req, store);
        const url = requestUrl(req);
        const outbox = store.listEmailOutbox({
          status: url.searchParams.get("status"),
          thread_id: url.searchParams.get("thread_id"),
          limit: url.searchParams.get("limit")
        });
        sendJson(res, 200, { outbox });
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/email/outbox/process") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const result = await store.processEmailOutboxBatch(body.limit || 10, emailRelay, actorIdentity);
        sendJson(res, 200, result);
        return;
      }

      if (methodIs(req, "POST") && path.startsWith("/v1/email/outbox/") && path.endsWith("/process")) {
        const actorIdentity = requireActorIdentity(req, store);
        const outboxId = path.slice("/v1/email/outbox/".length, -"/process".length);
        const result = await store.processEmailOutboxItem(outboxId, emailRelay, actorIdentity);
        sendJson(res, 200, result);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/gateway/imap/folders") {
        const actorIdentity = requireActorIdentity(req, store);
        const folders = store.listGatewayImapFolders(actorIdentity);
        sendJson(res, 200, { folders });
        return;
      }

      if (methodIs(req, "GET") && path.startsWith("/v1/gateway/imap/folders/") && path.endsWith("/messages")) {
        const actorIdentity = requireActorIdentity(req, store);
        const encodedFolderName = path.slice("/v1/gateway/imap/folders/".length, -"/messages".length);
        const folderName = decodeURIComponent(encodedFolderName) || "INBOX";
        const normalizedFolder = store.normalizeGatewayFolderName(folderName);
        const limit = requestUrl(req).searchParams.get("limit");
        const messages = store.listGatewayImapMessages(normalizedFolder, actorIdentity, limit);
        sendJson(res, 200, { folder: normalizedFolder, messages });
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/gateway/smtp/submit") {
        assertRouteEnabled(gatewaySmtpSubmitEnabled, req, path);
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const idempotency = createIdempotencyContext(req, store, actorIdentity, method, path, body);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }
        const submitted = store.submitGatewaySmtp(body, actorIdentity);
        storeIdempotentResult(store, idempotency, 201, submitted);
        sendJson(res, 201, submitted);
        return;
      }

      if (methodIs(req, "GET") && path.startsWith("/v1/threads/") && path.endsWith("/envelopes")) {
        const threadId = path.slice("/v1/threads/".length, -"/envelopes".length);
        const envelopes = store.getThreadEnvelopes(threadId);
        if (!envelopes) {
          throw new LoomError("THREAD_NOT_FOUND", `Thread not found: ${threadId}`, 404, {
            thread_id: threadId
          });
        }

        const requiresProtectedView = envelopes.some(
          (envelope) => store.requiresRecipientDeliveryWrapper(envelope) || store.envelopeContainsCapabilitySecret(envelope)
        );
        if (requiresProtectedView) {
          const actorIdentity = requireActorIdentity(req, store);
          const views = store.getThreadEnvelopesForIdentity(threadId, actorIdentity);
          sendJson(res, 200, {
            thread_id: threadId,
            envelopes: views.map((view) => ({
              ...view.envelope,
              delivery_wrapper: view.delivery_wrapper
            }))
          });
          return;
        }

        sendJson(res, 200, { thread_id: threadId, envelopes });
        return;
      }

      if (methodIs(req, "GET") && path.startsWith("/v1/threads/")) {
        const threadId = path.slice("/v1/threads/".length);
        const thread = store.getThread(threadId);
        if (!thread) {
          throw new LoomError("THREAD_NOT_FOUND", `Thread not found: ${threadId}`, 404, {
            thread_id: threadId
          });
        }
        sendJson(res, 200, thread);
        return;
      }

      throw new LoomError("ENVELOPE_NOT_FOUND", "Route not found", 404, {
        method: req.method,
        path
      });
    } catch (error) {
      const { status, body } = toErrorResponse(error, reqId);
      errorCode = body.error.code;
      sendJson(res, status, body);
    }
  });

  return { server, store };
}
