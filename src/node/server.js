import { createServer } from "node:http";
import { createSecureServer } from "node:http2";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { BlockList, isIP } from "node:net";
import { gzipSync, gunzipSync, brotliCompressSync, brotliDecompressSync, deflateSync, inflateSync, constants as zlibConstants } from "node:zlib";

import { toErrorResponse, LoomError } from "../protocol/errors.js";
import { buildRateLimitHeaders } from "../protocol/rate_limit.js";
import { validateSearchQuery } from "../protocol/search.js";
import {
  WS_EVENT_TYPES,
  validateSubscribeMessage,
  validateAckMessage
} from "../protocol/websocket.js";
import { LoomStore } from "./store.js";
import { renderDashboardHtml } from "./ui.js";
import { parseBoolean, parsePositiveNumber, parseHostAllowlist } from "./env.js";
import { applyConfigProfileOptionDefaults } from "./config_profile.js";
import { createMcpToolRegistry, createMcpSseSession, handleMcpRequest } from "./mcp_server.js";
import { negotiateEncoding, shouldCompress, buildCompressionHeaders, DEFAULT_COMPRESSION_POLICY } from "../protocol/compression.js";
import { createSearchIndex } from "../protocol/search_index.js";
import {
  PROTOCOL_PROFILE_FULL,
  PROTOCOL_PROFILE_CORE,
  normalizeProtocolProfile
} from "../protocol/extension_registry.js";

const DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024;
const DEFAULT_RATE_LIMIT_WINDOW_MS = 60 * 1000;
const DEFAULT_RATE_LIMIT_DEFAULT_MAX = 2000;
const DEFAULT_RATE_LIMIT_SENSITIVE_MAX = 120;
const INBOUND_CONTENT_FILTER_PROFILE_VALUES = new Set(["strict", "balanced", "agent"]);

function normalizeLogFormat(value, fallback = "json") {
  const normalized = String(value || fallback)
    .trim()
    .toLowerCase();
  if (normalized === "text") {
    return "text";
  }
  return "json";
}

function normalizeIdentityDomain(value) {
  const raw = String(value || "")
    .trim()
    .toLowerCase();
  if (!raw) {
    return null;
  }

  const withoutScheme = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  const hostPort = withoutScheme.split("/")[0];
  if (!hostPort) {
    return null;
  }

  if (hostPort.startsWith("[") && hostPort.includes("]")) {
    return hostPort.slice(1, hostPort.indexOf("]")) || null;
  }

  const colonIndex = hostPort.indexOf(":");
  if (colonIndex >= 0) {
    return hostPort.slice(0, colonIndex) || null;
  }

  return hostPort;
}

function parseStringList(value) {
  if (value == null) {
    return [];
  }
  const list = Array.isArray(value) ? value : String(value).split(/[,\n;]+/);
  return Array.from(
    new Set(
      list
        .map((entry) => String(entry || "").trim())
        .filter(Boolean)
    )
  );
}

function normalizePemOption(value) {
  if (value == null) {
    return null;
  }
  const text = String(value);
  if (!text.trim()) {
    return null;
  }
  return text.replace(/\\n/g, "\n");
}

function normalizeHeaderAllowlist(value) {
  const list = parseStringList(value).map((entry) => entry.toLowerCase().replace(/:+$/, ""));
  return list.length > 0 ? Array.from(new Set(list)) : null;
}

function normalizeInboundContentFilterProfile(value, fallback = "balanced") {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (INBOUND_CONTENT_FILTER_PROFILE_VALUES.has(normalized)) {
    return normalized;
  }
  const fallbackNormalized = String(fallback || "balanced")
    .trim()
    .toLowerCase();
  return INBOUND_CONTENT_FILTER_PROFILE_VALUES.has(fallbackNormalized) ? fallbackNormalized : "balanced";
}

function parseDnsTxtRdataValue(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return "";
  }
  if (!raw.includes("\"")) {
    return raw;
  }

  let combined = "";
  const pattern = /"((?:\\.|[^"\\])*)"/g;
  let match = null;
  while ((match = pattern.exec(raw)) != null) {
    combined += match[1].replace(/\\(.)/g, "$1");
  }
  return combined || raw.replace(/^"+|"+$/g, "");
}

function createDnssecDohTxtResolver(options = {}) {
  const endpoint = String(options.endpoint || "https://cloudflare-dns.com/dns-query").trim();
  const timeoutMs = Math.max(500, Math.floor(parsePositiveNumber(options.timeoutMs, 5000)));
  const maxResponseBytes = Math.max(1024, Math.floor(parsePositiveNumber(options.maxResponseBytes, 256 * 1024)));

  return async (dnsName) => {
    const url = new URL(endpoint);
    url.searchParams.set("name", String(dnsName || "").trim());
    url.searchParams.set("type", "TXT");
    url.searchParams.set("do", "true");
    url.searchParams.set("cd", "false");

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    timer.unref?.();

    try {
      const response = await fetch(url, {
        method: "GET",
        headers: {
          accept: "application/dns-json"
        },
        signal: controller.signal
      });

      const rawText = await response.text();
      if (Buffer.byteLength(rawText, "utf-8") > maxResponseBytes) {
        throw new Error(`DNS-over-HTTPS response exceeds ${maxResponseBytes} bytes`);
      }
      if (!response.ok) {
        throw new Error(`DNS-over-HTTPS resolver returned HTTP ${response.status}`);
      }

      let payload = null;
      try {
        payload = rawText ? JSON.parse(rawText) : {};
      } catch {
        throw new Error("DNS-over-HTTPS resolver returned non-JSON response");
      }

      const answerRecords = Array.isArray(payload?.Answer) ? payload.Answer : [];
      const txtRecords = answerRecords
        .filter((entry) => Number(entry?.type) === 16)
        .map((entry) => parseDnsTxtRdataValue(entry?.data))
        .filter(Boolean);

      const dnssecValidated = payload?.AD === true || payload?.ad === true;
      return {
        answers: txtRecords,
        dnssec_validated: dnssecValidated,
        dnssec_source: `doh:${url.origin}`,
        resolver_mode: "dnssec_doh",
        response_status: Number(payload?.Status || 0)
      };
    } finally {
      clearTimeout(timer);
    }
  };
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
  const bodyBytes = Buffer.byteLength(body);

  const ctx = res._compressionCtx;
  if (ctx && ctx.policy.enabled && shouldCompress("application/json", bodyBytes, ctx.policy)) {
    const encoding = negotiateEncoding(ctx.acceptEncoding, ctx.policy);
    if (encoding !== "identity") {
      const compressed = compressBuffer(Buffer.from(body), encoding, ctx.policy.level);
      const headers = buildCompressionHeaders(encoding);
      res.writeHead(status, {
        "content-type": "application/json; charset=utf-8",
        "content-length": compressed.length.toString(),
        ...headers
      });
      res.end(compressed);
      return;
    }
  }

  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": bodyBytes.toString(),
    ...(ctx ? { vary: "accept-encoding" } : {})
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

function compressBuffer(buffer, encoding, level = 6) {
  switch (encoding) {
    case "gzip":
      return gzipSync(buffer, { level });
    case "br":
      return brotliCompressSync(buffer, {
        params: { [zlibConstants.BROTLI_PARAM_QUALITY]: Math.min(level, 11) }
      });
    case "deflate":
      return deflateSync(buffer, { level });
    default:
      return buffer;
  }
}

function decompressBuffer(buffer, encoding) {
  switch (encoding) {
    case "gzip":
      return gunzipSync(buffer);
    case "br":
      return brotliDecompressSync(buffer);
    case "deflate":
      return inflateSync(buffer);
    default:
      return buffer;
  }
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

  let buffer = Buffer.concat(chunks);

  // Decompress if content-encoding header is present
  const contentEncoding = req.headers["content-encoding"];
  if (contentEncoding) {
    const encoding = contentEncoding.trim().toLowerCase();
    if (encoding === "gzip" || encoding === "br" || encoding === "deflate") {
      try {
        buffer = decompressBuffer(buffer, encoding);
      } catch {
        throw new LoomError("ENVELOPE_INVALID", `Failed to decompress ${encoding} content`, 400, {
          field: "content-encoding"
        });
      }
    }
  }

  return buffer.toString("utf-8");
}

function requestPath(req) {
  const authority = req.headers.host || req.headers[":authority"] || "localhost";
  return new URL(req.url, `http://${authority}`).pathname;
}

function requestUrl(req) {
  const authority = req.headers.host || req.headers[":authority"] || "localhost";
  return new URL(req.url, `http://${authority}`);
}

function sanitizeRequestId(value) {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  if (trimmed.length > 160) {
    return null;
  }
  if (!/^[A-Za-z0-9._:-]+$/.test(trimmed)) {
    return null;
  }
  return trimmed;
}

function getIncomingRequestId(req) {
  const candidates = [
    req.headers["x-loom-request-id"],
    req.headers["x-request-id"],
    req.headers["x-correlation-id"]
  ];
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) {
      for (const entry of candidate) {
        const normalized = sanitizeRequestId(entry);
        if (normalized) {
          return normalized;
        }
      }
      continue;
    }
    const normalized = sanitizeRequestId(candidate);
    if (normalized) {
      return normalized;
    }
  }
  return null;
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

function normalizePem(value) {
  if (value == null) {
    return null;
  }
  const normalized = String(value).replace(/\\n/g, "\n").trim();
  return normalized ? `${normalized}\n` : null;
}

function readPemFile(value) {
  const filePath = String(value || "").trim();
  if (!filePath) {
    return null;
  }

  const raw = readFileSync(filePath, "utf-8");
  return normalizePem(raw);
}

function resolveNativeTlsConfig(options = {}) {
  const enabled = parseBoolean(options.nativeTlsEnabled ?? process.env.LOOM_NATIVE_TLS_ENABLED, false);
  if (!enabled) {
    return {
      enabled: false
    };
  }

  const certPem =
    normalizePem(options.nativeTlsCertPem ?? process.env.LOOM_NATIVE_TLS_CERT_PEM) ??
    readPemFile(options.nativeTlsCertFile ?? process.env.LOOM_NATIVE_TLS_CERT_FILE);
  const keyPem =
    normalizePem(options.nativeTlsKeyPem ?? process.env.LOOM_NATIVE_TLS_KEY_PEM) ??
    readPemFile(options.nativeTlsKeyFile ?? process.env.LOOM_NATIVE_TLS_KEY_FILE);
  if (!certPem || !keyPem) {
    throw new Error("Native TLS requires both certificate and private key");
  }

  const minVersion = String(options.nativeTlsMinVersion ?? process.env.LOOM_NATIVE_TLS_MIN_VERSION ?? "TLSv1.3").trim();
  if (minVersion !== "TLSv1.3") {
    throw new Error("Native TLS minimum version must be TLSv1.3");
  }

  return {
    enabled: true,
    certPem,
    keyPem,
    minVersion,
    allowHttp1: parseBoolean(options.nativeTlsAllowHttp1 ?? process.env.LOOM_NATIVE_TLS_ALLOW_HTTP1, true)
  };
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

function normalizeForwardedProto(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (!normalized) {
    return null;
  }
  if (normalized === "https" || normalized === "http") {
    return normalized;
  }
  return null;
}

function extractForwardedProto(req) {
  const forwardedProto = req.headers["x-forwarded-proto"];
  if (Array.isArray(forwardedProto) && forwardedProto.length > 0) {
    const [first] = String(forwardedProto[0] || "").split(",");
    return normalizeForwardedProto(first);
  }
  if (typeof forwardedProto === "string" && forwardedProto.trim()) {
    const [first] = forwardedProto.split(",");
    return normalizeForwardedProto(first);
  }

  const forwarded = req.headers.forwarded;
  if (typeof forwarded !== "string" || !forwarded.trim()) {
    return null;
  }
  const firstSegment = forwarded.split(",")[0] || "";
  const protoMatch = firstSegment.match(/(?:^|;)\s*proto=([^;]+)/i);
  if (!protoMatch) {
    return null;
  }
  const cleaned = String(protoMatch[1] || "")
    .trim()
    .replace(/^"|"$/g, "");
  return normalizeForwardedProto(cleaned);
}

function isRequestSecure(req, options = {}) {
  const requireHttpsFromProxy = options.requireHttpsFromProxy === true;
  const trustProxyConfig = options.trustProxyConfig || null;
  if (req.socket?.encrypted === true) {
    return true;
  }
  if (!requireHttpsFromProxy) {
    return false;
  }
  if (!canTrustProxyHeaders(req, trustProxyConfig)) {
    return false;
  }
  return extractForwardedProto(req) === "https";
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
  if (method === "PATCH" && path.startsWith("/v1/identity/")) {
    return true;
  }

  if (method !== "POST") {
    return false;
  }

  if (
    path === "/v1/identity" ||
    path === "/v1/identity/challenge" ||
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
    path === "/v1/admin/content-filter/config" ||
    path === "/v1/webhooks" ||
    path === "/v1/webhooks/outbox/process" ||
    path === "/v1/federation/deliver" ||
    path === "/v1/federation/challenge" ||
    path === "/v1/federation/outbox/process" ||
    path === "/v1/federation/nodes/revalidate" ||
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

  if (path.startsWith("/v1/federation/nodes/") && path.endsWith("/revalidate")) {
    return true;
  }

  if (path.startsWith("/v1/email/outbox/") && path.endsWith("/process")) {
    return true;
  }

  if (path.startsWith("/v1/email/outbox/") && path.endsWith("/dsn")) {
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
    getStatus() {
      return {
        enabled,
        window_ms: windowMs,
        default_max: defaultMax,
        sensitive_max: sensitiveMax,
        tracked_buckets: stateByKey.size
      };
    },
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

  const parts = String(authorization).split(" ", 2);
  if (!parts[0] || parts[0].toLowerCase() !== "bearer" || !parts[1]) {
    return null;
  }

  return parts[1];
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
  store.enforceIdentityRateLimit({
    identity: session.identity,
    method: req.method || "GET",
    path: requestPath(req)
  });
  return session.identity;
}

function requireActorSession(req, store) {
  const token = getBearerToken(req);
  const session = store.authenticateAccessToken(token);
  store.enforceIdentityRateLimit({
    identity: session.identity,
    method: req.method || "GET",
    path: requestPath(req)
  });
  return session;
}

function resolveOptionalActorIdentity(req, store) {
  const token = getBearerToken(req);
  if (!token) {
    return null;
  }
  const session = store.authenticateAccessToken(token);
  store.enforceIdentityRateLimit({
    identity: session.identity,
    method: req.method || "GET",
    path: requestPath(req)
  });
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

function hasValidAdminToken(req, adminToken) {
  if (!adminToken) {
    return false;
  }
  const provided = getAdminToken(req);
  return Boolean(provided && constantTimeEqual(provided, adminToken));
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
  lines.push("# HELP loom_federation_outbox_lag_ms Age of the oldest queued federation outbox item in milliseconds.");
  lines.push("# TYPE loom_federation_outbox_lag_ms gauge");
  lines.push(`loom_federation_outbox_lag_ms ${federationOutbox.lag_ms || 0}`);

  lines.push("# HELP loom_email_outbox_total Total outbound email outbox items.");
  lines.push("# TYPE loom_email_outbox_total gauge");
  lines.push(`loom_email_outbox_total ${emailOutbox.total}`);
  lines.push(`loom_email_outbox_queued ${emailOutbox.queued}`);
  lines.push(`loom_email_outbox_delivered ${emailOutbox.delivered}`);
  lines.push(`loom_email_outbox_failed ${emailOutbox.failed}`);
  lines.push(`loom_email_outbox_retry_scheduled ${emailOutbox.retry_scheduled}`);
  lines.push("# HELP loom_email_outbox_lag_ms Age of the oldest queued email outbox item in milliseconds.");
  lines.push("# TYPE loom_email_outbox_lag_ms gauge");
  lines.push(`loom_email_outbox_lag_ms ${emailOutbox.lag_ms || 0}`);

  lines.push("# HELP loom_webhook_outbox_total Total webhook outbox items.");
  lines.push("# TYPE loom_webhook_outbox_total gauge");
  lines.push(`loom_webhook_outbox_total ${webhookOutbox.total}`);
  lines.push(`loom_webhook_outbox_queued ${webhookOutbox.queued}`);
  lines.push(`loom_webhook_outbox_delivered ${webhookOutbox.delivered}`);
  lines.push(`loom_webhook_outbox_failed ${webhookOutbox.failed}`);
  lines.push(`loom_webhook_outbox_retry_scheduled ${webhookOutbox.retry_scheduled}`);
  lines.push("# HELP loom_webhook_outbox_lag_ms Age of the oldest queued webhook outbox item in milliseconds.");
  lines.push("# TYPE loom_webhook_outbox_lag_ms gauge");
  lines.push(`loom_webhook_outbox_lag_ms ${webhookOutbox.lag_ms || 0}`);

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
    lines.push(
      `loom_inbound_content_filter_enabled ${federationInboundPolicy.content_filter_enabled ? 1 : 0}`
    );
    lines.push(
      `loom_inbound_content_filter_reject_malware ${federationInboundPolicy.content_filter_reject_malware ? 1 : 0}`
    );
    lines.push(
      `loom_inbound_content_filter_evaluated_total ${Number(federationInboundPolicy.content_filter_evaluated || 0)}`
    );
    lines.push(
      `loom_inbound_content_filter_rejected_total ${Number(federationInboundPolicy.content_filter_rejected || 0)}`
    );
    lines.push(
      `loom_inbound_content_filter_quarantined_total ${Number(federationInboundPolicy.content_filter_quarantined || 0)}`
    );
    lines.push(
      `loom_inbound_content_filter_spam_labeled_total ${Number(federationInboundPolicy.content_filter_spam_labeled || 0)}`
    );
    lines.push(
      `loom_inbound_content_filter_decision_log_enabled ${federationInboundPolicy.content_filter?.decision_log_enabled ? 1 : 0}`
    );
    lines.push(
      `loom_inbound_content_filter_decision_log_sink_configured ${federationInboundPolicy.content_filter?.decision_log_sink_configured ? 1 : 0}`
    );
    const profileDecisionCounts =
      federationInboundPolicy.content_filter_decision_counts_by_profile &&
      typeof federationInboundPolicy.content_filter_decision_counts_by_profile === "object"
        ? federationInboundPolicy.content_filter_decision_counts_by_profile
        : {};
    lines.push(
      "# HELP loom_inbound_content_filter_profile_evaluated_total Content filter evaluations grouped by active profile."
    );
    lines.push("# TYPE loom_inbound_content_filter_profile_evaluated_total counter");
    lines.push(
      "# HELP loom_inbound_content_filter_profile_spam_labeled_total Content filter spam labels grouped by active profile."
    );
    lines.push("# TYPE loom_inbound_content_filter_profile_spam_labeled_total counter");
    lines.push(
      "# HELP loom_inbound_content_filter_decisions_total Content filter allow/quarantine/reject decisions grouped by active profile."
    );
    lines.push("# TYPE loom_inbound_content_filter_decisions_total counter");
    for (const profile of ["strict", "balanced", "agent"]) {
      const counts =
        profileDecisionCounts[profile] && typeof profileDecisionCounts[profile] === "object"
          ? profileDecisionCounts[profile]
          : {};
      lines.push(
        `loom_inbound_content_filter_profile_evaluated_total{profile="${profile}"} ${Number(
          counts.evaluated || 0
        )}`
      );
      lines.push(
        `loom_inbound_content_filter_profile_spam_labeled_total{profile="${profile}"} ${Number(
          counts.spam_labeled || 0
        )}`
      );
      for (const action of ["allow", "quarantine", "reject"]) {
        lines.push(
          `loom_inbound_content_filter_decisions_total{profile="${profile}",action="${action}"} ${Number(
            counts[action] || 0
          )}`
        );
      }
    }
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

  if (runtimeStatus?.federation_trust_revalidation_worker) {
    const worker = runtimeStatus.federation_trust_revalidation_worker;
    lines.push(
      "# HELP loom_federation_trust_revalidation_worker_enabled Whether federation trust revalidation worker is enabled (1 or 0)."
    );
    lines.push("# TYPE loom_federation_trust_revalidation_worker_enabled gauge");
    lines.push(`loom_federation_trust_revalidation_worker_enabled ${worker.enabled ? 1 : 0}`);
    lines.push(`loom_federation_trust_revalidation_worker_in_progress ${worker.in_progress ? 1 : 0}`);
    lines.push(`loom_federation_trust_revalidation_worker_runs_total ${Number(worker.runs_total || 0)}`);
    lines.push(
      `loom_federation_trust_revalidation_worker_last_revalidated_count ${Number(worker.last_revalidated_count || 0)}`
    );
    lines.push(
      `loom_federation_trust_revalidation_worker_last_skipped_count ${Number(worker.last_skipped_count || 0)}`
    );
    lines.push(`loom_federation_trust_revalidation_worker_last_failed_count ${Number(worker.last_failed_count || 0)}`);
    lines.push(`loom_federation_trust_revalidation_worker_last_error ${worker.last_error ? 1 : 0}`);
    lines.push(`loom_federation_trust_revalidation_worker_batch_backoff_ms ${Number(worker.batch_backoff_ms || 0)}`);
    lines.push(`loom_federation_trust_revalidation_worker_interval_ms ${Number(worker.interval_ms || 0)}`);
    lines.push(`loom_federation_trust_revalidation_worker_batch_limit ${Number(worker.batch_limit || 0)}`);
    lines.push(
      `loom_federation_trust_revalidation_worker_include_non_public_modes ${worker.include_non_public_modes ? 1 : 0}`
    );
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
  options = { ...options };
  applyConfigProfileOptionDefaults(options, process.env);
  const protocolProfile = normalizeProtocolProfile(
    options.protocolProfile ??
      process.env.LOOM_PROTOCOL_PROFILE ??
      options.store?.protocolProfile ??
      PROTOCOL_PROFILE_FULL,
    PROTOCOL_PROFILE_FULL
  );
  const coreProtocolProfile = protocolProfile === PROTOCOL_PROFILE_CORE;
  const emailBridgeExtensionEnabled =
    parseBoolean(
      options.emailBridgeExtensionEnabled ??
        process.env.LOOM_EXTENSION_EMAIL_BRIDGE_ENABLED ??
        options.store?.emailBridgeExtensionEnabled,
      !coreProtocolProfile
    ) && !coreProtocolProfile;
  const legacyGatewayExtensionEnabled =
    parseBoolean(
      options.legacyGatewayExtensionEnabled ??
        process.env.LOOM_EXTENSION_LEGACY_GATEWAY_ENABLED ??
        options.store?.legacyGatewayExtensionEnabled,
      !coreProtocolProfile
    ) && !coreProtocolProfile;
  const mcpRuntimeExtensionEnabled =
    parseBoolean(
      options.mcpRuntimeExtensionEnabled ??
        process.env.LOOM_EXTENSION_MCP_RUNTIME_ENABLED ??
        options.store?.mcpRuntimeExtensionEnabled,
      !coreProtocolProfile
    ) && !coreProtocolProfile;
  const workflowExtensionEnabled =
    parseBoolean(
      options.workflowExtensionEnabled ??
        process.env.LOOM_EXTENSION_WORKFLOW_ENABLED ??
        options.store?.workflowExtensionEnabled,
      !coreProtocolProfile
    ) && !coreProtocolProfile;
  const e2eeExtensionEnabled =
    parseBoolean(
      options.e2eeExtensionEnabled ??
        process.env.LOOM_EXTENSION_E2EE_ENABLED ??
        options.store?.e2eeExtensionEnabled,
      !coreProtocolProfile
    ) && !coreProtocolProfile;
  const complianceExtensionEnabled =
    parseBoolean(
      options.complianceExtensionEnabled ??
        process.env.LOOM_EXTENSION_COMPLIANCE_ENABLED ??
        options.store?.complianceExtensionEnabled,
      !coreProtocolProfile
    ) && !coreProtocolProfile;
  const idempotencyTtlMs = parsePositiveNumber(
    options.idempotencyTtlMs ?? process.env.LOOM_IDEMPOTENCY_TTL_MS,
    24 * 60 * 60 * 1000
  );
  const idempotencyMaxEntries = parsePositiveNumber(
    options.idempotencyMaxEntries ?? process.env.LOOM_IDEMPOTENCY_MAX_ENTRIES,
    10000
  );
  const consumedCapabilityMaxEntries = parsePositiveNumber(
    options.consumedCapabilityMaxEntries ?? process.env.LOOM_CONSUMED_CAPABILITY_MAX_ENTRIES,
    50000
  );
  const revokedDelegationMaxEntries = parsePositiveNumber(
    options.revokedDelegationMaxEntries ?? process.env.LOOM_REVOKED_DELEGATION_MAX_ENTRIES,
    50000
  );
  const maxLocalIdentities = parsePositiveNumber(
    options.maxLocalIdentities ?? process.env.LOOM_MAX_LOCAL_IDENTITIES,
    10000
  );
  const maxRemoteIdentities = parsePositiveNumber(
    options.maxRemoteIdentities ?? process.env.LOOM_MAX_REMOTE_IDENTITIES,
    50000
  );
  const maxDelegationsPerIdentity = parsePositiveNumber(
    options.maxDelegationsPerIdentity ?? process.env.LOOM_MAX_DELEGATIONS_PER_IDENTITY,
    500
  );
  const maxDelegationsTotal = parsePositiveNumber(
    options.maxDelegationsTotal ?? process.env.LOOM_MAX_DELEGATIONS_TOTAL,
    100000
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
  const domain = options.domain || "localhost";
  const localIdentityAuthority =
    options.identityDomain ?? process.env.LOOM_IDENTITY_DOMAIN ?? options.nodeId ?? domain;
  const localIdentityDomain = normalizeIdentityDomain(localIdentityAuthority);
  const identityRequireProof = parseBoolean(
    options.identityRequireProof ?? process.env.LOOM_IDENTITY_REQUIRE_PROOF,
    false
  );
  const identityChallengeTtlMs = parsePositiveNumber(
    options.identityChallengeTtlMs ?? process.env.LOOM_IDENTITY_CHALLENGE_TTL_MS,
    2 * 60 * 1000
  );
  const remoteIdentityTtlMs = parsePositiveNumber(
    options.remoteIdentityTtlMs ?? process.env.LOOM_REMOTE_IDENTITY_TTL_MS,
    24 * 60 * 60 * 1000
  );
  const identityRateWindowMs = parsePositiveNumber(
    options.identityRateWindowMs ?? process.env.LOOM_IDENTITY_RATE_LIMIT_WINDOW_MS,
    60 * 1000
  );
  const identityRateDefaultMax = parsePositiveNumber(
    options.identityRateDefaultMax ?? process.env.LOOM_IDENTITY_RATE_LIMIT_DEFAULT_MAX,
    2000
  );
  const identityRateSensitiveMax = parsePositiveNumber(
    options.identityRateSensitiveMax ?? process.env.LOOM_IDENTITY_RATE_LIMIT_SENSITIVE_MAX,
    400
  );
  const envelopeDailyMax = Math.max(
    0,
    Math.floor(
      parsePositiveNumber(options.envelopeDailyMax ?? process.env.LOOM_ENVELOPE_DAILY_MAX, 0)
    )
  );
  const threadRecipientFanoutMax = Math.max(
    0,
    Math.floor(
      parsePositiveNumber(options.threadRecipientFanoutMax ?? process.env.LOOM_THREAD_RECIPIENT_MAX, 0)
    )
  );
  const blobDailyCountMax = Math.max(
    0,
    Math.floor(
      parsePositiveNumber(options.blobDailyCountMax ?? process.env.LOOM_BLOB_DAILY_COUNT_MAX, 0)
    )
  );
  const blobDailyBytesMax = Math.max(
    0,
    Math.floor(
      parsePositiveNumber(options.blobDailyBytesMax ?? process.env.LOOM_BLOB_DAILY_BYTES_MAX, 0)
    )
  );
  const blobIdentityTotalBytesMax = Math.max(
    0,
    Math.floor(
      parsePositiveNumber(
        options.blobIdentityTotalBytesMax ?? process.env.LOOM_BLOB_IDENTITY_TOTAL_BYTES_MAX,
        0
      )
    )
  );
  const federationResolveRemoteIdentities = parseBoolean(
    options.federationResolveRemoteIdentities ?? process.env.LOOM_FEDERATION_REMOTE_IDENTITY_RESOLVE_ENABLED,
    true
  );
  const federationRequireSignedRemoteIdentity = parseBoolean(
    options.federationRequireSignedRemoteIdentity ?? process.env.LOOM_FEDERATION_REQUIRE_SIGNED_REMOTE_IDENTITY,
    true
  );
  const federationRemoteIdentityFetchTimeoutMs = parsePositiveNumber(
    options.federationRemoteIdentityFetchTimeoutMs ?? process.env.LOOM_FEDERATION_REMOTE_IDENTITY_TIMEOUT_MS,
    5000
  );
  const federationRemoteIdentityMaxResponseBytes = parsePositiveNumber(
    options.federationRemoteIdentityMaxResponseBytes ?? process.env.LOOM_FEDERATION_REMOTE_IDENTITY_MAX_RESPONSE_BYTES,
    256 * 1024
  );
  const federationDeliverTimeoutMs = parsePositiveNumber(
    options.federationDeliverTimeoutMs ?? process.env.LOOM_FEDERATION_DELIVER_TIMEOUT_MS,
    10 * 1000
  );
  const federationDeliverMaxResponseBytes = parsePositiveNumber(
    options.federationDeliverMaxResponseBytes ?? process.env.LOOM_FEDERATION_DELIVER_MAX_RESPONSE_BYTES,
    256 * 1024
  );
  const webhookMaxResponseBytes = parsePositiveNumber(
    options.webhookMaxResponseBytes ?? process.env.LOOM_WEBHOOK_MAX_RESPONSE_BYTES,
    256 * 1024
  );
  const auditHmacKeyRaw = options.auditHmacKey ?? process.env.LOOM_AUDIT_HMAC_KEY ?? null;
  const auditHmacKey =
    typeof auditHmacKeyRaw === "string" && auditHmacKeyRaw.trim().length > 0 ? auditHmacKeyRaw.trim() : null;
  const auditRequireMacValidation = parseBoolean(
    options.auditRequireMacValidation ?? process.env.LOOM_AUDIT_REQUIRE_MAC_VALIDATION,
    false
  );
  const auditValidateChain = parseBoolean(
    options.auditValidateChain ?? process.env.LOOM_AUDIT_VALIDATE_CHAIN,
    true
  );
  const denyMetadataHosts = parseBoolean(
    options.denyMetadataHosts ?? process.env.LOOM_DENY_METADATA_HOSTS,
    true
  );
  const federationOutboundHostAllowlist = parseHostAllowlist(
    options.federationOutboundHostAllowlist ?? process.env.LOOM_FEDERATION_HOST_ALLOWLIST
  );
  const federationBootstrapHostAllowlist = parseHostAllowlist(
    options.federationBootstrapHostAllowlist ?? process.env.LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST
  );
  const webhookOutboundHostAllowlist = parseHostAllowlist(
    options.webhookOutboundHostAllowlist ?? process.env.LOOM_WEBHOOK_HOST_ALLOWLIST
  );
  const remoteIdentityHostAllowlist = parseHostAllowlist(
    options.remoteIdentityHostAllowlist ?? process.env.LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST
  );
  const federationTrustAnchorBindings =
    options.federationTrustAnchorBindings ?? process.env.LOOM_FEDERATION_TRUST_ANCHORS ?? null;
  const federationTrustMode = options.federationTrustMode ?? process.env.LOOM_FEDERATION_TRUST_MODE ?? null;
  const federationTrustFailClosed = parseBoolean(
    options.federationTrustFailClosed ?? process.env.LOOM_FEDERATION_TRUST_FAIL_CLOSED,
    true
  );
  const federationTrustMaxClockSkewMs = parsePositiveNumber(
    options.federationTrustMaxClockSkewMs ?? process.env.LOOM_FEDERATION_TRUST_MAX_CLOCK_SKEW_MS,
    5 * 60 * 1000
  );
  const federationTrustKeysetMaxAgeMs = parsePositiveNumber(
    options.federationTrustKeysetMaxAgeMs ?? process.env.LOOM_FEDERATION_TRUST_KEYSET_MAX_AGE_MS,
    24 * 60 * 60 * 1000
  );
  const federationTrustKeysetPublishTtlMs = parsePositiveNumber(
    options.federationTrustKeysetPublishTtlMs ?? process.env.LOOM_FEDERATION_TRUST_KEYSET_PUBLISH_TTL_MS,
    24 * 60 * 60 * 1000
  );
  const federationTrustDnsTxtLabel =
    options.federationTrustDnsTxtLabel ?? process.env.LOOM_FEDERATION_TRUST_DNS_TXT_LABEL ?? "_loomfed";
  const federationTrustDnsResolverMode = String(
    options.federationTrustDnsResolverMode ?? process.env.LOOM_FEDERATION_TRUST_DNS_RESOLVER_MODE ?? "system"
  )
    .trim()
    .toLowerCase();
  const federationTrustDnssecDohUrl =
    options.federationTrustDnssecDohUrl ?? process.env.LOOM_FEDERATION_TRUST_DNSSEC_DOH_URL ?? "https://cloudflare-dns.com/dns-query";
  const federationTrustDnssecDohTimeoutMs = Math.max(
    500,
    Math.floor(
      parsePositiveNumber(
        options.federationTrustDnssecDohTimeoutMs ?? process.env.LOOM_FEDERATION_TRUST_DNSSEC_DOH_TIMEOUT_MS,
        5000
      )
    )
  );
  const federationTrustDnssecDohMaxResponseBytes = Math.max(
    1024,
    Math.floor(
      parsePositiveNumber(
        options.federationTrustDnssecDohMaxResponseBytes ??
          process.env.LOOM_FEDERATION_TRUST_DNSSEC_DOH_MAX_RESPONSE_BYTES,
        256 * 1024
      )
    )
  );
  const federationTrustLocalEpoch = Math.max(
    0,
    Math.floor(
      parsePositiveNumber(options.federationTrustLocalEpoch ?? process.env.LOOM_FEDERATION_TRUST_LOCAL_EPOCH, 1)
    )
  );
  const federationTrustKeysetVersion = Math.max(
    0,
    Math.floor(
      parsePositiveNumber(options.federationTrustKeysetVersion ?? process.env.LOOM_FEDERATION_TRUST_KEYSET_VERSION, 1)
    )
  );
  const federationTrustRevokedKeyIds = parseStringList(
    options.federationTrustRevokedKeyIds ?? process.env.LOOM_FEDERATION_REVOKED_KEY_IDS
  );
  const nativeTlsConfig = resolveNativeTlsConfig(options);
  const publicService = parseBoolean(
    options.publicService ?? process.env.LOOM_PUBLIC_SERVICE,
    false
  );
  const federationTrustModeNormalized = String(federationTrustMode || "")
    .trim()
    .toLowerCase();
  const federationTrustRequireDnssec = parseBoolean(
    options.federationTrustRequireDnssec ?? process.env.LOOM_FEDERATION_TRUST_REQUIRE_DNSSEC,
    publicService && federationTrustModeNormalized === "public_dns_webpki"
  );
  const federationTrustRequireTransparency = parseBoolean(
    options.federationTrustRequireTransparency ?? process.env.LOOM_FEDERATION_TRUST_REQUIRE_TRANSPARENCY,
    publicService && federationTrustModeNormalized === "public_dns_webpki"
  );
  const federationTrustTransparencyMode = String(
    options.federationTrustTransparencyMode ?? process.env.LOOM_FEDERATION_TRUST_TRANSPARENCY_MODE ?? "local_append_only"
  )
    .trim()
    .toLowerCase();
  const requirePortableThreadOpCapability = parseBoolean(
    options.requirePortableThreadOpCapability ?? process.env.LOOM_REQUIRE_PORTABLE_THREAD_OP_CAPABILITY,
    publicService
  );
  const outboxClaimLeaseMs = Math.max(
    5000,
    Math.floor(
      parsePositiveNumber(options.outboxClaimLeaseMs ?? process.env.LOOM_OUTBOX_CLAIM_LEASE_MS, 60 * 1000)
    )
  );
  const outboxWorkerIdRaw = options.outboxWorkerId ?? process.env.LOOM_OUTBOX_WORKER_ID ?? null;
  const outboxWorkerId =
    typeof outboxWorkerIdRaw === "string" && outboxWorkerIdRaw.trim().length > 0 ? outboxWorkerIdRaw.trim() : null;
  let federationTrustDnsTxtResolver = null;
  if (typeof options.federationTrustDnsTxtResolver === "function") {
    federationTrustDnsTxtResolver = options.federationTrustDnsTxtResolver;
  } else if (federationTrustDnsResolverMode === "dnssec_doh") {
    federationTrustDnsTxtResolver = createDnssecDohTxtResolver({
      endpoint: federationTrustDnssecDohUrl,
      timeoutMs: federationTrustDnssecDohTimeoutMs,
      maxResponseBytes: federationTrustDnssecDohMaxResponseBytes
    });
  }
  const requireExternalSigningKeys = parseBoolean(
    options.requireExternalSigningKeys ?? process.env.LOOM_REQUIRE_EXTERNAL_SIGNING_KEYS,
    publicService
  );
  if (publicService && !requireExternalSigningKeys) {
    throw new Error(
      "Public service requires externally provisioned signing keys (set LOOM_REQUIRE_EXTERNAL_SIGNING_KEYS=true)."
    );
  }
  const requireDistinctFederationSigningKey = parseBoolean(
    options.requireDistinctFederationSigningKey ?? process.env.LOOM_REQUIRE_DISTINCT_FEDERATION_SIGNING_KEY,
    false
  );
  const federationRequireProtocolCapabilities = parseBoolean(
    options.federationRequireProtocolCapabilities ?? process.env.LOOM_FEDERATION_REQUIRE_PROTOCOL_CAPABILITIES,
    false
  );
  const federationRequireE2eeProfileOverlap = parseBoolean(
    options.federationRequireE2eeProfileOverlap ?? process.env.LOOM_FEDERATION_REQUIRE_E2EE_PROFILE_OVERLAP,
    false
  );
  const federationRequireTrustModeParity = parseBoolean(
    options.federationRequireTrustModeParity ?? process.env.LOOM_FEDERATION_REQUIRE_TRUST_MODE_PARITY,
    false
  );
  const e2eeProfileMigrationAllowlist =
    options.e2eeProfileMigrationAllowlist ?? process.env.LOOM_E2EE_PROFILE_MIGRATION_ALLOWLIST ?? null;
  const messageRetentionDays = Math.max(
    0,
    Math.floor(parsePositiveNumber(options.messageRetentionDays ?? process.env.LOOM_MESSAGE_RETENTION_DAYS, 0))
  );
  const blobRetentionDays = Math.max(
    0,
    Math.floor(parsePositiveNumber(options.blobRetentionDays ?? process.env.LOOM_BLOB_RETENTION_DAYS, 0))
  );
  const requireStateEncryptionAtRest = parseBoolean(
    options.requireStateEncryptionAtRest ?? process.env.LOOM_REQUIRE_STATE_ENCRYPTION_AT_REST,
    false
  );
  const stateEncryptionKey = options.stateEncryptionKey ?? process.env.LOOM_STATE_ENCRYPTION_KEY ?? null;
  const systemSigningKeyId = options.systemSigningKeyId ?? process.env.LOOM_SYSTEM_SIGNING_KEY_ID ?? null;
  const systemSigningPrivateKeyPem = normalizePemOption(
    options.systemSigningPrivateKeyPem ?? process.env.LOOM_SYSTEM_SIGNING_PRIVATE_KEY_PEM ?? null
  );
  const systemSigningPublicKeyPem = normalizePemOption(
    options.systemSigningPublicKeyPem ?? process.env.LOOM_SYSTEM_SIGNING_PUBLIC_KEY_PEM ?? null
  );
  const federationSigningPrivateKeyPem = normalizePemOption(
    options.federationSigningPrivateKeyPem ?? process.env.LOOM_NODE_SIGNING_PRIVATE_KEY_PEM ?? null
  );
  const store =
    options.store ||
    new LoomStore({
      nodeId: options.nodeId,
      protocolProfile,
      emailBridgeExtensionEnabled,
      legacyGatewayExtensionEnabled,
      mcpRuntimeExtensionEnabled,
      workflowExtensionEnabled,
      e2eeExtensionEnabled,
      complianceExtensionEnabled,
      dataDir: options.dataDir,
      systemSigningKeyId,
      systemSigningPrivateKeyPem,
      systemSigningPublicKeyPem,
      requireExternalSigningKeys,
      requireDistinctFederationSigningKey,
      federationSigningKeyId: options.federationSigningKeyId,
      federationSigningPrivateKeyPem,
      federationRequireProtocolCapabilities,
      federationRequireE2eeProfileOverlap,
      federationRequireTrustModeParity,
      e2eeProfileMigrationAllowlist,
      persistenceAdapter: options.persistenceAdapter,
      idempotencyTtlMs,
      idempotencyMaxEntries,
      consumedCapabilityMaxEntries,
      revokedDelegationMaxEntries,
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
      federationChallengeDurationMs,
      identityRegistrationProofRequired: identityRequireProof,
      identityRegistrationChallengeTtlMs: identityChallengeTtlMs,
      remoteIdentityTtlMs,
      identityRateWindowMs,
      identityRateDefaultMax,
      identityRateSensitiveMax,
      envelopeDailyMax,
      threadRecipientFanoutMax,
      blobDailyCountMax,
      blobDailyBytesMax,
      blobIdentityTotalBytesMax,
      federationResolveRemoteIdentities,
      federationRequireSignedRemoteIdentity,
      federationRemoteIdentityFetchTimeoutMs,
      federationRemoteIdentityMaxResponseBytes,
      federationDeliverTimeoutMs,
      federationDeliverMaxResponseBytes,
      webhookMaxResponseBytes,
      denyMetadataHosts,
      auditHmacKey,
      auditRequireMacValidation,
      auditValidateChain,
      federationOutboundHostAllowlist,
      federationBootstrapHostAllowlist,
      webhookOutboundHostAllowlist,
      remoteIdentityHostAllowlist,
      federationTrustAnchorBindings,
      federationTrustMode,
      federationTrustFailClosed,
      federationTrustMaxClockSkewMs,
      federationTrustKeysetMaxAgeMs,
      federationTrustKeysetPublishTtlMs,
      federationTrustDnsTxtLabel,
      federationTrustDnsTxtResolver,
      federationTrustRequireDnssec,
      federationTrustRequireTransparency,
      federationTrustTransparencyMode,
      federationTrustLocalEpoch,
      federationTrustKeysetVersion,
      federationTrustRevokedKeyIds,
      localIdentityDomain,
      outboxClaimLeaseMs,
      outboxWorkerId,
      maxLocalIdentities,
      maxRemoteIdentities,
      maxDelegationsPerIdentity,
      maxDelegationsTotal,
      messageRetentionDays,
      blobRetentionDays,
      requireStateEncryptionAtRest,
      stateEncryptionKey,
      outboxBackpressureMax: Math.max(
        0,
        Math.floor(
          parsePositiveNumber(
            options.outboxBackpressureMax ?? process.env.LOOM_OUTBOX_BACKPRESSURE_MAX,
            0
          )
        )
      )
    });
  store.protocolProfile = protocolProfile;
  store.coreProtocolProfile = coreProtocolProfile;
  store.emailBridgeExtensionEnabled = emailBridgeExtensionEnabled;
  store.legacyGatewayExtensionEnabled = legacyGatewayExtensionEnabled;
  store.mcpRuntimeExtensionEnabled = mcpRuntimeExtensionEnabled;
  store.workflowExtensionEnabled = workflowExtensionEnabled;
  store.e2eeExtensionEnabled = e2eeExtensionEnabled;
  store.complianceExtensionEnabled = complianceExtensionEnabled;
  store.mcpClientEnabled = store.mcpClientEnabled !== false && mcpRuntimeExtensionEnabled;
  const maxBodyBytes = parsePositiveNumber(
    options.maxBodyBytes ?? process.env.LOOM_MAX_BODY_BYTES,
    DEFAULT_MAX_BODY_BYTES
  );
  const trustProxyConfig = resolveTrustedProxyConfig({
    trustProxy: options.trustProxy ?? process.env.LOOM_TRUST_PROXY,
    trustProxyAllowlist:
      options.trustProxyAllowlist ?? process.env.LOOM_TRUST_PROXY_ALLOWLIST ?? null
  });
  const requireHttpsFromProxy = parseBoolean(
    options.requireHttpsFromProxy ?? process.env.LOOM_REQUIRE_HTTPS_FROM_PROXY,
    publicService && !nativeTlsConfig.enabled
  );
  if (requireHttpsFromProxy && !nativeTlsConfig.enabled && !trustProxyConfig.enabled) {
    throw new Error(
      "LOOM_REQUIRE_HTTPS_FROM_PROXY requires trusted proxy headers; set LOOM_TRUST_PROXY=true or LOOM_TRUST_PROXY_ALLOWLIST"
    );
  }
  const blobMaxBytes = parsePositiveNumber(options.blobMaxBytes ?? process.env.LOOM_BLOB_MAX_BYTES, 25 * 1024 * 1024);
  const blobMaxPartBytes = parsePositiveNumber(
    options.blobMaxPartBytes ?? process.env.LOOM_BLOB_MAX_PART_BYTES,
    2 * 1024 * 1024
  );
  const blobMaxParts = parsePositiveNumber(options.blobMaxParts ?? process.env.LOOM_BLOB_MAX_PARTS, 64);
  store.blobMaxBytes = blobMaxBytes;
  store.blobMaxPartBytes = blobMaxPartBytes;
  store.blobMaxParts = blobMaxParts;
  store.envelopeDailyMax = envelopeDailyMax;
  store.threadRecipientFanoutMax = threadRecipientFanoutMax;
  store.blobDailyCountMax = blobDailyCountMax;
  store.blobDailyBytesMax = blobDailyBytesMax;
  store.blobIdentityTotalBytesMax = blobIdentityTotalBytesMax;
  store.federationResolveRemoteIdentities = federationResolveRemoteIdentities;
  store.federationRequireSignedRemoteIdentity = federationRequireSignedRemoteIdentity;
  store.federationRemoteIdentityFetchTimeoutMs = Math.max(500, Math.floor(federationRemoteIdentityFetchTimeoutMs));
  store.federationRemoteIdentityMaxResponseBytes = Math.max(1024, Math.floor(federationRemoteIdentityMaxResponseBytes));
  store.federationDeliverTimeoutMs = Math.max(500, Math.floor(federationDeliverTimeoutMs));
  store.federationDeliverMaxResponseBytes = Math.max(1024, Math.floor(federationDeliverMaxResponseBytes));
  store.webhookMaxResponseBytes = Math.max(1024, Math.floor(webhookMaxResponseBytes));
  store.denyMetadataHosts = denyMetadataHosts;
  store.federationOutboundHostAllowlist = federationOutboundHostAllowlist;
  store.federationBootstrapHostAllowlist = federationBootstrapHostAllowlist;
  store.webhookOutboundHostAllowlist = webhookOutboundHostAllowlist;
  store.remoteIdentityHostAllowlist = remoteIdentityHostAllowlist;
  if (federationTrustMode != null && typeof store.resolveFederationBootstrapTrustMode === "function") {
    store.federationTrustMode = store.resolveFederationBootstrapTrustMode({
      trust_anchor_mode: federationTrustMode
    });
  }
  store.federationTrustFailClosed = federationTrustFailClosed;
  store.federationTrustMaxClockSkewMs = Math.max(1000, Math.floor(federationTrustMaxClockSkewMs));
  store.federationTrustKeysetMaxAgeMs = Math.max(60 * 1000, Math.floor(federationTrustKeysetMaxAgeMs));
  store.federationTrustKeysetPublishTtlMs = Math.max(60 * 1000, Math.floor(federationTrustKeysetPublishTtlMs));
  store.federationTrustDnsTxtLabel = String(federationTrustDnsTxtLabel || "_loomfed").trim() || "_loomfed";
  store.federationTrustRequireDnssec = federationTrustRequireDnssec;
  store.federationTrustRequireTransparency = federationTrustRequireTransparency;
  store.federationTrustTransparencyMode = federationTrustTransparencyMode || "local_append_only";
  store.federationTrustLocalEpoch = Math.max(0, Math.floor(federationTrustLocalEpoch));
  store.federationTrustKeysetVersion = Math.max(0, Math.floor(federationTrustKeysetVersion));
  store.federationTrustRevokedKeyIds = federationTrustRevokedKeyIds;
  if (typeof federationTrustDnsTxtResolver === "function") {
    store.federationTrustDnsTxtResolver = federationTrustDnsTxtResolver;
  }
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
  const bridgeInboundEnabled =
    emailBridgeExtensionEnabled &&
    parseBoolean(
      options.bridgeInboundEnabled ?? process.env.LOOM_BRIDGE_EMAIL_INBOUND_ENABLED,
      true
    );
  const bridgeInboundPublicConfirmed = parseBoolean(
    options.bridgeInboundPublicConfirmed ?? process.env.LOOM_BRIDGE_EMAIL_INBOUND_PUBLIC_CONFIRMED,
    false
  );
  const bridgeInboundRequireAuthResults = parseBoolean(
    options.bridgeInboundRequireAuthResults ?? process.env.LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_AUTH_RESULTS,
    publicService && bridgeInboundEnabled
  );
  const bridgeInboundRequireDmarcPass = parseBoolean(
    options.bridgeInboundRequireDmarcPass ?? process.env.LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_DMARC_PASS,
    publicService && bridgeInboundEnabled
  );
  const bridgeInboundRequireAdminToken = parseBoolean(
    options.bridgeInboundRequireAdminToken ??
      process.env.LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_ADMIN_TOKEN,
    publicService && bridgeInboundEnabled
  );
  const bridgeInboundRejectOnAuthFailure = parseBoolean(
    options.bridgeInboundRejectOnAuthFailure ?? process.env.LOOM_BRIDGE_EMAIL_INBOUND_REJECT_ON_AUTH_FAILURE,
    publicService && bridgeInboundEnabled
  );
  const bridgeInboundWeakAuthPolicyConfirmed = parseBoolean(
    options.bridgeInboundWeakAuthPolicyConfirmed ??
      process.env.LOOM_BRIDGE_EMAIL_INBOUND_WEAK_AUTH_POLICY_CONFIRMED,
    false
  );
  const bridgeInboundQuarantineOnAuthFailure = parseBoolean(
    options.bridgeInboundQuarantineOnAuthFailure ??
      process.env.LOOM_BRIDGE_EMAIL_INBOUND_QUARANTINE_ON_AUTH_FAILURE,
    true
  );
  const bridgeInboundAllowPayloadAuthResults = parseBoolean(
    options.bridgeInboundAllowPayloadAuthResults ??
      process.env.LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_PAYLOAD_AUTH_RESULTS,
    true
  );
  const bridgeInboundAllowAutomaticActuation = parseBoolean(
    options.bridgeInboundAllowAutomaticActuation ??
      process.env.LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_AUTOMATIC_ACTUATION,
    false
  );
  const bridgeInboundAutomationConfirmed = parseBoolean(
    options.bridgeInboundAutomationConfirmed ??
      process.env.LOOM_BRIDGE_EMAIL_INBOUND_AUTOMATION_CONFIRMED,
    false
  );
  const inboundContentFilterEnabled = parseBoolean(
    options.inboundContentFilterEnabled ?? process.env.LOOM_INBOUND_CONTENT_FILTER_ENABLED,
    store.inboundContentFilterEnabled
  );
  const inboundContentFilterRejectMalware = parseBoolean(
    options.inboundContentFilterRejectMalware ?? process.env.LOOM_INBOUND_CONTENT_FILTER_REJECT_MALWARE,
    store.inboundContentFilterRejectMalware
  );
  const inboundContentFilterSpamThreshold = Math.max(
    1,
    Math.floor(
      parsePositiveNumber(
        options.inboundContentFilterSpamThreshold ?? process.env.LOOM_INBOUND_CONTENT_FILTER_SPAM_THRESHOLD,
        store.inboundContentFilterSpamThreshold
      )
    )
  );
  const inboundContentFilterPhishThreshold = Math.max(
    1,
    Math.floor(
      parsePositiveNumber(
        options.inboundContentFilterPhishThreshold ?? process.env.LOOM_INBOUND_CONTENT_FILTER_PHISH_THRESHOLD,
        store.inboundContentFilterPhishThreshold
      )
    )
  );
  const inboundContentFilterQuarantineThreshold = Math.max(
    1,
    Math.floor(
      parsePositiveNumber(
        options.inboundContentFilterQuarantineThreshold ??
          process.env.LOOM_INBOUND_CONTENT_FILTER_QUARANTINE_THRESHOLD,
        store.inboundContentFilterQuarantineThreshold
      )
    )
  );
  const inboundContentFilterRejectThreshold = Math.max(
    inboundContentFilterQuarantineThreshold + 1,
    Math.floor(
      parsePositiveNumber(
        options.inboundContentFilterRejectThreshold ?? process.env.LOOM_INBOUND_CONTENT_FILTER_REJECT_THRESHOLD,
        store.inboundContentFilterRejectThreshold
      )
    )
  );
  const inboundContentFilterInjectionThreshold = Math.max(
    1,
    Math.floor(
      parsePositiveNumber(
        options.inboundContentFilterInjectionThreshold ?? process.env.LOOM_INBOUND_CONTENT_FILTER_INJECTION_THRESHOLD,
        store.inboundContentFilterInjectionThreshold
      )
    )
  );
  const inboundContentFilterProfileDefault = normalizeInboundContentFilterProfile(
    options.inboundContentFilterProfileDefault ?? process.env.LOOM_INBOUND_CONTENT_FILTER_PROFILE_DEFAULT,
    store.inboundContentFilterProfileDefault
  );
  const inboundContentFilterProfileBridge = normalizeInboundContentFilterProfile(
    options.inboundContentFilterProfileBridge ?? process.env.LOOM_INBOUND_CONTENT_FILTER_PROFILE_BRIDGE,
    store.inboundContentFilterProfileBridge || inboundContentFilterProfileDefault
  );
  const inboundContentFilterProfileFederation = normalizeInboundContentFilterProfile(
    options.inboundContentFilterProfileFederation ?? process.env.LOOM_INBOUND_CONTENT_FILTER_PROFILE_FEDERATION,
    store.inboundContentFilterProfileFederation
  );
  const inboundContentFilterDecisionLogEnabled = parseBoolean(
    options.inboundContentFilterDecisionLogEnabled ??
      process.env.LOOM_INBOUND_CONTENT_FILTER_DECISION_LOG_ENABLED,
    store.inboundContentFilterDecisionLogEnabled
  );
  const inboundContentFilterDecisionLogFile =
    typeof (options.inboundContentFilterDecisionLogFile ??
      process.env.LOOM_INBOUND_CONTENT_FILTER_DECISION_LOG_FILE) === "string"
      ? String(
          options.inboundContentFilterDecisionLogFile ??
            process.env.LOOM_INBOUND_CONTENT_FILTER_DECISION_LOG_FILE
        ).trim() || null
      : null;
  const inboundContentFilterDecisionLogSalt =
    typeof (options.inboundContentFilterDecisionLogSalt ??
      process.env.LOOM_INBOUND_CONTENT_FILTER_DECISION_LOG_SALT) === "string"
      ? String(
          options.inboundContentFilterDecisionLogSalt ??
            process.env.LOOM_INBOUND_CONTENT_FILTER_DECISION_LOG_SALT
        ).trim() || null
      : null;
  const bridgeInboundHeaderAllowlist = normalizeHeaderAllowlist(
    options.bridgeInboundHeaderAllowlist ?? process.env.LOOM_BRIDGE_EMAIL_INBOUND_HEADER_ALLOWLIST
  );
  if (publicService && bridgeInboundEnabled && !bridgeInboundPublicConfirmed) {
    throw new Error(
      "Refusing public service with LOOM_BRIDGE_EMAIL_INBOUND_ENABLED=true without LOOM_BRIDGE_EMAIL_INBOUND_PUBLIC_CONFIRMED=true"
    );
  }
  if (bridgeInboundEnabled && bridgeInboundRequireAdminToken && !adminToken) {
    throw new Error(
      "LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_ADMIN_TOKEN=true requires LOOM_ADMIN_TOKEN"
    );
  }
  if (publicService && bridgeInboundEnabled) {
    const strictPublicInboundPolicyEnabled =
      bridgeInboundRequireAdminToken &&
      bridgeInboundRequireAuthResults &&
      bridgeInboundRequireDmarcPass &&
      bridgeInboundRejectOnAuthFailure;
    if (!strictPublicInboundPolicyEnabled && !bridgeInboundWeakAuthPolicyConfirmed) {
      throw new Error(
        "Refusing weak public inbound bridge auth policy; enable strict policy or set LOOM_BRIDGE_EMAIL_INBOUND_WEAK_AUTH_POLICY_CONFIRMED=true"
      );
    }
    if (bridgeInboundAllowAutomaticActuation && !bridgeInboundAutomationConfirmed) {
      throw new Error(
        "Refusing public inbound bridge auto-actuation without LOOM_BRIDGE_EMAIL_INBOUND_AUTOMATION_CONFIRMED=true"
      );
    }
  }
  const bridgeOutboundEnabled =
    emailBridgeExtensionEnabled &&
    parseBoolean(
      options.bridgeOutboundEnabled ?? process.env.LOOM_BRIDGE_EMAIL_OUTBOUND_ENABLED,
      true
    );
  const bridgeSendEnabled =
    emailBridgeExtensionEnabled &&
    parseBoolean(options.bridgeSendEnabled ?? process.env.LOOM_BRIDGE_EMAIL_SEND_ENABLED, true);
  const gatewayImapEnabled =
    legacyGatewayExtensionEnabled &&
    parseBoolean(options.gatewayImapEnabled ?? process.env.LOOM_GATEWAY_IMAP_ENABLED, true);
  const gatewaySmtpSubmitEnabled =
    legacyGatewayExtensionEnabled &&
    parseBoolean(
      options.gatewaySmtpSubmitEnabled ?? process.env.LOOM_GATEWAY_SMTP_SUBMIT_ENABLED,
      true
    );
  const mcpRuntimeRoutesEnabled =
    mcpRuntimeExtensionEnabled &&
    parseBoolean(options.mcpRuntimeRoutesEnabled ?? process.env.LOOM_MCP_RUNTIME_ROUTES_ENABLED, true);
  const complianceRoutesEnabled =
    complianceExtensionEnabled &&
    parseBoolean(options.complianceRoutesEnabled ?? process.env.LOOM_COMPLIANCE_ROUTES_ENABLED, true);
  const requestLogEnabled = parseBoolean(options.requestLogEnabled ?? process.env.LOOM_REQUEST_LOG_ENABLED, false);
  const requestLogFormat = normalizeLogFormat(
    options.requestLogFormat ?? process.env.LOOM_REQUEST_LOG_FORMAT ?? "json"
  );
  const demoPublicReads = parseBoolean(
    options.demoPublicReads ?? process.env.LOOM_DEMO_PUBLIC_READS,
    false
  );
  store.bridgeInboundRequireAuthResults = bridgeInboundRequireAuthResults;
  store.bridgeInboundRequireDmarcPass = bridgeInboundRequireDmarcPass;
  store.bridgeInboundRejectOnAuthFailure = bridgeInboundRejectOnAuthFailure;
  store.bridgeInboundQuarantineOnAuthFailure = bridgeInboundQuarantineOnAuthFailure;
  store.bridgeInboundAllowPayloadAuthResults = bridgeInboundAllowPayloadAuthResults;
  store.bridgeInboundAllowAutomaticActuation = bridgeInboundAllowAutomaticActuation;
  store.inboundContentFilterEnabled = inboundContentFilterEnabled;
  store.inboundContentFilterRejectMalware = inboundContentFilterRejectMalware;
  store.inboundContentFilterSpamThreshold = inboundContentFilterSpamThreshold;
  store.inboundContentFilterPhishThreshold = inboundContentFilterPhishThreshold;
  store.inboundContentFilterQuarantineThreshold = inboundContentFilterQuarantineThreshold;
  store.inboundContentFilterRejectThreshold = inboundContentFilterRejectThreshold;
  store.inboundContentFilterInjectionThreshold = inboundContentFilterInjectionThreshold;
  store.inboundContentFilterProfileDefault = inboundContentFilterProfileDefault;
  store.inboundContentFilterProfileBridge = inboundContentFilterProfileBridge;
  store.inboundContentFilterProfileFederation = inboundContentFilterProfileFederation;
  store.inboundContentFilterDecisionLogEnabled = inboundContentFilterDecisionLogEnabled;
  if (inboundContentFilterDecisionLogFile) {
    store.inboundContentFilterDecisionLogFile = inboundContentFilterDecisionLogFile;
  }
  if (inboundContentFilterDecisionLogSalt) {
    store.inboundContentFilterDecisionLogSalt = inboundContentFilterDecisionLogSalt;
  }
  if (bridgeInboundHeaderAllowlist && bridgeInboundHeaderAllowlist.length > 0) {
    store.bridgeInboundHeaderAllowlist = bridgeInboundHeaderAllowlist;
  }
  store.requireExternalSigningKeys = requireExternalSigningKeys;
  store.requireDistinctFederationSigningKey = requireDistinctFederationSigningKey;
  if (publicService && requireExternalSigningKeys) {
    const hasSystemSigningPrivateKey = String(store.systemSigningPrivateKeyPem || "").trim().length > 0;
    const hasFederationSigningPrivateKey = String(store.federationSigningPrivateKeyPem || "").trim().length > 0;
    if (!hasSystemSigningPrivateKey || !hasFederationSigningPrivateKey) {
      throw new Error(
        "Public service requires externally provisioned system and federation signing private keys."
      );
    }
  }
  store.federationRequireProtocolCapabilities = federationRequireProtocolCapabilities;
  store.federationRequireE2eeProfileOverlap = federationRequireE2eeProfileOverlap;
  store.federationRequireTrustModeParity = federationRequireTrustModeParity;
  if (e2eeProfileMigrationAllowlist != null && options.store) {
    const entries = String(e2eeProfileMigrationAllowlist)
      .split(/[,\n;]+/)
      .map((entry) => String(entry || "").trim().toLowerCase())
      .filter(Boolean);
    store.e2eeProfileMigrationAllowlist = new Set(entries);
  }
  store.messageRetentionDays = messageRetentionDays;
  store.blobRetentionDays = blobRetentionDays;

  // Loop protection env var overrides
  const loopMaxHopCount = Math.floor(parsePositiveNumber(
    options.loopMaxHopCount ?? process.env.LOOM_LOOP_MAX_HOP_COUNT,
    store.loopProtection.max_hop_count
  ));
  const loopAgentWindowMax = Math.floor(parsePositiveNumber(
    options.loopAgentWindowMax ?? process.env.LOOM_LOOP_AGENT_WINDOW_MAX,
    store.loopProtection.max_agent_envelopes_per_thread_window
  ));
  const loopAgentWindowMs = Math.floor(parsePositiveNumber(
    options.loopAgentWindowMs ?? process.env.LOOM_LOOP_AGENT_WINDOW_MS,
    store.loopProtection.agent_window_ms
  ));
  store.loopProtection = {
    max_hop_count: Math.max(1, Math.min(loopMaxHopCount, 255)),
    max_agent_envelopes_per_thread_window: Math.max(1, loopAgentWindowMax),
    agent_window_ms: Math.max(1000, loopAgentWindowMs)
  };
  // MCP sandbox env var overrides
  const mcpMaxArgumentBytes = Math.max(1024, Math.floor(parsePositiveNumber(
    options.mcpMaxArgumentBytes ?? process.env.LOOM_MCP_MAX_ARGUMENT_BYTES,
    store.mcpSandboxPolicy.max_argument_bytes
  )));
  const mcpMaxResultBytes = Math.max(1024, Math.floor(parsePositiveNumber(
    options.mcpMaxResultBytes ?? process.env.LOOM_MCP_MAX_RESULT_BYTES,
    store.mcpSandboxPolicy.max_result_bytes
  )));
  const mcpExecutionTimeoutMs = Math.max(100, Math.floor(parsePositiveNumber(
    options.mcpExecutionTimeoutMs ?? process.env.LOOM_MCP_EXECUTION_TIMEOUT_MS,
    store.mcpSandboxPolicy.execution_timeout_ms
  )));
  const mcpRateLimitPerActor = Math.max(1, Math.floor(parsePositiveNumber(
    options.mcpRateLimitPerActor ?? process.env.LOOM_MCP_RATE_LIMIT_PER_ACTOR,
    store.mcpSandboxPolicy.rate_limit_per_actor
  )));
  const mcpRateLimitWindowMs = Math.max(1000, Math.floor(parsePositiveNumber(
    options.mcpRateLimitWindowMs ?? process.env.LOOM_MCP_RATE_LIMIT_WINDOW_MS,
    store.mcpSandboxPolicy.rate_limit_window_ms
  )));
  const mcpAllowWriteTools = parseBoolean(
    options.mcpAllowWriteTools ?? process.env.LOOM_MCP_ALLOW_WRITE_TOOLS,
    true
  );
  const mcpEnforceTimeout = parseBoolean(
    options.mcpEnforceTimeout ?? process.env.LOOM_MCP_ENFORCE_TIMEOUT,
    true
  );
  store.mcpSandboxPolicy = {
    max_argument_bytes: mcpMaxArgumentBytes,
    max_result_bytes: mcpMaxResultBytes,
    execution_timeout_ms: mcpExecutionTimeoutMs,
    rate_limit_per_actor: mcpRateLimitPerActor,
    rate_limit_window_ms: mcpRateLimitWindowMs,
    allow_write_tools: mcpAllowWriteTools,
    enforce_timeout: mcpEnforceTimeout
  };

  // Agent trust env var overrides
  const agentTrustEnabled = parseBoolean(
    options.agentTrustEnabled ?? process.env.LOOM_AGENT_TRUST_ENABLED,
    true
  );
  store.agentTrustEnabled = agentTrustEnabled;
  store.agentTrustPolicy = {
    decay_window_ms: Math.max(60000, Math.floor(parsePositiveNumber(
      options.agentTrustDecayWindowMs ?? process.env.LOOM_AGENT_TRUST_DECAY_WINDOW_MS,
      store.agentTrustPolicy.decay_window_ms
    ))),
    warning_threshold: Math.max(1, Math.floor(parsePositiveNumber(
      options.agentTrustWarningThreshold ?? process.env.LOOM_AGENT_TRUST_WARNING,
      store.agentTrustPolicy.warning_threshold
    ))),
    quarantine_threshold: Math.max(2, Math.floor(parsePositiveNumber(
      options.agentTrustQuarantineThreshold ?? process.env.LOOM_AGENT_TRUST_QUARANTINE,
      store.agentTrustPolicy.quarantine_threshold
    ))),
    block_threshold: Math.max(3, Math.floor(parsePositiveNumber(
      options.agentTrustBlockThreshold ?? process.env.LOOM_AGENT_TRUST_BLOCK,
      store.agentTrustPolicy.block_threshold
    ))),
    max_events_per_agent: Math.max(10, Math.floor(parsePositiveNumber(
      options.agentTrustMaxEventsPerAgent ?? process.env.LOOM_AGENT_TRUST_MAX_EVENTS,
      store.agentTrustPolicy.max_events_per_agent
    ))),
    good_behavior_decay: store.agentTrustPolicy.good_behavior_decay
  };

  // MIME policy env vars
  const mimePolicyMode = options.mimePolicyMode ?? process.env.LOOM_MIME_POLICY_MODE ?? undefined;
  if (mimePolicyMode) {
    const mimeAllowedCategories = parseStringList(
      options.mimeAllowedCategories ?? process.env.LOOM_MIME_ALLOWED_CATEGORIES
    );
    const mimeDeniedTypes = parseStringList(
      options.mimeDeniedTypes ?? process.env.LOOM_MIME_DENIED_TYPES
    );
    const mimeRequireRegistered = parseBoolean(
      options.mimeRequireRegistered ?? process.env.LOOM_MIME_REQUIRE_REGISTERED,
      false
    );
    store.mimePolicy = {
      ...store.mimePolicy,
      mode: mimePolicyMode,
      ...(mimeAllowedCategories.length > 0 ? { allowed_categories: mimeAllowedCategories } : {}),
      ...(mimeDeniedTypes.length > 0 ? { denied_types: mimeDeniedTypes } : {}),
      require_registered: mimeRequireRegistered
    };
  }

  // Compression policy env vars
  const compressionPolicy = {
    ...DEFAULT_COMPRESSION_POLICY,
    enabled: parseBoolean(
      options.compressionEnabled ?? process.env.LOOM_COMPRESSION_ENABLED,
      DEFAULT_COMPRESSION_POLICY.enabled
    ),
    min_size_bytes: Math.max(0, Math.floor(parsePositiveNumber(
      options.compressionMinSize ?? process.env.LOOM_COMPRESSION_MIN_SIZE,
      DEFAULT_COMPRESSION_POLICY.min_size_bytes
    ))),
    preferred_encoding: (options.compressionEncoding ?? process.env.LOOM_COMPRESSION_ENCODING ?? DEFAULT_COMPRESSION_POLICY.preferred_encoding).toLowerCase(),
    level: Math.max(1, Math.min(11, Math.floor(parsePositiveNumber(
      options.compressionLevel ?? process.env.LOOM_COMPRESSION_LEVEL,
      DEFAULT_COMPRESSION_POLICY.level
    ))))
  };
  store.compressionPolicy = compressionPolicy;

  // Key rotation policy env vars
  const DAY_MS = 24 * 60 * 60 * 1000;
  const HOUR_MS = 60 * 60 * 1000;
  const keyRotationMaxAgeDays = parsePositiveNumber(
    options.keyRotationMaxAgeDays ?? process.env.LOOM_KEY_ROTATION_MAX_AGE_DAYS, 90
  );
  const keyRotationGracePeriodDays = parsePositiveNumber(
    options.keyRotationGracePeriodDays ?? process.env.LOOM_KEY_ROTATION_GRACE_PERIOD_DAYS, 7
  );
  const keyRotationOverlapHours = parsePositiveNumber(
    options.keyRotationOverlapHours ?? process.env.LOOM_KEY_ROTATION_OVERLAP_HOURS, 24
  );
  const keyRotationAutoRotate = parseBoolean(
    options.keyRotationAutoRotate ?? process.env.LOOM_KEY_ROTATION_AUTO_ROTATE, false
  );
  store.keyRotationPolicy = {
    max_key_age_ms: keyRotationMaxAgeDays * DAY_MS,
    grace_period_ms: keyRotationGracePeriodDays * DAY_MS,
    overlap_window_ms: keyRotationOverlapHours * HOUR_MS,
    min_key_age_ms: HOUR_MS,
    auto_rotate: keyRotationAutoRotate
  };

  // Search index env vars
  const searchIndexEnabled = parseBoolean(
    options.searchIndexEnabled ?? process.env.LOOM_SEARCH_INDEX_ENABLED, true
  );
  const searchIndexMaxEntries = Math.max(1000, Math.floor(parsePositiveNumber(
    options.searchIndexMaxEntries ?? process.env.LOOM_SEARCH_INDEX_MAX_ENTRIES, 100000
  )));
  store.searchIndexEnabled = searchIndexEnabled;
  if (searchIndexEnabled && !store.searchIndex) {
    store.searchIndex = createSearchIndex({ max_entries: searchIndexMaxEntries });
  }

  const runtimeStatusProvider = typeof options.runtimeStatusProvider === "function" ? options.runtimeStatusProvider : null;
  const emailRelay = options.emailRelay || null;

  const mcpToolRegistry = createMcpToolRegistry(store, { domain, sandboxPolicy: store.mcpSandboxPolicy });
  const mcpSseSessions = new Map();

  const requestHandler = async (req, res) => {
    // Attach compression context for transparent sendJson compression
    res._compressionCtx = {
      acceptEncoding: req.headers["accept-encoding"] || "",
      policy: compressionPolicy
    };

    res.setHeader("x-content-type-options", "nosniff");
    res.setHeader("x-frame-options", "DENY");
    res.setHeader("cache-control", "no-store");
    if (nativeTlsConfig.enabled || requireHttpsFromProxy) {
      res.setHeader("strict-transport-security", "max-age=63072000; includeSubDomains");
    }

    const reqId = getIncomingRequestId(req) || `req_${randomUUID()}`;
    res.setHeader("x-loom-request-id", reqId);
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
          request_id: reqId,
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

    const executeRequest = async () => {
      try {
        path = requestPath(req);
        rateLimiter.enforce(req, path);
        if (requireHttpsFromProxy && !isRequestSecure(req, { requireHttpsFromProxy, trustProxyConfig })) {
          throw new LoomError("CAPABILITY_DENIED", "HTTPS is required for this service", 403, {
            field: "x-forwarded-proto"
          });
        }

        if (methodIs(req, "GET") && path === "/") {
          res.setHeader("content-security-policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
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
        const apiRateLimitPolicy = rateLimiter.getStatus();
        const identityRateLimitPolicy = store.getIdentityRateLimitPolicyStatus();

        let pgCheck = null;
        if (store.persistenceAdapter && typeof store.persistenceAdapter.pool?.query === "function") {
          try {
            await store.persistenceAdapter.pool.query("SELECT 1");
            pgCheck = "ok";
          } catch {
            pgCheck = "error";
          }
        }

        const allChecksOk = pgCheck !== "error";
        sendJson(res, allChecksOk ? 200 : 503, {
          ok: allChecksOk,
          service: "loom-mvn",
          timestamp: new Date().toISOString(),
          uptime_s: metrics.snapshot().uptime_s,
          checks: {
            http: "ok",
            store: "ok",
            postgres: pgCheck
          },
          outbox: {
            federation: federationOutbox,
            email: emailOutbox,
            webhook: webhookOutbox
          },
          api_rate_limit_policy: apiRateLimitPolicy,
          identity_rate_limit_policy: identityRateLimitPolicy,
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
        const apiRateLimitPolicy = rateLimiter.getStatus();
        const identityRateLimitPolicy = store.getIdentityRateLimitPolicyStatus();
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
          api_rate_limit_policy: apiRateLimitPolicy,
          identity_rate_limit_policy: identityRateLimitPolicy,
          federation_inbound_policy: federationInboundPolicy,
          federation_guards: federationGuards,
          idempotency: store.getIdempotencyStatus(),
          email_relay: typeof emailRelay?.getStatus === "function" ? emailRelay.getStatus() : null,
          persistence_schema: persistenceSchema,
          runtime: runtimeStatus
        });
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/admin/content-filter/config") {
        requireAdminToken(req, adminToken);
        sendJson(res, 200, store.getInboundContentFilterConfigStatus());
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/admin/content-filter/config") {
        requireAdminToken(req, adminToken);
        const body = await readJson(req, maxBodyBytes);
        const result = store.updateInboundContentFilterConfig(body, "admin");
        sendJson(res, 200, result);
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

      if (methodIs(req, "GET") && path === "/.well-known/loom-capabilities.json") {
        sendJson(res, 200, store.getProtocolCapabilities(domain));
        return;
      }

      if (methodIs(req, "GET") && path === "/.well-known/loom-keyset.json") {
        sendJson(res, 200, store.getFederationKeysetDocument(domain));
        return;
      }

      if (methodIs(req, "GET") && path === "/.well-known/loom-revocations.json") {
        sendJson(res, 200, store.getFederationRevocationsDocument(domain));
        return;
      }

      if (methodIs(req, "GET") && path === "/.well-known/loom-trust.json") {
        sendJson(res, 200, store.getFederationTrustDnsDescriptor(domain));
        return;
      }

      if (methodIs(req, "GET") && path === "/.well-known/loom-trust.txt") {
        const descriptor = store.getFederationTrustDnsDescriptor(domain);
        sendText(res, 200, `${descriptor.txt_record}\n`, "text/plain; charset=utf-8");
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/identity/challenge") {
        if (!identitySignupEnabled) {
          requireAdminToken(req, adminToken);
        }
        const body = await readJson(req, maxBodyBytes);
        const challenge = store.createIdentityRegistrationChallenge(body, {
          localIdentityDomain,
          allowRemoteDomain: false
        });
        sendJson(res, 200, challenge);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/identity") {
        const adminRequest = hasValidAdminToken(req, adminToken);
        if (!identitySignupEnabled) {
          requireAdminToken(req, adminToken);
        }
        const body = await readJson(req, maxBodyBytes);
        const importedRemote =
          body?.imported_remote === true ||
          body?.remote_import === true ||
          String(body?.registration_mode || "").trim().toLowerCase() === "remote_import";
        if (importedRemote && adminToken && !adminRequest) {
          throw new LoomError("CAPABILITY_DENIED", "Admin token required for remote identity import", 403, {
            field: "x-loom-admin-token"
          });
        }

        const identity = store.registerIdentity(body, {
          localIdentityDomain,
          allowRemoteDomain: importedRemote,
          allowOverwrite: false,
          importedRemote,
          requireProofOfKey: identityRequireProof && !adminRequest && !importedRemote
        });
        sendJson(res, 201, identity);
        return;
      }

      if (methodIs(req, "GET") && path.startsWith("/v1/identity/")) {
        const encodedIdentity = path.slice("/v1/identity/".length);
        const identityUri = decodeURIComponent(encodedIdentity);
        const identity = store.getIdentityDocument(identityUri);
        if (!identity) {
          throw new LoomError("IDENTITY_NOT_FOUND", `Identity not found: ${identityUri}`, 404, {
            identity: identityUri
          });
        }
        sendJson(res, 200, identity);
        return;
      }

      if (methodIs(req, "PATCH") && path.startsWith("/v1/identity/")) {
        const session = requireActorSession(req, store);
        const encodedIdentity = path.slice("/v1/identity/".length);
        const identityUri = decodeURIComponent(encodedIdentity);
        const body = await readJson(req, maxBodyBytes);
        const identity = store.updateIdentity(identityUri, body, session);
        sendJson(res, 200, identity);
        return;
      }

      // ── Agent Card Routes ─────────────────────────────────────────────────
      if (methodIs(req, "GET") && path === "/v1/agents") {
        const cards = store.listAgentCards();
        sendJson(res, 200, { agents: cards, count: cards.length });
        return;
      }

      if (methodIs(req, "GET") && path.startsWith("/v1/agents/")) {
        const encodedUri = path.slice("/v1/agents/".length);
        const agentUri = decodeURIComponent(encodedUri);
        const card = store.getAgentCard(agentUri);
        if (!card) {
          throw new LoomError("IDENTITY_NOT_FOUND", `Agent not found: ${agentUri}`, 404, {
            identity: agentUri
          });
        }
        sendJson(res, 200, card);
        return;
      }

      // ── Agent Trust Admin Routes ───────────────────────────────────────────
      if (methodIs(req, "GET") && path === "/v1/admin/agent-trust") {
        requireAdminToken(req, adminToken);
        const cards = store.listAgentCards();
        const summaries = cards.map((entry) => ({
          identity: entry.identity,
          trust: store.getAgentTrustScore(entry.identity)
        }));
        sendJson(res, 200, { agents: summaries, count: summaries.length });
        return;
      }

      if (methodIs(req, "GET") && path.startsWith("/v1/admin/agent-trust/")) {
        requireAdminToken(req, adminToken);
        const encodedUri = path.slice("/v1/admin/agent-trust/".length);
        const agentUri = decodeURIComponent(encodedUri);
        const trustScore = store.getAgentTrustScore(agentUri);
        sendJson(res, 200, trustScore);
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
          capabilityPresentationToken,
          requirePortableThreadOpCapability
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
          capabilityPresentationToken,
          requirePortableThreadOpCapability
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
        if (demoPublicReads) {
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

        const actorIdentity = requireActorIdentity(req, store);
        const capabilityPresentationToken = getCapabilityPresentationToken(req);
        const view = store.getEnvelopeForIdentity(envelopeId, actorIdentity, {
          capabilityTokenValue: capabilityPresentationToken
        });
        if (!view) {
          throw new LoomError("ENVELOPE_NOT_FOUND", `Envelope not found: ${envelopeId}`, 404, {
            envelope_id: envelopeId
          });
        }

        sendJson(res, 200, {
          ...view.envelope,
          delivery_wrapper: view.delivery_wrapper
        });
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

      if (methodIs(req, "GET") && path === "/v1/protocol/capabilities") {
        sendJson(res, 200, store.getProtocolCapabilities(domain));
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/protocol/extensions") {
        sendJson(res, 200, store.getProtocolExtensions(domain));
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/protocol/compliance") {
        assertRouteEnabled(complianceRoutesEnabled, req, path);
        sendJson(res, 200, store.getComplianceScore());
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/admin/compliance/audit") {
        assertRouteEnabled(complianceRoutesEnabled, req, path);
        requireAdminToken(req, adminToken);
        sendJson(res, 200, store.runComplianceAudit());
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/mime/registry") {
        assertRouteEnabled(complianceRoutesEnabled, req, path);
        sendJson(res, 200, store.getMimeRegistry());
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/admin/nist/summary") {
        assertRouteEnabled(complianceRoutesEnabled, req, path);
        requireAdminToken(req, adminToken);
        sendJson(res, 200, store.getNistComplianceSummary());
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/admin/key-rotation/status") {
        requireAdminToken(req, adminToken);
        sendJson(res, 200, store.assessKeyRotationStatus());
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/admin/key-rotation/rotate") {
        requireAdminToken(req, adminToken);
        const body = await readJson(req, maxBodyBytes);
        const result = store.executeKeyRotation({ force: body?.force === true });
        sendJson(res, 200, result);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/admin/key-rotation/history") {
        requireAdminToken(req, adminToken);
        sendJson(res, 200, { history: store.getKeyRotationHistory() });
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/admin/search-index/status") {
        requireAdminToken(req, adminToken);
        sendJson(res, 200, store.getSearchIndexStatus());
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/federation/trust") {
        requireAdminToken(req, adminToken);
        sendJson(res, 200, store.getFederationTrustStatus(domain));
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/federation/trust/verify-dns") {
        requireAdminToken(req, adminToken);
        const url = requestUrl(req);
        const verification = await store.verifyLocalFederationTrustDnsPublication(
          url.searchParams.get("domain") || domain
        );
        const requireMatch = parseBoolean(url.searchParams.get("require_match"), false);
        if (
          requireMatch &&
          (!verification.match_semantic || (verification.dnssec_required === true && verification.dnssec_validated !== true))
        ) {
          sendJson(res, 409, verification);
          return;
        }
        sendJson(res, 200, verification);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/federation/trust") {
        requireAdminToken(req, adminToken);
        const body = await readJson(req, maxBodyBytes);
        const result = store.updateFederationTrustConfig(body, "admin");
        sendJson(res, 200, result);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/federation/nodes") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const adminRequest = hasValidAdminToken(req, adminToken);
        const requestedInsecureTransport = body?.allow_insecure_http === true || body?.allow_private_network === true;
        if (requestedInsecureTransport && adminToken && !adminRequest) {
          throw new LoomError(
            "CAPABILITY_DENIED",
            "Admin token required for allow_insecure_http or allow_private_network federation node settings",
            403,
            {
              field: "x-loom-admin-token"
            }
          );
        }
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

      if (methodIs(req, "POST") && path === "/v1/federation/nodes/revalidate") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const adminRequest = hasValidAdminToken(req, adminToken);
        const requestedNodeIds = Array.isArray(body?.node_ids)
          ? Array.from(
              new Set(
                body.node_ids
                  .map((entry) => String(entry || "").trim())
                  .filter(Boolean)
              )
            )
          : [];
        const targetNodeIds =
          requestedNodeIds.length > 0
            ? requestedNodeIds
            : store.listFederationNodes().map((node) => node.node_id);
        const selectedNodes = targetNodeIds
          .map((nodeId) => store.knownNodesById.get(nodeId))
          .filter(Boolean);
        const requestedInsecureTransport = selectedNodes.some(
          (node) => node.allow_insecure_http === true || node.allow_private_network === true
        );
        if (requestedInsecureTransport && adminToken && !adminRequest) {
          throw new LoomError(
            "CAPABILITY_DENIED",
            "Admin token required to revalidate insecure federation node transport settings",
            403,
            {
              field: "x-loom-admin-token"
            }
          );
        }
        const result = await store.revalidateFederationNodesTrust(body, actorIdentity);
        sendJson(res, 200, result);
        return;
      }

      if (
        methodIs(req, "POST") &&
        path.startsWith("/v1/federation/nodes/") &&
        path.endsWith("/revalidate") &&
        path !== "/v1/federation/nodes/revalidate"
      ) {
        const actorIdentity = requireActorIdentity(req, store);
        const nodeId = path.slice("/v1/federation/nodes/".length, -"/revalidate".length);
        if (!nodeId || nodeId === "bootstrap") {
          throw new LoomError("ENVELOPE_INVALID", "node_id is required for federation revalidation", 400, {
            field: "node_id"
          });
        }

        const body = await readJson(req, maxBodyBytes);
        const node = store.knownNodesById.get(nodeId);
        const requestedInsecureTransport = node
          ? node.allow_insecure_http === true || node.allow_private_network === true
          : false;
        const adminRequest = hasValidAdminToken(req, adminToken);
        if (requestedInsecureTransport && adminToken && !adminRequest) {
          throw new LoomError(
            "CAPABILITY_DENIED",
            "Admin token required to revalidate insecure federation node transport settings",
            403,
            {
              field: "x-loom-admin-token"
            }
          );
        }

        const result = await store.revalidateFederationNodeTrust(nodeId, actorIdentity, body);
        sendJson(res, 200, result);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/federation/nodes/bootstrap") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const adminRequest = hasValidAdminToken(req, adminToken);
        const requestedInsecureTransport = body?.allow_insecure_http === true || body?.allow_private_network === true;
        if (requestedInsecureTransport && adminToken && !adminRequest) {
          throw new LoomError(
            "CAPABILITY_DENIED",
            "Admin token required for allow_insecure_http or allow_private_network federation bootstrap settings",
            403,
            {
              field: "x-loom-admin-token"
            }
          );
        }
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

          const result = await store.ingestFederationDelivery(wrapper, verifiedNode);
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
        if (demoPublicReads) {
          sendJson(res, 200, { threads: store.listThreads() });
          return;
        }
        const actorIdentity = requireActorIdentity(req, store);
        sendJson(res, 200, { threads: store.listThreadsForIdentity(actorIdentity) });
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
        const filters = {
          q: url.searchParams.get("q") || ""
        };
        if (url.searchParams.get("from")) filters.from = url.searchParams.get("from");
        if (url.searchParams.get("type")) filters.type = url.searchParams.get("type");
        if (url.searchParams.get("intent")) filters.intent = url.searchParams.get("intent");
        if (url.searchParams.get("thread_id")) filters.thread_id = url.searchParams.get("thread_id");
        if (url.searchParams.get("after")) filters.after = url.searchParams.get("after");
        if (url.searchParams.get("before")) filters.before = url.searchParams.get("before");
        if (url.searchParams.get("limit")) filters.limit = Number(url.searchParams.get("limit"));
        // Protocol-level search query validation
        const searchErrors = validateSearchQuery(filters);
        if (searchErrors.length > 0) {
          throw new LoomError("SEARCH_INVALID", searchErrors[0].reason, 400, {
            errors: searchErrors
          });
        }
        const result = store.searchEnvelopes(filters, actorIdentity);
        sendJson(res, 200, result);
        return;
      }

      // ── Events API (Section 17) ────────────────────────────────────────
      if (methodIs(req, "GET") && path === "/v1/events") {
        const actorIdentity = requireActorIdentity(req, store);
        const url = requestUrl(req);
        const cursor = url.searchParams.get("cursor") || null;
        const events = store.getEventsSince(cursor);
        sendJson(res, 200, { events });
        return;
      }

      // ── Export/Import API (Section 26.2) ───────────────────────────────
      if (methodIs(req, "GET") && path === "/v1/export") {
        const actorIdentity = requireActorIdentity(req, store);
        const url = requestUrl(req);
        const threadIds = url.searchParams.get("thread_ids")
          ? url.searchParams.get("thread_ids").split(",").map((s) => s.trim()).filter(Boolean)
          : null;
        const identityFilter = url.searchParams.get("identity") || null;
        const includeBlobs = url.searchParams.get("include_blobs") === "true";
        const exportPkg = store.exportMailbox({ threadIds, identityFilter, includeBlobs });
        sendJson(res, 200, exportPkg);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/import") {
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes * 10); // larger limit for imports
        const result = store.importMailbox(body, actorIdentity);
        sendJson(res, 200, result);
        return;
      }

      // ── Retention enforcement endpoint ─────────────────────────────────
      if (methodIs(req, "POST") && path === "/v1/admin/retention/enforce") {
        requireAdminToken(req, adminToken);
        const result = store.enforceRetentionPolicies();
        sendJson(res, 200, result);
        return;
      }

      // ── Content deletion endpoint (Section 25.2) ──────────────────────
      if (methodIs(req, "DELETE") && path.startsWith("/v1/envelopes/") && path.endsWith("/content")) {
        const actorIdentity = requireActorIdentity(req, store);
        const envelopeId = path.slice("/v1/envelopes/".length, -"/content".length);
        const erased = store.deleteEnvelopeContent(envelopeId, actorIdentity);
        sendJson(res, 200, { ok: true, envelope_id: envelopeId, deleted: true });
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/bridge/email/inbound") {
        assertRouteEnabled(bridgeInboundEnabled, req, path);
        if (bridgeInboundRequireAdminToken) {
          requireAdminToken(req, adminToken);
        }
        const actorIdentity = requireActorIdentity(req, store);
        const body = await readJson(req, maxBodyBytes);
        const idempotency = createIdempotencyContext(req, store, actorIdentity, method, path, body);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }
        const accepted = store.createBridgeInboundEnvelope(body, actorIdentity, {
          requireAuthResults: bridgeInboundRequireAuthResults,
          requireDmarcPass: bridgeInboundRequireDmarcPass,
          rejectOnAuthFailure: bridgeInboundRejectOnAuthFailure,
          quarantineOnAuthFailure: bridgeInboundQuarantineOnAuthFailure,
          allowPayloadAuthResults: bridgeInboundAllowPayloadAuthResults,
          headerAllowlist: bridgeInboundHeaderAllowlist
        });
        storeIdempotentResult(store, idempotency, 201, accepted);
        sendJson(res, 201, accepted);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/bridge/email/outbound") {
        assertRouteEnabled(bridgeOutboundEnabled, req, path);
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

      if (methodIs(req, "POST") && path.startsWith("/v1/email/outbox/") && path.endsWith("/dsn")) {
        const actorIdentity = requireActorIdentity(req, store);
        const outboxId = path.slice("/v1/email/outbox/".length, -"/dsn".length);
        const body = await readJson(req, maxBodyBytes);
        const idempotency = createIdempotencyContext(req, store, actorIdentity, method, path, body);
        if (maybeSendIdempotentReplay(res, idempotency)) {
          return;
        }
        const updated = store.applyEmailOutboxDsnReport(outboxId, body, actorIdentity);
        storeIdempotentResult(store, idempotency, 200, updated);
        sendJson(res, 200, updated);
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/gateway/imap/folders") {
        assertRouteEnabled(gatewayImapEnabled, req, path);
        const actorIdentity = requireActorIdentity(req, store);
        const folders = store.listGatewayImapFolders(actorIdentity);
        sendJson(res, 200, { folders });
        return;
      }

      if (methodIs(req, "GET") && path.startsWith("/v1/gateway/imap/folders/") && path.endsWith("/messages")) {
        assertRouteEnabled(gatewayImapEnabled, req, path);
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
        if (demoPublicReads) {
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

        const actorIdentity = requireActorIdentity(req, store);
        const capabilityPresentationToken = getCapabilityPresentationToken(req);
        const views = store.getThreadEnvelopesForIdentity(threadId, actorIdentity, {
          capabilityTokenValue: capabilityPresentationToken
        });
        if (!views) {
          throw new LoomError("THREAD_NOT_FOUND", `Thread not found: ${threadId}`, 404, {
            thread_id: threadId
          });
        }

        sendJson(res, 200, {
          thread_id: threadId,
          envelopes: views.map((view) => ({
            ...view.envelope,
            delivery_wrapper: view.delivery_wrapper
          }))
        });
        return;
      }

      if (methodIs(req, "GET") && path.startsWith("/v1/threads/")) {
        const threadId = path.slice("/v1/threads/".length);
        if (demoPublicReads) {
          const thread = store.getThread(threadId);
          if (!thread) {
            throw new LoomError("THREAD_NOT_FOUND", `Thread not found: ${threadId}`, 404, {
              thread_id: threadId
            });
          }
          sendJson(res, 200, thread);
          return;
        }

        const actorIdentity = requireActorIdentity(req, store);
        const capabilityPresentationToken = getCapabilityPresentationToken(req);
        const thread = store.getThreadForIdentity(threadId, actorIdentity, {
          capabilityTokenValue: capabilityPresentationToken
        });
        if (!thread) {
          throw new LoomError("THREAD_NOT_FOUND", `Thread not found: ${threadId}`, 404, {
            thread_id: threadId
          });
        }
        sendJson(res, 200, thread);
        return;
      }

      // ─── MCP Routes ─────────────────────────────────────────────────
      if (methodIs(req, "GET") && path === "/v1/mcp/tools") {
        assertRouteEnabled(mcpRuntimeRoutesEnabled, req, path);
        const toolList = mcpToolRegistry.listTools();
        sendJson(res, 200, { tools: toolList });
        return;
      }

      if (methodIs(req, "GET") && path === "/v1/mcp/sse") {
        assertRouteEnabled(mcpRuntimeRoutesEnabled, req, path);
        const actorIdentity = requireActorIdentity(req, store);
        const session = createMcpSseSession({
          registry: mcpToolRegistry,
          sessionContext: {
            actorIdentity,
            capabilityPresentationToken: getCapabilityPresentationToken(req),
            sessionPermissions: { allow_write_tools: store.mcpSandboxPolicy.allow_write_tools }
          }
        });
        mcpSseSessions.set(session.sessionId, session);
        req.on("close", () => {
          mcpSseSessions.delete(session.sessionId);
        });
        session.handleSse(req, res);
        return;
      }

      if (methodIs(req, "POST") && path === "/v1/mcp/message") {
        assertRouteEnabled(mcpRuntimeRoutesEnabled, req, path);
        const actorIdentity = requireActorIdentity(req, store);
        const url = requestUrl(req);
        const sessionId = url.searchParams.get("session_id");
        const session = sessionId ? mcpSseSessions.get(sessionId) : null;
        const body = await readJson(req, maxBodyBytes);

        if (session) {
          const response = session.handleMessage(body);
          sendJson(res, 202, { status: "accepted" });
        } else {
          const response = handleMcpRequest(body, mcpToolRegistry, {
            actorIdentity,
            capabilityPresentationToken: getCapabilityPresentationToken(req),
            sessionPermissions: { allow_write_tools: store.mcpSandboxPolicy.allow_write_tools }
          });
          sendJson(res, 200, response || { jsonrpc: "2.0", id: null, result: {} });
        }
        return;
      }

        throw new LoomError("ENVELOPE_NOT_FOUND", "Route not found", 404, {
          method: req.method,
          path
        });
      } catch (error) {
        const { status, body } = toErrorResponse(error, reqId);
        errorCode = body.error.code;

        // Add rate limit headers on 429 responses
        if (status === 429 && error?.details) {
          const rlHeaders = buildRateLimitHeaders({
            limit: error.details.limit || 0,
            remaining: 0,
            reset: new Date(Date.now() + (error.details.retry_after_ms || 60000)).toISOString()
          });
          for (const [key, value] of Object.entries(rlHeaders)) {
            res.setHeader(key, value);
          }
        }

        sendJson(res, status, body);
      }
    };

    if (typeof store.runWithTraceContext === "function") {
      await store.runWithTraceContext(
        {
          trace_id: reqId,
          request_id: reqId,
          trace_source: "api",
          method,
          route: req.url || ""
        },
        executeRequest
      );
      return;
    }
    await executeRequest();
  };

  const server = nativeTlsConfig.enabled
    ? createSecureServer(
        {
          allowHTTP1: nativeTlsConfig.allowHttp1,
          minVersion: nativeTlsConfig.minVersion,
          cert: nativeTlsConfig.certPem,
          key: nativeTlsConfig.keyPem
        },
        requestHandler
      )
    : createServer(requestHandler);

  server.headersTimeout = 30_000;
  server.requestTimeout = 120_000;
  server.keepAliveTimeout = 65_000;

  return { server, store };
}
