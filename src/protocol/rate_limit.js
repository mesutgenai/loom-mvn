// ─── Rate Limiting — Section 14.3 ───────────────────────────────────────────
//
// Sliding window rate limiters with X-LOOM-RateLimit-* header support.

export const DEFAULT_RATE_LIMITS = Object.freeze({
  envelopes_per_minute: 100,
  auth_per_minute: 10,
  reads_per_minute: 300,
  ws_messages_per_minute: 60,
  federation_per_minute: 1000
});

export function createRateLimiter(maxRequests, windowMs = 60000) {
  return {
    max_requests: maxRequests,
    window_ms: windowMs,
    timestamps: []
  };
}

export function checkRateLimit(limiter, now = Date.now()) {
  // Prune expired timestamps
  const windowStart = now - limiter.window_ms;
  limiter.timestamps = limiter.timestamps.filter((ts) => ts > windowStart);

  const remaining = limiter.max_requests - limiter.timestamps.length;
  const resetAt = limiter.timestamps.length > 0
    ? new Date(limiter.timestamps[0] + limiter.window_ms).toISOString()
    : new Date(now + limiter.window_ms).toISOString();

  if (remaining <= 0) {
    return {
      allowed: false,
      limit: limiter.max_requests,
      remaining: 0,
      reset: resetAt
    };
  }

  return {
    allowed: true,
    limit: limiter.max_requests,
    remaining,
    reset: resetAt
  };
}

export function recordRequest(limiter, now = Date.now()) {
  limiter.timestamps.push(now);
}

export function buildRateLimitHeaders(result) {
  return {
    "X-LOOM-RateLimit-Limit": String(result.limit),
    "X-LOOM-RateLimit-Remaining": String(result.remaining),
    "X-LOOM-RateLimit-Reset": result.reset
  };
}

// ─── Per-identity rate limiter registry ─────────────────────────────────────

export function createRateLimiterRegistry(limits = DEFAULT_RATE_LIMITS) {
  return {
    limits,
    limiters: new Map()
  };
}

export function getRateLimiter(registry, identity, endpoint) {
  const key = `${identity}:${endpoint}`;
  if (!registry.limiters.has(key)) {
    const max = resolveEndpointLimit(registry.limits, endpoint);
    registry.limiters.set(key, createRateLimiter(max));
  }
  return registry.limiters.get(key);
}

function resolveEndpointLimit(limits, endpoint) {
  if (endpoint.startsWith("/v1/envelopes")) return limits.envelopes_per_minute || 100;
  if (endpoint.startsWith("/v1/auth")) return limits.auth_per_minute || 10;
  if (endpoint.startsWith("/v1/threads")) return limits.reads_per_minute || 300;
  if (endpoint === "websocket") return limits.ws_messages_per_minute || 60;
  if (endpoint.startsWith("/v1/federation")) return limits.federation_per_minute || 1000;
  return 100;
}
