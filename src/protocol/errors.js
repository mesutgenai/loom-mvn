export class LoomError extends Error {
  constructor(code, message, status = 400, details = {}) {
    super(message);
    this.name = "LoomError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export const STATUS_BY_CODE = {
  ENVELOPE_INVALID: 400,
  SIGNATURE_INVALID: 401,
  DELEGATION_INVALID: 403,
  CAPABILITY_DENIED: 403,
  // Keep HTTP 404 to preserve fail-closed route-surface behavior while exposing
  // explicit machine semantics through the protocol error code.
  EXTENSION_DISABLED: 404,
  AUDIENCE_DENIED: 403,
  ENCRYPTION_REQUIRED: 403,
  LEGAL_HOLD_ACTIVE: 403,
  IDENTITY_NOT_FOUND: 404,
  THREAD_NOT_FOUND: 404,
  ENVELOPE_NOT_FOUND: 404,
  ENVELOPE_DUPLICATE: 409,
  THREAD_LOCKED: 409,
  STATE_TRANSITION_INVALID: 409,
  IDEMPOTENCY_CONFLICT: 409,
  PAYLOAD_TOO_LARGE: 413,
  MIME_TYPE_DENIED: 415,
  RATE_LIMIT_EXCEEDED: 429,
  NODE_UNREACHABLE: 502,
  DELIVERY_TIMEOUT: 504,
  AGENT_BLOCKED: 403,
  AGENT_QUARANTINED: 403,
  BRIDGE_DELIVERY_FAILED: 502,
  INTERNAL_ERROR: 500
};

export function toErrorResponse(error, requestId) {
  const code = error?.code || "INTERNAL_ERROR";
  const status = error?.status || STATUS_BY_CODE[code] || 500;
  const message = error?.message || "Unexpected internal error";
  const details = error?.details || {};

  return {
    status,
    body: {
      error: {
        code,
        message,
        details,
        request_id: requestId,
        timestamp: new Date().toISOString()
      }
    }
  };
}
