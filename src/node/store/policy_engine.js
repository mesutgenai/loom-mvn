import { LoomError } from "../../protocol/errors.js";
import { isNodeAuthorizedForIdentity, parseLoomIdentityAuthority } from "../../protocol/trust.js";

function nowMs() {
  return Date.now();
}

export function isIdentitySensitiveRoutePolicy(method, path) {
  const normalizedMethod = String(method || "GET").toUpperCase();
  if (normalizedMethod !== "GET") {
    return true;
  }

  const normalizedPath = String(path || "").trim();
  return normalizedPath === "/v1/audit" || normalizedPath === "/metrics";
}

export function enforceIdentityRateLimitPolicy({ identity, method = "GET", path = "/" } = {}) {
  const normalizedIdentity = this.normalizeIdentityReference(identity);
  if (!normalizedIdentity) {
    return;
  }

  const windowMs = this.identityRateWindowMs;
  const sensitive = this.isIdentitySensitiveRoute(method, path);
  const max = sensitive ? this.identityRateSensitiveMax : this.identityRateDefaultMax;
  if (!windowMs || !max) {
    return;
  }

  const bucket = sensitive ? "sensitive" : "default";
  const key = `${bucket}:${normalizedIdentity}`;
  const now = nowMs();
  const current = this.identityRateByBucket.get(key);
  if (!current || now - current.window_started_at >= windowMs) {
    this.identityRateByBucket.set(key, {
      count: 1,
      window_started_at: now
    });
    return;
  }

  if (current.count >= max) {
    const retryAfterMs = Math.max(1, current.window_started_at + windowMs - now);
    throw new LoomError("RATE_LIMIT_EXCEEDED", "Identity rate limit exceeded", 429, {
      limit: max,
      window_ms: windowMs,
      retry_after_ms: retryAfterMs,
      scope: `identity:${bucket}`,
      identity: normalizedIdentity
    });
  }

  current.count += 1;
}

export function assertFederatedEnvelopeIdentityAuthorityPolicy(envelope, verifiedNode) {
  const fromIdentity = this.normalizeIdentityReference(envelope?.from?.identity);
  const identityDomain = parseLoomIdentityAuthority(fromIdentity);
  if (!fromIdentity || !identityDomain) {
    throw new LoomError("SIGNATURE_INVALID", "Federated envelope sender identity must include a valid domain", 401, {
      field: "from.identity"
    });
  }

  const authorityNodeId = String(verifiedNode?.node_id || "").trim().toLowerCase();
  const trustDecision = isNodeAuthorizedForIdentity({
    identityUri: fromIdentity,
    senderNodeId: authorityNodeId,
    trustAnchorBindings: this.federationTrustAnchorBindings
  });

  if (!trustDecision.valid) {
    throw new LoomError("SIGNATURE_INVALID", "Federated envelope sender identity is not authorized for sender node", 401, {
      field: "from.identity",
      identity_domain: trustDecision.identityAuthority || identityDomain,
      sender_node: verifiedNode?.node_id || null,
      trusted_sender_nodes:
        trustDecision.trustedNodeAuthorities?.length > 0 ? trustDecision.trustedNodeAuthorities : null
    });
  }

  return {
    fromIdentity,
    identityDomain: trustDecision.identityAuthority || identityDomain
  };
}
