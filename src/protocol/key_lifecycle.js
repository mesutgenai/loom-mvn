function parseLifecycleTime(value) {
  if (!value) {
    return null;
  }
  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) ? parsed : null;
}

export function normalizeSigningKeyStatus(value) {
  const normalized = String(value || "active")
    .trim()
    .toLowerCase();
  if (!normalized) {
    return "active";
  }
  return normalized;
}

export function getSigningKeyLifecycleState(key, at = Date.now()) {
  const nowMs = Number.isFinite(Number(at)) ? Number(at) : Date.now();
  const status = normalizeSigningKeyStatus(key?.status);

  const revokedAt = parseLifecycleTime(key?.revoked_at);
  if (revokedAt != null && revokedAt <= nowMs) {
    return "revoked";
  }

  if (status === "revoked" || status === "retired" || status === "disabled" || status === "inactive") {
    return "inactive";
  }

  const notBefore = parseLifecycleTime(key?.not_before || key?.valid_from);
  if (notBefore != null && nowMs < notBefore) {
    return "pending";
  }

  const notAfter = parseLifecycleTime(key?.not_after || key?.valid_until || key?.expires_at);
  if (notAfter != null && nowMs > notAfter) {
    return "expired";
  }

  return "active";
}

export function isSigningKeyUsableAt(key, at = Date.now()) {
  if (!key || typeof key !== "object") {
    return false;
  }

  const state = getSigningKeyLifecycleState(key, at);
  return state === "active";
}
