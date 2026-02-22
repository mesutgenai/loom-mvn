// ─── Key Rotation Policy ── Section 25.5 ────────────────────────────────────
//
// Formalized rotation scheduling for federation signing keys: max age, grace
// period, overlap window, rotation triggers, and audit trail helpers.
// Pure-function module — no crypto, no I/O.

import { getSigningKeyLifecycleState } from "./key_lifecycle.js";

// ─── Constants ──────────────────────────────────────────────────────────────

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

export const DEFAULT_ROTATION_POLICY = Object.freeze({
  max_key_age_ms: 90 * DAY_MS,
  grace_period_ms: 7 * DAY_MS,
  overlap_window_ms: 24 * HOUR_MS,
  min_key_age_ms: 24 * HOUR_MS,
  auto_rotate: false
});

export const ROTATION_STATES = Object.freeze({
  CURRENT: "current",
  GRACE: "grace",
  EXPIRED: "expired",
  OVERLAP: "overlap",
  RETIRED: "retired",
  REVOKED: "revoked",
  PENDING: "pending"
});

export const KEY_ROTATION_AUDIT_EVENTS = Object.freeze({
  ROTATION_ASSESSED: "key_rotation.assessed",
  ROTATION_INITIATED: "key_rotation.initiated",
  ROTATION_COMPLETED: "key_rotation.completed",
  KEY_RETIRED: "key_rotation.key_retired",
  KEY_ARCHIVED: "key_rotation.key_archived",
  POLICY_UPDATED: "key_rotation.policy_updated"
});

// ─── Validation ─────────────────────────────────────────────────────────────

export function validateRotationPolicy(policy) {
  const errors = [];
  if (!policy || typeof policy !== "object") {
    return [{ field: "rotation_policy", reason: "must be an object" }];
  }

  if (policy.max_key_age_ms !== undefined && policy.max_key_age_ms !== null) {
    if (typeof policy.max_key_age_ms !== "number" || !Number.isFinite(policy.max_key_age_ms) || policy.max_key_age_ms <= 0) {
      errors.push({ field: "rotation_policy.max_key_age_ms", reason: "must be a positive number" });
    }
  }

  if (policy.grace_period_ms !== undefined && policy.grace_period_ms !== null) {
    if (typeof policy.grace_period_ms !== "number" || !Number.isFinite(policy.grace_period_ms) || policy.grace_period_ms < 0) {
      errors.push({ field: "rotation_policy.grace_period_ms", reason: "must be a non-negative number" });
    }
  }

  if (policy.overlap_window_ms !== undefined && policy.overlap_window_ms !== null) {
    if (typeof policy.overlap_window_ms !== "number" || !Number.isFinite(policy.overlap_window_ms) || policy.overlap_window_ms < 0) {
      errors.push({ field: "rotation_policy.overlap_window_ms", reason: "must be a non-negative number" });
    }
  }

  if (policy.min_key_age_ms !== undefined && policy.min_key_age_ms !== null) {
    if (typeof policy.min_key_age_ms !== "number" || !Number.isFinite(policy.min_key_age_ms) || policy.min_key_age_ms < 0) {
      errors.push({ field: "rotation_policy.min_key_age_ms", reason: "must be a non-negative number" });
    }
  }

  if (policy.auto_rotate !== undefined && policy.auto_rotate !== null) {
    if (typeof policy.auto_rotate !== "boolean") {
      errors.push({ field: "rotation_policy.auto_rotate", reason: "must be a boolean" });
    }
  }

  // Cross-field validation
  const maxAge = typeof policy.max_key_age_ms === "number" ? policy.max_key_age_ms : DEFAULT_ROTATION_POLICY.max_key_age_ms;
  const grace = typeof policy.grace_period_ms === "number" ? policy.grace_period_ms : DEFAULT_ROTATION_POLICY.grace_period_ms;
  const overlap = typeof policy.overlap_window_ms === "number" ? policy.overlap_window_ms : DEFAULT_ROTATION_POLICY.overlap_window_ms;

  if (grace >= maxAge && errors.length === 0) {
    errors.push({ field: "rotation_policy.grace_period_ms", reason: "must be less than max_key_age_ms" });
  }

  if (overlap >= grace && grace > 0 && errors.length === 0) {
    errors.push({ field: "rotation_policy.overlap_window_ms", reason: "must be less than grace_period_ms" });
  }

  return errors;
}

export function normalizeRotationPolicy(policy) {
  if (!policy || typeof policy !== "object") {
    return DEFAULT_ROTATION_POLICY;
  }
  return Object.freeze({
    ...DEFAULT_ROTATION_POLICY,
    ...policy
  });
}

// ─── Key Rotation State ─────────────────────────────────────────────────────

function parseKeyTime(key) {
  const raw = key?.not_before || key?.valid_from || key?.created_at;
  if (!raw) return null;
  const parsed = Date.parse(String(raw));
  return Number.isFinite(parsed) ? parsed : null;
}

export function getKeyRotationState(key, policy, now = Date.now()) {
  if (!key || typeof key !== "object") return ROTATION_STATES.EXPIRED;

  const effectivePolicy = { ...DEFAULT_ROTATION_POLICY, ...(policy || {}) };
  const nowMs = Number.isFinite(Number(now)) ? Number(now) : Date.now();

  // Check base lifecycle state first
  const baseState = getSigningKeyLifecycleState(key, nowMs);

  if (baseState === "revoked") return ROTATION_STATES.REVOKED;
  if (baseState === "pending") return ROTATION_STATES.PENDING;

  // Check for retired status
  if (key.status === "retired") return ROTATION_STATES.RETIRED;

  // Check overlap window
  const overlapUntil = key._overlap_until ? Date.parse(String(key._overlap_until)) : null;
  if (overlapUntil != null && Number.isFinite(overlapUntil) && nowMs < overlapUntil) {
    return ROTATION_STATES.OVERLAP;
  }

  // Inactive states from key_lifecycle (covers "retired", "disabled", "inactive" status)
  if (baseState === "inactive") return ROTATION_STATES.RETIRED;

  // Check age-based states
  const keyStartMs = parseKeyTime(key);
  if (keyStartMs != null) {
    const ageMs = nowMs - keyStartMs;

    if (baseState === "expired" || ageMs > effectivePolicy.max_key_age_ms) {
      return ROTATION_STATES.EXPIRED;
    }

    if (ageMs > effectivePolicy.max_key_age_ms - effectivePolicy.grace_period_ms) {
      return ROTATION_STATES.GRACE;
    }
  } else if (baseState === "expired") {
    return ROTATION_STATES.EXPIRED;
  }

  return ROTATION_STATES.CURRENT;
}

// ─── Rotation Needs Assessment ──────────────────────────────────────────────

export function assessKeyRotationNeeds(signingKeys, policy, now = Date.now()) {
  const effectivePolicy = { ...DEFAULT_ROTATION_POLICY, ...(policy || {}) };
  const nowMs = Number.isFinite(Number(now)) ? Number(now) : Date.now();
  const keys = Array.isArray(signingKeys) ? signingKeys : [];

  const keyStates = keys.map((key) => {
    const state = getKeyRotationState(key, effectivePolicy, nowMs);
    const keyStartMs = parseKeyTime(key);
    const ageMs = keyStartMs != null ? nowMs - keyStartMs : null;
    const expiresInMs = keyStartMs != null ? effectivePolicy.max_key_age_ms - (nowMs - keyStartMs) : null;

    let recommendation = null;
    if (state === ROTATION_STATES.GRACE) recommendation = "rotation recommended";
    else if (state === ROTATION_STATES.EXPIRED) recommendation = "rotation required";
    else if (state === ROTATION_STATES.OVERLAP) recommendation = "awaiting overlap completion";
    else if (state === ROTATION_STATES.RETIRED) recommendation = "eligible for archival";
    else if (state === ROTATION_STATES.REVOKED) recommendation = "revoked, no action needed";

    return {
      key_id: key.key_id || null,
      state,
      age_ms: ageMs,
      expires_in_ms: expiresInMs,
      recommendation
    };
  });

  const activeCount = keyStates.filter((k) =>
    k.state === ROTATION_STATES.CURRENT || k.state === ROTATION_STATES.GRACE
  ).length;
  const graceKeys = keyStates.filter((k) => k.state === ROTATION_STATES.GRACE).map((k) => k.key_id);
  const expiredKeys = keyStates.filter((k) => k.state === ROTATION_STATES.EXPIRED).map((k) => k.key_id);
  const pendingKeys = keyStates.filter((k) => k.state === ROTATION_STATES.PENDING);

  // Rotation is needed if any key is in GRACE or EXPIRED and there's no PENDING replacement
  const needsRotation = (graceKeys.length > 0 || expiredKeys.length > 0 || keys.length === 0) && pendingKeys.length === 0;

  let summary;
  if (keys.length === 0) {
    summary = "No signing keys configured; key generation required.";
  } else if (!needsRotation) {
    summary = `${activeCount} active key(s), no rotation needed.`;
  } else if (expiredKeys.length > 0) {
    summary = `${expiredKeys.length} expired key(s) require immediate rotation.`;
  } else {
    summary = `${graceKeys.length} key(s) in grace period; rotation recommended.`;
  }

  return {
    needs_rotation: needsRotation,
    keys: keyStates,
    active_key_count: activeCount,
    grace_keys: graceKeys,
    expired_keys: expiredKeys,
    summary
  };
}

// ─── Rotation Plan Generation ───────────────────────────────────────────────

export function generateRotationPlan(signingKeys, policy, now = Date.now()) {
  const effectivePolicy = { ...DEFAULT_ROTATION_POLICY, ...(policy || {}) };
  const nowMs = Number.isFinite(Number(now)) ? Number(now) : Date.now();
  const keys = Array.isArray(signingKeys) ? signingKeys : [];
  const actions = [];

  const keyStates = keys.map((key) => ({
    key,
    state: getKeyRotationState(key, effectivePolicy, nowMs),
    age_ms: parseKeyTime(key) != null ? nowMs - parseKeyTime(key) : null
  }));

  const hasCurrentOrPending = keyStates.some(
    (k) => k.state === ROTATION_STATES.CURRENT || k.state === ROTATION_STATES.PENDING
  );

  // Check if any key needs rotation
  const graceOrExpired = keyStates.filter(
    (k) => k.state === ROTATION_STATES.GRACE || k.state === ROTATION_STATES.EXPIRED
  );

  // If no keys at all, generate one
  if (keys.length === 0) {
    actions.push({
      type: "generate_new_key",
      key_id: null,
      not_before: new Date(nowMs).toISOString(),
      not_after: new Date(nowMs + effectivePolicy.max_key_age_ms).toISOString(),
      reason: "no signing keys configured"
    });
  } else if (graceOrExpired.length > 0 && !hasCurrentOrPending) {
    // Need a new key
    actions.push({
      type: "generate_new_key",
      key_id: null,
      not_before: new Date(nowMs).toISOString(),
      not_after: new Date(nowMs + effectivePolicy.max_key_age_ms).toISOString(),
      reason: `replacing ${graceOrExpired.length} key(s) in ${graceOrExpired[0].state} state`
    });

    // Set overlap for grace keys
    for (const k of graceOrExpired) {
      if (k.state === ROTATION_STATES.GRACE) {
        actions.push({
          type: "begin_overlap",
          key_id: k.key.key_id,
          not_before: null,
          not_after: new Date(nowMs + effectivePolicy.overlap_window_ms).toISOString(),
          reason: "entering overlap window before retirement"
        });
      } else {
        // Expired keys get retired immediately
        actions.push({
          type: "retire_key",
          key_id: k.key.key_id,
          not_before: null,
          not_after: null,
          reason: "key has expired"
        });
      }
    }
  }

  // Check for keys past overlap window that should be retired
  for (const k of keyStates) {
    if (k.state === ROTATION_STATES.OVERLAP) {
      const overlapUntil = k.key._overlap_until ? Date.parse(String(k.key._overlap_until)) : null;
      if (overlapUntil != null && nowMs >= overlapUntil) {
        actions.push({
          type: "retire_key",
          key_id: k.key.key_id,
          not_before: null,
          not_after: null,
          reason: "overlap window elapsed"
        });
      }
    }
  }

  // Check for retired keys eligible for archival
  for (const k of keyStates) {
    if (k.state === ROTATION_STATES.RETIRED) {
      actions.push({
        type: "archive_key",
        key_id: k.key.key_id,
        not_before: null,
        not_after: null,
        reason: "retired key eligible for archival"
      });
    }
  }

  const summary = actions.length === 0
    ? "No rotation actions needed."
    : `${actions.length} action(s) planned: ${actions.map((a) => a.type).join(", ")}.`;

  return { actions, summary };
}

// ─── Audit Helpers ──────────────────────────────────────────────────────────

export function buildRotationAuditEntry(eventType, details) {
  return {
    action: eventType,
    details: {
      ...(details || {}),
      timestamp: new Date().toISOString()
    }
  };
}
