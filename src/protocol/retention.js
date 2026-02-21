// ─── Retention Policy Engine — Section 25.4 ─────────────────────────────────
//
// Node-level configurable retention policies with label-based and
// intent-based matching. Supports legal hold blocking (Section 25.3).

export const DEFAULT_RETENTION_POLICIES = Object.freeze([
  { label: "sys.inbox", retention_days: 2555 },     // ~7 years
  { label: "sys.trash", retention_days: 30 },
  { label: "sys.spam", retention_days: 30 },
  { label: "sys.quarantine", retention_days: 90 },
  { intent: "notification.system@v1", retention_days: 90 },
  { intent: "notification.autoreply@v1", retention_days: 90 },
  { label: "compliance", retention_days: -1 }         // -1 = indefinite
]);

const LEGAL_HOLD_LABEL = "sys.legal_hold";

export function validateRetentionPolicy(policy) {
  const errors = [];
  if (!policy || typeof policy !== "object") {
    errors.push({ field: "policy", reason: "must be an object" });
    return errors;
  }

  const hasLabel = typeof policy.label === "string" && policy.label.trim().length > 0;
  const hasIntent = typeof policy.intent === "string" && policy.intent.trim().length > 0;

  if (!hasLabel && !hasIntent) {
    errors.push({ field: "policy", reason: "must specify label or intent" });
  }

  if (typeof policy.retention_days !== "number" || (!Number.isInteger(policy.retention_days) && policy.retention_days !== -1)) {
    errors.push({ field: "retention_days", reason: "must be an integer (-1 for indefinite)" });
  }

  return errors;
}

export function normalizeRetentionPolicies(policies) {
  if (!Array.isArray(policies)) return [];
  return policies
    .filter((p) => p && typeof p === "object")
    .map((p) => ({
      label: typeof p.label === "string" ? p.label.trim() : null,
      intent: typeof p.intent === "string" ? p.intent.trim() : null,
      retention_days: Number.isInteger(p.retention_days) ? p.retention_days : 2555
    }));
}

export function resolveRetentionDays(policies, { labels = [], intent = null }) {
  // Check for indefinite retention first (compliance labels)
  for (const policy of policies) {
    if (policy.retention_days === -1) {
      if (policy.label && labels.includes(policy.label)) return -1;
      if (policy.intent && policy.intent === intent) return -1;
    }
  }

  // Find the longest matching retention
  let maxDays = null;
  for (const policy of policies) {
    const matches =
      (policy.label && labels.includes(policy.label)) ||
      (policy.intent && policy.intent === intent);

    if (matches) {
      if (maxDays === null || policy.retention_days > maxDays) {
        maxDays = policy.retention_days;
      }
    }
  }

  return maxDays; // null means no matching policy
}

export function isExpiredByRetention(retentionDays, createdAt, now = Date.now()) {
  if (retentionDays === -1) return false; // indefinite
  if (retentionDays == null) return false; // no policy — don't expire
  const created = Date.parse(createdAt);
  if (!Number.isFinite(created)) return false;
  const expiresAt = created + retentionDays * 86400000;
  return now >= expiresAt;
}

export function isLegalHoldActive(threadOrEnvelopeLabels) {
  if (!Array.isArray(threadOrEnvelopeLabels)) return false;
  return threadOrEnvelopeLabels.includes(LEGAL_HOLD_LABEL);
}

export function collectExpiredEnvelopes(envelopes, threads, policies, now = Date.now()) {
  const expired = [];
  for (const envelope of envelopes) {
    const thread = threads.get(envelope.thread_id);
    const labels = thread?.labels || [];

    // Legal hold blocks all deletion
    if (isLegalHoldActive(labels)) continue;

    const intent = envelope.content?.structured?.intent || null;
    const retentionDays = resolveRetentionDays(policies, { labels, intent });
    if (retentionDays !== null && isExpiredByRetention(retentionDays, envelope.created_at, now)) {
      expired.push(envelope.id);
    }
  }
  return expired;
}
