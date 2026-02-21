// ─── Autoresponder / Out-of-Office — Section 20.5 ───────────────────────────
//
// Autoresponder rule evaluation with loop prevention and frequency limiting.

import { shouldSuppressAutoReply } from "./receipts.js";
import { generateUlid } from "./ulid.js";

export function validateAutoresponderRule(rule) {
  const errors = [];
  if (!rule || typeof rule !== "object") {
    errors.push({ field: "rule", reason: "must be an object" });
    return errors;
  }

  if (typeof rule.message !== "string" || rule.message.trim().length === 0) {
    errors.push({ field: "message", reason: "required non-empty string" });
  }

  if (rule.schedule_start !== undefined) {
    if (typeof rule.schedule_start !== "string" || !Number.isFinite(Date.parse(rule.schedule_start))) {
      errors.push({ field: "schedule_start", reason: "must be a valid ISO 8601 timestamp" });
    }
  }

  if (rule.schedule_end !== undefined) {
    if (typeof rule.schedule_end !== "string" || !Number.isFinite(Date.parse(rule.schedule_end))) {
      errors.push({ field: "schedule_end", reason: "must be a valid ISO 8601 timestamp" });
    }
  }

  if (rule.schedule_start && rule.schedule_end) {
    const start = Date.parse(rule.schedule_start);
    const end = Date.parse(rule.schedule_end);
    if (Number.isFinite(start) && Number.isFinite(end) && start >= end) {
      errors.push({ field: "schedule_end", reason: "must be after schedule_start" });
    }
  }

  const validFrequencies = ["once_per_sender", "once_per_day", "unlimited"];
  if (rule.frequency_limit !== undefined && !validFrequencies.includes(rule.frequency_limit)) {
    errors.push({ field: "frequency_limit", reason: `must be one of: ${validFrequencies.join(", ")}` });
  }

  return errors;
}

export function isAutoresponderActive(rule, now = Date.now()) {
  if (!rule || typeof rule !== "object") return false;

  if (rule.schedule_start) {
    const start = Date.parse(rule.schedule_start);
    if (Number.isFinite(start) && now < start) return false;
  }

  if (rule.schedule_end) {
    const end = Date.parse(rule.schedule_end);
    if (Number.isFinite(end) && now >= end) return false;
  }

  return true;
}

export function shouldAutoRespond(envelope, rule, sentHistory = new Map()) {
  // Never auto-reply to auto-replies, receipts, or system notifications
  if (shouldSuppressAutoReply(envelope)) {
    return { respond: false, reason: "suppressed_intent" };
  }

  // Check if rule is active
  if (!isAutoresponderActive(rule)) {
    return { respond: false, reason: "schedule_inactive" };
  }

  const senderIdentity = envelope.from?.identity;
  if (!senderIdentity) {
    return { respond: false, reason: "no_sender" };
  }

  // Frequency limiting
  const frequency = rule.frequency_limit || "once_per_sender";
  const lastSent = sentHistory.get(senderIdentity);

  if (frequency === "once_per_sender" && lastSent) {
    return { respond: false, reason: "already_sent_to_sender" };
  }

  if (frequency === "once_per_day" && lastSent) {
    const oneDayAgo = Date.now() - 86400000;
    const lastSentTime = Date.parse(lastSent);
    if (Number.isFinite(lastSentTime) && lastSentTime > oneDayAgo) {
      return { respond: false, reason: "already_sent_today" };
    }
  }

  return { respond: true };
}

export function buildAutoReplyEnvelope(originalEnvelope, rule, responderIdentity) {
  return {
    loom: "1.1",
    id: `env_${generateUlid()}`,
    thread_id: originalEnvelope.thread_id,
    parent_id: originalEnvelope.id,
    type: "notification",
    from: {
      identity: responderIdentity,
      display: "Auto-Reply",
      type: "service"
    },
    to: [
      {
        identity: originalEnvelope.from?.identity,
        role: "primary"
      }
    ],
    created_at: new Date().toISOString(),
    priority: "low",
    content: {
      human: {
        text: rule.message,
        format: rule.format || "plaintext"
      },
      structured: {
        intent: "notification.autoreply@v1",
        parameters: {
          original_recipient: responderIdentity,
          triggered_by_envelope_id: originalEnvelope.id,
          ...(rule.schedule_start ? { schedule_start: rule.schedule_start } : {}),
          ...(rule.schedule_end ? { schedule_end: rule.schedule_end } : {}),
          frequency_limit: rule.frequency_limit || "once_per_sender"
        }
      },
      encrypted: false
    },
    attachments: []
  };
}
