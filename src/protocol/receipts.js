// ─── Receipt Envelope Builders ──────────────────────────────────────────────
//
// Helpers for constructing receipt.delivered@v1, receipt.read@v1, and
// receipt.failed@v1 envelopes per Section 20.8.

import { generateUlid } from "./ulid.js";

function receiptBase(originalEnvelope, fromIdentity, intent, parameters) {
  return {
    loom: "1.1",
    id: `env_${generateUlid()}`,
    thread_id: originalEnvelope.thread_id,
    parent_id: originalEnvelope.id,
    type: "receipt",
    from: {
      identity: fromIdentity,
      display: "System",
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
        text: `Receipt: ${intent}`,
        format: "plaintext"
      },
      structured: {
        intent,
        parameters
      },
      encrypted: false
    },
    attachments: []
  };
}

export function buildDeliveryReceipt(originalEnvelope, { fromIdentity, nodeId = null }) {
  const parameters = {
    original_envelope_id: originalEnvelope.id,
    timestamp: new Date().toISOString()
  };
  if (nodeId) {
    parameters.node_id = nodeId;
  }
  return receiptBase(originalEnvelope, fromIdentity, "receipt.delivered@v1", parameters);
}

export function buildReadReceipt(originalEnvelope, { fromIdentity, deviceId = null, userConfirmed = true }) {
  const parameters = {
    original_envelope_id: originalEnvelope.id,
    read_at: new Date().toISOString(),
    user_confirmed: userConfirmed
  };
  if (deviceId) {
    parameters.device_id = deviceId;
  }
  return receiptBase(originalEnvelope, fromIdentity, "receipt.read@v1", parameters);
}

export function buildFailureReceipt(originalEnvelope, { fromIdentity, reason, details = null, retryAfter = null }) {
  const parameters = {
    original_envelope_id: originalEnvelope.id,
    reason,
    failed_at: new Date().toISOString()
  };
  if (details) {
    parameters.details = details;
  }
  if (retryAfter) {
    parameters.retry_after = retryAfter;
  }
  return receiptBase(originalEnvelope, fromIdentity, "receipt.failed@v1", parameters);
}

// ─── Autoresponder guard ────────────────────────────────────────────────────

export function isAutoReplyIntent(intent) {
  return intent === "notification.autoreply@v1";
}

export function shouldSuppressAutoReply(envelope) {
  const intent = envelope?.content?.structured?.intent;
  // Never auto-reply to another auto-reply (loop prevention)
  if (isAutoReplyIntent(intent)) return true;
  // Never auto-reply to receipts
  if (typeof intent === "string" && intent.startsWith("receipt.")) return true;
  // Never auto-reply to system notifications
  if (intent === "notification.system@v1") return true;
  return false;
}
