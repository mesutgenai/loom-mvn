// ─── Deletion & Crypto-Shredding — Section 25.2 ────────────────────────────
//
// Content erasure with audit skeleton retention and crypto-shredding support.

import { isLegalHoldActive } from "./retention.js";

export const DELETION_MODES = Object.freeze({
  CONTENT_ERASURE: "content_erasure",
  CRYPTO_SHRED: "crypto_shred"
});

export function canDeleteEnvelope(envelope, thread) {
  const labels = thread?.labels || [];
  if (isLegalHoldActive(labels)) {
    return { allowed: false, reason: "LEGAL_HOLD_ACTIVE" };
  }
  return { allowed: true };
}

export function eraseEnvelopeContent(envelope) {
  // Retain audit skeleton: id, thread_id, from.identity, created_at, type, meta
  // Erase: content.human.text, content.structured.parameters, attachments
  return {
    ...envelope,
    content: {
      human: { text: "[deleted]", format: "plaintext" },
      structured: envelope.content?.structured
        ? {
            intent: envelope.content.structured.intent,
            parameters: {} // erased
          }
        : null,
      encrypted: envelope.content?.encrypted || false
    },
    attachments: [],
    meta: {
      ...(envelope.meta || {}),
      deleted: true,
      deleted_at: new Date().toISOString()
    }
  };
}

export function buildCryptoShredRecord(threadId, keyEpoch) {
  return {
    thread_id: threadId,
    key_epoch: keyEpoch,
    shredded_at: new Date().toISOString(),
    keys_destroyed: true
  };
}

export function validateDeletionRequest(envelope, thread) {
  const errors = [];

  const canDelete = canDeleteEnvelope(envelope, thread);
  if (!canDelete.allowed) {
    errors.push({ field: "deletion", reason: canDelete.reason });
  }

  if (!envelope || !envelope.id) {
    errors.push({ field: "envelope_id", reason: "required" });
  }

  return errors;
}
