import {
  AUDIENCE_MODES,
  ENVELOPE_TYPES,
  IDENTITY_TYPES,
  LOOM_VERSION,
  PRIORITIES,
  RECIPIENT_ROLES
} from "./constants.js";
import { LoomError } from "./errors.js";
import {
  hasTypedUlid,
  isEnvelopeId,
  isIdentity,
  isIsoDateTime,
  isThreadId
} from "./ids.js";
import { validateEncryptedContentShape } from "./e2ee.js";

function pushError(errors, field, reason) {
  errors.push({ field, reason });
}

function validateSender(from, errors) {
  if (!from || typeof from !== "object") {
    pushError(errors, "from", "sender object is required");
    return;
  }

  if (!isIdentity(from.identity)) {
    pushError(errors, "from.identity", "must be a loom:// or bridge:// identity");
  }

  if (typeof from.key_id !== "string" || from.key_id.length < 3) {
    pushError(errors, "from.key_id", "must be present");
  }

  if (!IDENTITY_TYPES.has(from.type)) {
    pushError(errors, "from.type", "must be one of human|agent|team|service|bridge");
  }

  if (from.type === "agent" && !Array.isArray(from.delegation_chain)) {
    pushError(errors, "from.delegation_chain", "required for agent senders");
  }
}

function validateRecipients(to, errors) {
  if (!Array.isArray(to) || to.length === 0) {
    pushError(errors, "to", "must contain at least one recipient");
    return;
  }

  let hasPrimary = false;
  for (let idx = 0; idx < to.length; idx += 1) {
    const recipient = to[idx];
    if (!recipient || typeof recipient !== "object") {
      pushError(errors, `to[${idx}]`, "recipient entry must be an object");
      continue;
    }

    if (!isIdentity(recipient.identity)) {
      pushError(errors, `to[${idx}].identity`, "must be a loom:// or bridge:// identity");
    }

    if (!RECIPIENT_ROLES.has(recipient.role)) {
      pushError(errors, `to[${idx}].role`, "must be primary|cc|observer|bcc");
    }

    if (recipient.role === "primary") {
      hasPrimary = true;
    }
  }

  if (!hasPrimary) {
    pushError(errors, "to", "must include at least one primary recipient");
  }
}

function validateAudience(audience, errors) {
  if (audience == null) {
    return;
  }

  if (typeof audience !== "object") {
    pushError(errors, "audience", "must be an object");
    return;
  }

  if (!AUDIENCE_MODES.has(audience.mode)) {
    pushError(errors, "audience.mode", "must be thread|recipients|custom");
  }

  if (audience.mode === "custom") {
    if (!Array.isArray(audience.identities) || audience.identities.length === 0) {
      pushError(errors, "audience.identities", "must include identities for custom audience");
      return;
    }

    for (let idx = 0; idx < audience.identities.length; idx += 1) {
      if (!isIdentity(audience.identities[idx])) {
        pushError(errors, `audience.identities[${idx}]`, "must be valid identities");
      }
    }
  }
}

function validateRecipientAudienceConsistency(to, audience, errors) {
  if (!Array.isArray(to) || to.length === 0) {
    return;
  }

  const hasBcc = to.some((recipient) => recipient?.role === "bcc");
  if (!hasBcc) {
    return;
  }

  if (!audience || audience.mode !== "recipients") {
    pushError(
      errors,
      "audience.mode",
      "bcc recipients require audience.mode=\"recipients\" for privacy-safe recipient views"
    );
  }
}

function validateContent(content, errors) {
  if (!content || typeof content !== "object") {
    pushError(errors, "content", "content object is required");
    return;
  }

  const encrypted = Boolean(content.encrypted);

  if (encrypted) {
    const encryptedErrors = validateEncryptedContentShape(content);
    for (const encryptedError of encryptedErrors) {
      pushError(errors, encryptedError.field, encryptedError.reason);
    }
    return;
  }

  const hasHuman = !!content.human;
  const hasStructured = !!content.structured;

  if (!hasHuman && !hasStructured) {
    pushError(errors, "content", "must include content.human or content.structured when not encrypted");
  }

  if (hasHuman) {
    if (typeof content.human.text !== "string") {
      pushError(errors, "content.human.text", "must be a string");
    }
  }

  if (hasStructured) {
    if (typeof content.structured.intent !== "string" || content.structured.intent.length === 0) {
      pushError(errors, "content.structured.intent", "must be a non-empty string");
    }
  }
}

const INTENT_PREFIXES_BY_TYPE = {
  message: ["message."],
  task: ["task."],
  approval: ["approval."],
  event: ["event."],
  notification: ["notification."],
  handoff: ["handoff."],
  data: ["data."],
  receipt: ["receipt."],
  workflow: ["workflow."],
  thread_op: ["thread.", "capability.", "encryption."]
};

function validateTypeIntentConsistency(envelope, errors) {
  const type = typeof envelope?.type === "string" ? envelope.type.trim() : "";
  const structuredIntent =
    typeof envelope?.content?.structured?.intent === "string"
      ? envelope.content.structured.intent.trim()
      : "";

  if (!type || !structuredIntent) {
    if (type === "thread_op" && !structuredIntent) {
      pushError(errors, "content.structured.intent", "thread_op requires a structured intent");
    }
    return;
  }

  const allowedPrefixes = INTENT_PREFIXES_BY_TYPE[type];
  if (!allowedPrefixes || allowedPrefixes.length === 0) {
    return;
  }

  if (!allowedPrefixes.some((prefix) => structuredIntent.startsWith(prefix))) {
    pushError(
      errors,
      "content.structured.intent",
      `must match envelope type "${type}" (${allowedPrefixes.join(" or ")})`
    );
  }
}

function validateAttachments(attachments, errors) {
  if (attachments == null) {
    return;
  }

  if (!Array.isArray(attachments)) {
    pushError(errors, "attachments", "must be an array");
    return;
  }

  for (let idx = 0; idx < attachments.length; idx += 1) {
    const attachment = attachments[idx];
    if (!attachment || typeof attachment !== "object") {
      pushError(errors, `attachments[${idx}]`, "must be an object");
      continue;
    }

    if (!hasTypedUlid(attachment.id, "att_")) {
      pushError(errors, `attachments[${idx}].id`, "must be att_ + ULID");
    }

    if (!hasTypedUlid(attachment.blob_id, "blob_")) {
      pushError(errors, `attachments[${idx}].blob_id`, "must be blob_ + ULID");
    }

    if (typeof attachment.hash !== "string" || !attachment.hash.startsWith("sha256:")) {
      pushError(errors, `attachments[${idx}].hash`, "must use sha256:<hex> format");
    }
  }
}

function validateSignature(signature, errors) {
  if (!signature || typeof signature !== "object") {
    pushError(errors, "signature", "signature object is required");
    return;
  }

  if (signature.algorithm !== "Ed25519") {
    pushError(errors, "signature.algorithm", "must be Ed25519");
  }

  if (typeof signature.key_id !== "string" || signature.key_id.length < 3) {
    pushError(errors, "signature.key_id", "must be present");
  }

  if (typeof signature.value !== "string" || signature.value.length < 10) {
    pushError(errors, "signature.value", "must be a base64url string");
  }
}

export function validateEnvelopeShape(envelope) {
  const errors = [];

  if (!envelope || typeof envelope !== "object") {
    return [{ field: "envelope", reason: "must be a JSON object" }];
  }

  if (envelope.loom !== LOOM_VERSION) {
    pushError(errors, "loom", `must be \"${LOOM_VERSION}\"`);
  }

  if (!isEnvelopeId(envelope.id)) {
    pushError(errors, "id", "must be env_ + ULID");
  }

  if (!isThreadId(envelope.thread_id)) {
    pushError(errors, "thread_id", "must be thr_ + ULID");
  }

  if (envelope.parent_id != null && !isEnvelopeId(envelope.parent_id)) {
    pushError(errors, "parent_id", "must be env_ + ULID or null");
  }

  if (typeof envelope.type !== "string" || envelope.type.length === 0) {
    pushError(errors, "type", "must be a non-empty string");
  } else if (!ENVELOPE_TYPES.has(envelope.type)) {
    pushError(errors, "type", "must be one of the protocol envelope types");
  }

  validateSender(envelope.from, errors);
  validateRecipients(envelope.to, errors);
  validateAudience(envelope.audience, errors);
  validateRecipientAudienceConsistency(envelope.to, envelope.audience, errors);

  if (!isIsoDateTime(envelope.created_at)) {
    pushError(errors, "created_at", "must be an ISO-8601 timestamp");
  }

  if (envelope.expires_at != null && !isIsoDateTime(envelope.expires_at)) {
    pushError(errors, "expires_at", "must be null or an ISO-8601 timestamp");
  }

  if (envelope.priority != null && !PRIORITIES.has(envelope.priority)) {
    pushError(errors, "priority", "must be low|normal|high|urgent");
  }

  validateContent(envelope.content, errors);
  validateTypeIntentConsistency(envelope, errors);
  validateAttachments(envelope.attachments, errors);
  validateSignature(envelope.signature, errors);

  return errors;
}

export function validateEnvelopeOrThrow(envelope) {
  const errors = validateEnvelopeShape(envelope);
  if (errors.length > 0) {
    throw new LoomError("ENVELOPE_INVALID", "Envelope fails validation", 400, { errors });
  }
}
