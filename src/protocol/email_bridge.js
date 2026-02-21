// ─── Email Bridge — Section 21 ──────────────────────────────────────────────
//
// Inbound (email → LOOM) and outbound (LOOM → email) bridge helpers.

import { generateUlid } from "./ulid.js";

// ─── Inbound: Email → LOOM Envelope ────────────────────────────────────────

export function buildBridgeIdentity(emailAddress) {
  return `bridge://${String(emailAddress || "").trim().toLowerCase()}`;
}

export function buildInboundBridgeMeta(emailHeaders, authResults = {}) {
  return {
    bridge: {
      source: "email",
      original_message_id: emailHeaders["message-id"] || null,
      original_headers: emailHeaders,
      auth_results: {
        spf: authResults.spf || "none",
        dkim: authResults.dkim || "none",
        dmarc: authResults.dmarc || "none"
      },
      extraction_confidence: 0.0
    }
  };
}

export function buildInboundEnvelope({ from, to, subject, body, emailHeaders, authResults, threadId = null, parentId = null }) {
  const senderIdentity = buildBridgeIdentity(from);
  const recipients = (Array.isArray(to) ? to : [to]).map((addr) => ({
    identity: buildBridgeIdentity(addr),
    role: "primary"
  }));

  return {
    loom: "1.1",
    id: `env_${generateUlid()}`,
    thread_id: threadId || `thr_${generateUlid()}`,
    parent_id: parentId || null,
    type: "message",
    from: {
      identity: senderIdentity,
      display: from,
      type: "bridge"
    },
    to: recipients,
    created_at: new Date().toISOString(),
    priority: "normal",
    content: {
      human: {
        text: body || "",
        format: "markdown"
      },
      structured: {
        intent: "message.general@v1",
        parameters: {
          extracted: true,
          subject: subject || null
        }
      },
      encrypted: false
    },
    attachments: [],
    meta: buildInboundBridgeMeta(emailHeaders || {}, authResults || {})
  };
}

// ─── Outbound: LOOM Envelope → Email Headers ───────────────────────────────

export function buildOutboundHeaders(envelope) {
  const headers = {};

  headers["X-LOOM-Intent"] = envelope.content?.structured?.intent || "message.general@v1";
  headers["X-LOOM-Thread-ID"] = envelope.thread_id;
  headers["X-LOOM-Envelope-ID"] = envelope.id;

  // Threading headers
  if (envelope.parent_id) {
    headers["In-Reply-To"] = `<${envelope.parent_id}@loom>`;
  }

  // Build References chain
  const refs = [];
  const threadId = envelope.thread_id;
  if (threadId) {
    refs.push(`<${threadId}@loom>`);
  }
  if (envelope.parent_id) {
    refs.push(`<${envelope.parent_id}@loom>`);
  }
  if (refs.length > 0) {
    headers["References"] = refs.join(" ");
  }

  return headers;
}

export function renderPlaintext(envelope) {
  return envelope.content?.human?.text || "";
}

export function renderHtml(envelope) {
  const text = envelope.content?.human?.text || "";
  const format = envelope.content?.human?.format || "plaintext";

  if (format === "html") {
    return text; // Already HTML
  }

  // Basic markdown-to-HTML (minimal — production would use a proper renderer)
  let html = escapeHtml(text);
  // Bold
  html = html.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  // Italic
  html = html.replace(/\*(.+?)\*/g, "<em>$1</em>");
  // Code
  html = html.replace(/`(.+?)`/g, "<code>$1</code>");
  // Line breaks
  html = html.replace(/\n/g, "<br>\n");

  return `<!DOCTYPE html><html><body>${html}</body></html>`;
}

function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─── BCC Handling ───────────────────────────────────────────────────────────

export function splitBccRecipients(envelope) {
  const to = Array.isArray(envelope.to) ? envelope.to : [];
  const visible = to.filter((r) => r.role !== "bcc");
  const bcc = to.filter((r) => r.role === "bcc");

  return {
    visible,
    bcc,
    // Each BCC recipient gets a separate SMTP message
    bccMessages: bcc.map((recipient) => ({
      to: [recipient],
      visibleRecipients: visible
    }))
  };
}

// ─── Bridge identity restrictions — Section 21.4 ───────────────────────────

export function isBridgeIdentity(identity) {
  return typeof identity === "string" && identity.startsWith("bridge://");
}

export function validateBridgeIdentityRestrictions(identity, operation) {
  if (!isBridgeIdentity(identity)) return [];

  const errors = [];
  const forbidden = ["delegate", "spawn_agent", "encryption.epoch", "encryption.rotate"];
  if (forbidden.includes(operation)) {
    errors.push({
      field: "identity",
      reason: `bridge identities cannot perform ${operation}`
    });
  }

  return errors;
}
