// ─── Legacy Gateway (IMAP/SMTP Façade) — Section 22 ─────────────────────────
//
// IMAP folder mapping, RFC822 rendering, SMTP submission conversion.

// ─── IMAP Folder Mapping — Section 22.2 ─────────────────────────────────────

export const LABEL_TO_IMAP_FOLDER = Object.freeze({
  "sys.inbox": "INBOX",
  "sys.sent": "Sent",
  "sys.archive": "Archive",
  "sys.spam": "Junk",
  "sys.trash": "Trash",
  "sys.drafts": "Drafts",
  "sys.quarantine": "Quarantine"
});

export const IMAP_FOLDER_TO_LABEL = Object.freeze(
  Object.fromEntries(Object.entries(LABEL_TO_IMAP_FOLDER).map(([k, v]) => [v, k]))
);

export function resolveImapFolder(labels) {
  if (!Array.isArray(labels)) return "INBOX";

  // Priority order: quarantine > spam > trash > sent > archive > drafts > inbox
  const priority = ["sys.quarantine", "sys.spam", "sys.trash", "sys.sent", "sys.archive", "sys.drafts", "sys.inbox"];
  for (const label of priority) {
    if (labels.includes(label) && LABEL_TO_IMAP_FOLDER[label]) {
      return LABEL_TO_IMAP_FOLDER[label];
    }
  }

  return "INBOX";
}

// ─── RFC822 Rendering — Section 22.2 ───────────────────────────────────────

export function renderRfc822Message(envelope, options = {}) {
  const from = formatEmailAddress(envelope.from);
  const to = (envelope.to || [])
    .filter((r) => r.role !== "bcc")
    .map(formatEmailAddress)
    .join(", ");
  const subject = options.subject || envelope.content?.structured?.parameters?.subject || "(no subject)";
  const date = new Date(envelope.created_at).toUTCString();
  const messageId = `<${envelope.id}@loom>`;

  const headers = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `Date: ${date}`,
    `Message-ID: ${messageId}`,
    `MIME-Version: 1.0`,
    `X-LOOM-Thread-ID: ${envelope.thread_id}`,
    `X-LOOM-Envelope-ID: ${envelope.id}`,
    `X-LOOM-Intent: ${envelope.content?.structured?.intent || "message.general@v1"}`
  ];

  // Threading headers
  if (envelope.parent_id) {
    headers.push(`In-Reply-To: <${envelope.parent_id}@loom>`);
  }

  const refs = [];
  if (envelope.thread_id) refs.push(`<${envelope.thread_id}@loom>`);
  if (envelope.parent_id) refs.push(`<${envelope.parent_id}@loom>`);
  if (refs.length > 0) {
    headers.push(`References: ${refs.join(" ")}`);
  }

  const body = envelope.content?.human?.text || "";
  const format = envelope.content?.human?.format || "plaintext";

  if (format === "html" || format === "markdown") {
    // Multipart with plaintext + HTML
    const boundary = `loom-boundary-${envelope.id.slice(-12)}`;
    headers.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);

    const plainPart = `--${boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${body}`;
    const htmlBody = format === "html" ? body : markdownToBasicHtml(body);
    const htmlPart = `--${boundary}\r\nContent-Type: text/html; charset=utf-8\r\n\r\n${htmlBody}`;

    // Structured payload as application/loom+json part
    const structured = envelope.content?.structured;
    const loomPart = structured
      ? `--${boundary}\r\nContent-Type: application/loom+json; charset=utf-8\r\n\r\n${JSON.stringify(structured)}`
      : "";

    return `${headers.join("\r\n")}\r\n\r\n${plainPart}\r\n${htmlPart}\r\n${loomPart}\r\n--${boundary}--`;
  }

  // Plain text message with structured payload as additional part
  const structured = envelope.content?.structured;
  if (structured) {
    const boundary = `loom-boundary-${envelope.id.slice(-12)}`;
    headers.push(`Content-Type: multipart/mixed; boundary="${boundary}"`);
    const textPart = `--${boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${body}`;
    const loomPart = `--${boundary}\r\nContent-Type: application/loom+json; charset=utf-8\r\n\r\n${JSON.stringify(structured)}`;
    return `${headers.join("\r\n")}\r\n\r\n${textPart}\r\n${loomPart}\r\n--${boundary}--`;
  }

  headers.push("Content-Type: text/plain; charset=utf-8");
  return `${headers.join("\r\n")}\r\n\r\n${body}`;
}

function formatEmailAddress(participant) {
  if (!participant) return "unknown@loom";
  const identity = participant.identity || "";
  const display = participant.display || "";

  // Convert loom://user@domain to user@domain
  let email = identity;
  if (identity.startsWith("loom://")) {
    email = identity.slice(7);
  } else if (identity.startsWith("bridge://")) {
    email = identity.slice(9);
  }

  if (display && display !== email) {
    return `"${display}" <${email}>`;
  }
  return email;
}

function markdownToBasicHtml(text) {
  let html = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  html = html.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*(.+?)\*/g, "<em>$1</em>");
  html = html.replace(/`(.+?)`/g, "<code>$1</code>");
  html = html.replace(/\n/g, "<br>\n");
  return `<!DOCTYPE html><html><body>${html}</body></html>`;
}

// ─── SMTP Submission → LOOM Envelope — Section 22.3 ────────────────────────

export function convertSmtpSubmissionToEnvelope(parsedEmail, signerIdentity) {
  return {
    loom: "1.1",
    id: null, // Caller assigns
    thread_id: null, // Caller resolves from References
    parent_id: null, // Caller resolves from In-Reply-To
    type: "message",
    from: {
      identity: signerIdentity,
      display: parsedEmail.from_display || signerIdentity,
      type: "human"
    },
    to: (parsedEmail.to || []).map((addr) => ({
      identity: addr,
      role: "primary"
    })),
    created_at: new Date().toISOString(),
    priority: "normal",
    content: {
      human: {
        text: parsedEmail.body || "",
        format: parsedEmail.format || "plaintext"
      },
      structured: {
        intent: "message.general@v1", // Default — best-effort extraction by caller
        parameters: {
          subject: parsedEmail.subject || null
        }
      },
      encrypted: false
    },
    attachments: parsedEmail.attachments || []
  };
}
