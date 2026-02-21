import test from "node:test";
import assert from "node:assert/strict";

import {
  LABEL_TO_IMAP_FOLDER,
  IMAP_FOLDER_TO_LABEL,
  resolveImapFolder,
  renderRfc822Message,
  convertSmtpSubmissionToEnvelope
} from "../src/protocol/legacy_gateway.js";

// ─── IMAP Folder Mapping ───────────────────────────────────────────────────

test("LABEL_TO_IMAP_FOLDER maps standard labels", () => {
  assert.equal(LABEL_TO_IMAP_FOLDER["sys.inbox"], "INBOX");
  assert.equal(LABEL_TO_IMAP_FOLDER["sys.sent"], "Sent");
  assert.equal(LABEL_TO_IMAP_FOLDER["sys.archive"], "Archive");
  assert.equal(LABEL_TO_IMAP_FOLDER["sys.spam"], "Junk");
  assert.equal(LABEL_TO_IMAP_FOLDER["sys.trash"], "Trash");
  assert.equal(LABEL_TO_IMAP_FOLDER["sys.drafts"], "Drafts");
});

test("IMAP_FOLDER_TO_LABEL is reverse mapping", () => {
  assert.equal(IMAP_FOLDER_TO_LABEL["INBOX"], "sys.inbox");
  assert.equal(IMAP_FOLDER_TO_LABEL["Sent"], "sys.sent");
  assert.equal(IMAP_FOLDER_TO_LABEL["Junk"], "sys.spam");
});

// ─── resolveImapFolder ─────────────────────────────────────────────────────

test("resolveImapFolder: resolves by priority", () => {
  assert.equal(resolveImapFolder(["sys.inbox"]), "INBOX");
  assert.equal(resolveImapFolder(["sys.sent"]), "Sent");
  assert.equal(resolveImapFolder(["sys.trash"]), "Trash");
  assert.equal(resolveImapFolder(["sys.spam"]), "Junk");
});

test("resolveImapFolder: quarantine > spam", () => {
  assert.equal(resolveImapFolder(["sys.spam", "sys.quarantine"]), "Quarantine");
});

test("resolveImapFolder: spam > trash", () => {
  assert.equal(resolveImapFolder(["sys.trash", "sys.spam"]), "Junk");
});

test("resolveImapFolder: defaults to INBOX", () => {
  assert.equal(resolveImapFolder([]), "INBOX");
  assert.equal(resolveImapFolder(["custom.label"]), "INBOX");
});

test("resolveImapFolder: non-array defaults to INBOX", () => {
  assert.equal(resolveImapFolder(null), "INBOX");
});

// ─── renderRfc822Message ───────────────────────────────────────────────────

test("renderRfc822Message: basic plaintext message", () => {
  const envelope = {
    id: "env_abc123",
    thread_id: "thr_1",
    from: { identity: "loom://alice@example.com", display: "Alice" },
    to: [{ identity: "loom://bob@example.com", display: "Bob", role: "primary" }],
    created_at: "2025-06-01T12:00:00Z",
    content: {
      human: { text: "Hello Bob!", format: "plaintext" },
      structured: { intent: "message.general@v1", parameters: {} }
    }
  };
  const rfc822 = renderRfc822Message(envelope);
  assert.ok(rfc822.includes("From: "));
  assert.ok(rfc822.includes("To: "));
  assert.ok(rfc822.includes("Message-ID: <env_abc123@loom>"));
  assert.ok(rfc822.includes("X-LOOM-Thread-ID: thr_1"));
  assert.ok(rfc822.includes("X-LOOM-Envelope-ID: env_abc123"));
  assert.ok(rfc822.includes("X-LOOM-Intent: message.general@v1"));
  assert.ok(rfc822.includes("Hello Bob!"));
});

test("renderRfc822Message: includes threading headers for replies", () => {
  const envelope = {
    id: "env_2",
    thread_id: "thr_1",
    parent_id: "env_1",
    from: { identity: "loom://bob@ex" },
    to: [{ identity: "loom://alice@ex", role: "primary" }],
    created_at: "2025-06-01T12:00:00Z",
    content: { human: { text: "reply" } }
  };
  const rfc822 = renderRfc822Message(envelope);
  assert.ok(rfc822.includes("In-Reply-To: <env_1@loom>"));
  assert.ok(rfc822.includes("References:"));
});

test("renderRfc822Message: multipart for HTML/markdown", () => {
  const envelope = {
    id: "env_html",
    thread_id: "thr_1",
    from: { identity: "loom://a@ex" },
    to: [{ identity: "loom://b@ex", role: "primary" }],
    created_at: "2025-06-01T12:00:00Z",
    content: {
      human: { text: "**bold** text", format: "markdown" },
      structured: { intent: "message.general@v1" }
    }
  };
  const rfc822 = renderRfc822Message(envelope);
  assert.ok(rfc822.includes("multipart/alternative"));
  assert.ok(rfc822.includes("text/plain"));
  assert.ok(rfc822.includes("text/html"));
  assert.ok(rfc822.includes("application/loom+json"));
});

test("renderRfc822Message: excludes BCC from To header", () => {
  const envelope = {
    id: "env_bcc",
    thread_id: "thr_1",
    from: { identity: "loom://a@ex" },
    to: [
      { identity: "loom://visible@ex", role: "primary" },
      { identity: "loom://hidden@ex", role: "bcc" }
    ],
    created_at: "2025-06-01T12:00:00Z",
    content: { human: { text: "test" } }
  };
  const rfc822 = renderRfc822Message(envelope);
  assert.ok(rfc822.includes("visible@ex"));
  // BCC should not appear in the To header line
  const toLine = rfc822.split("\r\n").find((l) => l.startsWith("To:"));
  assert.ok(!toLine.includes("hidden@ex"));
});

test("renderRfc822Message: subject from options", () => {
  const rfc822 = renderRfc822Message(
    {
      id: "e1",
      thread_id: "t1",
      from: { identity: "loom://a" },
      to: [{ identity: "loom://b", role: "primary" }],
      created_at: "2025-06-01T12:00:00Z",
      content: { human: { text: "test" } }
    },
    { subject: "Custom Subject" }
  );
  assert.ok(rfc822.includes("Subject: Custom Subject"));
});

// ─── convertSmtpSubmissionToEnvelope ───────────────────────────────────────

test("convertSmtpSubmissionToEnvelope: creates envelope from email", () => {
  const parsed = {
    from_display: "Alice Smith",
    to: ["loom://bob@example.com"],
    subject: "Meeting Notes",
    body: "Here are the notes.",
    format: "plaintext",
    attachments: []
  };
  const env = convertSmtpSubmissionToEnvelope(parsed, "loom://alice@example.com");
  assert.equal(env.loom, "1.1");
  assert.equal(env.id, null); // caller assigns
  assert.equal(env.type, "message");
  assert.equal(env.from.identity, "loom://alice@example.com");
  assert.equal(env.from.display, "Alice Smith");
  assert.equal(env.to[0].identity, "loom://bob@example.com");
  assert.equal(env.content.human.text, "Here are the notes.");
  assert.equal(env.content.structured.intent, "message.general@v1");
  assert.equal(env.content.structured.parameters.subject, "Meeting Notes");
});

test("convertSmtpSubmissionToEnvelope: defaults for missing fields", () => {
  const env = convertSmtpSubmissionToEnvelope({}, "loom://user");
  assert.equal(env.from.identity, "loom://user");
  assert.equal(env.content.human.text, "");
  assert.equal(env.content.human.format, "plaintext");
});
