import nodemailer from "nodemailer";
import { readFileSync } from "node:fs";

import { LoomError } from "../protocol/errors.js";
import { parseBoolean, parsePositiveInt } from "./env.js";

function normalizeMode(value) {
  if (typeof value !== "string") {
    return null;
  }
  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    return null;
  }
  if (normalized === "disabled" || normalized === "smtp" || normalized === "stream") {
    return normalized;
  }
  return null;
}

function normalizePem(value) {
  if (value == null) {
    return null;
  }
  const normalized = String(value).replace(/\\n/g, "\n").trim();
  return normalized ? `${normalized}\n` : null;
}

function readOptionalFile(path) {
  const normalizedPath = String(path || "").trim();
  if (!normalizedPath) {
    return null;
  }

  try {
    const raw = readFileSync(normalizedPath, "utf-8");
    return normalizePem(raw);
  } catch {
    throw new LoomError("ENVELOPE_INVALID", `Unable to read DKIM private key file: ${normalizedPath}`, 400, {
      field: "smtp_dkim_private_key_file"
    });
  }
}

function normalizeDkimHeaderFieldNames(value) {
  if (value == null) {
    return null;
  }

  if (Array.isArray(value)) {
    const normalized = value
      .map((entry) => String(entry || "").trim())
      .filter(Boolean)
      .join(":");
    return normalized || null;
  }

  const normalized = String(value).trim();
  return normalized || null;
}

function buildDkimConfig(options = {}) {
  const domainName = String(options.smtpDkimDomainName || "").trim();
  const keySelector = String(options.smtpDkimKeySelector || "").trim();
  const privateKey =
    normalizePem(options.smtpDkimPrivateKeyPem) || readOptionalFile(options.smtpDkimPrivateKeyFile);
  const headerFieldNames = normalizeDkimHeaderFieldNames(options.smtpDkimHeaderFieldNames);

  const configuredFields = [domainName, keySelector, privateKey].filter(Boolean).length;
  if (configuredFields === 0) {
    return null;
  }

  if (!domainName || !keySelector || !privateKey) {
    throw new LoomError("ENVELOPE_INVALID", "DKIM requires domain, selector, and private key", 400, {
      field: "smtp_dkim"
    });
  }

  const config = {
    domainName,
    keySelector,
    privateKey
  };
  if (headerFieldNames) {
    config.headerFieldNames = headerFieldNames;
  }
  return config;
}

function redact(value) {
  if (!value) {
    return null;
  }
  const text = String(value);
  if (text.length <= 6) {
    return "***";
  }
  return `${text.slice(0, 2)}***${text.slice(-2)}`;
}

function containsUnsafeHeaderChars(value) {
  return /[\r\n\0]/.test(String(value || ""));
}

function decodeBase64Content(value, field) {
  const normalized = String(value || "").replace(/\s+/g, "");
  if (!normalized) {
    throw new LoomError("ENVELOPE_INVALID", `${field} must be non-empty base64`, 400, {
      field
    });
  }
  // Validate character set only; padding may legitimately be absent after
  // whitespace stripping, so we rely on Buffer.from to handle that correctly.
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new LoomError("ENVELOPE_INVALID", `${field} must be valid base64`, 400, {
      field
    });
  }
  const buf = Buffer.from(normalized, "base64");
  // Verify round-trip: re-encode and strip padding to detect corrupt input.
  const roundTrip = buf.toString("base64").replace(/=+$/, "");
  const strippedInput = normalized.replace(/=+$/, "");
  if (roundTrip !== strippedInput) {
    throw new LoomError("ENVELOPE_INVALID", `${field} must be valid base64`, 400, {
      field
    });
  }
  return buf;
}

function normalizeRenderedAttachments(attachments) {
  if (!Array.isArray(attachments) || attachments.length === 0) {
    return [];
  }

  return attachments.map((entry, index) => {
    if (!entry || typeof entry !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Attachment entry must be an object", 400, {
        field: `attachments[${index}]`
      });
    }

    const filename = String(entry.filename || `attachment-${index + 1}.bin`).trim();
    if (!filename || containsUnsafeHeaderChars(filename)) {
      throw new LoomError("ENVELOPE_INVALID", "Attachment filename is invalid", 400, {
        field: `attachments[${index}].filename`
      });
    }

    const contentType = String(entry.mime_type || "application/octet-stream").trim();
    if (!contentType || containsUnsafeHeaderChars(contentType)) {
      throw new LoomError("ENVELOPE_INVALID", "Attachment mime_type is invalid", 400, {
        field: `attachments[${index}].mime_type`
      });
    }

    const dispositionRaw = String(entry.disposition || "attachment")
      .trim()
      .toLowerCase();
    const disposition = dispositionRaw === "inline" ? "inline" : "attachment";

    const contentId = entry.content_id ? String(entry.content_id).trim() : null;
    if (contentId && containsUnsafeHeaderChars(contentId)) {
      throw new LoomError("ENVELOPE_INVALID", "Attachment content_id is invalid", 400, {
        field: `attachments[${index}].content_id`
      });
    }

    return {
      filename,
      contentType,
      contentDisposition: disposition,
      cid: contentId || undefined,
      content: decodeBase64Content(entry.data_base64, `attachments[${index}].data_base64`)
    };
  });
}

export class LoomEmailRelay {
  constructor(options = {}) {
    this.mode = normalizeMode(options.mode) || null;
    this.defaultFrom = options.defaultFrom || null;
    this.transporter = null;
    this.dkim = null;
    this.summary = {
      mode: "disabled",
      configured: false,
      host: null,
      port: null,
      secure: false,
      has_auth: false,
      dkim_enabled: false,
      dkim_domain: null,
      dkim_selector: null
    };

    this.initializeFromOptions(options);
  }

  initializeFromOptions(options) {
    const smtpUrl = options.smtpUrl || null;
    const smtpHost = options.smtpHost || null;
    const smtpPort = parsePositiveInt(options.smtpPort, 587);
    const smtpSecure = parseBoolean(options.smtpSecure, false);
    const smtpUser = options.smtpUser || null;
    const smtpPass = options.smtpPass || null;
    const smtpRequireTls = parseBoolean(options.smtpRequireTls, false);
    const smtpRejectUnauthorized = parseBoolean(options.smtpRejectUnauthorized, true);
    const dkim = buildDkimConfig(options);
    this.dkim = dkim;

    if (!this.mode) {
      if (smtpUrl || smtpHost) {
        this.mode = "smtp";
      } else {
        this.mode = "disabled";
      }
    }

    if (this.mode === "disabled") {
      this.summary = {
        mode: "disabled",
        configured: false,
        host: null,
        port: null,
        secure: false,
        has_auth: false,
        dkim_enabled: false,
        dkim_domain: null,
        dkim_selector: null
      };
      return;
    }

    if (this.mode === "stream") {
      const config = {
        streamTransport: true,
        newline: "unix",
        buffer: true
      };
      if (dkim) {
        config.dkim = dkim;
      }
      this.transporter = nodemailer.createTransport(config);
      this.summary = {
        mode: "stream",
        configured: true,
        host: "stream",
        port: 0,
        secure: false,
        has_auth: false,
        dkim_enabled: Boolean(dkim),
        dkim_domain: dkim?.domainName || null,
        dkim_selector: dkim?.keySelector || null
      };
      return;
    }

    if (this.mode !== "smtp") {
      throw new LoomError("ENVELOPE_INVALID", `Unsupported email relay mode: ${this.mode}`, 400, {
        relay_mode: this.mode
      });
    }

    if (smtpUrl) {
      this.transporter = dkim
        ? nodemailer.createTransport({
            url: smtpUrl,
            dkim
          })
        : nodemailer.createTransport(smtpUrl);
      this.summary = {
        mode: "smtp",
        configured: true,
        host: "url",
        port: null,
        secure: smtpUrl.startsWith("smtps://"),
        has_auth: true,
        dkim_enabled: Boolean(dkim),
        dkim_domain: dkim?.domainName || null,
        dkim_selector: dkim?.keySelector || null
      };
      return;
    }

    if (!smtpHost) {
      this.mode = "disabled";
      this.summary = {
        mode: "disabled",
        configured: false,
        host: null,
        port: null,
        secure: false,
        has_auth: false,
        dkim_enabled: false,
        dkim_domain: null,
        dkim_selector: null
      };
      return;
    }

    const config = {
      host: smtpHost,
      port: smtpPort,
      secure: smtpSecure,
      requireTLS: smtpRequireTls,
      tls: {
        rejectUnauthorized: smtpRejectUnauthorized
      }
    };

    if (smtpUser || smtpPass) {
      config.auth = {
        user: smtpUser || "",
        pass: smtpPass || ""
      };
    }
    if (dkim) {
      config.dkim = dkim;
    }

    this.transporter = nodemailer.createTransport(config);
    this.summary = {
      mode: "smtp",
      configured: true,
      host: smtpHost,
      port: smtpPort,
      secure: smtpSecure,
      has_auth: Boolean(smtpUser || smtpPass),
      auth_user_hint: redact(smtpUser),
      dkim_enabled: Boolean(dkim),
      dkim_domain: dkim?.domainName || null,
      dkim_selector: dkim?.keySelector || null
    };
  }

  isEnabled() {
    return this.mode !== "disabled" && !!this.transporter;
  }

  getStatus() {
    return {
      ...this.summary,
      enabled: this.isEnabled(),
      default_from: this.defaultFrom
    };
  }

  async send(renderedMessage) {
    if (!this.isEnabled()) {
      throw new LoomError("BRIDGE_DELIVERY_FAILED", "Email relay is not configured", 502, {
        relay_mode: this.mode
      });
    }

    if (!renderedMessage || typeof renderedMessage !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Rendered outbound message must be an object", 400, {
        field: "message"
      });
    }

    const recipients = Array.isArray(renderedMessage.rcpt_to) ? renderedMessage.rcpt_to : [];
    if (recipients.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "Rendered outbound message requires recipients", 400, {
        field: "rcpt_to"
      });
    }

    const mail = {
      from: renderedMessage.smtp_from || this.defaultFrom,
      to: recipients.join(", "),
      subject: renderedMessage.subject || "(no subject)",
      text: renderedMessage.text || "",
      html: renderedMessage.html || undefined,
      headers: renderedMessage.headers || {}
    };
    const attachments = normalizeRenderedAttachments(renderedMessage.attachments);
    if (attachments.length > 0) {
      mail.attachments = attachments;
    }

    if (!mail.from) {
      throw new LoomError("ENVELOPE_INVALID", "SMTP from is required for relay send", 400, {
        field: "smtp_from"
      });
    }

    try {
      const info = await this.transporter.sendMail(mail);
      return {
        provider_message_id: info?.messageId || null,
        accepted: Array.isArray(info?.accepted) ? info.accepted : [],
        rejected: Array.isArray(info?.rejected) ? info.rejected : [],
        response: info?.response || null,
        relay_mode: this.mode
      };
    } catch (error) {
      throw new LoomError("BRIDGE_DELIVERY_FAILED", `Email relay send failed: ${error.message}`, 502, {
        relay_mode: this.mode
      });
    }
  }
}

export function createEmailRelayFromEnv(options = {}) {
  return new LoomEmailRelay({
    mode: options.mode ?? process.env.LOOM_SMTP_MODE,
    defaultFrom: options.defaultFrom ?? process.env.LOOM_SMTP_DEFAULT_FROM ?? null,
    smtpUrl: options.smtpUrl ?? process.env.LOOM_SMTP_URL ?? null,
    smtpHost: options.smtpHost ?? process.env.LOOM_SMTP_HOST ?? null,
    smtpPort: options.smtpPort ?? process.env.LOOM_SMTP_PORT ?? null,
    smtpSecure: options.smtpSecure ?? process.env.LOOM_SMTP_SECURE ?? null,
    smtpUser: options.smtpUser ?? process.env.LOOM_SMTP_USER ?? null,
    smtpPass: options.smtpPass ?? process.env.LOOM_SMTP_PASS ?? null,
    smtpRequireTls: options.smtpRequireTls ?? process.env.LOOM_SMTP_REQUIRE_TLS ?? null,
    smtpRejectUnauthorized:
      options.smtpRejectUnauthorized ?? process.env.LOOM_SMTP_REJECT_UNAUTHORIZED ?? null,
    smtpDkimDomainName: options.smtpDkimDomainName ?? process.env.LOOM_SMTP_DKIM_DOMAIN_NAME ?? null,
    smtpDkimKeySelector: options.smtpDkimKeySelector ?? process.env.LOOM_SMTP_DKIM_KEY_SELECTOR ?? null,
    smtpDkimPrivateKeyPem: options.smtpDkimPrivateKeyPem ?? process.env.LOOM_SMTP_DKIM_PRIVATE_KEY_PEM ?? null,
    smtpDkimPrivateKeyFile: options.smtpDkimPrivateKeyFile ?? process.env.LOOM_SMTP_DKIM_PRIVATE_KEY_FILE ?? null,
    smtpDkimHeaderFieldNames:
      options.smtpDkimHeaderFieldNames ?? process.env.LOOM_SMTP_DKIM_HEADER_FIELD_NAMES ?? null
  });
}
