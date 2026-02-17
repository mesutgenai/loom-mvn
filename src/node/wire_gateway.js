import { createServer as createTcpServer } from "node:net";
import { readFileSync } from "node:fs";
import { createSecureContext, TLSSocket } from "node:tls";

import { LoomError } from "../protocol/errors.js";
import { parseBoolean, parsePositiveInt } from "./env.js";

function isPublicBindHost(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (!normalized) {
    return false;
  }

  if (normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1") {
    return false;
  }

  if (normalized.startsWith("127.")) {
    return false;
  }

  return true;
}

function parseNonNegativeInt(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function readPemFile(path) {
  try {
    return readFileSync(String(path || ""), "utf-8");
  } catch {
    return null;
  }
}

function normalizePem(value) {
  if (value == null) {
    return null;
  }
  const text = String(value);
  if (!text.trim()) {
    return null;
  }
  return text.replace(/\\n/g, "\n");
}

function sanitizeLine(value) {
  return String(value || "").replace(/[\r\n]+/g, " ").trim();
}

function quoteImapString(value) {
  return `"${String(value || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function parseSmtpPathWithParams(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) {
    return {
      address: null,
      parameters: []
    };
  }

  const angleMatch = trimmed.match(/^<([^>]+)>(?:\s+(.*))?$/);
  if (angleMatch) {
    const address = angleMatch[1].trim();
    const parameters = String(angleMatch[2] || "")
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    return {
      address: address || null,
      parameters
    };
  }

  const tokens = trimmed.split(/\s+/).filter(Boolean);
  const address = tokens[0] ? tokens[0].replace(/^<|>$/g, "").trim() : "";
  return {
    address: address || null,
    parameters: tokens.slice(1)
  };
}

function decodeBase64Utf8(value) {
  try {
    return Buffer.from(String(value || ""), "base64").toString("utf-8");
  } catch {
    return "";
  }
}

function extractIdentityFromImapUser(value) {
  const normalized = String(value || "").trim();
  if (!normalized) {
    return null;
  }
  return normalized.startsWith("loom://") ? normalized : null;
}

function extractTokenFromXOAuth2(decoded) {
  const parts = String(decoded || "").split("\u0001").filter(Boolean);
  const values = {};
  for (const part of parts) {
    const idx = part.indexOf("=");
    if (idx <= 0) {
      continue;
    }
    values[part.slice(0, idx).toLowerCase()] = part.slice(idx + 1);
  }

  const rawAuth = values.auth || "";
  const bearerMatch = rawAuth.match(/^bearer\s+(.+)$/i);
  return {
    user: values.user || null,
    token: bearerMatch ? bearerMatch[1].trim() : null
  };
}

function authenticateGatewayToken(store, token, expectedIdentity = null) {
  try {
    const session = store.authenticateAccessToken(token);
    if (expectedIdentity && expectedIdentity !== session.identity) {
      return null;
    }
    return session.identity;
  } catch {
    return null;
  }
}

function parseRfc822(rawMessage) {
  const message = String(rawMessage || "");
  const splitMatch = message.match(/\r?\n\r?\n/);
  const dividerIndex = splitMatch ? splitMatch.index : -1;
  const dividerLength = splitMatch ? splitMatch[0].length : 0;

  const headerBlock = dividerIndex >= 0 ? message.slice(0, dividerIndex) : message;
  const body = dividerIndex >= 0 ? message.slice(dividerIndex + dividerLength) : "";

  const rawHeaderLines = headerBlock.split(/\r?\n/);
  const unfoldedHeaderLines = [];
  for (const line of rawHeaderLines) {
    if (/^[ \t]/.test(line) && unfoldedHeaderLines.length > 0) {
      unfoldedHeaderLines[unfoldedHeaderLines.length - 1] += ` ${line.trim()}`;
    } else if (line.trim().length > 0) {
      unfoldedHeaderLines.push(line);
    }
  }

  const headers = {};
  for (const line of unfoldedHeaderLines) {
    const idx = line.indexOf(":");
    if (idx <= 0) {
      continue;
    }
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!key) {
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(headers, key)) {
      headers[key] = `${headers[key]}, ${value}`;
    } else {
      headers[key] = value;
    }
  }

  return {
    headers,
    body
  };
}

function parseImapAtoms(raw) {
  const input = String(raw || "").trim();
  const parts = [];
  let index = 0;

  while (index < input.length) {
    while (index < input.length && /\s/.test(input[index])) {
      index += 1;
    }
    if (index >= input.length) {
      break;
    }

    if (input[index] === '"') {
      index += 1;
      let token = "";
      while (index < input.length) {
        const ch = input[index];
        if (ch === "\\" && index + 1 < input.length) {
          token += input[index + 1];
          index += 2;
          continue;
        }
        if (ch === '"') {
          index += 1;
          break;
        }
        token += ch;
        index += 1;
      }
      parts.push(token);
      continue;
    }

    if (input[index] === "(") {
      let depth = 0;
      let token = "";
      while (index < input.length) {
        const ch = input[index];
        token += ch;
        if (ch === "(") {
          depth += 1;
        } else if (ch === ")") {
          depth -= 1;
          if (depth === 0) {
            index += 1;
            break;
          }
        }
        index += 1;
      }
      parts.push(token);
      continue;
    }

    const start = index;
    while (index < input.length && !/\s/.test(input[index])) {
      index += 1;
    }
    parts.push(input.slice(start, index));
  }

  return parts;
}

function parseSequenceToken(token, max) {
  const normalized = String(token || "").trim();
  if (!normalized || max <= 0) {
    return [];
  }

  const ids = new Set();
  const segments = normalized.split(",");
  for (const segmentRaw of segments) {
    const segment = segmentRaw.trim();
    if (!segment) {
      continue;
    }

    const resolveValue = (value) => {
      const trimmed = String(value || "").trim();
      if (trimmed === "*") {
        return max;
      }
      const parsed = Number(trimmed);
      return Number.isInteger(parsed) ? parsed : null;
    };

    if (segment.includes(":")) {
      const [startToken, endToken] = segment.split(":", 2);
      const start = resolveValue(startToken);
      const end = resolveValue(endToken);
      if (!start || !end) {
        continue;
      }
      const step = start <= end ? 1 : -1;
      for (let current = start; step > 0 ? current <= end : current >= end; current += step) {
        if (current >= 1 && current <= max) {
          ids.add(current);
        }
      }
      continue;
    }

    const single = resolveValue(segment);
    if (single && single >= 1 && single <= max) {
      ids.add(single);
    }
  }

  return Array.from(ids).sort((a, b) => a - b);
}

function identityToEmail(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return null;
  }
  if (raw.startsWith("loom://")) {
    return raw.slice("loom://".length);
  }
  if (raw.startsWith("bridge://")) {
    return raw.slice("bridge://".length);
  }
  if (raw.includes("@")) {
    return raw;
  }
  return null;
}

function renderImapRfc822(message) {
  const fromValue = identityToEmail(message.from_email || message.from) || "unknown@loom.local";
  const toValues = Array.isArray(message.to)
    ? message.to.map((recipient) => identityToEmail(recipient)).filter(Boolean)
    : [];

  const headers = [
    `Date: ${new Date(message.date || Date.now()).toUTCString()}`,
    `From: ${fromValue}`,
    `To: ${toValues.length > 0 ? toValues.join(", ") : "undisclosed-recipients:;"}`,
    `Subject: ${sanitizeLine(message.subject || "(no subject)")}`,
    `Message-ID: <${sanitizeLine(message.message_id || `${message.envelope_id}@loom.local`).replace(/[<>]/g, "")}>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: 8bit"
  ];

  if (message.in_reply_to) {
    headers.splice(4, 0, `In-Reply-To: <${sanitizeLine(message.in_reply_to).replace(/[<>]/g, "")}>`);
  }

  const body = String(message.body_text || "");
  return `${headers.join("\r\n")}\r\n\r\n${body}`;
}

function imapFlagsForMessage(message) {
  const flags = [];
  if (message.mailbox_state?.seen) {
    flags.push("\\Seen");
  }
  if (message.mailbox_state?.flagged) {
    flags.push("\\Flagged");
  }
  if (message.mailbox_state?.deleted) {
    flags.push("\\Deleted");
  }
  return flags;
}

function parseImapFlagList(rawFlags) {
  const text = String(rawFlags || "").toUpperCase();
  return {
    seen: text.includes("\\SEEN"),
    flagged: text.includes("\\FLAGGED"),
    deleted: text.includes("\\DELETED")
  };
}

function resolveMailboxMovePatch(store, destinationMailbox) {
  const normalized = store.normalizeGatewayFolderName(destinationMailbox);
  switch (normalized) {
    case "INBOX":
      return {
        archived: false,
        deleted: false
      };
    case "Archive":
      return {
        archived: true,
        deleted: false
      };
    case "Trash":
      return {
        archived: false,
        deleted: true
      };
    default:
      return null;
  }
}

function evaluateImapSearchCriteria(message, criteriaTokens) {
  const flags = {
    seen: Boolean(message.mailbox_state?.seen),
    flagged: Boolean(message.mailbox_state?.flagged),
    deleted: Boolean(message.mailbox_state?.deleted)
  };

  if (!Array.isArray(criteriaTokens) || criteriaTokens.length === 0) {
    return true;
  }

  for (let index = 0; index < criteriaTokens.length; index += 1) {
    const token = String(criteriaTokens[index] || "").toUpperCase();
    switch (token) {
      case "":
      case "ALL":
        break;
      case "SEEN":
        if (!flags.seen) {
          return false;
        }
        break;
      case "UNSEEN":
        if (flags.seen) {
          return false;
        }
        break;
      case "FLAGGED":
        if (!flags.flagged) {
          return false;
        }
        break;
      case "UNFLAGGED":
        if (flags.flagged) {
          return false;
        }
        break;
      case "DELETED":
        if (!flags.deleted) {
          return false;
        }
        break;
      case "UNDELETED":
        if (flags.deleted) {
          return false;
        }
        break;
      case "RECENT":
      case "OLD":
      case "ANSWERED":
      case "UNANSWERED":
      case "DRAFT":
      case "UNDRAFT":
        // Not yet mapped to LOOM message model.
        break;
      case "CHARSET":
        index += 1;
        break;
      case "SINCE":
      case "BEFORE":
      case "ON":
      case "SENTSINCE":
      case "SENTBEFORE":
      case "SENTON":
      case "FROM":
      case "TO":
      case "CC":
      case "BCC":
      case "SUBJECT":
      case "BODY":
      case "TEXT":
      case "KEYWORD":
      case "UNKEYWORD":
      case "HEADER":
      case "LARGER":
      case "SMALLER":
      case "UID":
        // Skip the next token for operators that take one argument.
        index += 1;
        break;
      case "OR":
      case "NOT":
        // Minimal parser does not implement boolean group operators.
        break;
      default:
        // Treat unknown criteria as non-fatal and continue.
        break;
    }
  }

  return true;
}

function buildImapFetchResponse(message, sequence, fetchSpec = "") {
  const fullRaw = renderImapRfc822(message);
  const fullSize = Buffer.byteLength(fullRaw, "utf-8");
  const upperSpec = String(fetchSpec || "").toUpperCase();
  let bodyLabel = "BODY[]";
  let raw = fullRaw;

  if (upperSpec.includes("BODY.PEEK[HEADER]") || upperSpec.includes("BODY[HEADER]")) {
    const headerSplit = fullRaw.match(/\r?\n\r?\n/);
    const dividerIndex = headerSplit ? headerSplit.index : -1;
    const dividerLength = headerSplit ? headerSplit[0].length : 0;
    raw =
      dividerIndex >= 0
        ? `${fullRaw.slice(0, dividerIndex)}\r\n\r\n`
        : `${fullRaw.slice(0, fullRaw.length)}\r\n\r\n`;
    bodyLabel = "BODY[HEADER]";
  } else if (upperSpec.includes("BODY.PEEK[TEXT]") || upperSpec.includes("BODY[TEXT]")) {
    const headerSplit = fullRaw.match(/\r?\n\r?\n/);
    const dividerIndex = headerSplit ? headerSplit.index : -1;
    const dividerLength = headerSplit ? headerSplit[0].length : 0;
    raw = dividerIndex >= 0 ? fullRaw.slice(dividerIndex + dividerLength) : fullRaw;
    bodyLabel = "BODY[TEXT]";
  }

  const size = Buffer.byteLength(raw, "utf-8");
  const flags = imapFlagsForMessage(message).join(" ");
  return {
    line: `* ${sequence} FETCH (UID ${message.uid} FLAGS (${flags}) RFC822.SIZE ${fullSize} ${bodyLabel} {${size}}`,
    raw
  };
}

async function upgradeSocketToTls(socket, secureContext) {
  const tlsSocket = new TLSSocket(socket, {
    isServer: true,
    secureContext
  });

  await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error = null) => {
      if (settled) {
        return;
      }
      settled = true;
      tlsSocket.off("secure", onSecure);
      tlsSocket.off("error", onError);
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    };

    const onSecure = () => finish();
    const onError = (error) => finish(error);
    tlsSocket.once("secure", onSecure);
    tlsSocket.once("error", onError);
  });

  return tlsSocket;
}

function createLineSocket(socket, onLine, options = {}) {
  const maxBufferBytes = parsePositiveInt(options.maxBufferBytes, 128 * 1024);
  const maxLineBytes = parsePositiveInt(options.maxLineBytes, 32 * 1024);
  const onBufferOverflow = typeof options.onBufferOverflow === "function" ? options.onBufferOverflow : null;
  const onLineTooLong = typeof options.onLineTooLong === "function" ? options.onLineTooLong : null;
  let buffer = "";
  socket.setEncoding("utf-8");
  const onData = (chunk) => {
    buffer += chunk;
    if (Buffer.byteLength(buffer, "utf-8") > maxBufferBytes && buffer.indexOf("\n") === -1) {
      onBufferOverflow?.();
      if (!socket.destroyed) {
        socket.destroy();
      }
      return;
    }

    let index = buffer.indexOf("\n");
    while (index >= 0) {
      const rawLine = buffer.slice(0, index).replace(/\r$/, "");
      buffer = buffer.slice(index + 1);
      if (Buffer.byteLength(rawLine, "utf-8") > maxLineBytes) {
        onLineTooLong?.();
        if (!socket.destroyed) {
          socket.destroy();
        }
        return;
      }
      Promise.resolve(onLine(rawLine)).catch(() => {});
      index = buffer.indexOf("\n");
    }

    if (Buffer.byteLength(buffer, "utf-8") > maxBufferBytes) {
      onBufferOverflow?.();
      if (!socket.destroyed) {
        socket.destroy();
      }
    }
  };
  socket.on("data", onData);

  return () => {
    socket.off("data", onData);
  };
}

function createSmtpGatewayServer(options) {
  const {
    store,
    host,
    port,
    requireAuth = true,
    allowInsecureAuth = false,
    maxMessageBytes = 10 * 1024 * 1024,
    lineMaxBytes = 32 * 1024,
    lineBufferMaxBytes = 128 * 1024,
    idleTimeoutMs = 2 * 60 * 1000,
    maxAuthFailures = 5,
    startTlsEnabled = false,
    tlsContext = null
  } = options;
  const requireSecureAuth = requireAuth && !allowInsecureAuth;

  const server = createTcpServer((socket) => {
    const state = {
      secure: false,
      helo: false,
      authIdentity: null,
      transaction: {
        mailFrom: null,
        rcptTo: []
      },
      dataMode: false,
      dataLines: [],
      dataBytes: 0,
      authLoginStage: null,
      authLoginUser: null,
      authFailures: 0
    };
    let activeSocket = socket;
    let detachLineReader = () => {};

    const configureSocketTimeout = () => {
      if (!Number.isFinite(idleTimeoutMs) || idleTimeoutMs <= 0) {
        activeSocket.setTimeout(0);
        return;
      }
      activeSocket.setTimeout(idleTimeoutMs);
      activeSocket.once("timeout", () => {
        writeLine("421 4.4.2 idle timeout");
        activeSocket.end();
      });
    };

    const attachLineReader = () => {
      detachLineReader();
      detachLineReader = createLineSocket(activeSocket, handleLine, {
        maxBufferBytes: lineBufferMaxBytes,
        maxLineBytes: lineMaxBytes,
        onBufferOverflow: () => {
          writeLine("500 5.5.2 line buffer limit exceeded");
        },
        onLineTooLong: () => {
          writeLine("500 5.5.2 line too long");
        }
      });
    };

    const writeLine = (line) => {
      activeSocket.write(`${line}\r\n`);
    };

    const resetTransaction = () => {
      state.transaction = {
        mailFrom: null,
        rcptTo: []
      };
      state.dataMode = false;
      state.dataLines = [];
      state.dataBytes = 0;
    };

    const recordAuthFailure = () => {
      state.authFailures += 1;
      if (state.authFailures >= Math.max(1, maxAuthFailures)) {
        writeLine("421 4.7.0 too many authentication failures");
        activeSocket.end();
      }
    };

    const advertiseEhlo = () => {
      const capabilities = [];
      if (!requireSecureAuth || state.secure) {
        capabilities.push("AUTH PLAIN LOGIN XOAUTH2");
      }
      if (startTlsEnabled && tlsContext && !state.secure) {
        capabilities.push("STARTTLS");
      }
      capabilities.push(`SIZE ${maxMessageBytes}`);

      writeLine(`250-${host}`);
      for (let index = 0; index < capabilities.length; index += 1) {
        const capability = capabilities[index];
        const isLast = index === capabilities.length - 1;
        writeLine(`${isLast ? "250 " : "250-"}${capability}`);
      }
    };

    const completeData = () => {
      const rawMessage = state.dataLines.join("\r\n");
      if (Buffer.byteLength(rawMessage, "utf-8") > maxMessageBytes) {
        resetTransaction();
        writeLine("552 Message exceeds maximum configured size");
        return;
      }

      try {
        const parsed = parseRfc822(rawMessage);
        const submissionIdentity = state.authIdentity || "bridge://anonymous@loom.local";
        const result = store.submitGatewaySmtp(
          {
            to: state.transaction.rcptTo,
            from: state.transaction.mailFrom,
            subject: parsed.headers.Subject || "(no subject)",
            text: parsed.body,
            headers: parsed.headers,
            date: parsed.headers.Date,
            message_id: parsed.headers["Message-ID"] || parsed.headers["Message-Id"],
            in_reply_to: parsed.headers["In-Reply-To"],
            references: parsed.headers.References
          },
          submissionIdentity
        );
        resetTransaction();
        writeLine(`250 2.0.0 accepted; envelope=${result.envelope_id}`);
      } catch (error) {
        resetTransaction();
        if (error instanceof LoomError) {
          if (error.status === 403) {
            writeLine("550 5.7.1 not authorized");
            return;
          }
          if (error.status === 400) {
            writeLine("501 5.5.2 invalid message");
            return;
          }
        }
        writeLine("451 4.3.0 unable to process message");
      }
    };

    const handleAuth = (rawArgs) => {
      if (requireSecureAuth && !state.secure) {
        state.authLoginStage = null;
        state.authLoginUser = null;
        writeLine("538 5.7.11 Encryption required for requested authentication mechanism");
        return;
      }

      const args = parseImapAtoms(rawArgs);
      const mechanism = String(args[0] || "").toUpperCase();
      const initialResponse = args[1] || null;

      if (!mechanism) {
        writeLine("504 5.5.4 authentication mechanism required");
        return;
      }

      if (mechanism === "PLAIN") {
        if (!initialResponse) {
          state.authLoginStage = "plain";
          writeLine("334 ");
          return;
        }
        const decoded = decodeBase64Utf8(initialResponse);
        const parts = decoded.split("\u0000");
        const username = parts.length > 1 ? parts[1] : null;
        const token = parts.length > 2 ? parts[2] : null;
        const expectedIdentity = extractIdentityFromImapUser(username);
        const identity = authenticateGatewayToken(store, token, expectedIdentity);
        if (!identity) {
          writeLine("535 5.7.8 authentication failed");
          recordAuthFailure();
          return;
        }
        state.authIdentity = identity;
        state.authFailures = 0;
        writeLine("235 2.7.0 authentication successful");
        return;
      }

      if (mechanism === "LOGIN") {
        if (initialResponse) {
          state.authLoginUser = decodeBase64Utf8(initialResponse).trim();
          state.authLoginStage = "login_password";
          writeLine("334 UGFzc3dvcmQ6");
          return;
        }
        state.authLoginStage = "login_user";
        writeLine("334 VXNlcm5hbWU6");
        return;
      }

      if (mechanism === "XOAUTH2") {
        if (!initialResponse) {
          writeLine("334 ");
          return;
        }
        const decoded = decodeBase64Utf8(initialResponse);
        const payload = extractTokenFromXOAuth2(decoded);
        const expectedIdentity = extractIdentityFromImapUser(payload.user);
        const identity = authenticateGatewayToken(store, payload.token, expectedIdentity);
        if (!identity) {
          writeLine("535 5.7.8 authentication failed");
          recordAuthFailure();
          return;
        }
        state.authIdentity = identity;
        state.authFailures = 0;
        writeLine("235 2.7.0 authentication successful");
        return;
      }

      writeLine("504 5.5.4 unsupported auth mechanism");
    };

    const startTls = async () => {
      if (!startTlsEnabled || !tlsContext) {
        writeLine("454 4.7.0 TLS not available");
        return;
      }
      if (state.secure) {
        writeLine("503 5.5.1 TLS already active");
        return;
      }
      if (state.dataMode || state.authLoginStage) {
        writeLine("503 5.5.1 Bad sequence of commands");
        return;
      }

      writeLine("220 2.0.0 Ready to start TLS");
      detachLineReader();
      try {
        activeSocket = await upgradeSocketToTls(activeSocket, tlsContext);
        configureSocketTimeout();
        state.secure = true;
        state.helo = false;
        state.authIdentity = null;
        state.authLoginStage = null;
        state.authLoginUser = null;
        resetTransaction();
        attachLineReader();
      } catch {
        activeSocket.destroy();
      }
    };

    const handleLine = async (line) => {
      if (state.dataMode) {
        if (line === ".") {
          completeData();
          return;
        }
        const nextLine = line.startsWith("..") ? line.slice(1) : line;
        state.dataBytes += Buffer.byteLength(nextLine, "utf-8") + 2;
        if (state.dataBytes > maxMessageBytes) {
          resetTransaction();
          writeLine("552 Message exceeds maximum configured size");
          return;
        }
        state.dataLines.push(nextLine);
        return;
      }

      if (state.authLoginStage === "plain") {
        if (requireSecureAuth && !state.secure) {
          state.authLoginStage = null;
          state.authLoginUser = null;
          writeLine("538 5.7.11 Encryption required for requested authentication mechanism");
          return;
        }
        state.authLoginStage = null;
        handleAuth(`PLAIN ${line}`);
        return;
      }

      if (state.authLoginStage === "login_user") {
        if (requireSecureAuth && !state.secure) {
          state.authLoginStage = null;
          state.authLoginUser = null;
          writeLine("538 5.7.11 Encryption required for requested authentication mechanism");
          return;
        }
        state.authLoginStage = "login_password";
        state.authLoginUser = decodeBase64Utf8(line).trim();
        writeLine("334 UGFzc3dvcmQ6");
        return;
      }

      if (state.authLoginStage === "login_password") {
        if (requireSecureAuth && !state.secure) {
          state.authLoginStage = null;
          state.authLoginUser = null;
          writeLine("538 5.7.11 Encryption required for requested authentication mechanism");
          return;
        }
        state.authLoginStage = null;
        const token = decodeBase64Utf8(line).trim();
        const expectedIdentity = extractIdentityFromImapUser(state.authLoginUser);
        const identity = authenticateGatewayToken(store, token, expectedIdentity);
        state.authLoginUser = null;
        if (!identity) {
          writeLine("535 5.7.8 authentication failed");
          recordAuthFailure();
          return;
        }
        state.authIdentity = identity;
        state.authFailures = 0;
        writeLine("235 2.7.0 authentication successful");
        return;
      }

      const commandMatch = line.match(/^([A-Za-z]+)(?:\s+(.*))?$/);
      if (!commandMatch) {
        writeLine("500 5.5.2 command not recognized");
        return;
      }

      const command = commandMatch[1].toUpperCase();
      const rawArgs = commandMatch[2] || "";

      if (command === "EHLO" || command === "HELO") {
        state.helo = true;
        advertiseEhlo();
        return;
      }

      if (command === "NOOP") {
        writeLine("250 2.0.0 ok");
        return;
      }

      if (command === "QUIT") {
        writeLine("221 2.0.0 bye");
        activeSocket.end();
        return;
      }

      if (command === "RSET") {
        resetTransaction();
        writeLine("250 2.0.0 state reset");
        return;
      }

      if (command === "STARTTLS") {
        await startTls();
        return;
      }

      if (command === "AUTH") {
        if (requireSecureAuth && !state.secure) {
          writeLine("538 5.7.11 Encryption required for requested authentication mechanism");
          return;
        }
        handleAuth(rawArgs);
        return;
      }

      if (!state.helo) {
        writeLine("503 5.5.1 send HELO/EHLO first");
        return;
      }

      if (requireAuth && !state.authIdentity) {
        writeLine("530 5.7.0 authentication required");
        return;
      }

      if (command === "MAIL") {
        const fromMatch = rawArgs.match(/^FROM:\s*(.+)$/i);
        if (!fromMatch) {
          writeLine("501 5.5.2 MAIL requires FROM:<address>");
          return;
        }
        const from = parseSmtpPathWithParams(fromMatch[1]);
        if (from.parameters.some((parameter) => String(parameter).trim().toUpperCase() === "SMTPUTF8")) {
          writeLine("504 5.5.4 SMTPUTF8 not supported");
          return;
        }
        const fromAddress = from.address;
        if (!fromAddress) {
          writeLine("501 5.5.2 invalid sender");
          return;
        }
        state.transaction.mailFrom = fromAddress;
        state.transaction.rcptTo = [];
        writeLine("250 2.1.0 sender ok");
        return;
      }

      if (command === "RCPT") {
        if (!state.transaction.mailFrom) {
          writeLine("503 5.5.1 MAIL FROM required");
          return;
        }
        const toMatch = rawArgs.match(/^TO:\s*(.+)$/i);
        if (!toMatch) {
          writeLine("501 5.5.2 RCPT requires TO:<address>");
          return;
        }
        const to = parseSmtpPathWithParams(toMatch[1]);
        if (to.parameters.some((parameter) => String(parameter).trim().toUpperCase() === "SMTPUTF8")) {
          writeLine("504 5.5.4 SMTPUTF8 not supported");
          return;
        }
        const recipient = to.address;
        if (!recipient) {
          writeLine("501 5.5.2 invalid recipient");
          return;
        }
        state.transaction.rcptTo.push(recipient);
        writeLine("250 2.1.5 recipient ok");
        return;
      }

      if (command === "DATA") {
        if (!state.transaction.mailFrom || state.transaction.rcptTo.length === 0) {
          writeLine("503 5.5.1 MAIL FROM and RCPT TO required");
          return;
        }
        state.dataMode = true;
        state.dataLines = [];
        state.dataBytes = 0;
        writeLine("354 End data with <CR><LF>.<CR><LF>");
        return;
      }

      writeLine("502 5.5.1 command not implemented");
    };

    writeLine("220 LOOM SMTP Gateway ready");
    configureSocketTimeout();
    attachLineReader();
  });

  return {
    name: "smtp",
    server,
    host,
    port
  };
}

function createImapGatewayServer(options) {
  const {
    store,
    host,
    port,
    requireAuth = true,
    allowInsecureAuth = false,
    lineMaxBytes = 32 * 1024,
    lineBufferMaxBytes = 128 * 1024,
    idleTimeoutMs = 2 * 60 * 1000,
    maxAuthFailures = 5,
    startTlsEnabled = false,
    tlsContext = null
  } = options;
  const requireSecureAuth = requireAuth && !allowInsecureAuth;

  const server = createTcpServer((socket) => {
    const state = {
      secure: false,
      authIdentity: null,
      selectedFolder: null,
      selectedMessages: [],
      readOnly: false,
      idleTag: null,
      authFailures: 0
    };
    let activeSocket = socket;
    let detachLineReader = () => {};

    const configureSocketTimeout = () => {
      if (!Number.isFinite(idleTimeoutMs) || idleTimeoutMs <= 0) {
        activeSocket.setTimeout(0);
        return;
      }
      activeSocket.setTimeout(idleTimeoutMs);
      activeSocket.once("timeout", () => {
        writeLine("* BYE idle timeout");
        activeSocket.end();
      });
    };

    const writeLine = (line) => {
      activeSocket.write(`${line}\r\n`);
    };

    const attachLineReader = () => {
      detachLineReader();
      detachLineReader = createLineSocket(activeSocket, handleLine, {
        maxBufferBytes: lineBufferMaxBytes,
        maxLineBytes: lineMaxBytes,
        onBufferOverflow: () => {
          writeLine("* BAD line buffer limit exceeded");
        },
        onLineTooLong: () => {
          writeLine("* BAD line too long");
        }
      });
    };

    const recordAuthFailure = () => {
      state.authFailures += 1;
      if (state.authFailures >= Math.max(1, maxAuthFailures)) {
        writeLine("* BYE too many authentication failures");
        activeSocket.end();
      }
    };

    const capabilityTokens = () => {
      const caps = ["IMAP4rev1", "UIDPLUS", "NAMESPACE", "ID"];
      if (!requireSecureAuth || state.secure) {
        caps.push("AUTH=PLAIN", "AUTH=LOGIN");
      } else {
        caps.push("LOGINDISABLED");
      }
      if (startTlsEnabled && tlsContext && !state.secure && !state.authIdentity) {
        caps.push("STARTTLS");
      }
      return caps.join(" ");
    };

    const requireAuthenticated = (tag) => {
      if (!state.authIdentity) {
        writeLine(`${tag} NO Authentication required`);
        return false;
      }
      return true;
    };

    const refreshSelectedMessages = () => {
      if (!state.selectedFolder) {
        state.selectedMessages = [];
        return;
      }
      state.selectedMessages = store.listGatewayImapMessages(state.selectedFolder, state.authIdentity, 1000);
    };

    const setSelection = (folder, readOnly = false) => {
      state.selectedFolder = folder;
      state.readOnly = readOnly;
      refreshSelectedMessages();
    };

    const clearSelection = () => {
      state.selectedFolder = null;
      state.selectedMessages = [];
      state.readOnly = false;
    };

    const emitFetchForMessage = (sequence, message, fetchSpec = "") => {
      const response = buildImapFetchResponse(message, sequence, fetchSpec);
      writeLine(response.line);
      activeSocket.write(`${response.raw}\r\n`);
      writeLine(")");
    };

    const applyStoreToMessage = (message, mode, flags) => {
      const current = {
        seen: Boolean(message.mailbox_state?.seen),
        flagged: Boolean(message.mailbox_state?.flagged),
        deleted: Boolean(message.mailbox_state?.deleted)
      };

      const patch =
        mode === "set"
          ? {
              seen: flags.seen,
              flagged: flags.flagged,
              deleted: flags.deleted
            }
          : mode === "add"
            ? {
                seen: current.seen || flags.seen,
                flagged: current.flagged || flags.flagged,
                deleted: current.deleted || flags.deleted
              }
            : {
                seen: current.seen && !flags.seen,
                flagged: current.flagged && !flags.flagged,
                deleted: current.deleted && !flags.deleted
              };

      const updated = store.updateThreadMailboxState(message.thread_id, state.authIdentity, patch);
      message.mailbox_state = {
        ...message.mailbox_state,
        seen: updated.seen,
        flagged: updated.flagged,
        deleted: updated.deleted
      };
      return message;
    };

    const runSearch = (criteriaTokens, useUid = false) => {
      const values = [];
      for (let index = 0; index < state.selectedMessages.length; index += 1) {
        const message = state.selectedMessages[index];
        if (!evaluateImapSearchCriteria(message, criteriaTokens)) {
          continue;
        }
        values.push(useUid ? Number(message.uid || index + 1) : index + 1);
      }
      writeLine(`* SEARCH${values.length > 0 ? ` ${values.join(" ")}` : ""}`);
    };

    const moveMessages = (messages, destinationMailbox) => {
      const patch = resolveMailboxMovePatch(store, destinationMailbox);
      if (!patch) {
        return {
          ok: false,
          reason: "unsupported_destination"
        };
      }

      for (const message of messages) {
        store.updateThreadMailboxState(message.thread_id, state.authIdentity, patch);
        message.mailbox_state = {
          ...message.mailbox_state,
          seen: patch.seen ?? message.mailbox_state?.seen,
          flagged: patch.flagged ?? message.mailbox_state?.flagged,
          archived: patch.archived,
          deleted: patch.deleted
        };
      }

      refreshSelectedMessages();
      return {
        ok: true
      };
    };

    const appendMessageToMailbox = (mailbox, rawMessage) => {
      if (!state.authIdentity) {
        throw new LoomError("CAPABILITY_DENIED", "Authentication required", 403, {
          action: "imap_append"
        });
      }

      const parsed = parseRfc822(rawMessage);
      const result = store.submitGatewaySmtp(
        {
          to: parsed.headers.To || identityToEmail(state.authIdentity) || "undisclosed@loom.local",
          cc: parsed.headers.Cc || null,
          bcc: parsed.headers.Bcc || null,
          subject: parsed.headers.Subject || "(no subject)",
          text: parsed.body || "",
          headers: parsed.headers,
          date: parsed.headers.Date,
          message_id: parsed.headers["Message-ID"] || parsed.headers["Message-Id"],
          in_reply_to: parsed.headers["In-Reply-To"],
          references: parsed.headers.References
        },
        state.authIdentity
      );

      const normalizedMailbox = store.normalizeGatewayFolderName(mailbox);
      if (normalizedMailbox === "Drafts") {
        store.ensureThreadLabel(result.thread_id, "sys.drafts");
      } else if (normalizedMailbox === "Archive" || normalizedMailbox === "Trash" || normalizedMailbox === "INBOX") {
        const patch = resolveMailboxMovePatch(store, normalizedMailbox);
        if (patch) {
          store.updateThreadMailboxState(result.thread_id, state.authIdentity, patch);
        }
      }

      if (state.selectedFolder) {
        refreshSelectedMessages();
      }

      return result;
    };

    const startTls = async (tag) => {
      if (!startTlsEnabled || !tlsContext) {
        writeLine(`${tag} NO STARTTLS not available`);
        return;
      }
      if (state.secure) {
        writeLine(`${tag} BAD TLS already active`);
        return;
      }
      if (state.authIdentity || state.selectedFolder) {
        writeLine(`${tag} BAD STARTTLS only allowed before authentication`);
        return;
      }

      writeLine(`${tag} OK Begin TLS negotiation now`);
      detachLineReader();
      try {
        activeSocket = await upgradeSocketToTls(activeSocket, tlsContext);
        state.secure = true;
        configureSocketTimeout();
        attachLineReader();
      } catch {
        activeSocket.destroy();
      }
    };

    const handleLine = async (line) => {
      if (state.idleTag) {
        if (String(line || "").trim().toUpperCase() === "DONE") {
          const idleTag = state.idleTag;
          state.idleTag = null;
          writeLine(`${idleTag} OK IDLE completed`);
          return;
        }
        writeLine("+ idling");
        return;
      }

      const match = line.match(/^(\S+)\s+([A-Za-z]+)(?:\s+(.*))?$/);
      if (!match) {
        writeLine("* BAD malformed command");
        return;
      }

      const tag = match[1];
      const command = match[2].toUpperCase();
      const rawArgs = match[3] || "";

      if (command === "CAPABILITY") {
        writeLine(`* CAPABILITY ${capabilityTokens()}`);
        writeLine(`${tag} OK CAPABILITY completed`);
        return;
      }

      if (command === "ID") {
        writeLine('* ID ("name" "loom-wire-gateway" "version" "0.1.0")');
        writeLine(`${tag} OK ID completed`);
        return;
      }

      if (command === "NAMESPACE") {
        writeLine('* NAMESPACE (("" "/")) NIL NIL');
        writeLine(`${tag} OK NAMESPACE completed`);
        return;
      }

      if (command === "NOOP") {
        writeLine(`${tag} OK NOOP completed`);
        return;
      }

      if (command === "LOGOUT") {
        writeLine("* BYE LOOM IMAP Gateway logging out");
        writeLine(`${tag} OK LOGOUT completed`);
        activeSocket.end();
        return;
      }

      if (command === "STARTTLS") {
        await startTls(tag);
        return;
      }

      if (command === "LOGIN") {
        if (requireSecureAuth && !state.secure) {
          writeLine(`${tag} NO [PRIVACYREQUIRED] TLS required before authentication`);
          return;
        }
        const args = parseImapAtoms(rawArgs);
        const username = args[0] || "";
        const token = args[1] || "";
        const expectedIdentity = extractIdentityFromImapUser(username);
        const identity = authenticateGatewayToken(store, token, expectedIdentity);
        if (!identity) {
          writeLine(`${tag} NO Authentication failed`);
          recordAuthFailure();
          return;
        }
        state.authIdentity = identity;
        state.authFailures = 0;
        writeLine(`${tag} OK LOGIN completed`);
        return;
      }

      if (command === "AUTHENTICATE") {
        if (requireSecureAuth && !state.secure) {
          writeLine(`${tag} NO [PRIVACYREQUIRED] TLS required before authentication`);
          return;
        }
        const args = parseImapAtoms(rawArgs);
        const mechanism = String(args[0] || "").toUpperCase();
        const initial = args[1] || "";

        if (mechanism === "PLAIN") {
          const decoded = decodeBase64Utf8(initial);
          const parts = decoded.split("\u0000");
          const username = parts.length > 1 ? parts[1] : null;
          const token = parts.length > 2 ? parts[2] : null;
          const expectedIdentity = extractIdentityFromImapUser(username);
          const identity = authenticateGatewayToken(store, token, expectedIdentity);
          if (!identity) {
            writeLine(`${tag} NO Authentication failed`);
            recordAuthFailure();
            return;
          }
          state.authIdentity = identity;
          state.authFailures = 0;
          writeLine(`${tag} OK AUTHENTICATE completed`);
          return;
        }

        writeLine(`${tag} NO Unsupported auth mechanism`);
        return;
      }

      if (requireAuth && !requireAuthenticated(tag)) {
        return;
      }

      if (command === "APPEND") {
        if (state.readOnly) {
          writeLine(`${tag} NO Mailbox is read-only`);
          return;
        }

        const args = parseImapAtoms(rawArgs);
        const mailbox = args[0] || state.selectedFolder || "INBOX";
        const payload = args.slice(1);
        if (payload.length === 0) {
          writeLine(`${tag} BAD APPEND requires mailbox and message data`);
          return;
        }

        if (payload[payload.length - 1].match(/^\{\d+\}$/)) {
          writeLine(`${tag} NO APPEND literal syntax is not supported`);
          return;
        }

        const rawMessage = payload.join(" ");
        try {
          appendMessageToMailbox(mailbox, rawMessage);
          writeLine(`${tag} OK APPEND completed`);
        } catch (error) {
          if (error instanceof LoomError && error.status === 403) {
            writeLine(`${tag} NO Authentication required`);
            return;
          }
          writeLine(`${tag} NO APPEND failed`);
        }
        return;
      }

      if (command === "LIST" || command === "LSUB" || command === "XLIST") {
        const folders = store.listGatewayImapFolders(state.authIdentity);
        for (const folder of folders) {
          writeLine(`* ${command === "LSUB" ? "LSUB" : "LIST"} (\\HasNoChildren) "/" ${quoteImapString(folder.name)}`);
        }
        writeLine(`${tag} OK ${command} completed`);
        return;
      }

      if (command === "STATUS") {
        const args = parseImapAtoms(rawArgs);
        const folder = args[0] || "INBOX";
        const fields = String(args[1] || "(MESSAGES)")
          .replace(/[()]/g, " ")
          .split(/\s+/)
          .map((value) => value.trim().toUpperCase())
          .filter(Boolean);

        const messages = store.listGatewayImapMessages(folder, state.authIdentity, 1000);
        const unseen = messages.filter((message) => !message.mailbox_state?.seen).length;
        const maxUid = messages.reduce((current, message) => Math.max(current, Number(message.uid || 0)), 0);
        const stats = {
          MESSAGES: messages.length,
          UNSEEN: unseen,
          UIDNEXT: maxUid + 1,
          UIDVALIDITY: 1,
          RECENT: 0
        };

        const parts = (fields.length > 0 ? fields : ["MESSAGES"])
          .map((field) => `${field} ${stats[field] ?? 0}`);
        writeLine(`* STATUS ${quoteImapString(folder)} (${parts.join(" ")})`);
        writeLine(`${tag} OK STATUS completed`);
        return;
      }

      if (command === "SELECT" || command === "EXAMINE") {
        const args = parseImapAtoms(rawArgs);
        const folder = args[0] || "INBOX";
        setSelection(folder, command === "EXAMINE");
        const exists = state.selectedMessages.length;
        const maxUid = state.selectedMessages.reduce((current, message) => Math.max(current, Number(message.uid || 0)), 0);

        writeLine(`* ${exists} EXISTS`);
        writeLine("* 0 RECENT");
        writeLine("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)");
        writeLine("* OK [PERMANENTFLAGS (\\Seen \\Flagged \\Deleted)]");
        writeLine("* OK [UIDVALIDITY 1]");
        writeLine(`* OK [UIDNEXT ${maxUid + 1}]`);
        writeLine(`${tag} OK [${command === "EXAMINE" ? "READ-ONLY" : "READ-WRITE"}] ${command} completed`);
        return;
      }

      if (command === "CHECK") {
        writeLine(`${tag} OK CHECK completed`);
        return;
      }

      if (command === "CLOSE" || command === "UNSELECT") {
        clearSelection();
        writeLine(`${tag} OK ${command} completed`);
        return;
      }

      if (!state.selectedFolder) {
        writeLine(`${tag} NO Select a mailbox first`);
        return;
      }

      if (command === "IDLE") {
        state.idleTag = tag;
        writeLine("+ idling");
        return;
      }

      if (command === "SEARCH") {
        const args = parseImapAtoms(rawArgs);
        runSearch(args, false);
        writeLine(`${tag} OK SEARCH completed`);
        return;
      }

      if (command === "FETCH") {
        const args = parseImapAtoms(rawArgs);
        const sequenceSet = args[0] || "1:*";
        const fetchSpec = args.slice(1).join(" ");
        const sequences = parseSequenceToken(sequenceSet, state.selectedMessages.length);
        for (const sequence of sequences) {
          const message = state.selectedMessages[sequence - 1];
          if (!message) {
            continue;
          }
          emitFetchForMessage(sequence, message, fetchSpec);
        }
        writeLine(`${tag} OK FETCH completed`);
        return;
      }

      if (command === "STORE") {
        const args = parseImapAtoms(rawArgs);
        const sequenceSet = args[0] || "";
        const modeToken = String(args[1] || "").toUpperCase();
        const mode = modeToken.startsWith("+") ? "add" : modeToken.startsWith("-") ? "remove" : "set";
        const silent = modeToken.includes(".SILENT");
        const flags = parseImapFlagList(args.slice(2).join(" "));
        const sequences = parseSequenceToken(sequenceSet, state.selectedMessages.length);
        for (const sequence of sequences) {
          const message = state.selectedMessages[sequence - 1];
          if (!message) {
            continue;
          }
          applyStoreToMessage(message, mode, flags);
          if (!silent) {
            const lineFlags = imapFlagsForMessage(message).join(" ");
            writeLine(`* ${sequence} FETCH (FLAGS (${lineFlags}) UID ${message.uid})`);
          }
        }
        refreshSelectedMessages();
        writeLine(`${tag} OK STORE completed`);
        return;
      }

      if (command === "COPY" || command === "MOVE") {
        const args = parseImapAtoms(rawArgs);
        const sequenceSet = args[0] || "";
        const destinationMailbox = args[1] || "";
        if (!sequenceSet || !destinationMailbox) {
          writeLine(`${tag} BAD ${command} requires sequence-set and destination mailbox`);
          return;
        }

        const sequences = parseSequenceToken(sequenceSet, state.selectedMessages.length);
        const messages = sequences
          .map((sequence) => state.selectedMessages[sequence - 1])
          .filter(Boolean);

        if (command === "COPY") {
          writeLine(`${tag} NO COPY not supported by LOOM mailbox model`);
          return;
        }

        if (state.readOnly) {
          writeLine(`${tag} NO Mailbox is read-only`);
          return;
        }

        const moved = moveMessages(messages, destinationMailbox);
        if (!moved.ok) {
          writeLine(`${tag} NO Unsupported destination mailbox`);
          return;
        }
        writeLine(`${tag} OK MOVE completed`);
        return;
      }

      if (command === "UID") {
        const args = parseImapAtoms(rawArgs);
        const subCommand = String(args[0] || "").toUpperCase();
        const maxSelectedUid = state.selectedMessages.reduce(
          (current, message) => Math.max(current, Number(message?.uid || 0)),
          0
        );
        if (subCommand === "FETCH") {
          const uidSet = args[1] || "1:*";
          const fetchSpec = args.slice(2).join(" ");
          const requestedUids = parseSequenceToken(uidSet, maxSelectedUid);
          const requestedSet = new Set(requestedUids);
          for (let index = 0; index < state.selectedMessages.length; index += 1) {
            const sequence = index + 1;
            const message = state.selectedMessages[index];
            const uid = Number(message.uid || 0);
            if (!requestedSet.has(uid)) {
              continue;
            }
            emitFetchForMessage(sequence, message, fetchSpec);
          }
          writeLine(`${tag} OK UID FETCH completed`);
          return;
        }

        if (subCommand === "SEARCH") {
          const criteria = args.slice(1);
          runSearch(criteria, true);
          writeLine(`${tag} OK UID SEARCH completed`);
          return;
        }

        if (subCommand === "STORE") {
          const uidSet = args[1] || "";
          const modeToken = String(args[2] || "").toUpperCase();
          const mode = modeToken.startsWith("+") ? "add" : modeToken.startsWith("-") ? "remove" : "set";
          const silent = modeToken.includes(".SILENT");
          const flags = parseImapFlagList(args.slice(3).join(" "));
          const requestedUids = new Set(parseSequenceToken(uidSet, maxSelectedUid));
          for (let index = 0; index < state.selectedMessages.length; index += 1) {
            const sequence = index + 1;
            const message = state.selectedMessages[index];
            const uid = Number(message.uid || 0);
            if (!requestedUids.has(uid)) {
              continue;
            }
            applyStoreToMessage(message, mode, flags);
            if (!silent) {
              const lineFlags = imapFlagsForMessage(message).join(" ");
              writeLine(`* ${sequence} FETCH (FLAGS (${lineFlags}) UID ${uid})`);
            }
          }
          refreshSelectedMessages();
          writeLine(`${tag} OK UID STORE completed`);
          return;
        }

        if (subCommand === "COPY" || subCommand === "MOVE") {
          const uidSet = args[1] || "";
          const destinationMailbox = args[2] || "";
          if (!uidSet || !destinationMailbox) {
            writeLine(`${tag} BAD UID ${subCommand} requires uid-set and destination mailbox`);
            return;
          }

          if (subCommand === "COPY") {
            writeLine(`${tag} NO UID COPY not supported by LOOM mailbox model`);
            return;
          }

          if (state.readOnly) {
            writeLine(`${tag} NO Mailbox is read-only`);
            return;
          }

          const requestedUids = new Set(parseSequenceToken(uidSet, maxSelectedUid));
          const messages = state.selectedMessages.filter((message) => requestedUids.has(Number(message.uid || 0)));
          const moved = moveMessages(messages, destinationMailbox);
          if (!moved.ok) {
            writeLine(`${tag} NO Unsupported destination mailbox`);
            return;
          }
          writeLine(`${tag} OK UID MOVE completed`);
          return;
        }

        if (subCommand === "EXPUNGE") {
          writeLine(`${tag} OK UID EXPUNGE completed`);
          return;
        }

        if (subCommand === "THREAD") {
          writeLine(`${tag} NO UID THREAD not implemented`);
          return;
        }

        if (subCommand === "SORT") {
          writeLine(`${tag} NO UID SORT not implemented`);
          return;
        }

        if (!subCommand) {
          writeLine(`${tag} BAD UID subcommand required`);
          return;
        }

        if (subCommand !== "FETCH" && subCommand !== "SEARCH" && subCommand !== "STORE") {
          writeLine(`${tag} BAD unsupported UID subcommand`);
          return;
        }
      }

      writeLine(`${tag} BAD unsupported command`);
    };

    writeLine("* OK LOOM IMAP Gateway ready");
    configureSocketTimeout();
    attachLineReader();
  });

  return {
    name: "imap",
    server,
    host,
    port
  };
}

export class LoomWireGateway {
  constructor(options = {}) {
    this.store = options.store;
    this.enabled = options.enabled === true;
    this.host = options.host || "127.0.0.1";
    this.publicBind = isPublicBindHost(this.host);
    this.requireAuth = options.requireAuth !== false;
    this.allowInsecureAuth = options.allowInsecureAuth === true;
    this.allowInsecureAuthOnPublicBind = options.allowInsecureAuthOnPublicBind === true;
    this.maxMessageBytes = parsePositiveInt(options.maxMessageBytes, 10 * 1024 * 1024);
    this.lineMaxBytes = parsePositiveInt(options.lineMaxBytes, 32 * 1024);
    this.lineBufferMaxBytes = parsePositiveInt(options.lineBufferMaxBytes, 128 * 1024);
    this.idleTimeoutMs = parsePositiveInt(options.idleTimeoutMs, 2 * 60 * 1000);
    this.maxAuthFailures = parsePositiveInt(options.maxAuthFailures, 5);
    this.maxConnections = parsePositiveInt(options.maxConnections, 500);
    this.smtpMaxConnections = parsePositiveInt(options.smtpMaxConnections, this.maxConnections);
    this.imapMaxConnections = parsePositiveInt(options.imapMaxConnections, this.maxConnections);
    this.smtpEnabled = this.enabled && options.smtpEnabled !== false;
    this.imapEnabled = this.enabled && options.imapEnabled !== false;
    this.smtpStartTlsEnabled = options.smtpStartTlsEnabled !== false;
    this.imapStartTlsEnabled = options.imapStartTlsEnabled !== false;
    this.smtpPort = parseNonNegativeInt(options.smtpPort, 2525);
    this.imapPort = parseNonNegativeInt(options.imapPort, 1143);
    this.tlsEnabled = options.tlsEnabled === true;
    this.tlsKeyPem = normalizePem(options.tlsKeyPem);
    this.tlsCertPem = normalizePem(options.tlsCertPem);
    this.tlsContext = null;
    if (this.tlsEnabled) {
      if (!this.tlsKeyPem || !this.tlsCertPem) {
        throw new Error("LOOM wire gateway TLS requires both certificate and private key");
      }
      this.tlsContext = createSecureContext({
        key: this.tlsKeyPem,
        cert: this.tlsCertPem
      });
    }

    if (this.enabled && this.requireAuth && !this.allowInsecureAuth && !this.tlsEnabled) {
      throw new Error(
        "Refusing authenticated wire gateway without TLS; enable LOOM_WIRE_TLS_ENABLED=true or set LOOM_WIRE_ALLOW_INSECURE_AUTH=true"
      );
    }

    if (this.enabled && this.requireAuth && !this.allowInsecureAuth) {
      if (this.smtpEnabled && !this.smtpStartTlsEnabled) {
        throw new Error(
          "Refusing SMTP wire gateway auth without STARTTLS; enable LOOM_WIRE_SMTP_STARTTLS_ENABLED=true or set LOOM_WIRE_ALLOW_INSECURE_AUTH=true"
        );
      }
      if (this.imapEnabled && !this.imapStartTlsEnabled) {
        throw new Error(
          "Refusing IMAP wire gateway auth without STARTTLS; enable LOOM_WIRE_IMAP_STARTTLS_ENABLED=true or set LOOM_WIRE_ALLOW_INSECURE_AUTH=true"
        );
      }
    }

    if (this.enabled && this.publicBind && this.requireAuth && !this.tlsEnabled) {
      throw new Error("Refusing public bind of authenticated wire gateway without TLS");
    }

    if (
      this.enabled &&
      this.publicBind &&
      this.requireAuth &&
      this.allowInsecureAuth &&
      !this.allowInsecureAuthOnPublicBind
    ) {
      throw new Error(
        "Refusing LOOM_WIRE_ALLOW_INSECURE_AUTH=true on public bind without LOOM_WIRE_ALLOW_INSECURE_AUTH_ON_PUBLIC_BIND=true"
      );
    }

    this.smtpServer = null;
    this.imapServer = null;
    this.smtpSockets = new Set();
    this.imapSockets = new Set();
  }

  isEnabled() {
    return this.enabled;
  }

  getStatus() {
    return {
      enabled: this.enabled,
      host: this.host,
      require_auth: this.requireAuth,
      allow_insecure_auth: this.allowInsecureAuth,
      max_connections: {
        total: this.maxConnections,
        smtp: this.smtpMaxConnections,
        imap: this.imapMaxConnections
      },
      active_connections: {
        total: this.smtpSockets.size + this.imapSockets.size,
        smtp: this.smtpSockets.size,
        imap: this.imapSockets.size
      },
      idle_timeout_ms: this.idleTimeoutMs,
      smtp: {
        enabled: this.smtpEnabled,
        configured_port: this.smtpPort,
        starttls_enabled: this.smtpEnabled && this.smtpStartTlsEnabled && this.tlsEnabled,
        listening: Boolean(this.smtpServer?.listening),
        bound_port: this.smtpServer?.address()?.port || null
      },
      imap: {
        enabled: this.imapEnabled,
        configured_port: this.imapPort,
        starttls_enabled: this.imapEnabled && this.imapStartTlsEnabled && this.tlsEnabled,
        listening: Boolean(this.imapServer?.listening),
        bound_port: this.imapServer?.address()?.port || null
      }
    };
  }

  async start() {
    if (!this.enabled) {
      return;
    }

    const registerSocket = (socket, protocolSockets, protocolMaxConnections) => {
      const totalConnections = this.smtpSockets.size + this.imapSockets.size;
      if (totalConnections >= this.maxConnections) {
        socket.destroy();
        return false;
      }
      if (protocolSockets.size >= protocolMaxConnections) {
        socket.destroy();
        return false;
      }
      protocolSockets.add(socket);
      socket.once("close", () => {
        protocolSockets.delete(socket);
      });
      return true;
    };

    if (this.smtpEnabled && !this.smtpServer) {
      const gateway = createSmtpGatewayServer({
        store: this.store,
        host: this.host,
        port: this.smtpPort,
        requireAuth: this.requireAuth,
        allowInsecureAuth: this.allowInsecureAuth,
        maxMessageBytes: this.maxMessageBytes,
        lineMaxBytes: this.lineMaxBytes,
        lineBufferMaxBytes: this.lineBufferMaxBytes,
        idleTimeoutMs: this.idleTimeoutMs,
        maxAuthFailures: this.maxAuthFailures,
        startTlsEnabled: this.smtpStartTlsEnabled && this.tlsEnabled,
        tlsContext: this.tlsContext
      });
      this.smtpServer = gateway.server;
      this.smtpServer.maxConnections = this.smtpMaxConnections;
      this.smtpServer.on("connection", (socket) => {
        registerSocket(socket, this.smtpSockets, this.smtpMaxConnections);
      });
      await new Promise((resolve, reject) => {
        const onError = (error) => {
          this.smtpServer.off("error", onError);
          reject(error);
        };
        this.smtpServer.once("error", onError);
        this.smtpServer.listen(this.smtpPort, this.host, () => {
          this.smtpServer.off("error", onError);
          resolve();
        });
      });
    }

    if (this.imapEnabled && !this.imapServer) {
      const gateway = createImapGatewayServer({
        store: this.store,
        host: this.host,
        port: this.imapPort,
        requireAuth: this.requireAuth,
        allowInsecureAuth: this.allowInsecureAuth,
        lineMaxBytes: this.lineMaxBytes,
        lineBufferMaxBytes: this.lineBufferMaxBytes,
        idleTimeoutMs: this.idleTimeoutMs,
        maxAuthFailures: this.maxAuthFailures,
        startTlsEnabled: this.imapStartTlsEnabled && this.tlsEnabled,
        tlsContext: this.tlsContext
      });
      this.imapServer = gateway.server;
      this.imapServer.maxConnections = this.imapMaxConnections;
      this.imapServer.on("connection", (socket) => {
        registerSocket(socket, this.imapSockets, this.imapMaxConnections);
      });
      await new Promise((resolve, reject) => {
        const onError = (error) => {
          this.imapServer.off("error", onError);
          reject(error);
        };
        this.imapServer.once("error", onError);
        this.imapServer.listen(this.imapPort, this.host, () => {
          this.imapServer.off("error", onError);
          resolve();
        });
      });
    }
  }

  async stop() {
    const closeServer = (server) =>
      new Promise((resolve) => {
        if (!server || !server.listening) {
          resolve();
          return;
        }
        server.close(() => resolve());
      });

    for (const socket of this.smtpSockets) {
      socket.destroy();
    }
    for (const socket of this.imapSockets) {
      socket.destroy();
    }

    await closeServer(this.smtpServer);
    await closeServer(this.imapServer);
    this.smtpServer = null;
    this.imapServer = null;
    this.smtpSockets.clear();
    this.imapSockets.clear();
  }
}

export function createWireGatewayFromEnv(options = {}) {
  const enabled = parseBoolean(options.enabled ?? process.env.LOOM_WIRE_GATEWAY_ENABLED, false);
  const tlsEnabled = parseBoolean(options.tlsEnabled ?? process.env.LOOM_WIRE_TLS_ENABLED, false);
  const tlsKeyPem =
    options.tlsKeyPem ??
    normalizePem(process.env.LOOM_WIRE_TLS_KEY_PEM) ??
    readPemFile(options.tlsKeyFile ?? process.env.LOOM_WIRE_TLS_KEY_FILE);
  const tlsCertPem =
    options.tlsCertPem ??
    normalizePem(process.env.LOOM_WIRE_TLS_CERT_PEM) ??
    readPemFile(options.tlsCertFile ?? process.env.LOOM_WIRE_TLS_CERT_FILE);

  return new LoomWireGateway({
    store: options.store,
    enabled,
    host: options.host ?? process.env.LOOM_WIRE_GATEWAY_HOST ?? "127.0.0.1",
    smtpEnabled: parseBoolean(options.smtpEnabled ?? process.env.LOOM_WIRE_SMTP_ENABLED, true),
    smtpStartTlsEnabled: parseBoolean(
      options.smtpStartTlsEnabled ?? process.env.LOOM_WIRE_SMTP_STARTTLS_ENABLED,
      true
    ),
    smtpPort: options.smtpPort ?? process.env.LOOM_WIRE_SMTP_PORT ?? 2525,
    imapEnabled: parseBoolean(options.imapEnabled ?? process.env.LOOM_WIRE_IMAP_ENABLED, true),
    imapStartTlsEnabled: parseBoolean(
      options.imapStartTlsEnabled ?? process.env.LOOM_WIRE_IMAP_STARTTLS_ENABLED,
      true
    ),
    imapPort: options.imapPort ?? process.env.LOOM_WIRE_IMAP_PORT ?? 1143,
    requireAuth: parseBoolean(options.requireAuth ?? process.env.LOOM_WIRE_GATEWAY_REQUIRE_AUTH, true),
    allowInsecureAuth: parseBoolean(
      options.allowInsecureAuth ?? process.env.LOOM_WIRE_ALLOW_INSECURE_AUTH,
      false
    ),
    allowInsecureAuthOnPublicBind: parseBoolean(
      options.allowInsecureAuthOnPublicBind ?? process.env.LOOM_WIRE_ALLOW_INSECURE_AUTH_ON_PUBLIC_BIND,
      false
    ),
    maxMessageBytes: options.maxMessageBytes ?? process.env.LOOM_WIRE_SMTP_MAX_MESSAGE_BYTES ?? 10 * 1024 * 1024,
    lineMaxBytes: options.lineMaxBytes ?? process.env.LOOM_WIRE_LINE_MAX_BYTES ?? 32 * 1024,
    lineBufferMaxBytes: options.lineBufferMaxBytes ?? process.env.LOOM_WIRE_LINE_BUFFER_MAX_BYTES ?? 128 * 1024,
    idleTimeoutMs: options.idleTimeoutMs ?? process.env.LOOM_WIRE_IDLE_TIMEOUT_MS ?? 2 * 60 * 1000,
    maxAuthFailures: options.maxAuthFailures ?? process.env.LOOM_WIRE_AUTH_MAX_FAILURES ?? 5,
    maxConnections: options.maxConnections ?? process.env.LOOM_WIRE_MAX_CONNECTIONS ?? 500,
    smtpMaxConnections: options.smtpMaxConnections ?? process.env.LOOM_WIRE_SMTP_MAX_CONNECTIONS ?? null,
    imapMaxConnections: options.imapMaxConnections ?? process.env.LOOM_WIRE_IMAP_MAX_CONNECTIONS ?? null,
    tlsEnabled,
    tlsKeyPem,
    tlsCertPem
  });
}
