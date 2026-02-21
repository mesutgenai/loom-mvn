import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  openSync,
  closeSync,
  fsyncSync,
  readFileSync,
  renameSync,
  writeFileSync
} from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { lookup, resolveTxt } from "node:dns/promises";
import { isIP } from "node:net";
import { join } from "node:path";

import {
  derivePublicKeyPemFromPrivateKeyPem,
  fromBase64Url,
  generateSigningKeyPair,
  signEnvelope,
  signUtf8Message,
  toBase64Url,
  verifyUtf8MessageSignature
} from "../protocol/crypto.js";
import { LoomError } from "../protocol/errors.js";
import { canonicalizeEnvelope, canonicalizeJson } from "../protocol/canonical.js";
import { canonicalThreadOrder, validateThreadDag } from "../protocol/thread.js";
import { isIdentity, normalizeLoomIdentity } from "../protocol/ids.js";
import { generateUlid } from "../protocol/ulid.js";
import { verifyDelegationLinkOrThrow } from "../protocol/delegation.js";
import { isSigningKeyUsableAt } from "../protocol/key_lifecycle.js";
import {
  listSupportedE2eeProfileCapabilities,
  listSupportedE2eeProfiles,
  resolveE2eeProfile
} from "../protocol/e2ee.js";
import {
  parseLoomIdentityAuthority,
  parseTrustAnchorBindings
} from "../protocol/trust.js";
import { deserializeMlsGroupState } from "../protocol/mls_codec.js";
import { validateAgentInfo, normalizeAgentInfo } from "../protocol/agent_info.js";
import { buildDeliveryReceipt, buildReadReceipt, buildFailureReceipt, shouldSuppressAutoReply } from "../protocol/receipts.js";
import {
  DEFAULT_RETENTION_POLICIES,
  normalizeRetentionPolicies,
  resolveRetentionDays,
  isExpiredByRetention,
  isLegalHoldActive,
  collectExpiredEnvelopes
} from "../protocol/retention.js";
import { canDeleteEnvelope, eraseEnvelopeContent, buildCryptoShredRecord } from "../protocol/deletion.js";
import { normalizeChannelRules, evaluateRules, applyRuleActions } from "../protocol/channel_rules.js";
import {
  validateAutoresponderRule,
  isAutoresponderActive,
  shouldAutoRespond,
  buildAutoReplyEnvelope
} from "../protocol/autoresponder.js";
import { normalizeRoutingPolicy, resolveTeamRecipients, requiresModeration } from "../protocol/distribution.js";
import { validateSearchQuery } from "../protocol/search.js";
import {
  validateImportPayload,
  buildExportPackage,
  prepareImportEnvelopes,
  prepareImportThreads,
  IMPORT_LABEL
} from "../protocol/import_export.js";
import { validateBlobInitiation } from "../protocol/blob.js";
import {
  createEventLog,
  appendEvent,
  getEventsSince,
  pruneEventLog,
  WS_EVENT_TYPES
} from "../protocol/websocket.js";
import { buildRateLimitHeaders } from "../protocol/rate_limit.js";
import { parseBoolean } from "./env.js";
import { processMcpToolRequest, isMcpToolRequestEnvelope } from "./mcp_client.js";
import { createMcpToolRegistry } from "./mcp_server.js";
import {
  enforceThreadEnvelopeEncryptionPolicyCore,
  getThreadEnvelopesCore,
  ingestEnvelopeCore,
  prepareThreadOperationCore,
  resolveAuthoritativeEnvelopeSenderTypeCore,
  resolveEnvelopeSignaturePublicKeyCore,
  resolvePendingParentsForThreadCore
} from "./store/protocol_core.js";
import {
  assertFederatedEnvelopeIdentityAuthorityPolicy,
  enforceIdentityRateLimitPolicy,
  isIdentitySensitiveRoutePolicy
} from "./store/policy_engine.js";
import {
  buildRecipientListAdapter,
  htmlToTextAdapter,
  inferEmailFromIdentityAdapter,
  inferIdentityFromAddressAdapter,
  normalizeEmailAddressAdapter,
  normalizeEmailAddressListAdapter,
  parseMessageIdAdapter,
  parseMessageIdListAdapter,
  parseReferencesAdapter,
  resolveHeaderValueAdapter,
  resolveIdentitiesFromAddressInputAdapter,
  splitAddressListAdapter
} from "./store/adapters.js";

function nowIso() {
  return new Date().toISOString();
}

function nowMs() {
  return Date.now();
}

function parseTime(value) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function parsePositiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function parseNonNegativeInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

const MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;
const STATE_ENCRYPTION_NONCE_BYTES = 12;
const STATE_ENCRYPTION_TAG_BYTES = 16;
const STATE_ENCRYPTION_WRAPPER_TYPE = "loom.state.encrypted@v1";
const STATE_ENCRYPTION_ALGORITHM = "aes-256-gcm";
const DEFAULT_BRIDGE_INBOUND_HEADER_ALLOWLIST = [
  "date",
  "from",
  "to",
  "cc",
  "bcc",
  "subject",
  "message-id",
  "in-reply-to",
  "references",
  "reply-to",
  "mime-version",
  "content-type",
  "content-transfer-encoding",
  "authentication-results",
  "x-authentication-results"
];

const E2EE_PROFILE_SECURITY_RANK = new Map([
  ["loom-e2ee-x25519-xchacha20-v1", 100],
  ["loom-e2ee-x25519-xchacha20-v2", 200],
  ["loom-e2ee-mls-1", 300]
]);

const CONTENT_FILTER_URL_RE = /\bhttps?:\/\/[^\s<>"'`]+/gi;
const CONTENT_FILTER_SHORTENER_HOSTS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "is.gd",
  "ow.ly",
  "shorturl.at",
  "rb.gy"
]);
const CONTENT_FILTER_MALWARE_EXTENSIONS = new Set([
  "exe",
  "scr",
  "com",
  "msi",
  "ps1",
  "vbs",
  "js",
  "jar",
  "bat",
  "cmd",
  "hta",
  "lnk",
  "iso",
  "img",
  "docm",
  "xlsm",
  "pptm"
]);
const CONTENT_FILTER_ARCHIVE_EXTENSIONS = new Set(["zip", "rar", "7z", "tar", "gz"]);
const CONTENT_FILTER_MALWARE_MIME_SNIPPETS = [
  "application/x-msdownload",
  "application/x-dosexec",
  "application/x-ms-installer",
  "application/x-sh",
  "application/x-bat"
];
const CONTENT_FILTER_SPAM_KEYWORDS = [
  "limited time offer",
  "act now",
  "urgent response",
  "winner",
  "lottery",
  "free gift",
  "risk free",
  "guaranteed income",
  "double your money",
  "exclusive deal"
];
const CONTENT_FILTER_PHISH_KEYWORDS = [
  "verify your account",
  "confirm your password",
  "account suspended",
  "security alert",
  "unusual activity",
  "reset your password",
  "payment failed",
  "login required",
  "click the link",
  "update your billing"
];
const INBOUND_CONTENT_FILTER_DECISION_ACTIONS = Object.freeze(["allow", "quarantine", "reject"]);
const INBOUND_CONTENT_FILTER_PROFILES = new Set(["strict", "balanced", "agent"]);
const INBOUND_CONTENT_FILTER_CONFIG_MODES = new Set(["canary", "apply", "rollback"]);
const INBOUND_CONTENT_FILTER_CONFIG_FIELDS = Object.freeze([
  "enabled",
  "reject_malware",
  "spam_threshold",
  "phish_threshold",
  "quarantine_threshold",
  "reject_threshold",
  "profile_default",
  "profile_bridge_email",
  "profile_federation"
]);
const INBOUND_CONTENT_FILTER_PROFILE_CONFIG = Object.freeze({
  strict: Object.freeze({
    threshold_deltas: Object.freeze({
      spam: -1,
      phish: -1,
      quarantine: -1,
      reject: -1
    }),
    weights: Object.freeze({
      keyword_spam: 1,
      keyword_phish: 2,
      keyword_phish_cluster: 3,
      subject_all_caps: 2,
      url_volume: 2,
      url_shortener: 1,
      url_punycode: 2,
      url_ip_literal: 2,
      attachment_archive_lure: 1,
      auth_dmarc_not_pass: 2,
      auth_dkim_not_pass: 1,
      auth_spf_not_pass: 1
    }),
    clusters: Object.freeze({
      spam_keyword_min: 3,
      spam_keyword_weight: 2,
      phish_keyword_min: 2,
      phish_keyword_weight: 3
    })
  }),
  balanced: Object.freeze({
    threshold_deltas: Object.freeze({
      spam: 0,
      phish: 0,
      quarantine: 0,
      reject: 0
    }),
    weights: Object.freeze({
      keyword_spam: 1,
      keyword_phish: 2,
      keyword_phish_cluster: 3,
      subject_all_caps: 1,
      url_volume: 1,
      url_shortener: 1,
      url_punycode: 2,
      url_ip_literal: 2,
      attachment_archive_lure: 1,
      auth_dmarc_not_pass: 2,
      auth_dkim_not_pass: 1,
      auth_spf_not_pass: 1
    }),
    clusters: Object.freeze({
      spam_keyword_min: 4,
      spam_keyword_weight: 2,
      phish_keyword_min: 3,
      phish_keyword_weight: 3
    })
  }),
  agent: Object.freeze({
    threshold_deltas: Object.freeze({
      spam: 2,
      phish: 1,
      quarantine: 2,
      reject: 2
    }),
    weights: Object.freeze({
      keyword_spam: 0,
      keyword_phish: 1,
      keyword_phish_cluster: 3,
      subject_all_caps: 0,
      url_volume: 0,
      url_shortener: 1,
      url_punycode: 2,
      url_ip_literal: 2,
      attachment_archive_lure: 1,
      auth_dmarc_not_pass: 2,
      auth_dkim_not_pass: 1,
      auth_spf_not_pass: 1
    }),
    clusters: Object.freeze({
      spam_keyword_min: 5,
      spam_keyword_weight: 2,
      phish_keyword_min: 3,
      phish_keyword_weight: 3
    })
  })
});

function normalizeInboundContentFilterProfile(value, fallback = "balanced") {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (INBOUND_CONTENT_FILTER_PROFILES.has(normalized)) {
    return normalized;
  }
  const fallbackNormalized = String(fallback || "balanced")
    .trim()
    .toLowerCase();
  return INBOUND_CONTENT_FILTER_PROFILES.has(fallbackNormalized) ? fallbackNormalized : "balanced";
}

function createInboundContentFilterProfileDecisionStats() {
  return {
    evaluated: 0,
    allow: 0,
    quarantine: 0,
    reject: 0,
    spam_labeled: 0
  };
}

function createInboundContentFilterDecisionStatsByProfile() {
  return {
    strict: createInboundContentFilterProfileDecisionStats(),
    balanced: createInboundContentFilterProfileDecisionStats(),
    agent: createInboundContentFilterProfileDecisionStats()
  };
}

function createInboundContentFilterStats() {
  return {
    evaluated: 0,
    rejected: 0,
    quarantined: 0,
    spam_labeled: 0,
    last_evaluated_at: null,
    decision_counts_by_profile: createInboundContentFilterDecisionStatsByProfile()
  };
}

function cloneInboundContentFilterConfig(config = {}) {
  const quarantineThreshold = Math.max(1, Number(config?.quarantine_threshold || 1));
  const rejectThreshold = Math.max(quarantineThreshold + 1, Number(config?.reject_threshold || quarantineThreshold + 1));
  return {
    enabled: config?.enabled === true,
    reject_malware: config?.reject_malware === true,
    spam_threshold: Math.max(1, Number(config?.spam_threshold || 1)),
    phish_threshold: Math.max(1, Number(config?.phish_threshold || 1)),
    quarantine_threshold: quarantineThreshold,
    reject_threshold: rejectThreshold,
    profile_default: normalizeInboundContentFilterProfile(config?.profile_default, "balanced"),
    profile_bridge_email: normalizeInboundContentFilterProfile(
      config?.profile_bridge_email,
      normalizeInboundContentFilterProfile(config?.profile_default, "balanced")
    ),
    profile_federation: normalizeInboundContentFilterProfile(config?.profile_federation, "agent")
  };
}

function areInboundContentFilterConfigsEqual(left = {}, right = {}) {
  return INBOUND_CONTENT_FILTER_CONFIG_FIELDS.every((field) => left[field] === right[field]);
}

function cloneInboundContentFilterCanaryState(value) {
  if (!value || typeof value !== "object") {
    return null;
  }
  return {
    canary_id: String(value.canary_id || "").trim() || null,
    mode: "canary",
    created_at:
      typeof value.created_at === "string" && value.created_at.trim().length > 0
        ? value.created_at.trim()
        : null,
    updated_at:
      typeof value.updated_at === "string" && value.updated_at.trim().length > 0
        ? value.updated_at.trim()
        : null,
    actor:
      typeof value.actor === "string" && value.actor.trim().length > 0
        ? value.actor.trim()
        : "system",
    note:
      typeof value.note === "string" && value.note.trim().length > 0
        ? value.note.trim().slice(0, 240)
        : null,
    config: cloneInboundContentFilterConfig(value.config || {})
  };
}

function cloneInboundContentFilterRollbackState(value) {
  if (!value || typeof value !== "object") {
    return null;
  }
  return {
    rollback_id: String(value.rollback_id || "").trim() || null,
    from_version: Math.max(0, parseNonNegativeInteger(value.from_version, 0)),
    source:
      typeof value.source === "string" && value.source.trim().length > 0
        ? value.source.trim()
        : "unknown",
    stored_at:
      typeof value.stored_at === "string" && value.stored_at.trim().length > 0
        ? value.stored_at.trim()
        : null,
    actor:
      typeof value.actor === "string" && value.actor.trim().length > 0
        ? value.actor.trim()
        : "system",
    config: cloneInboundContentFilterConfig(value.config || {})
  };
}

function normalizeInboundContentFilterConfigMode(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (!normalized) {
    return "canary";
  }
  return INBOUND_CONTENT_FILTER_CONFIG_MODES.has(normalized) ? normalized : null;
}

function parseInboundContentFilterBooleanField(value, field, fallback) {
  if (value === undefined) {
    return fallback;
  }

  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number" && (value === 0 || value === 1)) {
    return value === 1;
  }

  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (normalized === "true" || normalized === "1" || normalized === "yes" || normalized === "on") {
    return true;
  }
  if (normalized === "false" || normalized === "0" || normalized === "no" || normalized === "off") {
    return false;
  }

  throw new LoomError("ENVELOPE_INVALID", `${field} must be a boolean`, 400, {
    field
  });
}

function parseInboundContentFilterThresholdField(value, field, fallback) {
  if (value === undefined) {
    return fallback;
  }
  const parsed = parsePositiveInteger(value, Number.NaN);
  if (!Number.isFinite(parsed) || parsed < 1) {
    throw new LoomError("ENVELOPE_INVALID", `${field} must be an integer >= 1`, 400, {
      field
    });
  }
  return parsed;
}

function parseInboundContentFilterProfileField(value, field, fallback) {
  if (value === undefined) {
    return fallback;
  }
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (!normalized) {
    throw new LoomError("ENVELOPE_INVALID", `${field} must be a non-empty string`, 400, {
      field
    });
  }
  if (!INBOUND_CONTENT_FILTER_PROFILES.has(normalized)) {
    throw new LoomError("ENVELOPE_INVALID", `${field} must be one of strict, balanced, agent`, 400, {
      field
    });
  }
  return normalized;
}

function hashInboundContentTelemetryValue(value, salt) {
  const normalized = String(value || "");
  if (!normalized) {
    return null;
  }
  return createHash("sha256")
    .update(`${String(salt || "")}:${normalized}`, "utf-8")
    .digest("hex")
    .slice(0, 16);
}

function isIpv4Host(value) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(value || "").trim());
}

function normalizeUrlHost(value) {
  try {
    return new URL(String(value || "").trim()).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function extractContentUrls(value) {
  const text = String(value || "");
  const matches = text.match(CONTENT_FILTER_URL_RE) || [];
  return Array.from(new Set(matches.map((entry) => String(entry || "").trim()).filter(Boolean)));
}

function normalizeAttachmentExtension(filename) {
  const normalizedName = String(filename || "")
    .trim()
    .toLowerCase();
  const index = normalizedName.lastIndexOf(".");
  if (index < 0 || index === normalizedName.length - 1) {
    return "";
  }
  return normalizedName.slice(index + 1);
}

function normalizeBridgeInboundHeaderAllowlist(value) {
  const list = Array.isArray(value) ? value : String(value || "").split(/[,\n;]+/);
  const normalized = Array.from(
    new Set(
      list
        .map((entry) => String(entry || "").trim().toLowerCase())
        .filter(Boolean)
        .map((entry) => entry.replace(/:+$/, ""))
    )
  );
  if (normalized.length === 0) {
    return [...DEFAULT_BRIDGE_INBOUND_HEADER_ALLOWLIST];
  }
  return normalized;
}

function sanitizeBridgeInboundHeaders(headers, allowlist = DEFAULT_BRIDGE_INBOUND_HEADER_ALLOWLIST) {
  if (!headers || typeof headers !== "object") {
    return {};
  }

  const allowed = new Set(
    (Array.isArray(allowlist) ? allowlist : DEFAULT_BRIDGE_INBOUND_HEADER_ALLOWLIST)
      .map((entry) => String(entry || "").trim().toLowerCase())
      .filter(Boolean)
  );
  const sanitized = {};
  for (const [rawKey, rawValue] of Object.entries(headers)) {
    const key = String(rawKey || "").trim();
    if (!key || containsHeaderUnsafeChars(key)) {
      continue;
    }

    const normalizedKey = key.toLowerCase();
    if (allowed.size > 0 && !allowed.has(normalizedKey)) {
      continue;
    }

    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    const normalizedValue = values
      .map((entry) => String(entry == null ? "" : entry))
      .map((entry) => entry.replace(/\0/g, "").trim())
      .filter((entry) => entry.length > 0 && !containsHeaderUnsafeChars(entry))
      .slice(0, 16)
      .join(", ");
    if (!normalizedValue) {
      continue;
    }
    sanitized[key] = normalizedValue.slice(0, 8192);
  }
  return sanitized;
}

function normalizeE2eeProfileMigrationAllowlist(value) {
  const entries = Array.isArray(value) ? value : String(value || "").split(/[,\n;]+/);
  const normalized = new Set();
  for (const rawEntry of entries) {
    const entry = String(rawEntry || "").trim().toLowerCase();
    if (!entry) {
      continue;
    }
    const [fromProfile, toProfile] = entry.split(">", 2).map((part) => String(part || "").trim());
    if (!fromProfile || !toProfile) {
      continue;
    }
    const normalizedFrom = resolveE2eeProfile(fromProfile)?.id || fromProfile;
    const normalizedTo = resolveE2eeProfile(toProfile)?.id || toProfile;
    normalized.add(`${normalizedFrom.toLowerCase()}>${normalizedTo.toLowerCase()}`);
  }
  return normalized;
}

function normalizeStateEncryptionKey(value) {
  if (value == null) {
    return null;
  }
  const raw = String(value).trim();
  if (!raw) {
    return null;
  }

  let bytes = null;
  if (/^[A-Fa-f0-9]{64}$/.test(raw)) {
    bytes = Buffer.from(raw, "hex");
  } else {
    try {
      bytes = fromBase64Url(raw);
    } catch {}
    if ((!bytes || bytes.length !== 32) && /^[A-Za-z0-9+/=_-]+$/.test(raw)) {
      try {
        bytes = Buffer.from(raw, "base64");
      } catch {}
    }
  }

  if (!bytes || bytes.length !== 32) {
    throw new Error("stateEncryptionKey must decode to 32 bytes (base64url/base64/hex)");
  }
  return Buffer.from(bytes);
}

function normalizeProtocolCapabilityE2eeProfiles(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return Array.from(
    new Set(
      value
        .map((entry) => {
          const normalize = (candidate) => {
            const raw = String(candidate || "").trim();
            if (!raw) {
              return "";
            }
            const resolved = resolveE2eeProfile(raw);
            return resolved?.id || raw;
          };
          if (typeof entry === "string") {
            return normalize(entry);
          }
          if (entry && typeof entry === "object") {
            return normalize(entry.id);
          }
          return "";
        })
        .filter(Boolean)
    )
  );
}

function normalizeProtocolCapabilityTrustModes(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return Array.from(
    new Set(
      value
        .map((entry) => String(entry || "").trim().toLowerCase())
        .filter((entry) => FEDERATION_TRUST_MODES.has(entry))
    )
  );
}

function normalizeProtocolCapabilitiesDocument(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }

  const negotiation = value.federation_negotiation && typeof value.federation_negotiation === "object"
    ? value.federation_negotiation
    : {};
  const trustAnchorMode = normalizeFederationTrustMode(negotiation.trust_anchor_mode, { hasTrustAnchors: false });
  const trustModesSupported = normalizeProtocolCapabilityTrustModes(negotiation.trust_anchor_modes_supported);
  const e2eeProfiles = normalizeProtocolCapabilityE2eeProfiles(negotiation.e2ee_profiles);

  return {
    loom_version: String(value.loom_version || "").trim() || null,
    node_id: String(value.node_id || "").trim() || null,
    generated_at: String(value.generated_at || "").trim() || null,
    federation_negotiation: {
      trust_anchor_mode: trustAnchorMode,
      trust_anchor_modes_supported:
        trustModesSupported.length > 0
          ? trustModesSupported
          : Array.from(new Set([trustAnchorMode].filter(Boolean))),
      e2ee_profiles: e2eeProfiles
    }
  };
}

function intersectStrings(left = [], right = []) {
  const rightSet = new Set((Array.isArray(right) ? right : []).map((value) => String(value || "").trim()));
  return Array.from(
    new Set(
      (Array.isArray(left) ? left : [])
        .map((value) => String(value || "").trim())
        .filter((value) => value && rightSet.has(value))
    )
  );
}

function normalizeTraceField(value) {
  if (value == null) {
    return null;
  }
  const normalized = String(value).trim();
  if (!normalized) {
    return null;
  }
  if (normalized.length > 160) {
    return normalized.slice(0, 160);
  }
  return normalized;
}

function containsHeaderUnsafeChars(value) {
  return /[\r\n\0]/.test(String(value || ""));
}

function normalizeIpForChecks(ip) {
  return String(ip || "")
    .trim()
    .toLowerCase()
    .split("%")[0];
}

function isPrivateOrLocalIpv4(ip) {
  const parts = String(ip || "")
    .split(".")
    .map((value) => Number(value));
  if (parts.length !== 4 || parts.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
    return true;
  }

  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0) {
    return true;
  }
  if (a === 169 && b === 254) {
    return true;
  }
  if (a === 172 && b >= 16 && b <= 31) {
    return true;
  }
  if (a === 192 && b === 168) {
    return true;
  }
  if (a === 100 && b >= 64 && b <= 127) {
    return true;
  }
  if (a === 198 && (b === 18 || b === 19)) {
    return true;
  }
  return a >= 224;
}

function isPrivateOrLocalIpv6(ip) {
  const normalized = normalizeIpForChecks(ip);
  if (!normalized) {
    return true;
  }

  if (normalized === "::1" || normalized === "::") {
    return true;
  }

  if (normalized.startsWith("fc") || normalized.startsWith("fd")) {
    return true;
  }

  if (
    normalized.startsWith("fe8") ||
    normalized.startsWith("fe9") ||
    normalized.startsWith("fea") ||
    normalized.startsWith("feb")
  ) {
    return true;
  }

  if (normalized.startsWith("::ffff:")) {
    const mappedIpv4 = normalized.slice("::ffff:".length);
    if (isIP(mappedIpv4) === 4) {
      return isPrivateOrLocalIpv4(mappedIpv4);
    }
  }

  return false;
}

function isPrivateOrLocalIp(ip) {
  const normalized = normalizeIpForChecks(ip);
  const version = isIP(normalized);
  if (version === 4) {
    return isPrivateOrLocalIpv4(normalized);
  }
  if (version === 6) {
    return isPrivateOrLocalIpv6(normalized);
  }
  return true;
}

function normalizeHostname(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "");
}

function normalizeHostnameAllowlist(value) {
  if (value == null) {
    return [];
  }

  const list = Array.isArray(value) ? value : String(value).split(",");
  return Array.from(
    new Set(
      list
        .map((entry) => normalizeHostname(entry))
        .filter(Boolean)
    )
  );
}

function hostnameMatchesAllowlist(hostname, allowlist = []) {
  const normalizedHost = normalizeHostname(hostname);
  if (!normalizedHost) {
    return false;
  }

  for (const rawPattern of allowlist) {
    const pattern = normalizeHostname(rawPattern);
    if (!pattern) {
      continue;
    }

    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(2);
      if (suffix && (normalizedHost === suffix || normalizedHost.endsWith(`.${suffix}`))) {
        return true;
      }
      continue;
    }

    if (pattern.startsWith(".")) {
      const suffix = pattern.slice(1);
      if (suffix && (normalizedHost === suffix || normalizedHost.endsWith(`.${suffix}`))) {
        return true;
      }
      continue;
    }

    if (normalizedHost === pattern) {
      return true;
    }
  }

  return false;
}

const METADATA_HOST_DENYLIST = new Set([
  "metadata",
  "metadata.aws.internal",
  "metadata.google.internal",
  "instance-data",
  "instance-data.ec2.internal"
]);

function isMetadataHostname(hostname) {
  const normalized = normalizeHostname(hostname);
  if (!normalized) {
    return false;
  }
  if (METADATA_HOST_DENYLIST.has(normalized)) {
    return true;
  }
  return normalized.endsWith(".metadata.google.internal");
}

function isMetadataServiceAddress(value) {
  const normalized = normalizeIpForChecks(value);
  if (!normalized) {
    return false;
  }
  if (normalized === "169.254.169.254" || normalized === "169.254.170.2" || normalized === "100.100.100.200") {
    return true;
  }
  return normalized === "fd00:ec2::254";
}

async function assertOutboundUrlHostAllowed(url, options = {}) {
  const allowPrivateNetwork = options.allowPrivateNetwork === true;
  const denyMetadataHosts = options.denyMetadataHosts !== false;
  const allowedHosts = normalizeHostnameAllowlist(options.allowedHosts || []);
  const target = url instanceof URL ? url : new URL(String(url || ""));
  const resolvedAddresses = [];

  if (target.username || target.password) {
    throw new LoomError("ENVELOPE_INVALID", "URL credentials are not allowed", 400, {
      field: "url"
    });
  }

  if (allowedHosts.length > 0 && !hostnameMatchesAllowlist(target.hostname, allowedHosts)) {
    throw new LoomError("CAPABILITY_DENIED", "URL host is not in outbound allowlist", 403, {
      host: target.hostname,
      allowlist_count: allowedHosts.length
    });
  }

  const hostname = target.hostname;
  if (denyMetadataHosts && isMetadataHostname(hostname)) {
    throw new LoomError("CAPABILITY_DENIED", "Metadata service targets are blocked", 403, {
      host: hostname
    });
  }

  const ipVersion = isIP(hostname);
  if (ipVersion > 0) {
    if (denyMetadataHosts && isMetadataServiceAddress(hostname)) {
      throw new LoomError("CAPABILITY_DENIED", "Metadata service targets are blocked", 403, {
        host: hostname
      });
    }
    if (!allowPrivateNetwork && isPrivateOrLocalIp(hostname)) {
      throw new LoomError("CAPABILITY_DENIED", "Private or local network URL targets are not allowed", 403, {
        host: hostname
      });
    }
    resolvedAddresses.push({
      address: hostname,
      family: ipVersion
    });
    return {
      target,
      resolvedAddresses
    };
  }

  if (!allowPrivateNetwork || denyMetadataHosts) {
    let resolved;
    try {
      resolved = await lookup(hostname, { all: true, verbatim: true });
    } catch {
      throw new LoomError("NODE_UNREACHABLE", "Failed to resolve URL host", 502, {
        host: hostname
      });
    }

    if (!Array.isArray(resolved) || resolved.length === 0) {
      throw new LoomError("NODE_UNREACHABLE", "URL host did not resolve to any address", 502, {
        host: hostname
      });
    }

    if (denyMetadataHosts) {
      const metadataAddress = resolved.find((entry) => isMetadataServiceAddress(entry?.address));
      if (metadataAddress) {
        throw new LoomError("CAPABILITY_DENIED", "Resolved URL host points to metadata service", 403, {
          host: hostname,
          address: metadataAddress.address
        });
      }
    }

    if (!allowPrivateNetwork) {
      const privateAddress = resolved.find((entry) => isPrivateOrLocalIp(entry?.address));
      if (privateAddress) {
        throw new LoomError("CAPABILITY_DENIED", "Resolved URL host points to private or local network", 403, {
          host: hostname,
          address: privateAddress.address
        });
      }
    }

    for (const entry of resolved) {
      const address = normalizeIpForChecks(entry?.address);
      const family = Number(entry?.family) || isIP(address);
      if (!address || family <= 0) {
        continue;
      }
      resolvedAddresses.push({
        address,
        family
      });
    }
  }

  if (resolvedAddresses.length === 0) {
    throw new LoomError("NODE_UNREACHABLE", "URL host did not resolve to any usable address", 502, {
      host: hostname
    });
  }

  return {
    target,
    resolvedAddresses
  };
}

function createPinnedLookup(hostname, resolvedAddresses) {
  const expectedHost = normalizeHostname(hostname);
  const pins = Array.from(
    new Set(
      (Array.isArray(resolvedAddresses) ? resolvedAddresses : [])
        .map((entry) => {
          if (typeof entry === "string") {
            return normalizeIpForChecks(entry);
          }
          return normalizeIpForChecks(entry?.address);
        })
        .filter((address) => isIP(address) > 0)
    )
  ).map((address) => ({
    address,
    family: isIP(address)
  }));

  if (!expectedHost || pins.length === 0) {
    return null;
  }

  let index = 0;
  return (requestedHost, options, callback) => {
    const normalizedRequestedHost = normalizeHostname(requestedHost);
    if (normalizedRequestedHost !== expectedHost) {
      callback(new Error("Outbound request host mismatch during DNS pinning"));
      return;
    }

    if (options?.all === true) {
      callback(null, pins);
      return;
    }

    const selected = pins[index % pins.length];
    index += 1;
    callback(null, selected.address, selected.family);
  };
}

async function performPinnedOutboundHttpRequest(url, options = {}) {
  const target = url instanceof URL ? url : new URL(String(url || ""));
  const method = String(options.method || "GET").toUpperCase();
  const headers = options.headers && typeof options.headers === "object" ? options.headers : {};
  const body = options.body == null ? null : Buffer.from(String(options.body), "utf-8");
  const timeoutMs = Math.max(1, parsePositiveInteger(options.timeoutMs, 10 * 1000));
  const maxResponseBytes = Math.max(
    1024,
    parsePositiveInteger(options.maxResponseBytes, 256 * 1024)
  );
  const responseSizeContext =
    options.responseSizeContext && typeof options.responseSizeContext === "object"
      ? options.responseSizeContext
      : {};
  const rejectRedirects = options.rejectRedirects !== false;
  const pinnedLookup = createPinnedLookup(target.hostname, options.resolvedAddresses);

  return await new Promise((resolve, reject) => {
    const requestImpl = target.protocol === "https:" ? httpsRequest : httpRequest;
    const requestOptions = {
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || undefined,
      method,
      path: `${target.pathname}${target.search}`,
      headers,
      lookup: pinnedLookup || undefined
    };

    if (target.protocol === "https:") {
      requestOptions.servername = target.hostname;
    }

    const request = requestImpl(requestOptions, (response) => {
      const chunks = [];
      let totalBytes = 0;

      response.on("data", (chunk) => {
        const next = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        totalBytes += next.length;
        if (totalBytes > maxResponseBytes) {
          request.destroy(
            new LoomError("PAYLOAD_TOO_LARGE", "Response body exceeds configured size limit", 413, {
              max_response_bytes: maxResponseBytes,
              ...responseSizeContext
            })
          );
          return;
        }
        chunks.push(next);
      });

      response.on("end", () => {
        const status = Number(response.statusCode || 0);
        const locationHeader = response.headers.location;
        const location = Array.isArray(locationHeader) ? locationHeader[0] : locationHeader;
        if (rejectRedirects && status >= 300 && status < 400 && location) {
          reject(
            new Error(
              `Outbound request received redirect (${status}) which is disallowed`
            )
          );
          return;
        }

        resolve({
          status,
          ok: status >= 200 && status < 300,
          headers: response.headers,
          bodyText: Buffer.concat(chunks, totalBytes).toString("utf-8")
        });
      });
    });

    const timeoutHandle = setTimeout(() => {
      const timeoutError = new Error(`Outbound request timed out after ${timeoutMs}ms`);
      timeoutError.name = "AbortError";
      request.destroy(timeoutError);
    }, timeoutMs);
    timeoutHandle.unref?.();

    request.on("error", (error) => {
      clearTimeout(timeoutHandle);
      reject(error);
    });

    request.on("close", () => {
      clearTimeout(timeoutHandle);
    });

    if (body != null) {
      request.write(body);
    }
    request.end();
  });
}

function normalizeFederationDeliverUrl(value, options = {}) {
  if (value == null || String(value).trim().length === 0) {
    return null;
  }

  let target;
  try {
    target = new URL(String(value));
  } catch {
    throw new LoomError("ENVELOPE_INVALID", "deliver_url must be a valid absolute URL", 400, {
      field: "deliver_url"
    });
  }

  if (target.username || target.password) {
    throw new LoomError("ENVELOPE_INVALID", "deliver_url must not include credentials", 400, {
      field: "deliver_url"
    });
  }

  const allowInsecureHttp = options.allowInsecureHttp === true;
  if (target.protocol !== "https:" && !(allowInsecureHttp && target.protocol === "http:")) {
    throw new LoomError("ENVELOPE_INVALID", "deliver_url must use https unless allow_insecure_http=true", 400, {
      field: "deliver_url",
      protocol: target.protocol
    });
  }

  if (options.allowPrivateNetwork !== true) {
    const hostname = target.hostname;
    if (isIP(hostname) > 0 && isPrivateOrLocalIp(hostname)) {
      throw new LoomError("CAPABILITY_DENIED", "deliver_url cannot target private or local IPs", 403, {
        field: "deliver_url",
        host: hostname
      });
    }
  }

  return target.toString();
}

function normalizeFederationIdentityResolveUrl(value, options = {}) {
  if (value == null || String(value).trim().length === 0) {
    return null;
  }

  const raw = String(value).trim();
  const placeholderToken = "__loom_identity_placeholder__";
  const hasIdentityPlaceholder = raw.includes("{identity}");
  const candidate = hasIdentityPlaceholder ? raw.replace(/\{identity\}/g, placeholderToken) : raw;

  let target;
  try {
    target = new URL(candidate);
  } catch {
    throw new LoomError("ENVELOPE_INVALID", "identity_resolve_url must be a valid absolute URL", 400, {
      field: "identity_resolve_url"
    });
  }

  if (target.username || target.password) {
    throw new LoomError("ENVELOPE_INVALID", "identity_resolve_url must not include credentials", 400, {
      field: "identity_resolve_url"
    });
  }

  const allowInsecureHttp = options.allowInsecureHttp === true;
  if (target.protocol !== "https:" && !(allowInsecureHttp && target.protocol === "http:")) {
    throw new LoomError("ENVELOPE_INVALID", "identity_resolve_url must use https unless allow_insecure_http=true", 400, {
      field: "identity_resolve_url",
      protocol: target.protocol
    });
  }

  if (options.allowPrivateNetwork !== true) {
    const hostname = target.hostname;
    if (isIP(hostname) > 0 && isPrivateOrLocalIp(hostname)) {
      throw new LoomError("CAPABILITY_DENIED", "identity_resolve_url cannot target private or local IPs", 403, {
        field: "identity_resolve_url",
        host: hostname
      });
    }
  }

  const normalized = target.toString();
  if (!hasIdentityPlaceholder) {
    return normalized;
  }
  return normalized.split(placeholderToken).join("{identity}");
}

function normalizeFederationNodeDocumentUrl(value, options = {}) {
  if (value == null || String(value).trim().length === 0) {
    return null;
  }

  let target;
  try {
    target = new URL(String(value));
  } catch {
    throw new LoomError("ENVELOPE_INVALID", "node_document_url must be a valid absolute URL", 400, {
      field: "node_document_url"
    });
  }

  if (target.username || target.password) {
    throw new LoomError("ENVELOPE_INVALID", "node_document_url must not include credentials", 400, {
      field: "node_document_url"
    });
  }

  const allowInsecureHttp = options.allowInsecureHttp === true;
  if (target.protocol !== "https:" && !(allowInsecureHttp && target.protocol === "http:")) {
    throw new LoomError("ENVELOPE_INVALID", "node_document_url must use https unless allow_insecure_http=true", 400, {
      field: "node_document_url",
      protocol: target.protocol
    });
  }

  if (options.allowPrivateNetwork !== true) {
    const hostname = target.hostname;
    if (isIP(hostname) > 0 && isPrivateOrLocalIp(hostname)) {
      throw new LoomError("CAPABILITY_DENIED", "node_document_url cannot target private or local IPs", 403, {
        field: "node_document_url",
        host: hostname
      });
    }
  }

  return target.toString();
}

function normalizeFederationProtocolCapabilitiesUrl(value, options = {}) {
  if (value == null || String(value).trim().length === 0) {
    return null;
  }

  let target;
  try {
    target = new URL(String(value));
  } catch {
    throw new LoomError("ENVELOPE_INVALID", "protocol_capabilities_url must be a valid absolute URL", 400, {
      field: "protocol_capabilities_url"
    });
  }

  if (target.username || target.password) {
    throw new LoomError("ENVELOPE_INVALID", "protocol_capabilities_url must not include credentials", 400, {
      field: "protocol_capabilities_url"
    });
  }

  const allowInsecureHttp = options.allowInsecureHttp === true;
  if (target.protocol !== "https:" && !(allowInsecureHttp && target.protocol === "http:")) {
    throw new LoomError(
      "ENVELOPE_INVALID",
      "protocol_capabilities_url must use https unless allow_insecure_http=true",
      400,
      {
        field: "protocol_capabilities_url",
        protocol: target.protocol
      }
    );
  }

  if (options.allowPrivateNetwork !== true) {
    const hostname = target.hostname;
    if (isIP(hostname) > 0 && isPrivateOrLocalIp(hostname)) {
      throw new LoomError("CAPABILITY_DENIED", "protocol_capabilities_url cannot target private or local IPs", 403, {
        field: "protocol_capabilities_url",
        host: hostname
      });
    }
  }

  return target.toString();
}

function isExpiredIso(value) {
  if (!value) {
    return false;
  }
  const parsed = parseTime(value);
  if (parsed == null) {
    return true;
  }
  return parsed <= nowMs();
}

function parseLoomIdentityDomain(identityUri) {
  return parseLoomIdentityAuthority(identityUri);
}

const FEDERATION_TRUST_MODES = new Set([
  "strict_identity_authority",
  "curated_trust_anchors",
  "public_dns_webpki"
]);

function normalizeFederationTrustMode(value, { hasTrustAnchors = false } = {}) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (!normalized) {
    return hasTrustAnchors ? "curated_trust_anchors" : "strict_identity_authority";
  }
  if (normalized === "strict" || normalized === "strict_identity") {
    return "strict_identity_authority";
  }
  if (normalized === "curated" || normalized === "trust_anchors") {
    return "curated_trust_anchors";
  }
  if (FEDERATION_TRUST_MODES.has(normalized)) {
    return normalized;
  }
  return hasTrustAnchors ? "curated_trust_anchors" : "strict_identity_authority";
}

function normalizeHexDigest(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (!normalized || !/^[a-f0-9]{64}$/.test(normalized)) {
    return null;
  }
  return normalized;
}

function normalizePemForFingerprint(value) {
  const trimmed = String(value || "").replace(/\r\n/g, "\n").trim();
  return trimmed ? `${trimmed}\n` : null;
}

function fingerprintPublicKeyPem(publicKeyPem) {
  const normalizedPem = normalizePemForFingerprint(publicKeyPem);
  if (!normalizedPem) {
    return null;
  }
  return createHash("sha256").update(normalizedPem, "utf-8").digest("hex");
}

function parseFederationTrustDnsTxtRecord(record) {
  const fields = {};
  for (const part of String(record || "")
    .split(";")
    .map((entry) => entry.trim())
    .filter(Boolean)) {
    const separator = part.indexOf("=");
    if (separator <= 0 || separator >= part.length - 1) {
      continue;
    }
    const key = part
      .slice(0, separator)
      .trim()
      .toLowerCase();
    const value = part.slice(separator + 1).trim();
    if (!key || !value) {
      continue;
    }
    fields[key] = value;
  }
  return fields;
}

function normalizeFederationTrustDnsFields(fields) {
  const normalized = fields && typeof fields === "object" ? fields : {};
  const digest = normalizeSha256Digest(
    normalized.digest || normalized.sha256 || normalized.hash || normalized.h || ""
  );
  const keysetUrl = String(normalized.keyset || normalized.ks || normalized.k || "").trim();
  const revocationsUrl = String(normalized.revocations || normalized.revocation || "").trim();
  const trustEpoch = parseOptionalNonNegativeInteger(normalized.trust_epoch || normalized.epoch);
  const version = parseOptionalNonNegativeInteger(normalized.version);
  const formatVersion = String(normalized.v || "").trim().toLowerCase();

  return {
    format_version: formatVersion || null,
    keyset_url: keysetUrl || null,
    digest_sha256: digest || null,
    revocations_url: revocationsUrl || null,
    trust_epoch: trustEpoch,
    version
  };
}

function canonicalizeSignedDocumentPayload(document) {
  const payload = {
    ...(document && typeof document === "object" ? document : {})
  };
  delete payload.signature;
  return canonicalizeJson(payload);
}

function hashCanonicalSignedDocumentPayload(document) {
  return createHash("sha256")
    .update(canonicalizeSignedDocumentPayload(document), "utf-8")
    .digest("hex");
}

function normalizeKeysetSigningKeys(value) {
  const rawKeys = Array.isArray(value?.signing_keys)
    ? value.signing_keys
    : Array.isArray(value?.keys)
      ? value.keys
      : [];

  return normalizeFederationSigningKeys(
    rawKeys.map((key) => ({
      key_id: String(key?.key_id || "").trim(),
      public_key_pem: String(key?.public_key_pem || key?.public_key || "").trim(),
      status: key?.status,
      not_before: key?.not_before || key?.valid_from || null,
      not_after: key?.not_after || key?.valid_until || key?.expires_at || null,
      revoked_at: key?.revoked_at || null
    }))
  );
}

function normalizeRevokedKeyIds(value) {
  return Array.from(
    new Set(
      (Array.isArray(value) ? value : [])
        .map((entry) => String(entry || "").trim())
        .filter(Boolean)
    )
  ).sort();
}

function parseOptionalNonNegativeInteger(value) {
  if (value == null || String(value).trim().length === 0) {
    return null;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    return null;
  }
  return parsed;
}

function normalizeDnsTxtAnswerRecords(records) {
  if (!Array.isArray(records)) {
    return [];
  }
  return records
    .map((entry) => {
      if (Array.isArray(entry)) {
        return entry.join("");
      }
      return String(entry || "");
    })
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeFederationTrustDnsResolverResult(result) {
  if (Array.isArray(result)) {
    return {
      records: normalizeDnsTxtAnswerRecords(result),
      dnssec_validated: null,
      dnssec_source: null,
      transparency: null
    };
  }

  if (!result || typeof result !== "object") {
    return {
      records: normalizeDnsTxtAnswerRecords([]),
      dnssec_validated: null,
      dnssec_source: null,
      transparency: null
    };
  }

  const answers = Array.isArray(result.answers)
    ? result.answers
    : Array.isArray(result.records)
      ? result.records
      : Array.isArray(result.txt_records)
        ? result.txt_records
        : [];

  const dnssecValidated = (() => {
    if (typeof result.dnssec_validated === "boolean") {
      return result.dnssec_validated;
    }
    if (typeof result.dnssec === "boolean") {
      return result.dnssec;
    }
    if (typeof result.ad === "boolean") {
      return result.ad;
    }
    if (typeof result.authenticated_data === "boolean") {
      return result.authenticated_data;
    }
    return null;
  })();

  const dnssecSource = (() => {
    const normalized = String(result.dnssec_source || result.resolver || result.source || "").trim();
    return normalized || null;
  })();

  const transparency = result.transparency && typeof result.transparency === "object" ? result.transparency : null;

  return {
    records: normalizeDnsTxtAnswerRecords(answers),
    dnssec_validated: dnssecValidated,
    dnssec_source: dnssecSource,
    transparency
  };
}

function normalizeSha256Digest(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (!normalized) {
    return null;
  }
  const withoutPrefix = normalized.startsWith("sha256:") ? normalized.slice("sha256:".length).trim() : normalized;
  return normalizeHexDigest(withoutPrefix);
}

function applyRevokedKeyIdsToFederationSigningKeys(signingKeys = [], revokedKeyIds = [], revokedAt = null) {
  const revokedKeySet = new Set(normalizeRevokedKeyIds(revokedKeyIds));
  if (revokedKeySet.size === 0) {
    return normalizeFederationSigningKeys(signingKeys);
  }

  const normalizedRevokedAt = revokedAt ? String(revokedAt).trim() : null;
  return normalizeFederationSigningKeys(signingKeys).map((key) => {
    if (!revokedKeySet.has(key.key_id)) {
      return key;
    }
    return {
      ...key,
      status: "revoked",
      revoked_at: key.revoked_at || normalizedRevokedAt
    };
  });
}

const IDENTITY_ENCRYPTION_KEY_ALGORITHM_ALIAS_TO_ID = new Map([["x25519", "X25519"]]);

function normalizeIdentitySigningKeys(signingKeys = []) {
  const normalized = signingKeys
    .map((key) => ({
      key_id: String(key?.key_id || "").trim(),
      public_key_pem: String(key?.public_key_pem || "").trim()
    }))
    .filter((key) => key.key_id && key.public_key_pem)
    .sort((left, right) => left.key_id.localeCompare(right.key_id));

  return normalized;
}

function normalizeIdentityEncryptionKeyAlgorithm(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (!normalized) {
    return null;
  }
  return IDENTITY_ENCRYPTION_KEY_ALGORITHM_ALIAS_TO_ID.get(normalized) || null;
}

function resolveIdentityEncryptionKeysInput(value) {
  if (Array.isArray(value?.encryption_keys)) {
    return value.encryption_keys;
  }
  if (Array.isArray(value?.public_keys?.encryption)) {
    return value.public_keys.encryption;
  }
  return [];
}

function normalizeIdentityEncryptionKeys(encryptionKeys = []) {
  const normalized = [];
  for (const key of Array.isArray(encryptionKeys) ? encryptionKeys : []) {
    const keyId = String(key?.key_id || "").trim();
    const algorithm = normalizeIdentityEncryptionKeyAlgorithm(key?.algorithm);
    const publicKey = String(key?.public_key || "").trim();
    const publicKeyPem = String(key?.public_key_pem || "").trim();
    if (!keyId || !algorithm || (!publicKey && !publicKeyPem)) {
      continue;
    }
    normalized.push({
      key_id: keyId,
      algorithm,
      public_key: publicKey || null,
      public_key_pem: publicKeyPem || null,
      status: String(key?.status || "active")
        .trim()
        .toLowerCase() || "active",
      not_before: key?.not_before ? String(key.not_before).trim() : null,
      not_after: key?.not_after ? String(key.not_after).trim() : null,
      revoked_at: key?.revoked_at ? String(key.revoked_at).trim() : null
    });
  }
  normalized.sort((left, right) => left.key_id.localeCompare(right.key_id));
  return normalized;
}

function buildIdentityRegistrationDocument({
  identity,
  type = "human",
  displayName = null,
  signingKeys = [],
  encryptionKeys = [],
  agentInfo = null
}) {
  const document = {
    loom: "1.1",
    id: identity,
    type: String(type || "human"),
    display_name: String(displayName || identity),
    signing_keys: normalizeIdentitySigningKeys(signingKeys)
  };

  const normalizedEncryptionKeys = normalizeIdentityEncryptionKeys(encryptionKeys);
  if (normalizedEncryptionKeys.length > 0) {
    document.encryption_keys = normalizedEncryptionKeys;
  }

  if (agentInfo && typeof agentInfo === "object" && String(type || "human") === "agent") {
    document.agent_info = agentInfo;
  }

  return document;
}

function hashIdentityRegistrationDocument(documentPayload) {
  return createHash("sha256")
    .update(canonicalizeJson(documentPayload), "utf-8")
    .digest("hex");
}

function buildIdentityRegistrationProofMessage({ identity, keyId, documentHash, nonce }) {
  return [
    "loom.identity.register.v1",
    String(identity || ""),
    String(keyId || ""),
    String(documentHash || ""),
    String(nonce || "")
  ].join("\n");
}

function toThreadSummary(thread) {
  const pendingParentCount = Number(thread.pending_parent_count || 0);
  return {
    id: thread.id,
    root_envelope_id: thread.root_envelope_id,
    subject: thread.subject,
    state: thread.state,
    created_at: thread.created_at,
    updated_at: thread.updated_at,
    participants: thread.participants,
    labels: thread.labels,
    cap_epoch: thread.cap_epoch,
    encryption: thread.encryption,
    pending_parent_count: pendingParentCount,
    has_pending_parents: pendingParentCount > 0,
    snapshot: thread.snapshot || null,
    context_budgets: thread.context_budgets || null,
    workflow: thread.workflow || null
  };
}

function normalizeGrants(grants) {
  if (!Array.isArray(grants) || grants.length === 0) {
    throw new LoomError("ENVELOPE_INVALID", "Capability grants must be a non-empty array", 400, {
      field: "grants"
    });
  }

  const normalized = Array.from(
    new Set(
      grants
        .map((grant) => String(grant || "").trim())
        .filter((grant) => grant.length > 0)
    )
  );

  if (normalized.length === 0) {
    throw new LoomError("ENVELOPE_INVALID", "Capability grants must include at least one grant", 400, {
      field: "grants"
    });
  }

  return normalized;
}

function canonicalizeFederationReceipt(receipt) {
  const acceptedIds = Array.isArray(receipt?.accepted_envelope_ids)
    ? receipt.accepted_envelope_ids.map((id) => String(id || "").trim()).filter(Boolean)
    : [];

  return [
    String(receipt?.loom || ""),
    String(receipt?.type || ""),
    String(receipt?.delivery_id || ""),
    String(receipt?.sender_node || ""),
    String(receipt?.recipient_node || ""),
    String(receipt?.status || ""),
    String(receipt?.accepted_count ?? ""),
    acceptedIds.join(","),
    String(receipt?.timestamp || "")
  ].join("\n");
}

function canonicalizeFederationRequestSignatureInput({
  method,
  path,
  bodyHash,
  timestamp,
  nonce,
  trustEpoch = ""
}) {
  return [
    String(method || "POST").toUpperCase(),
    String(path || ""),
    String(bodyHash || ""),
    String(timestamp || ""),
    String(nonce || ""),
    String(trustEpoch || "")
  ].join("\n");
}

function canonicalizeDeliveryWrapper(wrapper) {
  const canonical = {};
  for (const [key, value] of Object.entries(wrapper || {})) {
    if (key !== "signature") {
      canonical[key] = value;
    }
  }
  return canonicalizeJson(canonical);
}

function deliveryWrapperKey(envelopeId, recipientIdentity) {
  return `${String(envelopeId || "").trim()}:${String(recipientIdentity || "").trim()}`;
}

function hashCapabilityPresentationToken(tokenValue) {
  return createHash("sha256")
    .update(`loom.capability.v1\n${String(tokenValue || "").trim()}`, "utf-8")
    .digest("hex");
}

function normalizePortableCapabilityGrants(grants) {
  return Array.from(
    new Set(
      (Array.isArray(grants) ? grants : [])
        .map((grant) => String(grant || "").trim())
        .filter(Boolean)
    )
  ).sort();
}

function buildPortableCapabilityTokenPayload(token) {
  const epoch = Number(token?.epoch);
  return {
    loom: "1.1",
    type: "capability_token",
    id: String(token?.id || "").trim(),
    thread_id: String(token?.thread_id || "").trim(),
    issued_by: String(token?.issued_by || "").trim(),
    issued_to: String(token?.issued_to || "").trim(),
    issuer_node: String(token?.issuer_node || "").trim(),
    created_at: String(token?.created_at || "").trim(),
    expires_at: token?.expires_at ? String(token.expires_at).trim() : null,
    single_use: token?.single_use === true,
    epoch: Number.isInteger(epoch) ? epoch : epoch,
    grants: normalizePortableCapabilityGrants(token?.grants)
  };
}

function canonicalizePortableCapabilityToken(token) {
  return canonicalizeJson(buildPortableCapabilityTokenPayload(token));
}

function mergeFederationSigningKeys(baseKeys = [], nextKeys = []) {
  const merged = new Map();
  for (const key of [...baseKeys, ...nextKeys]) {
    const keyId = String(key?.key_id || "").trim();
    const publicKeyPem = String(key?.public_key_pem || "").trim();
    if (!keyId || !publicKeyPem) {
      continue;
    }

    const status = String(key?.status || "").trim().toLowerCase() || "active";
    const notBefore = key?.not_before || key?.valid_from || null;
    const notAfter = key?.not_after || key?.valid_until || key?.expires_at || null;
    const revokedAt = key?.revoked_at || null;

    merged.set(keyId, {
      key_id: keyId,
      public_key_pem: publicKeyPem,
      status,
      not_before: notBefore ? String(notBefore).trim() : null,
      not_after: notAfter ? String(notAfter).trim() : null,
      revoked_at: revokedAt ? String(revokedAt).trim() : null
    });
  }
  return Array.from(merged.values());
}

function normalizeFederationSigningKeys(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return mergeFederationSigningKeys([], value);
}

function getFederationNodeSigningKeys(node) {
  const keys = normalizeFederationSigningKeys(node?.signing_keys);
  if (keys.length > 0) {
    return keys;
  }

  const keyId = String(node?.key_id || "").trim();
  const publicKeyPem = String(node?.public_key_pem || "").trim();
  if (!keyId || !publicKeyPem) {
    return [];
  }

  return [
    {
      key_id: keyId,
      public_key_pem: publicKeyPem
    }
  ];
}

function resolveFederationNodeSigningKey(node, keyId) {
  const normalizedKeyId = String(keyId || "").trim();
  if (!normalizedKeyId) {
    return null;
  }
  const keys = getFederationNodeSigningKeys(node);
  const key = keys.find((candidate) => candidate.key_id === normalizedKeyId) || null;
  if (!key) {
    return null;
  }
  if (!isSigningKeyUsableAt(key)) {
    return null;
  }
  return key;
}

function extractFederationSigningKeysFromNodeDocument(nodeDocument) {
  const federation = nodeDocument?.federation && typeof nodeDocument.federation === "object" ? nodeDocument.federation : {};
  const fromSigningKeys = normalizeFederationSigningKeys(federation.signing_keys);
  const fromLegacy =
    String(federation.signing_key_id || "").trim() && String(federation.public_key_pem || "").trim()
      ? [
          {
            key_id: String(federation.signing_key_id || "").trim(),
            public_key_pem: String(federation.public_key_pem || "").trim()
          }
        ]
      : [];
  return mergeFederationSigningKeys(fromSigningKeys, fromLegacy);
}

const THREAD_OP_TO_GRANT = {
  "thread.add_participant@v1": "add_participant",
  "thread.remove_participant@v1": "remove_participant",
  "thread.update@v1": "label",
  "thread.resolve@v1": "resolve",
  "thread.archive@v1": "archive",
  "thread.lock@v1": "lock",
  "thread.reopen@v1": "admin",
  "thread.delegate@v1": "delegate",
  "thread.fork@v1": "fork",
  "thread.merge@v1": "merge",
  "thread.link@v1": "forward",
  "encryption.epoch@v1": "admin",
  "encryption.rotate@v1": "admin",
  "capability.revoked@v1": "admin",
  "capability.spent@v1": "admin"
};

const ENVELOPE_TYPE_DELEGATION_ACTIONS = {
  message: ["message.send@v1", "message.general@v1"],
  task: ["task.send@v1", "task.general@v1"],
  approval: ["approval.send@v1", "approval.general@v1"],
  event: ["event.send@v1", "event.general@v1"],
  notification: ["notification.send@v1", "notification.general@v1"],
  handoff: ["handoff.send@v1", "handoff.general@v1"],
  data: ["data.send@v1", "data.general@v1"],
  receipt: ["receipt.send@v1", "receipt.general@v1"],
  workflow: ["workflow.send@v1", "workflow.general@v1"],
  thread_op: ["thread.op.execute@v1"]
};

const WEBHOOK_DELIVERY_ACTIONS = new Set([
  "email.outbox.process.delivered",
  "email.outbox.process.failed",
  "federation.outbox.process.delivered",
  "federation.outbox.process.failed",
  "email.outbox.requeue",
  "federation.outbox.requeue"
]);

function assertTransition(thread, allowedFrom, nextState) {
  if (!allowedFrom.includes(thread.state)) {
    throw new LoomError("STATE_TRANSITION_INVALID", `Cannot transition thread ${thread.id} from ${thread.state} to ${nextState}`, 409, {
      thread_id: thread.id,
      current_state: thread.state,
      next_state: nextState
    });
  }
}

export class LoomStore {
  constructor(options = {}) {
    this.nodeId = options.nodeId || "loom-node.local";
    this.systemSigningKeyId = options.systemSigningKeyId || "k_sign_system_1";
    this.systemSigningPrivateKeyPem = options.systemSigningPrivateKeyPem || null;
    this.systemSigningPublicKeyPem = options.systemSigningPublicKeyPem || null;
    this.requireExternalSigningKeys = options.requireExternalSigningKeys === true;
    this.requireDistinctFederationSigningKey = options.requireDistinctFederationSigningKey === true;
    this.federationSigningKeyId = options.federationSigningKeyId || "k_node_sign_local_1";
    this.federationSigningPrivateKeyPem = options.federationSigningPrivateKeyPem || null;
    this.federationRequireProtocolCapabilities = options.federationRequireProtocolCapabilities === true;
    this.federationRequireE2eeProfileOverlap = options.federationRequireE2eeProfileOverlap === true;
    this.federationRequireTrustModeParity = options.federationRequireTrustModeParity === true;
    this.e2eeProfileMigrationAllowlist = normalizeE2eeProfileMigrationAllowlist(
      options.e2eeProfileMigrationAllowlist
    );
    this.federationRequireSignedReceipts = options.federationRequireSignedReceipts === true;
    this.identityRegistrationProofRequired = options.identityRegistrationProofRequired === true;
    this.identityRegistrationChallengeTtlMs = Math.max(
      30 * 1000,
      parsePositiveInteger(options.identityRegistrationChallengeTtlMs, 2 * 60 * 1000)
    );
    this.remoteIdentityTtlMs = Math.max(
      60 * 1000,
      parsePositiveInteger(options.remoteIdentityTtlMs, 24 * 60 * 60 * 1000)
    );
    this.federationResolveRemoteIdentities = options.federationResolveRemoteIdentities !== false;
    this.federationRequireSignedRemoteIdentity = options.federationRequireSignedRemoteIdentity !== false;
    this.federationRemoteIdentityFetchTimeoutMs = Math.max(
      500,
      parsePositiveInteger(options.federationRemoteIdentityFetchTimeoutMs, 5000)
    );
    this.federationRemoteIdentityMaxResponseBytes = Math.max(
      1024,
      parsePositiveInteger(options.federationRemoteIdentityMaxResponseBytes, 256 * 1024)
    );
    this.federationDeliverTimeoutMs = Math.max(
      500,
      parsePositiveInteger(options.federationDeliverTimeoutMs, 10 * 1000)
    );
    this.federationDeliverMaxResponseBytes = Math.max(
      1024,
      parsePositiveInteger(options.federationDeliverMaxResponseBytes, 256 * 1024)
    );
    this.webhookMaxResponseBytes = Math.max(
      1024,
      parsePositiveInteger(options.webhookMaxResponseBytes, 256 * 1024)
    );
    this.denyMetadataHosts = options.denyMetadataHosts !== false;
    this.bridgeInboundRequireAuthResults = options.bridgeInboundRequireAuthResults === true;
    this.bridgeInboundRequireDmarcPass = options.bridgeInboundRequireDmarcPass === true;
    this.bridgeInboundRejectOnAuthFailure = options.bridgeInboundRejectOnAuthFailure === true;
    this.bridgeInboundQuarantineOnAuthFailure = options.bridgeInboundQuarantineOnAuthFailure !== false;
    this.bridgeInboundAllowPayloadAuthResults = options.bridgeInboundAllowPayloadAuthResults !== false;
    this.bridgeInboundHeaderAllowlist = normalizeBridgeInboundHeaderAllowlist(
      options.bridgeInboundHeaderAllowlist
    );
    this.inboundContentFilterEnabled = options.inboundContentFilterEnabled !== false;
    this.inboundContentFilterRejectMalware = options.inboundContentFilterRejectMalware !== false;
    this.inboundContentFilterSpamThreshold = Math.max(
      1,
      parsePositiveInteger(options.inboundContentFilterSpamThreshold, 3)
    );
    this.inboundContentFilterPhishThreshold = Math.max(
      1,
      parsePositiveInteger(options.inboundContentFilterPhishThreshold, 3)
    );
    this.inboundContentFilterQuarantineThreshold = Math.max(
      1,
      parsePositiveInteger(options.inboundContentFilterQuarantineThreshold, 4)
    );
    this.inboundContentFilterRejectThreshold = Math.max(
      this.inboundContentFilterQuarantineThreshold + 1,
      parsePositiveInteger(options.inboundContentFilterRejectThreshold, 7)
    );
    this.inboundContentFilterProfileDefault = normalizeInboundContentFilterProfile(
      options.inboundContentFilterProfileDefault,
      "balanced"
    );
    this.inboundContentFilterProfileBridge = normalizeInboundContentFilterProfile(
      options.inboundContentFilterProfileBridge,
      this.inboundContentFilterProfileDefault
    );
    this.inboundContentFilterProfileFederation = normalizeInboundContentFilterProfile(
      options.inboundContentFilterProfileFederation,
      "agent"
    );
    this.messageRetentionDays = Math.max(0, parseNonNegativeInteger(options.messageRetentionDays, 0));
    this.blobRetentionDays = Math.max(0, parseNonNegativeInteger(options.blobRetentionDays, 0));
    this.requireStateEncryptionAtRest = options.requireStateEncryptionAtRest === true;
    this.stateEncryptionKey = normalizeStateEncryptionKey(options.stateEncryptionKey);
    this.auditHmacKey =
      typeof options.auditHmacKey === "string" && options.auditHmacKey.trim().length > 0
        ? options.auditHmacKey.trim()
        : null;
    this.auditRequireMacValidation = options.auditRequireMacValidation === true;
    this.auditValidateChain = options.auditValidateChain !== false;
    if (this.auditRequireMacValidation && !this.auditHmacKey) {
      throw new Error("Audit MAC validation requires an audit HMAC key");
    }
    this.localIdentityDomain =
      typeof options.localIdentityDomain === "string" && options.localIdentityDomain.trim()
        ? options.localIdentityDomain.trim().toLowerCase()
        : null;
    this.federationTrustAnchorBindings = parseTrustAnchorBindings(options.federationTrustAnchorBindings);
    this.federationTrustMode = normalizeFederationTrustMode(options.federationTrustMode, {
      hasTrustAnchors: this.federationTrustAnchorBindings.size > 0
    });
    this.federationTrustFailClosed = parseBoolean(options.federationTrustFailClosed, true);
    this.federationTrustMaxClockSkewMs = Math.max(
      1000,
      parsePositiveInteger(options.federationTrustMaxClockSkewMs, 5 * 60 * 1000)
    );
    this.federationTrustKeysetMaxAgeMs = Math.max(
      60 * 1000,
      parsePositiveInteger(options.federationTrustKeysetMaxAgeMs, 24 * 60 * 60 * 1000)
    );
    this.federationTrustKeysetPublishTtlMs = Math.max(
      60 * 1000,
      parsePositiveInteger(options.federationTrustKeysetPublishTtlMs, 24 * 60 * 60 * 1000)
    );
    this.federationTrustDnsTxtLabel =
      typeof options.federationTrustDnsTxtLabel === "string" && options.federationTrustDnsTxtLabel.trim().length > 0
        ? options.federationTrustDnsTxtLabel.trim()
        : "_loomfed";
    this.federationTrustDnsTxtResolver =
      typeof options.federationTrustDnsTxtResolver === "function" ? options.federationTrustDnsTxtResolver : resolveTxt;
    this.federationTrustRequireDnssec = parseBoolean(
      options.federationTrustRequireDnssec,
      this.federationTrustMode === "public_dns_webpki"
    );
    this.federationTrustTransparencyMode = "local_append_only";
    this.federationTrustRequireTransparency = parseBoolean(
      options.federationTrustRequireTransparency,
      this.federationTrustMode === "public_dns_webpki"
    );
    this.federationTrustLocalEpoch = Math.max(
      0,
      parseNonNegativeInteger(options.federationTrustLocalEpoch, 1)
    );
    this.federationTrustKeysetVersion = Math.max(
      0,
      parseNonNegativeInteger(options.federationTrustKeysetVersion, 1)
    );
    this.federationTrustRevokedKeyIds = normalizeRevokedKeyIds(options.federationTrustRevokedKeyIds);
    this.federationOutboundHostAllowlist = normalizeHostnameAllowlist(options.federationOutboundHostAllowlist);
    this.federationBootstrapHostAllowlist = normalizeHostnameAllowlist(options.federationBootstrapHostAllowlist);
    this.webhookOutboundHostAllowlist = normalizeHostnameAllowlist(options.webhookOutboundHostAllowlist);
    this.remoteIdentityHostAllowlist = normalizeHostnameAllowlist(options.remoteIdentityHostAllowlist);
    this.reservedSigningKeyIds = new Set(
      [
        this.systemSigningKeyId,
        this.federationSigningKeyId,
        ...(Array.isArray(options.reservedSigningKeyIds) ? options.reservedSigningKeyIds : [])
      ]
        .map((value) => String(value || "").trim())
        .filter(Boolean)
    );
    this.dataDir = options.dataDir || null;
    this.stateFile = this.dataDir ? join(this.dataDir, "state.json") : null;
    this.auditFile = this.dataDir ? join(this.dataDir, "audit.log.jsonl") : null;
    this.inboundContentFilterDecisionLogEnabled = options.inboundContentFilterDecisionLogEnabled === true;
    const inboundContentFilterDecisionLogFileRaw =
      typeof options.inboundContentFilterDecisionLogFile === "string"
        ? options.inboundContentFilterDecisionLogFile.trim()
        : "";
    this.inboundContentFilterDecisionLogFile =
      inboundContentFilterDecisionLogFileRaw || (this.dataDir ? join(this.dataDir, "content-filter-decisions.jsonl") : null);
    this.inboundContentFilterDecisionLogSalt =
      typeof options.inboundContentFilterDecisionLogSalt === "string" &&
      options.inboundContentFilterDecisionLogSalt.trim().length > 0
        ? options.inboundContentFilterDecisionLogSalt.trim()
        : this.nodeId;
    if (this.requireStateEncryptionAtRest && this.stateFile && !this.stateEncryptionKey) {
      throw new Error("requireStateEncryptionAtRest=true requires stateEncryptionKey");
    }
    this.persistenceAdapter = options.persistenceAdapter || null;
    this.outboxClaimLeaseMs = Math.max(
      5 * 1000,
      parsePositiveInteger(options.outboxClaimLeaseMs, 60 * 1000)
    );
    this.outboxWorkerId =
      typeof options.outboxWorkerId === "string" && options.outboxWorkerId.trim().length > 0
        ? options.outboxWorkerId.trim()
        : `worker_${generateUlid()}`;

    this.identities = new Map();
    this.remoteIdentities = new Map();
    this.publicKeysById = new Map();
    this.keyOwnerById = new Map();
    this.encryptionKeysById = new Map();
    this.encryptionKeyOwnerById = new Map();
    this.envelopesById = new Map();
    this.threadsById = new Map();

    this.authChallenges = new Map();
    this.identityRegistrationChallenges = new Map();
    this.accessTokens = new Map();
    this.refreshTokens = new Map();
    this.capabilitiesById = new Map();
    this.capabilityIdBySecretHash = new Map();
    this.consumedPortableCapabilityIds = new Set();
    this.delegationsById = new Map();
    this.revokedDelegationIds = new Set();
    this.blobsById = new Map();
    this.knownNodesById = new Map();
    this.federationNonceCache = new Map();
    this.federationOutboxById = new Map();
    this.emailOutboxById = new Map();
    this.deliveryWrappersByEnvelopeAndIdentity = new Map();
    this.webhooksById = new Map();
    this.webhookOutboxById = new Map();
    this.emailMessageIndexById = new Map();
    this.auditEntries = [];
    this.auditHeadHash = null;
    this.idempotencyByKey = new Map();
    this.idempotencyTtlMs = Math.max(1000, parsePositiveInteger(options.idempotencyTtlMs, 24 * 60 * 60 * 1000));
    this.idempotencyMaxEntries = Math.max(100, parsePositiveInteger(options.idempotencyMaxEntries, 10000));
    this.consumedCapabilityMaxEntries = Math.max(100, parsePositiveInteger(options.consumedCapabilityMaxEntries, 50000));
    this.revokedDelegationMaxEntries = Math.max(100, parsePositiveInteger(options.revokedDelegationMaxEntries, 50000));
    this.maxLocalIdentities = Math.max(0, parseNonNegativeInteger(options.maxLocalIdentities, 10000));
    this.maxRemoteIdentities = Math.max(0, parseNonNegativeInteger(options.maxRemoteIdentities, 50000));
    this.maxDelegationsPerIdentity = Math.max(0, parseNonNegativeInteger(options.maxDelegationsPerIdentity, 500));
    this.maxDelegationsTotal = Math.max(0, parseNonNegativeInteger(options.maxDelegationsTotal, 100000));
    this.blobMaxBytes = Math.max(1024, parsePositiveInteger(options.blobMaxBytes, 25 * 1024 * 1024));
    this.blobMaxPartBytes = Math.max(1024, parsePositiveInteger(options.blobMaxPartBytes, 2 * 1024 * 1024));
    this.blobMaxParts = Math.max(1, parsePositiveInteger(options.blobMaxParts, 64));
    this.envelopeDailyMax = Math.max(0, parseNonNegativeInteger(options.envelopeDailyMax, 0));
    this.threadRecipientFanoutMax = Math.max(0, parseNonNegativeInteger(options.threadRecipientFanoutMax, 0));
    this.blobDailyCountMax = Math.max(0, parseNonNegativeInteger(options.blobDailyCountMax, 0));
    this.blobDailyBytesMax = Math.max(0, parseNonNegativeInteger(options.blobDailyBytesMax, 0));
    this.blobIdentityTotalBytesMax = Math.max(0, parseNonNegativeInteger(options.blobIdentityTotalBytesMax, 0));
    this.outboxBackpressureMax = Math.max(0, parseNonNegativeInteger(options.outboxBackpressureMax, 0));
    this.replayMode = ["strict", "sliding_window"].includes(options.replayMode) ? options.replayMode : "strict";
    this.threadLimits = {
      max_envelopes_per_thread: Math.max(0, parseNonNegativeInteger(options.threadMaxEnvelopesPerThread, 10000)),
      max_pending_parents: Math.max(0, parseNonNegativeInteger(options.threadMaxPendingParents, 500))
    };
    this.loopProtection = {
      max_hop_count: Math.max(1, Math.min(parsePositiveInteger(options.loopMaxHopCount, 20), 255)),
      max_agent_envelopes_per_thread_window: Math.max(1, parsePositiveInteger(options.loopAgentWindowMax, 50)),
      agent_window_ms: Math.max(1000, parsePositiveInteger(options.loopAgentWindowMs, 60000))
    };
    this.mcpClientEnabled = options.mcpClientEnabled !== false;
    this.mcpToolRegistry = null;
    this._mcpServiceKeys = null;
    this.identityEnvelopeUsageByDay = new Map();
    this.identityBlobUsageByDay = new Map();
    this.identityBlobTotalBytes = new Map();
    this.federationInboundRateWindowMs = Math.max(
      1000,
      parsePositiveInteger(options.federationNodeRateWindowMs, 60 * 1000)
    );
    this.federationInboundRateMax = Math.max(1, parsePositiveInteger(options.federationNodeRateMax, 120));
    this.federationInboundMaxEnvelopes = Math.max(
      1,
      Math.min(parsePositiveInteger(options.federationInboundMaxEnvelopes, 100), 5000)
    );
    this.federationGlobalInboundRateWindowMs = Math.max(
      1000,
      parsePositiveInteger(options.federationGlobalRateWindowMs, 60 * 1000)
    );
    this.federationGlobalInboundRateMax = Math.max(
      1,
      parsePositiveInteger(options.federationGlobalRateMax, 1000)
    );
    this.federationInboundRateByNode = new Map();
    this.federationInboundGlobalRate = {
      count: 0,
      window_started_at: 0
    };
    this.federationAbuseAutoPolicyEnabled = options.federationAbuseAutoPolicyEnabled !== false;
    this.federationDistributedGuardsEnabled = options.federationDistributedGuardsEnabled !== false;
    this.federationAbuseWindowMs = Math.max(
      1000,
      parsePositiveInteger(options.federationAbuseWindowMs, 5 * 60 * 1000)
    );
    this.federationAbuseQuarantineThreshold = Math.max(
      1,
      parsePositiveInteger(options.federationAbuseQuarantineThreshold, 3)
    );
    this.federationAbuseDenyThreshold = Math.max(
      this.federationAbuseQuarantineThreshold + 1,
      parsePositiveInteger(options.federationAbuseDenyThreshold, 6)
    );
    this.federationAutoPolicyDurationMs = Math.max(
      1000,
      parsePositiveInteger(options.federationAutoPolicyDurationMs, 30 * 60 * 1000)
    );
    this.federationChallengeEscalationEnabled = options.federationChallengeEscalationEnabled === true;
    this.federationChallengeThreshold = Math.max(
      1,
      parsePositiveInteger(
        options.federationChallengeThreshold,
        Math.max(2, this.federationAbuseQuarantineThreshold)
      )
    );
    this.federationChallengeDurationMs = Math.max(
      1000,
      parsePositiveInteger(options.federationChallengeDurationMs, 15 * 60 * 1000)
    );
    this.federationInboundAbuseByNode = new Map();
    this.federationChallengesByNode = new Map();
    this.identityRateWindowMs = Math.max(
      1000,
      parsePositiveInteger(options.identityRateWindowMs, 60 * 1000)
    );
    this.identityRateDefaultMax = Math.max(
      1,
      parsePositiveInteger(options.identityRateDefaultMax, 2000)
    );
    this.identityRateSensitiveMax = Math.max(
      1,
      parsePositiveInteger(options.identityRateSensitiveMax, 400)
    );
    this.identityRateByBucket = new Map();
    this.persistenceQueue = [];
    this.persistenceFlushInProgress = false;
    this.persistenceWritesTotal = 0;
    this.persistenceWritesSucceeded = 0;
    this.persistenceWritesFailed = 0;
    this.persistenceLastError = null;
    this.persistenceLastSyncAt = null;
    this.persistenceHydratedAt = null;
    this.traceContextStorage = new AsyncLocalStorage();
    this.federationPublishedKeysetsByDomain = new Map();
    this.federationPublishedRevocationsByDomain = new Map();
    this.inboundContentFilterStats = createInboundContentFilterStats();
    this.inboundContentFilterConfigVersion = 1;
    this.inboundContentFilterConfigUpdatedAt = nowIso();
    this.inboundContentFilterConfigUpdatedBy = "system";
    this.inboundContentFilterConfigCanary = null;
    this.inboundContentFilterConfigRollback = null;

    // ── Protocol module configuration ──────────────────────────────────────
    this.retentionPolicies = normalizeRetentionPolicies(
      Array.isArray(options.retentionPolicies) ? options.retentionPolicies : DEFAULT_RETENTION_POLICIES
    );
    this.channelRules = normalizeChannelRules(options.channelRules || []);
    this.autoresponderRules = new Map(); // keyed by identity URI
    this.autoresponderSentHistory = new Map(); // keyed by identity URI → Map(sender → timestamp)
    this.eventLog = createEventLog(
      Math.max(60000, parsePositiveInteger(options.eventLogRetentionMs, 7 * 24 * 60 * 60 * 1000))
    );

    this.initializeSystemSigningKeys();

    if (this.dataDir) {
      mkdirSync(this.dataDir, { recursive: true });
      this.loadStateFromDisk();
      this.loadAuditFromDisk();
    }

    this.ensureSystemSigningKeyRegistered();
  }

  buildTraceContext(patch = {}) {
    const existing = this.traceContextStorage.getStore();
    const context = {
      trace_id: normalizeTraceField(patch.trace_id ?? existing?.trace_id ?? patch.request_id ?? existing?.request_id),
      request_id: normalizeTraceField(patch.request_id ?? existing?.request_id),
      trace_source: normalizeTraceField(patch.trace_source ?? existing?.trace_source),
      worker: normalizeTraceField(patch.worker ?? existing?.worker),
      route: normalizeTraceField(patch.route ?? existing?.route),
      method: normalizeTraceField(patch.method ?? existing?.method),
      actor: normalizeTraceField(patch.actor ?? existing?.actor)
    };

    if (!context.trace_id && !context.request_id && !context.trace_source && !context.worker) {
      return null;
    }
    return context;
  }

  runWithTraceContext(contextPatch, callback) {
    if (typeof callback !== "function") {
      throw new Error("runWithTraceContext requires a callback function");
    }

    const nextContext = this.buildTraceContext(contextPatch);
    if (!nextContext) {
      return callback();
    }
    return this.traceContextStorage.run(nextContext, callback);
  }

  getCurrentTraceContext() {
    const context = this.traceContextStorage.getStore();
    return context && typeof context === "object" ? context : null;
  }

  getCurrentRequestId() {
    const context = this.getCurrentTraceContext();
    return context?.request_id || null;
  }

  initializeSystemSigningKeys() {
    if (this.requireExternalSigningKeys) {
      if (!this.systemSigningPrivateKeyPem) {
        throw new Error("System signing private key must be externally provisioned when requireExternalSigningKeys=true");
      }
      if (!this.systemSigningPublicKeyPem) {
        this.systemSigningPublicKeyPem = derivePublicKeyPemFromPrivateKeyPem(this.systemSigningPrivateKeyPem);
      }
      if (!this.federationSigningPrivateKeyPem) {
        throw new Error(
          "Federation signing private key must be externally provisioned when requireExternalSigningKeys=true"
        );
      }
    } else {
      if (!this.systemSigningPrivateKeyPem || !this.systemSigningPublicKeyPem) {
        const generated = generateSigningKeyPair();
        if (!this.systemSigningPrivateKeyPem) {
          this.systemSigningPrivateKeyPem = generated.privateKeyPem;
        }
        if (!this.systemSigningPublicKeyPem) {
          this.systemSigningPublicKeyPem = generated.publicKeyPem;
        }
      }

      if (!this.federationSigningPrivateKeyPem) {
        this.federationSigningPrivateKeyPem = this.systemSigningPrivateKeyPem;
      }
    }

    if (this.requireDistinctFederationSigningKey) {
      const sameKeyMaterial =
        String(this.federationSigningPrivateKeyPem || "").trim() ===
        String(this.systemSigningPrivateKeyPem || "").trim();
      if (sameKeyMaterial) {
        throw new Error(
          "Federation signing key must be distinct from system signing key when requireDistinctFederationSigningKey=true"
        );
      }
    }
  }

  ensureSystemSigningKeyRegistered() {
    if (this.systemSigningPublicKeyPem) {
      this.publicKeysById.set(this.systemSigningKeyId, this.systemSigningPublicKeyPem);
      this.keyOwnerById.set(this.systemSigningKeyId, "__loom_system__");
    }
  }

  applyIdentitySigningKeys(identityId, signingKeys = []) {
    for (const key of Array.isArray(signingKeys) ? signingKeys : []) {
      const keyId = String(key?.key_id || "").trim();
      const publicKeyPem = String(key?.public_key_pem || "").trim();
      if (!keyId || !publicKeyPem) {
        continue;
      }
      this.publicKeysById.set(keyId, publicKeyPem);
      this.keyOwnerById.set(keyId, identityId);
    }
  }

  applyIdentityEncryptionKeys(identityId, encryptionKeys = []) {
    for (const key of Array.isArray(encryptionKeys) ? encryptionKeys : []) {
      const keyId = String(key?.key_id || "").trim();
      const algorithm = normalizeIdentityEncryptionKeyAlgorithm(key?.algorithm);
      const publicKey = String(key?.public_key || "").trim();
      const publicKeyPem = String(key?.public_key_pem || "").trim();
      if (!keyId || !algorithm || (!publicKey && !publicKeyPem)) {
        continue;
      }
      this.encryptionKeysById.set(keyId, {
        key_id: keyId,
        algorithm,
        public_key: publicKey || null,
        public_key_pem: publicKeyPem || null,
        status: String(key?.status || "active")
          .trim()
          .toLowerCase() || "active",
        not_before: key?.not_before ? String(key.not_before).trim() : null,
        not_after: key?.not_after ? String(key.not_after).trim() : null,
        revoked_at: key?.revoked_at ? String(key.revoked_at).trim() : null
      });
      this.encryptionKeyOwnerById.set(keyId, identityId);
    }
  }

  removeIdentitySigningKeys(identityId, signingKeys = []) {
    for (const key of Array.isArray(signingKeys) ? signingKeys : []) {
      const keyId = String(key?.key_id || "").trim();
      if (!keyId) {
        continue;
      }
      const owner = this.keyOwnerById.get(keyId);
      if (owner === identityId) {
        this.keyOwnerById.delete(keyId);
        this.publicKeysById.delete(keyId);
      }
    }
  }

  removeIdentityEncryptionKeys(identityId, encryptionKeys = []) {
    for (const key of Array.isArray(encryptionKeys) ? encryptionKeys : []) {
      const keyId = String(key?.key_id || "").trim();
      if (!keyId) {
        continue;
      }
      const owner = this.encryptionKeyOwnerById.get(keyId);
      if (owner === identityId) {
        this.encryptionKeyOwnerById.delete(keyId);
        this.encryptionKeysById.delete(keyId);
      }
    }
  }

  rebuildIdentityKeyIndexes() {
    this.publicKeysById = new Map();
    this.keyOwnerById = new Map();
    this.encryptionKeysById = new Map();
    this.encryptionKeyOwnerById = new Map();
    this.ensureSystemSigningKeyRegistered();

    for (const identityDoc of this.identities.values()) {
      this.applyIdentitySigningKeys(identityDoc.id, identityDoc.signing_keys);
      this.applyIdentityEncryptionKeys(identityDoc.id, identityDoc.encryption_keys);
    }

    for (const identityDoc of this.remoteIdentities.values()) {
      this.applyIdentitySigningKeys(identityDoc.id, identityDoc.signing_keys);
      this.applyIdentityEncryptionKeys(identityDoc.id, identityDoc.encryption_keys);
    }
  }

  toDailyQuotaBucket(timestamp) {
    const parsed = parseTime(timestamp);
    const date = parsed == null ? new Date() : new Date(parsed);
    return date.toISOString().slice(0, 10);
  }

  buildIdentityDailyQuotaKey(identityUri, dayBucket) {
    const normalizedIdentity = this.normalizeIdentityReference(identityUri);
    const normalizedDayBucket = String(dayBucket || "").trim();
    if (!normalizedIdentity || !normalizedDayBucket) {
      return null;
    }
    return `${normalizedDayBucket}|${normalizedIdentity}`;
  }

  cleanupDailyQuotaMap(map, maxAgeDays = 8) {
    const maxAgeMs = Math.max(1, Number(maxAgeDays || 8)) * 24 * 60 * 60 * 1000;
    const cutoffMs = nowMs() - maxAgeMs;
    for (const key of map.keys()) {
      const [dayBucket] = String(key).split("|");
      const dayStartMs = parseTime(`${dayBucket}T00:00:00.000Z`);
      if (dayStartMs == null || dayStartMs < cutoffMs) {
        map.delete(key);
      }
    }
  }

  ensureBlobDailyUsage(identityUri, dayBucket) {
    const key = this.buildIdentityDailyQuotaKey(identityUri, dayBucket);
    if (!key) {
      return null;
    }

    let usage = this.identityBlobUsageByDay.get(key);
    if (!usage || typeof usage !== "object") {
      usage = { count: 0, bytes: 0 };
      this.identityBlobUsageByDay.set(key, usage);
    } else {
      usage.count = Math.max(0, Number(usage.count || 0));
      usage.bytes = Math.max(0, Number(usage.bytes || 0));
    }

    return usage;
  }

  getBlobDailyUsage(identityUri, dayBucket) {
    const key = this.buildIdentityDailyQuotaKey(identityUri, dayBucket);
    if (!key) {
      return {
        count: 0,
        bytes: 0
      };
    }

    const usage = this.identityBlobUsageByDay.get(key);
    if (!usage || typeof usage !== "object") {
      return {
        count: 0,
        bytes: 0
      };
    }

    return {
      count: Math.max(0, Number(usage.count || 0)),
      bytes: Math.max(0, Number(usage.bytes || 0))
    };
  }

  rebuildIdentityQuotaIndexes() {
    this.identityEnvelopeUsageByDay = new Map();
    this.identityBlobUsageByDay = new Map();
    this.identityBlobTotalBytes = new Map();

    for (const envelope of this.envelopesById.values()) {
      const identity = this.normalizeIdentityReference(envelope?.from?.identity);
      if (!identity) {
        continue;
      }

      const dayBucket = this.toDailyQuotaBucket(envelope.created_at || envelope?.meta?.received_at);
      const key = this.buildIdentityDailyQuotaKey(identity, dayBucket);
      if (!key) {
        continue;
      }

      this.identityEnvelopeUsageByDay.set(key, Math.max(0, Number(this.identityEnvelopeUsageByDay.get(key) || 0)) + 1);
    }

    for (const blob of this.blobsById.values()) {
      const identity = this.normalizeIdentityReference(blob?.created_by);
      if (!identity) {
        continue;
      }

      const createdDayBucket = this.toDailyQuotaBucket(blob.created_at);
      const createUsage = this.ensureBlobDailyUsage(identity, createdDayBucket);
      if (createUsage) {
        createUsage.count += 1;
      }

      let accountedBytes = Number(blob?.quota_accounted_bytes || 0);
      if (!Number.isFinite(accountedBytes) || accountedBytes < 0) {
        accountedBytes = 0;
      }

      if (accountedBytes === 0 && blob?.status === "complete") {
        const fallbackSizeBytes = Number(blob?.size_bytes || 0);
        if (Number.isFinite(fallbackSizeBytes) && fallbackSizeBytes > 0) {
          accountedBytes = fallbackSizeBytes;
        }
      }

      blob.quota_accounted_bytes = accountedBytes;
      if (accountedBytes <= 0) {
        continue;
      }

      const completedDayBucket = this.toDailyQuotaBucket(blob.completed_at || blob.created_at);
      const completeUsage = this.ensureBlobDailyUsage(identity, completedDayBucket);
      if (completeUsage) {
        completeUsage.bytes += accountedBytes;
      }

      this.identityBlobTotalBytes.set(
        identity,
        Math.max(0, Number(this.identityBlobTotalBytes.get(identity) || 0)) + accountedBytes
      );
    }

    this.cleanupDailyQuotaMap(this.identityEnvelopeUsageByDay);
    this.cleanupDailyQuotaMap(this.identityBlobUsageByDay);
  }

  enforceThreadRecipientFanout(envelope) {
    if (this.threadRecipientFanoutMax <= 0) {
      return;
    }

    const recipientCount = Array.isArray(envelope?.to) ? envelope.to.length : 0;
    if (recipientCount <= this.threadRecipientFanoutMax) {
      return;
    }

    throw new LoomError("PAYLOAD_TOO_LARGE", "Recipient fanout exceeds configured thread cap", 413, {
      field: "to",
      recipient_count: recipientCount,
      max_recipients: this.threadRecipientFanoutMax
    });
  }

  enforceEnvelopeDailyQuota(identityUri, createdAt) {
    if (this.envelopeDailyMax <= 0) {
      return;
    }

    const dayBucket = this.toDailyQuotaBucket(createdAt);
    const key = this.buildIdentityDailyQuotaKey(identityUri, dayBucket);
    if (!key) {
      return;
    }

    const count = Math.max(0, Number(this.identityEnvelopeUsageByDay.get(key) || 0));
    if (count < this.envelopeDailyMax) {
      return;
    }

    throw new LoomError("RATE_LIMIT_EXCEEDED", "Daily envelope quota exceeded", 429, {
      scope: "identity:envelope_daily",
      identity: this.normalizeIdentityReference(identityUri),
      day: dayBucket,
      limit: this.envelopeDailyMax
    });
  }

  trackEnvelopeDailyQuota(identityUri, createdAt) {
    if (this.envelopeDailyMax <= 0) {
      return;
    }

    const dayBucket = this.toDailyQuotaBucket(createdAt);
    const key = this.buildIdentityDailyQuotaKey(identityUri, dayBucket);
    if (!key) {
      return;
    }

    const count = Math.max(0, Number(this.identityEnvelopeUsageByDay.get(key) || 0));
    this.identityEnvelopeUsageByDay.set(key, count + 1);
    this.cleanupDailyQuotaMap(this.identityEnvelopeUsageByDay);
  }

  enforceBlobDailyCountQuota(identityUri, createdAt) {
    if (this.blobDailyCountMax <= 0) {
      return;
    }

    const dayBucket = this.toDailyQuotaBucket(createdAt);
    const usage = this.getBlobDailyUsage(identityUri, dayBucket);
    if (usage.count < this.blobDailyCountMax) {
      return;
    }

    throw new LoomError("RATE_LIMIT_EXCEEDED", "Daily blob count quota exceeded", 429, {
      scope: "identity:blob_daily_count",
      identity: this.normalizeIdentityReference(identityUri),
      day: dayBucket,
      limit: this.blobDailyCountMax
    });
  }

  trackBlobDailyCountQuota(identityUri, createdAt) {
    if (this.blobDailyCountMax <= 0) {
      return;
    }

    const dayBucket = this.toDailyQuotaBucket(createdAt);
    const usage = this.ensureBlobDailyUsage(identityUri, dayBucket);
    if (!usage) {
      return;
    }

    usage.count += 1;
    this.cleanupDailyQuotaMap(this.identityBlobUsageByDay);
  }

  enforceBlobByteQuotas(identityUri, additionalBytes, timestamp) {
    const bytesToAdd = Math.max(0, Number(additionalBytes || 0));
    if (bytesToAdd <= 0) {
      return;
    }

    const normalizedIdentity = this.normalizeIdentityReference(identityUri);
    if (!normalizedIdentity) {
      return;
    }

    if (this.blobDailyBytesMax > 0) {
      const dayBucket = this.toDailyQuotaBucket(timestamp);
      const usage = this.getBlobDailyUsage(normalizedIdentity, dayBucket);
      if (usage.bytes + bytesToAdd > this.blobDailyBytesMax) {
        throw new LoomError("RATE_LIMIT_EXCEEDED", "Daily blob byte quota exceeded", 429, {
          scope: "identity:blob_daily_bytes",
          identity: normalizedIdentity,
          day: dayBucket,
          limit_bytes: this.blobDailyBytesMax
        });
      }
    }

    if (this.blobIdentityTotalBytesMax > 0) {
      const totalBytes = Math.max(0, Number(this.identityBlobTotalBytes.get(normalizedIdentity) || 0));
      if (totalBytes + bytesToAdd > this.blobIdentityTotalBytesMax) {
        throw new LoomError("RATE_LIMIT_EXCEEDED", "Blob identity total byte quota exceeded", 429, {
          scope: "identity:blob_total_bytes",
          identity: normalizedIdentity,
          limit_bytes: this.blobIdentityTotalBytesMax
        });
      }
    }
  }

  trackBlobByteQuotas(identityUri, additionalBytes, timestamp) {
    const bytesToAdd = Math.max(0, Number(additionalBytes || 0));
    if (bytesToAdd <= 0) {
      return;
    }

    const normalizedIdentity = this.normalizeIdentityReference(identityUri);
    if (!normalizedIdentity) {
      return;
    }

    const dayBucket = this.toDailyQuotaBucket(timestamp);
    const usage = this.ensureBlobDailyUsage(normalizedIdentity, dayBucket);
    if (usage) {
      usage.bytes += bytesToAdd;
    }

    const totalBytes = Math.max(0, Number(this.identityBlobTotalBytes.get(normalizedIdentity) || 0));
    this.identityBlobTotalBytes.set(normalizedIdentity, totalBytes + bytesToAdd);
    this.cleanupDailyQuotaMap(this.identityBlobUsageByDay);
  }

  isRemoteIdentityExpired(identityDoc) {
    if (!identityDoc || identityDoc.imported_remote !== true) {
      return false;
    }
    if (!identityDoc.remote_expires_at) {
      return false;
    }
    return isExpiredIso(identityDoc.remote_expires_at);
  }

  purgeExpiredRemoteIdentity(identityUri) {
    const remoteIdentity = this.remoteIdentities.get(identityUri);
    if (!remoteIdentity) {
      return;
    }
    this.removeIdentitySigningKeys(identityUri, remoteIdentity.signing_keys);
    this.removeIdentityEncryptionKeys(identityUri, remoteIdentity.encryption_keys);
    this.remoteIdentities.delete(identityUri);
  }

  loadStateFromObject(state) {
    if (!state || typeof state !== "object") {
      return;
    }

    this.nodeId = state.node_id || this.nodeId;
    const trustState =
      state.federation_trust && typeof state.federation_trust === "object" ? state.federation_trust : null;
    if (trustState) {
      const modeInput =
        trustState.mode ?? trustState.trust_anchor_mode ?? trustState.trust_mode ?? this.federationTrustMode;
      this.federationTrustMode = normalizeFederationTrustMode(modeInput, {
        hasTrustAnchors: this.federationTrustAnchorBindings.size > 0
      });
      this.federationTrustFailClosed = parseBoolean(
        trustState.fail_closed ?? trustState.trust_fail_closed,
        this.federationTrustFailClosed
      );
      this.federationTrustMaxClockSkewMs = Math.max(
        1000,
        parsePositiveInteger(
          trustState.max_clock_skew_ms ?? trustState.trust_max_clock_skew_ms,
          this.federationTrustMaxClockSkewMs
        )
      );
      this.federationTrustKeysetMaxAgeMs = Math.max(
        60 * 1000,
        parsePositiveInteger(
          trustState.keyset_max_age_ms ?? trustState.trust_keyset_max_age_ms,
          this.federationTrustKeysetMaxAgeMs
        )
      );
      this.federationTrustKeysetPublishTtlMs = Math.max(
        60 * 1000,
        parsePositiveInteger(
          trustState.keyset_publish_ttl_ms ?? trustState.trust_keyset_publish_ttl_ms,
          this.federationTrustKeysetPublishTtlMs
        )
      );
      const dnsLabel = String(
        trustState.dns_txt_label ?? trustState.trust_dns_txt_label ?? this.federationTrustDnsTxtLabel ?? ""
      ).trim();
      if (dnsLabel) {
        this.federationTrustDnsTxtLabel = dnsLabel;
      }
      this.federationTrustRequireDnssec = parseBoolean(
        trustState.require_dnssec ?? trustState.trust_require_dnssec,
        this.federationTrustRequireDnssec
      );
      this.federationTrustRequireTransparency = parseBoolean(
        trustState.require_transparency ?? trustState.trust_require_transparency,
        this.federationTrustRequireTransparency
      );
      const transparencyMode = String(
        trustState.transparency_mode ?? trustState.trust_transparency_mode ?? this.federationTrustTransparencyMode
      )
        .trim()
        .toLowerCase();
      this.federationTrustTransparencyMode = transparencyMode || "local_append_only";
      this.federationTrustLocalEpoch = Math.max(
        0,
        parseNonNegativeInteger(
          trustState.local_epoch ?? trustState.trust_epoch ?? trustState.epoch,
          this.federationTrustLocalEpoch
        )
      );
      this.federationTrustKeysetVersion = Math.max(
        0,
        parseNonNegativeInteger(
          trustState.keyset_version ?? trustState.version,
          this.federationTrustKeysetVersion
        )
      );
      this.federationTrustRevokedKeyIds = normalizeRevokedKeyIds(
        trustState.revoked_key_ids ?? this.federationTrustRevokedKeyIds
      );
    }
    const inboundContentFilterState =
      state.inbound_content_filter && typeof state.inbound_content_filter === "object"
        ? state.inbound_content_filter
        : null;
    if (inboundContentFilterState) {
      const configSource =
        inboundContentFilterState.config &&
        typeof inboundContentFilterState.config === "object" &&
        !Array.isArray(inboundContentFilterState.config)
          ? inboundContentFilterState.config
          : inboundContentFilterState;
      try {
        const restoredConfig = this.buildInboundContentFilterConfigUpdate(
          configSource,
          this.getInboundContentFilterActiveConfig()
        );
        this.applyInboundContentFilterActiveConfig(restoredConfig.config);
      } catch {}

      if (
        inboundContentFilterState.stats &&
        typeof inboundContentFilterState.stats === "object" &&
        !Array.isArray(inboundContentFilterState.stats)
      ) {
        this.inboundContentFilterStats = { ...inboundContentFilterState.stats };
      } else if (
        inboundContentFilterState.decision_stats &&
        typeof inboundContentFilterState.decision_stats === "object" &&
        !Array.isArray(inboundContentFilterState.decision_stats)
      ) {
        this.inboundContentFilterStats = { ...inboundContentFilterState.decision_stats };
      }

      this.inboundContentFilterConfigVersion = Math.max(
        1,
        parsePositiveInteger(inboundContentFilterState.version, this.inboundContentFilterConfigVersion)
      );
      this.inboundContentFilterConfigUpdatedAt =
        typeof inboundContentFilterState.updated_at === "string" && inboundContentFilterState.updated_at.trim().length > 0
          ? inboundContentFilterState.updated_at.trim()
          : this.inboundContentFilterConfigUpdatedAt;
      this.inboundContentFilterConfigUpdatedBy =
        typeof inboundContentFilterState.updated_by === "string" && inboundContentFilterState.updated_by.trim().length > 0
          ? inboundContentFilterState.updated_by.trim()
          : this.inboundContentFilterConfigUpdatedBy;
      this.inboundContentFilterConfigCanary = this.normalizeInboundContentFilterCanaryState(
        inboundContentFilterState.canary
      );
      this.inboundContentFilterConfigRollback = this.normalizeInboundContentFilterRollbackState(
        inboundContentFilterState.rollback
      );
    } else if (
      state.inbound_content_filter_stats &&
      typeof state.inbound_content_filter_stats === "object" &&
      !Array.isArray(state.inbound_content_filter_stats)
    ) {
      this.inboundContentFilterStats = { ...state.inbound_content_filter_stats };
    }
    this.ensureInboundContentFilterStatsShape();

    const localIdentityEntries = [];
    const remoteIdentityEntries = [];
    for (const identityDoc of state.identities || []) {
      if (!identityDoc?.id) {
        continue;
      }
      if (identityDoc.imported_remote === true || identityDoc.identity_source === "remote") {
        remoteIdentityEntries.push(identityDoc);
      } else {
        localIdentityEntries.push(identityDoc);
      }
    }
    for (const identityDoc of state.remote_identities || []) {
      if (!identityDoc?.id) {
        continue;
      }
      remoteIdentityEntries.push({
        ...identityDoc,
        imported_remote: true,
        identity_source: "remote"
      });
    }

    this.identities = new Map(localIdentityEntries.map((item) => [item.id, item]));
    this.remoteIdentities = new Map(remoteIdentityEntries.map((item) => [item.id, item]));

    // Normalize agent_info on all identities
    for (const identity of this.identities.values()) {
      if (identity.agent_info !== undefined && identity.agent_info !== null) {
        identity.agent_info = normalizeAgentInfo(identity.agent_info);
      } else {
        identity.agent_info = null;
      }
    }
    for (const identity of this.remoteIdentities.values()) {
      if (identity.agent_info !== undefined && identity.agent_info !== null) {
        identity.agent_info = normalizeAgentInfo(identity.agent_info);
      } else {
        identity.agent_info = null;
      }
    }

    this.rebuildIdentityKeyIndexes();

    for (const [identityUri, identityDoc] of this.remoteIdentities.entries()) {
      if (this.isRemoteIdentityExpired(identityDoc)) {
        this.purgeExpiredRemoteIdentity(identityUri);
      }
    }
    this.envelopesById = new Map((state.envelopes || []).map((item) => [item.id, item]));
    this.threadsById = new Map((state.threads || []).map((item) => [item.id, item]));
    for (const thread of this.threadsById.values()) {
      if (!thread.mailbox_state || typeof thread.mailbox_state !== "object") {
        thread.mailbox_state = {};
      }
      if (thread.snapshot && typeof thread.snapshot !== "object") {
        thread.snapshot = null;
      }
      if (thread.context_budgets && typeof thread.context_budgets !== "object") {
        thread.context_budgets = {};
      }
      if (thread.encryption && typeof thread.encryption === "object") {
        if (thread.encryption.mls_state && typeof thread.encryption.mls_state === "object") {
          thread.encryption.mls_state = deserializeMlsGroupState(thread.encryption.mls_state);
        } else {
          thread.encryption.mls_state = null;
        }
      }
      if (thread.workflow !== undefined && thread.workflow !== null) {
        if (typeof thread.workflow !== "object" || Array.isArray(thread.workflow)) {
          thread.workflow = null;
        }
      }
      if (Number.isFinite(Number(thread.pending_parent_count))) {
        thread.pending_parent_count = Math.max(0, Number(thread.pending_parent_count || 0));
        continue;
      }

      const pendingCount = Array.isArray(thread.envelope_ids)
        ? thread.envelope_ids.reduce((count, envelopeId) => {
            const envelope = this.envelopesById.get(envelopeId);
            return count + (envelope?.meta?.pending_parent ? 1 : 0);
          }, 0)
        : 0;
      thread.pending_parent_count = pendingCount;
    }
    this.capabilitiesById = new Map((state.capabilities || []).map((item) => [item.id, item]));
    this.capabilityIdBySecretHash = new Map();
    for (const capability of this.capabilitiesById.values()) {
      if (!capability.secret_hash) {
        capability.secret_hash = hashCapabilityPresentationToken(`legacy-revoked:${capability.id || "unknown"}`);
        capability.secret_hint = null;
        capability.revoked = true;
        capability.revoked_at = capability.revoked_at || nowIso();
      }
      if (capability.secret_hash) {
        this.capabilityIdBySecretHash.set(capability.secret_hash, capability.id);
      }
      if (!capability.created_at) {
        capability.created_at = nowIso();
      }
      if (capability.secret_last_used_at == null) {
        capability.secret_last_used_at = null;
      }
    }
    this.consumedPortableCapabilityIds = new Set(
      (state.consumed_portable_capability_ids || [])
        .map((value) => String(value || "").trim())
        .filter(Boolean)
    );
    this.delegationsById = new Map((state.delegations || []).map((item) => [item.id, item]));
    this.revokedDelegationIds = new Set(state.revoked_delegation_ids || []);
    this.blobsById = new Map((state.blobs || []).map((item) => [item.id, item]));
    for (const blob of this.blobsById.values()) {
      const accountedBytes = Number(blob?.quota_accounted_bytes || 0);
      blob.quota_accounted_bytes = Number.isFinite(accountedBytes) && accountedBytes >= 0 ? accountedBytes : 0;
    }
    this.knownNodesById = new Map((state.known_nodes || []).map((item) => [item.node_id, item]));
    for (const node of this.knownNodesById.values()) {
      node.revoked_key_ids = normalizeRevokedKeyIds(node.revoked_key_ids);
      const signingKeys = applyRevokedKeyIdsToFederationSigningKeys(
        getFederationNodeSigningKeys(node),
        node.revoked_key_ids,
        node.updated_at
      );
      node.signing_keys = signingKeys;
      if (signingKeys.length > 0) {
        const activeKey =
          resolveFederationNodeSigningKey({ signing_keys: signingKeys }, node.key_id) ||
          signingKeys.find((key) => isSigningKeyUsableAt(key)) ||
          signingKeys[0];
        node.key_id = activeKey.key_id;
        node.public_key_pem = activeKey.public_key_pem;
      }

      node.trust_anchor_mode = normalizeFederationTrustMode(node.trust_anchor_mode || this.federationTrustMode, {
        hasTrustAnchors: this.federationTrustAnchorBindings.size > 0
      });
      node.trust_anchor_dns_name =
        typeof node.trust_anchor_dns_name === "string" && node.trust_anchor_dns_name.trim().length > 0
          ? node.trust_anchor_dns_name.trim()
          : null;
      node.trust_anchor_dns_record =
        typeof node.trust_anchor_dns_record === "string" && node.trust_anchor_dns_record.trim().length > 0
          ? node.trust_anchor_dns_record.trim()
          : null;
      node.trust_anchor_keyset_url =
        typeof node.trust_anchor_keyset_url === "string" && node.trust_anchor_keyset_url.trim().length > 0
          ? node.trust_anchor_keyset_url.trim()
          : null;
      node.trust_anchor_revocations_url =
        typeof node.trust_anchor_revocations_url === "string" && node.trust_anchor_revocations_url.trim().length > 0
          ? node.trust_anchor_revocations_url.trim()
          : null;
      node.trust_anchor_verified_at =
        typeof node.trust_anchor_verified_at === "string" && node.trust_anchor_verified_at.trim().length > 0
          ? node.trust_anchor_verified_at.trim()
          : null;
      node.trust_anchor_dnssec_validated = node.trust_anchor_dnssec_validated === true;
      node.trust_anchor_dnssec_source =
        typeof node.trust_anchor_dnssec_source === "string" && node.trust_anchor_dnssec_source.trim().length > 0
          ? node.trust_anchor_dnssec_source.trim()
          : null;
      node.trust_anchor_transparency_log_id =
        typeof node.trust_anchor_transparency_log_id === "string" &&
        node.trust_anchor_transparency_log_id.trim().length > 0
          ? node.trust_anchor_transparency_log_id.trim()
          : null;
      node.trust_anchor_transparency_mode =
        typeof node.trust_anchor_transparency_mode === "string" &&
        node.trust_anchor_transparency_mode.trim().length > 0
          ? node.trust_anchor_transparency_mode.trim().toLowerCase()
          : this.federationTrustTransparencyMode;
      node.trust_anchor_transparency_checkpoint =
        typeof node.trust_anchor_transparency_checkpoint === "string" &&
        node.trust_anchor_transparency_checkpoint.trim().length > 0
          ? node.trust_anchor_transparency_checkpoint.trim().toLowerCase()
          : null;
      node.trust_anchor_transparency_previous_checkpoint =
        typeof node.trust_anchor_transparency_previous_checkpoint === "string" &&
        node.trust_anchor_transparency_previous_checkpoint.trim().length > 0
          ? node.trust_anchor_transparency_previous_checkpoint.trim().toLowerCase()
          : null;
      const transparencyEventIndex = parseNonNegativeInteger(node.trust_anchor_transparency_event_index, -1);
      node.trust_anchor_transparency_event_index = transparencyEventIndex >= 0 ? transparencyEventIndex : null;
      node.trust_anchor_transparency_verified_at =
        typeof node.trust_anchor_transparency_verified_at === "string" &&
        node.trust_anchor_transparency_verified_at.trim().length > 0
          ? node.trust_anchor_transparency_verified_at.trim()
          : null;
      node.trust_anchor_keyset_hash = normalizeHexDigest(node.trust_anchor_keyset_hash) || null;
      node.trust_anchor_keyset_version = Math.max(
        0,
        parseNonNegativeInteger(node.trust_anchor_keyset_version, 0)
      );
      node.trust_anchor_epoch = Math.max(0, parseNonNegativeInteger(node.trust_anchor_epoch, 0));

      node.allow_insecure_http = node.allow_insecure_http === true;
      node.allow_private_network = node.allow_private_network === true;
      try {
        node.deliver_url = normalizeFederationDeliverUrl(node.deliver_url, {
          allowInsecureHttp: node.allow_insecure_http,
          allowPrivateNetwork: node.allow_private_network
        });
      } catch {
        node.deliver_url = null;
      }
      try {
        node.identity_resolve_url = normalizeFederationIdentityResolveUrl(node.identity_resolve_url, {
          allowInsecureHttp: node.allow_insecure_http,
          allowPrivateNetwork: node.allow_private_network
        });
      } catch {
        node.identity_resolve_url = null;
      }
      try {
        node.node_document_url = normalizeFederationNodeDocumentUrl(node.node_document_url, {
          allowInsecureHttp: node.allow_insecure_http,
          allowPrivateNetwork: node.allow_private_network
        });
      } catch {
        node.node_document_url = null;
      }
      try {
        node.protocol_capabilities_url = normalizeFederationProtocolCapabilitiesUrl(node.protocol_capabilities_url, {
          allowInsecureHttp: node.allow_insecure_http,
          allowPrivateNetwork: node.allow_private_network
        });
      } catch {
        node.protocol_capabilities_url = null;
      }
      node.protocol_capabilities = normalizeProtocolCapabilitiesDocument(node.protocol_capabilities);
      node.protocol_capabilities_fetched_at =
        typeof node.protocol_capabilities_fetched_at === "string" && node.protocol_capabilities_fetched_at.trim()
          ? node.protocol_capabilities_fetched_at.trim()
          : null;
      node.protocol_capabilities_fetch_error =
        typeof node.protocol_capabilities_fetch_error === "string" && node.protocol_capabilities_fetch_error.trim()
          ? node.protocol_capabilities_fetch_error.trim()
          : null;
      node.negotiated_e2ee_profiles = normalizeProtocolCapabilityE2eeProfiles(node.negotiated_e2ee_profiles);
      node.protocol_negotiated_trust_anchor_mode =
        typeof node.protocol_negotiated_trust_anchor_mode === "string" &&
        node.protocol_negotiated_trust_anchor_mode.trim()
          ? normalizeFederationTrustMode(node.protocol_negotiated_trust_anchor_mode.trim(), {
              hasTrustAnchors: this.federationTrustAnchorBindings.size > 0
            })
          : null;

      node.reputation_score = Math.max(0, Number(node.reputation_score || 0));
      node.challenge_required_until = node.challenge_required_until || null;
      node.challenge_reason = node.challenge_reason || null;
      if (isExpiredIso(node.challenge_required_until)) {
        node.challenge_required_until = null;
        node.challenge_reason = null;
      }

      node.configured_policy = node.configured_policy || node.policy || "trusted";
      if (node.auto_policy && !isExpiredIso(node.auto_policy_until)) {
        node.policy = node.auto_policy;
      } else {
        node.auto_policy = null;
        node.auto_policy_until = null;
        node.auto_policy_reason = null;
        node.policy = node.configured_policy;
      }
    }
    this.federationOutboxById = new Map((state.federation_outbox || []).map((item) => [item.id, item]));
    this.emailOutboxById = new Map((state.email_outbox || []).map((item) => [item.id, item]));
    this.deliveryWrappersByEnvelopeAndIdentity = new Map(
      (state.delivery_wrappers || [])
        .filter((wrapper) => wrapper?.envelope_id && wrapper?.recipient_identity)
        .map((wrapper) => [deliveryWrapperKey(wrapper.envelope_id, wrapper.recipient_identity), wrapper])
    );
    this.webhooksById = new Map((state.webhooks || []).map((item) => [item.id, item]));
    this.webhookOutboxById = new Map((state.webhook_outbox || []).map((item) => [item.id, item]));
    this.emailMessageIndexById = new Map((state.email_message_index || []).map((item) => [item.message_id, item]));
    const persistedNonces = Array.isArray(state.federation_nonces) ? state.federation_nonces : [];
    this.federationNonceCache = new Map(
      persistedNonces
        .map((entry) => {
          if (Array.isArray(entry) && entry.length === 2) {
            return [String(entry[0] || ""), Number(entry[1])];
          }
          if (entry && typeof entry === "object") {
            return [String(entry.key || entry.nonce || ""), Number(entry.seen_at_ms || entry.seen_at || 0)];
          }
          return ["", Number.NaN];
        })
        .filter(([key, seenAt]) => key.length > 0 && Number.isFinite(seenAt))
    );
    this.cleanupFederationNonces();
    this.rebuildIdentityQuotaIndexes();

    // ── Protocol module state restoration ────────────────────────────────
    if (Array.isArray(state.channel_rules)) {
      this.channelRules = normalizeChannelRules(state.channel_rules);
    }
    if (Array.isArray(state.retention_policies)) {
      this.retentionPolicies = normalizeRetentionPolicies(state.retention_policies);
    }
    if (Array.isArray(state.autoresponder_rules)) {
      this.autoresponderRules = new Map();
      for (const entry of state.autoresponder_rules) {
        if (entry?.identity && entry?.rule) {
          this.autoresponderRules.set(entry.identity, entry.rule);
        }
      }
    }
    if (Array.isArray(state.autoresponder_sent_history)) {
      this.autoresponderSentHistory = new Map();
      for (const entry of state.autoresponder_sent_history) {
        if (entry?.identity && Array.isArray(entry.history)) {
          const history = new Map();
          for (const h of entry.history) {
            if (h?.sender && h?.timestamp) {
              history.set(h.sender, h.timestamp);
            }
          }
          this.autoresponderSentHistory.set(entry.identity, history);
        }
      }
    }
  }

  buildAuditHashInput(entry) {
    return JSON.stringify({
      event_id: entry.event_id,
      timestamp: entry.timestamp,
      action: entry.action,
      payload: entry.payload ?? null,
      prev_hash: entry.prev_hash ?? null
    });
  }

  computeAuditHash(entry) {
    return createHash("sha256").update(this.buildAuditHashInput(entry), "utf-8").digest("hex");
  }

  buildAuditMacInput(entry) {
    return JSON.stringify({
      event_id: entry.event_id,
      timestamp: entry.timestamp,
      action: entry.action,
      payload: entry.payload ?? null,
      prev_hash: entry.prev_hash ?? null,
      hash: entry.hash
    });
  }

  computeAuditMac(entry) {
    if (!this.auditHmacKey) {
      return null;
    }
    return createHmac("sha256", this.auditHmacKey).update(this.buildAuditMacInput(entry), "utf-8").digest("hex");
  }

  validateAuditEntryOrThrow(entry, expectedPrevHash, index, options = {}) {
    const prevHash = entry?.prev_hash ?? null;
    if ((expectedPrevHash ?? null) !== prevHash) {
      throw new LoomError("AUDIT_TAMPERED", "Audit chain continuity check failed", 500, {
        index,
        expected_prev_hash: expectedPrevHash ?? null,
        actual_prev_hash: prevHash
      });
    }

    const mode = options.mode === "chain_only" ? "chain_only" : "strict";
    const hash = String(entry?.hash || "").trim();
    if (!/^[a-f0-9]{64}$/i.test(hash)) {
      throw new LoomError("AUDIT_TAMPERED", "Audit entry hash is malformed", 500, {
        index
      });
    }
    if (mode === "chain_only") {
      return;
    }

    const expectedHash = this.computeAuditHash(entry);
    if (hash !== expectedHash) {
      throw new LoomError("AUDIT_TAMPERED", "Audit entry hash mismatch", 500, {
        index
      });
    }

    if (!this.auditHmacKey) {
      return;
    }

    const mac = String(entry?.mac || "").trim();
    if (!mac) {
      if (this.auditRequireMacValidation) {
        throw new LoomError("AUDIT_TAMPERED", "Audit entry is missing required MAC signature", 500, {
          index
        });
      }
      return;
    }

    const expectedMac = this.computeAuditMac(entry);
    if (mac !== expectedMac) {
      throw new LoomError("AUDIT_TAMPERED", "Audit entry MAC verification failed", 500, {
        index
      });
    }
  }

  loadAuditFromEntries(entries, options = {}) {
    const list = Array.isArray(entries) ? entries : [];
    let expectedPrevHash = null;
    const normalized = [];

    for (let index = 0; index < list.length; index += 1) {
      const raw = list[index];
      if (!raw || typeof raw !== "object") {
        throw new LoomError("AUDIT_TAMPERED", "Audit entry is malformed", 500, {
          index
        });
      }

      const entry = { ...raw };
      if (this.auditValidateChain) {
        this.validateAuditEntryOrThrow(entry, expectedPrevHash, index, options);
      }
      expectedPrevHash = entry.hash ?? null;
      normalized.push(entry);
    }

    this.auditEntries = normalized;
    this.auditHeadHash = expectedPrevHash;
  }

  decodeStatePayloadFromDisk(raw) {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") {
      return parsed;
    }

    if (parsed.type !== STATE_ENCRYPTION_WRAPPER_TYPE) {
      if (this.requireStateEncryptionAtRest && this.stateEncryptionKey) {
        throw new Error("State file must be encrypted at rest but plaintext JSON was found");
      }
      return parsed;
    }

    if (!this.stateEncryptionKey) {
      throw new Error("State file is encrypted but no stateEncryptionKey is configured");
    }

    const algorithm = String(parsed.algorithm || "").trim().toLowerCase();
    if (algorithm !== STATE_ENCRYPTION_ALGORITHM) {
      throw new Error(`Unsupported state encryption algorithm: ${parsed.algorithm}`);
    }

    const nonce = fromBase64Url(String(parsed.nonce || "").trim());
    const tag = fromBase64Url(String(parsed.tag || "").trim());
    const ciphertext = fromBase64Url(String(parsed.ciphertext || "").trim());
    if (nonce.length !== STATE_ENCRYPTION_NONCE_BYTES) {
      throw new Error("Encrypted state nonce is invalid");
    }
    if (tag.length !== STATE_ENCRYPTION_TAG_BYTES) {
      throw new Error("Encrypted state authentication tag is invalid");
    }
    if (ciphertext.length === 0) {
      throw new Error("Encrypted state ciphertext is empty");
    }

    const decipher = createDecipheriv(
      STATE_ENCRYPTION_ALGORITHM,
      this.stateEncryptionKey,
      nonce
    );
    decipher.setAuthTag(tag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const decoded = JSON.parse(plaintext.toString("utf-8"));
    if (!decoded || typeof decoded !== "object") {
      throw new Error("Decrypted state payload must be a JSON object");
    }
    return decoded;
  }

  encodeStatePayloadForDisk(state) {
    if (!this.stateEncryptionKey) {
      return JSON.stringify(state, null, 2);
    }

    const nonce = randomBytes(STATE_ENCRYPTION_NONCE_BYTES);
    const cipher = createCipheriv(
      STATE_ENCRYPTION_ALGORITHM,
      this.stateEncryptionKey,
      nonce
    );
    const plaintext = Buffer.from(JSON.stringify(state), "utf-8");
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    const wrapper = {
      type: STATE_ENCRYPTION_WRAPPER_TYPE,
      algorithm: STATE_ENCRYPTION_ALGORITHM,
      nonce: toBase64Url(nonce),
      tag: toBase64Url(tag),
      ciphertext: toBase64Url(ciphertext),
      generated_at: nowIso()
    };
    return JSON.stringify(wrapper, null, 2);
  }

  loadStateFromDisk() {
    if (!this.stateFile || !existsSync(this.stateFile)) {
      return;
    }

    const raw = readFileSync(this.stateFile, "utf-8");
    if (!raw.trim()) {
      return;
    }

    const state = this.decodeStatePayloadFromDisk(raw);
    this.loadStateFromObject(state);
  }

  loadAuditFromDisk() {
    if (!this.auditFile || !existsSync(this.auditFile)) {
      return;
    }

    const lines = readFileSync(this.auditFile, "utf-8")
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    this.loadAuditFromEntries(lines.map((line) => JSON.parse(line)));
  }

  toSerializableState() {
    this.cleanupFederationNonces();
    this.ensureInboundContentFilterStatsShape();
    return {
      loom_version: "1.1",
      node_id: this.nodeId,
      updated_at: nowIso(),
      federation_trust: {
        mode: this.federationTrustMode,
        fail_closed: this.federationTrustFailClosed,
        max_clock_skew_ms: this.federationTrustMaxClockSkewMs,
        keyset_max_age_ms: this.federationTrustKeysetMaxAgeMs,
        keyset_publish_ttl_ms: this.federationTrustKeysetPublishTtlMs,
        dns_txt_label: this.federationTrustDnsTxtLabel,
        require_dnssec: this.federationTrustRequireDnssec,
        transparency_mode: this.federationTrustTransparencyMode,
        require_transparency: this.federationTrustRequireTransparency,
        local_epoch: this.federationTrustLocalEpoch,
        keyset_version: this.federationTrustKeysetVersion,
        revoked_key_ids: this.federationTrustRevokedKeyIds
      },
      inbound_content_filter: {
        version: Math.max(1, parsePositiveInteger(this.inboundContentFilterConfigVersion, 1)),
        updated_at: this.inboundContentFilterConfigUpdatedAt || null,
        updated_by: this.inboundContentFilterConfigUpdatedBy || null,
        config: this.getInboundContentFilterActiveConfig(),
        stats: {
          ...this.inboundContentFilterStats,
          decision_counts_by_profile: {
            strict: {
              ...createInboundContentFilterProfileDecisionStats(),
              ...(this.inboundContentFilterStats?.decision_counts_by_profile?.strict || {})
            },
            balanced: {
              ...createInboundContentFilterProfileDecisionStats(),
              ...(this.inboundContentFilterStats?.decision_counts_by_profile?.balanced || {})
            },
            agent: {
              ...createInboundContentFilterProfileDecisionStats(),
              ...(this.inboundContentFilterStats?.decision_counts_by_profile?.agent || {})
            }
          }
        },
        canary: cloneInboundContentFilterCanaryState(this.inboundContentFilterConfigCanary),
        rollback: cloneInboundContentFilterRollbackState(this.inboundContentFilterConfigRollback)
      },
      identities: Array.from(this.identities.values()),
      remote_identities: Array.from(this.remoteIdentities.values()),
      public_keys: Array.from(this.publicKeysById.entries()),
      envelopes: Array.from(this.envelopesById.values()),
      threads: Array.from(this.threadsById.values()),
      capabilities: Array.from(this.capabilitiesById.values()),
      consumed_portable_capability_ids: Array.from(this.consumedPortableCapabilityIds.values()),
      delegations: Array.from(this.delegationsById.values()),
      revoked_delegation_ids: Array.from(this.revokedDelegationIds),
      blobs: Array.from(this.blobsById.values()),
      known_nodes: Array.from(this.knownNodesById.values()),
      federation_outbox: Array.from(this.federationOutboxById.values()),
      email_outbox: Array.from(this.emailOutboxById.values()),
      delivery_wrappers: Array.from(this.deliveryWrappersByEnvelopeAndIdentity.values()),
      webhooks: Array.from(this.webhooksById.values()),
      webhook_outbox: Array.from(this.webhookOutboxById.values()),
      email_message_index: Array.from(this.emailMessageIndexById.values()),
      federation_nonces: Array.from(this.federationNonceCache.entries()),
      channel_rules: this.channelRules,
      retention_policies: this.retentionPolicies,
      autoresponder_rules: Array.from(this.autoresponderRules.entries()).map(([k, v]) => ({ identity: k, rule: v })),
      autoresponder_sent_history: Array.from(this.autoresponderSentHistory.entries()).map(([k, v]) => ({
        identity: k,
        history: Array.from(v.entries()).map(([sender, ts]) => ({ sender, timestamp: ts }))
      }))
    };
  }

  persistState() {
    if (!this.stateFile) {
      return;
    }

    const tmpFile = `${this.stateFile}.tmp`;
    writeFileSync(tmpFile, this.encodeStatePayloadForDisk(this.toSerializableState()));
    const fd = openSync(tmpFile, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmpFile, this.stateFile);
  }

  appendAudit(action, payload) {
    const trace = this.getCurrentTraceContext();
    let tracedPayload = payload;
    if (payload && typeof payload === "object" && !Array.isArray(payload)) {
      tracedPayload = { ...payload };
      if (trace?.request_id && !tracedPayload.request_id) {
        tracedPayload.request_id = trace.request_id;
      }
      if (trace?.trace_id && !tracedPayload.trace_id) {
        tracedPayload.trace_id = trace.trace_id;
      }
      if (trace?.trace_source && !tracedPayload.trace_source) {
        tracedPayload.trace_source = trace.trace_source;
      }
      if (trace?.worker && !tracedPayload.worker) {
        tracedPayload.worker = trace.worker;
      }
    }

    const entry = {
      event_id: `evt_${generateUlid()}`,
      timestamp: nowIso(),
      action,
      payload: tracedPayload,
      prev_hash: this.auditHeadHash
    };
    if (trace) {
      entry.trace = {
        ...trace
      };
    }

    const hash = this.computeAuditHash(entry);
    entry.hash = hash;
    if (this.auditHmacKey) {
      entry.mac = this.computeAuditMac(entry);
    }
    this.auditHeadHash = hash;
    this.auditEntries.push(entry);

    if (this.auditFile) {
      appendFileSync(this.auditFile, `${JSON.stringify(entry)}\n`, "utf-8");
    }

    return entry;
  }

  enqueuePersistenceWrite(snapshot, auditEntry) {
    if (!this.persistenceAdapter) {
      return;
    }

    this.persistenceWritesTotal += 1;
    this.persistenceQueue.push({
      snapshot,
      audit_entry: auditEntry
    });
    this.flushPersistenceQueue().catch((error) => {
      this.persistenceLastError = error?.message || String(error);
    });
  }

  persistAndAudit(action, payload) {
    const entry = this.appendAudit(action, payload);
    const queuedWebhookEvents = this.queueWebhookEventsFromAudit(action, payload, entry);
    if (queuedWebhookEvents > 0 || this.stateFile) {
      this.persistState();
    }
    if (this.persistenceAdapter) {
      this.enqueuePersistenceWrite(this.toSerializableState(), entry);
    }
  }

  async hydrateFromPersistence() {
    if (!this.persistenceAdapter || typeof this.persistenceAdapter.loadStateAndAudit !== "function") {
      return {
        enabled: false,
        loaded: false
      };
    }

    const loaded = await this.persistenceAdapter.loadStateAndAudit();
    if (loaded?.state) {
      this.loadStateFromObject(loaded.state);
    }
    if (loaded?.audit_entries) {
      // Persistence backends such as PostgreSQL JSONB may reorder object keys on round-trip,
      // so we enforce chain continuity but skip payload-hash recomputation on reload.
      this.loadAuditFromEntries(loaded.audit_entries, { mode: "chain_only" });
    }

    this.ensureSystemSigningKeyRegistered();
    this.persistenceHydratedAt = nowIso();

    return {
      enabled: true,
      loaded: Boolean(loaded?.state || loaded?.audit_entries),
      hydrated_at: this.persistenceHydratedAt,
      state_loaded: Boolean(loaded?.state),
      audit_loaded: Array.isArray(loaded?.audit_entries) && loaded.audit_entries.length > 0
    };
  }

  async flushPersistenceQueue() {
    if (!this.persistenceAdapter || this.persistenceFlushInProgress) {
      return;
    }

    this.persistenceFlushInProgress = true;
    try {
      while (this.persistenceQueue.length > 0) {
        const next = this.persistenceQueue[0];
        await this.persistenceAdapter.persistSnapshotAndAudit(next.snapshot, next.audit_entry);
        this.persistenceQueue.shift();
        this.persistenceWritesSucceeded += 1;
        this.persistenceLastError = null;
        this.persistenceLastSyncAt = nowIso();
      }
    } catch (error) {
      this.persistenceWritesFailed += 1;
      this.persistenceLastError = error?.message || String(error);
      throw error;
    } finally {
      this.persistenceFlushInProgress = false;
    }
  }

  async flushPersistenceQueueNow(timeoutMs = 10000) {
    const startedAt = nowMs();
    while (this.persistenceQueue.length > 0) {
      await this.flushPersistenceQueue().catch(() => {});
      if (this.persistenceQueue.length === 0) {
        break;
      }
      if (nowMs() - startedAt > timeoutMs) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 25));
    }

    return this.getPersistenceStatus();
  }

  getPersistenceStatus() {
    return {
      enabled: Boolean(this.persistenceAdapter),
      queue_length: this.persistenceQueue.length,
      flush_in_progress: this.persistenceFlushInProgress,
      writes_total: this.persistenceWritesTotal,
      writes_succeeded: this.persistenceWritesSucceeded,
      writes_failed: this.persistenceWritesFailed,
      last_sync_at: this.persistenceLastSyncAt,
      last_error: this.persistenceLastError,
      hydrated_at: this.persistenceHydratedAt
    };
  }

  async getPersistenceSchemaStatus() {
    if (!this.persistenceAdapter || typeof this.persistenceAdapter.getSchemaStatus !== "function") {
      return {
        backend: this.persistenceAdapter ? "custom" : "memory",
        initialized: false,
        schema_version: null
      };
    }

    return this.persistenceAdapter.getSchemaStatus();
  }

  async exportPersistenceBackup(options = {}) {
    await this.flushPersistenceQueueNow(15000);

    if (this.persistenceAdapter && typeof this.persistenceAdapter.exportBackup === "function") {
      return this.persistenceAdapter.exportBackup(options);
    }

    const includeAudit = options.includeAudit !== false;
    const auditLimit = Math.max(0, parsePositiveInteger(options.auditLimit, 0));
    const auditEntries = includeAudit
      ? auditLimit > 0
        ? this.auditEntries.slice(-auditLimit)
        : this.auditEntries
      : [];

    return {
      loom_backup_version: 1,
      backend: this.persistenceAdapter ? "custom" : "memory",
      state_key: "in-memory",
      schema_version: null,
      exported_at: nowIso(),
      state: this.toSerializableState(),
      state_updated_at: nowIso(),
      audit_entries: auditEntries.map((entry) => ({ ...entry }))
    };
  }

  async importPersistenceBackup(backupPayload, options = {}) {
    if (!backupPayload || typeof backupPayload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Backup payload must be an object", 400, {
        field: "backup"
      });
    }

    const backup = backupPayload.backup && typeof backupPayload.backup === "object" ? backupPayload.backup : backupPayload;
    const replaceState = options.replaceState !== false;
    const truncateAudit = options.truncateAudit === true;
    const state = backup.state && typeof backup.state === "object" ? backup.state : null;
    const auditEntries = Array.isArray(backup.audit_entries) ? backup.audit_entries : [];

    if (!state && auditEntries.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "Backup payload does not include state or audit_entries", 400, {
        field: "backup"
      });
    }

    let adapterResult = null;
    if (this.persistenceAdapter && typeof this.persistenceAdapter.importBackup === "function") {
      adapterResult = await this.persistenceAdapter.importBackup(backup, {
        replaceState,
        truncateAudit
      });
    }

    if (state && replaceState) {
      this.loadStateFromObject(state);
    }
    if (auditEntries.length > 0) {
      this.loadAuditFromEntries(auditEntries, {
        mode: adapterResult ? "chain_only" : "strict"
      });
    }

    this.ensureSystemSigningKeyRegistered();
    if (this.stateFile) {
      this.persistState();
    }

    this.persistAndAudit("persistence.restore", {
      backend: adapterResult ? "adapter" : "memory",
      replaced_state: Boolean(state && replaceState),
      imported_audit_count: auditEntries.length,
      truncate_audit: truncateAudit
    });

    return {
      restored_at: nowIso(),
      backend: adapterResult ? "adapter" : this.persistenceAdapter ? "custom" : "memory",
      replaced_state: Boolean(state && replaceState),
      imported_audit_count: auditEntries.length,
      truncate_audit: truncateAudit,
      adapter: adapterResult
    };
  }

  normalizeWebhookUrl(value) {
    if (typeof value !== "string") {
      return null;
    }
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }

    let parsed;
    try {
      parsed = new URL(trimmed);
    } catch {
      return null;
    }

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }

    return parsed.toString();
  }

  normalizeWebhookEvents(value) {
    if (value == null) {
      return ["*"];
    }

    if (!Array.isArray(value)) {
      throw new LoomError("ENVELOPE_INVALID", "Webhook events must be an array", 400, {
        field: "events"
      });
    }

    const normalized = Array.from(
      new Set(
        value
          .map((eventName) => String(eventName || "").trim())
          .filter((eventName) => eventName.length > 0)
      )
    );

    if (normalized.length === 0) {
      return ["*"];
    }

    return normalized;
  }

  webhookMatchesEvent(webhook, eventType) {
    const events = Array.isArray(webhook.events) ? webhook.events : ["*"];
    return events.includes("*") || events.includes(eventType);
  }

  registerWebhook(payload, actorIdentity = "admin") {
    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Webhook payload must be an object", 400, {
        field: "webhook"
      });
    }

    const url = this.normalizeWebhookUrl(payload.url);
    if (!url) {
      throw new LoomError("ENVELOPE_INVALID", "Webhook url must be a valid http(s) URL", 400, {
        field: "url"
      });
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch {
      throw new LoomError("ENVELOPE_INVALID", "Webhook url must be a valid http(s) URL", 400, {
        field: "url"
      });
    }

    if (parsedUrl.username || parsedUrl.password) {
      throw new LoomError("ENVELOPE_INVALID", "Webhook url must not include credentials", 400, {
        field: "url"
      });
    }

    if (
      this.webhookOutboundHostAllowlist.length > 0 &&
      !hostnameMatchesAllowlist(parsedUrl.hostname, this.webhookOutboundHostAllowlist)
    ) {
      throw new LoomError("CAPABILITY_DENIED", "Webhook url host is not in outbound allowlist", 403, {
        field: "url",
        host: parsedUrl.hostname
      });
    }

    if (
      this.denyMetadataHosts &&
      (isMetadataHostname(parsedUrl.hostname) ||
        (isIP(parsedUrl.hostname) > 0 && isMetadataServiceAddress(parsedUrl.hostname)))
    ) {
      throw new LoomError("CAPABILITY_DENIED", "Webhook url cannot target metadata services", 403, {
        field: "url",
        host: parsedUrl.hostname
      });
    }

    const allowPrivateNetwork = parseBoolean(payload.allow_private_network, false);
    if (!allowPrivateNetwork && isIP(parsedUrl.hostname) > 0 && isPrivateOrLocalIp(parsedUrl.hostname)) {
      throw new LoomError("CAPABILITY_DENIED", "Webhook url cannot target private or local network", 403, {
        field: "url",
        host: parsedUrl.hostname
      });
    }

    const webhook = {
      id: `wh_${generateUlid()}`,
      url,
      allow_private_network: allowPrivateNetwork,
      events: this.normalizeWebhookEvents(payload.events),
      active: payload.active !== false,
      max_attempts: Math.max(1, Math.min(parsePositiveInteger(payload.max_attempts, 8), 20)),
      timeout_ms: Math.max(250, Math.min(parsePositiveInteger(payload.timeout_ms, 5000), 60000)),
      created_at: nowIso(),
      updated_at: nowIso(),
      last_delivery_at: null,
      last_error: null
    };

    this.webhooksById.set(webhook.id, webhook);
    this.persistAndAudit("webhook.register", {
      webhook_id: webhook.id,
      url: webhook.url,
      actor: actorIdentity
    });
    return webhook;
  }

  listWebhooks() {
    return Array.from(this.webhooksById.values()).sort((a, b) => a.created_at.localeCompare(b.created_at));
  }

  deleteWebhook(webhookId, actorIdentity = "admin") {
    const webhook = this.webhooksById.get(webhookId);
    if (!webhook) {
      throw new LoomError("ENVELOPE_NOT_FOUND", `Webhook not found: ${webhookId}`, 404, {
        webhook_id: webhookId
      });
    }

    this.webhooksById.delete(webhookId);
    this.persistAndAudit("webhook.delete", {
      webhook_id: webhookId,
      actor: actorIdentity
    });
    return {
      webhook_id: webhookId,
      deleted: true
    };
  }

  queueWebhookEventsFromAudit(action, payload, auditEntry) {
    if (!WEBHOOK_DELIVERY_ACTIONS.has(action)) {
      return 0;
    }

    const activeWebhooks = Array.from(this.webhooksById.values()).filter(
      (webhook) => webhook.active && this.webhookMatchesEvent(webhook, action)
    );
    if (activeWebhooks.length === 0) {
      return 0;
    }

    let queued = 0;
    const sourceRequestId = auditEntry?.trace?.request_id || this.getCurrentRequestId();
    const sourceTraceId = auditEntry?.trace?.trace_id || sourceRequestId || null;
    for (const webhook of activeWebhooks) {
      const outbox = {
        id: `wout_${generateUlid()}`,
        webhook_id: webhook.id,
        event_id: auditEntry.event_id,
        event_type: action,
        payload: {
          action,
          data: payload,
          audit: {
            event_id: auditEntry.event_id,
            timestamp: auditEntry.timestamp
          }
        },
        status: "queued",
        attempts: 0,
        max_attempts: webhook.max_attempts,
        timeout_ms: webhook.timeout_ms,
        next_attempt_at: nowIso(),
        created_at: nowIso(),
        updated_at: nowIso(),
        delivered_at: null,
        last_error: null,
        last_http_status: null,
        source_request_id: sourceRequestId || null,
        source_trace_id: sourceTraceId
      };
      this.webhookOutboxById.set(outbox.id, outbox);
      queued += 1;
    }

    return queued;
  }

  listWebhookOutbox(filters = {}) {
    const status = filters.status ? String(filters.status) : null;
    const webhookId = filters.webhook_id ? String(filters.webhook_id) : null;
    const eventType = filters.event_type ? String(filters.event_type) : null;
    const limit = Math.max(1, Math.min(Number(filters.limit || 200), 1000));

    const items = Array.from(this.webhookOutboxById.values())
      .filter((item) => (status ? item.status === status : true))
      .filter((item) => (webhookId ? item.webhook_id === webhookId : true))
      .filter((item) => (eventType ? item.event_type === eventType : true))
      .sort((a, b) => a.created_at.localeCompare(b.created_at));

    return items.slice(0, limit);
  }

  getWebhookOutboxStats() {
    const stats = {
      total: 0,
      queued: 0,
      delivered: 0,
      failed: 0,
      retry_scheduled: 0,
      oldest_queued_at: null,
      newest_queued_at: null,
      lag_ms: 0
    };

    for (const item of this.webhookOutboxById.values()) {
      stats.total += 1;

      if (item.status === "queued") {
        stats.queued += 1;
        if (item.next_attempt_at) {
          stats.retry_scheduled += 1;
        }

        if (!stats.oldest_queued_at || item.created_at < stats.oldest_queued_at) {
          stats.oldest_queued_at = item.created_at;
        }
        if (!stats.newest_queued_at || item.created_at > stats.newest_queued_at) {
          stats.newest_queued_at = item.created_at;
        }
      } else if (item.status === "delivered") {
        stats.delivered += 1;
      } else if (item.status === "failed") {
        stats.failed += 1;
      }
    }

    if (stats.oldest_queued_at) {
      stats.lag_ms = Math.max(0, nowMs() - Date.parse(stats.oldest_queued_at));
    }

    return stats;
  }

  markWebhookOutboxFailure(item, errorMessage, statusCode = null) {
    item.attempts += 1;
    item.updated_at = nowIso();
    item.last_error = String(errorMessage || "webhook delivery failed");
    item.last_http_status = statusCode;

    if (item.attempts >= item.max_attempts) {
      item.status = "failed";
      item.next_attempt_at = null;
      return;
    }

    const backoffSeconds = Math.min(30 * 2 ** Math.max(0, item.attempts - 1), 3600);
    item.status = "queued";
    item.next_attempt_at = new Date(nowMs() + backoffSeconds * 1000).toISOString();
  }

  requeueWebhookOutboxItem(outboxId, actorIdentity = "admin") {
    const item = this.webhookOutboxById.get(outboxId);
    if (!item) {
      throw new LoomError("ENVELOPE_NOT_FOUND", `Webhook outbox item not found: ${outboxId}`, 404, {
        outbox_id: outboxId
      });
    }

    if (item.status !== "failed") {
      throw new LoomError("STATE_TRANSITION_INVALID", "Only failed webhook outbox items can be requeued", 409, {
        outbox_id: outboxId,
        current_status: item.status
      });
    }

    item.status = "queued";
    item.next_attempt_at = nowIso();
    item.updated_at = nowIso();
    item.last_error = null;
    item.last_http_status = null;
    item.receipt = null;
    item.receipt_verified = false;
    item.receipt_verified_at = null;
    item.receipt_verification_error = null;

    this.persistAndAudit("webhook.outbox.requeue", {
      outbox_id: item.id,
      webhook_id: item.webhook_id,
      event_id: item.event_id,
      actor: actorIdentity
    });

    return item;
  }

  async processWebhookOutboxItem(outboxId, actorIdentity = "system") {
    const item = this.webhookOutboxById.get(outboxId);
    if (!item) {
      throw new LoomError("ENVELOPE_NOT_FOUND", `Webhook outbox item not found: ${outboxId}`, 404, {
        outbox_id: outboxId
      });
    }

    if (item.status === "delivered" || item.status === "failed") {
      return item;
    }

    if (item.next_attempt_at && parseTime(item.next_attempt_at) > nowMs()) {
      return item;
    }

    if (!(await this.claimOutboxItemForProcessing("webhook", item))) {
      return item;
    }

    try {
      const webhook = this.webhooksById.get(item.webhook_id);
      if (!webhook || !webhook.active) {
        this.markWebhookOutboxFailure(item, "Webhook target not active");
        this.persistAndAudit("webhook.outbox.process.failed", {
          outbox_id: item.id,
          webhook_id: item.webhook_id,
          event_id: item.event_id,
          reason: item.last_error,
          actor: actorIdentity
        });
        return item;
      }

      if (!this.systemSigningPrivateKeyPem) {
        this.markWebhookOutboxFailure(item, "System signing key not configured");
        this.persistAndAudit("webhook.outbox.process.failed", {
          outbox_id: item.id,
          webhook_id: webhook.id,
          event_id: item.event_id,
          reason: item.last_error,
          actor: actorIdentity
        });
        return item;
      }

      const body = {
        loom: "1.1",
        delivery_id: item.id,
        event_id: item.event_id,
        event_type: item.event_type,
        timestamp: nowIso(),
        node_id: this.nodeId,
        payload: item.payload
      };
      const rawBody = JSON.stringify(body);
      const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
      const timestamp = nowIso();
      const nonce = `wh_${generateUlid()}`;
      const webhookUrl = webhook.url;
      const parsedUrl = new URL(webhookUrl);
      const outboundHostPolicy = await assertOutboundUrlHostAllowed(parsedUrl, {
        allowPrivateNetwork: webhook.allow_private_network === true,
        allowedHosts: this.webhookOutboundHostAllowlist,
        denyMetadataHosts: this.denyMetadataHosts
      });
      const canonical = `POST\n${parsedUrl.pathname}\n${bodyHash}\n${timestamp}\n${nonce}`;
      const signature = signUtf8Message(this.systemSigningPrivateKeyPem, canonical);

      try {
        const timeoutMs = Math.max(250, Math.min(parsePositiveInteger(item.timeout_ms, webhook.timeout_ms), 60000));
        const response = await performPinnedOutboundHttpRequest(webhookUrl, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-loom-event-id": item.event_id,
            "x-loom-delivery-id": item.id,
            "x-loom-event-type": item.event_type,
            "x-loom-key-id": this.systemSigningKeyId,
            "x-loom-timestamp": timestamp,
            "x-loom-nonce": nonce,
            "x-loom-signature": signature
          },
          body: rawBody,
          timeoutMs,
          maxResponseBytes: this.webhookMaxResponseBytes,
          responseSizeContext: {
            webhook_id: webhook.id,
            outbox_id: item.id
          },
          resolvedAddresses: outboundHostPolicy.resolvedAddresses,
          rejectRedirects: true
        });

        if (!response.ok) {
          const responseText = response.bodyText;
          this.markWebhookOutboxFailure(item, `Webhook response ${response.status}: ${responseText}`, response.status);
          this.persistAndAudit("webhook.outbox.process.failed", {
            outbox_id: item.id,
            webhook_id: webhook.id,
            event_id: item.event_id,
            reason: item.last_error,
            source_request_id: item.source_request_id || null,
            source_trace_id: item.source_trace_id || null,
            actor: actorIdentity
          });
          webhook.last_error = item.last_error;
          webhook.updated_at = nowIso();
          return item;
        }

        item.attempts += 1;
        item.status = "delivered";
        item.updated_at = nowIso();
        item.delivered_at = nowIso();
        item.next_attempt_at = null;
        item.last_error = null;
        item.last_http_status = response.status;

        webhook.last_delivery_at = item.delivered_at;
        webhook.last_error = null;
        webhook.updated_at = nowIso();

        this.persistAndAudit("webhook.outbox.process.delivered", {
          outbox_id: item.id,
          webhook_id: webhook.id,
          event_id: item.event_id,
          event_type: item.event_type,
          attempts: item.attempts,
          source_request_id: item.source_request_id || null,
          source_trace_id: item.source_trace_id || null,
          actor: actorIdentity
        });
        return item;
      } catch (error) {
        this.markWebhookOutboxFailure(item, error?.message || "Webhook delivery network error");
        this.persistAndAudit("webhook.outbox.process.failed", {
          outbox_id: item.id,
          webhook_id: webhook.id,
          event_id: item.event_id,
          reason: item.last_error,
          source_request_id: item.source_request_id || null,
          source_trace_id: item.source_trace_id || null,
          actor: actorIdentity
        });
        webhook.last_error = item.last_error;
        webhook.updated_at = nowIso();
        return item;
      }
    } finally {
      await this.releaseOutboxItemClaim("webhook", item);
    }
  }

  async processWebhookOutboxBatch(limit = 10, actorIdentity = "system") {
    const now = nowMs();
    const candidates = Array.from(this.webhookOutboxById.values())
      .filter((item) => item.status === "queued")
      .filter((item) => !item.next_attempt_at || parseTime(item.next_attempt_at) <= now)
      .sort((a, b) => a.created_at.localeCompare(b.created_at))
      .slice(0, Math.max(1, Math.min(Number(limit || 10), 200)));

    const processed = [];
    for (const item of candidates) {
      const result = await this.processWebhookOutboxItem(item.id, actorIdentity);
      processed.push({
        outbox_id: result.id,
        webhook_id: result.webhook_id,
        event_id: result.event_id,
        event_type: result.event_type,
        status: result.status,
        attempts: result.attempts,
        last_error: result.last_error,
        source_request_id: result.source_request_id || null,
        source_trace_id: result.source_trace_id || null
      });
    }

    return {
      processed_count: processed.length,
      processed
    };
  }

  normalizeIdempotencyKey(value) {
    if (value == null) {
      return null;
    }

    const normalized = String(value).trim();
    if (!normalized) {
      return null;
    }

    if (normalized.length > 200) {
      throw new LoomError("ENVELOPE_INVALID", "Idempotency key too long", 400, {
        field: "idempotency_key",
        max_length: 200
      });
    }

    return normalized;
  }

  cleanupIdempotencyCache() {
    const now = nowMs();
    for (const [cacheKey, record] of this.idempotencyByKey.entries()) {
      const expiresAtMs = parseTime(record.expires_at);
      if (expiresAtMs != null && expiresAtMs <= now) {
        this.idempotencyByKey.delete(cacheKey);
      }
    }

    if (this.idempotencyByKey.size <= this.idempotencyMaxEntries) {
      return;
    }

    const overflow = this.idempotencyByKey.size - this.idempotencyMaxEntries;
    if (overflow <= 0) {
      return;
    }

    const oldest = Array.from(this.idempotencyByKey.entries()).sort((a, b) => {
      const aTime = parseTime(a[1].created_at) || 0;
      const bTime = parseTime(b[1].created_at) || 0;
      if (aTime === bTime) {
        return a[0].localeCompare(b[0]);
      }
      return aTime - bTime;
    });

    for (let idx = 0; idx < overflow && idx < oldest.length; idx += 1) {
      this.idempotencyByKey.delete(oldest[idx][0]);
    }
  }

  buildIdempotencyCacheKey(scope, key) {
    return `${scope}::${key}`;
  }

  getIdempotencyResponse(scope, key, requestHash) {
    const normalizedKey = this.normalizeIdempotencyKey(key);
    if (!scope || !normalizedKey) {
      return null;
    }

    this.cleanupIdempotencyCache();
    const cacheKey = this.buildIdempotencyCacheKey(scope, normalizedKey);
    const record = this.idempotencyByKey.get(cacheKey);
    if (!record) {
      return null;
    }

    if (record.request_hash !== requestHash) {
      throw new LoomError("IDEMPOTENCY_CONFLICT", "Idempotency key was already used with different payload", 409, {
        scope,
        key: normalizedKey
      });
    }

    return {
      status: record.status,
      body: record.body
    };
  }

  /**
   * Atomically reserve an idempotency slot so that concurrent async
   * operations with the same key are serialized.  Returns null if the slot
   * cannot be reserved (e.g. missing key), an object with `replay` if a
   * completed response already exists, or an object with a `finalize`
   * callback that MUST be called with (status, body) once the operation
   * completes (or `release` on failure).
   */
  reserveIdempotencySlot(scope, key, requestHash) {
    const normalizedKey = this.normalizeIdempotencyKey(key);
    if (!scope || !normalizedKey) {
      return null;
    }

    this.cleanupIdempotencyCache();
    const cacheKey = this.buildIdempotencyCacheKey(scope, normalizedKey);
    const existing = this.idempotencyByKey.get(cacheKey);

    if (existing) {
      if (existing._inflight) {
        // Another request is already in-flight for this key — treat as replay
        // (the caller should retry or return 409).
        throw new LoomError("IDEMPOTENCY_CONFLICT", "Idempotency key is currently being processed", 409, {
          scope,
          key: normalizedKey
        });
      }
      if (existing.request_hash !== requestHash) {
        throw new LoomError("IDEMPOTENCY_CONFLICT", "Idempotency key was already used with different payload", 409, {
          scope,
          key: normalizedKey
        });
      }
      return { replay: { status: existing.status, body: existing.body } };
    }

    // Plant an in-flight sentinel synchronously so no other tick can claim
    // the same slot.
    const sentinel = {
      _inflight: true,
      key: normalizedKey,
      scope,
      request_hash: requestHash,
      created_at: nowIso(),
      expires_at: new Date(nowMs() + this.idempotencyTtlMs).toISOString()
    };
    this.idempotencyByKey.set(cacheKey, sentinel);

    return {
      finalize: (status, body) => {
        const code = Number(status);
        if (!Number.isFinite(code) || code < 200 || code >= 500) {
          this.idempotencyByKey.delete(cacheKey);
          return null;
        }
        const record = {
          key: normalizedKey,
          scope,
          request_hash: requestHash,
          status: code,
          body,
          created_at: sentinel.created_at,
          expires_at: sentinel.expires_at
        };
        this.idempotencyByKey.set(cacheKey, record);
        return record;
      },
      release: () => {
        this.idempotencyByKey.delete(cacheKey);
      }
    };
  }

  storeIdempotencyResponse(scope, key, requestHash, status, body) {
    const normalizedKey = this.normalizeIdempotencyKey(key);
    if (!scope || !normalizedKey) {
      return null;
    }

    const code = Number(status);
    if (!Number.isFinite(code) || code < 200 || code >= 500) {
      return null;
    }

    this.cleanupIdempotencyCache();
    const cacheKey = this.buildIdempotencyCacheKey(scope, normalizedKey);
    const existing = this.idempotencyByKey.get(cacheKey);
    if (existing && !existing._inflight) {
      if (existing.request_hash !== requestHash) {
        throw new LoomError("IDEMPOTENCY_CONFLICT", "Idempotency key was already used with different payload", 409, {
          scope,
          key: normalizedKey
        });
      }
      return existing;
    }

    const record = {
      key: normalizedKey,
      scope,
      request_hash: requestHash,
      status: code,
      body,
      created_at: nowIso(),
      expires_at: new Date(nowMs() + this.idempotencyTtlMs).toISOString()
    };
    this.idempotencyByKey.set(cacheKey, record);
    this.cleanupIdempotencyCache();

    return record;
  }

  getIdempotencyStatus() {
    return {
      ttl_ms: this.idempotencyTtlMs,
      max_entries: this.idempotencyMaxEntries,
      entries: this.idempotencyByKey.size
    };
  }

  getIdentityRateLimitPolicyStatus() {
    const now = nowMs();
    const rateCutoff = now - this.identityRateWindowMs * 2;
    for (const [key, entry] of this.identityRateByBucket) {
      if (entry.window_started_at < rateCutoff) {
        this.identityRateByBucket.delete(key);
      }
    }
    return {
      window_ms: this.identityRateWindowMs,
      default_max: this.identityRateDefaultMax,
      sensitive_max: this.identityRateSensitiveMax,
      tracked_buckets: this.identityRateByBucket.size
    };
  }

  getAuditEntries(limit = 100) {
    const capped = Math.max(1, Math.min(Number(limit || 100), 1000));
    return this.auditEntries.slice(-capped).reverse();
  }

  registerFederationNode(payload, actorIdentity) {
    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Federation node payload must be an object", 400, {
        field: "node"
      });
    }

    const nodeId = String(payload.node_id || "").trim();
    const activeKeyIdInput = String(payload.active_key_id || payload.key_id || "").trim();
    const payloadKeyId = String(payload.key_id || "").trim();
    const payloadPublicKeyPem = String(payload.public_key_pem || "").trim();
    const replaceSigningKeys = payload.replace_signing_keys === true;
    const payloadSigningKeys = mergeFederationSigningKeys(
      normalizeFederationSigningKeys(payload.signing_keys),
      payloadKeyId && payloadPublicKeyPem
        ? [
            {
              key_id: payloadKeyId,
              public_key_pem: payloadPublicKeyPem
            }
          ]
        : []
    );

    if (!nodeId) {
      throw new LoomError("ENVELOPE_INVALID", "node_id is required", 400, {
        field: "node_id"
      });
    }

    const existing = this.knownNodesById.get(nodeId);
    const existingSigningKeys = getFederationNodeSigningKeys(existing);
    const hasRevokedKeyIds = Object.prototype.hasOwnProperty.call(payload, "revoked_key_ids");
    const revokedKeyIds = hasRevokedKeyIds
      ? normalizeRevokedKeyIds(payload.revoked_key_ids)
      : normalizeRevokedKeyIds(existing?.revoked_key_ids);
    const mergedSigningKeys = replaceSigningKeys
      ? payloadSigningKeys
      : mergeFederationSigningKeys(existingSigningKeys, payloadSigningKeys);
    const signingKeys = applyRevokedKeyIdsToFederationSigningKeys(
      mergedSigningKeys,
      revokedKeyIds,
      payload.trust_anchor_verified_at || existing?.trust_anchor_verified_at || nowIso()
    );
    const hasAllowInsecureHttp = Object.prototype.hasOwnProperty.call(payload, "allow_insecure_http");
    const hasAllowPrivateNetwork = Object.prototype.hasOwnProperty.call(payload, "allow_private_network");
    const allowInsecureHttp = hasAllowInsecureHttp
      ? parseBoolean(payload.allow_insecure_http, false)
      : existing?.allow_insecure_http === true;
    const allowPrivateNetwork = hasAllowPrivateNetwork
      ? parseBoolean(payload.allow_private_network, false)
      : existing?.allow_private_network === true;

    if (signingKeys.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "At least one federation signing key is required", 400, {
        field: "signing_keys"
      });
    }

    let activeKey = resolveFederationNodeSigningKey({ signing_keys: signingKeys }, activeKeyIdInput || existing?.key_id);
    if (!activeKey) {
      activeKey = signingKeys.find((key) => isSigningKeyUsableAt(key)) || signingKeys[0];
    }

    const hasExplicitPolicy = Object.prototype.hasOwnProperty.call(payload, "policy");
    const configuredPolicy = hasExplicitPolicy
      ? String(payload.policy || "trusted")
      : existing?.configured_policy || existing?.policy || "trusted";
    const hasTrustAnchorMode = Object.prototype.hasOwnProperty.call(payload, "trust_anchor_mode");
    const trustAnchorMode = normalizeFederationTrustMode(
      hasTrustAnchorMode ? payload.trust_anchor_mode : existing?.trust_anchor_mode || this.federationTrustMode,
      { hasTrustAnchors: this.federationTrustAnchorBindings.size > 0 }
    );
    const hasTrustAnchorEpoch = Object.prototype.hasOwnProperty.call(payload, "trust_anchor_epoch");
    const trustAnchorEpoch = Math.max(
      0,
      parseNonNegativeInteger(
        hasTrustAnchorEpoch ? payload.trust_anchor_epoch : existing?.trust_anchor_epoch,
        0
      )
    );
    const hasTrustAnchorKeysetVersion = Object.prototype.hasOwnProperty.call(payload, "trust_anchor_keyset_version");
    const trustAnchorKeysetVersion = Math.max(
      0,
      parseNonNegativeInteger(
        hasTrustAnchorKeysetVersion ? payload.trust_anchor_keyset_version : existing?.trust_anchor_keyset_version,
        0
      )
    );
    const hasTrustAnchorKeysetHash = Object.prototype.hasOwnProperty.call(payload, "trust_anchor_keyset_hash");
    const trustAnchorKeysetHash =
      normalizeHexDigest(
        hasTrustAnchorKeysetHash ? payload.trust_anchor_keyset_hash : existing?.trust_anchor_keyset_hash
      ) || null;
    const hasTrustAnchorDnsName = Object.prototype.hasOwnProperty.call(payload, "trust_anchor_dns_name");
    const trustAnchorDnsName = (() => {
      const value = hasTrustAnchorDnsName ? payload.trust_anchor_dns_name : existing?.trust_anchor_dns_name;
      if (value == null) {
        return null;
      }
      const normalized = String(value).trim();
      return normalized || null;
    })();
    const hasTrustAnchorDnsRecord = Object.prototype.hasOwnProperty.call(payload, "trust_anchor_dns_record");
    const trustAnchorDnsRecord = (() => {
      const value = hasTrustAnchorDnsRecord ? payload.trust_anchor_dns_record : existing?.trust_anchor_dns_record;
      if (value == null) {
        return null;
      }
      const normalized = String(value).trim();
      return normalized || null;
    })();
    const hasTrustAnchorKeysetUrl = Object.prototype.hasOwnProperty.call(payload, "trust_anchor_keyset_url");
    const trustAnchorKeysetUrl = (() => {
      const value = hasTrustAnchorKeysetUrl ? payload.trust_anchor_keyset_url : existing?.trust_anchor_keyset_url;
      if (value == null) {
        return null;
      }
      const normalized = String(value).trim();
      return normalized || null;
    })();
    const hasTrustAnchorRevocationsUrl = Object.prototype.hasOwnProperty.call(payload, "trust_anchor_revocations_url");
    const trustAnchorRevocationsUrl = (() => {
      const value = hasTrustAnchorRevocationsUrl
        ? payload.trust_anchor_revocations_url
        : existing?.trust_anchor_revocations_url;
      if (value == null) {
        return null;
      }
      const normalized = String(value).trim();
      return normalized || null;
    })();
    const hasTrustAnchorVerifiedAt = Object.prototype.hasOwnProperty.call(payload, "trust_anchor_verified_at");
    const trustAnchorVerifiedAt = (() => {
      const value = hasTrustAnchorVerifiedAt ? payload.trust_anchor_verified_at : existing?.trust_anchor_verified_at;
      if (value == null) {
        return null;
      }
      const normalized = String(value).trim();
      return normalized || null;
    })();
    const hasTrustAnchorDnssecValidated = Object.prototype.hasOwnProperty.call(payload, "trust_anchor_dnssec_validated");
    const trustAnchorDnssecValidated = hasTrustAnchorDnssecValidated
      ? payload.trust_anchor_dnssec_validated === true
      : existing?.trust_anchor_dnssec_validated === true;
    const hasTrustAnchorDnssecSource = Object.prototype.hasOwnProperty.call(payload, "trust_anchor_dnssec_source");
    const trustAnchorDnssecSource = (() => {
      const value = hasTrustAnchorDnssecSource ? payload.trust_anchor_dnssec_source : existing?.trust_anchor_dnssec_source;
      if (value == null) {
        return null;
      }
      const normalized = String(value).trim();
      return normalized || null;
    })();
    const hasTrustAnchorTransparencyLogId = Object.prototype.hasOwnProperty.call(
      payload,
      "trust_anchor_transparency_log_id"
    );
    const trustAnchorTransparencyLogId = (() => {
      const value = hasTrustAnchorTransparencyLogId
        ? payload.trust_anchor_transparency_log_id
        : existing?.trust_anchor_transparency_log_id;
      if (value == null) {
        return null;
      }
      const normalized = String(value).trim();
      return normalized || null;
    })();
    const hasTrustAnchorTransparencyMode = Object.prototype.hasOwnProperty.call(
      payload,
      "trust_anchor_transparency_mode"
    );
    const trustAnchorTransparencyMode = (() => {
      const value = hasTrustAnchorTransparencyMode
        ? payload.trust_anchor_transparency_mode
        : existing?.trust_anchor_transparency_mode || this.federationTrustTransparencyMode;
      const normalized = String(value || "")
        .trim()
        .toLowerCase();
      return normalized || this.federationTrustTransparencyMode;
    })();
    const hasTrustAnchorTransparencyCheckpoint = Object.prototype.hasOwnProperty.call(
      payload,
      "trust_anchor_transparency_checkpoint"
    );
    const trustAnchorTransparencyCheckpoint = (() => {
      const value = hasTrustAnchorTransparencyCheckpoint
        ? payload.trust_anchor_transparency_checkpoint
        : existing?.trust_anchor_transparency_checkpoint;
      if (value == null) {
        return null;
      }
      const normalized = String(value).trim().toLowerCase();
      return normalized || null;
    })();
    const hasTrustAnchorTransparencyPreviousCheckpoint = Object.prototype.hasOwnProperty.call(
      payload,
      "trust_anchor_transparency_previous_checkpoint"
    );
    const trustAnchorTransparencyPreviousCheckpoint = (() => {
      const value = hasTrustAnchorTransparencyPreviousCheckpoint
        ? payload.trust_anchor_transparency_previous_checkpoint
        : existing?.trust_anchor_transparency_previous_checkpoint;
      if (value == null) {
        return null;
      }
      const normalized = String(value).trim().toLowerCase();
      return normalized || null;
    })();
    const hasTrustAnchorTransparencyEventIndex = Object.prototype.hasOwnProperty.call(
      payload,
      "trust_anchor_transparency_event_index"
    );
    const trustAnchorTransparencyEventIndex = (() => {
      const value = hasTrustAnchorTransparencyEventIndex
        ? payload.trust_anchor_transparency_event_index
        : existing?.trust_anchor_transparency_event_index;
      const parsed = parseNonNegativeInteger(value, -1);
      return parsed >= 0 ? parsed : null;
    })();
    const hasTrustAnchorTransparencyVerifiedAt = Object.prototype.hasOwnProperty.call(
      payload,
      "trust_anchor_transparency_verified_at"
    );
    const trustAnchorTransparencyVerifiedAt = (() => {
      const value = hasTrustAnchorTransparencyVerifiedAt
        ? payload.trust_anchor_transparency_verified_at
        : existing?.trust_anchor_transparency_verified_at;
      if (value == null) {
        return null;
      }
      const normalized = String(value).trim();
      return normalized || null;
    })();
    const deliverUrl = normalizeFederationDeliverUrl(payload.deliver_url || existing?.deliver_url || null, {
      allowInsecureHttp,
      allowPrivateNetwork
    });
    const hasIdentityResolveUrl = Object.prototype.hasOwnProperty.call(payload, "identity_resolve_url");
    const identityResolveUrl = normalizeFederationIdentityResolveUrl(
      hasIdentityResolveUrl ? payload.identity_resolve_url : existing?.identity_resolve_url || null,
      {
        allowInsecureHttp,
        allowPrivateNetwork
      }
    );
    const hasNodeDocumentUrl = Object.prototype.hasOwnProperty.call(payload, "node_document_url");
    const nodeDocumentUrl = normalizeFederationNodeDocumentUrl(
      hasNodeDocumentUrl ? payload.node_document_url : existing?.node_document_url || null,
      {
        allowInsecureHttp,
        allowPrivateNetwork
      }
    );
    const hasProtocolCapabilitiesUrl = Object.prototype.hasOwnProperty.call(payload, "protocol_capabilities_url");
    const protocolCapabilitiesUrl = normalizeFederationProtocolCapabilitiesUrl(
      hasProtocolCapabilitiesUrl ? payload.protocol_capabilities_url : existing?.protocol_capabilities_url || null,
      {
        allowInsecureHttp,
        allowPrivateNetwork
      }
    );
    const hasProtocolCapabilities = Object.prototype.hasOwnProperty.call(payload, "protocol_capabilities");
    const protocolCapabilities = hasProtocolCapabilities
      ? normalizeProtocolCapabilitiesDocument(payload.protocol_capabilities)
      : normalizeProtocolCapabilitiesDocument(existing?.protocol_capabilities);
    const hasProtocolCapabilitiesFetchedAt = Object.prototype.hasOwnProperty.call(
      payload,
      "protocol_capabilities_fetched_at"
    );
    const protocolCapabilitiesFetchedAt = (() => {
      const value = hasProtocolCapabilitiesFetchedAt
        ? payload.protocol_capabilities_fetched_at
        : existing?.protocol_capabilities_fetched_at;
      if (value == null) {
        return null;
      }
      const normalized = String(value).trim();
      return normalized || null;
    })();
    const hasProtocolCapabilitiesFetchError = Object.prototype.hasOwnProperty.call(
      payload,
      "protocol_capabilities_fetch_error"
    );
    const protocolCapabilitiesFetchError = (() => {
      const value = hasProtocolCapabilitiesFetchError
        ? payload.protocol_capabilities_fetch_error
        : existing?.protocol_capabilities_fetch_error;
      if (value == null) {
        return null;
      }
      const normalized = String(value).trim();
      return normalized || null;
    })();
    const derivedProtocolNegotiation = protocolCapabilities
      ? this.deriveFederationProtocolNegotiationState(protocolCapabilities)
      : null;
    const hasNegotiatedE2eeProfiles = Object.prototype.hasOwnProperty.call(payload, "negotiated_e2ee_profiles");
    const negotiatedE2eeProfiles = hasNegotiatedE2eeProfiles
      ? normalizeProtocolCapabilityE2eeProfiles(payload.negotiated_e2ee_profiles)
      : normalizeProtocolCapabilityE2eeProfiles(
          existing?.negotiated_e2ee_profiles || derivedProtocolNegotiation?.negotiated_e2ee_profiles
        );
    const hasProtocolNegotiatedTrustAnchorMode = Object.prototype.hasOwnProperty.call(
      payload,
      "protocol_negotiated_trust_anchor_mode"
    );
    const protocolNegotiatedTrustAnchorMode = (() => {
      const rawValue = hasProtocolNegotiatedTrustAnchorMode
        ? payload.protocol_negotiated_trust_anchor_mode
        : existing?.protocol_negotiated_trust_anchor_mode || derivedProtocolNegotiation?.negotiated_trust_anchor_mode;
      const normalized = String(rawValue || "").trim();
      if (!normalized) {
        return null;
      }
      return normalizeFederationTrustMode(normalized, {
        hasTrustAnchors: this.federationTrustAnchorBindings.size > 0
      });
    })();

    const node = {
      node_id: nodeId,
      key_id: activeKey.key_id,
      public_key_pem: activeKey.public_key_pem,
      signing_keys: signingKeys,
      deliver_url: deliverUrl,
      identity_resolve_url: identityResolveUrl,
      node_document_url: nodeDocumentUrl,
      protocol_capabilities_url: protocolCapabilitiesUrl,
      protocol_capabilities: protocolCapabilities,
      protocol_capabilities_fetched_at: protocolCapabilitiesFetchedAt,
      protocol_capabilities_fetch_error: protocolCapabilitiesFetchError,
      negotiated_e2ee_profiles: negotiatedE2eeProfiles,
      protocol_negotiated_trust_anchor_mode: protocolNegotiatedTrustAnchorMode,
      allow_insecure_http: allowInsecureHttp,
      allow_private_network: allowPrivateNetwork,
      configured_policy: configuredPolicy,
      policy: configuredPolicy,
      trust_anchor_mode: trustAnchorMode,
      trust_anchor_dns_name: trustAnchorDnsName,
      trust_anchor_dns_record: trustAnchorDnsRecord,
      trust_anchor_keyset_url: trustAnchorKeysetUrl,
      trust_anchor_keyset_hash: trustAnchorKeysetHash,
      trust_anchor_keyset_version: trustAnchorKeysetVersion,
      trust_anchor_epoch: trustAnchorEpoch,
      trust_anchor_verified_at: trustAnchorVerifiedAt,
      trust_anchor_revocations_url: trustAnchorRevocationsUrl,
      trust_anchor_dnssec_validated: trustAnchorDnssecValidated,
      trust_anchor_dnssec_source: trustAnchorDnssecSource,
      trust_anchor_transparency_log_id: trustAnchorTransparencyLogId,
      trust_anchor_transparency_mode: trustAnchorTransparencyMode,
      trust_anchor_transparency_checkpoint: trustAnchorTransparencyCheckpoint,
      trust_anchor_transparency_previous_checkpoint: trustAnchorTransparencyPreviousCheckpoint,
      trust_anchor_transparency_event_index: trustAnchorTransparencyEventIndex,
      trust_anchor_transparency_verified_at: trustAnchorTransparencyVerifiedAt,
      revoked_key_ids: revokedKeyIds,
      auto_policy: hasExplicitPolicy ? null : existing?.auto_policy || null,
      auto_policy_until: hasExplicitPolicy ? null : existing?.auto_policy_until || null,
      auto_policy_reason: hasExplicitPolicy ? null : existing?.auto_policy_reason || null,
      challenge_required_until: existing?.challenge_required_until || null,
      challenge_reason: existing?.challenge_reason || null,
      reputation_score: Math.max(0, Number(existing?.reputation_score || 0)),
      created_at: existing?.created_at || nowIso(),
      updated_at: nowIso()
    };

    if (node.auto_policy && !isExpiredIso(node.auto_policy_until)) {
      node.policy = node.auto_policy;
    } else {
      node.auto_policy = null;
      node.auto_policy_until = null;
      node.auto_policy_reason = null;
    }

    if (isExpiredIso(node.challenge_required_until)) {
      node.challenge_required_until = null;
      node.challenge_reason = null;
    }

    this.knownNodesById.set(nodeId, node);
    this.persistAndAudit("federation.node.upsert", {
      node_id: nodeId,
      key_id: node.key_id,
      signing_key_count: node.signing_keys.length,
      actor: actorIdentity
    });
    return node;
  }

  listFederationNodes() {
    this.refreshAllFederationNodeAutoPolicies();
    return Array.from(this.knownNodesById.values()).sort((a, b) => a.node_id.localeCompare(b.node_id));
  }

  buildFederationNodeRevalidationPayload(node, overrides = {}) {
    const existingNode = node && typeof node === "object" ? node : null;
    if (!existingNode?.node_id) {
      throw new LoomError("ENVELOPE_INVALID", "Known federation node is required for trust revalidation", 400, {
        field: "node"
      });
    }

    const requestedNodeDocumentUrl = String(
      overrides.node_document_url || existingNode.node_document_url || ""
    ).trim();
    const fallbackNodeDocumentUrl = `https://${existingNode.node_id}/.well-known/loom.json`;
    const deliverUrlHost = (() => {
      try {
        return new URL(String(existingNode.deliver_url || "")).hostname;
      } catch {
        return null;
      }
    })();
    const allowCrossHostDeliverUrl = Boolean(
      deliverUrlHost && String(deliverUrlHost).trim().toLowerCase() !== String(existingNode.node_id).trim().toLowerCase()
    );

    return {
      node_document_url: requestedNodeDocumentUrl || fallbackNodeDocumentUrl,
      allow_insecure_http: existingNode.allow_insecure_http === true,
      allow_private_network: existingNode.allow_private_network === true,
      allow_cross_host_deliver_url: allowCrossHostDeliverUrl,
      deliver_url: existingNode.deliver_url || undefined,
      identity_resolve_url: existingNode.identity_resolve_url || undefined,
      protocol_capabilities_url: existingNode.protocol_capabilities_url || undefined,
      policy: existingNode.configured_policy || existingNode.policy || "trusted",
      trust_anchor_mode: existingNode.trust_anchor_mode || this.federationTrustMode,
      trust_anchor_keyset_url: existingNode.trust_anchor_keyset_url || undefined,
      trust_anchor_revocations_url: existingNode.trust_anchor_revocations_url || undefined,
      active_key_id: existingNode.key_id || undefined,
      replace_signing_keys:
        String(existingNode.trust_anchor_mode || "").trim().toLowerCase() === "public_dns_webpki",
      timeout_ms: overrides.timeout_ms || undefined,
      max_response_bytes: overrides.max_response_bytes || undefined
    };
  }

  async revalidateFederationNodeTrust(nodeId, actorIdentity, options = {}) {
    const normalizedNodeId = String(nodeId || "").trim();
    if (!normalizedNodeId) {
      throw new LoomError("ENVELOPE_INVALID", "node_id is required for federation node revalidation", 400, {
        field: "node_id"
      });
    }

    const node = this.knownNodesById.get(normalizedNodeId);
    if (!node) {
      throw new LoomError("ENVELOPE_INVALID", `Unknown federation node: ${normalizedNodeId}`, 400, {
        node_id: normalizedNodeId
      });
    }

    const mode = String(node.trust_anchor_mode || "").trim().toLowerCase();
    const includeNonPublic = options.include_non_public_modes === true;
    if (mode !== "public_dns_webpki" && !includeNonPublic) {
      return {
        node_id: normalizedNodeId,
        status: "skipped",
        reason: "trust_mode_not_public_dns_webpki",
        trust_anchor_mode: node.trust_anchor_mode || null
      };
    }

    const payload = this.buildFederationNodeRevalidationPayload(node, options);
    const previousTrustEpoch = Math.max(0, parseNonNegativeInteger(node.trust_anchor_epoch, 0));
    const previousKeysetVersion = Math.max(0, parseNonNegativeInteger(node.trust_anchor_keyset_version, 0));
    const previousKeysetHash = normalizeHexDigest(node.trust_anchor_keyset_hash) || null;

    const result = await this.bootstrapFederationNode(payload, actorIdentity);
    const updatedNode = result?.node || this.knownNodesById.get(normalizedNodeId);
    const nextTrustEpoch = Math.max(0, parseNonNegativeInteger(updatedNode?.trust_anchor_epoch, 0));
    const nextKeysetVersion = Math.max(0, parseNonNegativeInteger(updatedNode?.trust_anchor_keyset_version, 0));
    const nextKeysetHash = normalizeHexDigest(updatedNode?.trust_anchor_keyset_hash) || null;

    this.persistAndAudit("federation.node.revalidate", {
      node_id: normalizedNodeId,
      trust_anchor_mode: updatedNode?.trust_anchor_mode || null,
      previous_trust_epoch: previousTrustEpoch,
      next_trust_epoch: nextTrustEpoch,
      previous_keyset_version: previousKeysetVersion,
      next_keyset_version: nextKeysetVersion,
      previous_keyset_hash: previousKeysetHash,
      next_keyset_hash: nextKeysetHash,
      actor: actorIdentity
    });

    return {
      node_id: normalizedNodeId,
      status: "revalidated",
      node: updatedNode,
      previous: {
        trust_epoch: previousTrustEpoch,
        keyset_version: previousKeysetVersion,
        keyset_hash: previousKeysetHash
      },
      next: {
        trust_epoch: nextTrustEpoch,
        keyset_version: nextKeysetVersion,
        keyset_hash: nextKeysetHash
      },
      discovery: result?.discovery || null
    };
  }

  async revalidateFederationNodesTrust(payload, actorIdentity) {
    const options = payload && typeof payload === "object" ? payload : {};
    const includeNonPublic = options.include_non_public_modes === true;
    const continueOnError = options.continue_on_error !== false;
    const requestedNodeIds = Array.isArray(options.node_ids)
      ? Array.from(
          new Set(
            options.node_ids
              .map((entry) => String(entry || "").trim())
              .filter(Boolean)
          )
        )
      : [];
    const targetNodeIds =
      requestedNodeIds.length > 0
        ? requestedNodeIds
        : Array.from(this.knownNodesById.keys()).sort((left, right) => left.localeCompare(right));
    const limit = Math.max(1, Math.min(parsePositiveInteger(options.limit, targetNodeIds.length || 1), 1000));

    const processed = [];
    const skipped = [];
    const failed = [];

    for (const nodeId of targetNodeIds.slice(0, limit)) {
      try {
        const result = await this.revalidateFederationNodeTrust(nodeId, actorIdentity, {
          include_non_public_modes: includeNonPublic,
          timeout_ms: options.timeout_ms,
          max_response_bytes: options.max_response_bytes,
          node_document_url:
            options.node_document_urls && typeof options.node_document_urls === "object"
              ? options.node_document_urls[nodeId]
              : null
        });
        if (result?.status === "skipped") {
          skipped.push(result);
        } else {
          processed.push(result);
        }
      } catch (error) {
        const failure = {
          node_id: nodeId,
          status: "failed",
          error_code: error?.code || "UNKNOWN",
          error: error?.message || String(error)
        };
        failed.push(failure);
        if (!continueOnError) {
          const summaryError = new LoomError("NODE_UNREACHABLE", "Federation node revalidation failed", 502, {
            node_id: nodeId,
            error_code: failure.error_code,
            reason: failure.error
          });
          summaryError.details = {
            processed,
            skipped,
            failed
          };
          throw summaryError;
        }
      }
    }

    return {
      requested_count: targetNodeIds.length,
      attempted_count: Math.min(limit, targetNodeIds.length),
      revalidated_count: processed.length,
      skipped_count: skipped.length,
      failed_count: failed.length,
      processed,
      skipped,
      failed
    };
  }

  resolveFederationBootstrapNodeDocumentUrl(payload) {
    const explicitUrl = String(payload?.node_document_url || payload?.well_known_url || "").trim();
    if (explicitUrl) {
      return explicitUrl;
    }

    const targetDomain = String(payload?.domain || payload?.node_id || "").trim();
    if (!targetDomain) {
      throw new LoomError("ENVELOPE_INVALID", "node_document_url or domain is required for federation bootstrap", 400, {
        field: "node_document_url"
      });
    }

    return `https://${targetDomain}/.well-known/loom.json`;
  }

  resolveFederationBootstrapTrustMode(payload) {
    const hasOverride = payload && Object.prototype.hasOwnProperty.call(payload, "trust_anchor_mode");
    return normalizeFederationTrustMode(hasOverride ? payload?.trust_anchor_mode : this.federationTrustMode, {
      hasTrustAnchors: this.federationTrustAnchorBindings.size > 0
    });
  }

  resolveFederationTrustDnsName(nodeId) {
    const rawAuthority = String(nodeId || "")
      .trim()
      .toLowerCase()
      .replace(/^[a-z][a-z0-9+.-]*:\/\//, "")
      .split("/")[0];
    let hostOnly = rawAuthority;
    if (rawAuthority.startsWith("[") && rawAuthority.includes("]")) {
      hostOnly = rawAuthority.slice(1, rawAuthority.indexOf("]"));
    } else if (rawAuthority.includes(":")) {
      hostOnly = rawAuthority.split(":")[0];
    }
    const normalizedNodeAuthority = normalizeHostname(hostOnly);
    if (!normalizedNodeAuthority) {
      throw new LoomError("ENVELOPE_INVALID", "Federation node_id is required for trust-anchor DNS lookup", 400, {
        field: "node_id"
      });
    }
    const label = String(this.federationTrustDnsTxtLabel || "_loomfed")
      .trim()
      .replace(/\.+$/, "");
    const normalizedLabel = label.length > 0 ? label : "_loomfed";
    return `${normalizedLabel}.${normalizedNodeAuthority}`;
  }

  async resolveFederationTrustDnsProof(nodeId) {
    const dnsName = this.resolveFederationTrustDnsName(nodeId);
    let resolverResult;
    try {
      resolverResult = normalizeFederationTrustDnsResolverResult(await this.federationTrustDnsTxtResolver(dnsName));
    } catch (error) {
      if (this.federationTrustFailClosed) {
        throw new LoomError("NODE_UNREACHABLE", "Failed to resolve federation trust-anchor DNS TXT record", 502, {
          node_id: nodeId,
          dns_name: dnsName,
          reason: error?.message || String(error)
        });
      }
      return {
        dns_name: dnsName,
        record: null,
        fields: {},
        all_records: [],
        dnssec_validated: false,
        dnssec_source: null
      };
    }

    if (this.federationTrustRequireDnssec && resolverResult.dnssec_validated !== true) {
      throw new LoomError(
        "SIGNATURE_INVALID",
        "Federation trust-anchor DNS TXT lookup did not provide DNSSEC-validated proof",
        401,
        {
          node_id: nodeId,
          dns_name: dnsName,
          dnssec_validated: resolverResult.dnssec_validated === true,
          dnssec_source: resolverResult.dnssec_source || null
        }
      );
    }

    const records = resolverResult.records;
    const candidates = records
      .map((record) => ({
        record,
        fields: parseFederationTrustDnsTxtRecord(record)
      }))
      .filter((candidate) => Object.keys(candidate.fields).length > 0)
      .filter((candidate) => {
        const version = String(candidate.fields.v || candidate.fields.version || "")
          .trim()
          .toLowerCase();
        if (!version) {
          return true;
        }
        return version === "loomfed1" || version === "loom1" || version === "loom-federation-1";
      });

    const preferred =
      candidates.find((candidate) => {
        const hasKeysetUrl = Boolean(candidate.fields.keyset || candidate.fields.ks || candidate.fields.k);
        const hasDigest = Boolean(candidate.fields.digest || candidate.fields.sha256 || candidate.fields.hash || candidate.fields.h);
        return hasKeysetUrl && hasDigest;
      }) ||
      candidates[0] ||
      null;

    if (!preferred && this.federationTrustFailClosed) {
      throw new LoomError("SIGNATURE_INVALID", "Federation trust-anchor DNS TXT record is missing or invalid", 401, {
        node_id: nodeId,
        dns_name: dnsName
      });
    }

    return {
      dns_name: dnsName,
      record: preferred?.record || null,
      fields: preferred?.fields || {},
      all_records: records,
      dnssec_validated: resolverResult.dnssec_validated === true,
      dnssec_source: resolverResult.dnssec_source || null
    };
  }

  deriveFederationTrustTransparencyState(nodeId, trustEpoch, keysetVersion, keysetHash, previousNode = null) {
    const normalizedNodeId = String(nodeId || "").trim();
    const normalizedHash = normalizeHexDigest(keysetHash);
    const normalizedEpoch = Math.max(0, parseNonNegativeInteger(trustEpoch, 0));
    const normalizedVersion = Math.max(0, parseNonNegativeInteger(keysetVersion, 0));
    if (!normalizedNodeId || !normalizedHash) {
      throw new LoomError("ENVELOPE_INVALID", "Transparency state requires node_id and keyset hash", 400, {
        node_id: normalizedNodeId || null
      });
    }

    const previous = previousNode && typeof previousNode === "object" ? previousNode : this.knownNodesById.get(normalizedNodeId) || null;
    const previousCheckpoint = String(previous?.trust_anchor_transparency_checkpoint || "")
      .trim()
      .toLowerCase() || null;
    const previousEventIndex = parseNonNegativeInteger(previous?.trust_anchor_transparency_event_index, -1);
    const previousEpoch = Math.max(0, parseNonNegativeInteger(previous?.trust_anchor_epoch, 0));
    const previousVersion = Math.max(0, parseNonNegativeInteger(previous?.trust_anchor_keyset_version, 0));
    const previousHash = normalizeHexDigest(previous?.trust_anchor_keyset_hash);

    if (
      previous &&
      previousHash === normalizedHash &&
      previousEpoch === normalizedEpoch &&
      previousVersion === normalizedVersion &&
      previousCheckpoint &&
      previousEventIndex >= 0
    ) {
      return {
        log_id: String(previous?.trust_anchor_transparency_log_id || `loom-local-trust-log:${this.nodeId}`).trim(),
        mode: String(previous?.trust_anchor_transparency_mode || this.federationTrustTransparencyMode).trim().toLowerCase(),
        checkpoint: previousCheckpoint,
        previous_checkpoint: String(previous?.trust_anchor_transparency_previous_checkpoint || "")
          .trim()
          .toLowerCase() || null,
        event_index: previousEventIndex,
        verified_at: String(previous?.trust_anchor_transparency_verified_at || "")
          .trim() || nowIso(),
        appended: false
      };
    }

    const eventIndex = Math.max(0, previousEventIndex + 1);
    const payload = {
      type: "loom.federation.transparency.event@v1",
      node_id: normalizedNodeId,
      trust_epoch: normalizedEpoch,
      keyset_version: normalizedVersion,
      keyset_hash: normalizedHash,
      previous_checkpoint: previousCheckpoint,
      event_index: eventIndex
    };
    const checkpoint = createHash("sha256").update(canonicalizeJson(payload), "utf-8").digest("hex");
    return {
      log_id: `loom-local-trust-log:${this.nodeId}`,
      mode: this.federationTrustTransparencyMode,
      checkpoint,
      previous_checkpoint: previousCheckpoint,
      event_index: eventIndex,
      verified_at: nowIso(),
      appended: true
    };
  }

  async fetchFederationJsonDocument(url, options = {}) {
    const allowInsecureHttp = options.allowInsecureHttp === true;
    const allowPrivateNetwork = options.allowPrivateNetwork === true;
    const timeoutMs = Math.max(500, parsePositiveInteger(options.timeoutMs, 5000));
    const maxResponseBytes = Math.max(1024, parsePositiveInteger(options.maxResponseBytes, 256 * 1024));
    let parsedUrl;
    try {
      parsedUrl = new URL(String(url || ""));
    } catch {
      throw new LoomError("ENVELOPE_INVALID", "Federation document URL must be a valid absolute URL", 400, {
        field: options.field || "url"
      });
    }

    if (parsedUrl.username || parsedUrl.password) {
      throw new LoomError("ENVELOPE_INVALID", "Federation document URL must not include credentials", 400, {
        field: options.field || "url"
      });
    }

    if (parsedUrl.protocol !== "https:" && !(allowInsecureHttp && parsedUrl.protocol === "http:")) {
      throw new LoomError("ENVELOPE_INVALID", "Federation document URL must use https unless allow_insecure_http=true", 400, {
        field: options.field || "url",
        protocol: parsedUrl.protocol
      });
    }

    const hostPolicy = await assertOutboundUrlHostAllowed(parsedUrl, {
      allowPrivateNetwork,
      allowedHosts: options.allowedHosts || this.federationBootstrapHostAllowlist,
      denyMetadataHosts: this.denyMetadataHosts
    });

    let response;
    try {
      response = await performPinnedOutboundHttpRequest(parsedUrl, {
        method: "GET",
        headers: {
          accept: "application/json"
        },
        timeoutMs,
        maxResponseBytes,
        responseSizeContext: {
          url: parsedUrl.toString(),
          field: options.field || "url"
        },
        resolvedAddresses: hostPolicy.resolvedAddresses,
        rejectRedirects: true
      });
    } catch (error) {
      if (error instanceof LoomError) {
        throw error;
      }
      if (error?.name === "AbortError") {
        throw new LoomError("DELIVERY_TIMEOUT", "Federation document fetch timed out", 504, {
          url: parsedUrl.toString(),
          timeout_ms: timeoutMs
        });
      }
      throw new LoomError("NODE_UNREACHABLE", "Federation document fetch failed", 502, {
        url: parsedUrl.toString(),
        reason: error?.message || String(error)
      });
    }

    if (!response.ok) {
      throw new LoomError("NODE_UNREACHABLE", `Federation document fetch returned ${response.status}`, 502, {
        url: parsedUrl.toString(),
        status: response.status
      });
    }

    try {
      return {
        url: parsedUrl.toString(),
        payload: JSON.parse(response.bodyText)
      };
    } catch {
      throw new LoomError("ENVELOPE_INVALID", "Federation document response must be valid JSON", 400, {
        field: options.field || "url",
        url: parsedUrl.toString()
      });
    }
  }

  deriveFederationProtocolNegotiationState(protocolCapabilities) {
    const normalizedCapabilities = normalizeProtocolCapabilitiesDocument(protocolCapabilities);
    if (!normalizedCapabilities) {
      return null;
    }

    const localTrustAnchorMode = this.getFederationTrustAnchorMode();
    const localE2eeProfiles = listSupportedE2eeProfiles();
    const remoteE2eeProfiles = normalizeProtocolCapabilityE2eeProfiles(
      normalizedCapabilities?.federation_negotiation?.e2ee_profiles
    );
    const negotiatedE2eeProfiles = intersectStrings(localE2eeProfiles, remoteE2eeProfiles);
    const remoteTrustAnchorModes = normalizeProtocolCapabilityTrustModes(
      normalizedCapabilities?.federation_negotiation?.trust_anchor_modes_supported
    );
    const remoteTrustAnchorMode = normalizeFederationTrustMode(
      normalizedCapabilities?.federation_negotiation?.trust_anchor_mode,
      {
        hasTrustAnchors: this.federationTrustAnchorBindings.size > 0
      }
    );
    const remoteTrustAnchorModesSupported =
      remoteTrustAnchorModes.length > 0
        ? remoteTrustAnchorModes
        : Array.from(new Set([remoteTrustAnchorMode].filter(Boolean)));
    const trustModeParity = remoteTrustAnchorModesSupported.includes(localTrustAnchorMode);

    return {
      protocol_capabilities: normalizedCapabilities,
      local_e2ee_profiles: localE2eeProfiles,
      remote_e2ee_profiles: remoteE2eeProfiles,
      negotiated_e2ee_profiles: negotiatedE2eeProfiles,
      local_trust_anchor_mode: localTrustAnchorMode,
      remote_trust_anchor_modes_supported: remoteTrustAnchorModesSupported,
      negotiated_trust_anchor_mode: trustModeParity ? localTrustAnchorMode : null,
      trust_mode_parity: trustModeParity
    };
  }

  assertFederationProtocolNegotiationRequirements(negotiationState, context = {}) {
    const nodeId = String(context.node_id || "").trim() || null;
    const state = negotiationState && typeof negotiationState === "object" ? negotiationState : null;
    const hasProtocolCapabilities = Boolean(state?.protocol_capabilities);

    if (this.federationRequireProtocolCapabilities && !hasProtocolCapabilities) {
      throw new LoomError(
        "CAPABILITY_DENIED",
        "Federation node must publish protocol capabilities for negotiation",
        403,
        {
          node_id: nodeId,
          requirement: "protocol_capabilities"
        }
      );
    }

    if (this.federationRequireTrustModeParity) {
      const parity = state?.trust_mode_parity === true;
      if (!parity) {
        throw new LoomError(
          "CAPABILITY_DENIED",
          "Federation trust-anchor mode parity negotiation failed",
          403,
          {
            node_id: nodeId,
            local_trust_anchor_mode: state?.local_trust_anchor_mode || this.getFederationTrustAnchorMode(),
            remote_trust_anchor_modes_supported: state?.remote_trust_anchor_modes_supported || []
          }
        );
      }
    }

    if (this.federationRequireE2eeProfileOverlap) {
      const overlap = normalizeProtocolCapabilityE2eeProfiles(state?.negotiated_e2ee_profiles);
      if (overlap.length === 0) {
        throw new LoomError("CAPABILITY_DENIED", "Federation E2EE profile negotiation overlap is required", 403, {
          node_id: nodeId,
          local_e2ee_profiles: state?.local_e2ee_profiles || listSupportedE2eeProfiles(),
          remote_e2ee_profiles: state?.remote_e2ee_profiles || []
        });
      }
    }
  }

  resolveFederationProtocolCapabilitiesDiscoveryUrl({
    payload,
    nodeDocument,
    nodeDocumentUrl,
    allowInsecureHttp,
    allowPrivateNetwork
  }) {
    const overrideUrl = String(payload?.protocol_capabilities_url || "").trim();
    const discoveredUrl = String(
      nodeDocument?.protocol_capabilities_url || nodeDocument?.federation?.protocol_capabilities_url || ""
    ).trim();
    const fallbackUrl = new URL("/v1/protocol/capabilities", nodeDocumentUrl).toString();
    const candidate = overrideUrl || discoveredUrl || fallbackUrl;
    if (!candidate) {
      return null;
    }

    return normalizeFederationProtocolCapabilitiesUrl(candidate, {
      allowInsecureHttp,
      allowPrivateNetwork
    });
  }

  async fetchFederationProtocolCapabilitiesState({
    payload,
    nodeId,
    nodeDocument,
    nodeDocumentUrl,
    allowInsecureHttp,
    allowPrivateNetwork,
    timeoutMs,
    maxResponseBytes,
    failOnMissing = false,
    failOnFetchError = false
  }) {
    const protocolCapabilitiesUrl = this.resolveFederationProtocolCapabilitiesDiscoveryUrl({
      payload,
      nodeDocument,
      nodeDocumentUrl,
      allowInsecureHttp,
      allowPrivateNetwork
    });
    if (!protocolCapabilitiesUrl) {
      if (failOnMissing) {
        throw new LoomError("CAPABILITY_DENIED", "Federation node is missing protocol_capabilities_url", 403, {
          node_id: nodeId
        });
      }
      return {
        protocol_capabilities_url: null,
        protocol_capabilities: null,
        protocol_capabilities_fetched_at: null,
        protocol_capabilities_fetch_error: null,
        negotiated_e2ee_profiles: [],
        protocol_negotiated_trust_anchor_mode: null
      };
    }

    try {
      const document = await this.fetchFederationJsonDocument(protocolCapabilitiesUrl, {
        allowInsecureHttp,
        allowPrivateNetwork,
        timeoutMs,
        maxResponseBytes,
        field: "protocol_capabilities_url",
        allowedHosts:
          this.federationBootstrapHostAllowlist.length > 0
            ? this.federationBootstrapHostAllowlist
            : this.federationOutboundHostAllowlist
      });
      const normalizedCapabilities = normalizeProtocolCapabilitiesDocument(document.payload);
      if (!normalizedCapabilities) {
        throw new LoomError(
          "ENVELOPE_INVALID",
          "Federation protocol capabilities document is malformed",
          400,
          {
            node_id: nodeId,
            url: document.url
          }
        );
      }

      const capabilityNodeId = String(normalizedCapabilities.node_id || "").trim();
      if (capabilityNodeId && capabilityNodeId !== nodeId) {
        throw new LoomError("ENVELOPE_INVALID", "Federation protocol capabilities node_id mismatch", 400, {
          expected_node_id: nodeId,
          capability_node_id: capabilityNodeId
        });
      }

      const negotiation = this.deriveFederationProtocolNegotiationState(normalizedCapabilities);
      const result = {
        protocol_capabilities_url: document.url,
        protocol_capabilities: normalizedCapabilities,
        protocol_capabilities_fetched_at: nowIso(),
        protocol_capabilities_fetch_error: null,
        negotiated_e2ee_profiles: normalizeProtocolCapabilityE2eeProfiles(negotiation?.negotiated_e2ee_profiles),
        protocol_negotiated_trust_anchor_mode: negotiation?.negotiated_trust_anchor_mode || null
      };
      this.assertFederationProtocolNegotiationRequirements(
        {
          ...negotiation,
          protocol_capabilities: normalizedCapabilities
        },
        {
          node_id: nodeId
        }
      );
      return result;
    } catch (error) {
      if (failOnFetchError) {
        throw error;
      }
      return {
        protocol_capabilities_url: protocolCapabilitiesUrl,
        protocol_capabilities: null,
        protocol_capabilities_fetched_at: nowIso(),
        protocol_capabilities_fetch_error: error?.message || String(error),
        negotiated_e2ee_profiles: [],
        protocol_negotiated_trust_anchor_mode: null
      };
    }
  }

  async ensureFederationNodeProtocolCapabilities(node, actorIdentity = "system", options = {}) {
    const existingNode = node && typeof node === "object" ? node : null;
    if (!existingNode?.node_id) {
      return existingNode;
    }

    const forceRefresh = options.forceRefresh === true;
    const hasCapabilities = Boolean(existingNode.protocol_capabilities);
    const hasFetchError = Boolean(String(existingNode.protocol_capabilities_fetch_error || "").trim());
    if (!forceRefresh && hasCapabilities && !hasFetchError) {
      const negotiation = this.deriveFederationProtocolNegotiationState(existingNode.protocol_capabilities);
      this.assertFederationProtocolNegotiationRequirements(
        {
          ...negotiation,
          protocol_capabilities: existingNode.protocol_capabilities
        },
        {
          node_id: existingNode.node_id
        }
      );
      if (
        Array.isArray(existingNode.negotiated_e2ee_profiles) &&
        existingNode.negotiated_e2ee_profiles.length > 0 &&
        existingNode.protocol_negotiated_trust_anchor_mode
      ) {
        return existingNode;
      }
    }

    const nodeDocumentUrlRaw = String(existingNode.node_document_url || "").trim();
    let nodeDocumentUrl;
    try {
      nodeDocumentUrl = nodeDocumentUrlRaw ? new URL(nodeDocumentUrlRaw) : new URL(`https://${existingNode.node_id}/.well-known/loom.json`);
    } catch {
      nodeDocumentUrl = new URL(`https://${existingNode.node_id}/.well-known/loom.json`);
    }

    const capabilityState = await this.fetchFederationProtocolCapabilitiesState({
      payload: {
        protocol_capabilities_url: existingNode.protocol_capabilities_url || null
      },
      nodeId: existingNode.node_id,
      nodeDocument: {
        node_id: existingNode.node_id,
        protocol_capabilities_url: existingNode.protocol_capabilities_url
      },
      nodeDocumentUrl,
      allowInsecureHttp: existingNode.allow_insecure_http === true,
      allowPrivateNetwork: existingNode.allow_private_network === true,
      timeoutMs: this.federationDeliverTimeoutMs,
      maxResponseBytes: this.federationDeliverMaxResponseBytes,
      failOnMissing: options.failOnMissing === true,
      failOnFetchError: options.failOnFetchError === true
    });

    const nextNode = {
      ...existingNode,
      protocol_capabilities_url: capabilityState.protocol_capabilities_url,
      protocol_capabilities: capabilityState.protocol_capabilities,
      protocol_capabilities_fetched_at: capabilityState.protocol_capabilities_fetched_at,
      protocol_capabilities_fetch_error: capabilityState.protocol_capabilities_fetch_error,
      negotiated_e2ee_profiles: normalizeProtocolCapabilityE2eeProfiles(capabilityState.negotiated_e2ee_profiles),
      protocol_negotiated_trust_anchor_mode: capabilityState.protocol_negotiated_trust_anchor_mode || null
    };

    const previousSnapshot = canonicalizeJson({
      protocol_capabilities_url: existingNode.protocol_capabilities_url || null,
      protocol_capabilities: normalizeProtocolCapabilitiesDocument(existingNode.protocol_capabilities),
      protocol_capabilities_fetched_at: existingNode.protocol_capabilities_fetched_at || null,
      protocol_capabilities_fetch_error: existingNode.protocol_capabilities_fetch_error || null,
      negotiated_e2ee_profiles: normalizeProtocolCapabilityE2eeProfiles(existingNode.negotiated_e2ee_profiles),
      protocol_negotiated_trust_anchor_mode: existingNode.protocol_negotiated_trust_anchor_mode || null
    });
    const nextSnapshot = canonicalizeJson({
      protocol_capabilities_url: nextNode.protocol_capabilities_url || null,
      protocol_capabilities: normalizeProtocolCapabilitiesDocument(nextNode.protocol_capabilities),
      protocol_capabilities_fetched_at: nextNode.protocol_capabilities_fetched_at || null,
      protocol_capabilities_fetch_error: nextNode.protocol_capabilities_fetch_error || null,
      negotiated_e2ee_profiles: normalizeProtocolCapabilityE2eeProfiles(nextNode.negotiated_e2ee_profiles),
      protocol_negotiated_trust_anchor_mode: nextNode.protocol_negotiated_trust_anchor_mode || null
    });
    if (previousSnapshot !== nextSnapshot) {
      nextNode.updated_at = nowIso();
      this.knownNodesById.set(nextNode.node_id, nextNode);
      if (options.persist !== false) {
        this.persistAndAudit("federation.node.protocol_capabilities.update", {
          node_id: nextNode.node_id,
          protocol_capabilities_url: nextNode.protocol_capabilities_url,
          protocol_capabilities_fetched_at: nextNode.protocol_capabilities_fetched_at,
          protocol_capabilities_fetch_error: nextNode.protocol_capabilities_fetch_error,
          negotiated_e2ee_profiles: nextNode.negotiated_e2ee_profiles,
          protocol_negotiated_trust_anchor_mode: nextNode.protocol_negotiated_trust_anchor_mode,
          actor: actorIdentity
        });
      }
    } else {
      this.knownNodesById.set(nextNode.node_id, nextNode);
    }

    return nextNode;
  }

  assertFederationOutboxNodeCompatibility(node, envelopes = []) {
    const normalizedNode = node && typeof node === "object" ? node : null;
    if (!normalizedNode?.node_id) {
      throw new LoomError("ENVELOPE_INVALID", "Known federation node is required for outbox compatibility checks", 400, {
        field: "recipient_node"
      });
    }

    const derivedNegotiation = normalizedNode.protocol_capabilities
      ? this.deriveFederationProtocolNegotiationState(normalizedNode.protocol_capabilities)
      : null;
    const negotiationState = {
      ...(derivedNegotiation || {}),
      protocol_capabilities: normalizeProtocolCapabilitiesDocument(normalizedNode.protocol_capabilities)
    };
    this.assertFederationProtocolNegotiationRequirements(negotiationState, {
      node_id: normalizedNode.node_id
    });

    const localTrustMode = this.getFederationTrustAnchorMode();
    const negotiatedTrustMode = String(
      normalizedNode.protocol_negotiated_trust_anchor_mode || derivedNegotiation?.negotiated_trust_anchor_mode || ""
    ).trim();
    if (this.federationRequireTrustModeParity && negotiatedTrustMode !== localTrustMode) {
      throw new LoomError("CAPABILITY_DENIED", "Federation trust-anchor mode parity mismatch for recipient node", 403, {
        node_id: normalizedNode.node_id,
        local_trust_anchor_mode: localTrustMode,
        negotiated_trust_anchor_mode: negotiatedTrustMode || null
      });
    }

    const encryptedEnvelopeProfiles = Array.from(
      new Set(
        (Array.isArray(envelopes) ? envelopes : [])
          .filter((envelope) => envelope?.content?.encrypted === true)
          .map((envelope) => {
            const profileValue = String(envelope?.content?.profile || "").trim();
            const resolved = resolveE2eeProfile(profileValue);
            return resolved?.id || profileValue;
          })
          .filter(Boolean)
      )
    );
    if (encryptedEnvelopeProfiles.length === 0) {
      return;
    }

    const negotiatedProfiles = normalizeProtocolCapabilityE2eeProfiles(
      normalizedNode.negotiated_e2ee_profiles?.length > 0
        ? normalizedNode.negotiated_e2ee_profiles
        : derivedNegotiation?.negotiated_e2ee_profiles
    );
    const remoteAdvertisedProfiles = normalizeProtocolCapabilityE2eeProfiles(
      normalizedNode.protocol_capabilities?.federation_negotiation?.e2ee_profiles
    );

    if (negotiatedProfiles.length === 0) {
      if (this.federationRequireE2eeProfileOverlap || this.federationRequireProtocolCapabilities) {
        throw new LoomError(
          "CAPABILITY_DENIED",
          "Federation E2EE profile overlap is unavailable for encrypted envelope delivery",
          403,
          {
            node_id: normalizedNode.node_id,
            encrypted_profiles: encryptedEnvelopeProfiles,
            local_profiles: listSupportedE2eeProfiles(),
            remote_profiles: remoteAdvertisedProfiles
          }
        );
      }
    }

    const allowedProfiles = negotiatedProfiles.length > 0 ? negotiatedProfiles : remoteAdvertisedProfiles;
    if (allowedProfiles.length === 0) {
      throw new LoomError(
        "CAPABILITY_DENIED",
        "Recipient federation node does not advertise encrypted profile support",
        403,
        {
          node_id: normalizedNode.node_id,
          encrypted_profiles: encryptedEnvelopeProfiles
        }
      );
    }

    const unsupportedProfiles = encryptedEnvelopeProfiles.filter((profileId) => !allowedProfiles.includes(profileId));
    if (unsupportedProfiles.length > 0) {
      throw new LoomError(
        "CAPABILITY_DENIED",
        "Encrypted envelope profile is not supported by recipient federation node",
        403,
        {
          node_id: normalizedNode.node_id,
          envelope_profiles: encryptedEnvelopeProfiles,
          allowed_profiles: allowedProfiles,
          unsupported_profiles: unsupportedProfiles
        }
      );
    }
  }

  verifySignedFederationDocument(document, signingKeys, context = {}) {
    const signature = document?.signature;
    if (!signature || typeof signature !== "object") {
      throw new LoomError("SIGNATURE_INVALID", "Signed federation document is missing signature", 401, {
        field: context.field || "signature",
        context: context.name || null
      });
    }

    const algorithm = String(signature.algorithm || "").trim();
    const keyId = String(signature.key_id || "").trim();
    const value = String(signature.value || "").trim();
    if (algorithm !== "Ed25519" || !keyId || !value) {
      throw new LoomError("SIGNATURE_INVALID", "Signed federation document signature metadata is invalid", 401, {
        field: context.field || "signature",
        context: context.name || null
      });
    }

    const key = resolveFederationNodeSigningKey(
      {
        signing_keys: signingKeys
      },
      keyId
    );
    if (!key) {
      throw new LoomError("SIGNATURE_INVALID", "Signed federation document signature key is not trusted", 401, {
        field: `${context.field || "signature"}.key_id`,
        context: context.name || null,
        key_id: keyId
      });
    }

    const canonicalPayload = canonicalizeSignedDocumentPayload(document);
    const valid = verifyUtf8MessageSignature(key.public_key_pem, canonicalPayload, value);
    if (!valid) {
      throw new LoomError("SIGNATURE_INVALID", "Signed federation document signature verification failed", 401, {
        field: context.field || "signature",
        context: context.name || null,
        key_id: keyId
      });
    }

    return {
      key_id: keyId,
      canonical_hash: createHash("sha256").update(canonicalPayload, "utf-8").digest("hex")
    };
  }

  verifyFederationKeysetDocumentFreshness(document, context = {}) {
    const generatedAt = String(document?.generated_at || document?.issued_at || "").trim();
    const generatedAtMs = generatedAt ? parseTime(generatedAt) : null;
    if (generatedAtMs == null) {
      if (this.federationTrustFailClosed) {
        throw new LoomError("SIGNATURE_INVALID", "Signed federation keyset must include a valid generated_at timestamp", 401, {
          context: context.name || "keyset"
        });
      }
      return;
    }

    const now = nowMs();
    if (generatedAtMs > now + this.federationTrustMaxClockSkewMs) {
      throw new LoomError("SIGNATURE_INVALID", "Signed federation keyset timestamp exceeds allowed future skew", 401, {
        context: context.name || "keyset",
        generated_at: generatedAt
      });
    }

    if (now - generatedAtMs > this.federationTrustKeysetMaxAgeMs) {
      throw new LoomError("SIGNATURE_INVALID", "Signed federation keyset is too old", 401, {
        context: context.name || "keyset",
        generated_at: generatedAt,
        max_age_ms: this.federationTrustKeysetMaxAgeMs
      });
    }

    const validUntil = String(document?.valid_until || document?.expires_at || "").trim();
    if (validUntil) {
      const validUntilMs = parseTime(validUntil);
      if (validUntilMs == null || validUntilMs <= now) {
        throw new LoomError("SIGNATURE_INVALID", "Signed federation keyset has expired", 401, {
          context: context.name || "keyset",
          valid_until: validUntil
        });
      }
    }
  }

  async resolveFederationPublicTrustMaterial({
    payload,
    nodeId,
    nodeDocument,
    nodeDocumentUrl,
    allowInsecureHttp,
    allowPrivateNetwork,
    timeoutMs,
    maxResponseBytes
  }) {
    const dnsProof = await this.resolveFederationTrustDnsProof(nodeId);
    const dnsFields = dnsProof?.fields || {};
    const dnsKeysetUrl = String(dnsFields.keyset || dnsFields.ks || dnsFields.k || "").trim();
    const overrideKeysetUrl = String(payload?.trust_anchor_keyset_url || payload?.keyset_url || "").trim();
    const fallbackKeysetUrl = String(
      nodeDocument?.federation?.keyset_url || nodeDocument?.federation?.trust_keyset_url || nodeDocument?.keyset_url || ""
    ).trim();
    const defaultKeysetUrl = new URL("/.well-known/loom-keyset.json", nodeDocumentUrl).toString();
    const keysetUrl = overrideKeysetUrl || dnsKeysetUrl || fallbackKeysetUrl || defaultKeysetUrl;
    if (!keysetUrl) {
      throw new LoomError("SIGNATURE_INVALID", "Unable to resolve federation keyset URL for trust bootstrap", 401, {
        node_id: nodeId
      });
    }

    if (!dnsKeysetUrl && !overrideKeysetUrl && this.federationTrustFailClosed) {
      throw new LoomError("SIGNATURE_INVALID", "DNS trust-anchor record must publish a keyset URL", 401, {
        node_id: nodeId,
        dns_name: dnsProof?.dns_name || null
      });
    }

    const keysetResponse = await this.fetchFederationJsonDocument(keysetUrl, {
      allowInsecureHttp,
      allowPrivateNetwork,
      timeoutMs,
      maxResponseBytes,
      field: "federation.keyset_url"
    });
    const keysetDocument = keysetResponse.payload;
    const keysetNodeId = String(keysetDocument?.node_id || "").trim();
    if (keysetNodeId && keysetNodeId !== nodeId) {
      throw new LoomError("SIGNATURE_INVALID", "Federation keyset node_id does not match discovered node", 401, {
        expected_node_id: nodeId,
        keyset_node_id: keysetNodeId
      });
    }

    const keysetSigningKeys = normalizeKeysetSigningKeys(keysetDocument);
    if (keysetSigningKeys.length === 0) {
      throw new LoomError("SIGNATURE_INVALID", "Federation keyset document must include signing keys", 401, {
        field: "signing_keys",
        node_id: nodeId
      });
    }

    this.verifySignedFederationDocument(keysetDocument, keysetSigningKeys, {
      name: "federation_keyset",
      field: "signature"
    });
    this.verifyFederationKeysetDocumentFreshness(keysetDocument, {
      name: "federation_keyset"
    });

    const keysetHash = hashCanonicalSignedDocumentPayload(keysetDocument);
    const expectedDigest = normalizeSha256Digest(
      dnsFields.digest || dnsFields.sha256 || dnsFields.hash || dnsFields.h || ""
    );
    if (expectedDigest) {
      if (expectedDigest !== keysetHash) {
        throw new LoomError("SIGNATURE_INVALID", "Federation keyset hash does not match DNS trust anchor digest", 401, {
          node_id: nodeId,
          expected_digest: expectedDigest,
          actual_digest: keysetHash,
          dns_name: dnsProof?.dns_name || null
        });
      }
    } else if (this.federationTrustFailClosed) {
      throw new LoomError("SIGNATURE_INVALID", "DNS trust-anchor record must include keyset SHA-256 digest", 401, {
        node_id: nodeId,
        dns_name: dnsProof?.dns_name || null
      });
    }

    const keysetEpoch =
      parseOptionalNonNegativeInteger(keysetDocument?.trust_epoch) ??
      parseOptionalNonNegativeInteger(keysetDocument?.epoch) ??
      0;
    const keysetVersion = parseOptionalNonNegativeInteger(keysetDocument?.version) ?? 0;
    const dnsEpoch = parseOptionalNonNegativeInteger(dnsFields.trust_epoch || dnsFields.epoch) ?? null;
    const dnsVersion = parseOptionalNonNegativeInteger(dnsFields.version) ?? null;
    const trustEpoch = Math.max(keysetEpoch, dnsEpoch ?? 0);
    const trustKeysetVersion = Math.max(keysetVersion, dnsVersion ?? 0);

    const dnsRevocationsUrl = String(dnsFields.revocations || dnsFields.revocation || "").trim();
    const overrideRevocationsUrl = String(payload?.trust_anchor_revocations_url || payload?.revocations_url || "").trim();
    const fallbackRevocationsUrl = String(
      keysetDocument?.revocations_url || nodeDocument?.federation?.revocations_url || nodeDocument?.revocations_url || ""
    ).trim();
    const revocationsUrl = overrideRevocationsUrl || dnsRevocationsUrl || fallbackRevocationsUrl || null;
    let revokedKeyIds = [];
    let revocationEpoch = 0;
    if (revocationsUrl) {
      const revocationsResponse = await this.fetchFederationJsonDocument(revocationsUrl, {
        allowInsecureHttp,
        allowPrivateNetwork,
        timeoutMs,
        maxResponseBytes,
        field: "federation.revocations_url"
      });
      const revocationsDocument = revocationsResponse.payload;
      const revocationsNodeId = String(revocationsDocument?.node_id || "").trim();
      if (revocationsNodeId && revocationsNodeId !== nodeId) {
        throw new LoomError("SIGNATURE_INVALID", "Federation revocations node_id does not match discovered node", 401, {
          expected_node_id: nodeId,
          revocations_node_id: revocationsNodeId
        });
      }
      this.verifySignedFederationDocument(revocationsDocument, keysetSigningKeys, {
        name: "federation_revocations",
        field: "signature"
      });
      this.verifyFederationKeysetDocumentFreshness(revocationsDocument, {
        name: "federation_revocations"
      });
      const revocationEntries = Array.isArray(revocationsDocument?.revoked_key_ids)
        ? revocationsDocument.revoked_key_ids
        : Array.isArray(revocationsDocument?.revoked_keys)
          ? revocationsDocument.revoked_keys.map((entry) => (typeof entry === "object" ? entry?.key_id : entry))
          : [];
      revokedKeyIds = normalizeRevokedKeyIds(revocationEntries);
      revocationEpoch =
        parseOptionalNonNegativeInteger(revocationsDocument?.trust_epoch) ??
        parseOptionalNonNegativeInteger(revocationsDocument?.epoch) ??
        0;
    }

    const effectiveTrustEpoch = Math.max(trustEpoch, revocationEpoch);
    const existing = this.knownNodesById.get(nodeId);
    if (existing) {
      const previousEpoch = Math.max(0, parseNonNegativeInteger(existing.trust_anchor_epoch, 0));
      const previousVersion = Math.max(0, parseNonNegativeInteger(existing.trust_anchor_keyset_version, 0));
      const previousHash = normalizeHexDigest(existing.trust_anchor_keyset_hash);
      if (effectiveTrustEpoch < previousEpoch) {
        throw new LoomError("SIGNATURE_INVALID", "Federation trust-anchor epoch rollback detected", 401, {
          node_id: nodeId,
          previous_epoch: previousEpoch,
          next_epoch: effectiveTrustEpoch
        });
      }
      if (effectiveTrustEpoch === previousEpoch && trustKeysetVersion < previousVersion) {
        throw new LoomError("SIGNATURE_INVALID", "Federation trust-anchor keyset version rollback detected", 401, {
          node_id: nodeId,
          previous_version: previousVersion,
          next_version: trustKeysetVersion
        });
      }
      if (
        effectiveTrustEpoch === previousEpoch &&
        trustKeysetVersion === previousVersion &&
        previousHash &&
        previousHash !== keysetHash
      ) {
        throw new LoomError("SIGNATURE_INVALID", "Federation trust-anchor keyset hash changed without epoch/version increment", 401, {
          node_id: nodeId,
          previous_hash: previousHash,
          next_hash: keysetHash
        });
      }
      if (effectiveTrustEpoch <= previousEpoch) {
        const previousRevoked = new Set(normalizeRevokedKeyIds(existing.revoked_key_ids));
        const nextRevoked = new Set(revokedKeyIds);
        for (const revokedKeyId of previousRevoked) {
          if (!nextRevoked.has(revokedKeyId)) {
            throw new LoomError("SIGNATURE_INVALID", "Federation trust-anchor revocation rollback detected", 401, {
              node_id: nodeId,
              key_id: revokedKeyId
            });
          }
        }
      }
    }

    const transparencyState = this.deriveFederationTrustTransparencyState(
      nodeId,
      effectiveTrustEpoch,
      trustKeysetVersion,
      keysetHash,
      existing
    );
    if (this.federationTrustRequireTransparency && !transparencyState?.checkpoint) {
      throw new LoomError("SIGNATURE_INVALID", "Federation trust transparency checkpoint generation failed", 401, {
        node_id: nodeId
      });
    }

    const verifiedAt = nowIso();
    const signingKeys = applyRevokedKeyIdsToFederationSigningKeys(
      keysetSigningKeys,
      revokedKeyIds,
      verifiedAt
    );
    const activeKeyId = String(keysetDocument?.active_key_id || keysetDocument?.signing_key_id || "").trim();
    const activeKey =
      resolveFederationNodeSigningKey({ signing_keys: signingKeys }, activeKeyId) ||
      signingKeys.find((candidate) => isSigningKeyUsableAt(candidate)) ||
      null;
    if (!activeKey) {
      throw new LoomError("SIGNATURE_INVALID", "Federation keyset does not contain any active signing key", 401, {
        node_id: nodeId
      });
    }

    return {
      key_id: activeKey.key_id,
      signing_keys: signingKeys,
      revoked_key_ids: revokedKeyIds,
      trust_anchor_dns_name: dnsProof?.dns_name || null,
      trust_anchor_dns_record: dnsProof?.record || null,
      trust_anchor_dnssec_validated: dnsProof?.dnssec_validated === true,
      trust_anchor_dnssec_source: dnsProof?.dnssec_source || null,
      trust_anchor_keyset_url: keysetResponse.url,
      trust_anchor_keyset_hash: keysetHash,
      trust_anchor_keyset_version: trustKeysetVersion,
      trust_anchor_epoch: effectiveTrustEpoch,
      trust_anchor_revocations_url: revocationsUrl || null,
      trust_anchor_verified_at: verifiedAt,
      trust_anchor_transparency_log_id: transparencyState.log_id,
      trust_anchor_transparency_mode: transparencyState.mode,
      trust_anchor_transparency_checkpoint: transparencyState.checkpoint,
      trust_anchor_transparency_previous_checkpoint: transparencyState.previous_checkpoint,
      trust_anchor_transparency_event_index: transparencyState.event_index,
      trust_anchor_transparency_verified_at: transparencyState.verified_at
    };
  }

  async bootstrapFederationNode(payload, actorIdentity) {
    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Federation bootstrap payload must be an object", 400, {
        field: "payload"
      });
    }

    const allowInsecureHttp = payload.allow_insecure_http === true;
    const allowPrivateNetwork = payload.allow_private_network === true;
    const allowCrossHostDeliverUrl = payload.allow_cross_host_deliver_url === true;
    const timeoutMs = Math.max(500, Math.min(parsePositiveInteger(payload.timeout_ms, 5000), 20000));
    const maxResponseBytes = Math.max(1024, Math.min(parsePositiveInteger(payload.max_response_bytes, 256 * 1024), 1024 * 1024));

    const nodeDocumentUrlRaw = this.resolveFederationBootstrapNodeDocumentUrl(payload);
    let nodeDocumentUrl;
    try {
      nodeDocumentUrl = new URL(nodeDocumentUrlRaw);
    } catch {
      throw new LoomError("ENVELOPE_INVALID", "node_document_url must be a valid absolute URL", 400, {
        field: "node_document_url"
      });
    }

    if (nodeDocumentUrl.username || nodeDocumentUrl.password) {
      throw new LoomError("ENVELOPE_INVALID", "node_document_url must not include credentials", 400, {
        field: "node_document_url"
      });
    }

    if (nodeDocumentUrl.protocol !== "https:" && !(allowInsecureHttp && nodeDocumentUrl.protocol === "http:")) {
      throw new LoomError("ENVELOPE_INVALID", "node_document_url must use https unless allow_insecure_http=true", 400, {
        field: "node_document_url",
        protocol: nodeDocumentUrl.protocol
      });
    }

    const outboundHostPolicy = await assertOutboundUrlHostAllowed(nodeDocumentUrl, {
      allowPrivateNetwork,
      allowedHosts: this.federationBootstrapHostAllowlist,
      denyMetadataHosts: this.denyMetadataHosts
    });

    let response;
    try {
      response = await performPinnedOutboundHttpRequest(nodeDocumentUrl, {
        method: "GET",
        headers: {
          accept: "application/json"
        },
        timeoutMs,
        maxResponseBytes,
        responseSizeContext: {
          node_document_url: nodeDocumentUrl.toString()
        },
        resolvedAddresses: outboundHostPolicy.resolvedAddresses,
        rejectRedirects: true
      });
    } catch (error) {
      if (error instanceof LoomError) {
        throw error;
      }
      if (error?.name === "AbortError") {
        throw new LoomError("DELIVERY_TIMEOUT", "Federation node discovery timed out", 504, {
          node_document_url: nodeDocumentUrl.toString(),
          timeout_ms: timeoutMs
        });
      }
      throw new LoomError("NODE_UNREACHABLE", "Federation node discovery failed", 502, {
        node_document_url: nodeDocumentUrl.toString(),
        reason: error?.message || String(error)
      });
    }

    if (!response.ok) {
      throw new LoomError("NODE_UNREACHABLE", `Federation node discovery returned ${response.status}`, 502, {
        node_document_url: nodeDocumentUrl.toString(),
        status: response.status
      });
    }

    let nodeDocument;
    try {
      nodeDocument = JSON.parse(response.bodyText);
    } catch (error) {
      if (error instanceof LoomError) {
        throw error;
      }
      throw new LoomError("ENVELOPE_INVALID", "Federation node discovery response must be JSON", 400, {
        field: "node_document"
      });
    }

    const discoveredNodeId = String(nodeDocument?.node_id || "").trim();
    if (!discoveredNodeId) {
      throw new LoomError("ENVELOPE_INVALID", "Federation node document is missing node_id", 400, {
        field: "node_document.node_id"
      });
    }

    const bootstrapTrustMode = this.resolveFederationBootstrapTrustMode(payload);
    let signingKeys = extractFederationSigningKeysFromNodeDocument(nodeDocument);
    if (signingKeys.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "Federation node document is missing federation signing keys", 400, {
        field: "node_document.federation.signing_keys"
      });
    }

    let trustMaterial = null;
    if (bootstrapTrustMode === "public_dns_webpki") {
      trustMaterial = await this.resolveFederationPublicTrustMaterial({
        payload,
        nodeId: discoveredNodeId,
        nodeDocument,
        nodeDocumentUrl,
        allowInsecureHttp,
        allowPrivateNetwork,
        timeoutMs,
        maxResponseBytes
      });
      signingKeys = trustMaterial.signing_keys;
    }

    const documentActiveKeyId = String(
      trustMaterial?.key_id || nodeDocument?.federation?.signing_key_id || ""
    ).trim();
    const requestedActiveKeyId = String(payload.active_key_id || "").trim();
    const activeKey =
      resolveFederationNodeSigningKey({ signing_keys: signingKeys }, requestedActiveKeyId || documentActiveKeyId) ||
      signingKeys.find((key) => isSigningKeyUsableAt(key)) ||
      signingKeys[0];

    let discoveredDeliverUrl = String(
      payload.deliver_url || nodeDocument?.deliver_url || nodeDocument?.federation?.deliver_url || ""
    ).trim();

    if (!discoveredDeliverUrl) {
      const apiUrl = String(nodeDocument?.api_url || "").trim();
      if (apiUrl) {
        try {
          discoveredDeliverUrl = new URL("federation/deliver", apiUrl.endsWith("/") ? apiUrl : `${apiUrl}/`).toString();
        } catch {}
      }
    }

    if (!discoveredDeliverUrl) {
      discoveredDeliverUrl = new URL("/v1/federation/deliver", nodeDocumentUrl).toString();
    }

    let deliverUrl;
    try {
      deliverUrl = new URL(discoveredDeliverUrl);
    } catch {
      throw new LoomError("ENVELOPE_INVALID", "Federation node document has invalid deliver_url", 400, {
        field: "node_document.deliver_url"
      });
    }

    if (deliverUrl.username || deliverUrl.password) {
      throw new LoomError("ENVELOPE_INVALID", "Federation deliver_url must not include credentials", 400, {
        field: "deliver_url"
      });
    }

    if (deliverUrl.protocol !== "https:" && !(allowInsecureHttp && deliverUrl.protocol === "http:")) {
      throw new LoomError("ENVELOPE_INVALID", "deliver_url must use https unless allow_insecure_http=true", 400, {
        field: "deliver_url",
        protocol: deliverUrl.protocol
      });
    }

    if (!allowCrossHostDeliverUrl && deliverUrl.hostname !== nodeDocumentUrl.hostname) {
      throw new LoomError("ENVELOPE_INVALID", "deliver_url host must match node_document_url host", 400, {
        field: "deliver_url",
        node_document_host: nodeDocumentUrl.hostname,
        deliver_host: deliverUrl.hostname
      });
    }

    await assertOutboundUrlHostAllowed(deliverUrl, {
      allowPrivateNetwork,
      allowedHosts: this.federationOutboundHostAllowlist,
      denyMetadataHosts: this.denyMetadataHosts
    });

    const discoveredIdentityResolveUrl = String(
      payload.identity_resolve_url ||
        nodeDocument?.identity_resolve_url ||
        nodeDocument?.federation?.identity_resolve_url ||
        ""
    ).trim();
    const identityResolveUrl = normalizeFederationIdentityResolveUrl(discoveredIdentityResolveUrl || null, {
      allowInsecureHttp,
      allowPrivateNetwork
    });
    if (identityResolveUrl) {
      const identityProbeUrl = new URL(
        identityResolveUrl.replace(/\{identity\}/g, encodeURIComponent("loom://probe@bootstrap.local"))
      );
      const identityAllowedHosts =
        this.remoteIdentityHostAllowlist.length > 0
          ? this.remoteIdentityHostAllowlist
          : this.federationOutboundHostAllowlist;
      await assertOutboundUrlHostAllowed(identityProbeUrl, {
        allowPrivateNetwork,
        allowedHosts: identityAllowedHosts,
        denyMetadataHosts: this.denyMetadataHosts
      });
    }

    const protocolCapabilityPolicyRequired =
      this.federationRequireProtocolCapabilities ||
      this.federationRequireE2eeProfileOverlap ||
      this.federationRequireTrustModeParity;
    const protocolCapabilitiesState = await this.fetchFederationProtocolCapabilitiesState({
      payload,
      nodeId: discoveredNodeId,
      nodeDocument,
      nodeDocumentUrl,
      allowInsecureHttp,
      allowPrivateNetwork,
      timeoutMs,
      maxResponseBytes,
      failOnMissing: protocolCapabilityPolicyRequired,
      failOnFetchError: protocolCapabilityPolicyRequired
    });

    const trustAnchorRegistrationPayload =
      bootstrapTrustMode === "public_dns_webpki" && trustMaterial
        ? {
            trust_anchor_mode: "public_dns_webpki",
            trust_anchor_dns_name: trustMaterial.trust_anchor_dns_name,
            trust_anchor_dns_record: trustMaterial.trust_anchor_dns_record,
            trust_anchor_keyset_url: trustMaterial.trust_anchor_keyset_url,
            trust_anchor_keyset_hash: trustMaterial.trust_anchor_keyset_hash,
            trust_anchor_keyset_version: trustMaterial.trust_anchor_keyset_version,
            trust_anchor_epoch: trustMaterial.trust_anchor_epoch,
            trust_anchor_revocations_url: trustMaterial.trust_anchor_revocations_url,
            trust_anchor_verified_at: trustMaterial.trust_anchor_verified_at,
            revoked_key_ids: trustMaterial.revoked_key_ids
          }
        : {
            trust_anchor_mode: bootstrapTrustMode
          };

    const node = this.registerFederationNode(
      {
        node_id: discoveredNodeId,
        key_id: activeKey.key_id,
        public_key_pem: activeKey.public_key_pem,
        signing_keys: signingKeys,
        active_key_id: activeKey.key_id,
        replace_signing_keys:
          bootstrapTrustMode === "public_dns_webpki" || payload.replace_signing_keys === true,
        node_document_url: nodeDocumentUrl.toString(),
        deliver_url: deliverUrl.toString(),
        identity_resolve_url: identityResolveUrl,
        protocol_capabilities_url: protocolCapabilitiesState.protocol_capabilities_url,
        protocol_capabilities: protocolCapabilitiesState.protocol_capabilities,
        protocol_capabilities_fetched_at: protocolCapabilitiesState.protocol_capabilities_fetched_at,
        protocol_capabilities_fetch_error: protocolCapabilitiesState.protocol_capabilities_fetch_error,
        negotiated_e2ee_profiles: protocolCapabilitiesState.negotiated_e2ee_profiles,
        protocol_negotiated_trust_anchor_mode: protocolCapabilitiesState.protocol_negotiated_trust_anchor_mode,
        allow_insecure_http: allowInsecureHttp,
        allow_private_network: allowPrivateNetwork,
        policy: Object.prototype.hasOwnProperty.call(payload, "policy") ? payload.policy : undefined,
        ...trustAnchorRegistrationPayload
      },
      actorIdentity
    );

    this.persistAndAudit("federation.node.bootstrap", {
      node_id: node.node_id,
      key_id: node.key_id,
      signing_key_count: node.signing_keys.length,
      trust_anchor_mode: node.trust_anchor_mode,
      trust_anchor_epoch: node.trust_anchor_epoch,
      node_document_url: nodeDocumentUrl.toString(),
      deliver_url: node.deliver_url,
      protocol_capabilities_url: node.protocol_capabilities_url,
      negotiated_e2ee_profiles: node.negotiated_e2ee_profiles || [],
      protocol_negotiated_trust_anchor_mode: node.protocol_negotiated_trust_anchor_mode || null,
      actor: actorIdentity
    });

    return {
      node,
      discovery: {
        node_document_url: nodeDocumentUrl.toString(),
        protocol_capabilities_url: node.protocol_capabilities_url || null,
        fetched_at: nowIso()
      }
    };
  }

  cleanupFederationNonces() {
    const cutoff = nowMs() - 15 * 60 * 1000;
    for (const [nonce, seenAt] of this.federationNonceCache.entries()) {
      if (seenAt < cutoff) {
        this.federationNonceCache.delete(nonce);
      }
    }
  }

  cleanupFederationInboundRateState() {
    const cutoff = nowMs() - this.federationInboundRateWindowMs * 2;
    for (const [nodeId, entry] of this.federationInboundRateByNode.entries()) {
      if (entry.window_started_at < cutoff) {
        this.federationInboundRateByNode.delete(nodeId);
      }
    }
  }

  cleanupFederationInboundAbuseState() {
    const cutoff = nowMs() - this.federationAbuseWindowMs * 2;
    for (const [nodeId, entry] of this.federationInboundAbuseByNode.entries()) {
      if (entry.window_started_at < cutoff && (!entry.blocked_until_ms || entry.blocked_until_ms < cutoff)) {
        this.federationInboundAbuseByNode.delete(nodeId);
      }
    }
  }

  cleanupFederationChallengeState() {
    const now = nowMs();
    for (const [nodeId, challenge] of this.federationChallengesByNode.entries()) {
      const expiresAt = parseTime(challenge?.expires_at);
      if (expiresAt == null || expiresAt <= now) {
        this.federationChallengesByNode.delete(nodeId);
      }
    }
  }

  isFederationChallengeRequired(node) {
    if (!this.federationChallengeEscalationEnabled || !node) {
      return false;
    }
    const untilMs = parseTime(node.challenge_required_until);
    return untilMs != null && untilMs > nowMs();
  }

  refreshFederationNodeChallengeRequirement(node, actorIdentity = "system") {
    if (!node?.challenge_required_until) {
      return false;
    }

    const untilMs = parseTime(node.challenge_required_until);
    if (untilMs != null && untilMs > nowMs()) {
      return false;
    }

    const previousUntil = node.challenge_required_until;
    node.challenge_required_until = null;
    node.challenge_reason = null;
    node.updated_at = nowIso();

    this.persistAndAudit("federation.node.challenge.expired", {
      node_id: node.node_id,
      previous_until: previousUntil,
      actor: actorIdentity
    });
    return true;
  }

  applyFederationChallengeEscalation(node, reasonCode, actorIdentity = "system") {
    if (!this.federationChallengeEscalationEnabled || !node) {
      return false;
    }

    const untilIso = new Date(nowMs() + this.federationChallengeDurationMs).toISOString();
    const alreadyActive = this.isFederationChallengeRequired(node);
    node.challenge_required_until = untilIso;
    node.challenge_reason = String(reasonCode || "UNKNOWN").trim() || "UNKNOWN";
    node.updated_at = nowIso();

    if (alreadyActive) {
      return false;
    }

    this.persistAndAudit("federation.node.challenge.required", {
      node_id: node.node_id,
      reason_code: node.challenge_reason,
      until: untilIso,
      actor: actorIdentity
    });
    return true;
  }

  async issueFederationChallengeToken(nodeId, actorIdentity = "system") {
    const normalizedNodeId = String(nodeId || "").trim();
    if (!normalizedNodeId) {
      throw new LoomError("ENVELOPE_INVALID", "node_id is required for federation challenge", 400, {
        field: "node_id"
      });
    }

    const node = this.knownNodesById.get(normalizedNodeId);
    if (!node) {
      throw new LoomError("ENVELOPE_INVALID", `Unknown federation node: ${normalizedNodeId}`, 400, {
        node_id: normalizedNodeId
      });
    }

    this.refreshFederationNodeChallengeRequirement(node, actorIdentity);
    if (!this.isFederationChallengeRequired(node)) {
      this.applyFederationChallengeEscalation(node, "MANUAL_CHALLENGE", actorIdentity);
    }

    const now = nowMs();
    const challengeUntilMs = parseTime(node.challenge_required_until) || now + this.federationChallengeDurationMs;
    const tokenExpiresAt = new Date(Math.min(challengeUntilMs, now + this.federationChallengeDurationMs)).toISOString();
    const token = `fch_${generateUlid()}`;

    this.cleanupFederationChallengeState();
    this.federationChallengesByNode.set(normalizedNodeId, {
      token,
      expires_at: tokenExpiresAt,
      issued_at: nowIso(),
      issued_by: actorIdentity
    });

    if (this.federationDistributedGuardsEnabled && this.persistenceAdapter?.issueFederationChallengeToken) {
      await this.persistenceAdapter.issueFederationChallengeToken({
        nodeId: normalizedNodeId,
        token,
        expiresAt: tokenExpiresAt
      });
    }

    this.persistAndAudit("federation.node.challenge.issued", {
      node_id: normalizedNodeId,
      expires_at: tokenExpiresAt,
      actor: actorIdentity
    });

    return {
      node_id: normalizedNodeId,
      challenge_token: token,
      expires_at: tokenExpiresAt,
      required_until: node.challenge_required_until,
      required: this.isFederationChallengeRequired(node)
    };
  }

  async consumeFederationChallengeToken(nodeId, token) {
    const normalizedNodeId = String(nodeId || "").trim();
    const normalizedToken = String(token || "").trim();
    if (!normalizedNodeId || !normalizedToken) {
      return false;
    }

    this.cleanupFederationChallengeState();
    const inMemory = this.federationChallengesByNode.get(normalizedNodeId);
    if (inMemory && inMemory.token === normalizedToken && !isExpiredIso(inMemory.expires_at)) {
      this.federationChallengesByNode.delete(normalizedNodeId);
      return true;
    }

    if (this.federationDistributedGuardsEnabled && this.persistenceAdapter?.consumeFederationChallengeToken) {
      return this.persistenceAdapter.consumeFederationChallengeToken({
        nodeId: normalizedNodeId,
        token: normalizedToken
      });
    }

    return false;
  }

  async enforceFederationGlobalInboundRate(nodeId) {
    const max = this.federationGlobalInboundRateMax;
    const windowMs = this.federationGlobalInboundRateWindowMs;
    if (max <= 0 || windowMs <= 0) {
      return;
    }

    const now = nowMs();
    if (!this.federationInboundGlobalRate.window_started_at || now - this.federationInboundGlobalRate.window_started_at >= windowMs) {
      this.federationInboundGlobalRate = {
        count: 1,
        window_started_at: now
      };
    } else if (this.federationInboundGlobalRate.count >= max) {
      const retryAfterMs = Math.max(1, this.federationInboundGlobalRate.window_started_at + windowMs - now);
      throw new LoomError("RATE_LIMIT_EXCEEDED", "Federation global inbound rate limit exceeded", 429, {
        scope: "federation_global",
        node_id: nodeId,
        limit: max,
        window_ms: windowMs,
        retry_after_ms: retryAfterMs
      });
    } else {
      this.federationInboundGlobalRate.count += 1;
    }

    if (this.federationDistributedGuardsEnabled && this.persistenceAdapter?.incrementFederationInboundRate) {
      const distributed = await this.persistenceAdapter.incrementFederationInboundRate({
        nodeId: "__global__",
        windowMs
      });
      if (Number(distributed?.count || 0) > max) {
        const oldestMs = Number(distributed?.oldest_ms || 0);
        const retryAfterMs = oldestMs ? Math.max(1, oldestMs + windowMs - nowMs()) : windowMs;
        throw new LoomError("RATE_LIMIT_EXCEEDED", "Distributed federation global inbound rate limit exceeded", 429, {
          scope: "federation_global_distributed",
          node_id: nodeId,
          limit: max,
          window_ms: windowMs,
          retry_after_ms: retryAfterMs
        });
      }
    }
  }

  refreshFederationNodeAutoPolicy(node, actorIdentity = "system") {
    if (!node?.auto_policy) {
      return false;
    }

    const untilMs = parseTime(node.auto_policy_until);
    if (untilMs == null || untilMs > nowMs()) {
      return false;
    }

    const previousPolicy = node.policy;
    node.auto_policy = null;
    node.auto_policy_until = null;
    node.auto_policy_reason = null;
    node.policy = node.configured_policy || "trusted";
    node.updated_at = nowIso();

    this.persistAndAudit("federation.node.auto_policy.expired", {
      node_id: node.node_id,
      previous_policy: previousPolicy,
      restored_policy: node.policy,
      actor: actorIdentity
    });

    return true;
  }

  refreshAllFederationNodeAutoPolicies(actorIdentity = "system") {
    for (const node of this.knownNodesById.values()) {
      this.refreshFederationNodeAutoPolicy(node, actorIdentity);
      this.refreshFederationNodeChallengeRequirement(node, actorIdentity);
    }
  }

  applyFederationAutoPolicy(node, policy, reasonCode, actorIdentity = "system") {
    if (!node) {
      return;
    }

    const now = nowMs();
    const untilIso = new Date(now + this.federationAutoPolicyDurationMs).toISOString();
    const alreadyActive = node.auto_policy === policy && !isExpiredIso(node.auto_policy_until);
    node.auto_policy = policy;
    node.auto_policy_until = untilIso;
    node.auto_policy_reason = reasonCode;
    node.policy = policy;
    node.updated_at = nowIso();

    if (alreadyActive) {
      return;
    }

    this.persistAndAudit("federation.node.auto_policy.applied", {
      node_id: node.node_id,
      policy,
      reason_code: reasonCode,
      until: untilIso,
      actor: actorIdentity
    });
  }

  async recordFederationInboundFailure(nodeId, reasonCode, actorIdentity = "system") {
    if (!this.federationAbuseAutoPolicyEnabled) {
      return;
    }

    const node = this.knownNodesById.get(nodeId);
    if (!node) {
      return;
    }

    this.refreshFederationNodeAutoPolicy(node, actorIdentity);
    this.refreshFederationNodeChallengeRequirement(node, actorIdentity);
    this.cleanupFederationInboundAbuseState();

    const now = nowMs();
    let current = this.federationInboundAbuseByNode.get(nodeId);
    if (!current || now - current.window_started_at >= this.federationAbuseWindowMs) {
      current = {
        count: 0,
        window_started_at: now,
        blocked_until_ms: null,
        last_reason_code: null
      };
      this.federationInboundAbuseByNode.set(nodeId, current);
    }

    current.count += 1;
    current.last_reason_code = reasonCode;
    let effectiveCount = current.count;
    node.reputation_score = Math.max(0, Number(node.reputation_score || 0)) + 1;

    if (this.federationDistributedGuardsEnabled && this.persistenceAdapter?.recordFederationAbuseFailure) {
      try {
        const distributed = await this.persistenceAdapter.recordFederationAbuseFailure({
          nodeId,
          reasonCode,
          windowMs: this.federationAbuseWindowMs
        });
        effectiveCount = Math.max(effectiveCount, Number(distributed?.window_count || 0));
        if (Number.isFinite(Number(distributed?.reputation_score))) {
          node.reputation_score = Math.max(node.reputation_score, Number(distributed.reputation_score));
        }
      } catch {}
    }

    node.updated_at = nowIso();

    this.persistAndAudit("federation.node.reputation.updated", {
      node_id: node.node_id,
      reputation_score: node.reputation_score,
      reason_code: reasonCode,
      actor: actorIdentity
    });

    if (effectiveCount >= this.federationAbuseDenyThreshold) {
      current.blocked_until_ms = now + this.federationAutoPolicyDurationMs;
      this.applyFederationAutoPolicy(node, "deny", reasonCode, actorIdentity);
    } else if (effectiveCount >= this.federationAbuseQuarantineThreshold && node.policy === "trusted") {
      current.blocked_until_ms = now + this.federationAutoPolicyDurationMs;
      this.applyFederationAutoPolicy(node, "quarantine", reasonCode, actorIdentity);
    }

    if (
      this.federationChallengeEscalationEnabled &&
      (effectiveCount >= this.federationChallengeThreshold || node.reputation_score >= this.federationChallengeThreshold)
    ) {
      this.applyFederationChallengeEscalation(node, reasonCode, actorIdentity);
    }
  }

  async recordFederationInboundFailureFromRequest(headers = {}, verifiedNode = null, error = null) {
    if (!this.federationAbuseAutoPolicyEnabled) {
      return;
    }

    if (error?.code === "CAPABILITY_DENIED" && error?.details?.auto_policy === true) {
      return;
    }

    const headerNode = String(headers["x-loom-node"] || "").trim();
    const nodeId = verifiedNode?.node_id || headerNode;
    if (!nodeId || !this.knownNodesById.has(nodeId)) {
      return;
    }

    await this.recordFederationInboundFailure(nodeId, error?.code || "UNKNOWN", "system");
  }

  async recordFederationInboundSuccess(nodeId) {
    if (!nodeId) {
      return;
    }

    const node = this.knownNodesById.get(nodeId) || null;

    const current = this.federationInboundAbuseByNode.get(nodeId);
    if (current) {
      this.federationInboundAbuseByNode.set(nodeId, {
        count: 0,
        window_started_at: nowMs(),
        blocked_until_ms: current.blocked_until_ms || null,
        last_reason_code: null
      });
    }

    if (!node) {
      return;
    }

    const previousScore = Math.max(0, Number(node.reputation_score || 0));
    node.reputation_score = Math.max(0, previousScore - 1);

    if (this.federationDistributedGuardsEnabled && this.persistenceAdapter?.recordFederationAbuseSuccess) {
      try {
        const distributed = await this.persistenceAdapter.recordFederationAbuseSuccess({
          nodeId
        });
        if (Number.isFinite(Number(distributed?.reputation_score))) {
          node.reputation_score = Number(distributed.reputation_score);
        }
      } catch {}
    }

    if (node.reputation_score !== previousScore) {
      node.updated_at = nowIso();
      this.persistAndAudit("federation.node.reputation.updated", {
        node_id: node.node_id,
        reputation_score: node.reputation_score,
        reason_code: "SUCCESS",
        actor: "system"
      });
    }
  }

  async enforceFederationInboundRate(nodeId) {
    const max = this.federationInboundRateMax;
    const windowMs = this.federationInboundRateWindowMs;
    if (max <= 0 || windowMs <= 0) {
      return;
    }

    const now = nowMs();
    const current = this.federationInboundRateByNode.get(nodeId);
    if (!current || now - current.window_started_at >= windowMs) {
      this.federationInboundRateByNode.set(nodeId, {
        count: 1,
        window_started_at: now
      });
    } else if (current.count >= max) {
      const retryAfterMs = Math.max(1, current.window_started_at + windowMs - now);
      throw new LoomError("RATE_LIMIT_EXCEEDED", "Federation node inbound rate limit exceeded", 429, {
        scope: "federation_node",
        node_id: nodeId,
        limit: max,
        window_ms: windowMs,
        retry_after_ms: retryAfterMs
      });
    } else {
      current.count += 1;
    }

    if (this.federationDistributedGuardsEnabled && this.persistenceAdapter?.incrementFederationInboundRate) {
      const distributed = await this.persistenceAdapter.incrementFederationInboundRate({
        nodeId,
        windowMs
      });
      if (Number(distributed?.count || 0) > max) {
        const oldestMs = Number(distributed?.oldest_ms || 0);
        const retryAfterMs = oldestMs ? Math.max(1, oldestMs + windowMs - nowMs()) : windowMs;
        throw new LoomError("RATE_LIMIT_EXCEEDED", "Distributed federation node inbound rate limit exceeded", 429, {
          scope: "federation_node_distributed",
          node_id: nodeId,
          limit: max,
          window_ms: windowMs,
          retry_after_ms: retryAfterMs
        });
      }
    }
  }

  getFederationInboundPolicyStatus() {
    this.cleanupFederationInboundRateState();
    this.cleanupFederationInboundAbuseState();
    this.cleanupFederationChallengeState();
    this.refreshAllFederationNodeAutoPolicies();
    const inboundContentFilter = this.getInboundContentFilterStatus();
    let activeAutoPolicies = 0;
    let activeChallenges = 0;
    let highReputationNodes = 0;
    for (const node of this.knownNodesById.values()) {
      if (node.auto_policy && !isExpiredIso(node.auto_policy_until)) {
        activeAutoPolicies += 1;
      }
      if (this.isFederationChallengeRequired(node)) {
        activeChallenges += 1;
      }
      if (Number(node.reputation_score || 0) >= this.federationChallengeThreshold) {
        highReputationNodes += 1;
      }
    }
    return {
      max_envelopes_per_delivery: this.federationInboundMaxEnvelopes,
      rate_limit_window_ms: this.federationInboundRateWindowMs,
      rate_limit_max: this.federationInboundRateMax,
      global_rate_limit_window_ms: this.federationGlobalInboundRateWindowMs,
      global_rate_limit_max: this.federationGlobalInboundRateMax,
      tracked_nodes: this.federationInboundRateByNode.size,
      abuse_auto_policy_enabled: this.federationAbuseAutoPolicyEnabled,
      abuse_window_ms: this.federationAbuseWindowMs,
      abuse_quarantine_threshold: this.federationAbuseQuarantineThreshold,
      abuse_deny_threshold: this.federationAbuseDenyThreshold,
      abuse_policy_duration_ms: this.federationAutoPolicyDurationMs,
      abuse_tracked_nodes: this.federationInboundAbuseByNode.size,
      active_auto_policies: activeAutoPolicies,
      challenge_escalation_enabled: this.federationChallengeEscalationEnabled,
      challenge_threshold: this.federationChallengeThreshold,
      challenge_duration_ms: this.federationChallengeDurationMs,
      active_challenges: activeChallenges,
      high_reputation_nodes: highReputationNodes,
      distributed_guards_enabled: this.federationDistributedGuardsEnabled,
      require_signed_receipts: this.federationRequireSignedReceipts,
      content_filter: inboundContentFilter,
      content_filter_enabled: inboundContentFilter.enabled,
      content_filter_reject_malware: inboundContentFilter.reject_malware,
      content_filter_evaluated: inboundContentFilter.evaluated,
      content_filter_rejected: inboundContentFilter.rejected,
      content_filter_quarantined: inboundContentFilter.quarantined,
      content_filter_spam_labeled: inboundContentFilter.spam_labeled,
      content_filter_decision_counts_by_profile: inboundContentFilter.decision_counts_by_profile
    };
  }

  async getFederationGuardStatus() {
    const local = {
      challenge_tokens_tracked: this.federationChallengesByNode.size
    };

    if (this.federationDistributedGuardsEnabled && this.persistenceAdapter?.getFederationGuardStatus) {
      try {
        const distributed = await this.persistenceAdapter.getFederationGuardStatus();
        return {
          local,
          distributed
        };
      } catch {
        return {
          local,
          distributed: null
        };
      }
    }

    return {
      local,
      distributed: null
    };
  }

  createFederationDeliveryReceipt(payload) {
    const acceptedEnvelopeIds = Array.isArray(payload?.accepted_envelope_ids)
      ? payload.accepted_envelope_ids.map((id) => String(id || "").trim()).filter(Boolean)
      : [];
    const receipt = {
      loom: "1.1",
      type: "federation.delivery.receipt@v1",
      delivery_id: String(payload?.delivery_id || "").trim(),
      sender_node: String(payload?.sender_node || "").trim(),
      recipient_node: String(payload?.recipient_node || "").trim(),
      status: String(payload?.status || "accepted").trim() || "accepted",
      accepted_count: acceptedEnvelopeIds.length,
      accepted_envelope_ids: acceptedEnvelopeIds,
      timestamp: nowIso()
    };

    const signatureValue = signUtf8Message(this.federationSigningPrivateKeyPem, canonicalizeFederationReceipt(receipt));
    return {
      ...receipt,
      signature: {
        algorithm: "Ed25519",
        key_id: this.federationSigningKeyId,
        value: signatureValue
      }
    };
  }

  verifyFederationDeliveryReceipt(receipt, expected = {}) {
    if (!receipt || typeof receipt !== "object") {
      return {
        valid: false,
        reason: "missing_receipt"
      };
    }

    const expectedSenderNode = String(expected.sender_node || "").trim();
    const expectedRecipientNode = String(expected.recipient_node || "").trim();
    const expectedDeliveryId = String(expected.delivery_id || "").trim();
    const node = expected.node || null;

    if (!node) {
      return {
        valid: false,
        reason: "missing_node"
      };
    }

    if (expectedSenderNode && receipt.sender_node !== expectedSenderNode) {
      return {
        valid: false,
        reason: "sender_node_mismatch"
      };
    }

    if (expectedRecipientNode && receipt.recipient_node !== expectedRecipientNode) {
      return {
        valid: false,
        reason: "recipient_node_mismatch"
      };
    }

    if (expectedDeliveryId && receipt.delivery_id !== expectedDeliveryId) {
      return {
        valid: false,
        reason: "delivery_id_mismatch"
      };
    }

    if (receipt.type !== "federation.delivery.receipt@v1") {
      return {
        valid: false,
        reason: "receipt_type_invalid"
      };
    }

    const signature = receipt.signature;
    if (!signature?.value || !signature?.key_id) {
      return {
        valid: false,
        reason: "missing_signature"
      };
    }

    const nodeSigningKey = resolveFederationNodeSigningKey(node, signature.key_id);
    if (!nodeSigningKey) {
      return {
        valid: false,
        reason: "key_id_unknown"
      };
    }

    const canonicalPayload = {
      ...receipt
    };
    delete canonicalPayload.signature;
    const valid = verifyUtf8MessageSignature(
      nodeSigningKey.public_key_pem,
      canonicalizeFederationReceipt(canonicalPayload),
      signature.value
    );

    return {
      valid,
      reason: valid ? null : "signature_invalid"
    };
  }

  async verifyFederationRequest({ method, path, headers, rawBody, bypassChallenge = false }) {
    const nodeId = String(headers["x-loom-node"] || "").trim();
    const timestamp = String(headers["x-loom-timestamp"] || "").trim();
    const nonce = String(headers["x-loom-nonce"] || "").trim();
    const keyId = String(headers["x-loom-key-id"] || "").trim();
    const signature = String(headers["x-loom-signature"] || "").trim();
    const trustEpochHeader = String(headers["x-loom-trust-epoch"] || "").trim();

    if (!nodeId || !timestamp || !nonce || !keyId || !signature) {
      throw new LoomError("SIGNATURE_INVALID", "Missing required federation signature headers", 401, {
        required_headers: [
          "x-loom-node",
          "x-loom-timestamp",
          "x-loom-nonce",
          "x-loom-key-id",
          "x-loom-signature"
        ]
      });
    }

    const node = this.knownNodesById.get(nodeId);
    const nodeSigningKey = resolveFederationNodeSigningKey(node, keyId);
    if (!node || !nodeSigningKey) {
      throw new LoomError("SIGNATURE_INVALID", "Unknown federation node or key id", 401, {
        node_id: nodeId,
        key_id: keyId
      });
    }

    this.refreshFederationNodeAutoPolicy(node, "system");
    this.refreshFederationNodeChallengeRequirement(node, "system");

    if (node.policy === "deny") {
      throw new LoomError("CAPABILITY_DENIED", "Federation node policy denies inbound delivery", 403, {
        node_id: nodeId,
        auto_policy: Boolean(node.auto_policy),
        auto_policy_until: node.auto_policy_until || null
      });
    }

    await this.enforceFederationGlobalInboundRate(nodeId);
    this.cleanupFederationInboundRateState();
    await this.enforceFederationInboundRate(nodeId);

    const requestTimeMs = parseTime(timestamp);
    if (requestTimeMs == null || Math.abs(nowMs() - requestTimeMs) > this.federationTrustMaxClockSkewMs) {
      throw new LoomError("SIGNATURE_INVALID", "Federation request timestamp outside freshness window", 401, {
        timestamp,
        max_skew_ms: this.federationTrustMaxClockSkewMs
      });
    }

    if (node.trust_anchor_mode === "public_dns_webpki") {
      const expectedEpoch = Math.max(0, parseNonNegativeInteger(node.trust_anchor_epoch, 0));
      const requestEpoch = parseOptionalNonNegativeInteger(trustEpochHeader);
      if (expectedEpoch > 0 && requestEpoch == null) {
        if (this.federationTrustFailClosed) {
          throw new LoomError("SIGNATURE_INVALID", "Federation request is missing trust epoch header", 401, {
            node_id: nodeId,
            required_header: "x-loom-trust-epoch",
            expected_epoch: expectedEpoch
          });
        }
      } else if (requestEpoch != null && requestEpoch < expectedEpoch) {
        throw new LoomError("SIGNATURE_INVALID", "Federation request trust epoch is stale", 401, {
          node_id: nodeId,
          expected_epoch: expectedEpoch,
          request_epoch: requestEpoch
        });
      } else if (requestEpoch != null && requestEpoch > expectedEpoch && this.federationTrustFailClosed) {
        throw new LoomError("SIGNATURE_INVALID", "Federation request trust epoch is newer than local trust anchor", 401, {
          node_id: nodeId,
          expected_epoch: expectedEpoch,
          request_epoch: requestEpoch
        });
      }
    }

    this.cleanupFederationNonces();
    const nonceKey = `${nodeId}:${nonce}`;
    if (this.federationNonceCache.has(nonceKey)) {
      throw new LoomError("SIGNATURE_INVALID", "Federation request nonce replay detected", 401, {
        node_id: nodeId,
        nonce
      });
    }

    const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
    const canonicalV2 = canonicalizeFederationRequestSignatureInput({
      method,
      path,
      bodyHash,
      timestamp,
      nonce,
      trustEpoch: trustEpochHeader
    });
    const canonicalV1 = `${method.toUpperCase()}\n${path}\n${bodyHash}\n${timestamp}\n${nonce}`;
    const validV2 = verifyUtf8MessageSignature(nodeSigningKey.public_key_pem, canonicalV2, signature);
    const validV1 = validV2 ? false : verifyUtf8MessageSignature(nodeSigningKey.public_key_pem, canonicalV1, signature);
    const valid = validV2 || validV1;

    if (!valid) {
      throw new LoomError("SIGNATURE_INVALID", "Federation request signature verification failed", 401, {
        node_id: nodeId
      });
    }

    if (node.trust_anchor_mode === "public_dns_webpki" && validV1 && this.federationTrustFailClosed) {
      throw new LoomError("SIGNATURE_INVALID", "Federation request must sign trust epoch in canonical input", 401, {
        node_id: nodeId
      });
    }

    if (!bypassChallenge && this.isFederationChallengeRequired(node)) {
      const challengeToken = String(headers["x-loom-challenge-token"] || "").trim();
      if (!challengeToken) {
        throw new LoomError("CAPABILITY_DENIED", "Federation challenge token required", 403, {
          scope: "federation_challenge",
          node_id: nodeId,
          challenge_required: true,
          challenge_required_until: node.challenge_required_until,
          challenge_endpoint: "/v1/federation/challenge"
        });
      }

      const validChallenge = await this.consumeFederationChallengeToken(nodeId, challengeToken);
      if (!validChallenge) {
        throw new LoomError("CAPABILITY_DENIED", "Invalid federation challenge token", 403, {
          scope: "federation_challenge",
          node_id: nodeId,
          challenge_required: true,
          challenge_required_until: node.challenge_required_until,
          challenge_endpoint: "/v1/federation/challenge"
        });
      }
    }

    this.federationNonceCache.set(nonceKey, nowMs());
    this.persistAndAudit("federation.nonce.accepted", {
      node_id: nodeId,
      nonce
    });
    return node;
  }

  async ingestFederationDelivery(wrapper, verifiedNode) {
    if (!wrapper || typeof wrapper !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Federation wrapper must be an object", 400, {
        field: "wrapper"
      });
    }

    if (wrapper.sender_node !== verifiedNode.node_id) {
      throw new LoomError("SIGNATURE_INVALID", "Federation sender node mismatch", 401, {
        header_node: verifiedNode.node_id,
        body_node: wrapper.sender_node
      });
    }

    if (!Array.isArray(wrapper.envelopes) || wrapper.envelopes.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "Federation wrapper must include envelopes[]", 400, {
        field: "envelopes"
      });
    }

    if (wrapper.envelopes.length > this.federationInboundMaxEnvelopes) {
      throw new LoomError(
        "PAYLOAD_TOO_LARGE",
        `Federation delivery exceeds maximum envelope count (${this.federationInboundMaxEnvelopes})`,
        413,
        {
          field: "envelopes",
          max_envelopes: this.federationInboundMaxEnvelopes
        }
      );
    }

    const accepted = [];
    const rejected = [];
    const nodePolicyQuarantine = verifiedNode.policy === "quarantine";
    let contentQuarantinedCount = 0;
    let contentSpamLabeledCount = 0;
    for (const envelope of wrapper.envelopes) {
      try {
        await this.ensureFederatedSenderIdentity(envelope, verifiedNode);

        const contentEvaluation = this.evaluateInboundContentPolicy(
          {
            subject: envelope?.content?.structured?.intent || envelope?.type || "",
            text: envelope?.content?.encrypted ? "" : envelope?.content?.human?.text || "",
            html: "",
            attachments: Array.isArray(envelope?.attachments) ? envelope.attachments : []
          },
          {
            source: "federation",
            actor: envelope?.from?.identity || null,
            node_id: verifiedNode.node_id
          }
        );
        if (contentEvaluation.action === "reject") {
          await this.recordFederationInboundFailure(
            verifiedNode.node_id,
            "CONTENT_FILTER_REJECT",
            "system"
          );
          throw new LoomError("CAPABILITY_DENIED", "Federation content policy rejected envelope", 403, {
            envelope_id: envelope?.id || null,
            node_id: verifiedNode.node_id,
            content_filter: {
              action: contentEvaluation.action,
              score: contentEvaluation.score,
              categories: contentEvaluation.detected_categories
            }
          });
        }

        const quarantined = nodePolicyQuarantine || contentEvaluation.action === "quarantine";
        const envelopeWithPolicyMeta = {
          ...envelope,
          meta: {
            ...(envelope.meta || {}),
            federation: {
              ...(envelope.meta?.federation || {}),
              source_node: verifiedNode.node_id,
              policy: quarantined ? "quarantine" : verifiedNode.policy || "trusted",
              content_filter_action: contentEvaluation.action
            },
            security: {
              ...(envelope.meta?.security || {}),
              content_filter: {
                version: contentEvaluation.version,
                source: contentEvaluation.source,
                action: contentEvaluation.action,
                labels: contentEvaluation.labels,
                score: contentEvaluation.score,
                spam_score: contentEvaluation.spam_score,
                phish_score: contentEvaluation.phish_score,
                malware_score: contentEvaluation.malware_score,
                detected_categories: contentEvaluation.detected_categories,
                signal_codes: contentEvaluation.signals.map((signal) => signal.code),
                evaluated_at: nowIso()
              }
            }
          }
        };

        const stored = this.ingestEnvelope(envelopeWithPolicyMeta, {
          actorIdentity: envelopeWithPolicyMeta?.from?.identity,
          federated: true,
          federationNode: verifiedNode
        });

        if (quarantined) {
          const thread = this.threadsById.get(stored.thread_id);
          if (thread && !thread.labels.includes("sys.quarantine")) {
            thread.labels = [...thread.labels, "sys.quarantine"];
            thread.updated_at = nowIso();
            contentQuarantinedCount += 1;
          }
        }

        if (contentEvaluation.labels.includes("sys.spam")) {
          const thread = this.threadsById.get(stored.thread_id);
          if (thread && !thread.labels.includes("sys.spam")) {
            thread.labels = [...thread.labels, "sys.spam"];
            thread.updated_at = nowIso();
            contentSpamLabeledCount += 1;
          }
        }

        accepted.push(stored.id);
      } catch (envelopeError) {
        rejected.push({
          envelope_id: envelope?.id || null,
          error: envelopeError?.code || envelopeError?.message || "UNKNOWN",
          _error: envelopeError
        });
      }
    }

    if (accepted.length === 0 && rejected.length > 0) {
      // If every envelope was rejected, re-throw the first original error
      // so callers see the real status code and error code.
      const firstError = rejected[0]._error;
      if (firstError) {
        throw firstError;
      }
      throw new LoomError("ENVELOPE_INVALID", "All envelopes in federation delivery were rejected", 400, {
        rejected_count: rejected.length,
        rejected: rejected.map(({ envelope_id, error }) => ({ envelope_id, error }))
      });
    }

    this.persistAndAudit("federation.deliver", {
      sender_node: verifiedNode.node_id,
      accepted_count: accepted.length,
      rejected_count: rejected.length,
      policy: verifiedNode.policy,
      content_quarantined_count: contentQuarantinedCount,
      content_spam_labeled_count: contentSpamLabeledCount
    });

    const deliveryId = String(wrapper.delivery_id || "").trim() || null;
    const receipt = this.createFederationDeliveryReceipt({
      delivery_id: deliveryId || `fdel_${generateUlid()}`,
      sender_node: this.nodeId,
      recipient_node: verifiedNode.node_id,
      status: rejected.length > 0 ? "partial" : "accepted",
      accepted_envelope_ids: accepted
    });

    return {
      sender_node: verifiedNode.node_id,
      accepted_count: accepted.length,
      rejected_count: rejected.length,
      rejected: rejected.length > 0 ? rejected.map(({ envelope_id, error }) => ({ envelope_id, error })) : undefined,
      accepted_envelope_ids: accepted,
      content_quarantined_count: contentQuarantinedCount,
      content_spam_labeled_count: contentSpamLabeledCount,
      receipt
    };
  }

  resolveFederationDeliverUrl(node) {
    return node.deliver_url || `https://${node.node_id}/v1/federation/deliver`;
  }

  queueFederationOutbox(payload, actorIdentity) {
    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Federation outbox payload must be an object", 400, {
        field: "outbox"
      });
    }

    const recipientNode = String(payload.recipient_node || "").trim();
    if (!recipientNode) {
      throw new LoomError("ENVELOPE_INVALID", "recipient_node is required", 400, {
        field: "recipient_node"
      });
    }

    const node = this.knownNodesById.get(recipientNode);
    if (!node) {
      throw new LoomError("ENVELOPE_INVALID", `Unknown recipient node: ${recipientNode}`, 400, {
        recipient_node: recipientNode
      });
    }

    if (!Array.isArray(payload.envelope_ids) || payload.envelope_ids.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "envelope_ids must be a non-empty array", 400, {
        field: "envelope_ids"
      });
    }

    const envelopeIds = Array.from(new Set(payload.envelope_ids.map((id) => String(id || "").trim()).filter(Boolean)));
    const envelopeSummaries = [];
    const envelopes = [];

    for (const envelopeId of envelopeIds) {
      const envelope = this.envelopesById.get(envelopeId);
      if (!envelope) {
        throw new LoomError("ENVELOPE_NOT_FOUND", `Envelope not found: ${envelopeId}`, 404, {
          envelope_id: envelopeId
        });
      }

      const thread = this.threadsById.get(envelope.thread_id);
      const canQueue =
        envelope.from?.identity === actorIdentity || (thread ? this.isActiveParticipant(thread, actorIdentity) : false);
      if (!canQueue) {
        throw new LoomError("CAPABILITY_DENIED", "Not authorized to federate one or more envelopes", 403, {
          envelope_id: envelopeId,
          actor: actorIdentity
        });
      }

      envelopeSummaries.push({
        envelope_id: envelope.id,
        thread_id: envelope.thread_id
      });
      envelopes.push(envelope);
    }

    this.assertFederationOutboxNodeCompatibility(node, envelopes);

    const traceContext = this.getCurrentTraceContext();
    const sourceRequestId = traceContext?.request_id || null;
    const sourceTraceId = traceContext?.trace_id || sourceRequestId || null;

    const outbox = {
      id: `fout_${generateUlid()}`,
      recipient_node: recipientNode,
      deliver_url: this.resolveFederationDeliverUrl(node),
      delivery_id: `fdel_${generateUlid()}`,
      envelope_ids: envelopeIds,
      status: "queued",
      attempts: 0,
      max_attempts: Math.max(1, Math.min(Number(payload.max_attempts || 8), 20)),
      next_attempt_at: nowIso(),
      created_at: nowIso(),
      updated_at: nowIso(),
      expires_at: payload.expires_at || new Date(nowMs() + 72 * 60 * 60 * 1000).toISOString(),
      delivered_at: null,
      last_error: null,
      last_http_status: null,
      receipt: null,
      receipt_verified: false,
      receipt_verified_at: null,
      receipt_verification_error: null,
      queued_by: actorIdentity,
      source_request_id: sourceRequestId,
      source_trace_id: sourceTraceId
    };

    this.federationOutboxById.set(outbox.id, outbox);
    this.persistAndAudit("federation.outbox.queue", {
      outbox_id: outbox.id,
      recipient_node: recipientNode,
      envelope_count: envelopeSummaries.length,
      actor: actorIdentity,
      source_request_id: sourceRequestId,
      source_trace_id: sourceTraceId
    });

    return outbox;
  }

  listFederationOutbox(filters = {}) {
    const status = filters.status ? String(filters.status) : null;
    const recipientNode = filters.recipient_node ? String(filters.recipient_node) : null;
    const limit = Math.max(1, Math.min(Number(filters.limit || 200), 1000));

    const items = Array.from(this.federationOutboxById.values())
      .filter((item) => (status ? item.status === status : true))
      .filter((item) => (recipientNode ? item.recipient_node === recipientNode : true))
      .sort((a, b) => a.created_at.localeCompare(b.created_at));

    return items.slice(0, limit);
  }

  getFederationOutboxStats() {
    const stats = {
      total: 0,
      queued: 0,
      delivered: 0,
      failed: 0,
      retry_scheduled: 0,
      oldest_queued_at: null,
      newest_queued_at: null,
      lag_ms: 0
    };

    for (const item of this.federationOutboxById.values()) {
      stats.total += 1;

      if (item.status === "queued") {
        stats.queued += 1;
        if (item.next_attempt_at) {
          stats.retry_scheduled += 1;
        }

        if (!stats.oldest_queued_at || item.created_at < stats.oldest_queued_at) {
          stats.oldest_queued_at = item.created_at;
        }
        if (!stats.newest_queued_at || item.created_at > stats.newest_queued_at) {
          stats.newest_queued_at = item.created_at;
        }
      } else if (item.status === "delivered") {
        stats.delivered += 1;
      } else if (item.status === "failed") {
        stats.failed += 1;
      }
    }

    if (stats.oldest_queued_at) {
      stats.lag_ms = Math.max(0, nowMs() - Date.parse(stats.oldest_queued_at));
    }

    return stats;
  }

  listDeadLetterOutbox(filters = {}) {
    const normalizedKind = String(filters.kind || "all")
      .trim()
      .toLowerCase();
    const kind = ["email", "federation", "webhook", "all"].includes(normalizedKind) ? normalizedKind : "all";
    const limit = Math.max(1, Math.min(Number(filters.limit || 200), 1000));
    const entries = [];

    if (kind === "all" || kind === "federation") {
      for (const item of this.federationOutboxById.values()) {
        if (item.status !== "failed") {
          continue;
        }
        entries.push({
          kind: "federation",
          id: item.id,
          thread_id: null,
          updated_at: item.updated_at,
          item
        });
      }
    }

    if (kind === "all" || kind === "email") {
      for (const item of this.emailOutboxById.values()) {
        if (item.status !== "failed") {
          continue;
        }
        entries.push({
          kind: "email",
          id: item.id,
          thread_id: item.thread_id,
          updated_at: item.updated_at,
          item
        });
      }
    }

    if (kind === "all" || kind === "webhook") {
      for (const item of this.webhookOutboxById.values()) {
        if (item.status !== "failed") {
          continue;
        }
        entries.push({
          kind: "webhook",
          id: item.id,
          thread_id: null,
          updated_at: item.updated_at,
          item
        });
      }
    }

    entries.sort((a, b) => {
      if (a.updated_at === b.updated_at) {
        return a.id.localeCompare(b.id);
      }
      return a.updated_at > b.updated_at ? -1 : 1;
    });

    return entries.slice(0, limit);
  }

  requeueFederationOutboxItem(outboxId, actorIdentity = null) {
    const item = this.federationOutboxById.get(outboxId);
    if (!item) {
      throw new LoomError("ENVELOPE_NOT_FOUND", `Federation outbox item not found: ${outboxId}`, 404, {
        outbox_id: outboxId
      });
    }

    if (item.status !== "failed") {
      throw new LoomError("STATE_TRANSITION_INVALID", "Only failed federation outbox items can be requeued", 409, {
        outbox_id: outboxId,
        current_status: item.status
      });
    }

    item.status = "queued";
    item.next_attempt_at = nowIso();
    item.updated_at = nowIso();
    item.last_error = null;
    item.last_http_status = null;

    this.persistAndAudit("federation.outbox.requeue", {
      outbox_id: item.id,
      recipient_node: item.recipient_node,
      actor: actorIdentity
    });

    return item;
  }

  markOutboxFailure(item, errorMessage, statusCode = null, options = {}) {
    const receiptVerificationError = options?.receiptVerificationError || null;
    item.attempts += 1;
    item.updated_at = nowIso();
    item.last_error = String(errorMessage || "federation delivery failed");
    item.last_http_status = statusCode;
    item.receipt_verified = false;
    item.receipt_verified_at = null;
    item.receipt_verification_error = receiptVerificationError;

    const expired = isExpiredIso(item.expires_at);
    if (expired || item.attempts >= item.max_attempts) {
      item.status = "failed";
      item.next_attempt_at = null;
      return;
    }

    const backoffSeconds = Math.min(30 * 2 ** Math.max(0, item.attempts - 1), 3600);
    item.status = "queued";
    item.next_attempt_at = new Date(nowMs() + backoffSeconds * 1000).toISOString();
  }

  async processFederationOutboxItem(outboxId, actorIdentity = null) {
    const item = this.federationOutboxById.get(outboxId);
    if (!item) {
      throw new LoomError("ENVELOPE_NOT_FOUND", `Federation outbox item not found: ${outboxId}`, 404, {
        outbox_id: outboxId
      });
    }

    if (item.status === "delivered") {
      return item;
    }

    if (item.status === "failed") {
      return item;
    }

    if (!this.federationSigningPrivateKeyPem) {
      this.markOutboxFailure(item, "Local federation signing key not configured");
      this.persistAndAudit("federation.outbox.process.failed", {
        outbox_id: item.id,
        reason: item.last_error,
        actor: actorIdentity
      });
      return item;
    }

    if (item.next_attempt_at && parseTime(item.next_attempt_at) > nowMs()) {
      return item;
    }

    if (!(await this.claimOutboxItemForProcessing("federation", item))) {
      return item;
    }

    try {
      let node = this.knownNodesById.get(item.recipient_node);
      if (!node) {
        this.markOutboxFailure(item, `Unknown recipient node: ${item.recipient_node}`);
        this.persistAndAudit("federation.outbox.process.failed", {
          outbox_id: item.id,
          reason: item.last_error,
          actor: actorIdentity
        });
        return item;
      }

      const envelopes = item.envelope_ids
        .map((envelopeId) => this.envelopesById.get(envelopeId))
        .filter(Boolean);

      if (envelopes.length !== item.envelope_ids.length) {
        this.markOutboxFailure(item, "One or more queued envelopes are missing");
        this.persistAndAudit("federation.outbox.process.failed", {
          outbox_id: item.id,
          reason: item.last_error,
          actor: actorIdentity
        });
        return item;
      }

      const encryptedEnvelopeQueued = envelopes.some((envelope) => envelope?.content?.encrypted === true);
      const protocolNegotiationRequired =
        this.federationRequireProtocolCapabilities ||
        this.federationRequireE2eeProfileOverlap ||
        this.federationRequireTrustModeParity ||
        encryptedEnvelopeQueued;
      try {
        node = await this.ensureFederationNodeProtocolCapabilities(node, actorIdentity || "system", {
          forceRefresh: !node.protocol_capabilities || Boolean(node.protocol_capabilities_fetch_error),
          failOnMissing: protocolNegotiationRequired,
          failOnFetchError: protocolNegotiationRequired,
          persist: true
        });
        this.assertFederationOutboxNodeCompatibility(node, envelopes);
      } catch (error) {
        this.markOutboxFailure(item, error?.message || "Federation protocol capability negotiation failed");
        this.persistAndAudit("federation.outbox.process.failed", {
          outbox_id: item.id,
          recipient_node: item.recipient_node,
          reason: item.last_error,
          actor: actorIdentity
        });
        return item;
      }

      const wrapper = {
        loom: "1.1",
        sender_node: this.nodeId,
        delivery_id: item.delivery_id || item.id,
        timestamp: nowIso(),
        envelopes
      };

      const rawBody = JSON.stringify(wrapper);
      const bodyHash = createHash("sha256").update(rawBody, "utf-8").digest("hex");
      const timestamp = nowIso();
      const nonce = `nonce_${generateUlid()}`;
      const trustEpoch = Math.max(0, parseNonNegativeInteger(this.federationTrustLocalEpoch, 0));

      const deliverUrl = item.deliver_url || this.resolveFederationDeliverUrl(node);
      let parsedUrl;
      try {
        parsedUrl = new URL(deliverUrl);
      } catch {
        this.markOutboxFailure(item, "Invalid federation deliver_url");
        this.persistAndAudit("federation.outbox.process.failed", {
          outbox_id: item.id,
          recipient_node: item.recipient_node,
          reason: item.last_error,
          actor: actorIdentity
        });
        return item;
      }

      if (parsedUrl.username || parsedUrl.password) {
        this.markOutboxFailure(item, "Federation deliver_url must not include credentials");
        this.persistAndAudit("federation.outbox.process.failed", {
          outbox_id: item.id,
          recipient_node: item.recipient_node,
          reason: item.last_error,
          actor: actorIdentity
        });
        return item;
      }

      const allowInsecureHttp = node.allow_insecure_http === true;
      if (parsedUrl.protocol !== "https:" && !(allowInsecureHttp && parsedUrl.protocol === "http:")) {
        this.markOutboxFailure(item, "Federation deliver_url must use https unless allow_insecure_http=true");
        this.persistAndAudit("federation.outbox.process.failed", {
          outbox_id: item.id,
          recipient_node: item.recipient_node,
          reason: item.last_error,
          actor: actorIdentity
        });
        return item;
      }

      let outboundHostPolicy;
      try {
        outboundHostPolicy = await assertOutboundUrlHostAllowed(parsedUrl, {
          allowPrivateNetwork: node.allow_private_network === true,
          allowedHosts: this.federationOutboundHostAllowlist,
          denyMetadataHosts: this.denyMetadataHosts
        });
      } catch (error) {
        this.markOutboxFailure(item, error?.message || "Federation deliver_url host denied");
        this.persistAndAudit("federation.outbox.process.failed", {
          outbox_id: item.id,
          recipient_node: item.recipient_node,
          reason: item.last_error,
          actor: actorIdentity
        });
        return item;
      }

      const canonical =
        node.trust_anchor_mode === "public_dns_webpki"
          ? canonicalizeFederationRequestSignatureInput({
              method: "POST",
              path: parsedUrl.pathname,
              bodyHash,
              timestamp,
              nonce,
              trustEpoch
            })
          : `POST\n${parsedUrl.pathname}\n${bodyHash}\n${timestamp}\n${nonce}`;
      const signature = signUtf8Message(this.federationSigningPrivateKeyPem, canonical);

      try {
        const response = await performPinnedOutboundHttpRequest(parsedUrl.toString(), {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-loom-node": this.nodeId,
            "x-loom-timestamp": timestamp,
            "x-loom-nonce": nonce,
            "x-loom-key-id": this.federationSigningKeyId,
            "x-loom-signature": signature,
            "x-loom-trust-epoch": String(trustEpoch)
          },
          body: rawBody,
          timeoutMs: this.federationDeliverTimeoutMs,
          maxResponseBytes: this.federationDeliverMaxResponseBytes,
          responseSizeContext: {
            outbox_id: item.id,
            recipient_node: item.recipient_node
          },
          resolvedAddresses: outboundHostPolicy.resolvedAddresses,
          rejectRedirects: true
        });

        if (!response.ok) {
          const responseText = response.bodyText;
          this.markOutboxFailure(item, `Remote response ${response.status}: ${responseText}`, response.status);
          this.persistAndAudit("federation.outbox.process.failed", {
            outbox_id: item.id,
            recipient_node: item.recipient_node,
            reason: item.last_error,
            actor: actorIdentity
          });
          return item;
        }

        let responseJson = null;
        try {
          responseJson = response.bodyText ? JSON.parse(response.bodyText) : null;
        } catch {
          responseJson = null;
        }

        const receiptValidation = this.verifyFederationDeliveryReceipt(responseJson?.receipt, {
          sender_node: item.recipient_node,
          recipient_node: this.nodeId,
          delivery_id: item.delivery_id || item.id,
          node
        });

        if (!receiptValidation.valid && this.federationRequireSignedReceipts) {
          this.markOutboxFailure(item, `Signed receipt verification failed: ${receiptValidation.reason}`, null, {
            receiptVerificationError: receiptValidation.reason
          });
          this.persistAndAudit("federation.outbox.process.failed", {
            outbox_id: item.id,
            recipient_node: item.recipient_node,
            reason: item.last_error,
            receipt_verification_error: receiptValidation.reason,
            actor: actorIdentity
          });
          return item;
        }

        item.attempts += 1;
        item.status = "delivered";
        item.updated_at = nowIso();
        item.delivered_at = nowIso();
        item.next_attempt_at = null;
        item.last_error = null;
        item.last_http_status = response.status;
        item.receipt = responseJson?.receipt || null;
        item.receipt_verified = receiptValidation.valid;
        item.receipt_verified_at = receiptValidation.valid ? nowIso() : null;
        item.receipt_verification_error = receiptValidation.valid ? null : receiptValidation.reason;

        this.persistAndAudit("federation.outbox.process.delivered", {
          outbox_id: item.id,
          delivery_id: item.delivery_id || item.id,
          recipient_node: item.recipient_node,
          attempts: item.attempts,
          receipt_verified: item.receipt_verified,
          receipt_verification_error: item.receipt_verification_error,
          source_request_id: item.source_request_id || null,
          source_trace_id: item.source_trace_id || null,
          actor: actorIdentity
        });

        return item;
      } catch (error) {
        if (error?.name === "AbortError") {
          this.markOutboxFailure(
            item,
            `Federation delivery timed out after ${this.federationDeliverTimeoutMs}ms`
          );
        } else {
          this.markOutboxFailure(item, error?.message || "Network error");
        }
        this.persistAndAudit("federation.outbox.process.failed", {
          outbox_id: item.id,
          recipient_node: item.recipient_node,
          reason: item.last_error,
          source_request_id: item.source_request_id || null,
          source_trace_id: item.source_trace_id || null,
          actor: actorIdentity
        });
        return item;
      }
    } finally {
      await this.releaseOutboxItemClaim("federation", item);
    }
  }

  async processFederationOutboxBatch(limit = 10, actorIdentity = null) {
    const now = nowMs();
    const candidates = Array.from(this.federationOutboxById.values())
      .filter((item) => item.status === "queued")
      .filter((item) => !item.next_attempt_at || parseTime(item.next_attempt_at) <= now)
      .sort((a, b) => a.created_at.localeCompare(b.created_at))
      .slice(0, Math.max(1, Math.min(Number(limit || 10), 200)));

    const processed = [];
    for (const item of candidates) {
      const result = await this.processFederationOutboxItem(item.id, actorIdentity);
      processed.push({
        outbox_id: result.id,
        status: result.status,
        attempts: result.attempts,
        last_error: result.last_error,
        receipt_verified: result.receipt_verified,
        receipt_verification_error: result.receipt_verification_error,
        source_request_id: result.source_request_id || null,
        source_trace_id: result.source_trace_id || null
      });
    }

    return {
      processed_count: processed.length,
      processed
    };
  }

  normalizeEmailAddress(value) {
    return normalizeEmailAddressAdapter(value);
  }

  splitAddressList(value) {
    return splitAddressListAdapter(value);
  }

  normalizeEmailAddressList(value) {
    return normalizeEmailAddressListAdapter(value);
  }

  resolveHeaderValue(headers, headerName) {
    return resolveHeaderValueAdapter(headers, headerName);
  }

  parseMessageId(value) {
    return parseMessageIdAdapter(value);
  }

  parseMessageIdList(value) {
    return parseMessageIdListAdapter(value);
  }

  parseReferences(value) {
    return parseReferencesAdapter(value);
  }

  resolveIdentitiesFromAddressInput(value) {
    return resolveIdentitiesFromAddressInputAdapter(value);
  }

  buildRecipientList({ primary = [], cc = [], bcc = [] } = {}) {
    return buildRecipientListAdapter({ primary, cc, bcc });
  }

  inferIdentityFromAddress(value) {
    return inferIdentityFromAddressAdapter(value);
  }

  inferEmailFromIdentity(identity) {
    return inferEmailFromIdentityAdapter(identity);
  }

  htmlToText(html) {
    return htmlToTextAdapter(html);
  }

  resolveThreadFromEmailHeaders(payload, options = {}) {
    const headers =
      options?.headers && typeof options.headers === "object"
        ? options.headers
        : payload?.headers && typeof payload.headers === "object"
          ? payload.headers
          : {};
    const inReplyToHeader = this.resolveHeaderValue(headers, "in-reply-to");
    const referencesHeader = this.resolveHeaderValue(headers, "references");
    const inReplyTo = this.parseMessageIdList(payload?.in_reply_to || inReplyToHeader);
    const references = this.parseReferences(payload?.references || referencesHeader);

    for (const ref of inReplyTo) {
      if (!this.emailMessageIndexById.has(ref)) {
        continue;
      }
      const mapped = this.emailMessageIndexById.get(ref);
      return {
        thread_id: mapped.thread_id,
        parent_id: mapped.envelope_id
      };
    }

    for (let idx = references.length - 1; idx >= 0; idx -= 1) {
      const ref = references[idx];
      const mapped = this.emailMessageIndexById.get(ref);
      if (mapped) {
        return {
          thread_id: mapped.thread_id,
          parent_id: mapped.envelope_id
        };
      }
    }

    return {
      thread_id: `thr_${generateUlid()}`,
      parent_id: null
    };
  }

  recordEmailMessageIndex(messageId, envelopeId, threadId) {
    const normalized = this.parseMessageId(messageId);
    if (!normalized) {
      return null;
    }

    const entry = {
      message_id: normalized,
      envelope_id: envelopeId,
      thread_id: threadId,
      updated_at: nowIso()
    };

    this.emailMessageIndexById.set(normalized, entry);
    return entry;
  }

  ensureThreadLabel(threadId, label) {
    const thread = this.threadsById.get(threadId);
    if (!thread) {
      return false;
    }

    if (!thread.labels.includes(label)) {
      thread.labels.push(label);
      thread.updated_at = nowIso();
      return true;
    }

    return false;
  }

  getInboundContentFilterActiveConfig() {
    return cloneInboundContentFilterConfig({
      enabled: this.inboundContentFilterEnabled,
      reject_malware: this.inboundContentFilterRejectMalware,
      spam_threshold: this.inboundContentFilterSpamThreshold,
      phish_threshold: this.inboundContentFilterPhishThreshold,
      quarantine_threshold: this.inboundContentFilterQuarantineThreshold,
      reject_threshold: this.inboundContentFilterRejectThreshold,
      profile_default: this.inboundContentFilterProfileDefault,
      profile_bridge_email: this.inboundContentFilterProfileBridge,
      profile_federation: this.inboundContentFilterProfileFederation
    });
  }

  applyInboundContentFilterActiveConfig(config = {}) {
    const normalized = cloneInboundContentFilterConfig(config);
    this.inboundContentFilterEnabled = normalized.enabled === true;
    this.inboundContentFilterRejectMalware = normalized.reject_malware === true;
    this.inboundContentFilterSpamThreshold = Math.max(1, Math.floor(normalized.spam_threshold));
    this.inboundContentFilterPhishThreshold = Math.max(1, Math.floor(normalized.phish_threshold));
    this.inboundContentFilterQuarantineThreshold = Math.max(1, Math.floor(normalized.quarantine_threshold));
    this.inboundContentFilterRejectThreshold = Math.max(
      this.inboundContentFilterQuarantineThreshold + 1,
      Math.floor(normalized.reject_threshold)
    );
    this.inboundContentFilterProfileDefault = normalizeInboundContentFilterProfile(
      normalized.profile_default,
      "balanced"
    );
    this.inboundContentFilterProfileBridge = normalizeInboundContentFilterProfile(
      normalized.profile_bridge_email,
      this.inboundContentFilterProfileDefault
    );
    this.inboundContentFilterProfileFederation = normalizeInboundContentFilterProfile(
      normalized.profile_federation,
      "agent"
    );
  }

  extractInboundContentFilterConfigPatch(payload = {}) {
    if (!payload || typeof payload !== "object") {
      return {};
    }
    const source =
      payload.config && typeof payload.config === "object" && !Array.isArray(payload.config)
        ? payload.config
        : payload;
    const patch = {};
    for (const field of INBOUND_CONTENT_FILTER_CONFIG_FIELDS) {
      if (Object.prototype.hasOwnProperty.call(source, field)) {
        patch[field] = source[field];
      }
    }
    return patch;
  }

  buildInboundContentFilterConfigUpdate(patch = {}, baseConfig = null) {
    const sourcePatch = patch && typeof patch === "object" && !Array.isArray(patch) ? patch : {};
    const current = baseConfig ? cloneInboundContentFilterConfig(baseConfig) : this.getInboundContentFilterActiveConfig();
    const next = { ...current };

    if (Object.prototype.hasOwnProperty.call(sourcePatch, "enabled")) {
      next.enabled = parseInboundContentFilterBooleanField(sourcePatch.enabled, "enabled", next.enabled);
    }
    if (Object.prototype.hasOwnProperty.call(sourcePatch, "reject_malware")) {
      next.reject_malware = parseInboundContentFilterBooleanField(
        sourcePatch.reject_malware,
        "reject_malware",
        next.reject_malware
      );
    }
    if (Object.prototype.hasOwnProperty.call(sourcePatch, "spam_threshold")) {
      next.spam_threshold = parseInboundContentFilterThresholdField(
        sourcePatch.spam_threshold,
        "spam_threshold",
        next.spam_threshold
      );
    }
    if (Object.prototype.hasOwnProperty.call(sourcePatch, "phish_threshold")) {
      next.phish_threshold = parseInboundContentFilterThresholdField(
        sourcePatch.phish_threshold,
        "phish_threshold",
        next.phish_threshold
      );
    }
    if (Object.prototype.hasOwnProperty.call(sourcePatch, "quarantine_threshold")) {
      next.quarantine_threshold = parseInboundContentFilterThresholdField(
        sourcePatch.quarantine_threshold,
        "quarantine_threshold",
        next.quarantine_threshold
      );
    }
    if (Object.prototype.hasOwnProperty.call(sourcePatch, "reject_threshold")) {
      next.reject_threshold = parseInboundContentFilterThresholdField(
        sourcePatch.reject_threshold,
        "reject_threshold",
        next.reject_threshold
      );
    }
    if (Object.prototype.hasOwnProperty.call(sourcePatch, "profile_default")) {
      next.profile_default = parseInboundContentFilterProfileField(
        sourcePatch.profile_default,
        "profile_default",
        next.profile_default
      );
    }
    if (Object.prototype.hasOwnProperty.call(sourcePatch, "profile_bridge_email")) {
      next.profile_bridge_email = parseInboundContentFilterProfileField(
        sourcePatch.profile_bridge_email,
        "profile_bridge_email",
        next.profile_bridge_email
      );
    }
    if (Object.prototype.hasOwnProperty.call(sourcePatch, "profile_federation")) {
      next.profile_federation = parseInboundContentFilterProfileField(
        sourcePatch.profile_federation,
        "profile_federation",
        next.profile_federation
      );
    }

    if (next.reject_threshold <= next.quarantine_threshold) {
      throw new LoomError("ENVELOPE_INVALID", "reject_threshold must be greater than quarantine_threshold", 400, {
        field: "reject_threshold",
        reject_threshold: next.reject_threshold,
        quarantine_threshold: next.quarantine_threshold
      });
    }

    const normalized = cloneInboundContentFilterConfig(next);
    return {
      config: normalized,
      changed: !areInboundContentFilterConfigsEqual(current, normalized)
    };
  }

  normalizeInboundContentFilterCanaryState(value) {
    if (!value || typeof value !== "object") {
      return null;
    }
    const configSource = value.config && typeof value.config === "object" ? value.config : value;
    let normalizedConfig;
    try {
      normalizedConfig = this.buildInboundContentFilterConfigUpdate(configSource, this.getInboundContentFilterActiveConfig()).config;
    } catch {
      return null;
    }
    return cloneInboundContentFilterCanaryState({
      ...value,
      config: normalizedConfig
    });
  }

  normalizeInboundContentFilterRollbackState(value) {
    if (!value || typeof value !== "object") {
      return null;
    }
    const configSource = value.config && typeof value.config === "object" ? value.config : value;
    let normalizedConfig;
    try {
      normalizedConfig = this.buildInboundContentFilterConfigUpdate(configSource, this.getInboundContentFilterActiveConfig()).config;
    } catch {
      return null;
    }
    return cloneInboundContentFilterRollbackState({
      ...value,
      config: normalizedConfig
    });
  }

  getInboundContentFilterConfigStatus() {
    return {
      version: Math.max(1, parsePositiveInteger(this.inboundContentFilterConfigVersion, 1)),
      updated_at: this.inboundContentFilterConfigUpdatedAt || null,
      updated_by: this.inboundContentFilterConfigUpdatedBy || null,
      active: this.getInboundContentFilterActiveConfig(),
      canary: cloneInboundContentFilterCanaryState(this.inboundContentFilterConfigCanary),
      rollback: cloneInboundContentFilterRollbackState(this.inboundContentFilterConfigRollback)
    };
  }

  updateInboundContentFilterConfig(payload, actorIdentity = "system") {
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new LoomError("ENVELOPE_INVALID", "Inbound content filter config payload must be an object", 400, {
        field: "payload"
      });
    }

    const mode = normalizeInboundContentFilterConfigMode(payload.mode);
    if (!mode) {
      throw new LoomError("ENVELOPE_INVALID", "mode must be one of canary, apply, rollback", 400, {
        field: "mode"
      });
    }

    const activeConfig = this.getInboundContentFilterActiveConfig();
    const now = nowIso();
    const normalizedActor = String(actorIdentity || "system").trim() || "system";

    if (mode === "canary") {
      const patch = this.extractInboundContentFilterConfigPatch(payload);
      if (Object.keys(patch).length === 0) {
        throw new LoomError("ENVELOPE_INVALID", "canary mode requires at least one config field", 400, {
          field: "config"
        });
      }
      const update = this.buildInboundContentFilterConfigUpdate(patch, activeConfig);
      const note =
        typeof payload.note === "string" && payload.note.trim().length > 0
          ? payload.note.trim().slice(0, 240)
          : null;
      this.inboundContentFilterConfigCanary = cloneInboundContentFilterCanaryState({
        canary_id: `cfcan_${generateUlid()}`,
        mode: "canary",
        created_at: now,
        updated_at: now,
        actor: normalizedActor,
        note,
        config: update.config
      });
      this.persistAndAudit("content.filter.config.canary", {
        actor: normalizedActor,
        mode,
        canary_id: this.inboundContentFilterConfigCanary?.canary_id || null,
        changed: update.changed,
        config: this.inboundContentFilterConfigCanary?.config || null
      });
      return this.getInboundContentFilterConfigStatus();
    }

    if (mode === "apply") {
      const patch = this.extractInboundContentFilterConfigPatch(payload);
      const hasPatch = Object.keys(patch).length > 0;
      const source = hasPatch ? "payload" : "canary";
      const previousVersion = Math.max(1, parsePositiveInteger(this.inboundContentFilterConfigVersion, 1));
      const appliedFromCanaryId = source === "canary" ? this.inboundContentFilterConfigCanary?.canary_id || null : null;
      let nextConfig = null;
      let changed = false;

      if (hasPatch) {
        const update = this.buildInboundContentFilterConfigUpdate(patch, activeConfig);
        nextConfig = update.config;
        changed = update.changed;
      } else if (this.inboundContentFilterConfigCanary?.config) {
        nextConfig = cloneInboundContentFilterConfig(this.inboundContentFilterConfigCanary.config);
        changed = !areInboundContentFilterConfigsEqual(activeConfig, nextConfig);
      } else {
        throw new LoomError("STATE_TRANSITION_INVALID", "No staged canary config to apply", 409, {
          field: "mode"
        });
      }

      this.inboundContentFilterConfigRollback = cloneInboundContentFilterRollbackState({
        rollback_id: `cfroll_${generateUlid()}`,
        from_version: previousVersion,
        source,
        stored_at: now,
        actor: normalizedActor,
        config: activeConfig
      });

      this.applyInboundContentFilterActiveConfig(nextConfig);
      this.inboundContentFilterConfigVersion = previousVersion + 1;
      this.inboundContentFilterConfigUpdatedAt = now;
      this.inboundContentFilterConfigUpdatedBy = normalizedActor;
      if (payload.keep_canary !== true) {
        this.inboundContentFilterConfigCanary = null;
      }

      this.persistAndAudit("content.filter.config.apply", {
        actor: normalizedActor,
        mode,
        source,
        changed,
        from_version: previousVersion,
        to_version: this.inboundContentFilterConfigVersion,
        applied_from_canary_id: appliedFromCanaryId,
        config: this.getInboundContentFilterActiveConfig()
      });
      return this.getInboundContentFilterConfigStatus();
    }

    const rollback = this.inboundContentFilterConfigRollback?.config
      ? cloneInboundContentFilterRollbackState(this.inboundContentFilterConfigRollback)
      : null;
    if (!rollback?.config) {
      throw new LoomError("STATE_TRANSITION_INVALID", "No rollback snapshot is available", 409, {
        field: "mode"
      });
    }

    const previousActive = this.getInboundContentFilterActiveConfig();
    const previousVersion = Math.max(1, parsePositiveInteger(this.inboundContentFilterConfigVersion, 1));
    this.applyInboundContentFilterActiveConfig(rollback.config);
    this.inboundContentFilterConfigVersion = previousVersion + 1;
    this.inboundContentFilterConfigUpdatedAt = now;
    this.inboundContentFilterConfigUpdatedBy = normalizedActor;
    this.inboundContentFilterConfigCanary = null;
    this.inboundContentFilterConfigRollback = cloneInboundContentFilterRollbackState({
      rollback_id: `cfroll_${generateUlid()}`,
      from_version: previousVersion,
      source: "rollback",
      stored_at: now,
      actor: normalizedActor,
      config: previousActive
    });

    this.persistAndAudit("content.filter.config.rollback", {
      actor: normalizedActor,
      mode,
      from_version: rollback.from_version,
      to_version: this.inboundContentFilterConfigVersion,
      restored_from_rollback_id: rollback.rollback_id || null,
      config: this.getInboundContentFilterActiveConfig()
    });
    return this.getInboundContentFilterConfigStatus();
  }

  resolveInboundContentFilterProfile(context = {}) {
    const explicitProfile = String(context?.profile || "")
      .trim()
      .toLowerCase();
    if (INBOUND_CONTENT_FILTER_PROFILES.has(explicitProfile)) {
      return explicitProfile;
    }

    const source = String(context?.source || "")
      .trim()
      .toLowerCase();
    if (source === "bridge_email") {
      return this.inboundContentFilterProfileBridge;
    }
    if (source === "federation") {
      return this.inboundContentFilterProfileFederation;
    }
    return this.inboundContentFilterProfileDefault;
  }

  resolveInboundContentFilterProfileConfig(profile) {
    const normalizedProfile = normalizeInboundContentFilterProfile(profile, this.inboundContentFilterProfileDefault);
    return INBOUND_CONTENT_FILTER_PROFILE_CONFIG[normalizedProfile] || INBOUND_CONTENT_FILTER_PROFILE_CONFIG.balanced;
  }

  resolveInboundContentFilterThresholds(profileConfig) {
    const deltas = profileConfig?.threshold_deltas && typeof profileConfig.threshold_deltas === "object"
      ? profileConfig.threshold_deltas
      : {};
    const delta = (value) => {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? Math.trunc(parsed) : 0;
    };
    const spamThreshold = Math.max(1, this.inboundContentFilterSpamThreshold + delta(deltas.spam));
    const phishThreshold = Math.max(1, this.inboundContentFilterPhishThreshold + delta(deltas.phish));
    const quarantineThreshold = Math.max(
      1,
      this.inboundContentFilterQuarantineThreshold + delta(deltas.quarantine)
    );
    const rejectThreshold = Math.max(
      quarantineThreshold + 1,
      this.inboundContentFilterRejectThreshold + delta(deltas.reject)
    );
    return {
      spam: spamThreshold,
      phish: phishThreshold,
      quarantine: quarantineThreshold,
      reject: rejectThreshold
    };
  }

  ensureInboundContentFilterStatsShape() {
    if (!this.inboundContentFilterStats || typeof this.inboundContentFilterStats !== "object") {
      this.inboundContentFilterStats = createInboundContentFilterStats();
      return;
    }

    const normalizeCount = (value) => {
      const parsed = Number(value);
      return Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : 0;
    };

    this.inboundContentFilterStats.evaluated = normalizeCount(this.inboundContentFilterStats.evaluated);
    this.inboundContentFilterStats.rejected = normalizeCount(this.inboundContentFilterStats.rejected);
    this.inboundContentFilterStats.quarantined = normalizeCount(this.inboundContentFilterStats.quarantined);
    this.inboundContentFilterStats.spam_labeled = normalizeCount(this.inboundContentFilterStats.spam_labeled);
    this.inboundContentFilterStats.last_evaluated_at =
      typeof this.inboundContentFilterStats.last_evaluated_at === "string" &&
      this.inboundContentFilterStats.last_evaluated_at.trim().length > 0
        ? this.inboundContentFilterStats.last_evaluated_at.trim()
        : null;

    const existingByProfile =
      this.inboundContentFilterStats.decision_counts_by_profile &&
      typeof this.inboundContentFilterStats.decision_counts_by_profile === "object"
        ? this.inboundContentFilterStats.decision_counts_by_profile
        : {};
    const normalizedByProfile = createInboundContentFilterDecisionStatsByProfile();
    for (const profile of Object.keys(normalizedByProfile)) {
      const current = existingByProfile?.[profile] && typeof existingByProfile[profile] === "object"
        ? existingByProfile[profile]
        : {};
      normalizedByProfile[profile] = {
        evaluated: normalizeCount(current.evaluated),
        allow: normalizeCount(current.allow),
        quarantine: normalizeCount(current.quarantine),
        reject: normalizeCount(current.reject),
        spam_labeled: normalizeCount(current.spam_labeled)
      };
    }
    this.inboundContentFilterStats.decision_counts_by_profile = normalizedByProfile;
  }

  appendInboundContentFilterDecisionTelemetry(payload = {}, context = {}, result = {}) {
    if (!this.inboundContentFilterDecisionLogEnabled || !this.inboundContentFilterDecisionLogFile) {
      return;
    }

    const subject = String(payload?.subject || "");
    const text = String(payload?.text || "");
    const html = String(payload?.html || "");
    const urls = extractContentUrls([subject, text, html].join("\n"));
    const attachments = Array.isArray(payload?.attachments) ? payload.attachments : [];
    const authResults = payload?.auth_results && typeof payload.auth_results === "object" ? payload.auth_results : {};
    const signalCodes = Array.isArray(result?.signals)
      ? result.signals.map((signal) => String(signal?.code || "").trim()).filter(Boolean)
      : [];

    const entry = {
      timestamp: nowIso(),
      source: String(result?.source || context?.source || "unknown").trim() || "unknown",
      profile: String(result?.profile || "").trim() || null,
      action: String(result?.action || "").trim() || "allow",
      score: Number(result?.score || 0),
      spam_score: Number(result?.spam_score || 0),
      phish_score: Number(result?.phish_score || 0),
      malware_score: Number(result?.malware_score || 0),
      labels: Array.isArray(result?.labels) ? result.labels : [],
      signal_codes: signalCodes,
      signal_count: signalCodes.length,
      url_count: urls.length,
      attachment_count: attachments.length,
      subject_length: subject.length,
      text_length: text.length,
      auth_results: {
        spf: String(authResults?.spf || "").trim().toLowerCase() || "none",
        dkim: String(authResults?.dkim || "").trim().toLowerCase() || "none",
        dmarc: String(authResults?.dmarc || "").trim().toLowerCase() || "none"
      },
      actor_hash: hashInboundContentTelemetryValue(context?.actor || "", this.inboundContentFilterDecisionLogSalt),
      node_hash: hashInboundContentTelemetryValue(context?.node_id || "", this.inboundContentFilterDecisionLogSalt),
      subject_hash: hashInboundContentTelemetryValue(subject, this.inboundContentFilterDecisionLogSalt),
      text_hash: hashInboundContentTelemetryValue(text, this.inboundContentFilterDecisionLogSalt)
    };

    try {
      appendFileSync(this.inboundContentFilterDecisionLogFile, `${JSON.stringify(entry)}\n`, "utf-8");
    } catch {}
  }

  getInboundContentFilterStatus() {
    this.ensureInboundContentFilterStatsShape();
    const strictThresholds = this.resolveInboundContentFilterThresholds(
      this.resolveInboundContentFilterProfileConfig("strict")
    );
    const balancedThresholds = this.resolveInboundContentFilterThresholds(
      this.resolveInboundContentFilterProfileConfig("balanced")
    );
    const agentThresholds = this.resolveInboundContentFilterThresholds(
      this.resolveInboundContentFilterProfileConfig("agent")
    );
    return {
      enabled: this.inboundContentFilterEnabled,
      reject_malware: this.inboundContentFilterRejectMalware,
      spam_threshold: this.inboundContentFilterSpamThreshold,
      phish_threshold: this.inboundContentFilterPhishThreshold,
      quarantine_threshold: this.inboundContentFilterQuarantineThreshold,
      reject_threshold: this.inboundContentFilterRejectThreshold,
      profile_default: this.inboundContentFilterProfileDefault,
      profile_bridge_email: this.inboundContentFilterProfileBridge,
      profile_federation: this.inboundContentFilterProfileFederation,
      profile_thresholds: {
        strict: strictThresholds,
        balanced: balancedThresholds,
        agent: agentThresholds
      },
      config_version: Math.max(1, parsePositiveInteger(this.inboundContentFilterConfigVersion, 1)),
      config_updated_at: this.inboundContentFilterConfigUpdatedAt || null,
      canary_staged: Boolean(this.inboundContentFilterConfigCanary?.config),
      rollback_available: Boolean(this.inboundContentFilterConfigRollback?.config),
      decision_log_enabled: this.inboundContentFilterDecisionLogEnabled,
      decision_log_sink_configured: Boolean(this.inboundContentFilterDecisionLogFile),
      decision_counts_by_profile: this.inboundContentFilterStats.decision_counts_by_profile,
      evaluated: Number(this.inboundContentFilterStats?.evaluated || 0),
      rejected: Number(this.inboundContentFilterStats?.rejected || 0),
      quarantined: Number(this.inboundContentFilterStats?.quarantined || 0),
      spam_labeled: Number(this.inboundContentFilterStats?.spam_labeled || 0),
      last_evaluated_at: this.inboundContentFilterStats?.last_evaluated_at || null
    };
  }

  evaluateInboundContentPolicy(payload = {}, context = {}) {
    const source = String(context?.source || "unknown").trim() || "unknown";
    const profile = this.resolveInboundContentFilterProfile({
      ...context,
      source
    });
    const profileConfig = this.resolveInboundContentFilterProfileConfig(profile);
    const profileWeights = profileConfig?.weights && typeof profileConfig.weights === "object" ? profileConfig.weights : {};
    const profileClusters = profileConfig?.clusters && typeof profileConfig.clusters === "object" ? profileConfig.clusters : {};
    const thresholds = this.resolveInboundContentFilterThresholds(profileConfig);
    const result = {
      enabled: this.inboundContentFilterEnabled === true,
      version: "content-filter@v1",
      source,
      profile,
      thresholds,
      action: "allow",
      labels: [],
      detected_categories: [],
      score: 0,
      spam_score: 0,
      phish_score: 0,
      malware_score: 0,
      signals: []
    };

    if (!result.enabled) {
      return result;
    }

    this.ensureInboundContentFilterStatsShape();

    const addSignal = (category, code, weight, detail = null) => {
      const normalizedCategory = String(category || "")
        .trim()
        .toLowerCase();
      const normalizedCode = String(code || "").trim();
      const parsedWeight = Number(weight);
      if (!normalizedCategory || !normalizedCode || !Number.isFinite(parsedWeight) || parsedWeight <= 0) {
        return;
      }
      const normalizedWeight = Math.round(parsedWeight * 100) / 100;
      if (normalizedCategory === "spam") {
        result.spam_score += normalizedWeight;
      } else if (normalizedCategory === "phish") {
        result.phish_score += normalizedWeight;
      } else if (normalizedCategory === "malware") {
        result.malware_score += normalizedWeight;
      }
      result.signals.push({
        category: normalizedCategory,
        code: normalizedCode,
        weight: normalizedWeight,
        ...(detail ? { detail: String(detail).slice(0, 180) } : {})
      });
    };

    const subject = String(payload?.subject || "").trim();
    const text = String(payload?.text || "").trim();
    const html = String(payload?.html || "").trim();
    const extractedHtmlText = html ? this.htmlToText(html) : "";
    const combinedText = [subject, text, extractedHtmlText].filter(Boolean).join("\n");
    const combinedLower = combinedText.toLowerCase();
    const spamKeywordMatches = new Set();
    const phishKeywordMatches = new Set();

    for (const keyword of CONTENT_FILTER_SPAM_KEYWORDS) {
      if (combinedLower.includes(keyword)) {
        spamKeywordMatches.add(keyword);
        addSignal("spam", "keyword.spam", profileWeights.keyword_spam, keyword);
      }
    }
    for (const keyword of CONTENT_FILTER_PHISH_KEYWORDS) {
      if (combinedLower.includes(keyword)) {
        phishKeywordMatches.add(keyword);
        addSignal("phish", "keyword.phish", profileWeights.keyword_phish, keyword);
      }
    }
    const spamKeywordClusterMin = Math.max(1, Number(profileClusters.spam_keyword_min || 0));
    const phishKeywordClusterMin = Math.max(1, Number(profileClusters.phish_keyword_min || 0));
    if (spamKeywordMatches.size >= spamKeywordClusterMin) {
      addSignal(
        "spam",
        "keyword.spam_cluster",
        profileClusters.spam_keyword_weight,
        `count=${spamKeywordMatches.size}`
      );
    }
    if (phishKeywordMatches.size >= phishKeywordClusterMin) {
      addSignal(
        "phish",
        "keyword.phish_cluster",
        profileClusters.phish_keyword_weight,
        `count=${phishKeywordMatches.size}`
      );
    }

    const subjectLetters = subject.replace(/[^A-Za-z]/g, "");
    if (subjectLetters.length >= 10) {
      const upper = subjectLetters.replace(/[^A-Z]/g, "").length;
      if (upper / subjectLetters.length >= 0.8) {
        addSignal("spam", "subject.all_caps", profileWeights.subject_all_caps, subject.slice(0, 80));
      }
    }

    const urls = extractContentUrls([subject, text, html].join("\n"));
    if (urls.length >= 6) {
      addSignal("spam", "url.volume_high", profileWeights.url_volume, `count=${urls.length}`);
    }
    for (const url of urls) {
      const host = normalizeUrlHost(url);
      if (!host) {
        continue;
      }
      if (CONTENT_FILTER_SHORTENER_HOSTS.has(host)) {
        addSignal("phish", "url.shortener", profileWeights.url_shortener, host);
      }
      if (host.startsWith("xn--") || host.includes(".xn--")) {
        addSignal("phish", "url.punycode", profileWeights.url_punycode, host);
      }
      if (isIpv4Host(host)) {
        addSignal("phish", "url.ip_literal", profileWeights.url_ip_literal, host);
      }
    }

    const attachments = Array.isArray(payload?.attachments) ? payload.attachments : [];
    for (const attachment of attachments.slice(0, 24)) {
      const filename = String(attachment?.filename || attachment?.name || "").trim();
      const extension = normalizeAttachmentExtension(filename);
      const mimeType = String(attachment?.mime_type || attachment?.mimeType || attachment?.contentType || "")
        .trim()
        .toLowerCase();
      if (extension && CONTENT_FILTER_MALWARE_EXTENSIONS.has(extension)) {
        addSignal("malware", "attachment.risky_extension", 5, filename || extension);
      }
      if (extension && CONTENT_FILTER_ARCHIVE_EXTENSIONS.has(extension)) {
        const suspiciousArchiveContext =
          combinedLower.includes("invoice") ||
          combinedLower.includes("payment") ||
          combinedLower.includes("statement");
        if (suspiciousArchiveContext) {
          addSignal("phish", "attachment.archive_lure", profileWeights.attachment_archive_lure, filename || extension);
        }
      }
      const dotSegments = filename
        .toLowerCase()
        .split(".")
        .map((entry) => entry.trim())
        .filter(Boolean);
      if (dotSegments.length >= 3 && CONTENT_FILTER_MALWARE_EXTENSIONS.has(dotSegments[dotSegments.length - 1])) {
        addSignal("malware", "attachment.double_extension", 4, filename);
      }
      if (mimeType && CONTENT_FILTER_MALWARE_MIME_SNIPPETS.some((snippet) => mimeType.includes(snippet))) {
        addSignal("malware", "attachment.risky_mime", 4, mimeType);
      }
    }

    const authResults = payload?.auth_results && typeof payload.auth_results === "object" ? payload.auth_results : null;
    if (authResults) {
      const dmarc = String(authResults.dmarc || "").trim().toLowerCase();
      const dkim = String(authResults.dkim || "").trim().toLowerCase();
      const spf = String(authResults.spf || "").trim().toLowerCase();
      const hardFailureStatuses = new Set(["fail", "softfail", "temperror", "permerror", "policy"]);
      if (hardFailureStatuses.has(dmarc)) {
        addSignal("phish", "auth.dmarc_not_pass", profileWeights.auth_dmarc_not_pass, dmarc);
      }
      if (hardFailureStatuses.has(dkim)) {
        addSignal("phish", "auth.dkim_not_pass", profileWeights.auth_dkim_not_pass, dkim);
      }
      if (hardFailureStatuses.has(spf)) {
        addSignal("phish", "auth.spf_not_pass", profileWeights.auth_spf_not_pass, spf);
      }
    }

    result.score = result.spam_score + result.phish_score + result.malware_score;
    if (result.spam_score >= thresholds.spam) {
      result.labels.push("sys.spam");
    }

    if (this.inboundContentFilterRejectMalware && result.malware_score > 0) {
      result.action = "reject";
    } else if (
      result.score >= thresholds.reject ||
      result.phish_score >= thresholds.phish + 2
    ) {
      result.action = "reject";
    } else if (
      result.malware_score > 0 ||
      result.phish_score >= thresholds.phish ||
      result.score >= thresholds.quarantine
    ) {
      result.action = "quarantine";
    }

    if (result.action === "quarantine" && !result.labels.includes("sys.quarantine")) {
      result.labels.push("sys.quarantine");
    }

    result.detected_categories = Array.from(
      new Set(result.signals.map((signal) => signal.category).filter(Boolean))
    );

    this.inboundContentFilterStats.evaluated += 1;
    this.inboundContentFilterStats.last_evaluated_at = nowIso();
    if (result.action === "reject") {
      this.inboundContentFilterStats.rejected += 1;
    }
    if (result.action === "quarantine") {
      this.inboundContentFilterStats.quarantined += 1;
    }
    if (result.labels.includes("sys.spam")) {
      this.inboundContentFilterStats.spam_labeled += 1;
    }
    const profileDecisionStats =
      this.inboundContentFilterStats.decision_counts_by_profile?.[result.profile] ||
      createInboundContentFilterProfileDecisionStats();
    profileDecisionStats.evaluated += 1;
    if (INBOUND_CONTENT_FILTER_DECISION_ACTIONS.includes(result.action)) {
      profileDecisionStats[result.action] += 1;
    }
    if (result.labels.includes("sys.spam")) {
      profileDecisionStats.spam_labeled += 1;
    }
    this.inboundContentFilterStats.decision_counts_by_profile[result.profile] = profileDecisionStats;
    this.appendInboundContentFilterDecisionTelemetry(payload, context, result);

    if (result.action !== "allow" || result.labels.includes("sys.spam")) {
      this.persistAndAudit("content.filter.flagged", {
        source,
        action: result.action,
        score: result.score,
        spam_score: result.spam_score,
        phish_score: result.phish_score,
        malware_score: result.malware_score,
        profile: result.profile,
        thresholds: result.thresholds,
        labels: result.labels,
        signal_count: result.signals.length,
        actor: context?.actor || null,
        node_id: context?.node_id || null
      });
    }

    return result;
  }

  normalizeBridgeAuthStatus(value, fallback = "none") {
    const normalized = String(value || "")
      .trim()
      .toLowerCase();
    if (!normalized) {
      return fallback;
    }

    if (
      normalized === "pass" ||
      normalized === "fail" ||
      normalized === "softfail" ||
      normalized === "neutral" ||
      normalized === "temperror" ||
      normalized === "permerror" ||
      normalized === "policy" ||
      normalized === "none"
    ) {
      return normalized;
    }

    return fallback;
  }

  parseAuthenticationResultsHeader(value) {
    const text = String(value || "");
    if (!text.trim()) {
      return null;
    }

    const extract = (name) => {
      const match = text.match(new RegExp(`(?:^|[;\\s])${name}\\s*=\\s*([a-zA-Z_-]+)`, "i"));
      return match?.[1] ? this.normalizeBridgeAuthStatus(match[1], "none") : "none";
    };

    return {
      spf: extract("spf"),
      dkim: extract("dkim"),
      dmarc: extract("dmarc"),
      source: "authentication-results-header"
    };
  }

  resolveBridgeInboundAuthResults(payload, headers, options = {}) {
    const allowPayloadAuthResults = options.allowPayloadAuthResults !== false;
    const fromPayload = payload?.auth_results;
    if (allowPayloadAuthResults && fromPayload && typeof fromPayload === "object") {
      return {
        spf: this.normalizeBridgeAuthStatus(fromPayload.spf, "none"),
        dkim: this.normalizeBridgeAuthStatus(fromPayload.dkim, "none"),
        dmarc: this.normalizeBridgeAuthStatus(fromPayload.dmarc, "none"),
        source: "payload"
      };
    }

    const headerValue =
      payload?.authentication_results ||
      this.resolveHeaderValue(headers, "authentication-results") ||
      this.resolveHeaderValue(headers, "x-authentication-results");
    const parsedHeader = this.parseAuthenticationResultsHeader(headerValue);
    if (parsedHeader) {
      return parsedHeader;
    }

    return {
      spf: "none",
      dkim: "none",
      dmarc: "none",
      source: "none"
    };
  }

  evaluateBridgeInboundAuthPolicy(authResults, options = {}) {
    const requireAuthResults = options.requireAuthResults === true;
    const requireDmarcPass = options.requireDmarcPass === true;
    const rejectOnAuthFailure = options.rejectOnAuthFailure === true;
    const quarantineOnAuthFailure = options.quarantineOnAuthFailure !== false;

    const spf = this.normalizeBridgeAuthStatus(authResults?.spf, "none");
    const dkim = this.normalizeBridgeAuthStatus(authResults?.dkim, "none");
    const dmarc = this.normalizeBridgeAuthStatus(authResults?.dmarc, "none");
    const source = String(authResults?.source || "none").trim() || "none";
    const missingAuthResults =
      source === "none" || (spf === "none" && dkim === "none" && dmarc === "none");
    const hasPass = spf === "pass" || dkim === "pass" || dmarc === "pass";
    const failureStatus = new Set(["fail", "softfail", "temperror", "permerror", "policy"]);
    const authSignalProvided = !missingAuthResults;
    const authFailed = failureStatus.has(dmarc) || (authSignalProvided && !hasPass);
    const dmarcRequiredFailed = requireDmarcPass && dmarc !== "pass";
    const reject = rejectOnAuthFailure && (authFailed || dmarcRequiredFailed || (requireAuthResults && missingAuthResults));
    const quarantine =
      quarantineOnAuthFailure && (authFailed || dmarcRequiredFailed || (requireAuthResults && missingAuthResults));
    const reason = reject || quarantine
      ? requireAuthResults && missingAuthResults
        ? "missing_auth_results"
        : dmarcRequiredFailed
          ? "dmarc_required_failed"
          : !hasPass
            ? "email_auth_unverified"
            : "email_auth_failed"
      : null;

    return {
      normalized: {
        spf,
        dkim,
        dmarc,
        source
      },
      missingAuthResults,
      reject,
      quarantine,
      reason
    };
  }

  createBridgeInboundEnvelope(payload, actorIdentity, options = {}) {
    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Email inbound payload must be an object", 400, {
        field: "payload"
      });
    }

    const fromEmail = this.normalizeEmailAddress(payload.smtp_from || payload.from);
    if (!fromEmail) {
      throw new LoomError("ENVELOPE_INVALID", "Inbound email requires smtp_from", 400, {
        field: "smtp_from"
      });
    }

    const hasRcptTo = payload?.rcpt_to != null;
    const primaryIdentities = this.resolveIdentitiesFromAddressInput(hasRcptTo ? payload.rcpt_to : payload.to);
    const ccIdentities = this.resolveIdentitiesFromAddressInput(payload.cc);
    const bccIdentities = this.resolveIdentitiesFromAddressInput(payload.bcc);
    const to = this.buildRecipientList({
      primary: primaryIdentities,
      cc: ccIdentities,
      bcc: bccIdentities
    });

    if (to.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "Inbound email requires recipients", 400, {
        field: "rcpt_to"
      });
    }

    const inboundHeaderAllowlist = normalizeBridgeInboundHeaderAllowlist(
      options.headerAllowlist == null ? this.bridgeInboundHeaderAllowlist : options.headerAllowlist
    );
    const rawHeaders = payload?.headers && typeof payload.headers === "object" ? payload.headers : {};
    const headers = sanitizeBridgeInboundHeaders(rawHeaders, inboundHeaderAllowlist);
    const threading = this.resolveThreadFromEmailHeaders(payload, {
      headers
    });
    const dateHeader = this.resolveHeaderValue(headers, "date");
    const createdAtInput = payload.date || dateHeader;
    const createdAt = parseTime(createdAtInput) != null ? new Date(parseTime(createdAtInput)).toISOString() : nowIso();
    const envelopeId = `env_${generateUlid()}`;
    const incomingMessageId = this.parseMessageId(payload.message_id || this.resolveHeaderValue(headers, "message-id"));
    const canonicalMessageId = incomingMessageId || `${envelopeId}@${this.nodeId}`;
    const inboundAuthPolicy = {
      requireAuthResults:
        options.requireAuthResults === true ||
        (options.requireAuthResults == null && this.bridgeInboundRequireAuthResults),
      requireDmarcPass:
        options.requireDmarcPass === true ||
        (options.requireDmarcPass == null && this.bridgeInboundRequireDmarcPass),
      rejectOnAuthFailure:
        options.rejectOnAuthFailure === true ||
        (options.rejectOnAuthFailure == null && this.bridgeInboundRejectOnAuthFailure),
      quarantineOnAuthFailure:
        options.quarantineOnAuthFailure == null
          ? this.bridgeInboundQuarantineOnAuthFailure
          : options.quarantineOnAuthFailure !== false,
      allowPayloadAuthResults:
        options.allowPayloadAuthResults == null
          ? this.bridgeInboundAllowPayloadAuthResults
          : options.allowPayloadAuthResults !== false
    };
    const authResults = this.resolveBridgeInboundAuthResults(payload, headers, {
      allowPayloadAuthResults: inboundAuthPolicy.allowPayloadAuthResults
    });
    const authEvaluation = this.evaluateBridgeInboundAuthPolicy(authResults, inboundAuthPolicy);
    if (authEvaluation.reject) {
      throw new LoomError("CAPABILITY_DENIED", "Inbound email authentication policy rejected message", 403, {
        field: "auth_results",
        reason: authEvaluation.reason,
        auth_results: authEvaluation.normalized
      });
    }

    const humanText =
      typeof payload.text === "string" && payload.text.trim().length > 0
        ? payload.text
        : this.htmlToText(payload.html || "");
    const contentEvaluation = this.evaluateInboundContentPolicy(
      {
        subject: payload.subject || this.resolveHeaderValue(headers, "subject") || "",
        text: humanText,
        html: payload.html || "",
        attachments: Array.isArray(payload.attachments) ? payload.attachments : [],
        auth_results: authEvaluation.normalized
      },
      {
        source: "bridge_email",
        actor: actorIdentity
      }
    );
    if (contentEvaluation.action === "reject") {
      throw new LoomError("CAPABILITY_DENIED", "Inbound email content policy rejected message", 403, {
        field: "content",
        content_filter: {
          action: contentEvaluation.action,
          score: contentEvaluation.score,
          categories: contentEvaluation.detected_categories
        }
      });
    }

    const unsignedEnvelope = {
      loom: "1.1",
      id: envelopeId,
      thread_id: threading.thread_id,
      parent_id: threading.parent_id,
      type: "message",
      from: {
        identity: `bridge://${fromEmail}`,
        display: payload.display_from || fromEmail,
        key_id: this.systemSigningKeyId,
        type: "bridge"
      },
      to,
      audience: {
        mode: to.some((recipient) => recipient.role === "bcc") ? "recipients" : "thread"
      },
      created_at: createdAt,
      priority: payload.priority || "normal",
      content: {
        human: {
          text: humanText || "(no body)",
          format: "plaintext"
        },
        structured: {
          intent: "message.general@v1",
          parameters: {
            source: "email",
            extracted: true,
            extraction_confidence:
              typeof payload.extraction_confidence === "number" ? payload.extraction_confidence : 0.25
          }
        },
        encrypted: false
      },
      attachments: Array.isArray(payload.attachments) ? payload.attachments : [],
      references: {
        in_reply_to: threading.parent_id,
        linked_envelopes: [],
        linked_threads: [],
        external: [
          {
            type: "email_message_id",
            ref: canonicalMessageId
          }
        ]
      },
      meta: {
        bridge: {
          source: "email",
          original_message_id: canonicalMessageId,
          original_headers: headers,
          auth_results: authEvaluation.normalized,
          auth_policy: {
            require_auth_results: inboundAuthPolicy.requireAuthResults,
            require_dmarc_pass: inboundAuthPolicy.requireDmarcPass,
            reject_on_auth_failure: inboundAuthPolicy.rejectOnAuthFailure,
            quarantine_on_auth_failure: inboundAuthPolicy.quarantineOnAuthFailure,
            allow_payload_auth_results: inboundAuthPolicy.allowPayloadAuthResults,
            reason: authEvaluation.reason
          },
          extraction_confidence:
            typeof payload.extraction_confidence === "number" ? payload.extraction_confidence : 0.25
        },
        security: {
          content_filter: {
            version: contentEvaluation.version,
            source: contentEvaluation.source,
            action: contentEvaluation.action,
            labels: contentEvaluation.labels,
            score: contentEvaluation.score,
            spam_score: contentEvaluation.spam_score,
            phish_score: contentEvaluation.phish_score,
            malware_score: contentEvaluation.malware_score,
            detected_categories: contentEvaluation.detected_categories,
            signal_codes: contentEvaluation.signals.map((signal) => signal.code),
            evaluated_at: nowIso()
          }
        }
      }
    };

    const signedEnvelope = signEnvelope(
      unsignedEnvelope,
      this.systemSigningPrivateKeyPem,
      this.systemSigningKeyId
    );

    const stored = this.ingestEnvelope(signedEnvelope, {
      actorIdentity: signedEnvelope.from.identity
    });

    this.recordEmailMessageIndex(canonicalMessageId, stored.id, stored.thread_id);
    this.recordEmailMessageIndex(`${stored.id}@${this.nodeId}`, stored.id, stored.thread_id);

    const shouldQuarantine =
      payload.quarantine === true || authEvaluation.quarantine || contentEvaluation.action === "quarantine";
    let quarantined = false;
    const spamLabeled =
      contentEvaluation.labels.includes("sys.spam") && this.ensureThreadLabel(stored.thread_id, "sys.spam");
    if (shouldQuarantine) {
      quarantined = this.ensureThreadLabel(stored.thread_id, "sys.quarantine");
    } else if (!spamLabeled) {
      this.ensureThreadLabel(stored.thread_id, "sys.inbox");
    }

    this.persistAndAudit("bridge.email.inbound", {
      envelope_id: stored.id,
      thread_id: stored.thread_id,
      message_id: canonicalMessageId,
      actor: actorIdentity,
      auth_results: authEvaluation.normalized,
      content_filter_action: contentEvaluation.action,
      content_filter_score: contentEvaluation.score,
      content_filter_categories: contentEvaluation.detected_categories,
      spam_labeled: spamLabeled,
      quarantined,
      quarantine_reason: authEvaluation.reason
    });

    return {
      envelope_id: stored.id,
      thread_id: stored.thread_id,
      message_id: canonicalMessageId,
      quarantined,
      spam_labeled: spamLabeled
    };
  }

  buildBridgeOutboundMimeAttachments(envelope, actorIdentity) {
    const sourceAttachments = Array.isArray(envelope?.attachments) ? envelope.attachments : [];
    const renderedAttachments = [];

    for (let index = 0; index < sourceAttachments.length; index += 1) {
      const attachment = sourceAttachments[index];
      if (!attachment || typeof attachment !== "object") {
        throw new LoomError("ENVELOPE_INVALID", "Attachment must be an object", 400, {
          field: `attachments[${index}]`
        });
      }

      const blobId = String(attachment.blob_id || "").trim();
      if (!blobId) {
        throw new LoomError("ENVELOPE_INVALID", "Attachment blob_id is required", 400, {
          field: `attachments[${index}].blob_id`
        });
      }

      const blob = this.getBlob(blobId, actorIdentity);
      if (!blob) {
        throw new LoomError("ENVELOPE_NOT_FOUND", `Attachment blob not found: ${blobId}`, 404, {
          field: `attachments[${index}].blob_id`,
          blob_id: blobId
        });
      }

      if (blob.status !== "complete" || typeof blob.data_base64 !== "string") {
        throw new LoomError("ENVELOPE_INVALID", "Attachment blob must be complete before outbound rendering", 400, {
          field: `attachments[${index}].blob_id`,
          blob_id: blobId
        });
      }

      const expectedHash = String(attachment.hash || "").trim();
      if (expectedHash && blob.hash && expectedHash !== blob.hash) {
        throw new LoomError("ENVELOPE_INVALID", "Attachment blob hash mismatch", 400, {
          field: `attachments[${index}].hash`,
          blob_id: blobId,
          expected_hash: expectedHash,
          actual_hash: blob.hash
        });
      }

      const filename = String(attachment.filename || blob.filename || `${blob.id}.bin`).trim();
      if (!filename || containsHeaderUnsafeChars(filename)) {
        throw new LoomError("ENVELOPE_INVALID", "Attachment filename is invalid", 400, {
          field: `attachments[${index}].filename`
        });
      }

      const mimeType = String(attachment.mime_type || blob.mime_type || "application/octet-stream").trim();
      if (!mimeType || containsHeaderUnsafeChars(mimeType)) {
        throw new LoomError("ENVELOPE_INVALID", "Attachment mime_type is invalid", 400, {
          field: `attachments[${index}].mime_type`
        });
      }

      const dispositionRaw = String(attachment.disposition || "attachment")
        .trim()
        .toLowerCase();
      const disposition = dispositionRaw === "inline" ? "inline" : "attachment";
      const contentId = attachment.content_id ? String(attachment.content_id).trim() : null;
      if (contentId && containsHeaderUnsafeChars(contentId)) {
        throw new LoomError("ENVELOPE_INVALID", "Attachment content_id is invalid", 400, {
          field: `attachments[${index}].content_id`
        });
      }

      renderedAttachments.push({
        id: String(attachment.id || "").trim() || null,
        blob_id: blob.id,
        hash: blob.hash || expectedHash || null,
        filename,
        mime_type: mimeType,
        disposition,
        content_id: contentId || null,
        size_bytes: Number(blob.size_bytes || 0),
        data_base64: blob.data_base64
      });
    }

    return renderedAttachments;
  }

  renderBridgeOutboundEmail(payload, actorIdentity) {
    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Outbound email payload must be an object", 400, {
        field: "payload"
      });
    }

    const envelopeId = String(payload.envelope_id || "").trim();
    const envelope = this.envelopesById.get(envelopeId);
    if (!envelope) {
      throw new LoomError("ENVELOPE_NOT_FOUND", `Envelope not found: ${envelopeId}`, 404, {
        envelope_id: envelopeId
      });
    }

    const thread = this.threadsById.get(envelope.thread_id);
    const canRender =
      envelope.from?.identity === actorIdentity || (thread ? this.isActiveParticipant(thread, actorIdentity) : false);
    if (!canRender) {
      throw new LoomError("CAPABILITY_DENIED", "Not authorized to render outbound email for this envelope", 403, {
        envelope_id: envelopeId,
        actor: actorIdentity
      });
    }

    const toEmailsRaw = Array.isArray(payload.to_email)
      ? payload.to_email
      : typeof payload.to_email === "string"
        ? this.splitAddressList(payload.to_email)
        : envelope.to.map((recipient) => this.inferEmailFromIdentity(recipient.identity)).filter(Boolean);

    const toEmails = toEmailsRaw.map((value) => this.normalizeEmailAddress(String(value || ""))).filter(Boolean);
    if (toEmails.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "No outbound email recipients resolved", 400, {
        field: "to_email"
      });
    }

    const subject =
      payload.subject ||
      thread?.subject ||
      envelope.content?.structured?.intent ||
      `LOOM ${envelope.type}`;
    if (containsHeaderUnsafeChars(subject)) {
      throw new LoomError("ENVELOPE_INVALID", "subject contains invalid header characters", 400, {
        field: "subject"
      });
    }

    const smtpFrom = payload.smtp_from ? this.normalizeEmailAddress(payload.smtp_from) : this.normalizeEmailAddress(`no-reply@${this.nodeId}`);
    if (!smtpFrom) {
      throw new LoomError("ENVELOPE_INVALID", "smtp_from must be a valid email address", 400, {
        field: "smtp_from"
      });
    }

    const textBody =
      envelope.content?.encrypted
        ? "[Encrypted LOOM content]"
        : envelope.content?.human?.text || JSON.stringify(envelope.content?.structured || {}, null, 2);

    const escapedTextBody = String(textBody)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
    const htmlBody = `<pre>${escapedTextBody}</pre>`;

    const messageId = `${envelope.id}@${this.nodeId}`;
    const inReplyTo = envelope.parent_id ? `${envelope.parent_id}@${this.nodeId}` : null;
    const references = Array.from(
      new Set(
        (envelope.references?.external || [])
          .filter((entry) => entry?.type === "email_message_id" && entry?.ref)
          .map((entry) => String(entry.ref).trim())
          .filter(Boolean)
      )
    )
      .map((ref) => (ref.startsWith("<") ? ref : `<${ref}>`))
      .join(" ");
    const renderedAttachments = this.buildBridgeOutboundMimeAttachments(envelope, actorIdentity);

    this.recordEmailMessageIndex(messageId, envelope.id, envelope.thread_id);
    this.persistAndAudit("bridge.email.outbound.render", {
      envelope_id: envelope.id,
      thread_id: envelope.thread_id,
      actor: actorIdentity
    });

    return {
      smtp_from: smtpFrom,
      rcpt_to: toEmails,
      subject,
      text: textBody,
      html: htmlBody,
      headers: {
        "Message-ID": `<${messageId}>`,
        ...(inReplyTo ? { "In-Reply-To": `<${inReplyTo}>` } : {}),
        ...(references ? { References: references } : {}),
        "X-LOOM-Intent": envelope.content?.structured?.intent || "message.general@v1",
        "X-LOOM-Thread-ID": envelope.thread_id,
        "X-LOOM-Envelope-ID": envelope.id
      },
      attachments: renderedAttachments
    };
  }

  ensureMailboxState(thread, identityUri) {
    if (!thread.mailbox_state || typeof thread.mailbox_state !== "object") {
      thread.mailbox_state = {};
    }

    const key = String(identityUri || "").trim();
    if (!key) {
      return {
        seen: false,
        flagged: false,
        archived: false,
        deleted: false,
        updated_at: null,
        last_read_at: null
      };
    }

    if (!thread.mailbox_state[key] || typeof thread.mailbox_state[key] !== "object") {
      thread.mailbox_state[key] = {
        seen: false,
        flagged: false,
        archived: false,
        deleted: false,
        updated_at: nowIso(),
        last_read_at: null
      };
    }

    const state = thread.mailbox_state[key];
    state.seen = Boolean(state.seen);
    state.flagged = Boolean(state.flagged);
    state.archived = Boolean(state.archived);
    state.deleted = Boolean(state.deleted);
    state.updated_at = state.updated_at || nowIso();
    state.last_read_at = state.last_read_at || null;
    return state;
  }

  getThreadMailboxState(threadId, actorIdentity) {
    const thread = this.threadsById.get(threadId);
    if (!thread) {
      throw new LoomError("THREAD_NOT_FOUND", `Thread not found: ${threadId}`, 404, {
        thread_id: threadId
      });
    }

    if (!this.isActiveParticipant(thread, actorIdentity)) {
      throw new LoomError("CAPABILITY_DENIED", "Only thread participants can access mailbox state", 403, {
        thread_id: threadId,
        actor: actorIdentity
      });
    }

    const state = this.ensureMailboxState(thread, actorIdentity);
    return {
      thread_id: threadId,
      identity: actorIdentity,
      ...state
    };
  }

  updateThreadMailboxState(threadId, actorIdentity, payload = {}) {
    const thread = this.threadsById.get(threadId);
    if (!thread) {
      throw new LoomError("THREAD_NOT_FOUND", `Thread not found: ${threadId}`, 404, {
        thread_id: threadId
      });
    }

    if (!this.isActiveParticipant(thread, actorIdentity)) {
      throw new LoomError("CAPABILITY_DENIED", "Only thread participants can update mailbox state", 403, {
        thread_id: threadId,
        actor: actorIdentity
      });
    }

    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Mailbox state payload must be an object", 400, {
        field: "mailbox_state"
      });
    }

    const state = this.ensureMailboxState(thread, actorIdentity);
    const patchableFields = ["seen", "flagged", "archived", "deleted"];
    let changed = false;

    for (const field of patchableFields) {
      if (payload[field] == null) {
        continue;
      }

      if (typeof payload[field] !== "boolean") {
        throw new LoomError("ENVELOPE_INVALID", `Mailbox state field ${field} must be boolean`, 400, {
          field
        });
      }

      if (state[field] !== payload[field]) {
        state[field] = payload[field];
        changed = true;
      }
    }

    if (state.deleted) {
      state.archived = false;
    } else if (state.archived) {
      state.deleted = false;
    }

    if (state.seen) {
      state.last_read_at = state.last_read_at || nowIso();
    } else if (payload.seen === false) {
      state.last_read_at = null;
    }

    if (changed) {
      state.updated_at = nowIso();
      thread.updated_at = nowIso();
      this.persistAndAudit("mailbox.state.update", {
        thread_id: threadId,
        identity: actorIdentity,
        state: {
          seen: state.seen,
          flagged: state.flagged,
          archived: state.archived,
          deleted: state.deleted
        }
      });
    }

    return {
      thread_id: threadId,
      identity: actorIdentity,
      ...state
    };
  }

  classifyThreadFolder(thread, actorIdentity = null) {
    const labels = new Set(thread.labels || []);
    const mailboxState = actorIdentity ? this.ensureMailboxState(thread, actorIdentity) : null;

    if (mailboxState?.deleted) {
      return "Trash";
    }
    if (mailboxState?.archived) {
      return "Archive";
    }

    if (labels.has("sys.trash")) {
      return "Trash";
    }
    if (labels.has("sys.spam")) {
      return "Spam";
    }
    if (labels.has("sys.quarantine")) {
      return "Quarantine";
    }
    if (labels.has("sys.archive")) {
      return "Archive";
    }
    if (labels.has("sys.sent")) {
      return "Sent";
    }

    return "INBOX";
  }

  normalizeGatewayFolderName(folderName) {
    const normalized = String(folderName || "").trim();
    if (!normalized) {
      return "INBOX";
    }

    const lookup = normalized.toLowerCase();
    if (lookup === "inbox") {
      return "INBOX";
    }
    if (lookup === "sent" || lookup === "sent items") {
      return "Sent";
    }
    if (lookup === "archive" || lookup === "all mail") {
      return "Archive";
    }
    if (lookup === "spam" || lookup === "junk" || lookup === "junk email") {
      return "Spam";
    }
    if (lookup === "trash" || lookup === "deleted" || lookup === "deleted items") {
      return "Trash";
    }
    if (lookup === "quarantine") {
      return "Quarantine";
    }
    if (lookup === "drafts" || lookup === "draft") {
      return "Drafts";
    }

    return normalized;
  }

  listGatewayImapFolders(actorIdentity) {
    const folderNames = ["INBOX", "Sent", "Archive", "Spam", "Trash", "Quarantine", "Drafts"];
    const counts = new Map(folderNames.map((name) => [name, 0]));

    for (const thread of this.threadsById.values()) {
      if (!this.isActiveParticipant(thread, actorIdentity)) {
        continue;
      }
      const folder = this.classifyThreadFolder(thread, actorIdentity);
      counts.set(folder, (counts.get(folder) || 0) + 1);
    }

    return folderNames.map((name) => ({
      name,
      count: counts.get(name) || 0
    }));
  }

  getVisibleEnvelopeRecipients(envelope, viewerIdentity) {
    const recipients = Array.isArray(envelope?.to) ? envelope.to : [];
    if (recipients.length === 0) {
      return [];
    }

    const viewerIsSender = envelope?.from?.identity === viewerIdentity;
    return recipients.filter((recipient) => {
      if (recipient.role !== "bcc") {
        return true;
      }
      return viewerIsSender || recipient.identity === viewerIdentity;
    });
  }

  hasBccRecipients(envelope) {
    return Array.isArray(envelope?.to) && envelope.to.some((recipient) => recipient?.role === "bcc");
  }

  requiresRecipientDeliveryWrapper(envelope) {
    if (!envelope || typeof envelope !== "object") {
      return false;
    }
    return envelope?.audience?.mode === "recipients" || this.hasBccRecipients(envelope);
  }

  envelopeContainsCapabilitySecret(envelope) {
    const parameters = envelope?.content?.structured?.parameters;
    const capabilityToken = parameters?.capability_token;
    return Boolean(
      parameters &&
      typeof parameters === "object" &&
      ((typeof capabilityToken === "string" && capabilityToken.trim().length > 0) ||
        (capabilityToken && typeof capabilityToken === "object" && !Array.isArray(capabilityToken)))
    );
  }

  getDeliveryWrapper(envelopeId, recipientIdentity) {
    const key = deliveryWrapperKey(envelopeId, recipientIdentity);
    return this.deliveryWrappersByEnvelopeAndIdentity.get(key) || null;
  }

  issueDeliveryWrapperForRecipient(envelope, recipientIdentity) {
    if (!this.requiresRecipientDeliveryWrapper(envelope)) {
      return null;
    }

    const normalizedRecipientIdentity = String(recipientIdentity || "").trim();
    if (!normalizedRecipientIdentity) {
      return null;
    }

    const coreEnvelopeHash = createHash("sha256")
      .update(canonicalizeEnvelope(envelope), "utf-8")
      .digest("hex");
    const visibleRecipients = this.getVisibleEnvelopeRecipients(envelope, normalizedRecipientIdentity).map((recipient) => ({
      identity: recipient.identity,
      role: recipient.role
    }));
    const existing = this.getDeliveryWrapper(envelope.id, normalizedRecipientIdentity);

    if (
      existing &&
      existing.core_envelope_hash === coreEnvelopeHash &&
      JSON.stringify(existing.visible_recipients || []) === JSON.stringify(visibleRecipients)
    ) {
      return existing;
    }

    const unsignedWrapper = {
      loom: "1.1",
      type: "delivery.wrapper@v1",
      id: existing?.id || `dwr_${generateUlid()}`,
      envelope_id: envelope.id,
      thread_id: envelope.thread_id,
      recipient_identity: normalizedRecipientIdentity,
      visible_recipients: visibleRecipients,
      audience_mode: envelope?.audience?.mode || "thread",
      core_envelope_hash: coreEnvelopeHash,
      issued_by_node: this.nodeId,
      created_at: existing?.created_at || nowIso(),
      updated_at: nowIso()
    };

    const signedWrapper = {
      ...unsignedWrapper,
      signature: {
        algorithm: "Ed25519",
        key_id: this.systemSigningKeyId,
        value: signUtf8Message(this.systemSigningPrivateKeyPem, canonicalizeDeliveryWrapper(unsignedWrapper))
      }
    };

    this.deliveryWrappersByEnvelopeAndIdentity.set(
      deliveryWrapperKey(envelope.id, normalizedRecipientIdentity),
      signedWrapper
    );
    return signedWrapper;
  }

  ensureDeliveryWrappersForEnvelope(envelope) {
    if (!this.requiresRecipientDeliveryWrapper(envelope)) {
      return [];
    }

    const recipientIdentities = Array.from(
      new Set((envelope.to || []).map((recipient) => String(recipient?.identity || "").trim()).filter(Boolean))
    );

    const wrappers = [];
    for (const identity of recipientIdentities) {
      const wrapper = this.issueDeliveryWrapperForRecipient(envelope, identity);
      if (wrapper) {
        wrappers.push(wrapper);
      }
    }
    return wrappers;
  }

  buildEnvelopeRecipientView(envelope, actorIdentity, options = {}) {
    const thread = this.threadsById.get(envelope.thread_id);
    const normalizedActor = String(actorIdentity || "").trim();
    const allowThreadReadCapability = options.allowThreadReadCapability === true;
    const actorIsSender = envelope.from?.identity === normalizedActor;
    const actorIsRecipient = (envelope.to || []).some((recipient) => recipient.identity === normalizedActor);
    const actorIsParticipant = thread ? this.isActiveParticipant(thread, normalizedActor) : false;

    if (!actorIsSender && !actorIsRecipient && !actorIsParticipant && !allowThreadReadCapability) {
      throw new LoomError("CAPABILITY_DENIED", "Not authorized to view envelope", 403, {
        envelope_id: envelope.id,
        actor: normalizedActor
      });
    }

    let visibleEnvelope = envelope;
    if (!actorIsSender && envelope?.type === "thread_op" && envelope?.content?.structured?.parameters) {
      const parameters = envelope.content.structured.parameters;
      const capabilityToken = parameters.capability_token;
      if (
        (typeof capabilityToken === "string" && capabilityToken.trim()) ||
        (capabilityToken && typeof capabilityToken === "object" && !Array.isArray(capabilityToken))
      ) {
        const redactedParameters = { ...parameters };
        delete redactedParameters.capability_token;
        redactedParameters.capability_token_redacted = true;

        visibleEnvelope = {
          ...envelope,
          content: {
            ...envelope.content,
            structured: {
              ...envelope.content.structured,
              parameters: redactedParameters
            }
          }
        };
      }
    }

    if (!this.requiresRecipientDeliveryWrapper(envelope)) {
      return {
        envelope: visibleEnvelope,
        delivery_wrapper: null
      };
    }

    if (actorIsSender) {
      return {
        envelope: visibleEnvelope,
        delivery_wrapper: null
      };
    }

    const wrapper = actorIsRecipient ? this.issueDeliveryWrapperForRecipient(envelope, normalizedActor) : null;
    const visibleRecipients = wrapper
      ? wrapper.visible_recipients
      : this.getVisibleEnvelopeRecipients(envelope, normalizedActor).map((recipient) => ({
          identity: recipient.identity,
          role: recipient.role
        }));
    const coreEnvelopeHash = createHash("sha256")
      .update(canonicalizeEnvelope(envelope), "utf-8")
      .digest("hex");

    return {
      envelope: {
        ...visibleEnvelope,
        to: visibleRecipients,
        meta: {
          ...(visibleEnvelope.meta || {}),
          delivery: {
            wrapper_id: wrapper?.id || null,
            recipient_identity: normalizedActor,
            audience_mode: envelope?.audience?.mode || "thread",
            bcc_redacted: true,
            core_envelope_hash: coreEnvelopeHash
          }
        }
      },
      delivery_wrapper: wrapper || null
    };
  }

  getEnvelopeForIdentity(envelopeId, actorIdentity, options = {}) {
    const envelope = this.envelopesById.get(envelopeId);
    if (!envelope) {
      return null;
    }
    const thread = this.threadsById.get(envelope.thread_id);
    const normalizedActor = this.normalizeIdentityReference(actorIdentity);
    const actorIsSender = envelope.from?.identity === normalizedActor;
    const actorIsRecipient = (envelope.to || []).some((recipient) => recipient.identity === normalizedActor);
    const actorIsParticipant = thread ? this.isActiveParticipant(thread, normalizedActor) : false;

    let capabilityAuthorized = false;
    if (!actorIsSender && !actorIsRecipient && !actorIsParticipant) {
      if (!thread) {
        throw new LoomError("CAPABILITY_DENIED", "Not authorized to view envelope", 403, {
          envelope_id: envelope.id,
          actor: normalizedActor
        });
      }

      this.validateCapabilityForThreadRead({
        thread,
        actorIdentity: normalizedActor,
        capabilityTokenValue: options.capabilityTokenValue ?? null,
        strict: true
      });
      capabilityAuthorized = true;
    }

    return this.buildEnvelopeRecipientView(envelope, normalizedActor, {
      allowThreadReadCapability: capabilityAuthorized
    });
  }

  getThreadEnvelopesForIdentity(threadId, actorIdentity, options = {}) {
    const thread = this.threadsById.get(threadId);
    if (!thread) {
      return null;
    }

    const normalizedActor = this.normalizeIdentityReference(actorIdentity);
    const capabilityTokenValue = options.capabilityTokenValue ?? null;
    const readToken = this.validateCapabilityForThreadRead({
      thread,
      actorIdentity: normalizedActor,
      capabilityTokenValue,
      strict: true
    });

    let envelopeIds = thread.envelope_ids;

    if (options.after_snapshot && thread.snapshot) {
      const cutoffIndex = thread.snapshot.cutoff_index;
      const snapshotEnvelopeId = thread.snapshot.envelope_id;
      const postCutoffIds = envelopeIds.slice(cutoffIndex + 1);
      if (!postCutoffIds.includes(snapshotEnvelopeId)) {
        postCutoffIds.unshift(snapshotEnvelopeId);
      }
      envelopeIds = postCutoffIds;
    }

    const envelopes = canonicalThreadOrder(envelopeIds.map((id) => this.envelopesById.get(id)));
    const allowThreadReadCapability = Boolean(readToken);
    return envelopes.map((envelope) =>
      this.buildEnvelopeRecipientView(envelope, normalizedActor, {
        allowThreadReadCapability
      })
    );
  }

  listGatewayImapMessages(folderName, actorIdentity, limit = 100) {
    const normalizedFolder = this.normalizeGatewayFolderName(folderName);
    const cappedLimit = Math.max(1, Math.min(Number(limit || 100), 500));
    const messages = [];

    for (const thread of this.threadsById.values()) {
      if (!this.isActiveParticipant(thread, actorIdentity)) {
        continue;
      }

      if (this.classifyThreadFolder(thread, actorIdentity) !== normalizedFolder) {
        continue;
      }

      const mailboxState = this.ensureMailboxState(thread, actorIdentity);
      const envelopes = canonicalThreadOrder(thread.envelope_ids.map((id) => this.envelopesById.get(id))).reverse();
      for (const envelope of envelopes) {
        const messageId = `<${envelope.id}@${this.nodeId}>`;
        const inReplyTo = envelope.parent_id ? `<${envelope.parent_id}@${this.nodeId}>` : null;
        const references = Array.from(
          new Set(
            (envelope.references?.external || [])
              .filter((entry) => entry?.type === "email_message_id" && entry?.ref)
              .map((entry) => String(entry.ref).trim())
              .filter(Boolean)
          )
        )
          .map((ref) => (ref.startsWith("<") ? ref : `<${ref}>`))
          .join(" ");

        messages.push({
          envelope_id: envelope.id,
          thread_id: envelope.thread_id,
          subject: thread.subject || "(no subject)",
          from: envelope.from?.identity || null,
          from_email: this.inferEmailFromIdentity(envelope.from?.identity || ""),
          to: this.getVisibleEnvelopeRecipients(envelope, actorIdentity).map((recipient) => recipient.identity),
          date: envelope.created_at,
          message_id: messageId,
          in_reply_to: inReplyTo,
          body_text: envelope.content?.encrypted ? "[Encrypted LOOM content]" : envelope.content?.human?.text || "",
          mailbox_state: {
            seen: mailboxState.seen,
            flagged: mailboxState.flagged,
            archived: mailboxState.archived,
            deleted: mailboxState.deleted
          },
          headers: {
            "Message-ID": messageId,
            ...(inReplyTo ? { "In-Reply-To": inReplyTo } : {}),
            ...(references ? { References: references } : {}),
            "X-LOOM-Thread-ID": envelope.thread_id,
            "X-LOOM-Envelope-ID": envelope.id,
            "X-LOOM-Intent": envelope.content?.structured?.intent || "message.general@v1"
          }
        });
      }
    }

    messages.sort((a, b) => {
      if (a.date === b.date) {
        return a.envelope_id.localeCompare(b.envelope_id);
      }
      return a.date > b.date ? -1 : 1;
    });

    return messages.slice(0, cappedLimit).map((message, index) => ({
      ...message,
      uid: index + 1
    }));
  }

  submitGatewaySmtp(payload, actorIdentity) {
    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "SMTP submit payload must be an object", 400, {
        field: "payload"
      });
    }

    const toIdentities = this.resolveIdentitiesFromAddressInput(payload.to);
    const ccIdentities = this.resolveIdentitiesFromAddressInput(payload.cc);
    const bccIdentities = this.resolveIdentitiesFromAddressInput(payload.bcc);
    const to = this.buildRecipientList({
      primary: toIdentities,
      cc: ccIdentities,
      bcc: bccIdentities
    });

    if (to.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "SMTP submit recipients could not be mapped", 400, {
        field: "to"
      });
    }

    const threading = this.resolveThreadFromEmailHeaders(payload);
    const envelopeId = `env_${generateUlid()}`;
    const headers = payload?.headers && typeof payload.headers === "object" ? payload.headers : {};
    const dateHeader = this.resolveHeaderValue(headers, "date");
    const createdAtInput = payload.date || dateHeader;
    const createdAt = parseTime(createdAtInput) != null ? new Date(parseTime(createdAtInput)).toISOString() : nowIso();
    const messageId =
      this.parseMessageId(payload.message_id || this.resolveHeaderValue(headers, "message-id")) ||
      `${envelopeId}@${this.nodeId}`;

    const humanText =
      typeof payload.text === "string" && payload.text.trim().length > 0
        ? payload.text
        : this.htmlToText(payload.html || "");

    const unsignedEnvelope = {
      loom: "1.1",
      id: envelopeId,
      thread_id: threading.thread_id,
      parent_id: threading.parent_id,
      type: "message",
      from: {
        identity: actorIdentity,
        display: payload.display_from || actorIdentity,
        key_id: this.systemSigningKeyId,
        type: "human"
      },
      to,
      audience: {
        mode: to.some((recipient) => recipient.role === "bcc") ? "recipients" : "thread"
      },
      created_at: createdAt,
      priority: payload.priority || "normal",
      content: {
        human: {
          text: humanText || "(no body)",
          format: "plaintext"
        },
        structured: {
          intent: "message.general@v1",
          parameters: {
            source: "legacy_gateway"
          }
        },
        encrypted: false
      },
      attachments: Array.isArray(payload.attachments) ? payload.attachments : [],
      references: {
        in_reply_to: threading.parent_id,
        linked_envelopes: [],
        linked_threads: [],
        external: [
          {
            type: "email_message_id",
            ref: messageId
          }
        ]
      },
      meta: {
        bridge: {
          source: "legacy_gateway",
          original_message_id: messageId,
          original_headers: headers,
          auth_results: {
            spf: "pass",
            dkim: "pass",
            dmarc: "pass"
          },
          extraction_confidence: 1
        }
      }
    };

    const signedEnvelope = signEnvelope(
      unsignedEnvelope,
      this.systemSigningPrivateKeyPem,
      this.systemSigningKeyId
    );

    const stored = this.ingestEnvelope(signedEnvelope, {
      actorIdentity,
      allowSystemSignatureOverride: true
    });

    this.recordEmailMessageIndex(messageId, stored.id, stored.thread_id);
    const labeledSent = this.ensureThreadLabel(stored.thread_id, "sys.sent");

    this.persistAndAudit("gateway.smtp.submit", {
      envelope_id: stored.id,
      thread_id: stored.thread_id,
      actor: actorIdentity,
      labeled_sent: labeledSent
    });

    return {
      envelope_id: stored.id,
      thread_id: stored.thread_id,
      message_id: messageId
    };
  }

  queueEmailOutbox(payload, actorIdentity) {
    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Email outbox payload must be an object", 400, {
        field: "outbox"
      });
    }

    const envelopeId = String(payload.envelope_id || "").trim();
    if (!envelopeId) {
      throw new LoomError("ENVELOPE_INVALID", "envelope_id is required", 400, {
        field: "envelope_id"
      });
    }

    const envelope = this.envelopesById.get(envelopeId);
    if (!envelope) {
      throw new LoomError("ENVELOPE_NOT_FOUND", `Envelope not found: ${envelopeId}`, 404, {
        envelope_id: envelopeId
      });
    }

    const thread = this.threadsById.get(envelope.thread_id);
    const canQueue =
      envelope.from?.identity === actorIdentity || (thread ? this.isActiveParticipant(thread, actorIdentity) : false);
    if (!canQueue) {
      throw new LoomError("CAPABILITY_DENIED", "Not authorized to queue outbound email for this envelope", 403, {
        envelope_id: envelopeId,
        actor: actorIdentity
      });
    }

    const toEmailRaw = Array.isArray(payload.to_email)
      ? payload.to_email
      : typeof payload.to_email === "string"
        ? this.splitAddressList(payload.to_email)
        : null;
    const toEmail = toEmailRaw
      ? toEmailRaw.map((value) => this.normalizeEmailAddress(String(value || ""))).filter(Boolean)
      : null;

    if (toEmailRaw && (!toEmail || toEmail.length === 0)) {
      throw new LoomError("ENVELOPE_INVALID", "to_email was provided but no valid email recipients were resolved", 400, {
        field: "to_email"
      });
    }

    const smtpFrom = payload.smtp_from ? this.normalizeEmailAddress(String(payload.smtp_from || "")) : null;
    if (payload.smtp_from && !smtpFrom) {
      throw new LoomError("ENVELOPE_INVALID", "smtp_from must be a valid email address", 400, {
        field: "smtp_from"
      });
    }

    if (payload.subject && containsHeaderUnsafeChars(payload.subject)) {
      throw new LoomError("ENVELOPE_INVALID", "subject contains invalid header characters", 400, {
        field: "subject"
      });
    }

    const traceContext = this.getCurrentTraceContext();
    const sourceRequestId = traceContext?.request_id || null;
    const sourceTraceId = traceContext?.trace_id || sourceRequestId || null;

    const outbox = {
      id: `eout_${generateUlid()}`,
      envelope_id: envelopeId,
      thread_id: envelope.thread_id,
      smtp_from: smtpFrom,
      to_email: toEmail,
      subject: payload.subject || null,
      status: "queued",
      attempts: 0,
      max_attempts: Math.max(1, Math.min(Number(payload.max_attempts || 8), 20)),
      next_attempt_at: nowIso(),
      created_at: nowIso(),
      updated_at: nowIso(),
      expires_at: payload.expires_at || new Date(nowMs() + 72 * 60 * 60 * 1000).toISOString(),
      delivered_at: null,
      provider_message_id: null,
      last_provider_response: null,
      last_error: null,
      recipient_statuses: [],
      last_dsn_at: null,
      last_dsn_source: null,
      queued_by: actorIdentity,
      source_request_id: sourceRequestId,
      source_trace_id: sourceTraceId
    };

    this.emailOutboxById.set(outbox.id, outbox);
    this.persistAndAudit("email.outbox.queue", {
      outbox_id: outbox.id,
      envelope_id: outbox.envelope_id,
      thread_id: outbox.thread_id,
      actor: actorIdentity,
      source_request_id: sourceRequestId,
      source_trace_id: sourceTraceId
    });
    return outbox;
  }

  listEmailOutbox(filters = {}) {
    const status = filters.status ? String(filters.status) : null;
    const threadId = filters.thread_id ? String(filters.thread_id) : null;
    const limit = Math.max(1, Math.min(Number(filters.limit || 200), 1000));

    const items = Array.from(this.emailOutboxById.values())
      .filter((item) => (status ? item.status === status : true))
      .filter((item) => (threadId ? item.thread_id === threadId : true))
      .sort((a, b) => a.created_at.localeCompare(b.created_at));

    return items.slice(0, limit);
  }

  getEmailOutboxStats() {
    const stats = {
      total: 0,
      queued: 0,
      delivered: 0,
      failed: 0,
      retry_scheduled: 0,
      oldest_queued_at: null,
      newest_queued_at: null,
      lag_ms: 0
    };

    for (const item of this.emailOutboxById.values()) {
      stats.total += 1;

      if (item.status === "queued") {
        stats.queued += 1;
        if (item.next_attempt_at) {
          stats.retry_scheduled += 1;
        }

        if (!stats.oldest_queued_at || item.created_at < stats.oldest_queued_at) {
          stats.oldest_queued_at = item.created_at;
        }
        if (!stats.newest_queued_at || item.created_at > stats.newest_queued_at) {
          stats.newest_queued_at = item.created_at;
        }
      } else if (item.status === "delivered") {
        stats.delivered += 1;
      } else if (item.status === "failed") {
        stats.failed += 1;
      }
    }

    if (stats.oldest_queued_at) {
      stats.lag_ms = Math.max(0, nowMs() - Date.parse(stats.oldest_queued_at));
    }

    return stats;
  }

  requeueEmailOutboxItem(outboxId, actorIdentity = null) {
    const item = this.emailOutboxById.get(outboxId);
    if (!item) {
      throw new LoomError("ENVELOPE_NOT_FOUND", `Email outbox item not found: ${outboxId}`, 404, {
        outbox_id: outboxId
      });
    }

    if (item.status !== "failed") {
      throw new LoomError("STATE_TRANSITION_INVALID", "Only failed email outbox items can be requeued", 409, {
        outbox_id: outboxId,
        current_status: item.status
      });
    }

    item.status = "queued";
    item.next_attempt_at = nowIso();
    item.updated_at = nowIso();
    item.last_error = null;
    item.last_provider_response = null;

    this.persistAndAudit("email.outbox.requeue", {
      outbox_id: item.id,
      envelope_id: item.envelope_id,
      thread_id: item.thread_id,
      actor: actorIdentity
    });

    return item;
  }

  markEmailOutboxFailure(item, errorMessage) {
    item.attempts += 1;
    item.updated_at = nowIso();
    item.last_error = String(errorMessage || "email delivery failed");
    item.last_provider_response = null;

    const expired = isExpiredIso(item.expires_at);
    if (expired || item.attempts >= item.max_attempts) {
      item.status = "failed";
      item.next_attempt_at = null;
      return;
    }

    const backoffSeconds = Math.min(30 * 2 ** Math.max(0, item.attempts - 1), 3600);
    item.status = "queued";
    item.next_attempt_at = new Date(nowMs() + backoffSeconds * 1000).toISOString();
  }

  normalizeEmailDeliveryStatus(value, fallback = "unknown") {
    const normalized = String(value || "")
      .trim()
      .toLowerCase();
    if (!normalized) {
      return fallback;
    }

    if (
      normalized === "delivered" ||
      normalized === "relayed" ||
      normalized === "expanded" ||
      normalized === "failed" ||
      normalized === "delayed" ||
      normalized === "unknown"
    ) {
      return normalized;
    }

    if (normalized === "success" || normalized === "ok") {
      return "delivered";
    }
    if (normalized === "temporary_failure" || normalized === "deferred" || normalized === "retry") {
      return "delayed";
    }
    if (normalized === "permanent_failure" || normalized === "error" || normalized === "bounced") {
      return "failed";
    }
    return fallback;
  }

  normalizeEmailRecipientDeliveryUpdates(recipients) {
    const normalized = [];
    for (const entry of Array.isArray(recipients) ? recipients : []) {
      if (!entry || typeof entry !== "object") {
        continue;
      }

      const recipient = this.normalizeEmailAddress(
        entry.recipient || entry.address || entry.to || entry.email || entry.rcpt_to
      );
      if (!recipient) {
        continue;
      }

      const status = this.normalizeEmailDeliveryStatus(entry.status || entry.action, "unknown");
      normalized.push({
        recipient,
        status,
        action: String(entry.action || status).trim().toLowerCase() || status,
        status_code: entry.status_code ? String(entry.status_code).trim() : null,
        diagnostic_code: entry.diagnostic_code ? String(entry.diagnostic_code).trim() : null,
        remote_mta: entry.remote_mta ? String(entry.remote_mta).trim() : null
      });
    }
    return normalized;
  }

  mergeEmailRecipientStatuses(existingStatuses, updates, source, updatedAt, options = {}) {
    const dsnMessageId = options.dsnMessageId ? String(options.dsnMessageId).trim() : null;
    const byRecipient = new Map();
    for (const statusEntry of Array.isArray(existingStatuses) ? existingStatuses : []) {
      if (!statusEntry || typeof statusEntry !== "object") {
        continue;
      }
      const recipient = this.normalizeEmailAddress(statusEntry.recipient);
      if (!recipient) {
        continue;
      }
      byRecipient.set(recipient, {
        recipient,
        status: this.normalizeEmailDeliveryStatus(statusEntry.status, "unknown"),
        action: statusEntry.action || null,
        status_code: statusEntry.status_code || null,
        diagnostic_code: statusEntry.diagnostic_code || null,
        remote_mta: statusEntry.remote_mta || null,
        source: statusEntry.source || null,
        updated_at: statusEntry.updated_at || null,
        dsn_message_id: statusEntry.dsn_message_id || null
      });
    }

    for (const update of updates) {
      const recipient = this.normalizeEmailAddress(update.recipient);
      if (!recipient) {
        continue;
      }
      byRecipient.set(recipient, {
        recipient,
        status: this.normalizeEmailDeliveryStatus(update.status, "unknown"),
        action: update.action || null,
        status_code: update.status_code || null,
        diagnostic_code: update.diagnostic_code || null,
        remote_mta: update.remote_mta || null,
        source,
        updated_at: updatedAt,
        dsn_message_id: dsnMessageId
      });
    }

    return Array.from(byRecipient.values()).sort((left, right) => left.recipient.localeCompare(right.recipient));
  }

  computeEmailOutboxStateFromRecipientStatuses(recipientStatuses = []) {
    const statuses = Array.isArray(recipientStatuses) ? recipientStatuses : [];
    const hasFailed = statuses.some((entry) => entry.status === "failed");
    const hasDelayed = statuses.some((entry) => entry.status === "delayed");
    const hasDelivered = statuses.some((entry) =>
      entry.status === "delivered" || entry.status === "relayed" || entry.status === "expanded"
    );

    if (hasFailed) {
      return {
        status: "failed",
        reason: "Delivery failed for one or more recipients"
      };
    }
    if (hasDelayed) {
      return {
        status: "queued",
        reason: "Delivery delayed for one or more recipients"
      };
    }
    if (hasDelivered) {
      return {
        status: "delivered",
        reason: null
      };
    }
    return {
      status: "queued",
      reason: null
    };
  }

  applyEmailOutboxDsnReport(outboxId, payload, actorIdentity = "system") {
    const item = this.emailOutboxById.get(outboxId);
    if (!item) {
      throw new LoomError("ENVELOPE_NOT_FOUND", `Email outbox item not found: ${outboxId}`, 404, {
        outbox_id: outboxId
      });
    }

    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "DSN payload must be an object", 400, {
        field: "dsn"
      });
    }

    const updates = this.normalizeEmailRecipientDeliveryUpdates(payload.recipients);
    if (updates.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "DSN payload must include at least one valid recipient status", 400, {
        field: "recipients"
      });
    }
    const allowedRecipients = new Set(
      (Array.isArray(item.to_email) ? item.to_email : [])
        .map((entry) => this.normalizeEmailAddress(entry))
        .filter(Boolean)
    );
    if (allowedRecipients.size > 0) {
      const invalidRecipient = updates.find((entry) => !allowedRecipients.has(entry.recipient));
      if (invalidRecipient) {
        throw new LoomError("ENVELOPE_INVALID", "DSN recipient is not part of this outbox delivery", 400, {
          field: "recipients",
          recipient: invalidRecipient.recipient
        });
      }
    }

    const source = String(payload.source || "dsn").trim().toLowerCase() || "dsn";
    const dsnReceivedAt = parseTime(payload.received_at) != null ? new Date(parseTime(payload.received_at)).toISOString() : nowIso();
    const dsnMessageId = payload.dsn_message_id ? this.parseMessageId(payload.dsn_message_id) : null;

    item.recipient_statuses = this.mergeEmailRecipientStatuses(item.recipient_statuses, updates, source, dsnReceivedAt, {
      dsnMessageId
    });
    item.last_dsn_at = dsnReceivedAt;
    item.last_dsn_source = source;
    item.updated_at = nowIso();
    if (payload.provider_message_id) {
      item.provider_message_id = String(payload.provider_message_id).trim();
    }
    if (payload.provider_response) {
      item.last_provider_response = String(payload.provider_response).trim();
    }

    const aggregate = this.computeEmailOutboxStateFromRecipientStatuses(item.recipient_statuses);
    item.status = aggregate.status;
    if (aggregate.status === "delivered") {
      item.delivered_at = item.delivered_at || dsnReceivedAt;
      item.next_attempt_at = null;
      item.last_error = null;
    } else if (aggregate.status === "failed") {
      const firstFailure = item.recipient_statuses.find((entry) => entry.status === "failed");
      item.last_error = firstFailure?.diagnostic_code || aggregate.reason;
      item.next_attempt_at = null;
    } else {
      item.last_error = aggregate.reason;
      if (!item.next_attempt_at || parseTime(item.next_attempt_at) == null || parseTime(item.next_attempt_at) <= nowMs()) {
        item.next_attempt_at = new Date(nowMs() + 5 * 60 * 1000).toISOString();
      }
    }

    this.persistAndAudit("email.outbox.dsn.update", {
      outbox_id: item.id,
      envelope_id: item.envelope_id,
      status: item.status,
      recipient_updates: updates.length,
      source,
      actor: actorIdentity
    });

    return item;
  }

  async claimOutboxItemForProcessing(kind, item) {
    if (!item) {
      return false;
    }

    // In-memory lease guard — prevents double-processing within the same
    // process even when no persistence adapter is configured.
    const leaseKey = `${kind}:${item.id}`;
    const existingLease = this._outboxLeases?.get(leaseKey);
    if (existingLease && existingLease > Date.now()) {
      return false;
    }
    if (!this._outboxLeases) {
      this._outboxLeases = new Map();
    }
    this._outboxLeases.set(leaseKey, Date.now() + this.outboxClaimLeaseMs);

    if (!this.persistenceAdapter || typeof this.persistenceAdapter.claimOutboxItem !== "function") {
      return true;
    }

    const claim = await this.persistenceAdapter.claimOutboxItem({
      kind,
      outboxId: item.id,
      expectedUpdatedAt: item.updated_at,
      leaseMs: this.outboxClaimLeaseMs,
      workerId: this.outboxWorkerId
    });
    if (claim?.claimed === false) {
      this._outboxLeases.delete(leaseKey);
      return false;
    }
    return true;
  }

  async releaseOutboxItemClaim(kind, item) {
    if (!item) {
      return;
    }

    // Clear in-memory lease.
    const leaseKey = `${kind}:${item.id}`;
    this._outboxLeases?.delete(leaseKey);

    if (!this.persistenceAdapter || typeof this.persistenceAdapter.releaseOutboxClaim !== "function") {
      return;
    }
    await this.persistenceAdapter.releaseOutboxClaim({
      kind,
      outboxId: item.id,
      workerId: this.outboxWorkerId
    });
  }

  async processEmailOutboxItem(outboxId, emailRelay, actorIdentity = null) {
    const item = this.emailOutboxById.get(outboxId);
    if (!item) {
      throw new LoomError("ENVELOPE_NOT_FOUND", `Email outbox item not found: ${outboxId}`, 404, {
        outbox_id: outboxId
      });
    }

    if (item.status === "delivered" || item.status === "failed") {
      return item;
    }

    if (item.next_attempt_at && parseTime(item.next_attempt_at) > nowMs()) {
      return item;
    }

    if (!(await this.claimOutboxItemForProcessing("email", item))) {
      return item;
    }

    try {
      if (!emailRelay || typeof emailRelay.send !== "function") {
        this.markEmailOutboxFailure(item, "Email relay adapter not configured");
        this.persistAndAudit("email.outbox.process.failed", {
          outbox_id: item.id,
          envelope_id: item.envelope_id,
          reason: item.last_error,
          source_request_id: item.source_request_id || null,
          source_trace_id: item.source_trace_id || null,
          actor: actorIdentity
        });
        return item;
      }

      const renderPayload = {
        envelope_id: item.envelope_id
      };
      if (item.smtp_from) {
        renderPayload.smtp_from = item.smtp_from;
      }
      if (item.to_email?.length) {
        renderPayload.to_email = item.to_email;
      }
      if (item.subject) {
        renderPayload.subject = item.subject;
      }

      const rendered = this.renderBridgeOutboundEmail(renderPayload, item.queued_by);
      const relayResult = await emailRelay.send(rendered);
      const accepted = Array.isArray(relayResult?.accepted)
        ? relayResult.accepted.map((entry) => this.normalizeEmailAddress(String(entry || ""))).filter(Boolean)
        : [];
      const rejected = Array.isArray(relayResult?.rejected)
        ? relayResult.rejected.map((entry) => this.normalizeEmailAddress(String(entry || ""))).filter(Boolean)
        : [];

      item.attempts += 1;
      item.updated_at = nowIso();
      item.provider_message_id = relayResult.provider_message_id || null;
      item.last_provider_response = relayResult.response || null;
      item.recipient_statuses = this.mergeEmailRecipientStatuses(
        item.recipient_statuses,
        [
          ...accepted.map((recipient) => ({
            recipient,
            status: "relayed",
            action: "relayed"
          })),
          ...rejected.map((recipient) => ({
            recipient,
            status: "failed",
            action: "failed",
            diagnostic_code: relayResult?.response || null
          }))
        ],
        "relay",
        nowIso()
      );

      const aggregate = this.computeEmailOutboxStateFromRecipientStatuses(item.recipient_statuses);
      item.status = aggregate.status;
      if (aggregate.status === "failed") {
        item.next_attempt_at = null;
        const firstFailure = item.recipient_statuses.find((entry) => entry.status === "failed");
        item.last_error = firstFailure?.diagnostic_code || aggregate.reason;
        item.delivered_at = null;
      } else if (aggregate.status === "queued") {
        item.last_error = aggregate.reason;
        item.next_attempt_at = new Date(nowMs() + 5 * 60 * 1000).toISOString();
      } else {
        item.last_error = null;
        item.delivered_at = nowIso();
        item.next_attempt_at = null;
      }

      const envelope = this.envelopesById.get(item.envelope_id);
      if (envelope) {
        this.ensureThreadLabel(envelope.thread_id, "sys.sent");
      }

      this.persistAndAudit("email.outbox.process.delivered", {
        outbox_id: item.id,
        envelope_id: item.envelope_id,
        thread_id: item.thread_id,
        provider_message_id: item.provider_message_id,
        status: item.status,
        source_request_id: item.source_request_id || null,
        source_trace_id: item.source_trace_id || null,
        actor: actorIdentity
      });
      return item;
    } catch (error) {
      this.markEmailOutboxFailure(item, error?.message || "Email relay send failed");
      this.persistAndAudit("email.outbox.process.failed", {
        outbox_id: item.id,
        envelope_id: item.envelope_id,
        thread_id: item.thread_id,
        reason: item.last_error,
        source_request_id: item.source_request_id || null,
        source_trace_id: item.source_trace_id || null,
        actor: actorIdentity
      });
      return item;
    } finally {
      await this.releaseOutboxItemClaim("email", item);
    }
  }

  async processEmailOutboxBatch(limit = 10, emailRelay, actorIdentity = null) {
    const now = nowMs();
    const candidates = Array.from(this.emailOutboxById.values())
      .filter((item) => item.status === "queued")
      .filter((item) => !item.next_attempt_at || parseTime(item.next_attempt_at) <= now)
      .sort((a, b) => a.created_at.localeCompare(b.created_at))
      .slice(0, Math.max(1, Math.min(Number(limit || 10), 200)));

    const processed = [];
    for (const item of candidates) {
      const result = await this.processEmailOutboxItem(item.id, emailRelay, actorIdentity);
      processed.push({
        outbox_id: result.id,
        status: result.status,
        attempts: result.attempts,
        provider_message_id: result.provider_message_id,
        last_error: result.last_error,
        source_request_id: result.source_request_id || null,
        source_trace_id: result.source_trace_id || null
      });
    }

    return {
      processed_count: processed.length,
      processed
    };
  }

  normalizeIdentityReference(identity) {
    if (typeof identity !== "string") {
      return "";
    }
    const trimmed = identity.trim();
    if (!trimmed) {
      return "";
    }
    return normalizeLoomIdentity(trimmed) || trimmed;
  }

  resolveIdentitySigningKey(identityUri, keyId) {
    const normalizedIdentity = this.normalizeIdentityReference(identityUri);
    const normalizedKeyId = String(keyId || "").trim();
    if (!normalizedIdentity || !normalizedKeyId) {
      return null;
    }

    const identity = this.resolveIdentity(normalizedIdentity);
    if (!identity) {
      return null;
    }

    const signingKeys = Array.isArray(identity.signing_keys) ? identity.signing_keys : [];
    return signingKeys.find((key) => key?.key_id === normalizedKeyId) || null;
  }

  resolveIdentitySigningPublicKey(identityUri, keyId) {
    const signingKey = this.resolveIdentitySigningKey(identityUri, keyId);
    return signingKey?.public_key_pem || null;
  }

  resolveIdentityEncryptionKey(identityUri, keyId, options = {}) {
    const normalizedIdentity = this.normalizeIdentityReference(identityUri);
    const normalizedKeyId = String(keyId || "").trim();
    if (!normalizedIdentity || !normalizedKeyId) {
      return null;
    }

    const owner = this.encryptionKeyOwnerById.get(normalizedKeyId);
    if (owner && owner !== normalizedIdentity) {
      return null;
    }

    const identity = this.resolveIdentity(normalizedIdentity);
    if (!identity) {
      return null;
    }

    const encryptionKeys = Array.isArray(identity.encryption_keys) ? identity.encryption_keys : [];
    const key = encryptionKeys.find((candidate) => String(candidate?.key_id || "").trim() === normalizedKeyId) || null;
    if (!key) {
      return null;
    }

    if (options.requireUsable !== false && !isSigningKeyUsableAt(key)) {
      return null;
    }

    return {
      ...key,
      algorithm: normalizeIdentityEncryptionKeyAlgorithm(key.algorithm) || String(key.algorithm || "").trim()
    };
  }

  cleanupIdentityRegistrationChallenges(now = nowMs()) {
    for (const [challengeId, challenge] of this.identityRegistrationChallenges.entries()) {
      if (challenge?.used || isExpiredIso(challenge?.expires_at)) {
        this.identityRegistrationChallenges.delete(challengeId);
      }
    }
  }

  createIdentityRegistrationChallenge(payload = {}, options = {}) {
    const normalizedIdentity = normalizeLoomIdentity(payload.identity || payload.id);
    if (!normalizedIdentity) {
      throw new LoomError("ENVELOPE_INVALID", "identity must be a loom:// URI", 400, {
        field: "identity"
      });
    }

    const keyId = String(payload.key_id || "").trim();
    if (!keyId) {
      throw new LoomError("ENVELOPE_INVALID", "key_id is required", 400, {
        field: "key_id"
      });
    }

    const localIdentityDomain =
      typeof options.localIdentityDomain === "string" && options.localIdentityDomain.trim()
        ? options.localIdentityDomain.trim().toLowerCase()
        : this.localIdentityDomain;
    const identityDomain = parseLoomIdentityDomain(normalizedIdentity);
    if (
      localIdentityDomain &&
      identityDomain &&
      identityDomain !== localIdentityDomain &&
      options.allowRemoteDomain !== true
    ) {
      throw new LoomError("CAPABILITY_DENIED", "Identity domain must match local node domain", 403, {
        field: "identity",
        identity_domain: identityDomain,
        local_domain: localIdentityDomain
      });
    }

    if (this.resolveIdentity(normalizedIdentity) && options.allowExistingIdentity !== true) {
      throw new LoomError("ENVELOPE_DUPLICATE", `Identity already exists: ${normalizedIdentity}`, 409, {
        identity: normalizedIdentity
      });
    }

    this.cleanupIdentityRegistrationChallenges();

    const challengeId = `ichl_${generateUlid()}`;
    const nonce = `nonce_${generateUlid()}`;
    const expiresAt = new Date(nowMs() + this.identityRegistrationChallengeTtlMs).toISOString();
    const challenge = {
      challenge_id: challengeId,
      identity: normalizedIdentity,
      key_id: keyId,
      nonce,
      expires_at: expiresAt,
      used: false,
      created_at: nowIso()
    };

    this.identityRegistrationChallenges.set(challengeId, challenge);
    return {
      challenge_id: challengeId,
      identity: normalizedIdentity,
      key_id: keyId,
      nonce,
      expires_at: expiresAt,
      algorithm: "Ed25519",
      purpose: "identity.register@v1"
    };
  }

  consumeIdentityRegistrationProof(
    identityDoc,
    normalizedIdentity,
    normalizedSigningKeys,
    normalizedEncryptionKeys = [],
    options = {}
  ) {
    const requireProofOfKey =
      options.requireProofOfKey === true ||
      (options.requireProofOfKey !== false && this.identityRegistrationProofRequired);
    if (!requireProofOfKey || options.importedRemote === true) {
      return null;
    }

    const proof = identityDoc?.registration_proof;
    if (!proof || typeof proof !== "object") {
      throw new LoomError("SIGNATURE_INVALID", "Identity registration proof is required", 401, {
        field: "registration_proof"
      });
    }

    const challengeId = String(proof.challenge_id || "").trim();
    const proofKeyId = String(proof.key_id || "").trim();
    const signature = String(proof.signature || "").trim();
    if (!challengeId || !proofKeyId || !signature) {
      throw new LoomError("SIGNATURE_INVALID", "registration_proof requires challenge_id, key_id, and signature", 401, {
        field: "registration_proof"
      });
    }

    const challenge = this.identityRegistrationChallenges.get(challengeId);
    if (!challenge) {
      throw new LoomError("SIGNATURE_INVALID", "Identity registration challenge not found", 401, {
        field: "registration_proof.challenge_id"
      });
    }

    if (challenge.used) {
      throw new LoomError("SIGNATURE_INVALID", "Identity registration challenge already used", 401, {
        field: "registration_proof.challenge_id"
      });
    }

    if (isExpiredIso(challenge.expires_at)) {
      throw new LoomError("SIGNATURE_INVALID", "Identity registration challenge expired", 401, {
        field: "registration_proof.challenge_id"
      });
    }

    if (challenge.identity !== normalizedIdentity || challenge.key_id !== proofKeyId) {
      throw new LoomError("SIGNATURE_INVALID", "Identity registration challenge mismatch", 401, {
        field: "registration_proof"
      });
    }

    const proofKey = normalizedSigningKeys.find((key) => key.key_id === proofKeyId);
    if (!proofKey) {
      throw new LoomError("SIGNATURE_INVALID", "registration_proof.key_id must be present in signing_keys", 401, {
        field: "registration_proof.key_id"
      });
    }

    const registrationDocument = buildIdentityRegistrationDocument({
      identity: normalizedIdentity,
      type: identityDoc.type || "human",
      displayName: identityDoc.display_name || normalizedIdentity,
      signingKeys: normalizedSigningKeys,
      encryptionKeys: normalizedEncryptionKeys,
      agentInfo: identityDoc.agent_info || null
    });
    const documentHash = hashIdentityRegistrationDocument(registrationDocument);
    const message = buildIdentityRegistrationProofMessage({
      identity: normalizedIdentity,
      keyId: proofKeyId,
      documentHash,
      nonce: challenge.nonce
    });
    const valid = verifyUtf8MessageSignature(proofKey.public_key_pem, message, signature);
    if (!valid) {
      throw new LoomError("SIGNATURE_INVALID", "Identity registration proof signature verification failed", 401, {
        field: "registration_proof.signature"
      });
    }

    challenge.used = true;
    return {
      challenge_id: challengeId,
      key_id: proofKeyId,
      document_hash: documentHash
    };
  }

  registerIdentity(identityDoc, options = {}) {
    if (!identityDoc || typeof identityDoc !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Identity payload must be an object", 400, {
        field: "identity"
      });
    }

    const normalizedIdentity = normalizeLoomIdentity(identityDoc.id);
    if (!normalizedIdentity) {
      throw new LoomError("ENVELOPE_INVALID", "Identity id must be a loom:// URI", 400, {
        field: "id"
      });
    }

    const localIdentityDomain =
      typeof options.localIdentityDomain === "string" && options.localIdentityDomain.trim()
        ? options.localIdentityDomain.trim().toLowerCase()
        : this.localIdentityDomain;
    const identityDomain = parseLoomIdentityDomain(normalizedIdentity);
    const allowRemoteDomain = options.allowRemoteDomain === true;
    if (localIdentityDomain && identityDomain && identityDomain !== localIdentityDomain && !allowRemoteDomain) {
      throw new LoomError("CAPABILITY_DENIED", "Identity domain must match local node domain", 403, {
        field: "id",
        identity_domain: identityDomain,
        local_domain: localIdentityDomain
      });
    }

    const existingLocalIdentity = this.identities.get(normalizedIdentity) || null;
    const existingRemoteIdentity = this.remoteIdentities.get(normalizedIdentity) || null;
    const existingIdentity = existingLocalIdentity || existingRemoteIdentity;
    const targetMap = options.importedRemote === true ? this.remoteIdentities : this.identities;
    const nonTargetMap = options.importedRemote === true ? this.identities : this.remoteIdentities;
    const allowOverwrite = options.allowOverwrite === true;
    if (existingIdentity && !allowOverwrite) {
      throw new LoomError("ENVELOPE_DUPLICATE", `Identity already exists: ${normalizedIdentity}`, 409, {
        identity: normalizedIdentity
      });
    }
    if (allowOverwrite && nonTargetMap.has(normalizedIdentity)) {
      throw new LoomError("CAPABILITY_DENIED", "Cannot overwrite identity across local/remote stores", 403, {
        identity: normalizedIdentity
      });
    }

    if (!existingIdentity) {
      const isRemote = options.importedRemote === true;
      const cap = isRemote ? this.maxRemoteIdentities : this.maxLocalIdentities;
      const currentCount = isRemote ? this.remoteIdentities.size : this.identities.size;
      if (cap > 0 && currentCount >= cap) {
        throw new LoomError("RESOURCE_LIMIT", `Maximum ${isRemote ? "remote" : "local"} identity count reached (${cap})`, 403, {
          limit: cap,
          current: currentCount
        });
      }
    }

    const signingKeys = Array.isArray(identityDoc.signing_keys) ? identityDoc.signing_keys : [];
    if (signingKeys.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "Identity must include at least one signing key", 400, {
        field: "signing_keys"
      });
    }

    const normalizedSigningKeys = [];
    const seenSigningKeyIds = new Set();
    for (const key of signingKeys) {
      const keyId = String(key?.key_id || "").trim();
      const publicKeyPem = String(key?.public_key_pem || "").trim();
      if (!keyId || !publicKeyPem) {
        throw new LoomError("ENVELOPE_INVALID", "Signing key entries require key_id and public_key_pem", 400, {
          field: "signing_keys"
        });
      }

      if (this.reservedSigningKeyIds.has(keyId)) {
        throw new LoomError("ENVELOPE_INVALID", `Signing key id is reserved: ${keyId}`, 400, {
          field: "signing_keys.key_id",
          key_id: keyId
        });
      }

      if (seenSigningKeyIds.has(keyId)) {
        throw new LoomError("ENVELOPE_INVALID", `Duplicate signing key id in identity payload: ${keyId}`, 400, {
          field: "signing_keys.key_id",
          key_id: keyId
        });
      }
      seenSigningKeyIds.add(keyId);

      const existingOwner = this.keyOwnerById.get(keyId);
      if (existingOwner && existingOwner !== normalizedIdentity) {
        throw new LoomError("ENVELOPE_INVALID", `Signing key id is already assigned to another identity: ${keyId}`, 400, {
          field: "signing_keys.key_id",
          key_id: keyId
        });
      }

      const existingPublicKeyPem = this.publicKeysById.get(keyId);
      if (existingPublicKeyPem && existingPublicKeyPem !== publicKeyPem) {
        throw new LoomError("ENVELOPE_INVALID", `Signing key id already exists with a different public key: ${keyId}`, 400, {
          field: "signing_keys.key_id",
          key_id: keyId
        });
      }

      normalizedSigningKeys.push({
        key_id: keyId,
        public_key_pem: publicKeyPem
      });
    }

    normalizedSigningKeys.sort((left, right) => left.key_id.localeCompare(right.key_id));

    const encryptionKeys = resolveIdentityEncryptionKeysInput(identityDoc);
    if (
      (Object.prototype.hasOwnProperty.call(identityDoc, "encryption_keys") ||
        Object.prototype.hasOwnProperty.call(identityDoc, "public_keys")) &&
      !Array.isArray(encryptionKeys)
    ) {
      throw new LoomError("ENVELOPE_INVALID", "encryption_keys must be an array when provided", 400, {
        field: "encryption_keys"
      });
    }

    const normalizedEncryptionKeys = [];
    const seenEncryptionKeyIds = new Set();
    for (const key of encryptionKeys) {
      const keyId = String(key?.key_id || "").trim();
      const algorithm = normalizeIdentityEncryptionKeyAlgorithm(key?.algorithm);
      const publicKey = String(key?.public_key || "").trim();
      const publicKeyPem = String(key?.public_key_pem || "").trim();
      if (!keyId || !algorithm || (!publicKey && !publicKeyPem)) {
        throw new LoomError(
          "ENVELOPE_INVALID",
          "Encryption key entries require key_id, algorithm, and public_key or public_key_pem",
          400,
          {
            field: "encryption_keys"
          }
        );
      }

      if (seenEncryptionKeyIds.has(keyId)) {
        throw new LoomError("ENVELOPE_INVALID", `Duplicate encryption key id in identity payload: ${keyId}`, 400, {
          field: "encryption_keys.key_id",
          key_id: keyId
        });
      }
      seenEncryptionKeyIds.add(keyId);

      const existingOwner = this.encryptionKeyOwnerById.get(keyId);
      if (existingOwner && existingOwner !== normalizedIdentity) {
        throw new LoomError(
          "ENVELOPE_INVALID",
          `Encryption key id is already assigned to another identity: ${keyId}`,
          400,
          {
            field: "encryption_keys.key_id",
            key_id: keyId
          }
        );
      }

      const existing = this.encryptionKeysById.get(keyId);
      if (existing) {
        if (
          existing.algorithm !== algorithm ||
          (existing.public_key || null) !== (publicKey || null) ||
          (existing.public_key_pem || null) !== (publicKeyPem || null)
        ) {
          throw new LoomError("ENVELOPE_INVALID", `Encryption key id already exists with different key material: ${keyId}`, 400, {
            field: "encryption_keys.key_id",
            key_id: keyId
          });
        }
      }

      normalizedEncryptionKeys.push({
        key_id: keyId,
        algorithm,
        public_key: publicKey || null,
        public_key_pem: publicKeyPem || null,
        status: String(key?.status || "active")
          .trim()
          .toLowerCase() || "active",
        not_before: key?.not_before ? String(key.not_before).trim() : null,
        not_after: key?.not_after ? String(key.not_after).trim() : null,
        revoked_at: key?.revoked_at ? String(key.revoked_at).trim() : null
      });
    }
    normalizedEncryptionKeys.sort((left, right) => left.key_id.localeCompare(right.key_id));

    const registrationProof = this.consumeIdentityRegistrationProof(
      identityDoc,
      normalizedIdentity,
      normalizedSigningKeys,
      normalizedEncryptionKeys,
      options
    );

    const remoteExpiresAtInput = options.remoteExpiresAt || identityDoc.remote_expires_at || null;
    const remoteExpiresAt = options.importedRemote
      ? remoteExpiresAtInput && parseTime(remoteExpiresAtInput) != null
        ? new Date(parseTime(remoteExpiresAtInput)).toISOString()
        : new Date(nowMs() + this.remoteIdentityTtlMs).toISOString()
      : null;

    // agent_info — only for agent-type identities
    let normalizedAgentInfo = null;
    const identityType = String(identityDoc.type || "human");
    if (identityDoc.agent_info !== undefined && identityDoc.agent_info !== null) {
      if (identityType !== "agent") {
        throw new LoomError("ENVELOPE_INVALID", "agent_info is only allowed for agent-type identities", 400, {
          field: "agent_info",
          identity_type: identityType
        });
      }
      const agentInfoErrors = validateAgentInfo(identityDoc.agent_info);
      if (agentInfoErrors.length > 0) {
        throw new LoomError("ENVELOPE_INVALID", `Invalid agent_info: ${agentInfoErrors.map((e) => `${e.field}: ${e.reason}`).join("; ")}`, 400, {
          field: "agent_info",
          validation_errors: agentInfoErrors
        });
      }
      normalizedAgentInfo = normalizeAgentInfo(identityDoc.agent_info);
    }

    const stored = {
      id: normalizedIdentity,
      type: identityDoc.type || "human",
      display_name: identityDoc.display_name || normalizedIdentity,
      signing_keys: normalizedSigningKeys,
      encryption_keys: normalizedEncryptionKeys,
      agent_info: normalizedAgentInfo,
      created_at: existingIdentity?.created_at || identityDoc.created_at || nowIso(),
      updated_at: nowIso(),
      identity_source: options.importedRemote === true ? "remote" : "local",
      imported_remote: options.importedRemote === true,
      remote_fetched_at: options.importedRemote === true ? nowIso() : null,
      remote_expires_at: remoteExpiresAt
    };

    if (existingIdentity) {
      this.removeIdentitySigningKeys(existingIdentity.id, existingIdentity.signing_keys);
      this.removeIdentityEncryptionKeys(existingIdentity.id, existingIdentity.encryption_keys);
    }
    this.applyIdentitySigningKeys(normalizedIdentity, normalizedSigningKeys);
    this.applyIdentityEncryptionKeys(normalizedIdentity, normalizedEncryptionKeys);

    targetMap.set(stored.id, stored);
    this.persistAndAudit("identity.register", {
      identity: stored.id,
      type: stored.type,
      imported_remote: options.importedRemote === true,
      proof_of_key: Boolean(registrationProof),
      encryption_key_count: stored.encryption_keys.length
    });
    return stored;
  }

  updateIdentity(identityUri, payload = {}, session = {}) {
    const normalizedIdentity = normalizeLoomIdentity(identityUri);
    if (!normalizedIdentity) {
      throw new LoomError("ENVELOPE_INVALID", "Identity id must be a loom:// URI", 400, {
        field: "id"
      });
    }

    const identity = this.identities.get(normalizedIdentity) || null;
    if (!identity) {
      if (this.remoteIdentities.has(normalizedIdentity)) {
        throw new LoomError("CAPABILITY_DENIED", "Remote imported identities are read-only", 403, {
          identity: normalizedIdentity
        });
      }
      throw new LoomError("IDENTITY_NOT_FOUND", `Identity not found: ${normalizedIdentity}`, 404, {
        identity: normalizedIdentity
      });
    }

    const actorIdentity = this.normalizeIdentityReference(session?.identity);
    if (actorIdentity !== normalizedIdentity) {
      throw new LoomError("CAPABILITY_DENIED", "Only identity owner may update identity document", 403, {
        actor: actorIdentity,
        identity: normalizedIdentity
      });
    }

    const actorKeyId = String(session?.key_id || "").trim();
    if (!actorKeyId || !this.resolveIdentitySigningKey(normalizedIdentity, actorKeyId)) {
      throw new LoomError("CAPABILITY_DENIED", "Authenticated session key is not authorized for identity update", 403, {
        actor: actorIdentity,
        key_id: actorKeyId
      });
    }

    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Identity update payload must be an object", 400, {
        field: "identity"
      });
    }

    const nextDisplayName =
      payload.display_name == null ? identity.display_name : String(payload.display_name || "").trim();
    if (!nextDisplayName) {
      throw new LoomError("ENVELOPE_INVALID", "display_name cannot be empty", 400, {
        field: "display_name"
      });
    }

    let nextSigningKeys = identity.signing_keys;
    if (payload.signing_keys != null) {
      if (!Array.isArray(payload.signing_keys) || payload.signing_keys.length === 0) {
        throw new LoomError("ENVELOPE_INVALID", "signing_keys must be a non-empty array when provided", 400, {
          field: "signing_keys"
        });
      }

      const normalizedSigningKeys = [];
      const seenKeyIds = new Set();
      for (const key of payload.signing_keys) {
        const keyId = String(key?.key_id || "").trim();
        const publicKeyPem = String(key?.public_key_pem || "").trim();
        if (!keyId || !publicKeyPem) {
          throw new LoomError("ENVELOPE_INVALID", "Signing key entries require key_id and public_key_pem", 400, {
            field: "signing_keys"
          });
        }

        if (this.reservedSigningKeyIds.has(keyId)) {
          throw new LoomError("ENVELOPE_INVALID", `Signing key id is reserved: ${keyId}`, 400, {
            field: "signing_keys.key_id",
            key_id: keyId
          });
        }

        if (seenKeyIds.has(keyId)) {
          throw new LoomError("ENVELOPE_INVALID", `Duplicate signing key id in identity payload: ${keyId}`, 400, {
            field: "signing_keys.key_id",
            key_id: keyId
          });
        }
        seenKeyIds.add(keyId);

        const existingOwner = this.keyOwnerById.get(keyId);
        if (existingOwner && existingOwner !== normalizedIdentity) {
          throw new LoomError("ENVELOPE_INVALID", `Signing key id is already assigned to another identity: ${keyId}`, 400, {
            field: "signing_keys.key_id",
            key_id: keyId
          });
        }

        const existingPublicKeyPem = this.publicKeysById.get(keyId);
        if (existingPublicKeyPem && existingPublicKeyPem !== publicKeyPem) {
          throw new LoomError("ENVELOPE_INVALID", `Signing key id already exists with a different public key: ${keyId}`, 400, {
            field: "signing_keys.key_id",
            key_id: keyId
          });
        }

        normalizedSigningKeys.push({
          key_id: keyId,
          public_key_pem: publicKeyPem
        });
      }

      normalizedSigningKeys.sort((left, right) => left.key_id.localeCompare(right.key_id));
      if (!normalizedSigningKeys.some((key) => key.key_id === actorKeyId)) {
        throw new LoomError("CAPABILITY_DENIED", "Identity rotation must retain the currently authenticated key", 403, {
          field: "signing_keys",
          key_id: actorKeyId
        });
      }

      nextSigningKeys = normalizedSigningKeys;
    }

    let nextEncryptionKeys = normalizeIdentityEncryptionKeys(identity.encryption_keys);
    const hasEncryptionKeysUpdate =
      Object.prototype.hasOwnProperty.call(payload, "encryption_keys") ||
      Object.prototype.hasOwnProperty.call(payload, "public_keys");
    if (hasEncryptionKeysUpdate) {
      const encryptionKeys = resolveIdentityEncryptionKeysInput(payload);
      if (!Array.isArray(encryptionKeys)) {
        throw new LoomError("ENVELOPE_INVALID", "encryption_keys must be an array when provided", 400, {
          field: "encryption_keys"
        });
      }

      const normalizedEncryptionKeys = [];
      const seenKeyIds = new Set();
      for (const key of encryptionKeys) {
        const keyId = String(key?.key_id || "").trim();
        const algorithm = normalizeIdentityEncryptionKeyAlgorithm(key?.algorithm);
        const publicKey = String(key?.public_key || "").trim();
        const publicKeyPem = String(key?.public_key_pem || "").trim();
        if (!keyId || !algorithm || (!publicKey && !publicKeyPem)) {
          throw new LoomError(
            "ENVELOPE_INVALID",
            "Encryption key entries require key_id, algorithm, and public_key or public_key_pem",
            400,
            {
              field: "encryption_keys"
            }
          );
        }

        if (seenKeyIds.has(keyId)) {
          throw new LoomError("ENVELOPE_INVALID", `Duplicate encryption key id in identity payload: ${keyId}`, 400, {
            field: "encryption_keys.key_id",
            key_id: keyId
          });
        }
        seenKeyIds.add(keyId);

        const existingOwner = this.encryptionKeyOwnerById.get(keyId);
        if (existingOwner && existingOwner !== normalizedIdentity) {
          throw new LoomError(
            "ENVELOPE_INVALID",
            `Encryption key id is already assigned to another identity: ${keyId}`,
            400,
            {
              field: "encryption_keys.key_id",
              key_id: keyId
            }
          );
        }

        const existing = this.encryptionKeysById.get(keyId);
        if (existing) {
          if (
            existing.algorithm !== algorithm ||
            (existing.public_key || null) !== (publicKey || null) ||
            (existing.public_key_pem || null) !== (publicKeyPem || null)
          ) {
            throw new LoomError("ENVELOPE_INVALID", `Encryption key id already exists with different key material: ${keyId}`, 400, {
              field: "encryption_keys.key_id",
              key_id: keyId
            });
          }
        }

        normalizedEncryptionKeys.push({
          key_id: keyId,
          algorithm,
          public_key: publicKey || null,
          public_key_pem: publicKeyPem || null,
          status: String(key?.status || "active")
            .trim()
            .toLowerCase() || "active",
          not_before: key?.not_before ? String(key.not_before).trim() : null,
          not_after: key?.not_after ? String(key.not_after).trim() : null,
          revoked_at: key?.revoked_at ? String(key.revoked_at).trim() : null
        });
      }

      normalizedEncryptionKeys.sort((left, right) => left.key_id.localeCompare(right.key_id));
      nextEncryptionKeys = normalizedEncryptionKeys;
    }

    // agent_info update — only for agent-type identities
    let nextAgentInfo = identity.agent_info || null;
    if (Object.prototype.hasOwnProperty.call(payload, "agent_info")) {
      if (payload.agent_info === null) {
        nextAgentInfo = null;
      } else {
        const identityType = String(identity.type || "human");
        if (identityType !== "agent") {
          throw new LoomError("ENVELOPE_INVALID", "agent_info is only allowed for agent-type identities", 400, {
            field: "agent_info",
            identity_type: identityType
          });
        }
        const agentInfoErrors = validateAgentInfo(payload.agent_info);
        if (agentInfoErrors.length > 0) {
          throw new LoomError("ENVELOPE_INVALID", `Invalid agent_info: ${agentInfoErrors.map((e) => `${e.field}: ${e.reason}`).join("; ")}`, 400, {
            field: "agent_info",
            validation_errors: agentInfoErrors
          });
        }
        nextAgentInfo = normalizeAgentInfo(payload.agent_info);
      }
    }

    const updated = {
      ...identity,
      display_name: nextDisplayName,
      signing_keys: nextSigningKeys,
      encryption_keys: nextEncryptionKeys,
      agent_info: nextAgentInfo,
      updated_at: nowIso(),
      identity_source: "local",
      imported_remote: false,
      remote_fetched_at: null,
      remote_expires_at: null
    };

    this.removeIdentitySigningKeys(identity.id, identity.signing_keys);
    this.removeIdentityEncryptionKeys(identity.id, identity.encryption_keys);
    this.applyIdentitySigningKeys(updated.id, updated.signing_keys);
    this.applyIdentityEncryptionKeys(updated.id, updated.encryption_keys);
    this.identities.set(updated.id, updated);

    this.persistAndAudit("identity.update", {
      identity: updated.id,
      actor: actorIdentity,
      key_id: actorKeyId,
      signing_key_count: updated.signing_keys.length,
      encryption_key_count: updated.encryption_keys.length
    });

    return updated;
  }

  resolveIdentity(identityUri) {
    const normalizedIdentity = this.normalizeIdentityReference(identityUri);
    if (!normalizedIdentity) {
      return null;
    }

    const localIdentity = this.identities.get(normalizedIdentity) || null;
    if (localIdentity) {
      return localIdentity;
    }

    const remoteIdentity = this.remoteIdentities.get(normalizedIdentity) || null;
    if (!remoteIdentity) {
      return null;
    }

    if (this.isRemoteIdentityExpired(remoteIdentity)) {
      this.purgeExpiredRemoteIdentity(normalizedIdentity);
      return null;
    }

    return remoteIdentity;
  }

  resolvePublicKey(keyId) {
    return this.publicKeysById.get(keyId) || null;
  }

  resolveKnownNodeById(nodeId) {
    const normalizedNodeId = String(nodeId || "").trim();
    if (!normalizedNodeId) {
      return null;
    }

    const direct = this.knownNodesById.get(normalizedNodeId);
    if (direct) {
      return direct;
    }

    const lower = normalizedNodeId.toLowerCase();
    for (const [knownNodeId, node] of this.knownNodesById.entries()) {
      if (String(knownNodeId || "").trim().toLowerCase() === lower) {
        return node;
      }
    }

    return null;
  }

  assertFederatedEnvelopeIdentityAuthority(envelope, verifiedNode) {
    return assertFederatedEnvelopeIdentityAuthorityPolicy.call(this, envelope, verifiedNode);
  }

  resolveFederationIdentityFetchUrl(node, identityUri) {
    const encodedIdentity = encodeURIComponent(identityUri);
    const explicitUrl = String(node?.identity_resolve_url || "").trim();
    if (explicitUrl) {
      try {
        if (explicitUrl.includes("{identity}")) {
          return new URL(explicitUrl.replace("{identity}", encodedIdentity));
        }

        const template = new URL(explicitUrl);
        if (template.pathname.endsWith("/")) {
          template.pathname = `${template.pathname}${encodedIdentity}`;
          return template;
        }
        template.pathname = `${template.pathname}/${encodedIdentity}`;
        return template;
      } catch {
        throw new LoomError("ENVELOPE_INVALID", "Federation node identity_resolve_url is invalid", 400, {
          node_id: node?.node_id || null,
          identity_resolve_url: explicitUrl
        });
      }
    }

    const deliverUrlRaw = String(node?.deliver_url || "").trim() || `https://${node?.node_id}/v1/federation/deliver`;
    let deliverUrl;
    try {
      deliverUrl = new URL(deliverUrlRaw);
    } catch {
      throw new LoomError("ENVELOPE_INVALID", "Federation node deliver_url is invalid", 400, {
        node_id: node?.node_id || null
      });
    }

    const base = `${deliverUrl.protocol}//${deliverUrl.host}`;
    return new URL(`/v1/identity/${encodedIdentity}`, base);
  }

  async fetchRemoteIdentityDocument(node, identityUri) {
    const identityUrl = this.resolveFederationIdentityFetchUrl(node, identityUri);
    const allowInsecureHttp = node?.allow_insecure_http === true;
    if (identityUrl.protocol !== "https:" && !(allowInsecureHttp && identityUrl.protocol === "http:")) {
      throw new LoomError("CAPABILITY_DENIED", "Remote identity fetch requires https unless node allows insecure http", 403, {
        node_id: node?.node_id || null,
        identity_url: identityUrl.toString()
      });
    }

    const allowedHosts =
      this.remoteIdentityHostAllowlist.length > 0
        ? this.remoteIdentityHostAllowlist
        : this.federationOutboundHostAllowlist;
    const outboundHostPolicy = await assertOutboundUrlHostAllowed(identityUrl, {
      allowPrivateNetwork: node?.allow_private_network === true,
      allowedHosts,
      denyMetadataHosts: this.denyMetadataHosts
    });

    let response;
    try {
      response = await performPinnedOutboundHttpRequest(identityUrl, {
        method: "GET",
        headers: {
          accept: "application/json"
        },
        timeoutMs: this.federationRemoteIdentityFetchTimeoutMs,
        maxResponseBytes: this.federationRemoteIdentityMaxResponseBytes,
        responseSizeContext: {
          identity: identityUri,
          node_id: node?.node_id || null
        },
        resolvedAddresses: outboundHostPolicy.resolvedAddresses,
        rejectRedirects: true
      });
    } catch (error) {
      if (error instanceof LoomError) {
        throw error;
      }
      if (error?.name === "AbortError") {
        throw new LoomError("DELIVERY_TIMEOUT", "Remote identity fetch timed out", 504, {
          identity: identityUri,
          node_id: node?.node_id || null,
          timeout_ms: this.federationRemoteIdentityFetchTimeoutMs
        });
      }

      throw new LoomError("NODE_UNREACHABLE", "Remote identity fetch failed", 502, {
        identity: identityUri,
        node_id: node?.node_id || null,
        reason: error?.message || String(error)
      });
    }

    if (!response.ok) {
      throw new LoomError("IDENTITY_NOT_FOUND", "Remote identity endpoint returned non-success status", 404, {
        identity: identityUri,
        node_id: node?.node_id || null,
        status: response.status
      });
    }

    let payload;
    try {
      payload = JSON.parse(response.bodyText);
    } catch (error) {
      if (error instanceof LoomError) {
        throw error;
      }
      throw new LoomError("ENVELOPE_INVALID", "Remote identity response must be valid JSON", 400, {
        identity: identityUri,
        node_id: node?.node_id || null
      });
    }

    this.verifyRemoteIdentityDocumentSignature(payload, node);

    return payload;
  }

  verifyRemoteIdentityDocumentSignature(identityDocument, node) {
    if (this.federationRequireSignedRemoteIdentity !== true) {
      return;
    }

    const signature = identityDocument?.node_signature;
    if (!signature || typeof signature !== "object") {
      throw new LoomError("SIGNATURE_INVALID", "Remote identity document signature is required", 401, {
        field: "node_signature",
        node_id: node?.node_id || null
      });
    }

    const algorithm = String(signature.algorithm || "").trim();
    const keyId = String(signature.key_id || "").trim();
    const value = String(signature.value || "").trim();
    if (algorithm !== "Ed25519" || !keyId || !value) {
      throw new LoomError("SIGNATURE_INVALID", "Remote identity document signature is invalid", 401, {
        field: "node_signature",
        node_id: node?.node_id || null
      });
    }

    const signingKey = resolveFederationNodeSigningKey(node, keyId);
    if (!signingKey) {
      throw new LoomError("SIGNATURE_INVALID", "Remote identity document signature key is not trusted for node", 401, {
        field: "node_signature.key_id",
        node_id: node?.node_id || null,
        key_id: keyId
      });
    }

    const canonicalIdentity = buildIdentityRegistrationDocument({
      identity: identityDocument?.id,
      type: identityDocument?.type || "human",
      displayName: identityDocument?.display_name || identityDocument?.id,
      signingKeys: Array.isArray(identityDocument?.signing_keys) ? identityDocument.signing_keys : [],
      encryptionKeys: resolveIdentityEncryptionKeysInput(identityDocument),
      agentInfo: identityDocument?.agent_info || null
    });
    const canonicalPayload = canonicalizeJson(canonicalIdentity);
    const valid = verifyUtf8MessageSignature(signingKey.public_key_pem, canonicalPayload, value);
    if (!valid) {
      throw new LoomError("SIGNATURE_INVALID", "Remote identity document signature verification failed", 401, {
        field: "node_signature",
        node_id: node?.node_id || null,
        key_id: keyId
      });
    }
  }

  async ensureFederatedSenderIdentity(envelope, verifiedNode) {
    const { fromIdentity, identityDomain } = this.assertFederatedEnvelopeIdentityAuthority(envelope, verifiedNode);

    const currentIdentity = this.resolveIdentity(fromIdentity);
    const signingKeyId = String(envelope?.signature?.key_id || envelope?.from?.key_id || "").trim();
    if (currentIdentity && this.resolveIdentitySigningKey(fromIdentity, signingKeyId)) {
      return currentIdentity;
    }

    if (!this.federationResolveRemoteIdentities) {
      throw new LoomError("IDENTITY_NOT_FOUND", "Federated sender identity is not registered locally", 404, {
        identity: fromIdentity
      });
    }

    const authorityNode = this.resolveKnownNodeById(verifiedNode?.node_id || identityDomain);
    if (!authorityNode) {
      throw new LoomError("IDENTITY_NOT_FOUND", "Federation authority node for sender identity is unknown", 404, {
        identity: fromIdentity,
        identity_domain: identityDomain
      });
    }

    const remotePayload = await this.fetchRemoteIdentityDocument(authorityNode, fromIdentity);
    const normalizedRemoteIdentity = normalizeLoomIdentity(remotePayload?.id);
    if (!normalizedRemoteIdentity || normalizedRemoteIdentity !== fromIdentity) {
      throw new LoomError("SIGNATURE_INVALID", "Remote identity document id does not match sender identity", 401, {
        expected_identity: fromIdentity,
        actual_identity: remotePayload?.id || null
      });
    }

    const remoteSigningKeys = Array.isArray(remotePayload?.signing_keys) ? remotePayload.signing_keys : [];
    if (remoteSigningKeys.length === 0) {
      throw new LoomError("SIGNATURE_INVALID", "Remote identity document must include signing_keys", 401, {
        identity: fromIdentity
      });
    }

    return this.registerIdentity(
      {
        ...remotePayload,
        id: fromIdentity
      },
      {
        importedRemote: true,
        allowOverwrite: true,
        allowRemoteDomain: true,
        requireProofOfKey: false,
        remoteExpiresAt: new Date(nowMs() + this.remoteIdentityTtlMs).toISOString()
      }
    );
  }

  createAuthChallenge({ identity, key_id }) {
    const normalizedIdentity = this.normalizeIdentityReference(identity);
    const identityDoc = this.resolveIdentity(normalizedIdentity);
    if (!identityDoc) {
      throw new LoomError("IDENTITY_NOT_FOUND", `Identity not found: ${normalizedIdentity || identity}`, 404, {
        identity: normalizedIdentity || identity
      });
    }

    if (identityDoc.imported_remote === true || identityDoc.identity_source === "remote") {
      throw new LoomError("CAPABILITY_DENIED", "Authentication challenge is only available for local identities", 403, {
        identity: identityDoc.id
      });
    }

    const signingKey = this.resolveIdentitySigningKey(identityDoc.id, key_id);
    if (!signingKey) {
      throw new LoomError("SIGNATURE_INVALID", `Unknown signing key for identity: ${key_id}`, 401, {
        field: "key_id"
      });
    }

    const challengeId = `chl_${generateUlid()}`;
    const nonce = `nonce_${generateUlid()}`;
    const expiresAt = new Date(nowMs() + 2 * 60 * 1000).toISOString();

    this.authChallenges.set(challengeId, {
      challenge_id: challengeId,
      identity: identityDoc.id,
      key_id,
      nonce,
      expires_at: expiresAt,
      used: false,
      created_at: nowIso()
    });

    return {
      challenge_id: challengeId,
      identity: identityDoc.id,
      key_id,
      nonce,
      expires_at: expiresAt,
      algorithm: "Ed25519"
    };
  }

  exchangeAuthToken({ identity, key_id, challenge_id, signature }) {
    const challenge = this.authChallenges.get(challenge_id);
    if (!challenge) {
      throw new LoomError("SIGNATURE_INVALID", "Challenge not found", 401, {
        field: "challenge_id"
      });
    }

    if (challenge.used) {
      throw new LoomError("SIGNATURE_INVALID", "Challenge already used", 401, {
        field: "challenge_id"
      });
    }

    if (isExpiredIso(challenge.expires_at)) {
      throw new LoomError("SIGNATURE_INVALID", "Challenge expired", 401, {
        field: "challenge_id"
      });
    }

    const normalizedIdentity = this.normalizeIdentityReference(identity);
    if (challenge.identity !== normalizedIdentity || challenge.key_id !== key_id) {
      throw new LoomError("SIGNATURE_INVALID", "Challenge identity/key mismatch", 401, {
        field: "identity"
      });
    }

    const publicKeyPem = this.resolveIdentitySigningPublicKey(challenge.identity, key_id);
    if (!publicKeyPem) {
      throw new LoomError("SIGNATURE_INVALID", `Unknown signing key for identity: ${key_id}`, 401, {
        field: "key_id"
      });
    }

    if (!signature || typeof signature !== "string") {
      throw new LoomError("SIGNATURE_INVALID", "Missing challenge signature", 401, {
        field: "signature"
      });
    }

    const valid = verifyUtf8MessageSignature(publicKeyPem, challenge.nonce, signature);
    if (!valid) {
      throw new LoomError("SIGNATURE_INVALID", "Challenge signature verification failed", 401, {
        field: "signature"
      });
    }

    challenge.used = true;

    const accessToken = `at_${randomUUID().replace(/-/g, "")}`;
    const refreshToken = `rt_${randomUUID().replace(/-/g, "")}`;
    const accessExpiresAt = new Date(nowMs() + 60 * 60 * 1000).toISOString();
    const refreshExpiresAt = new Date(nowMs() + 30 * 24 * 60 * 60 * 1000).toISOString();

    this.accessTokens.set(accessToken, {
      access_token: accessToken,
      identity: challenge.identity,
      key_id,
      created_at: nowIso(),
      expires_at: accessExpiresAt
    });

    this.refreshTokens.set(refreshToken, {
      refresh_token: refreshToken,
      identity: challenge.identity,
      key_id,
      created_at: nowIso(),
      expires_at: refreshExpiresAt
    });

    return {
      token_type: "Bearer",
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600,
      identity: challenge.identity,
      key_id
    };
  }

  refreshAuthToken({ refresh_token }) {
    const session = this.refreshTokens.get(refresh_token);
    if (!session || isExpiredIso(session.expires_at)) {
      throw new LoomError("SIGNATURE_INVALID", "Refresh token invalid or expired", 401, {
        field: "refresh_token"
      });
    }

    const accessToken = `at_${randomUUID().replace(/-/g, "")}`;
    const accessExpiresAt = new Date(nowMs() + 60 * 60 * 1000).toISOString();

    this.accessTokens.set(accessToken, {
      access_token: accessToken,
      identity: session.identity,
      key_id: session.key_id,
      created_at: nowIso(),
      expires_at: accessExpiresAt
    });

    return {
      token_type: "Bearer",
      access_token: accessToken,
      expires_in: 3600,
      identity: session.identity,
      key_id: session.key_id
    };
  }

  authenticateAccessToken(accessToken) {
    if (!accessToken) {
      throw new LoomError("SIGNATURE_INVALID", "Missing bearer token", 401, {
        field: "authorization"
      });
    }

    const session = this.accessTokens.get(accessToken);
    if (!session || isExpiredIso(session.expires_at)) {
      throw new LoomError("SIGNATURE_INVALID", "Access token invalid or expired", 401, {
        field: "authorization"
      });
    }

    return session;
  }

  isIdentitySensitiveRoute(method, path) {
    return isIdentitySensitiveRoutePolicy(method, path);
  }

  enforceIdentityRateLimit({ identity, method = "GET", path = "/" } = {}) {
    return enforceIdentityRateLimitPolicy.call(this, { identity, method, path });
  }

  createDelegation(payload, actorIdentity) {
    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Delegation payload must be an object", 400, {
        field: "delegation"
      });
    }

    const delegator = payload.delegator || actorIdentity;
    if (delegator !== actorIdentity) {
      throw new LoomError("DELEGATION_INVALID", "Authenticated actor must be the delegator", 403, {
        actor: actorIdentity,
        delegator
      });
    }

    if (!isIdentity(payload.delegate)) {
      throw new LoomError("ENVELOPE_INVALID", "Delegation requires valid delegate identity", 400, {
        field: "delegate"
      });
    }

    const signedDelegation = {
      id: payload.id || `dlg_${generateUlid()}`,
      delegator,
      delegate: payload.delegate,
      scope: payload.scope,
      created_at: payload.created_at || nowIso(),
      expires_at: payload.expires_at || null,
      revocable: payload.revocable ?? true,
      allow_sub_delegation: payload.allow_sub_delegation ?? false,
      max_sub_delegation_depth: payload.max_sub_delegation_depth ?? 0,
      key_id: payload.key_id || null,
      signature: payload.signature
    };

    const delegation = {
      ...signedDelegation,
      revoked: false,
      revoked_at: null
    };

    if (this.delegationsById.has(delegation.id)) {
      throw new LoomError("ENVELOPE_DUPLICATE", `Delegation id already exists: ${delegation.id}`, 409, {
        delegation_id: delegation.id
      });
    }

    verifyDelegationLinkOrThrow(signedDelegation, {
      resolveIdentity: (identity) => this.resolveIdentity(identity),
      resolvePublicKey: (keyId) => this.resolvePublicKey(keyId)
    });

    if (this.maxDelegationsTotal > 0 && this.delegationsById.size >= this.maxDelegationsTotal) {
      throw new LoomError("RESOURCE_LIMIT", `Maximum total delegation count reached (${this.maxDelegationsTotal})`, 403, {
        limit: this.maxDelegationsTotal,
        current: this.delegationsById.size
      });
    }

    if (this.maxDelegationsPerIdentity > 0) {
      let delegatorCount = 0;
      for (const d of this.delegationsById.values()) {
        if (d.delegator === delegation.delegator) {
          delegatorCount += 1;
        }
      }
      if (delegatorCount >= this.maxDelegationsPerIdentity) {
        throw new LoomError("RESOURCE_LIMIT", `Maximum delegations per identity reached (${this.maxDelegationsPerIdentity})`, 403, {
          limit: this.maxDelegationsPerIdentity,
          current: delegatorCount,
          identity: delegation.delegator
        });
      }
    }

    this.delegationsById.set(delegation.id, delegation);
    this.persistAndAudit("delegation.create", {
      delegation_id: delegation.id,
      delegator: delegation.delegator,
      delegate: delegation.delegate
    });
    return delegation;
  }

  listDelegations(actorIdentity, role = "all") {
    const all = Array.from(this.delegationsById.values()).sort((a, b) => a.created_at.localeCompare(b.created_at));

    if (role === "delegator") {
      return all.filter((delegation) => delegation.delegator === actorIdentity);
    }

    if (role === "delegate") {
      return all.filter((delegation) => delegation.delegate === actorIdentity);
    }

    return all.filter(
      (delegation) => delegation.delegator === actorIdentity || delegation.delegate === actorIdentity
    );
  }

  revokeDelegation(delegationId, actorIdentity) {
    const delegation = this.delegationsById.get(delegationId);
    if (!delegation) {
      throw new LoomError("DELEGATION_INVALID", `Delegation not found: ${delegationId}`, 403, {
        delegation_id: delegationId
      });
    }

    if (delegation.delegator !== actorIdentity) {
      throw new LoomError("DELEGATION_INVALID", "Only delegator may revoke delegation", 403, {
        delegation_id: delegationId,
        actor: actorIdentity
      });
    }

    if (!delegation.revoked) {
      delegation.revoked = true;
      delegation.revoked_at = nowIso();
      this.revokedDelegationIds.add(delegation.id);
      this.persistAndAudit("delegation.revoke", {
        delegation_id: delegation.id,
        delegator: delegation.delegator
      });
    }

    return delegation;
  }

  isDelegationRevoked(link) {
    if (!link || typeof link !== "object") {
      return false;
    }

    if (link.id && this.revokedDelegationIds.has(link.id)) {
      return true;
    }

    if (link.id) {
      const stored = this.delegationsById.get(link.id);
      if (stored?.revoked) {
        return true;
      }
    }

    return false;
  }

  createBlob(payload, actorIdentity) {
    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Blob payload must be an object", 400, {
        field: "blob"
      });
    }

    // Protocol-level validation (non-fatal: store handles required fields)
    if (payload.size_bytes && payload.filename && payload.mime_type) {
      const blobErrors = validateBlobInitiation(payload);
      if (blobErrors.length > 0) {
        throw new LoomError("ENVELOPE_INVALID", blobErrors[0].reason, 400, {
          field: blobErrors[0].field,
          errors: blobErrors
        });
      }
    }

    const threadId = payload.thread_id || null;
    if (threadId) {
      const thread = this.threadsById.get(threadId);
      if (!thread) {
        throw new LoomError("THREAD_NOT_FOUND", `Thread not found: ${threadId}`, 404, {
          thread_id: threadId
        });
      }

      if (!this.isActiveParticipant(thread, actorIdentity)) {
        throw new LoomError("CAPABILITY_DENIED", "Only thread participants may attach blobs", 403, {
          actor: actorIdentity,
          thread_id: threadId
        });
      }
    }

    const createdAt = nowIso();
    this.enforceBlobDailyCountQuota(actorIdentity, createdAt);

    const requestedSizeBytes = Number(payload.size_bytes || 0);
    if (!Number.isFinite(requestedSizeBytes) || requestedSizeBytes < 0) {
      throw new LoomError("ENVELOPE_INVALID", "size_bytes must be a non-negative number", 400, {
        field: "size_bytes"
      });
    }

    if (requestedSizeBytes > this.blobMaxBytes) {
      throw new LoomError("PAYLOAD_TOO_LARGE", "Blob size exceeds configured max", 413, {
        field: "size_bytes",
        size_bytes: requestedSizeBytes,
        max_blob_bytes: this.blobMaxBytes
      });
    }

    const blob = {
      id: `blob_${generateUlid()}`,
      created_by: actorIdentity,
      thread_id: threadId,
      filename: payload.filename || null,
      mime_type: payload.mime_type || "application/octet-stream",
      size_bytes: requestedSizeBytes,
      created_at: createdAt,
      completed_at: null,
      status: "pending",
      parts: {},
      data_base64: null,
      hash: null,
      quota_accounted_bytes: 0
    };

    this.blobsById.set(blob.id, blob);
    this.trackBlobDailyCountQuota(actorIdentity, createdAt);
    this.persistAndAudit("blob.create", {
      blob_id: blob.id,
      actor: actorIdentity,
      thread_id: threadId
    });

    return {
      blob_id: blob.id,
      status: blob.status
    };
  }

  putBlobPart(blobId, partNumber, payload, actorIdentity) {
    const blob = this.blobsById.get(blobId);
    if (!blob) {
      throw new LoomError("ENVELOPE_NOT_FOUND", `Blob not found: ${blobId}`, 404, {
        blob_id: blobId
      });
    }

    const thread = blob.thread_id ? this.threadsById.get(blob.thread_id) : null;
    const canUseThread = thread ? this.isActiveParticipant(thread, actorIdentity) : false;

    if (!(blob.created_by === actorIdentity || canUseThread)) {
      throw new LoomError("CAPABILITY_DENIED", "Not authorized to upload blob part", 403, {
        blob_id: blobId,
        actor: actorIdentity
      });
    }

    if (blob.status === "complete") {
      throw new LoomError("STATE_TRANSITION_INVALID", "Blob is already complete", 409, {
        blob_id: blobId
      });
    }

    const dataBase64 = payload?.data_base64;
    if (typeof dataBase64 !== "string" || dataBase64.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "Blob part payload requires data_base64", 400, {
        field: "data_base64"
      });
    }

    let partBuffer;
    try {
      partBuffer = Buffer.from(dataBase64, "base64");
    } catch {
      throw new LoomError("ENVELOPE_INVALID", "data_base64 is not valid base64", 400, {
        field: "data_base64"
      });
    }

    if (partBuffer.byteLength > this.blobMaxPartBytes) {
      throw new LoomError("PAYLOAD_TOO_LARGE", "Blob part exceeds configured max", 413, {
        field: "data_base64",
        part_size_bytes: partBuffer.byteLength,
        max_blob_part_bytes: this.blobMaxPartBytes
      });
    }

    const partKey = String(partNumber);
    const existingPartKeys = Object.keys(blob.parts || {});
    if (!Object.prototype.hasOwnProperty.call(blob.parts, partKey) && existingPartKeys.length >= this.blobMaxParts) {
      throw new LoomError("PAYLOAD_TOO_LARGE", "Blob part count exceeds configured max", 413, {
        blob_id: blobId,
        max_blob_parts: this.blobMaxParts
      });
    }

    let projectedBytes = partBuffer.byteLength;
    for (const existingKey of existingPartKeys) {
      if (existingKey === partKey) {
        continue;
      }
      projectedBytes += Buffer.from(blob.parts[existingKey], "base64").byteLength;
    }
    if (projectedBytes > this.blobMaxBytes) {
      throw new LoomError("PAYLOAD_TOO_LARGE", "Blob accumulated size exceeds configured max", 413, {
        blob_id: blobId,
        projected_size_bytes: projectedBytes,
        max_blob_bytes: this.blobMaxBytes
      });
    }

    blob.parts[partKey] = dataBase64;
    this.persistAndAudit("blob.part.put", {
      blob_id: blobId,
      part_number: Number(partNumber),
      actor: actorIdentity
    });

    return {
      blob_id: blob.id,
      part_number: Number(partNumber),
      status: "part_uploaded"
    };
  }

  completeBlob(blobId, actorIdentity) {
    const blob = this.blobsById.get(blobId);
    if (!blob) {
      throw new LoomError("ENVELOPE_NOT_FOUND", `Blob not found: ${blobId}`, 404, {
        blob_id: blobId
      });
    }

    const thread = blob.thread_id ? this.threadsById.get(blob.thread_id) : null;
    const canUseThread = thread ? this.isActiveParticipant(thread, actorIdentity) : false;

    if (!(blob.created_by === actorIdentity || canUseThread)) {
      throw new LoomError("CAPABILITY_DENIED", "Not authorized to complete blob", 403, {
        blob_id: blobId,
        actor: actorIdentity
      });
    }

    const orderedPartNumbers = Object.keys(blob.parts)
      .map((value) => Number(value))
      .filter((value) => Number.isFinite(value) && value > 0)
      .sort((a, b) => a - b);

    if (orderedPartNumbers.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "Cannot complete blob with no parts", 400, {
        blob_id: blobId
      });
    }

    const buffers = orderedPartNumbers.map((number) => Buffer.from(blob.parts[String(number)], "base64"));
    const joined = Buffer.concat(buffers);

    if (joined.byteLength > this.blobMaxBytes) {
      throw new LoomError("PAYLOAD_TOO_LARGE", "Blob size exceeds configured max", 413, {
        blob_id: blobId,
        size_bytes: joined.byteLength,
        max_blob_bytes: this.blobMaxBytes
      });
    }

    const accountedBytes = Math.max(0, Number(blob.quota_accounted_bytes || 0));
    const additionalBytes = Math.max(0, joined.byteLength - accountedBytes);
    const completedAt = nowIso();
    this.enforceBlobByteQuotas(blob.created_by, additionalBytes, completedAt);

    blob.data_base64 = joined.toString("base64");
    blob.size_bytes = joined.byteLength;
    blob.hash = `sha256:${createHash("sha256").update(joined).digest("hex")}`;
    blob.status = "complete";
    blob.completed_at = completedAt;
    blob.quota_accounted_bytes = Math.max(accountedBytes, joined.byteLength);
    this.trackBlobByteQuotas(blob.created_by, additionalBytes, completedAt);

    this.persistAndAudit("blob.complete", {
      blob_id: blobId,
      actor: actorIdentity,
      size_bytes: blob.size_bytes
    });

    return {
      blob_id: blob.id,
      status: blob.status,
      size_bytes: blob.size_bytes,
      hash: blob.hash
    };
  }

  getBlob(blobId, actorIdentity) {
    const blob = this.blobsById.get(blobId);
    if (!blob) {
      return null;
    }

    const thread = blob.thread_id ? this.threadsById.get(blob.thread_id) : null;
    const isAuthorized =
      blob.created_by === actorIdentity || (thread ? this.isActiveParticipant(thread, actorIdentity) : false);

    if (!isAuthorized) {
      throw new LoomError("CAPABILITY_DENIED", "Not authorized to read blob", 403, {
        blob_id: blobId,
        actor: actorIdentity
      });
    }

    return {
      id: blob.id,
      created_by: blob.created_by,
      thread_id: blob.thread_id,
      filename: blob.filename,
      mime_type: blob.mime_type,
      size_bytes: blob.size_bytes,
      status: blob.status,
      hash: blob.hash,
      created_at: blob.created_at,
      completed_at: blob.completed_at,
      data_base64: blob.data_base64
    };
  }

  isThreadOwner(thread, identityUri) {
    return thread.participants.some(
      (participant) => participant.identity === identityUri && participant.role === "owner" && participant.left_at == null
    );
  }

  isActiveParticipant(thread, identityUri) {
    return thread.participants.some(
      (participant) => participant.identity === identityUri && participant.left_at == null
    );
  }

  getActiveParticipantIdentities(thread) {
    if (!thread || !Array.isArray(thread.participants)) {
      return [];
    }
    return thread.participants
      .filter((participant) => participant?.left_at == null)
      .map((participant) => String(participant.identity || "").trim())
      .filter(Boolean);
  }

  getE2eeProfileSecurityRank(profileId) {
    const resolved = resolveE2eeProfile(profileId);
    const canonicalId = resolved?.id || String(profileId || "").trim();
    if (!canonicalId) {
      return null;
    }
    const rank = Number(E2EE_PROFILE_SECURITY_RANK.get(canonicalId));
    return Number.isFinite(rank) ? rank : null;
  }

  assertE2eeProfileMigrationPolicy(fromProfileId, toProfileId, context = {}) {
    const fromResolved = resolveE2eeProfile(fromProfileId);
    const toResolved = resolveE2eeProfile(toProfileId);
    const fromCanonical = fromResolved?.id || String(fromProfileId || "").trim();
    const toCanonical = toResolved?.id || String(toProfileId || "").trim();

    if (!fromCanonical || !toCanonical) {
      throw new LoomError("STATE_TRANSITION_INVALID", "E2EE profile migration requires valid source and destination profiles", 409, {
        thread_id: context.thread_id || null,
        from_profile: fromCanonical || null,
        to_profile: toCanonical || null
      });
    }

    if (fromCanonical === toCanonical) {
      return {
        allowed: true,
        reason: "same_profile"
      };
    }

    const allowlistKey = `${fromCanonical.toLowerCase()}>${toCanonical.toLowerCase()}`;
    if (this.e2eeProfileMigrationAllowlist.has(allowlistKey)) {
      return {
        allowed: true,
        reason: "allowlist"
      };
    }

    const fromRank = this.getE2eeProfileSecurityRank(fromCanonical);
    const toRank = this.getE2eeProfileSecurityRank(toCanonical);
    if (Number.isFinite(fromRank) && Number.isFinite(toRank) && toRank > fromRank) {
      return {
        allowed: true,
        reason: "rank_upgrade",
        from_rank: fromRank,
        to_rank: toRank
      };
    }

    throw new LoomError("STATE_TRANSITION_INVALID", "E2EE profile migration is not permitted by policy", 409, {
      thread_id: context.thread_id || null,
      envelope_id: context.envelope_id || null,
      from_profile: fromCanonical,
      to_profile: toCanonical,
      from_rank: fromRank,
      to_rank: toRank,
      allowlist_entry_required: true
    });
  }

  sanitizeCapabilityToken(token, options = {}) {
    if (!token) {
      return null;
    }

    const sanitized = {
      loom: token.loom,
      id: token.id,
      thread_id: token.thread_id,
      issued_by: token.issued_by,
      issued_to: token.issued_to,
      created_at: token.created_at,
      expires_at: token.expires_at,
      single_use: token.single_use,
      epoch: token.epoch,
      grants: Array.isArray(token.grants) ? [...token.grants] : [],
      revoked: Boolean(token.revoked),
      revoked_at: token.revoked_at || null,
      spent: Boolean(token.spent),
      spent_at: token.spent_at || null,
      secret_hint: token.secret_hint || null,
      secret_last_used_at: token.secret_last_used_at || null
    };

    if (options.includePresentationToken === true && options.presentationToken) {
      sanitized.presentation_token = options.presentationToken;
    }
    if (options.includePortableToken === true && token?.portable_token) {
      sanitized.portable_token = structuredClone(token.portable_token);
    }

    return sanitized;
  }

  issuePortableCapabilityToken(token) {
    if (!token || typeof token !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Capability token payload is required", 400, {
        field: "capability"
      });
    }

    const signingPrivateKeyPem = this.federationSigningPrivateKeyPem || this.systemSigningPrivateKeyPem;
    const signingKeyId = String(this.federationSigningKeyId || this.systemSigningKeyId || "").trim();
    if (!signingPrivateKeyPem || !signingKeyId) {
      throw new LoomError("SIGNATURE_INVALID", "Capability token signing key is not configured", 500, {
        field: "signature"
      });
    }

    const unsignedToken = buildPortableCapabilityTokenPayload({
      ...token,
      issuer_node: this.nodeId
    });

    const signature = signUtf8Message(signingPrivateKeyPem, canonicalizePortableCapabilityToken(unsignedToken));
    return {
      ...unsignedToken,
      signature: {
        algorithm: "Ed25519",
        key_id: signingKeyId,
        value: signature
      }
    };
  }

  issueCapabilityToken(payload, issuedBy) {
    const threadId = payload?.thread_id;
    const thread = this.threadsById.get(threadId);

    if (!thread) {
      throw new LoomError("THREAD_NOT_FOUND", `Thread not found: ${threadId}`, 404, {
        thread_id: threadId
      });
    }

    if (!this.isThreadOwner(thread, issuedBy)) {
      throw new LoomError("CAPABILITY_DENIED", "Only thread owner can issue capability tokens", 403, {
        actor: issuedBy,
        thread_id: threadId
      });
    }

    if (!isIdentity(payload?.issued_to)) {
      throw new LoomError("ENVELOPE_INVALID", "Capability issued_to must be a valid identity URI", 400, {
        field: "issued_to"
      });
    }

    const presentationToken = `cpt_${randomUUID().replace(/-/g, "")}`;
    const token = {
      loom: "1.1",
      id: `cap_${generateUlid()}`,
      thread_id: threadId,
      issued_by: issuedBy,
      issued_to: payload.issued_to,
      created_at: nowIso(),
      expires_at: payload.expires_at || null,
      single_use: Boolean(payload.single_use),
      epoch: thread.cap_epoch,
      grants: normalizeGrants(payload.grants),
      revoked: false,
      revoked_at: null,
      spent: false,
      spent_at: null,
      secret_hash: hashCapabilityPresentationToken(presentationToken),
      secret_hint: presentationToken.slice(-6),
      secret_last_used_at: null,
      portable_token: null
    };

    if (token.expires_at && parseTime(token.expires_at) == null) {
      throw new LoomError("ENVELOPE_INVALID", "Capability expires_at must be ISO-8601", 400, {
        field: "expires_at"
      });
    }

    token.portable_token = this.issuePortableCapabilityToken(token);

    this.capabilitiesById.set(token.id, token);
    this.capabilityIdBySecretHash.set(token.secret_hash, token.id);
    this.persistAndAudit("capability.issue", {
      capability_id: token.id,
      thread_id: token.thread_id,
      issued_by: token.issued_by,
      issued_to: token.issued_to,
      portable_token_signing_key: token.portable_token?.signature?.key_id || null
    });
    return this.sanitizeCapabilityToken(token, {
      includePresentationToken: true,
      presentationToken,
      includePortableToken: true
    });
  }

  listCapabilities(threadId, actorIdentity) {
    const thread = this.threadsById.get(threadId);
    if (!thread) {
      throw new LoomError("THREAD_NOT_FOUND", `Thread not found: ${threadId}`, 404, {
        thread_id: threadId
      });
    }

    if (!this.isActiveParticipant(thread, actorIdentity)) {
      throw new LoomError("CAPABILITY_DENIED", "Only thread participants can list capabilities", 403, {
        actor: actorIdentity,
        thread_id: threadId
      });
    }

    return Array.from(this.capabilitiesById.values())
      .filter((token) => token.thread_id === threadId)
      .sort((a, b) => a.created_at.localeCompare(b.created_at))
      .map((token) => this.sanitizeCapabilityToken(token));
  }

  revokeCapabilityToken(capabilityId, actorIdentity) {
    const token = this.capabilitiesById.get(capabilityId);
    if (!token) {
      throw new LoomError("CAPABILITY_DENIED", `Capability token not found: ${capabilityId}`, 403, {
        capability_id: capabilityId
      });
    }

    const thread = this.threadsById.get(token.thread_id);
    if (!thread) {
      throw new LoomError("THREAD_NOT_FOUND", `Thread not found: ${token.thread_id}`, 404, {
        thread_id: token.thread_id
      });
    }

    if (!(token.issued_by === actorIdentity || this.isThreadOwner(thread, actorIdentity))) {
      throw new LoomError("CAPABILITY_DENIED", "Not authorized to revoke this capability token", 403, {
        actor: actorIdentity,
        capability_id: capabilityId
      });
    }

    if (!token.revoked) {
      token.revoked = true;
      token.revoked_at = nowIso();
      thread.cap_epoch += 1;
      thread.updated_at = nowIso();
      this.persistAndAudit("capability.revoke", {
        capability_id: token.id,
        thread_id: token.thread_id,
        actor: actorIdentity
      });
    }

    return this.sanitizeCapabilityToken(token);
  }

  resolveCapabilityTokenByPresentation({ capabilityTokenValue, capabilityTokenId = null }) {
    const normalizedValue = String(capabilityTokenValue || "").trim();
    if (!normalizedValue) {
      return null;
    }

    const hashed = hashCapabilityPresentationToken(normalizedValue);
    if (capabilityTokenId) {
      const token = this.capabilitiesById.get(capabilityTokenId) || null;
      if (!token) {
        return null;
      }
      return token.secret_hash === hashed ? token : null;
    }

    const resolvedId = this.capabilityIdBySecretHash.get(hashed);
    if (!resolvedId) {
      return null;
    }
    return this.capabilitiesById.get(resolvedId) || null;
  }

  resolvePortableCapabilitySigningPublicKey(portableToken, context = {}) {
    const signatureKeyId = String(portableToken?.signature?.key_id || "").trim();
    if (!signatureKeyId) {
      throw new LoomError("SIGNATURE_INVALID", "Portable capability token signature key_id is required", 401, {
        field: "content.structured.parameters.capability_token.signature.key_id"
      });
    }

    const issuerNodeId = String(portableToken?.issuer_node || "").trim();
    if (!issuerNodeId) {
      throw new LoomError("CAPABILITY_DENIED", "Portable capability token issuer_node is required", 403, {
        field: "content.structured.parameters.capability_token.issuer_node"
      });
    }

    if (context?.federated === true && context?.federationNode?.node_id) {
      const expectedNodeId = String(context.federationNode.node_id || "").trim().toLowerCase();
      if (issuerNodeId.toLowerCase() !== expectedNodeId) {
        throw new LoomError("CAPABILITY_DENIED", "Portable capability token issuer_node must match federation sender node", 403, {
          field: "content.structured.parameters.capability_token.issuer_node",
          issuer_node: issuerNodeId,
          sender_node: context.federationNode.node_id
        });
      }
    }

    if (issuerNodeId.toLowerCase() === String(this.nodeId || "").trim().toLowerCase()) {
      if (signatureKeyId !== this.federationSigningKeyId) {
        throw new LoomError("SIGNATURE_INVALID", "Portable capability token key_id is not authorized for local issuer node", 401, {
          field: "content.structured.parameters.capability_token.signature.key_id",
          key_id: signatureKeyId
        });
      }

      try {
        return derivePublicKeyPemFromPrivateKeyPem(this.federationSigningPrivateKeyPem);
      } catch {
        throw new LoomError("SIGNATURE_INVALID", "Unable to derive local federation signing public key", 500, {
          field: "content.structured.parameters.capability_token.signature.key_id"
        });
      }
    }

    const knownNode = context?.federationNode || this.resolveKnownNodeById(issuerNodeId);
    if (!knownNode) {
      throw new LoomError("CAPABILITY_DENIED", "Portable capability token issuer node is unknown", 403, {
        field: "content.structured.parameters.capability_token.issuer_node",
        issuer_node: issuerNodeId
      });
    }

    const signingKey = resolveFederationNodeSigningKey(knownNode, signatureKeyId);
    if (!signingKey) {
      throw new LoomError("SIGNATURE_INVALID", "Portable capability token signature key is not trusted for issuer node", 401, {
        field: "content.structured.parameters.capability_token.signature.key_id",
        issuer_node: issuerNodeId,
        key_id: signatureKeyId
      });
    }

    return signingKey.public_key_pem;
  }

  validatePortableCapabilityTokenForThreadOperation({
    thread,
    actorIdentity,
    requiredGrant,
    portableCapabilityToken,
    context = {}
  }) {
    if (!portableCapabilityToken || typeof portableCapabilityToken !== "object" || Array.isArray(portableCapabilityToken)) {
      throw new LoomError("CAPABILITY_DENIED", "Portable capability token is invalid", 403, {
        field: "content.structured.parameters.capability_token"
      });
    }

    const signature = portableCapabilityToken.signature;
    if (!signature || typeof signature !== "object") {
      throw new LoomError("SIGNATURE_INVALID", "Portable capability token signature is required", 401, {
        field: "content.structured.parameters.capability_token.signature"
      });
    }

    const signatureAlgorithm = String(signature.algorithm || "").trim();
    const signatureValue = String(signature.value || "").trim();
    if (signatureAlgorithm !== "Ed25519" || !signatureValue) {
      throw new LoomError("SIGNATURE_INVALID", "Portable capability token signature is invalid", 401, {
        field: "content.structured.parameters.capability_token.signature"
      });
    }

    const normalizedToken = buildPortableCapabilityTokenPayload(portableCapabilityToken);
    if (!normalizedToken.id || !normalizedToken.thread_id || !normalizedToken.issued_by || !normalizedToken.issued_to) {
      throw new LoomError("CAPABILITY_DENIED", "Portable capability token requires id, thread_id, issued_by, and issued_to", 403, {
        field: "content.structured.parameters.capability_token"
      });
    }

    if (normalizedToken.thread_id !== thread.id) {
      throw new LoomError("CAPABILITY_DENIED", "Portable capability token thread scope mismatch", 403, {
        capability_token: normalizedToken.id,
        token_thread_id: normalizedToken.thread_id,
        thread_id: thread.id
      });
    }

    if (normalizedToken.issued_to !== actorIdentity) {
      throw new LoomError("CAPABILITY_DENIED", "Portable capability token issued_to mismatch", 403, {
        capability_token: normalizedToken.id,
        issued_to: normalizedToken.issued_to,
        actor: actorIdentity
      });
    }

    if (!this.isThreadOwner(thread, normalizedToken.issued_by)) {
      throw new LoomError("CAPABILITY_DENIED", "Portable capability token issuer is not an active thread owner", 403, {
        capability_token: normalizedToken.id,
        issued_by: normalizedToken.issued_by
      });
    }

    if (normalizedToken.expires_at) {
      if (parseTime(normalizedToken.expires_at) == null || isExpiredIso(normalizedToken.expires_at)) {
        throw new LoomError("CAPABILITY_DENIED", "Portable capability token expired or invalid expires_at", 403, {
          capability_token: normalizedToken.id
        });
      }
    }

    if (!Number.isInteger(normalizedToken.epoch) || normalizedToken.epoch < 0) {
      throw new LoomError("CAPABILITY_DENIED", "Portable capability token epoch is invalid", 403, {
        capability_token: normalizedToken.id,
        token_epoch: normalizedToken.epoch
      });
    }

    if (normalizedToken.epoch !== thread.cap_epoch) {
      throw new LoomError("CAPABILITY_DENIED", "Portable capability token epoch mismatch", 403, {
        capability_token: normalizedToken.id,
        token_epoch: normalizedToken.epoch,
        thread_epoch: thread.cap_epoch
      });
    }

    const grantSet = new Set(normalizedToken.grants);
    if (!grantSet.has("admin") && !grantSet.has(requiredGrant)) {
      throw new LoomError("CAPABILITY_DENIED", "Portable capability token grant missing for operation", 403, {
        capability_token: normalizedToken.id,
        required_grant: requiredGrant
      });
    }

    if (normalizedToken.single_use && this.consumedPortableCapabilityIds.has(normalizedToken.id)) {
      throw new LoomError("CAPABILITY_DENIED", "Portable capability token already spent", 403, {
        capability_token: normalizedToken.id
      });
    }

    const publicKeyPem = this.resolvePortableCapabilitySigningPublicKey(
      {
        ...normalizedToken,
        signature
      },
      context
    );
    const validSignature = verifyUtf8MessageSignature(
      publicKeyPem,
      canonicalizePortableCapabilityToken(normalizedToken),
      signatureValue
    );
    if (!validSignature) {
      throw new LoomError("SIGNATURE_INVALID", "Portable capability token signature verification failed", 401, {
        field: "content.structured.parameters.capability_token.signature"
      });
    }

    const localToken = this.capabilitiesById.get(normalizedToken.id) || null;
    if (localToken && localToken.revoked) {
      throw new LoomError("CAPABILITY_DENIED", "Portable capability token revoked", 403, {
        capability_token: normalizedToken.id
      });
    }

    return {
      kind: "portable",
      id: normalizedToken.id,
      single_use: normalizedToken.single_use,
      localToken
    };
  }

  validateCapabilityForThreadOperation({
    thread,
    intent,
    actorIdentity,
    capabilityTokenValue,
    capabilityTokenId = null,
    portableCapabilityToken = null,
    context = {}
  }) {
    const requiredGrant = THREAD_OP_TO_GRANT[intent] || "admin";

    if (this.isThreadOwner(thread, actorIdentity)) {
      return null;
    }

    if (portableCapabilityToken && typeof portableCapabilityToken === "object") {
      return this.validatePortableCapabilityTokenForThreadOperation({
        thread,
        actorIdentity,
        requiredGrant,
        portableCapabilityToken,
        context
      });
    }

    if (context?.federated === true) {
      throw new LoomError(
        "CAPABILITY_DENIED",
        "Federated non-owner thread operations require portable signed capability_token payload",
        403,
        {
          intent,
          actor: actorIdentity,
          field: "content.structured.parameters.capability_token"
        }
      );
    }

    if (!capabilityTokenValue) {
      throw new LoomError("CAPABILITY_DENIED", "Capability presentation token required for thread operation", 403, {
        intent,
        actor: actorIdentity
      });
    }

    const token = this.resolveCapabilityTokenByPresentation({
      capabilityTokenValue,
      capabilityTokenId
    });
    if (!token) {
      throw new LoomError("CAPABILITY_DENIED", "Capability token invalid", 403, {
        intent,
        actor: actorIdentity
      });
    }

    if (token.thread_id !== thread.id) {
      throw new LoomError("CAPABILITY_DENIED", "Capability token thread scope mismatch", 403, {
        capability_token: token.id,
        thread_id: thread.id
      });
    }

    if (token.issued_to !== actorIdentity) {
      throw new LoomError("CAPABILITY_DENIED", "Capability token issued to different identity", 403, {
        capability_token: token.id,
        actor: actorIdentity
      });
    }

    if (token.revoked || token.spent || isExpiredIso(token.expires_at)) {
      throw new LoomError("CAPABILITY_DENIED", "Capability token not usable", 403, {
        capability_token: token.id
      });
    }

    if (token.epoch !== thread.cap_epoch) {
      throw new LoomError("CAPABILITY_DENIED", "Capability token epoch mismatch", 403, {
        capability_token: token.id,
        token_epoch: token.epoch,
        thread_epoch: thread.cap_epoch
      });
    }

    const grantSet = new Set(token.grants);
    if (!grantSet.has("admin") && !grantSet.has(requiredGrant)) {
      throw new LoomError("CAPABILITY_DENIED", "Capability token grant missing for operation", 403, {
        capability_token: token.id,
        required_grant: requiredGrant
      });
    }

    token.secret_last_used_at = nowIso();

    return {
      kind: "local",
      token
    };
  }

  validateCapabilityForThreadRead({ thread, actorIdentity, capabilityTokenValue, strict = true }) {
    const normalizedActor = this.normalizeIdentityReference(actorIdentity);
    if (!normalizedActor) {
      if (!strict) {
        return null;
      }
      throw new LoomError("CAPABILITY_DENIED", "Authentication required for thread read", 403, {
        field: "authorization"
      });
    }

    if (this.isActiveParticipant(thread, normalizedActor)) {
      return null;
    }

    const normalizedCapabilityTokenValue = String(capabilityTokenValue || "").trim();
    if (!normalizedCapabilityTokenValue) {
      if (!strict) {
        return null;
      }
      throw new LoomError("CAPABILITY_DENIED", "Capability read token required for non-participant thread access", 403, {
        thread_id: thread.id,
        actor: normalizedActor
      });
    }

    const token = this.resolveCapabilityTokenByPresentation({
      capabilityTokenValue: normalizedCapabilityTokenValue
    });

    if (!token) {
      if (!strict) {
        return null;
      }
      throw new LoomError("CAPABILITY_DENIED", "Capability token invalid", 403, {
        thread_id: thread.id,
        actor: normalizedActor
      });
    }

    if (token.thread_id !== thread.id) {
      if (!strict) {
        return null;
      }
      throw new LoomError("CAPABILITY_DENIED", "Capability token thread scope mismatch", 403, {
        capability_token: token.id,
        thread_id: thread.id
      });
    }

    if (token.issued_to !== normalizedActor) {
      if (!strict) {
        return null;
      }
      throw new LoomError("CAPABILITY_DENIED", "Capability token issued to different identity", 403, {
        capability_token: token.id,
        actor: normalizedActor
      });
    }

    if (token.revoked || token.spent || isExpiredIso(token.expires_at)) {
      if (!strict) {
        return null;
      }
      throw new LoomError("CAPABILITY_DENIED", "Capability token not usable", 403, {
        capability_token: token.id
      });
    }

    if (token.epoch !== thread.cap_epoch) {
      if (!strict) {
        return null;
      }
      throw new LoomError("CAPABILITY_DENIED", "Capability token epoch mismatch", 403, {
        capability_token: token.id,
        token_epoch: token.epoch,
        thread_epoch: thread.cap_epoch
      });
    }

    const grantSet = new Set(token.grants);
    if (!grantSet.has("admin") && !grantSet.has("read")) {
      if (!strict) {
        return null;
      }
      throw new LoomError("CAPABILITY_DENIED", "Capability token grant missing for read operation", 403, {
        capability_token: token.id,
        required_grant: "read"
      });
    }

    token.secret_last_used_at = nowIso();
    return token;
  }

  resolveDelegationRequiredActions(envelope) {
    const type = String(envelope?.type || "").trim();
    if (!type) {
      return ["message.send@v1"];
    }

    if (type === "thread_op") {
      const intent = String(envelope?.content?.structured?.intent || "").trim();
      const actions = [...(ENVELOPE_TYPE_DELEGATION_ACTIONS.thread_op || ["thread.op.execute@v1"])];
      if (intent && THREAD_OP_TO_GRANT[intent]) {
        actions.unshift(intent);
      }
      return Array.from(new Set(actions));
    }

    const mapped = ENVELOPE_TYPE_DELEGATION_ACTIONS[type];
    if (Array.isArray(mapped) && mapped.length > 0) {
      return mapped;
    }

    return [`${type}.send@v1`];
  }

  resolvePendingParentsForThread(thread, parentEnvelopeId) {
    return resolvePendingParentsForThreadCore.call(this, thread, parentEnvelopeId);
  }

  enforceThreadEnvelopeEncryptionPolicy(thread, envelope, isNewThread, context = {}) {
    return enforceThreadEnvelopeEncryptionPolicyCore.call(this, thread, envelope, isNewThread, context);
  }

  prepareThreadOperation(thread, envelope, actorIdentity, context = {}) {
    return prepareThreadOperationCore.call(this, thread, envelope, actorIdentity, context);
  }

  resolveEnvelopeSignaturePublicKey(envelope, signatureKeyId, context = {}) {
    return resolveEnvelopeSignaturePublicKeyCore.call(this, envelope, signatureKeyId, context);
  }

  resolveAuthoritativeEnvelopeSenderType(envelope) {
    return resolveAuthoritativeEnvelopeSenderTypeCore.call(this, envelope);
  }

  ingestEnvelope(envelope, context = {}) {
    const storedEnvelope = ingestEnvelopeCore.call(this, envelope, {
      ...context,
      replayMode: context.replayMode || this.replayMode,
      threadLimits: context.threadLimits || this.threadLimits,
      loopProtection: context.loopProtection || this.loopProtection
    });

    if (this.mcpClientEnabled && !context._mcpClientResponse) {
      this._processIngestedMcpToolRequest(storedEnvelope);
    }

    // ── Post-ingestion: event log ──────────────────────────────────────────
    this._emitEnvelopeEvent(storedEnvelope);

    // ── Post-ingestion: channel rules ──────────────────────────────────────
    this._applyChannelRules(storedEnvelope);

    // ── Post-ingestion: autoresponder ──────────────────────────────────────
    if (!context._autoReply) {
      this._processAutoresponder(storedEnvelope);
    }

    return storedEnvelope;
  }

  ensureMcpServiceIdentity() {
    if (this._mcpServiceKeys) {
      return this._mcpServiceKeys;
    }
    const keys = generateSigningKeyPair();
    const serviceIdentity = `loom://mcp-service@${this.nodeId}`;
    const serviceKeyId = "k_sign_mcp_service_1";

    if (!this.identities.has(serviceIdentity) && !this.remoteIdentities.has(serviceIdentity)) {
      this.registerIdentity({
        id: serviceIdentity,
        display_name: "MCP Service",
        type: "service",
        signing_keys: [{ key_id: serviceKeyId, public_key_pem: keys.publicKeyPem }]
      });
    }

    this._mcpServiceKeys = {
      serviceIdentity,
      serviceKeyId,
      privateKeyPem: keys.privateKeyPem,
      publicKeyPem: keys.publicKeyPem
    };
    return this._mcpServiceKeys;
  }

  getMcpToolRegistry() {
    if (!this.mcpToolRegistry) {
      this.mcpToolRegistry = createMcpToolRegistry(this);
    }
    return this.mcpToolRegistry;
  }

  _processIngestedMcpToolRequest(storedEnvelope) {
    if (!isMcpToolRequestEnvelope(storedEnvelope)) {
      return null;
    }

    try {
      const serviceKeys = this.ensureMcpServiceIdentity();
      const result = processMcpToolRequest(this, storedEnvelope, {
        mcpToolRegistry: this.getMcpToolRegistry(),
        serviceIdentity: serviceKeys.serviceIdentity,
        serviceKeyId: serviceKeys.serviceKeyId,
        servicePrivateKeyPem: serviceKeys.privateKeyPem
      });

      if (result.processed) {
        this.persistAndAudit("mcp.client.tool_executed", {
          request_envelope_id: storedEnvelope.id,
          response_envelope_id: result.response_envelope_id,
          thread_id: storedEnvelope.thread_id,
          tool_name: storedEnvelope.content?.structured?.parameters?.tool_name,
          requester: storedEnvelope.from?.identity,
          is_error: result.is_error || false
        });
      }

      return result;
    } catch (error) {
      this.persistAndAudit("mcp.client.tool_execution_failed", {
        request_envelope_id: storedEnvelope.id,
        thread_id: storedEnvelope.thread_id,
        error_code: error?.code || "INTERNAL_ERROR",
        error_message: error?.message || "Unknown error"
      });
      return null;
    }
  }

  getEnvelope(envelopeId) {
    return this.envelopesById.get(envelopeId) || null;
  }

  listThreads() {
    return Array.from(this.threadsById.values())
      .map((thread) => toThreadSummary(thread))
      .sort((a, b) => b.updated_at.localeCompare(a.updated_at));
  }

  listThreadsForIdentity(actorIdentity) {
    const normalizedActor = this.normalizeIdentityReference(actorIdentity);
    if (!normalizedActor) {
      throw new LoomError("CAPABILITY_DENIED", "Authentication required to list threads", 403, {
        field: "authorization"
      });
    }

    return Array.from(this.threadsById.values())
      .filter((thread) => this.isActiveParticipant(thread, normalizedActor))
      .map((thread) => toThreadSummary(thread))
      .sort((a, b) => b.updated_at.localeCompare(a.updated_at));
  }

  getThread(threadId) {
    const thread = this.threadsById.get(threadId);
    return thread ? toThreadSummary(thread) : null;
  }

  getThreadForIdentity(threadId, actorIdentity, options = {}) {
    const thread = this.threadsById.get(threadId);
    if (!thread) {
      return null;
    }

    this.validateCapabilityForThreadRead({
      thread,
      actorIdentity,
      capabilityTokenValue: options.capabilityTokenValue ?? null,
      strict: true
    });

    return toThreadSummary(thread);
  }

  getThreadEnvelopes(threadId) {
    return getThreadEnvelopesCore.call(this, threadId);
  }

  searchEnvelopes(filters, actorIdentity) {
    const query = String(filters?.q || "").trim().toLowerCase();
    const fromFilter = filters?.from ? String(filters.from).trim() : null;
    const typeFilter = filters?.type ? String(filters.type).trim() : null;
    const intentFilter = filters?.intent ? String(filters.intent).trim() : null;
    const threadFilter = filters?.thread_id ? String(filters.thread_id).trim() : null;
    const afterMs = filters?.after ? parseTime(filters.after) : null;
    const beforeMs = filters?.before ? parseTime(filters.before) : null;
    const limit = Math.max(1, Math.min(Number(filters?.limit || 50), 200));

    const matches = [];
    const candidateThreads = threadFilter
      ? [this.threadsById.get(threadFilter)].filter(Boolean)
      : Array.from(this.threadsById.values()).filter((thread) => this.isActiveParticipant(thread, actorIdentity));
    if (threadFilter && candidateThreads.length > 0 && !this.isActiveParticipant(candidateThreads[0], actorIdentity)) {
      return {
        total: 0,
        results: []
      };
    }

    for (const thread of candidateThreads) {
      if (!thread || !Array.isArray(thread.envelope_ids)) {
        continue;
      }
      if (!this.isActiveParticipant(thread, actorIdentity)) {
        continue;
      }

      for (const envelopeId of thread.envelope_ids) {
        const envelope = this.envelopesById.get(envelopeId);
        if (!envelope) {
          continue;
        }

        if (fromFilter && envelope.from?.identity !== fromFilter) {
          continue;
        }

        if (typeFilter && envelope.type !== typeFilter) {
          continue;
        }

        const intent = envelope.content?.structured?.intent || null;
        if (intentFilter && intent !== intentFilter) {
          continue;
        }

        const createdMs = parseTime(envelope.created_at);
        if (afterMs != null && (createdMs == null || createdMs < afterMs)) {
          continue;
        }

        if (beforeMs != null && (createdMs == null || createdMs > beforeMs)) {
          continue;
        }

        if (query.length > 0) {
          const haystack = [
            envelope.content?.encrypted ? "" : envelope.content?.human?.text || "",
            intent || "",
            envelope.type || "",
            envelope.from?.identity || "",
            envelope.thread_id || ""
          ]
            .join(" ")
            .toLowerCase();

          if (!haystack.includes(query)) {
            continue;
          }
        }

        matches.push({
          envelope_id: envelope.id,
          thread_id: envelope.thread_id,
          type: envelope.type,
          from: envelope.from?.identity || null,
          created_at: envelope.created_at,
          intent,
          excerpt: envelope.content?.encrypted
            ? null
            : (envelope.content?.human?.text || "").slice(0, 240)
        });
      }
    }

    matches.sort((a, b) => b.created_at.localeCompare(a.created_at));
    return {
      total: matches.length,
      results: matches.slice(0, limit)
    };
  }

  getLocalFederationSigningKeys() {
    let federationPublicKeyPem = null;
    if (this.federationSigningPrivateKeyPem) {
      try {
        federationPublicKeyPem = derivePublicKeyPemFromPrivateKeyPem(this.federationSigningPrivateKeyPem);
      } catch {
        federationPublicKeyPem = null;
      }
    }

    const signingKeys =
      federationPublicKeyPem && this.federationSigningKeyId
        ? [
            {
              key_id: this.federationSigningKeyId,
              public_key_pem: federationPublicKeyPem
            }
          ]
        : [];

    return applyRevokedKeyIdsToFederationSigningKeys(
      signingKeys,
      this.federationTrustRevokedKeyIds
    );
  }

  signFederationDocumentPayload(payload) {
    if (!this.federationSigningPrivateKeyPem || !this.federationSigningKeyId) {
      return payload;
    }

    const signature = signUtf8Message(
      this.federationSigningPrivateKeyPem,
      canonicalizeSignedDocumentPayload(payload)
    );
    return {
      ...payload,
      signature: {
        algorithm: "Ed25519",
        key_id: this.federationSigningKeyId,
        value: signature
      }
    };
  }

  getFederationKeysetDocument(domain) {
    const normalizedDomain = String(domain || "").trim() || "localhost";
    const protocolCapabilitiesUrl = `https://${normalizedDomain}/v1/protocol/capabilities`;
    const keysetUrl = `https://${normalizedDomain}/.well-known/loom-keyset.json`;
    const revocationsUrl = `https://${normalizedDomain}/.well-known/loom-revocations.json`;
    const signingKeys = this.getLocalFederationSigningKeys();
    const activeSigningKey =
      resolveFederationNodeSigningKey({ signing_keys: signingKeys }, this.federationSigningKeyId) ||
      signingKeys.find((key) => isSigningKeyUsableAt(key)) ||
      signingKeys[0] ||
      null;
    const revokedKeyIds = normalizeRevokedKeyIds(this.federationTrustRevokedKeyIds);
    const cacheKey = canonicalizeJson({
      node_id: this.nodeId,
      domain: normalizedDomain,
      trust_epoch: this.federationTrustLocalEpoch,
      version: this.federationTrustKeysetVersion,
      signing_keys: signingKeys,
      revoked_key_ids: revokedKeyIds
    });
    const cached = this.federationPublishedKeysetsByDomain.get(normalizedDomain);
    if (cached && cached.cache_key === cacheKey && !isExpiredIso(cached.document?.valid_until)) {
      return {
        ...cached.document
      };
    }

    const generatedAt = nowIso();
    const validUntil = new Date(nowMs() + this.federationTrustKeysetPublishTtlMs).toISOString();
    const unsigned = {
      loom_version: "1.1",
      type: "loom.federation.keyset@v1",
      node_id: this.nodeId,
      domain: normalizedDomain,
      generated_at: generatedAt,
      valid_until: validUntil,
      trust_epoch: this.federationTrustLocalEpoch,
      epoch: this.federationTrustLocalEpoch,
      version: this.federationTrustKeysetVersion,
      active_key_id: activeSigningKey?.key_id || null,
      signing_key_id: activeSigningKey?.key_id || null,
      keyset_url: keysetUrl,
      revocations_url: revocationsUrl,
      protocol_capabilities_url: protocolCapabilitiesUrl,
      signing_keys: signingKeys
    };
    const signed = this.signFederationDocumentPayload(unsigned);
    this.federationPublishedKeysetsByDomain.set(normalizedDomain, {
      cache_key: cacheKey,
      document: signed
    });
    return {
      ...signed
    };
  }

  getFederationRevocationsDocument(domain) {
    const normalizedDomain = String(domain || "").trim() || "localhost";
    const revokedKeyIds = normalizeRevokedKeyIds(this.federationTrustRevokedKeyIds);
    const cacheKey = canonicalizeJson({
      node_id: this.nodeId,
      domain: normalizedDomain,
      trust_epoch: this.federationTrustLocalEpoch,
      version: this.federationTrustKeysetVersion,
      revoked_key_ids: revokedKeyIds
    });
    const cached = this.federationPublishedRevocationsByDomain.get(normalizedDomain);
    if (cached && cached.cache_key === cacheKey && !isExpiredIso(cached.document?.valid_until)) {
      return {
        ...cached.document
      };
    }

    const generatedAt = nowIso();
    const validUntil = new Date(nowMs() + this.federationTrustKeysetPublishTtlMs).toISOString();
    const unsigned = {
      loom_version: "1.1",
      type: "loom.federation.revocations@v1",
      node_id: this.nodeId,
      domain: normalizedDomain,
      generated_at: generatedAt,
      valid_until: validUntil,
      trust_epoch: this.federationTrustLocalEpoch,
      epoch: this.federationTrustLocalEpoch,
      version: this.federationTrustKeysetVersion,
      revoked_key_ids: revokedKeyIds
    };
    const signed = this.signFederationDocumentPayload(unsigned);
    this.federationPublishedRevocationsByDomain.set(normalizedDomain, {
      cache_key: cacheKey,
      document: signed
    });
    return {
      ...signed
    };
  }

  buildFederationTrustDnsTxtRecord(domain) {
    const normalizedDomain = String(domain || "").trim() || "localhost";
    const keysetDocument = this.getFederationKeysetDocument(normalizedDomain);
    const keysetUrl = String(keysetDocument?.keyset_url || `https://${normalizedDomain}/.well-known/loom-keyset.json`).trim();
    const revocationsUrl = String(
      keysetDocument?.revocations_url || `https://${normalizedDomain}/.well-known/loom-revocations.json`
    ).trim();
    const keysetDigest = hashCanonicalSignedDocumentPayload(keysetDocument);
    return [
      "v=loomfed1",
      `keyset=${keysetUrl}`,
      `digest=sha256:${keysetDigest}`,
      `revocations=${revocationsUrl}`,
      `trust_epoch=${this.federationTrustLocalEpoch}`,
      `version=${this.federationTrustKeysetVersion}`
    ].join(";");
  }

  getFederationTrustDnsDescriptor(domain) {
    const normalizedDomain = String(domain || "").trim() || "localhost";
    let dnsName = null;
    try {
      dnsName = this.resolveFederationTrustDnsName(this.nodeId);
    } catch {
      dnsName = null;
    }

    const record = this.buildFederationTrustDnsTxtRecord(normalizedDomain);
    return {
      version: "loomfed1",
      dns_name: dnsName,
      txt_record: record,
      trust_epoch: this.federationTrustLocalEpoch,
      keyset_version: this.federationTrustKeysetVersion,
      keyset_url: `https://${normalizedDomain}/.well-known/loom-keyset.json`,
      revocations_url: `https://${normalizedDomain}/.well-known/loom-revocations.json`,
      generated_at: nowIso()
    };
  }

  async verifyLocalFederationTrustDnsPublication(domain) {
    const descriptor = this.getFederationTrustDnsDescriptor(domain);
    const dnsName = String(descriptor?.dns_name || "").trim();
    const expectedRecord = String(descriptor?.txt_record || "").trim();
    if (!dnsName || !expectedRecord) {
      throw new LoomError("ENVELOPE_INVALID", "Unable to resolve local federation trust DNS publication descriptor", 400, {
        dns_name: dnsName || null
      });
    }

    let resolverResult = {
      records: [],
      dnssec_validated: null,
      dnssec_source: null
    };
    let resolutionError = null;
    try {
      resolverResult = normalizeFederationTrustDnsResolverResult(await this.federationTrustDnsTxtResolver(dnsName));
    } catch (error) {
      resolutionError = error;
      resolverResult = {
        records: [],
        dnssec_validated: null,
        dnssec_source: null
      };
    }

    const answers = resolverResult.records;
    const dnssecValidated = resolverResult.dnssec_validated === true;
    const dnssecRequired = this.federationTrustRequireDnssec === true;
    const expectedFields = normalizeFederationTrustDnsFields(parseFederationTrustDnsTxtRecord(expectedRecord));
    const candidateRecords = answers.map((record) => {
      const parsed = parseFederationTrustDnsTxtRecord(record);
      return {
        record,
        parsed,
        normalized: normalizeFederationTrustDnsFields(parsed)
      };
    });

    const exactMatch = candidateRecords.some((candidate) => candidate.record === expectedRecord);
    const semanticMatchCandidate = candidateRecords.find((candidate) => {
      const normalized = candidate.normalized;
      return (
        normalized.keyset_url === expectedFields.keyset_url &&
        normalized.digest_sha256 === expectedFields.digest_sha256 &&
        normalized.revocations_url === expectedFields.revocations_url &&
        normalized.trust_epoch === expectedFields.trust_epoch &&
        normalized.version === expectedFields.version
      );
    });
    const semanticMatch = Boolean(semanticMatchCandidate);
    const dnssecMissing = dnssecRequired && !dnssecValidated;
    const status = resolutionError
      ? "dns_unreachable"
      : dnssecMissing
        ? "dnssec_unverified"
      : exactMatch
        ? "match_exact"
        : semanticMatch
          ? "match_semantic"
          : "mismatch";

    return {
      dns_name: dnsName,
      expected_txt_record: expectedRecord,
      expected_fields: expectedFields,
      observed_txt_records: answers,
      observed_record_count: answers.length,
      observed_fields: candidateRecords.map((candidate) => candidate.normalized),
      match_exact: exactMatch,
      match_semantic: semanticMatch,
      dnssec_required: dnssecRequired,
      dnssec_validated: dnssecValidated,
      dnssec_source: resolverResult.dnssec_source || null,
      status,
      verified_at: nowIso(),
      dns_resolution_error: resolutionError?.message || null
    };
  }

  getFederationTrustStatus(domain) {
    return {
      trust_anchor_mode: this.federationTrustMode,
      trust_anchor_fail_closed: this.federationTrustFailClosed,
      trust_anchor_dns_txt_label: this.federationTrustDnsTxtLabel,
      trust_anchor_require_dnssec: this.federationTrustRequireDnssec,
      trust_anchor_transparency_mode: this.federationTrustTransparencyMode,
      trust_anchor_require_transparency: this.federationTrustRequireTransparency,
      trust_anchor_max_clock_skew_ms: this.federationTrustMaxClockSkewMs,
      trust_anchor_keyset_max_age_ms: this.federationTrustKeysetMaxAgeMs,
      trust_anchor_keyset_publish_ttl_ms: this.federationTrustKeysetPublishTtlMs,
      trust_anchor_bindings_count: this.federationTrustAnchorBindings.size,
      trust_epoch: this.federationTrustLocalEpoch,
      keyset_version: this.federationTrustKeysetVersion,
      revoked_key_ids: normalizeRevokedKeyIds(this.federationTrustRevokedKeyIds),
      dns: this.getFederationTrustDnsDescriptor(domain)
    };
  }

  updateFederationTrustConfig(payload, actorIdentity = "system") {
    if (!payload || typeof payload !== "object") {
      throw new LoomError("ENVELOPE_INVALID", "Federation trust config payload must be an object", 400, {
        field: "payload"
      });
    }

    const previous = {
      mode: this.federationTrustMode,
      fail_closed: this.federationTrustFailClosed,
      dns_txt_label: this.federationTrustDnsTxtLabel,
      require_dnssec: this.federationTrustRequireDnssec,
      transparency_mode: this.federationTrustTransparencyMode,
      require_transparency: this.federationTrustRequireTransparency,
      max_clock_skew_ms: this.federationTrustMaxClockSkewMs,
      keyset_max_age_ms: this.federationTrustKeysetMaxAgeMs,
      keyset_publish_ttl_ms: this.federationTrustKeysetPublishTtlMs,
      trust_epoch: this.federationTrustLocalEpoch,
      keyset_version: this.federationTrustKeysetVersion,
      revoked_key_ids: normalizeRevokedKeyIds(this.federationTrustRevokedKeyIds)
    };

    if (Object.prototype.hasOwnProperty.call(payload, "trust_anchor_mode")) {
      this.federationTrustMode = normalizeFederationTrustMode(payload.trust_anchor_mode, {
        hasTrustAnchors: this.federationTrustAnchorBindings.size > 0
      });
    }

    if (Object.prototype.hasOwnProperty.call(payload, "trust_anchor_fail_closed")) {
      this.federationTrustFailClosed = parseBoolean(payload.trust_anchor_fail_closed, this.federationTrustFailClosed);
    }

    if (Object.prototype.hasOwnProperty.call(payload, "trust_anchor_dns_txt_label")) {
      const value = String(payload.trust_anchor_dns_txt_label || "").trim();
      if (!value) {
        throw new LoomError("ENVELOPE_INVALID", "trust_anchor_dns_txt_label must be a non-empty string", 400, {
          field: "trust_anchor_dns_txt_label"
        });
      }
      this.federationTrustDnsTxtLabel = value;
    }

    if (Object.prototype.hasOwnProperty.call(payload, "trust_anchor_require_dnssec")) {
      this.federationTrustRequireDnssec = parseBoolean(
        payload.trust_anchor_require_dnssec,
        this.federationTrustRequireDnssec
      );
    }

    if (Object.prototype.hasOwnProperty.call(payload, "trust_anchor_transparency_mode")) {
      const normalized = String(payload.trust_anchor_transparency_mode || "")
        .trim()
        .toLowerCase();
      if (!normalized) {
        throw new LoomError("ENVELOPE_INVALID", "trust_anchor_transparency_mode must be a non-empty string", 400, {
          field: "trust_anchor_transparency_mode"
        });
      }
      this.federationTrustTransparencyMode = normalized;
    }

    if (Object.prototype.hasOwnProperty.call(payload, "trust_anchor_require_transparency")) {
      this.federationTrustRequireTransparency = parseBoolean(
        payload.trust_anchor_require_transparency,
        this.federationTrustRequireTransparency
      );
    }

    if (Object.prototype.hasOwnProperty.call(payload, "trust_anchor_max_clock_skew_ms")) {
      const parsed = parsePositiveInteger(payload.trust_anchor_max_clock_skew_ms, Number.NaN);
      if (!Number.isFinite(parsed) || parsed < 1000) {
        throw new LoomError("ENVELOPE_INVALID", "trust_anchor_max_clock_skew_ms must be an integer >= 1000", 400, {
          field: "trust_anchor_max_clock_skew_ms"
        });
      }
      this.federationTrustMaxClockSkewMs = parsed;
    }

    if (Object.prototype.hasOwnProperty.call(payload, "trust_anchor_keyset_max_age_ms")) {
      const parsed = parsePositiveInteger(payload.trust_anchor_keyset_max_age_ms, Number.NaN);
      if (!Number.isFinite(parsed) || parsed < 60 * 1000) {
        throw new LoomError("ENVELOPE_INVALID", "trust_anchor_keyset_max_age_ms must be an integer >= 60000", 400, {
          field: "trust_anchor_keyset_max_age_ms"
        });
      }
      this.federationTrustKeysetMaxAgeMs = parsed;
    }

    if (Object.prototype.hasOwnProperty.call(payload, "trust_anchor_keyset_publish_ttl_ms")) {
      const parsed = parsePositiveInteger(payload.trust_anchor_keyset_publish_ttl_ms, Number.NaN);
      if (!Number.isFinite(parsed) || parsed < 60 * 1000) {
        throw new LoomError("ENVELOPE_INVALID", "trust_anchor_keyset_publish_ttl_ms must be an integer >= 60000", 400, {
          field: "trust_anchor_keyset_publish_ttl_ms"
        });
      }
      this.federationTrustKeysetPublishTtlMs = parsed;
    }

    const explicitEpoch = Object.prototype.hasOwnProperty.call(payload, "trust_epoch");
    const bumpEpoch = payload.bump_trust_epoch === true;
    if (explicitEpoch) {
      const parsed = parseNonNegativeInteger(payload.trust_epoch, -1);
      if (parsed < 0) {
        throw new LoomError("ENVELOPE_INVALID", "trust_epoch must be a non-negative integer", 400, {
          field: "trust_epoch"
        });
      }
      this.federationTrustLocalEpoch = parsed;
    } else if (bumpEpoch) {
      this.federationTrustLocalEpoch += 1;
    }

    const explicitVersion = Object.prototype.hasOwnProperty.call(payload, "keyset_version");
    const bumpVersion = payload.bump_keyset_version === true;
    if (explicitVersion) {
      const parsed = parseNonNegativeInteger(payload.keyset_version, -1);
      if (parsed < 0) {
        throw new LoomError("ENVELOPE_INVALID", "keyset_version must be a non-negative integer", 400, {
          field: "keyset_version"
        });
      }
      this.federationTrustKeysetVersion = parsed;
    } else if (bumpVersion) {
      this.federationTrustKeysetVersion += 1;
    }

    const hasRevokedKeyIds = Object.prototype.hasOwnProperty.call(payload, "revoked_key_ids");
    const hasAppendRevokedKeyIds = Object.prototype.hasOwnProperty.call(payload, "append_revoked_key_ids");
    if (hasRevokedKeyIds || hasAppendRevokedKeyIds) {
      const nextRevoked = hasRevokedKeyIds
        ? normalizeRevokedKeyIds(payload.revoked_key_ids)
        : normalizeRevokedKeyIds(this.federationTrustRevokedKeyIds);
      const appendRevoked = hasAppendRevokedKeyIds ? normalizeRevokedKeyIds(payload.append_revoked_key_ids) : [];
      this.federationTrustRevokedKeyIds = normalizeRevokedKeyIds([...nextRevoked, ...appendRevoked]);
      if (!explicitVersion && !bumpVersion) {
        this.federationTrustKeysetVersion += 1;
      }
    }

    if (this.federationTrustLocalEpoch < previous.trust_epoch) {
      throw new LoomError("ENVELOPE_INVALID", "trust_epoch cannot decrease", 400, {
        field: "trust_epoch",
        previous: previous.trust_epoch,
        next: this.federationTrustLocalEpoch
      });
    }
    if (
      this.federationTrustLocalEpoch === previous.trust_epoch &&
      this.federationTrustKeysetVersion < previous.keyset_version
    ) {
      throw new LoomError("ENVELOPE_INVALID", "keyset_version cannot decrease without trust_epoch bump", 400, {
        field: "keyset_version",
        previous: previous.keyset_version,
        next: this.federationTrustKeysetVersion
      });
    }

    this.federationPublishedKeysetsByDomain.clear();
    this.federationPublishedRevocationsByDomain.clear();
    this.persistAndAudit("federation.trust.config.update", {
      actor: actorIdentity,
      trust_anchor_mode: this.federationTrustMode,
      trust_epoch: this.federationTrustLocalEpoch,
      keyset_version: this.federationTrustKeysetVersion,
      revoked_key_count: this.federationTrustRevokedKeyIds.length,
      previous_trust_epoch: previous.trust_epoch,
      previous_keyset_version: previous.keyset_version
    });

    return this.getFederationTrustStatus();
  }

  getNodeDocument(domain) {
    const normalizedDomain = String(domain || "").trim() || "localhost";
    const protocolCapabilitiesUrl = `https://${normalizedDomain}/v1/protocol/capabilities`;
    const federationKeysetUrl = `https://${normalizedDomain}/.well-known/loom-keyset.json`;
    const federationRevocationsUrl = `https://${normalizedDomain}/.well-known/loom-revocations.json`;
    const keysetDocument = this.getFederationKeysetDocument(normalizedDomain);
    const federationSigningKeys = normalizeKeysetSigningKeys(keysetDocument);
    const activeSigningKey =
      resolveFederationNodeSigningKey({ signing_keys: federationSigningKeys }, keysetDocument?.active_key_id) ||
      federationSigningKeys[0] ||
      null;
    let trustAnchorDnsName = null;
    try {
      trustAnchorDnsName = this.resolveFederationTrustDnsName(this.nodeId);
    } catch {
      trustAnchorDnsName = null;
    }

    return {
      loom_version: "1.1",
      node_id: this.nodeId,
      domain: normalizedDomain,
      api_url: `https://${normalizedDomain}/v1`,
      websocket_url: `wss://${normalizedDomain}/ws`,
      deliver_url: `https://${normalizedDomain}/v1/federation/deliver`,
      identity_resolve_url: `https://${normalizedDomain}/v1/identity/{identity}`,
      protocol_capabilities_url: protocolCapabilitiesUrl,
      federation_keyset_url: federationKeysetUrl,
      federation_revocations_url: federationRevocationsUrl,
      trust_anchor_dns_name: trustAnchorDnsName,
      federation: {
        signing_key_id: activeSigningKey?.key_id || null,
        public_key_pem: activeSigningKey?.public_key_pem || null,
        signing_keys: federationSigningKeys,
        outbox_url: `https://${normalizedDomain}/v1/federation/outbox`,
        challenge_url: `https://${normalizedDomain}/v1/federation/challenge`,
        identity_resolve_url: `https://${normalizedDomain}/v1/identity/{identity}`,
        protocol_capabilities_url: protocolCapabilitiesUrl,
        keyset_url: federationKeysetUrl,
        revocations_url: federationRevocationsUrl,
        trust_anchor_mode: this.getFederationTrustAnchorMode(),
        trust_anchor_dns_name: trustAnchorDnsName,
        trust_epoch: this.federationTrustLocalEpoch,
        keyset_hash_sha256: hashCanonicalSignedDocumentPayload(keysetDocument)
      },
      auth_endpoints: {
        identity_challenge: `https://${normalizedDomain}/v1/identity/challenge`,
        challenge: `https://${normalizedDomain}/v1/auth/challenge`,
        token: `https://${normalizedDomain}/v1/auth/token`,
        refresh: `https://${normalizedDomain}/v1/auth/refresh`
      },
      supported_profiles: ["loom-core-1"],
      auth: {
        proof_of_key: true
      },
      generated_at: nowIso(),
      request_id: randomUUID()
    };
  }

  getFederationTrustAnchorMode() {
    return this.federationTrustMode;
  }

  getProtocolCapabilities(domain = null) {
    const normalizedDomain = String(domain || "").trim() || null;
    const protocolCapabilitiesUrl = normalizedDomain ? `https://${normalizedDomain}/v1/protocol/capabilities` : null;
    return {
      loom_version: "1.1",
      node_id: this.nodeId,
      protocol_capabilities_url: protocolCapabilitiesUrl,
      federation_negotiation: {
        trust_anchor_mode: this.getFederationTrustAnchorMode(),
        trust_anchor_modes_supported: Array.from(FEDERATION_TRUST_MODES).sort(),
        trust_anchor_bindings_count: this.federationTrustAnchorBindings.size,
        trust_anchor_fail_closed: this.federationTrustFailClosed,
        trust_anchor_dns_txt_label: this.federationTrustDnsTxtLabel,
        trust_anchor_require_dnssec: this.federationTrustRequireDnssec,
        trust_anchor_transparency_mode: this.federationTrustTransparencyMode,
        trust_anchor_require_transparency: this.federationTrustRequireTransparency,
        trust_anchor_epoch: this.federationTrustLocalEpoch,
        e2ee_profiles: listSupportedE2eeProfileCapabilities()
      },
      mcp: {
        supported: true,
        protocol_version: "2024-11-05",
        transports: ["sse", "stdio"],
        tools_url: normalizedDomain ? `https://${normalizedDomain}/v1/mcp/tools` : null,
        sse_url: normalizedDomain ? `https://${normalizedDomain}/v1/mcp/sse` : null
      },
      generated_at: nowIso(),
      request_id: randomUUID()
    };
  }

  getIdentityDocument(identityUri) {
    const identity = this.resolveIdentity(identityUri);
    if (!identity) {
      return null;
    }

    const payload = {
      ...identity,
      signing_keys: normalizeIdentitySigningKeys(identity.signing_keys),
      encryption_keys: normalizeIdentityEncryptionKeys(identity.encryption_keys)
    };

    if (identity.imported_remote === true || identity.identity_source === "remote") {
      return payload;
    }

    if (!this.federationSigningPrivateKeyPem) {
      return payload;
    }

    const canonicalIdentity = buildIdentityRegistrationDocument({
      identity: payload.id,
      type: payload.type || "human",
      displayName: payload.display_name || payload.id,
      signingKeys: payload.signing_keys,
      encryptionKeys: payload.encryption_keys,
      agentInfo: payload.agent_info || null
    });
    const nodeSignature = signUtf8Message(
      this.federationSigningPrivateKeyPem,
      canonicalizeJson(canonicalIdentity)
    );

    return {
      ...payload,
      node_signature: {
        algorithm: "Ed25519",
        key_id: this.federationSigningKeyId,
        value: nodeSignature
      }
    };
  }

  getRetentionCutoffMs(retentionDays) {
    const days = Math.max(0, parseNonNegativeInteger(retentionDays, 0));
    if (days <= 0) {
      return null;
    }
    return nowMs() - days * MILLISECONDS_PER_DAY;
  }

  collectProtectedEnvelopeIdsForRetention() {
    const protectedIds = new Set();
    for (const item of this.federationOutboxById.values()) {
      if (item?.status !== "queued") {
        continue;
      }
      for (const envelopeId of Array.isArray(item.envelope_ids) ? item.envelope_ids : []) {
        const normalized = String(envelopeId || "").trim();
        if (normalized) {
          protectedIds.add(normalized);
        }
      }
    }

    for (const item of this.emailOutboxById.values()) {
      if (item?.status !== "queued") {
        continue;
      }
      const envelopeId = String(item?.envelope_id || "").trim();
      if (envelopeId) {
        protectedIds.add(envelopeId);
      }
    }

    return protectedIds;
  }

  purgeThreadScopedArtifacts(threadId) {
    const normalizedThreadId = String(threadId || "").trim();
    if (!normalizedThreadId) {
      return 0;
    }

    let removed = 0;
    for (const [capabilityId, token] of this.capabilitiesById.entries()) {
      if (String(token?.thread_id || "").trim() !== normalizedThreadId) {
        continue;
      }
      if (token?.secret_hash) {
        this.capabilityIdBySecretHash.delete(token.secret_hash);
      }
      this.capabilitiesById.delete(capabilityId);
      removed += 1;
    }

    for (const [delegationId, delegation] of this.delegationsById.entries()) {
      if (String(delegation?.thread_id || "").trim() !== normalizedThreadId) {
        continue;
      }
      this.delegationsById.delete(delegationId);
      this.revokedDelegationIds.delete(delegationId);
      removed += 1;
    }

    return removed;
  }

  applyMessageRetentionSweep() {
    const cutoffMs = this.getRetentionCutoffMs(this.messageRetentionDays);
    if (cutoffMs == null) {
      return {
        removed: 0,
        threads_removed: 0,
        artifacts_removed: 0
      };
    }

    const protectedEnvelopeIds = this.collectProtectedEnvelopeIdsForRetention();
    const removedEnvelopeIds = new Set();
    const touchedThreadIds = new Set();
    let removed = 0;

    for (const [envelopeId, envelope] of this.envelopesById.entries()) {
      const createdAtMs = parseTime(envelope?.created_at);
      if (createdAtMs == null || createdAtMs > cutoffMs) {
        continue;
      }
      if (protectedEnvelopeIds.has(envelopeId)) {
        continue;
      }

      this.envelopesById.delete(envelopeId);
      removedEnvelopeIds.add(envelopeId);
      const threadId = String(envelope?.thread_id || "").trim();
      if (threadId) {
        touchedThreadIds.add(threadId);
      }
      removed += 1;
    }

    if (removed === 0) {
      return {
        removed: 0,
        threads_removed: 0,
        artifacts_removed: 0
      };
    }

    for (const [wrapperKey, wrapper] of this.deliveryWrappersByEnvelopeAndIdentity.entries()) {
      const envelopeId = String(wrapper?.envelope_id || "").trim();
      if (!envelopeId || this.envelopesById.has(envelopeId)) {
        continue;
      }
      this.deliveryWrappersByEnvelopeAndIdentity.delete(wrapperKey);
    }

    for (const [messageId, entry] of this.emailMessageIndexById.entries()) {
      const envelopeId = String(entry?.envelope_id || "").trim();
      if (!envelopeId || this.envelopesById.has(envelopeId)) {
        continue;
      }
      this.emailMessageIndexById.delete(messageId);
    }

    let threadsRemoved = 0;
    let artifactsRemoved = 0;
    const updatedAt = nowIso();
    for (const threadId of touchedThreadIds) {
      const thread = this.threadsById.get(threadId);
      if (!thread) {
        continue;
      }

      const remainingEnvelopeIds = (Array.isArray(thread.envelope_ids) ? thread.envelope_ids : []).filter((envelopeId) =>
        this.envelopesById.has(envelopeId)
      );
      if (remainingEnvelopeIds.length === 0) {
        this.threadsById.delete(threadId);
        threadsRemoved += 1;
        artifactsRemoved += this.purgeThreadScopedArtifacts(threadId);
        continue;
      }

      thread.envelope_ids = remainingEnvelopeIds;
      if (!remainingEnvelopeIds.includes(thread.root_envelope_id)) {
        thread.root_envelope_id = remainingEnvelopeIds[0];
      }

      let pendingParentCount = 0;
      for (const envelopeId of remainingEnvelopeIds) {
        const envelope = this.envelopesById.get(envelopeId);
        if (!envelope) {
          continue;
        }
        const parentId = String(envelope.parent_id || "").trim();
        if (parentId && !this.envelopesById.has(parentId)) {
          envelope.parent_id = null;
          envelope.meta = {
            ...(envelope.meta || {}),
            pending_parent: false,
            parent_resolved_at: updatedAt
          };
        }
        if (envelope?.meta?.pending_parent === true) {
          pendingParentCount += 1;
        }
      }
      thread.pending_parent_count = pendingParentCount;
      thread.updated_at = updatedAt;
    }

    return {
      removed,
      threads_removed: threadsRemoved,
      artifacts_removed: artifactsRemoved
    };
  }

  applyBlobRetentionSweep() {
    const cutoffMs = this.getRetentionCutoffMs(this.blobRetentionDays);
    if (cutoffMs == null) {
      return {
        removed: 0,
        scrubbed: 0
      };
    }

    const referencedBlobIds = new Set();
    for (const envelope of this.envelopesById.values()) {
      for (const attachment of Array.isArray(envelope?.attachments) ? envelope.attachments : []) {
        const blobId = String(attachment?.blob_id || "").trim();
        if (blobId) {
          referencedBlobIds.add(blobId);
        }
      }
    }

    let removed = 0;
    let scrubbed = 0;
    const expiredAt = nowIso();
    for (const [blobId, blob] of this.blobsById.entries()) {
      const createdAtMs = parseTime(blob?.completed_at || blob?.created_at || blob?.updated_at || null);
      if (createdAtMs == null || createdAtMs > cutoffMs) {
        continue;
      }

      if (!referencedBlobIds.has(blobId)) {
        this.blobsById.delete(blobId);
        removed += 1;
        continue;
      }

      let changed = false;
      if (Object.prototype.hasOwnProperty.call(blob, "data_base64")) {
        delete blob.data_base64;
        changed = true;
      }
      if (blob.parts && typeof blob.parts === "object" && Object.keys(blob.parts).length > 0) {
        blob.parts = {};
        changed = true;
      }
      if (blob.status !== "expired") {
        blob.status = "expired";
        changed = true;
      }
      if (Number(blob.size_bytes || 0) !== 0) {
        blob.size_bytes = 0;
        changed = true;
      }
      if (blob.hash != null) {
        blob.hash = null;
        changed = true;
      }
      if (blob.completed_at != null) {
        blob.completed_at = null;
        changed = true;
      }
      if (Number(blob.quota_accounted_bytes || 0) !== 0) {
        blob.quota_accounted_bytes = 0;
        changed = true;
      }
      if (changed) {
        blob.retention_expired_at = expiredAt;
        blob.updated_at = expiredAt;
        scrubbed += 1;
      }
    }

    if (removed > 0 || scrubbed > 0) {
      this.rebuildIdentityQuotaIndexes();
    }

    return {
      removed,
      scrubbed
    };
  }

  runMaintenanceSweep() {
    const now = nowMs();
    let swept = 0;

    for (const [token, session] of this.accessTokens) {
      if (isExpiredIso(session.expires_at)) {
        this.accessTokens.delete(token);
        swept += 1;
      }
    }

    for (const [token, session] of this.refreshTokens) {
      if (isExpiredIso(session.expires_at)) {
        this.refreshTokens.delete(token);
        swept += 1;
      }
    }

    for (const [id, challenge] of this.authChallenges) {
      if (challenge.used || isExpiredIso(challenge.expires_at)) {
        this.authChallenges.delete(id);
        swept += 1;
      }
    }

    const rateCutoff = now - this.identityRateWindowMs * 2;
    for (const [key, entry] of this.identityRateByBucket) {
      if (entry.window_started_at < rateCutoff) {
        this.identityRateByBucket.delete(key);
        swept += 1;
      }
    }

    if (this.consumedPortableCapabilityIds.size > this.consumedCapabilityMaxEntries) {
      const overflow = this.consumedPortableCapabilityIds.size - this.consumedCapabilityMaxEntries;
      let removed = 0;
      for (const id of this.consumedPortableCapabilityIds) {
        if (removed >= overflow) break;
        this.consumedPortableCapabilityIds.delete(id);
        removed += 1;
      }
      swept += removed;
    }

    if (this.revokedDelegationIds.size > this.revokedDelegationMaxEntries) {
      const overflow = this.revokedDelegationIds.size - this.revokedDelegationMaxEntries;
      let removed = 0;
      for (const id of this.revokedDelegationIds) {
        if (removed >= overflow) break;
        this.revokedDelegationIds.delete(id);
        removed += 1;
      }
      swept += removed;
    }

    this.cleanupIdempotencyCache();
    this.cleanupFederationNonces();
    this.cleanupFederationInboundRateState();
    this.cleanupFederationInboundAbuseState();
    this.cleanupFederationChallengeState();
    this.cleanupIdentityRegistrationChallenges(now);
    this.cleanupDailyQuotaMap(this.identityEnvelopeUsageByDay);
    this.cleanupDailyQuotaMap(this.identityBlobUsageByDay);
    const messageRetention = this.applyMessageRetentionSweep();
    const blobRetention = this.applyBlobRetentionSweep();
    swept +=
      Number(messageRetention.removed || 0) +
      Number(messageRetention.threads_removed || 0) +
      Number(messageRetention.artifacts_removed || 0);
    swept += Number(blobRetention.removed || 0) + Number(blobRetention.scrubbed || 0);

    return {
      swept,
      retention: {
        messages: messageRetention,
        blobs: blobRetention
      }
    };
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Protocol Module Integrations
  // ══════════════════════════════════════════════════════════════════════════

  // ── Receipts (Section 20.8) ──────────────────────────────────────────────

  _ensureSystemServiceIdentity() {
    const serviceIdentity = `loom://system@${this.nodeId}`;
    if (!this.identities.has(serviceIdentity)) {
      // Register with a non-reserved key ID for the identity
      const serviceKeyId = "k_sign_system_svc_1";
      if (!this.publicKeysById.has(serviceKeyId)) {
        this.publicKeysById.set(serviceKeyId, this.systemSigningPublicKeyPem);
        this.keyOwnerById.set(serviceKeyId, serviceIdentity);
      }
      this.identities.set(serviceIdentity, {
        id: serviceIdentity,
        display_name: "System Service",
        type: "service",
        created_at: nowIso(),
        signing_keys: [{ key_id: serviceKeyId, public_key_pem: this.systemSigningPublicKeyPem }]
      });
    }
    return serviceIdentity;
  }

  _signSystemEnvelope(envelope) {
    const serviceIdentity = this._ensureSystemServiceIdentity();
    const serviceKeyId = "k_sign_system_svc_1";
    envelope.from = {
      ...envelope.from,
      identity: serviceIdentity,
      key_id: serviceKeyId,
      type: "service"
    };
    return signEnvelope(envelope, this.systemSigningPrivateKeyPem, serviceKeyId);
  }

  _ensureServiceParticipant(threadId) {
    const serviceIdentity = this._ensureSystemServiceIdentity();
    const thread = this.threadsById.get(threadId);
    if (thread && !this.isActiveParticipant(thread, serviceIdentity)) {
      thread.participants.push({
        identity: serviceIdentity,
        role: "participant",
        joined_at: nowIso(),
        left_at: null
      });
    }
    return serviceIdentity;
  }

  generateDeliveryReceipt(originalEnvelope) {
    this._ensureServiceParticipant(originalEnvelope.thread_id);
    const receipt = buildDeliveryReceipt(originalEnvelope, {
      fromIdentity: `loom://system@${this.nodeId}`,
      nodeId: this.nodeId
    });
    return this.ingestEnvelope(this._signSystemEnvelope(receipt), { _autoReply: true });
  }

  generateReadReceipt(originalEnvelope, { fromIdentity, deviceId = null, userConfirmed = true }) {
    this._ensureServiceParticipant(originalEnvelope.thread_id);
    const receipt = buildReadReceipt(originalEnvelope, { fromIdentity, deviceId, userConfirmed });
    return this.ingestEnvelope(this._signSystemEnvelope(receipt), { _autoReply: true });
  }

  generateFailureReceipt(originalEnvelope, { reason, details = null, retryAfter = null }) {
    this._ensureServiceParticipant(originalEnvelope.thread_id);
    const receipt = buildFailureReceipt(originalEnvelope, {
      fromIdentity: `loom://system@${this.nodeId}`,
      reason,
      details,
      retryAfter
    });
    return this.ingestEnvelope(this._signSystemEnvelope(receipt), { _autoReply: true });
  }

  // ── Deletion & Content Erasure (Section 25.2) ───────────────────────────

  deleteEnvelopeContent(envelopeId, actorIdentity) {
    const envelope = this.envelopesById.get(envelopeId);
    if (!envelope) {
      throw new LoomError("ENVELOPE_NOT_FOUND", `Envelope not found: ${envelopeId}`, 404, {
        envelope_id: envelopeId
      });
    }

    const thread = this.threadsById.get(envelope.thread_id);
    const check = canDeleteEnvelope(envelope, thread);
    if (!check.allowed) {
      throw new LoomError("DELETION_BLOCKED", check.reason, 403, {
        envelope_id: envelopeId,
        reason: check.reason
      });
    }

    const erased = eraseEnvelopeContent(envelope);
    this.envelopesById.set(envelopeId, erased);
    this.persistAndAudit("envelope.content_erased", {
      envelope_id: envelopeId,
      thread_id: envelope.thread_id,
      actor: actorIdentity
    });

    return erased;
  }

  cryptoShredThread(threadId, keyEpoch, actorIdentity) {
    const thread = this.threadsById.get(threadId);
    if (!thread) {
      throw new LoomError("THREAD_NOT_FOUND", `Thread not found: ${threadId}`, 404, {
        thread_id: threadId
      });
    }

    if (isLegalHoldActive(thread.labels)) {
      throw new LoomError("DELETION_BLOCKED", "LEGAL_HOLD_ACTIVE", 403, {
        thread_id: threadId
      });
    }

    const record = buildCryptoShredRecord(threadId, keyEpoch);

    // Erase all envelope content in the thread
    for (const envId of thread.envelope_ids || []) {
      const envelope = this.envelopesById.get(envId);
      if (envelope && !envelope.meta?.deleted) {
        this.envelopesById.set(envId, eraseEnvelopeContent(envelope));
      }
    }

    this.persistAndAudit("thread.crypto_shred", {
      thread_id: threadId,
      key_epoch: keyEpoch,
      actor: actorIdentity
    });

    return record;
  }

  // ── Retention Enforcement (Section 25.4) ─────────────────────────────────

  enforceRetentionPolicies(now = Date.now()) {
    const expired = collectExpiredEnvelopes(
      Array.from(this.envelopesById.values()),
      this.threadsById,
      this.retentionPolicies,
      now
    );

    let erased = 0;
    for (const envelopeId of expired) {
      const envelope = this.envelopesById.get(envelopeId);
      if (envelope && !envelope.meta?.deleted) {
        this.envelopesById.set(envelopeId, eraseEnvelopeContent(envelope));
        erased++;
      }
    }

    if (erased > 0) {
      this.persistAndAudit("retention.enforced", {
        expired_count: expired.length,
        erased_count: erased
      });
    }

    return { expired_count: expired.length, erased_count: erased };
  }

  // ── Channel Rules (Section 20.4) ─────────────────────────────────────────

  _applyChannelRules(storedEnvelope) {
    if (this.channelRules.length === 0) return;

    const thread = this.threadsById.get(storedEnvelope.thread_id);
    if (!thread) return;

    const actions = evaluateRules(storedEnvelope, this.channelRules, thread.labels || []);
    if (actions.length === 0) return;

    const result = applyRuleActions(actions);

    // Apply label changes to the thread
    if (result.labels_to_add.length > 0 || result.labels_to_remove.length > 0) {
      const currentLabels = new Set(thread.labels || []);
      for (const label of result.labels_to_add) {
        currentLabels.add(label);
      }
      for (const label of result.labels_to_remove) {
        currentLabels.delete(label);
      }
      thread.labels = Array.from(currentLabels);
    }

    // Store routing metadata on the envelope
    if (result.quarantine) {
      storedEnvelope.meta = storedEnvelope.meta || {};
      storedEnvelope.meta.quarantined = true;
      storedEnvelope.meta.quarantined_at = nowIso();
    }

    if (result.route_to || result.delegate_to || result.escalate) {
      storedEnvelope.meta = storedEnvelope.meta || {};
      storedEnvelope.meta.channel_rule_actions = {
        route_to: result.route_to,
        delegate_to: result.delegate_to,
        escalate: result.escalate
      };
    }
  }

  setChannelRules(rules) {
    this.channelRules = normalizeChannelRules(rules);
    this.persistAndAudit("channel_rules.updated", {
      rule_count: this.channelRules.length
    });
  }

  // ── Autoresponder (Section 20.5) ─────────────────────────────────────────

  setAutoresponderRule(identityUri, rule) {
    if (rule === null || rule === undefined) {
      this.autoresponderRules.delete(identityUri);
      this.persistAndAudit("autoresponder.removed", { identity: identityUri });
      return;
    }

    const errors = validateAutoresponderRule(rule);
    if (errors.length > 0) {
      throw new LoomError("AUTORESPONDER_INVALID", errors[0].reason, 400, { errors });
    }

    this.autoresponderRules.set(identityUri, rule);
    this.persistAndAudit("autoresponder.set", {
      identity: identityUri,
      schedule_start: rule.schedule_start || null,
      schedule_end: rule.schedule_end || null
    });
  }

  _processAutoresponder(storedEnvelope) {
    // Only process message-type envelopes
    if (storedEnvelope.type !== "message") return;

    // Check each recipient for autoresponder rules
    const recipients = storedEnvelope.to || [];
    for (const recipient of recipients) {
      const identity = recipient.identity;
      const rule = this.autoresponderRules.get(identity);
      if (!rule) continue;

      const sentHistory = this.autoresponderSentHistory.get(identity) || new Map();
      const decision = shouldAutoRespond(storedEnvelope, rule, sentHistory);
      if (!decision.respond) continue;

      this._ensureServiceParticipant(storedEnvelope.thread_id);
      const autoReply = buildAutoReplyEnvelope(storedEnvelope, rule, identity);
      this.ingestEnvelope(this._signSystemEnvelope(autoReply), { _autoReply: true });

      // Track sent history
      if (!this.autoresponderSentHistory.has(identity)) {
        this.autoresponderSentHistory.set(identity, new Map());
      }
      this.autoresponderSentHistory.get(identity).set(
        storedEnvelope.from?.identity,
        new Date().toISOString()
      );
    }
  }

  // ── Distribution / Team Routing (Section 20.3) ──────────────────────────

  setIdentityRoutingPolicy(identityUri, policy) {
    const identity = this.identities.get(identityUri);
    if (!identity) {
      throw new LoomError("IDENTITY_NOT_FOUND", `Identity not found: ${identityUri}`, 404, {
        identity: identityUri
      });
    }

    identity.routing_policy = normalizeRoutingPolicy(policy);
    this.persistAndAudit("identity.routing_policy_set", {
      identity: identityUri,
      routing_policy: identity.routing_policy
    });

    return identity.routing_policy;
  }

  resolveDistributionRecipients(envelope) {
    const recipients = envelope.to || [];
    const expandedRecipients = [];

    for (const recipient of recipients) {
      const identity = this.identities.get(recipient.identity);
      if (identity?.routing_policy && Array.isArray(identity.members) && identity.members.length > 0) {
        // This is a team/distribution identity — expand
        const policy = normalizeRoutingPolicy(identity.routing_policy);

        if (requiresModeration(policy)) {
          // Moderated: keep original recipient, mark for moderation
          expandedRecipients.push({ ...recipient, _moderation_pending: true });
          continue;
        }

        const resolved = resolveTeamRecipients(identity, policy);
        for (const member of resolved) {
          const memberIdentity = typeof member === "object" ? member.identity || member : member;
          expandedRecipients.push({
            identity: memberIdentity,
            role: recipient.role,
            _expanded_from: recipient.identity
          });
        }
      } else {
        expandedRecipients.push(recipient);
      }
    }

    return expandedRecipients;
  }

  // ── Search Validation (Section 16.6) ─────────────────────────────────────

  validateAndSearchEnvelopes(filters, actorIdentity) {
    const validationErrors = validateSearchQuery(filters || {});
    if (validationErrors.length > 0) {
      throw new LoomError("SEARCH_INVALID", validationErrors[0].reason, 400, {
        errors: validationErrors
      });
    }
    return this.searchEnvelopes(filters, actorIdentity);
  }

  // ── Import / Export (Section 26.2) ───────────────────────────────────────

  exportMailbox(options = {}) {
    const state = {
      threads: Array.from(this.threadsById.values()),
      envelopes: Array.from(this.envelopesById.values()),
      blobs: Array.from(this.blobsById.values())
    };

    const exportPkg = buildExportPackage(state, options);

    this.persistAndAudit("mailbox.exported", {
      thread_count: exportPkg.thread_count,
      envelope_count: exportPkg.envelope_count,
      identity_filter: options.identityFilter || null
    });

    return exportPkg;
  }

  importMailbox(payload, actorIdentity) {
    const errors = validateImportPayload(payload);
    if (errors.length > 0) {
      throw new LoomError("IMPORT_INVALID", errors[0].reason, 400, { errors });
    }

    const importedEnvelopes = prepareImportEnvelopes(payload.envelopes || []);
    const importedThreads = prepareImportThreads(payload.threads || []);

    let envelopeCount = 0;
    let threadCount = 0;

    // Import threads
    for (const thread of importedThreads) {
      if (!thread.id) continue;
      if (!this.threadsById.has(thread.id)) {
        this.threadsById.set(thread.id, {
          ...thread,
          mailbox_state: thread.mailbox_state || {},
          pending_parent_count: 0
        });
        threadCount++;
      }
    }

    // Import envelopes
    for (const envelope of importedEnvelopes) {
      if (!envelope.id) continue;
      if (!this.envelopesById.has(envelope.id)) {
        this.envelopesById.set(envelope.id, envelope);
        // Add to thread envelope_ids if thread exists
        const thread = this.threadsById.get(envelope.thread_id);
        if (thread) {
          if (!Array.isArray(thread.envelope_ids)) thread.envelope_ids = [];
          if (!thread.envelope_ids.includes(envelope.id)) {
            thread.envelope_ids.push(envelope.id);
          }
        }
        envelopeCount++;
      }
    }

    this.persistAndAudit("mailbox.imported", {
      thread_count: threadCount,
      envelope_count: envelopeCount,
      actor: actorIdentity
    });

    return { thread_count: threadCount, envelope_count: envelopeCount };
  }

  // ── Blob Validation (Section 19) ─────────────────────────────────────────

  validateBlobPayload(payload) {
    return validateBlobInitiation(payload);
  }

  // ── Event Log (WebSocket support — Section 17) ──────────────────────────

  _emitEnvelopeEvent(storedEnvelope) {
    const eventType = storedEnvelope.type === "receipt"
      ? WS_EVENT_TYPES.RECEIPT_DELIVERED
      : WS_EVENT_TYPES.ENVELOPE_NEW;

    appendEvent(this.eventLog, {
      type: eventType,
      payload: {
        envelope_id: storedEnvelope.id,
        thread_id: storedEnvelope.thread_id,
        from: storedEnvelope.from?.identity || null,
        type: storedEnvelope.type,
        intent: storedEnvelope.content?.structured?.intent || null
      }
    });
  }

  getEventsSince(cursor) {
    pruneEventLog(this.eventLog);
    return getEventsSince(this.eventLog, cursor);
  }

  getEventLog() {
    return this.eventLog;
  }

  // ── Rate Limit Headers (Section 18.4) ───────────────────────────────────

  buildRateLimitResponseHeaders(rateLimitResult) {
    return buildRateLimitHeaders(rateLimitResult);
  }
}
