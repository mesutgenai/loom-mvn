import { createHash, randomUUID } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync
} from "node:fs";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { join } from "node:path";

import {
  derivePublicKeyPemFromPrivateKeyPem,
  generateSigningKeyPair,
  signEnvelope,
  signUtf8Message,
  verifyEnvelopeSignature,
  verifyUtf8MessageSignature
} from "../protocol/crypto.js";
import { validateEnvelopeOrThrow } from "../protocol/envelope.js";
import { LoomError } from "../protocol/errors.js";
import { canonicalizeEnvelope, canonicalizeJson } from "../protocol/canonical.js";
import { canonicalThreadOrder, validateThreadDag } from "../protocol/thread.js";
import { isIdentity, normalizeLoomIdentity } from "../protocol/ids.js";
import { generateUlid } from "../protocol/ulid.js";
import {
  verifyDelegationChainOrThrow,
  verifyDelegationLinkOrThrow
} from "../protocol/delegation.js";

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

function parseBoolean(value, fallback = false) {
  if (value == null) {
    return fallback;
  }

  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  return fallback;
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

async function assertOutboundUrlHostAllowed(url, options = {}) {
  const allowPrivateNetwork = options.allowPrivateNetwork === true;
  const allowedHosts = normalizeHostnameAllowlist(options.allowedHosts || []);
  const target = url instanceof URL ? url : new URL(String(url || ""));

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

  if (!allowPrivateNetwork) {
    const hostname = target.hostname;
    const ipVersion = isIP(hostname);
    if (ipVersion > 0) {
      if (isPrivateOrLocalIp(hostname)) {
        throw new LoomError("CAPABILITY_DENIED", "Private or local network URL targets are not allowed", 403, {
          host: hostname
        });
      }
      return;
    }

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

    const privateAddress = resolved.find((entry) => isPrivateOrLocalIp(entry?.address));
    if (privateAddress) {
      throw new LoomError("CAPABILITY_DENIED", "Resolved URL host points to private or local network", 403, {
        host: hostname,
        address: privateAddress.address
      });
    }
  }
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
  const normalized = normalizeLoomIdentity(identityUri);
  if (!normalized) {
    return null;
  }

  const raw = normalized.slice("loom://".length);
  const atIndex = raw.indexOf("@");
  if (atIndex <= 0 || atIndex >= raw.length - 1) {
    return null;
  }

  return raw.slice(atIndex + 1).toLowerCase();
}

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

function buildIdentityRegistrationDocument({
  identity,
  type = "human",
  displayName = null,
  signingKeys = []
}) {
  return {
    loom: "1.1",
    id: identity,
    type: String(type || "human"),
    display_name: String(displayName || identity),
    signing_keys: normalizeIdentitySigningKeys(signingKeys)
  };
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
    has_pending_parents: pendingParentCount > 0
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

function mergeFederationSigningKeys(baseKeys = [], nextKeys = []) {
  const merged = new Map();
  for (const key of [...baseKeys, ...nextKeys]) {
    const keyId = String(key?.key_id || "").trim();
    const publicKeyPem = String(key?.public_key_pem || "").trim();
    if (!keyId || !publicKeyPem) {
      continue;
    }
    merged.set(keyId, {
      key_id: keyId,
      public_key_pem: publicKeyPem
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
  return keys.find((key) => key.key_id === normalizedKeyId) || null;
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
    this.federationSigningKeyId = options.federationSigningKeyId || "k_node_sign_local_1";
    this.federationSigningPrivateKeyPem = options.federationSigningPrivateKeyPem || null;
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
    this.localIdentityDomain =
      typeof options.localIdentityDomain === "string" && options.localIdentityDomain.trim()
        ? options.localIdentityDomain.trim().toLowerCase()
        : null;
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
    this.persistenceAdapter = options.persistenceAdapter || null;

    this.identities = new Map();
    this.remoteIdentities = new Map();
    this.publicKeysById = new Map();
    this.keyOwnerById = new Map();
    this.envelopesById = new Map();
    this.threadsById = new Map();

    this.authChallenges = new Map();
    this.identityRegistrationChallenges = new Map();
    this.accessTokens = new Map();
    this.refreshTokens = new Map();
    this.capabilitiesById = new Map();
    this.capabilityIdBySecretHash = new Map();
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
    this.blobMaxBytes = Math.max(1024, parsePositiveInteger(options.blobMaxBytes, 25 * 1024 * 1024));
    this.blobMaxPartBytes = Math.max(1024, parsePositiveInteger(options.blobMaxPartBytes, 2 * 1024 * 1024));
    this.blobMaxParts = Math.max(1, parsePositiveInteger(options.blobMaxParts, 64));
    this.envelopeDailyMax = Math.max(0, parseNonNegativeInteger(options.envelopeDailyMax, 0));
    this.threadRecipientFanoutMax = Math.max(0, parseNonNegativeInteger(options.threadRecipientFanoutMax, 0));
    this.blobDailyCountMax = Math.max(0, parseNonNegativeInteger(options.blobDailyCountMax, 0));
    this.blobDailyBytesMax = Math.max(0, parseNonNegativeInteger(options.blobDailyBytesMax, 0));
    this.blobIdentityTotalBytesMax = Math.max(0, parseNonNegativeInteger(options.blobIdentityTotalBytesMax, 0));
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

    this.initializeSystemSigningKeys();

    if (this.dataDir) {
      mkdirSync(this.dataDir, { recursive: true });
      this.loadStateFromDisk();
      this.loadAuditFromDisk();
    }

    this.ensureSystemSigningKeyRegistered();
  }

  initializeSystemSigningKeys() {
    if (this.systemSigningPrivateKeyPem && this.systemSigningPublicKeyPem) {
      return;
    }

    const generated = generateSigningKeyPair();
    if (!this.systemSigningPrivateKeyPem) {
      this.systemSigningPrivateKeyPem = generated.privateKeyPem;
    }

    if (!this.systemSigningPublicKeyPem) {
      this.systemSigningPublicKeyPem = generated.publicKeyPem;
    }

    if (!this.federationSigningPrivateKeyPem) {
      this.federationSigningPrivateKeyPem = this.systemSigningPrivateKeyPem;
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

  rebuildIdentityKeyIndexes() {
    this.publicKeysById = new Map();
    this.keyOwnerById = new Map();
    this.ensureSystemSigningKeyRegistered();

    for (const identityDoc of this.identities.values()) {
      this.applyIdentitySigningKeys(identityDoc.id, identityDoc.signing_keys);
    }

    for (const identityDoc of this.remoteIdentities.values()) {
      this.applyIdentitySigningKeys(identityDoc.id, identityDoc.signing_keys);
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
    this.remoteIdentities.delete(identityUri);
  }

  loadStateFromObject(state) {
    if (!state || typeof state !== "object") {
      return;
    }

    this.nodeId = state.node_id || this.nodeId;
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
    this.delegationsById = new Map((state.delegations || []).map((item) => [item.id, item]));
    this.revokedDelegationIds = new Set(state.revoked_delegation_ids || []);
    this.blobsById = new Map((state.blobs || []).map((item) => [item.id, item]));
    for (const blob of this.blobsById.values()) {
      const accountedBytes = Number(blob?.quota_accounted_bytes || 0);
      blob.quota_accounted_bytes = Number.isFinite(accountedBytes) && accountedBytes >= 0 ? accountedBytes : 0;
    }
    this.knownNodesById = new Map((state.known_nodes || []).map((item) => [item.node_id, item]));
    for (const node of this.knownNodesById.values()) {
      const signingKeys = getFederationNodeSigningKeys(node);
      node.signing_keys = signingKeys;
      if (signingKeys.length > 0) {
        const activeKey = signingKeys.find((key) => key.key_id === node.key_id) || signingKeys[0];
        node.key_id = activeKey.key_id;
        node.public_key_pem = activeKey.public_key_pem;
      }

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
  }

  loadAuditFromEntries(entries) {
    const list = Array.isArray(entries) ? entries : [];
    this.auditEntries = list.map((entry) => ({ ...entry }));
    this.auditHeadHash = this.auditEntries.length > 0 ? this.auditEntries[this.auditEntries.length - 1].hash : null;
  }

  loadStateFromDisk() {
    if (!this.stateFile || !existsSync(this.stateFile)) {
      return;
    }

    const raw = readFileSync(this.stateFile, "utf-8");
    if (!raw.trim()) {
      return;
    }

    const state = JSON.parse(raw);
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
    return {
      loom_version: "1.1",
      node_id: this.nodeId,
      updated_at: nowIso(),
      identities: Array.from(this.identities.values()),
      remote_identities: Array.from(this.remoteIdentities.values()),
      public_keys: Array.from(this.publicKeysById.entries()),
      envelopes: Array.from(this.envelopesById.values()),
      threads: Array.from(this.threadsById.values()),
      capabilities: Array.from(this.capabilitiesById.values()),
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
      federation_nonces: Array.from(this.federationNonceCache.entries())
    };
  }

  persistState() {
    if (!this.stateFile) {
      return;
    }

    writeFileSync(this.stateFile, JSON.stringify(this.toSerializableState(), null, 2));
  }

  appendAudit(action, payload) {
    const entry = {
      event_id: `evt_${generateUlid()}`,
      timestamp: nowIso(),
      action,
      payload,
      prev_hash: this.auditHeadHash
    };

    const hash = createHash("sha256").update(JSON.stringify(entry)).digest("hex");
    entry.hash = hash;
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
      this.loadAuditFromEntries(loaded.audit_entries);
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
      this.loadAuditFromEntries(auditEntries);
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
        last_http_status: null
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
      newest_queued_at: null
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
    await assertOutboundUrlHostAllowed(parsedUrl, {
      allowPrivateNetwork: webhook.allow_private_network === true,
      allowedHosts: this.webhookOutboundHostAllowlist
    });
    const canonical = `POST\n${parsedUrl.pathname}\n${bodyHash}\n${timestamp}\n${nonce}`;
    const signature = signUtf8Message(this.systemSigningPrivateKeyPem, canonical);

    try {
      const timeoutMs = Math.max(250, Math.min(parsePositiveInteger(item.timeout_ms, webhook.timeout_ms), 60000));
      const response = await fetch(webhookUrl, {
        method: "POST",
        redirect: "error",
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
        signal: AbortSignal.timeout(timeoutMs)
      });

      if (!response.ok) {
        const responseText = await response.text();
        this.markWebhookOutboxFailure(item, `Webhook response ${response.status}: ${responseText}`, response.status);
        this.persistAndAudit("webhook.outbox.process.failed", {
          outbox_id: item.id,
          webhook_id: webhook.id,
          event_id: item.event_id,
          reason: item.last_error,
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
        actor: actorIdentity
      });
      webhook.last_error = item.last_error;
      webhook.updated_at = nowIso();
      return item;
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
        last_error: result.last_error
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
    if (existing) {
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
    const signingKeys = replaceSigningKeys
      ? payloadSigningKeys
      : mergeFederationSigningKeys(existingSigningKeys, payloadSigningKeys);
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
      activeKey = signingKeys[0];
    }

    const hasExplicitPolicy = Object.prototype.hasOwnProperty.call(payload, "policy");
    const configuredPolicy = hasExplicitPolicy
      ? String(payload.policy || "trusted")
      : existing?.configured_policy || existing?.policy || "trusted";
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

    const node = {
      node_id: nodeId,
      key_id: activeKey.key_id,
      public_key_pem: activeKey.public_key_pem,
      signing_keys: signingKeys,
      deliver_url: deliverUrl,
      identity_resolve_url: identityResolveUrl,
      allow_insecure_http: allowInsecureHttp,
      allow_private_network: allowPrivateNetwork,
      configured_policy: configuredPolicy,
      policy: configuredPolicy,
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

    await assertOutboundUrlHostAllowed(nodeDocumentUrl, {
      allowPrivateNetwork,
      allowedHosts: this.federationBootstrapHostAllowlist
    });

    const abortController = new AbortController();
    const timeoutHandle = setTimeout(() => abortController.abort(), timeoutMs);
    timeoutHandle.unref?.();

    let response;
    try {
      response = await fetch(nodeDocumentUrl, {
        method: "GET",
        redirect: "error",
        headers: {
          accept: "application/json"
        },
        signal: abortController.signal
      });
    } catch (error) {
      clearTimeout(timeoutHandle);
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
    clearTimeout(timeoutHandle);

    if (!response.ok) {
      throw new LoomError("NODE_UNREACHABLE", `Federation node discovery returned ${response.status}`, 502, {
        node_document_url: nodeDocumentUrl.toString(),
        status: response.status
      });
    }

    let nodeDocument;
    try {
      const rawNodeDocument = await response.text();
      if (Buffer.byteLength(rawNodeDocument, "utf-8") > maxResponseBytes) {
        throw new LoomError("PAYLOAD_TOO_LARGE", "Federation node document exceeds allowed size", 413, {
          node_document_url: nodeDocumentUrl.toString(),
          max_response_bytes: maxResponseBytes
        });
      }
      nodeDocument = JSON.parse(rawNodeDocument);
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

    const signingKeys = extractFederationSigningKeysFromNodeDocument(nodeDocument);
    if (signingKeys.length === 0) {
      throw new LoomError("ENVELOPE_INVALID", "Federation node document is missing federation signing keys", 400, {
        field: "node_document.federation.signing_keys"
      });
    }

    const documentActiveKeyId = String(nodeDocument?.federation?.signing_key_id || "").trim();
    const requestedActiveKeyId = String(payload.active_key_id || "").trim();
    const activeKey =
      resolveFederationNodeSigningKey({ signing_keys: signingKeys }, requestedActiveKeyId || documentActiveKeyId) ||
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
      allowedHosts: this.federationOutboundHostAllowlist
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
        allowedHosts: identityAllowedHosts
      });
    }

    const node = this.registerFederationNode(
      {
        node_id: discoveredNodeId,
        key_id: activeKey.key_id,
        public_key_pem: activeKey.public_key_pem,
        signing_keys: signingKeys,
        active_key_id: activeKey.key_id,
        replace_signing_keys: payload.replace_signing_keys === true,
        deliver_url: deliverUrl.toString(),
        identity_resolve_url: identityResolveUrl,
        allow_insecure_http: allowInsecureHttp,
        allow_private_network: allowPrivateNetwork,
        policy: Object.prototype.hasOwnProperty.call(payload, "policy") ? payload.policy : undefined
      },
      actorIdentity
    );

    this.persistAndAudit("federation.node.bootstrap", {
      node_id: node.node_id,
      key_id: node.key_id,
      signing_key_count: node.signing_keys.length,
      node_document_url: nodeDocumentUrl.toString(),
      deliver_url: node.deliver_url,
      actor: actorIdentity
    });

    return {
      node,
      discovery: {
        node_document_url: nodeDocumentUrl.toString(),
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
      require_signed_receipts: this.federationRequireSignedReceipts
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
    if (requestTimeMs == null || Math.abs(nowMs() - requestTimeMs) > 5 * 60 * 1000) {
      throw new LoomError("SIGNATURE_INVALID", "Federation request timestamp outside freshness window", 401, {
        timestamp
      });
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
    const canonical = `${method.toUpperCase()}\n${path}\n${bodyHash}\n${timestamp}\n${nonce}`;
    const valid = verifyUtf8MessageSignature(nodeSigningKey.public_key_pem, canonical, signature);

    if (!valid) {
      throw new LoomError("SIGNATURE_INVALID", "Federation request signature verification failed", 401, {
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
    const quarantined = verifiedNode.policy === "quarantine";
    for (const envelope of wrapper.envelopes) {
      await this.ensureFederatedSenderIdentity(envelope, verifiedNode);

      const envelopeWithPolicyMeta = quarantined
        ? {
            ...envelope,
            meta: {
              ...(envelope.meta || {}),
              federation: {
                ...(envelope.meta?.federation || {}),
                source_node: verifiedNode.node_id,
                policy: "quarantine"
              }
            }
          }
        : envelope;

      const stored = this.ingestEnvelope(envelopeWithPolicyMeta, {
        actorIdentity: envelopeWithPolicyMeta?.from?.identity,
        federated: true
      });

      if (quarantined) {
        const thread = this.threadsById.get(stored.thread_id);
        if (thread && !thread.labels.includes("sys.quarantine")) {
          thread.labels.push("sys.quarantine");
          thread.updated_at = nowIso();
        }
      }

      accepted.push(stored.id);
    }

    this.persistAndAudit("federation.deliver", {
      sender_node: verifiedNode.node_id,
      accepted_count: accepted.length,
      policy: verifiedNode.policy
    });

    const deliveryId = String(wrapper.delivery_id || "").trim() || null;
    const receipt = this.createFederationDeliveryReceipt({
      delivery_id: deliveryId || `fdel_${generateUlid()}`,
      sender_node: this.nodeId,
      recipient_node: verifiedNode.node_id,
      status: "accepted",
      accepted_envelope_ids: accepted
    });

    return {
      sender_node: verifiedNode.node_id,
      accepted_count: accepted.length,
      accepted_envelope_ids: accepted,
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
    }

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
      queued_by: actorIdentity
    };

    this.federationOutboxById.set(outbox.id, outbox);
    this.persistAndAudit("federation.outbox.queue", {
      outbox_id: outbox.id,
      recipient_node: recipientNode,
      envelope_count: envelopeSummaries.length,
      actor: actorIdentity
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
      newest_queued_at: null
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

    const node = this.knownNodesById.get(item.recipient_node);
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

    try {
      await assertOutboundUrlHostAllowed(parsedUrl, {
        allowPrivateNetwork: node.allow_private_network === true,
        allowedHosts: this.federationOutboundHostAllowlist
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

    const canonical = `POST\n${parsedUrl.pathname}\n${bodyHash}\n${timestamp}\n${nonce}`;
    const signature = signUtf8Message(this.federationSigningPrivateKeyPem, canonical);

    try {
      const response = await fetch(parsedUrl.toString(), {
        method: "POST",
        redirect: "error",
        headers: {
          "content-type": "application/json",
          "x-loom-node": this.nodeId,
          "x-loom-timestamp": timestamp,
          "x-loom-nonce": nonce,
          "x-loom-key-id": this.federationSigningKeyId,
          "x-loom-signature": signature
        },
        body: rawBody
      });

      if (!response.ok) {
        const responseText = await response.text();
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
        responseJson = await response.json();
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
        actor: actorIdentity
      });

      return item;
    } catch (error) {
      this.markOutboxFailure(item, error?.message || "Network error");
      this.persistAndAudit("federation.outbox.process.failed", {
        outbox_id: item.id,
        recipient_node: item.recipient_node,
        reason: item.last_error,
        actor: actorIdentity
      });
      return item;
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
        receipt_verification_error: result.receipt_verification_error
      });
    }

    return {
      processed_count: processed.length,
      processed
    };
  }

  normalizeEmailAddress(value) {
    if (typeof value !== "string") {
      return null;
    }

    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }
    if (containsHeaderUnsafeChars(trimmed)) {
      return null;
    }

    const angleMatch = trimmed.match(/<([^>]+)>/);
    const candidate = angleMatch ? angleMatch[1].trim() : trimmed.replace(/^<|>$/g, "").trim();

    if (!candidate.includes("@")) {
      return null;
    }
    if (containsHeaderUnsafeChars(candidate)) {
      return null;
    }

    return candidate.toLowerCase();
  }

  splitAddressList(value) {
    if (Array.isArray(value)) {
      const flattened = [];
      for (const entry of value) {
        flattened.push(...this.splitAddressList(String(entry || "")));
      }
      return flattened;
    }

    if (typeof value !== "string") {
      return [];
    }

    const input = value.trim();
    if (!input) {
      return [];
    }

    const items = [];
    let current = "";
    let inQuote = false;
    let angleDepth = 0;
    let escapeNext = false;

    for (const char of input) {
      if (escapeNext) {
        current += char;
        escapeNext = false;
        continue;
      }

      if (char === "\\" && inQuote) {
        current += char;
        escapeNext = true;
        continue;
      }

      if (char === '"') {
        inQuote = !inQuote;
        current += char;
        continue;
      }

      if (!inQuote) {
        if (char === "<") {
          angleDepth += 1;
        } else if (char === ">" && angleDepth > 0) {
          angleDepth -= 1;
        }

        if ((char === "," || char === ";") && angleDepth === 0) {
          if (current.trim()) {
            items.push(current.trim());
          }
          current = "";
          continue;
        }
      }

      current += char;
    }

    if (current.trim()) {
      items.push(current.trim());
    }

    return items;
  }

  normalizeEmailAddressList(value) {
    return this.splitAddressList(value)
      .map((entry) => this.normalizeEmailAddress(String(entry || "")))
      .filter(Boolean);
  }

  resolveHeaderValue(headers, headerName) {
    if (!headers || typeof headers !== "object") {
      return null;
    }

    const target = String(headerName || "").trim().toLowerCase();
    if (!target) {
      return null;
    }

    for (const [key, value] of Object.entries(headers)) {
      if (String(key || "").trim().toLowerCase() === target) {
        return value;
      }
    }

    return null;
  }

  parseMessageId(value) {
    if (typeof value !== "string") {
      return null;
    }

    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }

    const bracketMatch = trimmed.match(/<([^>]+)>/);
    if (bracketMatch?.[1]) {
      return bracketMatch[1].trim();
    }

    const token = trimmed.split(/[\s,]+/).find(Boolean);
    if (!token) {
      return null;
    }

    return token.replace(/^<|>$/g, "").trim() || null;
  }

  parseMessageIdList(value) {
    if (Array.isArray(value)) {
      const combined = [];
      for (const entry of value) {
        combined.push(...this.parseMessageIdList(entry));
      }
      return Array.from(new Set(combined));
    }

    if (typeof value !== "string") {
      return [];
    }

    const trimmed = value.trim();
    if (!trimmed) {
      return [];
    }

    const bracketMatches = trimmed.match(/<[^>]+>/g);
    const tokens = bracketMatches?.length ? bracketMatches : trimmed.split(/[\s,]+/);

    return Array.from(
      new Set(
        tokens
          .map((token) => this.parseMessageId(token))
          .filter(Boolean)
      )
    );
  }

  parseReferences(value) {
    return this.parseMessageIdList(value);
  }

  resolveIdentitiesFromAddressInput(value) {
    return this.splitAddressList(value)
      .map((address) => this.inferIdentityFromAddress(String(address || "")))
      .filter(Boolean);
  }

  buildRecipientList({ primary = [], cc = [], bcc = [] } = {}) {
    const recipients = [];
    const byIdentity = new Map();
    const precedence = {
      primary: 3,
      cc: 2,
      bcc: 1
    };

    const addRecipient = (identity, role) => {
      if (!identity) {
        return;
      }

      const existingIndex = byIdentity.get(identity);
      if (existingIndex == null) {
        byIdentity.set(identity, recipients.length);
        recipients.push({
          identity,
          role
        });
        return;
      }

      const existing = recipients[existingIndex];
      if (precedence[role] > precedence[existing.role]) {
        existing.role = role;
      }
    };

    for (const identity of primary) {
      addRecipient(identity, "primary");
    }
    for (const identity of cc) {
      addRecipient(identity, "cc");
    }
    for (const identity of bcc) {
      addRecipient(identity, "bcc");
    }

    if (!recipients.some((recipient) => recipient.role === "primary") && recipients.length > 0) {
      recipients[0].role = "primary";
    }

    return recipients;
  }

  inferIdentityFromAddress(value) {
    if (typeof value !== "string") {
      return null;
    }

    const trimmed = value.trim();
    if (trimmed.startsWith("loom://") || trimmed.startsWith("bridge://")) {
      return trimmed;
    }

    const email = this.normalizeEmailAddress(trimmed);
    if (!email) {
      return null;
    }

    return `loom://${email}`;
  }

  inferEmailFromIdentity(identity) {
    if (typeof identity !== "string") {
      return null;
    }

    if (identity.startsWith("bridge://")) {
      return identity.slice("bridge://".length);
    }

    if (identity.startsWith("loom://")) {
      return identity.slice("loom://".length);
    }

    return null;
  }

  htmlToText(html) {
    if (typeof html !== "string") {
      return "";
    }

    return html
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/gi, " ")
      .replace(/&amp;/gi, "&")
      .replace(/&lt;/gi, "<")
      .replace(/&gt;/gi, ">")
      .replace(/\s+/g, " ")
      .trim();
  }

  resolveThreadFromEmailHeaders(payload) {
    const headers = payload?.headers && typeof payload.headers === "object" ? payload.headers : {};
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

  createBridgeInboundEnvelope(payload, actorIdentity) {
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

    const threading = this.resolveThreadFromEmailHeaders(payload);
    const headers = payload?.headers && typeof payload.headers === "object" ? payload.headers : {};
    const dateHeader = this.resolveHeaderValue(headers, "date");
    const createdAtInput = payload.date || dateHeader;
    const createdAt = parseTime(createdAtInput) != null ? new Date(parseTime(createdAtInput)).toISOString() : nowIso();
    const envelopeId = `env_${generateUlid()}`;
    const incomingMessageId = this.parseMessageId(payload.message_id || this.resolveHeaderValue(headers, "message-id"));
    const canonicalMessageId = incomingMessageId || `${envelopeId}@${this.nodeId}`;

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
          auth_results: payload.auth_results || {
            spf: "none",
            dkim: "none",
            dmarc: "none"
          },
          extraction_confidence:
            typeof payload.extraction_confidence === "number" ? payload.extraction_confidence : 0.25
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

    let quarantined = false;
    if (payload.quarantine === true) {
      quarantined = this.ensureThreadLabel(stored.thread_id, "sys.quarantine");
    } else {
      this.ensureThreadLabel(stored.thread_id, "sys.inbox");
    }

    this.persistAndAudit("bridge.email.inbound", {
      envelope_id: stored.id,
      thread_id: stored.thread_id,
      message_id: canonicalMessageId,
      actor: actorIdentity
    });

    return {
      envelope_id: stored.id,
      thread_id: stored.thread_id,
      message_id: canonicalMessageId,
      quarantined
    };
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
        "X-LOOM-Intent": envelope.content?.structured?.intent || "message.general@v1",
        "X-LOOM-Thread-ID": envelope.thread_id,
        "X-LOOM-Envelope-ID": envelope.id
      },
      attachments: envelope.attachments || []
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
    return Boolean(
      parameters &&
      typeof parameters === "object" &&
      typeof parameters.capability_token === "string" &&
      parameters.capability_token.trim().length > 0
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
      if (typeof parameters.capability_token === "string" && parameters.capability_token.trim()) {
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

    const envelopes = canonicalThreadOrder(thread.envelope_ids.map((id) => this.envelopesById.get(id)));
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
      queued_by: actorIdentity
    };

    this.emailOutboxById.set(outbox.id, outbox);
    this.persistAndAudit("email.outbox.queue", {
      outbox_id: outbox.id,
      envelope_id: outbox.envelope_id,
      thread_id: outbox.thread_id,
      actor: actorIdentity
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
      newest_queued_at: null
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

    if (!emailRelay || typeof emailRelay.send !== "function") {
      this.markEmailOutboxFailure(item, "Email relay adapter not configured");
      this.persistAndAudit("email.outbox.process.failed", {
        outbox_id: item.id,
        envelope_id: item.envelope_id,
        reason: item.last_error,
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

    try {
      const rendered = this.renderBridgeOutboundEmail(renderPayload, item.queued_by);
      const relayResult = await emailRelay.send(rendered);

      item.attempts += 1;
      item.status = "delivered";
      item.updated_at = nowIso();
      item.delivered_at = nowIso();
      item.next_attempt_at = null;
      item.last_error = null;
      item.provider_message_id = relayResult.provider_message_id || null;
      item.last_provider_response = relayResult.response || null;

      const envelope = this.envelopesById.get(item.envelope_id);
      if (envelope) {
        this.ensureThreadLabel(envelope.thread_id, "sys.sent");
      }

      this.persistAndAudit("email.outbox.process.delivered", {
        outbox_id: item.id,
        envelope_id: item.envelope_id,
        thread_id: item.thread_id,
        provider_message_id: item.provider_message_id,
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
        actor: actorIdentity
      });
      return item;
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
        last_error: result.last_error
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

  consumeIdentityRegistrationProof(identityDoc, normalizedIdentity, normalizedSigningKeys, options = {}) {
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
      signingKeys: normalizedSigningKeys
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

    const registrationProof = this.consumeIdentityRegistrationProof(
      identityDoc,
      normalizedIdentity,
      normalizedSigningKeys,
      options
    );

    const remoteExpiresAtInput = options.remoteExpiresAt || identityDoc.remote_expires_at || null;
    const remoteExpiresAt = options.importedRemote
      ? remoteExpiresAtInput && parseTime(remoteExpiresAtInput) != null
        ? new Date(parseTime(remoteExpiresAtInput)).toISOString()
        : new Date(nowMs() + this.remoteIdentityTtlMs).toISOString()
      : null;

    const stored = {
      id: normalizedIdentity,
      type: identityDoc.type || "human",
      display_name: identityDoc.display_name || normalizedIdentity,
      signing_keys: normalizedSigningKeys,
      created_at: existingIdentity?.created_at || identityDoc.created_at || nowIso(),
      updated_at: nowIso(),
      identity_source: options.importedRemote === true ? "remote" : "local",
      imported_remote: options.importedRemote === true,
      remote_fetched_at: options.importedRemote === true ? nowIso() : null,
      remote_expires_at: remoteExpiresAt
    };

    if (existingIdentity) {
      this.removeIdentitySigningKeys(existingIdentity.id, existingIdentity.signing_keys);
    }
    for (const key of normalizedSigningKeys) {
      this.publicKeysById.set(key.key_id, key.public_key_pem);
      this.keyOwnerById.set(key.key_id, normalizedIdentity);
    }

    targetMap.set(stored.id, stored);
    this.persistAndAudit("identity.register", {
      identity: stored.id,
      type: stored.type,
      imported_remote: options.importedRemote === true,
      proof_of_key: Boolean(registrationProof)
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

    const updated = {
      ...identity,
      display_name: nextDisplayName,
      signing_keys: nextSigningKeys,
      updated_at: nowIso(),
      identity_source: "local",
      imported_remote: false,
      remote_fetched_at: null,
      remote_expires_at: null
    };

    this.removeIdentitySigningKeys(identity.id, identity.signing_keys);
    this.applyIdentitySigningKeys(updated.id, updated.signing_keys);
    this.identities.set(updated.id, updated);

    this.persistAndAudit("identity.update", {
      identity: updated.id,
      actor: actorIdentity,
      key_id: actorKeyId,
      signing_key_count: updated.signing_keys.length
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
    const fromIdentity = this.normalizeIdentityReference(envelope?.from?.identity);
    const identityDomain = parseLoomIdentityDomain(fromIdentity);
    if (!fromIdentity || !identityDomain) {
      throw new LoomError("SIGNATURE_INVALID", "Federated envelope sender identity must include a valid domain", 401, {
        field: "from.identity"
      });
    }

    const authorityNodeId = String(verifiedNode?.node_id || "").trim().toLowerCase();
    if (authorityNodeId && identityDomain.toLowerCase() !== authorityNodeId) {
      throw new LoomError("SIGNATURE_INVALID", "Federated envelope sender identity domain does not match sender node", 401, {
        field: "from.identity",
        identity_domain: identityDomain,
        sender_node: verifiedNode?.node_id || null
      });
    }

    return {
      fromIdentity,
      identityDomain
    };
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
    await assertOutboundUrlHostAllowed(identityUrl, {
      allowPrivateNetwork: node?.allow_private_network === true,
      allowedHosts
    });

    let response;
    try {
      response = await fetch(identityUrl, {
        method: "GET",
        redirect: "error",
        headers: {
          accept: "application/json"
        },
        signal: AbortSignal.timeout(this.federationRemoteIdentityFetchTimeoutMs)
      });
    } catch (error) {
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
      const rawBody = await response.text();
      if (Buffer.byteLength(rawBody, "utf-8") > this.federationRemoteIdentityMaxResponseBytes) {
        throw new LoomError("PAYLOAD_TOO_LARGE", "Remote identity response exceeds allowed size", 413, {
          identity: identityUri,
          node_id: node?.node_id || null,
          max_response_bytes: this.federationRemoteIdentityMaxResponseBytes
        });
      }
      payload = JSON.parse(rawBody);
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
      signingKeys: Array.isArray(identityDocument?.signing_keys) ? identityDocument.signing_keys : []
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
    const normalizedMethod = String(method || "GET").toUpperCase();
    if (normalizedMethod !== "GET") {
      return true;
    }

    const normalizedPath = String(path || "").trim();
    return normalizedPath === "/v1/audit" || normalizedPath === "/metrics";
  }

  enforceIdentityRateLimit({ identity, method = "GET", path = "/" } = {}) {
    const normalizedIdentity = this.normalizeIdentityReference(identity);
    if (!normalizedIdentity) {
      return;
    }

    const windowMs = this.identityRateWindowMs;
    const sensitive = this.isIdentitySensitiveRoute(method, path);
    const max = sensitive ? this.identityRateSensitiveMax : this.identityRateDefaultMax;
    if (!windowMs || !max) {
      return;
    }

    const bucket = sensitive ? "sensitive" : "default";
    const key = `${bucket}:${normalizedIdentity}`;
    const now = nowMs();
    const current = this.identityRateByBucket.get(key);
    if (!current || now - current.window_started_at >= windowMs) {
      this.identityRateByBucket.set(key, {
        count: 1,
        window_started_at: now
      });
      return;
    }

    if (current.count >= max) {
      const retryAfterMs = Math.max(1, current.window_started_at + windowMs - now);
      throw new LoomError("RATE_LIMIT_EXCEEDED", "Identity rate limit exceeded", 429, {
        limit: max,
        window_ms: windowMs,
        retry_after_ms: retryAfterMs,
        scope: `identity:${bucket}`,
        identity: normalizedIdentity
      });
    }

    current.count += 1;
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

    return sanitized;
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
      secret_last_used_at: null
    };

    if (token.expires_at && parseTime(token.expires_at) == null) {
      throw new LoomError("ENVELOPE_INVALID", "Capability expires_at must be ISO-8601", 400, {
        field: "expires_at"
      });
    }

    this.capabilitiesById.set(token.id, token);
    this.capabilityIdBySecretHash.set(token.secret_hash, token.id);
    this.persistAndAudit("capability.issue", {
      capability_id: token.id,
      thread_id: token.thread_id,
      issued_by: token.issued_by,
      issued_to: token.issued_to
    });
    return this.sanitizeCapabilityToken(token, {
      includePresentationToken: true,
      presentationToken
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

  validateCapabilityForThreadOperation({ thread, intent, actorIdentity, capabilityTokenValue, capabilityTokenId = null }) {
    const requiredGrant = THREAD_OP_TO_GRANT[intent] || "admin";

    if (this.isThreadOwner(thread, actorIdentity)) {
      return null;
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

    return token;
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
    if (!thread || !parentEnvelopeId) {
      return 0;
    }

    let resolved = 0;
    for (const envelopeId of thread.envelope_ids || []) {
      if (envelopeId === parentEnvelopeId) {
        continue;
      }

      const envelope = this.envelopesById.get(envelopeId);
      if (!envelope || envelope.parent_id !== parentEnvelopeId) {
        continue;
      }

      if (!envelope.meta?.pending_parent) {
        continue;
      }

      envelope.meta = {
        ...envelope.meta,
        pending_parent: false,
        parent_resolved_at: nowIso()
      };
      resolved += 1;
    }

    if (resolved > 0) {
      thread.pending_parent_count = Math.max(0, Number(thread.pending_parent_count || 0) - resolved);
    }

    return resolved;
  }

  prepareThreadOperation(thread, envelope, actorIdentity, context = {}) {
    const intent = envelope.content?.structured?.intent;
    const parameters = envelope.content?.structured?.parameters || {};

    if (!intent || typeof intent !== "string") {
      throw new LoomError("ENVELOPE_INVALID", "thread_op requires content.structured.intent", 400, {
        field: "content.structured.intent"
      });
    }

    const payloadCapabilityToken =
      typeof parameters.capability_token === "string" ? parameters.capability_token.trim() : "";
    if (payloadCapabilityToken) {
      throw new LoomError(
        "ENVELOPE_INVALID",
        "Capability token must be provided via x-loom-capability-token header, not envelope payload",
        400,
        {
          field: "content.structured.parameters.capability_token"
        }
      );
    }

    const capabilityTokenValue = String(context?.capabilityPresentationToken || "").trim();
    const capabilityTokenId =
      typeof parameters.capability_id === "string" && parameters.capability_id.trim()
        ? parameters.capability_id.trim()
        : null;

    const token = this.validateCapabilityForThreadOperation({
      thread,
      intent,
      actorIdentity,
      capabilityTokenValue,
      capabilityTokenId
    });

    return () => {
      switch (intent) {
        case "thread.add_participant@v1": {
          const participantIdentity = parameters.identity;
          if (!isIdentity(participantIdentity)) {
            throw new LoomError("ENVELOPE_INVALID", "thread.add_participant requires valid parameters.identity", 400, {
              field: "content.structured.parameters.identity"
            });
          }

          const existing = thread.participants.find(
            (participant) => participant.identity === participantIdentity
          );

          if (!existing) {
            thread.participants.push({
              identity: participantIdentity,
              role: parameters.role || "participant",
              joined_at: envelope.created_at,
              left_at: null
            });
          } else {
            existing.left_at = null;
            existing.role = parameters.role || existing.role;
          }
          break;
        }

        case "thread.remove_participant@v1": {
          const participantIdentity = parameters.identity;
          const existing = thread.participants.find(
            (participant) => participant.identity === participantIdentity
          );

          if (!existing) {
            throw new LoomError("ENVELOPE_INVALID", "Participant not found for removal", 400, {
              participant: participantIdentity
            });
          }

          if (existing.role === "owner") {
            throw new LoomError("STATE_TRANSITION_INVALID", "Cannot remove thread owner directly", 409, {
              participant: participantIdentity
            });
          }

          existing.left_at = existing.left_at || envelope.created_at;
          break;
        }

        case "thread.update@v1": {
          if (typeof parameters.subject === "string") {
            thread.subject = parameters.subject;
          }

          if (Array.isArray(parameters.labels)) {
            thread.labels = Array.from(
              new Set(parameters.labels.map((label) => String(label).trim()).filter(Boolean))
            );
          }
          break;
        }

        case "thread.resolve@v1":
          assertTransition(thread, ["active"], "resolved");
          thread.state = "resolved";
          break;

        case "thread.archive@v1":
          assertTransition(thread, ["resolved"], "archived");
          thread.state = "archived";
          break;

        case "thread.lock@v1":
          assertTransition(thread, ["active", "resolved"], "locked");
          thread.state = "locked";
          break;

        case "thread.reopen@v1":
          assertTransition(thread, ["resolved", "locked"], "active");
          thread.state = "active";
          break;

        case "thread.delegate@v1": {
          const delegateIdentity = parameters.identity;
          if (!isIdentity(delegateIdentity)) {
            throw new LoomError("ENVELOPE_INVALID", "thread.delegate requires valid parameters.identity", 400, {
              field: "content.structured.parameters.identity"
            });
          }

          for (const participant of thread.participants) {
            if (participant.role === "owner" && participant.left_at == null) {
              participant.role = "participant";
            }
          }

          const existing = thread.participants.find(
            (participant) => participant.identity === delegateIdentity
          );

          if (!existing) {
            thread.participants.push({
              identity: delegateIdentity,
              role: "owner",
              joined_at: envelope.created_at,
              left_at: null
            });
          } else {
            existing.left_at = null;
            existing.role = "owner";
          }

          break;
        }

        case "capability.revoked@v1": {
          const capabilityId = parameters.capability_id;
          const target = this.capabilitiesById.get(capabilityId);
          if (!target || target.thread_id !== thread.id) {
            throw new LoomError("ENVELOPE_INVALID", "Capability token not found for revocation", 400, {
              capability_id: capabilityId
            });
          }

          if (!target.revoked) {
            target.revoked = true;
            target.revoked_at = envelope.created_at;
            thread.cap_epoch += 1;
          }
          break;
        }

        case "capability.spent@v1": {
          const capabilityId = parameters.capability_id;
          const target = this.capabilitiesById.get(capabilityId);
          if (!target || target.thread_id !== thread.id) {
            throw new LoomError("ENVELOPE_INVALID", "Capability token not found for spend update", 400, {
              capability_id: capabilityId
            });
          }

          if (!target.spent) {
            target.spent = true;
            target.spent_at = envelope.created_at;
          }
          break;
        }

        case "thread.fork@v1":
        case "thread.merge@v1":
        case "thread.link@v1":
          // MVP behavior: accept operation and preserve it in authoritative event-log.
          break;

        default:
          throw new LoomError("ENVELOPE_INVALID", `Unsupported thread operation intent: ${intent}`, 400, {
            intent
          });
      }

      if (token?.single_use && !token.spent) {
        token.spent = true;
        token.spent_at = envelope.created_at;
      }
    };
  }

  resolveEnvelopeSignaturePublicKey(envelope, signatureKeyId, context = {}) {
    const normalizedSignatureKeyId = String(signatureKeyId || "").trim();
    const normalizedFromKeyId = String(envelope?.from?.key_id || "").trim();
    if (!normalizedFromKeyId || normalizedFromKeyId !== normalizedSignatureKeyId) {
      throw new LoomError("SIGNATURE_INVALID", "from.key_id must match signature.key_id", 401, {
        field: "from.key_id"
      });
    }

    const fromIdentity = this.normalizeIdentityReference(envelope?.from?.identity);
    if (!fromIdentity) {
      throw new LoomError("SIGNATURE_INVALID", "Envelope sender identity is missing", 401, {
        field: "from.identity"
      });
    }

    if (fromIdentity.startsWith("bridge://")) {
      if (normalizedSignatureKeyId !== this.systemSigningKeyId) {
        throw new LoomError("SIGNATURE_INVALID", "Bridge identities must be signed by system signing key", 401, {
          field: "signature.key_id",
          identity: fromIdentity
        });
      }
      const systemPublicKey = this.resolvePublicKey(this.systemSigningKeyId);
      if (!systemPublicKey) {
        throw new LoomError("SIGNATURE_INVALID", "System signing key is not available for verification", 401, {
          field: "signature.key_id"
        });
      }
      return systemPublicKey;
    }

    if (context.allowSystemSignatureOverride === true && normalizedSignatureKeyId === this.systemSigningKeyId) {
      const systemPublicKey = this.resolvePublicKey(this.systemSigningKeyId);
      if (!systemPublicKey) {
        throw new LoomError("SIGNATURE_INVALID", "System signing key is not available for verification", 401, {
          field: "signature.key_id"
        });
      }
      return systemPublicKey;
    }

    const identityPublicKey = this.resolveIdentitySigningPublicKey(fromIdentity, normalizedSignatureKeyId);
    if (!identityPublicKey) {
      throw new LoomError(
        "SIGNATURE_INVALID",
        `Signing key is not registered for envelope sender identity: ${normalizedSignatureKeyId}`,
        401,
        {
          field: "signature.key_id",
          identity: fromIdentity
        }
      );
    }

    return identityPublicKey;
  }

  ingestEnvelope(envelope, context = {}) {
    validateEnvelopeOrThrow(envelope);

    const actorIdentity = context.actorIdentity || envelope.from?.identity;
    if (actorIdentity !== envelope.from?.identity) {
      throw new LoomError("CAPABILITY_DENIED", "Authenticated actor must match envelope.from.identity", 403, {
        actor: actorIdentity,
        from: envelope.from?.identity
      });
    }

    this.enforceThreadRecipientFanout(envelope);

    if (this.envelopesById.has(envelope.id)) {
      throw new LoomError("ENVELOPE_DUPLICATE", `Envelope already exists: ${envelope.id}`, 409, {
        envelope_id: envelope.id
      });
    }

    this.enforceEnvelopeDailyQuota(actorIdentity, envelope.created_at);

    verifyEnvelopeSignature(envelope, (keyId, signedEnvelope) =>
      this.resolveEnvelopeSignaturePublicKey(signedEnvelope, keyId, context)
    );

    if (envelope.from?.type === "agent") {
      const contextRequiredActions = Array.isArray(context.requiredActions)
        ? context.requiredActions
        : context.requiredAction
          ? [context.requiredAction]
          : [];
      const requiredActions =
        contextRequiredActions.length > 0
          ? Array.from(new Set(contextRequiredActions.map((value) => String(value || "").trim()).filter(Boolean)))
          : this.resolveDelegationRequiredActions(envelope);
      verifyDelegationChainOrThrow(envelope, {
        resolveIdentity: (identity) => this.resolveIdentity(identity),
        resolvePublicKey: (keyId) => this.resolvePublicKey(keyId),
        isDelegationRevoked: (link) => this.isDelegationRevoked(link),
        now: nowMs(),
        requiredActions
      });
    }

    const threadId = envelope.thread_id;
    const existingThread = this.threadsById.get(threadId);

    if (existingThread?.state === "locked" && envelope.type !== "thread_op") {
      throw new LoomError("THREAD_LOCKED", `Thread is locked: ${threadId}`, 409, {
        thread_id: threadId
      });
    }

    if (existingThread && envelope.type !== "thread_op" && !this.isActiveParticipant(existingThread, actorIdentity)) {
      throw new LoomError("CAPABILITY_DENIED", "Sender is not an active participant of the thread", 403, {
        thread_id: threadId,
        actor: actorIdentity
      });
    }

    if (envelope.type === "thread_op" && !existingThread) {
      throw new LoomError("THREAD_NOT_FOUND", `thread_op requires an existing thread: ${threadId}`, 404, {
        thread_id: threadId
      });
    }

    const isNewThread = !existingThread;
    const thread =
      existingThread ||
      {
        id: threadId,
        root_envelope_id: envelope.parent_id ? null : envelope.id,
        subject: null,
        state: "active",
        created_at: envelope.created_at,
        updated_at: nowIso(),
        participants: [],
        mailbox_state: {},
        labels: [],
        cap_epoch: 0,
        encryption: {
          enabled: false,
          profile: null,
          key_epoch: 0
        },
        event_seq_counter: 0,
        envelope_ids: [],
        pending_parent_count: 0
      };

    const operationMutation =
      envelope.type === "thread_op" ? this.prepareThreadOperation(thread, envelope, actorIdentity, context) : null;

    const threadSnapshot = !isNewThread ? structuredClone(thread) : null;

    const pendingParent = !!(envelope.parent_id && !this.envelopesById.has(envelope.parent_id));
    if (pendingParent) {
      thread.pending_parent_count = Number(thread.pending_parent_count || 0) + 1;
    }
    thread.event_seq_counter += 1;

    const storedEnvelope = {
      ...envelope,
      meta: {
        ...(envelope.meta || {}),
        node_id: this.nodeId,
        received_at: nowIso(),
        event_seq: thread.event_seq_counter,
        origin_event_seq: envelope.meta?.origin_event_seq ?? thread.event_seq_counter,
        pending_parent: pendingParent
      }
    };

    thread.envelope_ids.push(storedEnvelope.id);
    thread.updated_at = nowIso();

    if (!thread.root_envelope_id && !storedEnvelope.parent_id) {
      thread.root_envelope_id = storedEnvelope.id;
    }

    if (isNewThread) {
      const participantUris = new Set([
        storedEnvelope.from.identity,
        ...(storedEnvelope.to || []).map((recipient) => recipient.identity)
      ]);

      thread.participants = Array.from(participantUris).map((identityUri, index) => ({
        identity: identityUri,
        role: index === 0 ? "owner" : "participant",
        joined_at: storedEnvelope.created_at,
        left_at: null
      }));
      for (const participant of thread.participants) {
        this.ensureMailboxState(thread, participant.identity);
      }
    }

    this.envelopesById.set(storedEnvelope.id, storedEnvelope);
    this.threadsById.set(thread.id, thread);

    const rollback = () => {
      this.envelopesById.delete(storedEnvelope.id);

      if (isNewThread) {
        this.threadsById.delete(thread.id);
      } else if (threadSnapshot) {
        this.threadsById.set(thread.id, threadSnapshot);
      }
    };

    const threadEnvelopes = thread.envelope_ids.map((id) => this.envelopesById.get(id));
    const dagResult = validateThreadDag(threadEnvelopes);

    if (!dagResult.valid) {
      rollback();
      throw new LoomError("ENVELOPE_INVALID", "Thread DAG contains a cycle", 400, {
        thread_id: thread.id,
        envelope_id: storedEnvelope.id
      });
    }

    try {
      if (operationMutation) {
        operationMutation();
        thread.updated_at = nowIso();
      }
    } catch (error) {
      rollback();
      throw error;
    }

    const resolvedPendingParents = this.resolvePendingParentsForThread(thread, storedEnvelope.id);
    const deliveryWrappers = this.ensureDeliveryWrappersForEnvelope(storedEnvelope);
    this.trackEnvelopeDailyQuota(storedEnvelope.from?.identity, storedEnvelope.created_at);

    this.persistAndAudit("envelope.ingest", {
      envelope_id: storedEnvelope.id,
      thread_id: storedEnvelope.thread_id,
      type: storedEnvelope.type,
      pending_parent: pendingParent,
      resolved_pending_parents: resolvedPendingParents,
      delivery_wrapper_count: deliveryWrappers.length,
      actor: actorIdentity
    });

    return storedEnvelope;
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
    const thread = this.threadsById.get(threadId);
    if (!thread) {
      return null;
    }

    const envelopes = thread.envelope_ids.map((id) => this.envelopesById.get(id));
    return canonicalThreadOrder(envelopes);
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
    for (const envelope of this.envelopesById.values()) {
      const thread = this.threadsById.get(envelope.thread_id);
      if (!thread || !this.isActiveParticipant(thread, actorIdentity)) {
        continue;
      }

      if (threadFilter && envelope.thread_id !== threadFilter) {
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

    matches.sort((a, b) => b.created_at.localeCompare(a.created_at));
    return {
      total: matches.length,
      results: matches.slice(0, limit)
    };
  }

  getNodeDocument(domain) {
    let federationPublicKeyPem = null;
    if (this.federationSigningPrivateKeyPem) {
      try {
        federationPublicKeyPem = derivePublicKeyPemFromPrivateKeyPem(this.federationSigningPrivateKeyPem);
      } catch {
        federationPublicKeyPem = null;
      }
    }

    const federationSigningKeys =
      federationPublicKeyPem && this.federationSigningKeyId
        ? [
            {
              key_id: this.federationSigningKeyId,
              public_key_pem: federationPublicKeyPem
            }
          ]
        : [];

    return {
      loom_version: "1.1",
      node_id: this.nodeId,
      domain,
      api_url: `https://${domain}/v1`,
      websocket_url: `wss://${domain}/ws`,
      deliver_url: `https://${domain}/v1/federation/deliver`,
      identity_resolve_url: `https://${domain}/v1/identity/{identity}`,
      federation: {
        signing_key_id: this.federationSigningKeyId,
        public_key_pem: federationPublicKeyPem,
        signing_keys: federationSigningKeys,
        outbox_url: `https://${domain}/v1/federation/outbox`,
        challenge_url: `https://${domain}/v1/federation/challenge`,
        identity_resolve_url: `https://${domain}/v1/identity/{identity}`
      },
      auth_endpoints: {
        identity_challenge: `https://${domain}/v1/identity/challenge`,
        challenge: `https://${domain}/v1/auth/challenge`,
        token: `https://${domain}/v1/auth/token`,
        refresh: `https://${domain}/v1/auth/refresh`
      },
      supported_profiles: ["loom-core-1"],
      auth: {
        proof_of_key: true
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
      signing_keys: normalizeIdentitySigningKeys(identity.signing_keys)
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
      signingKeys: payload.signing_keys
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
}
