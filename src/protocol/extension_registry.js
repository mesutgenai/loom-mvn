export const PROTOCOL_PROFILE_FULL = "loom-v1.1-full";
export const PROTOCOL_PROFILE_CORE = "loom-core-1";

const PROTOCOL_PROFILE_ALIASES = new Map([
  ["loom-v1.1-full", PROTOCOL_PROFILE_FULL],
  ["full", PROTOCOL_PROFILE_FULL],
  ["loom-full", PROTOCOL_PROFILE_FULL],
  ["loom-core-1", PROTOCOL_PROFILE_CORE],
  ["core", PROTOCOL_PROFILE_CORE],
  ["core-only", PROTOCOL_PROFILE_CORE],
  ["loom-core", PROTOCOL_PROFILE_CORE]
]);

export const EXTENSION_REGISTRY = Object.freeze([
  Object.freeze({
    id: "loom-ext-email-bridge-v1",
    status: "active",
    owner: "mail-bridge",
    spec_ref: "docs/INBOUND-BRIDGE-HARDENING.md",
    description: "Inbound/outbound email bridge and translation boundaries."
  }),
  Object.freeze({
    id: "loom-ext-legacy-gateway-v1",
    status: "active",
    owner: "legacy-gateway",
    spec_ref: "docs/IMAP-COMPATIBILITY-MATRIX.md",
    description: "Legacy SMTP/IMAP gateway compatibility surface."
  }),
  Object.freeze({
    id: "loom-ext-mcp-runtime-v1",
    status: "active",
    owner: "mcp-runtime",
    spec_ref: "docs/CONFORMANCE.md",
    description: "MCP tool execution and SSE/runtime semantics."
  }),
  Object.freeze({
    id: "loom-ext-workflow-v1",
    status: "active",
    owner: "workflow",
    spec_ref: "docs/CONFORMANCE.md",
    description: "Workflow orchestration envelope semantics."
  }),
  Object.freeze({
    id: "loom-ext-e2ee-x25519-v1",
    status: "active",
    owner: "e2ee",
    spec_ref: "LOOM-Protocol-Spec-v1.1.md",
    description: "X25519 + XChaCha20 encrypted content profile (v1)."
  }),
  Object.freeze({
    id: "loom-ext-e2ee-x25519-v2",
    status: "active",
    owner: "e2ee",
    spec_ref: "LOOM-Protocol-Spec-v1.1.md",
    description: "X25519 + XChaCha20 encrypted content profile (v2)."
  }),
  Object.freeze({
    id: "loom-ext-e2ee-mls-1",
    status: "active",
    owner: "e2ee",
    spec_ref: "LOOM-Protocol-Spec-v1.1.md",
    description: "MLS-backed encrypted content profile support."
  }),
  Object.freeze({
    id: "loom-ext-compliance-v1",
    status: "active",
    owner: "compliance",
    spec_ref: "docs/COMPLIANCE-CONTROLS.md",
    description: "Compliance and audit overlay endpoints."
  })
]);

export function listProtocolProfiles() {
  return [PROTOCOL_PROFILE_FULL, PROTOCOL_PROFILE_CORE];
}

export function normalizeProtocolProfile(value, fallback = PROTOCOL_PROFILE_FULL) {
  const raw = String(value == null ? fallback : value)
    .trim()
    .toLowerCase();
  const normalized = PROTOCOL_PROFILE_ALIASES.get(raw);
  if (!normalized) {
    throw new Error(
      `Unknown LOOM protocol profile: ${value}. Supported profiles: ${listProtocolProfiles().join(", ")}`
    );
  }
  return normalized;
}

function toEnabledBoolean(value, fallback) {
  if (value == null) {
    return fallback;
  }
  return value === true;
}

export function buildProtocolExtensionSnapshot(options = {}) {
  const protocolProfile = normalizeProtocolProfile(options.protocolProfile, PROTOCOL_PROFILE_FULL);
  const coreMode = protocolProfile === PROTOCOL_PROFILE_CORE;
  const runtime = options.runtime || {};

  const enabledById = new Map([
    ["loom-ext-email-bridge-v1", toEnabledBoolean(runtime.email_bridge, !coreMode)],
    ["loom-ext-legacy-gateway-v1", toEnabledBoolean(runtime.legacy_gateway, !coreMode)],
    ["loom-ext-mcp-runtime-v1", toEnabledBoolean(runtime.mcp_runtime, !coreMode)],
    ["loom-ext-workflow-v1", toEnabledBoolean(runtime.workflow, !coreMode)],
    ["loom-ext-e2ee-x25519-v1", toEnabledBoolean(runtime.e2ee_x25519_v1, !coreMode)],
    ["loom-ext-e2ee-x25519-v2", toEnabledBoolean(runtime.e2ee_x25519_v2, !coreMode)],
    ["loom-ext-e2ee-mls-1", toEnabledBoolean(runtime.e2ee_mls_1, !coreMode)],
    ["loom-ext-compliance-v1", toEnabledBoolean(runtime.compliance, !coreMode)],
  ]);

  return EXTENSION_REGISTRY.map((entry) => {
    if (entry.status === "reserved") {
      return {
        ...entry,
        enabled: false,
        reason: "reserved"
      };
    }
    if (coreMode) {
      return {
        ...entry,
        enabled: false,
        reason: "disabled_by_protocol_profile"
      };
    }
    const enabled = enabledById.get(entry.id) === true;
    return {
      ...entry,
      enabled,
      reason: enabled ? "enabled" : "disabled_by_runtime_policy"
    };
  });
}
