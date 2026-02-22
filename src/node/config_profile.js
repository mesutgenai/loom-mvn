const CONFIG_PROFILE_ALIASES = new Map([
  ["secure_public", "secure_public"],
  ["secure-public", "secure_public"],
  ["securepublic", "secure_public"],
  ["public_secure", "secure_public"],
  ["public-secure", "secure_public"],
  ["secure", "secure_public"]
]);

const SECURE_PUBLIC_DEFAULTS = Object.freeze([
  { optionKey: "publicService", envKey: "LOOM_PUBLIC_SERVICE", value: true },
  { optionKey: "requireHttpsFromProxy", envKey: "LOOM_REQUIRE_HTTPS_FROM_PROXY", value: true },
  { optionKey: "metricsPublic", envKey: "LOOM_METRICS_PUBLIC", value: false },
  { optionKey: "demoPublicReads", envKey: "LOOM_DEMO_PUBLIC_READS", value: false },
  { optionKey: "identityRequireProof", envKey: "LOOM_IDENTITY_REQUIRE_PROOF", value: true },
  {
    optionKey: "requirePortableThreadOpCapability",
    envKey: "LOOM_REQUIRE_PORTABLE_THREAD_OP_CAPABILITY",
    value: true
  },
  { optionKey: "requireExternalSigningKeys", envKey: "LOOM_REQUIRE_EXTERNAL_SIGNING_KEYS", value: true },
  {
    optionKey: "requireDistinctFederationSigningKey",
    envKey: "LOOM_REQUIRE_DISTINCT_FEDERATION_SIGNING_KEY",
    value: true
  },
  {
    optionKey: "federationRequireProtocolCapabilities",
    envKey: "LOOM_FEDERATION_REQUIRE_PROTOCOL_CAPABILITIES",
    value: true
  },
  {
    optionKey: "federationRequireE2eeProfileOverlap",
    envKey: "LOOM_FEDERATION_REQUIRE_E2EE_PROFILE_OVERLAP",
    value: true
  },
  {
    optionKey: "federationRequireTrustModeParity",
    envKey: "LOOM_FEDERATION_REQUIRE_TRUST_MODE_PARITY",
    value: true
  },
  {
    optionKey: "federationRequireSignedReceipts",
    envKey: "LOOM_FEDERATION_REQUIRE_SIGNED_RECEIPTS",
    value: true
  },
  {
    optionKey: "federationChallengeEscalationEnabled",
    envKey: "LOOM_FEDERATION_CHALLENGE_ESCALATION_ENABLED",
    value: true
  },
  { optionKey: "federationTrustMode", envKey: "LOOM_FEDERATION_TRUST_MODE", value: "public_dns_webpki" },
  { optionKey: "federationTrustFailClosed", envKey: "LOOM_FEDERATION_TRUST_FAIL_CLOSED", value: true },
  { optionKey: "federationTrustRequireDnssec", envKey: "LOOM_FEDERATION_TRUST_REQUIRE_DNSSEC", value: true },
  {
    optionKey: "federationTrustRequireTransparency",
    envKey: "LOOM_FEDERATION_TRUST_REQUIRE_TRANSPARENCY",
    value: true
  },
  {
    optionKey: "federationTrustDnsResolverMode",
    envKey: "LOOM_FEDERATION_TRUST_DNS_RESOLVER_MODE",
    value: "dnssec_doh"
  },
  { optionKey: "bridgeInboundEnabled", envKey: "LOOM_BRIDGE_EMAIL_INBOUND_ENABLED", value: true },
  {
    optionKey: "bridgeInboundPublicConfirmed",
    envKey: "LOOM_BRIDGE_EMAIL_INBOUND_PUBLIC_CONFIRMED",
    value: true
  },
  {
    optionKey: "bridgeInboundRequireAdminToken",
    envKey: "LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_ADMIN_TOKEN",
    value: true
  },
  {
    optionKey: "bridgeInboundRequireAuthResults",
    envKey: "LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_AUTH_RESULTS",
    value: true
  },
  {
    optionKey: "bridgeInboundRequireDmarcPass",
    envKey: "LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_DMARC_PASS",
    value: true
  },
  {
    optionKey: "bridgeInboundRejectOnAuthFailure",
    envKey: "LOOM_BRIDGE_EMAIL_INBOUND_REJECT_ON_AUTH_FAILURE",
    value: true
  },
  {
    optionKey: "bridgeInboundQuarantineOnAuthFailure",
    envKey: "LOOM_BRIDGE_EMAIL_INBOUND_QUARANTINE_ON_AUTH_FAILURE",
    value: true
  },
  {
    optionKey: "bridgeInboundAllowPayloadAuthResults",
    envKey: "LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_PAYLOAD_AUTH_RESULTS",
    value: false
  },
  {
    optionKey: "bridgeInboundAllowAutomaticActuation",
    envKey: "LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_AUTOMATIC_ACTUATION",
    value: false
  },
  { optionKey: "inboundContentFilterEnabled", envKey: "LOOM_INBOUND_CONTENT_FILTER_ENABLED", value: true },
  {
    optionKey: "inboundContentFilterRejectMalware",
    envKey: "LOOM_INBOUND_CONTENT_FILTER_REJECT_MALWARE",
    value: true
  },
  {
    optionKey: "inboundContentFilterProfileDefault",
    envKey: "LOOM_INBOUND_CONTENT_FILTER_PROFILE_DEFAULT",
    value: "balanced"
  },
  {
    optionKey: "inboundContentFilterProfileBridge",
    envKey: "LOOM_INBOUND_CONTENT_FILTER_PROFILE_BRIDGE",
    value: "strict"
  },
  {
    optionKey: "inboundContentFilterProfileFederation",
    envKey: "LOOM_INBOUND_CONTENT_FILTER_PROFILE_FEDERATION",
    value: "agent"
  },
  { optionKey: "requireTlsProxy", envKey: "LOOM_REQUIRE_TLS_PROXY", value: true },
  { optionKey: "allowOpenOutboundHostsOnPublicBind", envKey: "LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND", value: false }
]);

const CONFIG_PROFILE_SPECS = Object.freeze({
  secure_public: Object.freeze({
    description: "Public-service secure defaults with fail-closed bridge and federation posture.",
    defaults: SECURE_PUBLIC_DEFAULTS
  })
});

function isUnset(value) {
  if (value == null) {
    return true;
  }
  if (typeof value === "string") {
    return value.trim().length === 0;
  }
  return false;
}

function serializeEnvValue(value) {
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  return String(value);
}

function normalizeProfileName(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (!normalized || normalized === "none" || normalized === "off" || normalized === "default") {
    return null;
  }
  const alias = CONFIG_PROFILE_ALIASES.get(normalized);
  if (!alias) {
    const supported = Array.from(new Set(CONFIG_PROFILE_ALIASES.values())).sort().join(", ");
    throw new Error(`Unknown LOOM config profile: ${value}. Supported profiles: ${supported}`);
  }
  return alias;
}

export function resolveConfigProfileName(value) {
  return normalizeProfileName(value);
}

export function listConfigProfiles() {
  return Object.keys(CONFIG_PROFILE_SPECS);
}

export function getConfigProfileSpec(profileName) {
  const normalized = normalizeProfileName(profileName);
  return normalized ? CONFIG_PROFILE_SPECS[normalized] : null;
}

export function applyConfigProfileEnvDefaults(env, profileNameInput = env?.LOOM_CONFIG_PROFILE) {
  if (!env || typeof env !== "object") {
    throw new Error("applyConfigProfileEnvDefaults requires an env object.");
  }
  const profileName = normalizeProfileName(profileNameInput);
  if (!profileName) {
    return null;
  }
  const spec = CONFIG_PROFILE_SPECS[profileName];
  for (const entry of spec.defaults) {
    if (isUnset(env[entry.envKey])) {
      env[entry.envKey] = serializeEnvValue(entry.value);
    }
  }
  env.LOOM_CONFIG_PROFILE = profileName;
  return profileName;
}

export function applyConfigProfileOptionDefaults(options = {}, env = process.env) {
  if (!options || typeof options !== "object") {
    throw new Error("applyConfigProfileOptionDefaults requires an options object.");
  }
  const profileName = normalizeProfileName(options.configProfile ?? env?.LOOM_CONFIG_PROFILE);
  if (!profileName) {
    return null;
  }
  const spec = CONFIG_PROFILE_SPECS[profileName];
  options.configProfile = profileName;
  for (const entry of spec.defaults) {
    if (options[entry.optionKey] != null) {
      continue;
    }
    if (!isUnset(env?.[entry.envKey])) {
      continue;
    }
    options[entry.optionKey] = entry.value;
  }
  return profileName;
}
