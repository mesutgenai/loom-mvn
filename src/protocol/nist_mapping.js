// ─── NIST SP 800-53 Rev 5 & SP 800-207 Alignment ── Section 16.10 ──────────
//
// Machine-readable control mappings for NIST compliance. Pure-function module
// with no store or server dependencies.

// ─── Framework Reference ────────────────────────────────────────────────────

export const NIST_FRAMEWORK_REF = Object.freeze({
  standard: "NIST SP 800-53 Rev 5",
  publication_date: "2020-09",
  supplementary: Object.freeze([
    "NIST SP 800-207 (Zero Trust Architecture)",
    "NIST SP 800-208 (Post-Quantum Cryptography)",
    "NIST SP 800-56A Rev 3 (Key Establishment)"
  ])
});

// ─── Control Families ───────────────────────────────────────────────────────

export const NIST_FAMILIES = Object.freeze({
  AC: "Access Control",
  AU: "Audit and Accountability",
  IA: "Identification and Authentication",
  SC: "System and Communications Protection",
  SI: "System and Information Integrity",
  CM: "Configuration Management",
  IR: "Incident Response"
});

// ─── SP 800-53 Control Mappings ─────────────────────────────────────────────

export const NIST_CONTROL_MAPPINGS = Object.freeze([
  // ── Access Control (AC) ─────────────────────────────────────────────────
  Object.freeze({
    control_id: "AC-1",
    family: "AC",
    title: "Policy and Procedures",
    description: "Establish and maintain access control policy and procedures.",
    loom_feature: "MIME policy modes (allowlist/denylist/permissive), capability-based access",
    compliance_check_id: "mime_policy_configured"
  }),
  Object.freeze({
    control_id: "AC-2",
    family: "AC",
    title: "Account Management",
    description: "Manage information system accounts.",
    loom_feature: "Identity types (human/agent/team/service/bridge), identity verification",
    compliance_check_id: "identity_verification_enabled"
  }),
  Object.freeze({
    control_id: "AC-3",
    family: "AC",
    title: "Access Enforcement",
    description: "Enforce approved authorizations for logical access.",
    loom_feature: "Capability tokens with audience constraints, admin token protection",
    compliance_check_id: "admin_token_set"
  }),
  Object.freeze({
    control_id: "AC-4",
    family: "AC",
    title: "Information Flow Enforcement",
    description: "Enforce approved authorizations for controlling information flow.",
    loom_feature: "Channel rules, audience modes (thread/recipients/custom), content filtering",
    compliance_check_id: "content_filter_enabled"
  }),
  Object.freeze({
    control_id: "AC-6",
    family: "AC",
    title: "Least Privilege",
    description: "Employ the principle of least privilege.",
    loom_feature: "Scoped capability tokens, recipient roles (primary/cc/observer/bcc)",
    compliance_check_id: null
  }),
  Object.freeze({
    control_id: "AC-7",
    family: "AC",
    title: "Unsuccessful Logon Attempts",
    description: "Enforce a limit on consecutive invalid access attempts.",
    loom_feature: "Rate limiting on authentication endpoints, configurable rate windows",
    compliance_check_id: "rate_limit_configured"
  }),
  Object.freeze({
    control_id: "AC-17",
    family: "AC",
    title: "Remote Access",
    description: "Establish and manage remote access sessions.",
    loom_feature: "TLS enforcement for federation, webhook signature verification",
    compliance_check_id: "tls_enforced"
  }),

  // ── Audit and Accountability (AU) ───────────────────────────────────────
  Object.freeze({
    control_id: "AU-2",
    family: "AU",
    title: "Event Logging",
    description: "Identify events that need to be logged.",
    loom_feature: "Audit log with hash chain integrity, configurable retention",
    compliance_check_id: "audit_log_enabled"
  }),
  Object.freeze({
    control_id: "AU-3",
    family: "AU",
    title: "Content of Audit Records",
    description: "Generate audit records containing sufficient information.",
    loom_feature: "Structured audit entries with actor, action, resource_type, resource_id, timestamp, metadata",
    compliance_check_id: "audit_log_enabled"
  }),
  Object.freeze({
    control_id: "AU-6",
    family: "AU",
    title: "Audit Record Review, Analysis, and Reporting",
    description: "Review and analyze audit records for indications of inappropriate activity.",
    loom_feature: "Compliance audit endpoint, automated compliance scoring",
    compliance_check_id: null
  }),
  Object.freeze({
    control_id: "AU-8",
    family: "AU",
    title: "Time Stamps",
    description: "Use internal system clocks to generate time stamps for audit records.",
    loom_feature: "ISO 8601 timestamps on all envelopes and audit entries",
    compliance_check_id: null
  }),
  Object.freeze({
    control_id: "AU-9",
    family: "AU",
    title: "Protection of Audit Information",
    description: "Protect audit information from unauthorized access.",
    loom_feature: "SHA-256 hash chain for audit log tamper detection",
    compliance_check_id: "hash_chain_enabled"
  }),
  Object.freeze({
    control_id: "AU-12",
    family: "AU",
    title: "Audit Record Generation",
    description: "Generate audit records for defined events.",
    loom_feature: "Automatic audit logging for envelope operations, blob uploads, admin actions",
    compliance_check_id: "audit_log_enabled"
  }),

  // ── Identification and Authentication (IA) ──────────────────────────────
  Object.freeze({
    control_id: "IA-2",
    family: "IA",
    title: "Identification and Authentication (Organizational Users)",
    description: "Uniquely identify and authenticate organizational users.",
    loom_feature: "Ed25519 signing keys per identity, ULID-based unique identifiers",
    compliance_check_id: "signing_enabled"
  }),
  Object.freeze({
    control_id: "IA-5",
    family: "IA",
    title: "Authenticator Management",
    description: "Manage information system authenticators.",
    loom_feature: "Key rotation support, signing key lifecycle management",
    compliance_check_id: "signing_enabled"
  }),
  Object.freeze({
    control_id: "IA-8",
    family: "IA",
    title: "Identification and Authentication (Non-Organizational Users)",
    description: "Identify and authenticate non-organizational users.",
    loom_feature: "Agent identity type with trust scoring, bridge identity for cross-system auth",
    compliance_check_id: "agent_trust_enabled"
  }),

  // ── System and Communications Protection (SC) ──────────────────────────
  Object.freeze({
    control_id: "SC-7",
    family: "SC",
    title: "Boundary Protection",
    description: "Monitor and control communications at external boundaries.",
    loom_feature: "Content filtering, MIME type policy enforcement, dangerous type blocking",
    compliance_check_id: "content_filter_enabled"
  }),
  Object.freeze({
    control_id: "SC-8",
    family: "SC",
    title: "Transmission Confidentiality and Integrity",
    description: "Protect the confidentiality and integrity of transmitted information.",
    loom_feature: "E2EE with X25519 + HKDF-SHA-256 + XChaCha20-Poly1305, TLS for transport",
    compliance_check_id: "e2ee_available"
  }),
  Object.freeze({
    control_id: "SC-12",
    family: "SC",
    title: "Cryptographic Key Establishment and Management",
    description: "Establish and manage cryptographic keys.",
    loom_feature: "X25519 key agreement, HKDF-SHA-256 key derivation, key rotation",
    compliance_check_id: "signing_enabled"
  }),
  Object.freeze({
    control_id: "SC-13",
    family: "SC",
    title: "Cryptographic Protection",
    description: "Implement FIPS-validated or NSA-approved cryptography.",
    loom_feature: "Ed25519 signatures, AES-128-GCM (MLS), SHA-256 hashing, HMAC verification",
    compliance_check_id: "signing_enabled"
  }),
  Object.freeze({
    control_id: "SC-23",
    family: "SC",
    title: "Session Authenticity",
    description: "Protect the authenticity of communications sessions.",
    loom_feature: "Webhook HMAC signatures, capability token audience binding",
    compliance_check_id: "webhook_signing_enabled"
  }),
  Object.freeze({
    control_id: "SC-28",
    family: "SC",
    title: "Protection of Information at Rest",
    description: "Protect the confidentiality and integrity of information at rest.",
    loom_feature: "Encrypted blob storage, audit chain integrity verification",
    compliance_check_id: "hash_chain_enabled"
  }),

  // ── System and Information Integrity (SI) ───────────────────────────────
  Object.freeze({
    control_id: "SI-3",
    family: "SI",
    title: "Malicious Code Protection",
    description: "Implement malicious code protection mechanisms.",
    loom_feature: "Dangerous MIME type blocking, content filter with malware pattern detection",
    compliance_check_id: "content_filter_enabled"
  }),
  Object.freeze({
    control_id: "SI-4",
    family: "SI",
    title: "System Monitoring",
    description: "Monitor the system to detect attacks and unauthorized activity.",
    loom_feature: "Rate limiting, agent trust scoring, prompt injection detection",
    compliance_check_id: "rate_limit_configured"
  }),
  Object.freeze({
    control_id: "SI-7",
    family: "SI",
    title: "Software, Firmware, and Information Integrity",
    description: "Employ integrity verification tools to detect unauthorized changes.",
    loom_feature: "SHA-256 hash chain for audit logs, Ed25519 envelope signatures",
    compliance_check_id: "hash_chain_enabled"
  }),
  Object.freeze({
    control_id: "SI-10",
    family: "SI",
    title: "Information Input Validation",
    description: "Check the validity of information inputs.",
    loom_feature: "Envelope schema validation, MIME type validation, content format validation",
    compliance_check_id: "content_filter_enabled"
  }),

  // ── Configuration Management (CM) ───────────────────────────────────────
  Object.freeze({
    control_id: "CM-3",
    family: "CM",
    title: "Configuration Change Control",
    description: "Implement controls for configuration changes.",
    loom_feature: "Protocol version negotiation, capability advertisement, env-based configuration",
    compliance_check_id: null
  }),

  // ── Incident Response (IR) ─────────────────────────────────────────────
  Object.freeze({
    control_id: "IR-4",
    family: "IR",
    title: "Incident Handling",
    description: "Implement an incident handling capability.",
    loom_feature: "Audit log export for incident investigation, compliance scoring alerts",
    compliance_check_id: "audit_export_enabled"
  }),
  Object.freeze({
    control_id: "IR-5",
    family: "IR",
    title: "Incident Monitoring",
    description: "Track and document incidents on an ongoing basis.",
    loom_feature: "Structured audit log with retention, hash chain integrity for evidence",
    compliance_check_id: "audit_log_enabled"
  })
]);

// ─── SP 800-207 Zero Trust Mappings ─────────────────────────────────────────

export const NIST_ZERO_TRUST_MAPPINGS = Object.freeze([
  Object.freeze({
    principle: "ZT-1",
    title: "All data sources and computing services are considered resources",
    description: "Every agent, service, and bridge is a distinct identity with capabilities.",
    loom_feature: "Five identity types (human/agent/team/service/bridge), each with unique ULID"
  }),
  Object.freeze({
    principle: "ZT-2",
    title: "All communication is secured regardless of network location",
    description: "TLS enforcement for federation, E2EE for sensitive content.",
    loom_feature: "TLS-required federation, X25519+XChaCha20 E2EE, webhook HMAC signatures"
  }),
  Object.freeze({
    principle: "ZT-3",
    title: "Access to individual resources is granted on a per-session basis",
    description: "Capability tokens with expiration, audience constraints, and scope limits.",
    loom_feature: "Scoped capability tokens, audience modes, per-envelope authorization"
  }),
  Object.freeze({
    principle: "ZT-4",
    title: "Access is determined by dynamic policy",
    description: "Agent trust scoring adjusts privileges based on behavior history.",
    loom_feature: "Dynamic agent trust scores, configurable trust thresholds, decay factors"
  }),
  Object.freeze({
    principle: "ZT-5",
    title: "Enterprise monitors and measures integrity and security posture",
    description: "Continuous compliance auditing with automated scoring.",
    loom_feature: "ATP compliance layer, 23 automated checks, hash-chain audit logs"
  })
]);

// ─── Lookup Functions ───────────────────────────────────────────────────────

export function listNistMappings() {
  return [...NIST_CONTROL_MAPPINGS];
}

export function getNistMappingsByFamily(family) {
  if (!family || typeof family !== "string") return [];
  const normalized = family.toUpperCase();
  return NIST_CONTROL_MAPPINGS.filter((m) => m.family === normalized);
}

export function getNistMappingByControlId(controlId) {
  if (!controlId || typeof controlId !== "string") return null;
  const normalized = controlId.toUpperCase();
  return NIST_CONTROL_MAPPINGS.find((m) => m.control_id === normalized) || null;
}

// ─── Coverage Computation ───────────────────────────────────────────────────

export function computeNistCoverage() {
  const familyCounts = {};
  for (const code of Object.keys(NIST_FAMILIES)) {
    familyCounts[code] = { total: 0, mapped: 0 };
  }

  for (const mapping of NIST_CONTROL_MAPPINGS) {
    if (familyCounts[mapping.family]) {
      familyCounts[mapping.family].total++;
      if (mapping.loom_feature) {
        familyCounts[mapping.family].mapped++;
      }
    }
  }

  const total = NIST_CONTROL_MAPPINGS.length;
  const mapped = NIST_CONTROL_MAPPINGS.filter((m) => m.loom_feature).length;

  return {
    total,
    mapped,
    coverage_percent: total > 0 ? Math.round((mapped / total) * 100 * 10) / 10 : 0,
    families: familyCounts
  };
}

// ─── Report Formatting ──────────────────────────────────────────────────────

export function formatNistReport(mappings) {
  if (!Array.isArray(mappings) || mappings.length === 0) {
    return "No NIST control mappings to report.";
  }

  const lines = [];
  lines.push("NIST SP 800-53 Rev 5 — Control Mapping Report");
  lines.push("=".repeat(50));
  lines.push("");

  let currentFamily = null;
  for (const m of mappings) {
    if (m.family !== currentFamily) {
      currentFamily = m.family;
      const familyName = NIST_FAMILIES[currentFamily] || currentFamily;
      lines.push(`── ${currentFamily}: ${familyName} ──`);
      lines.push("");
    }
    lines.push(`  ${m.control_id} — ${m.title}`);
    lines.push(`    LOOM: ${m.loom_feature}`);
    if (m.compliance_check_id) {
      lines.push(`    Check: ${m.compliance_check_id}`);
    }
    lines.push("");
  }

  const coverage = computeNistCoverage();
  lines.push(`Coverage: ${coverage.mapped}/${coverage.total} controls (${coverage.coverage_percent}%)`);

  return lines.join("\n");
}

// ─── Zero Trust Lookup ──────────────────────────────────────────────────────

export function listZeroTrustMappings() {
  return [...NIST_ZERO_TRUST_MAPPINGS];
}
