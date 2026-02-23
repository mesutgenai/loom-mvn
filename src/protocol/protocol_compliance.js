// ─── Protocol Compliance Audit Layer ─────────────────────────────────────────
//
// Protocol-level compliance check definitions and audit execution.
// Pure-function module with no store or server dependencies.
// Evaluates node state against canonical LOOM spec/doc references.

// ─── Severity Levels ─────────────────────────────────────────────────────────

export const COMPLIANCE_SEVERITY = Object.freeze({
  REQUIRED: "required",
  RECOMMENDED: "recommended",
  OPTIONAL: "optional"
});

// ─── Compliance Levels ───────────────────────────────────────────────────────

export const COMPLIANCE_LEVELS = Object.freeze({
  FULL: "full",
  SUBSTANTIAL: "substantial",
  PARTIAL: "partial",
  MINIMAL: "minimal"
});

// ─── Compliance Checks ───────────────────────────────────────────────────────

export const COMPLIANCE_CHECKS = Object.freeze([
  // ── Required (8) ─────────────────────────────────────────────────────────
  Object.freeze({
    id: "envelope_validation",
    section: "8.1",
    reference: "LOOM-Protocol-Spec-v1.1.md §8.1",
    severity: "required",
    description: "Envelope shape validation is enabled",
    evaluate: (state) => ({
      pass: state.envelope_validation_enabled === true,
      detail: state.envelope_validation_enabled ? "Envelope validation active" : "Envelope validation disabled"
    })
  }),
  Object.freeze({
    id: "signature_ed25519",
    section: "7.3",
    reference: "LOOM-Protocol-Spec-v1.1.md §7.3",
    severity: "required",
    description: "Ed25519 signature verification is enabled",
    evaluate: (state) => ({
      pass: state.signature_verification_enabled === true,
      detail: state.signature_verification_enabled ? "Ed25519 verification active" : "Signature verification disabled"
    })
  }),
  Object.freeze({
    id: "capability_token_format",
    section: "12.1",
    reference: "LOOM-Protocol-Spec-v1.1.md §12.1",
    severity: "required",
    description: "Capability token format enforcement",
    evaluate: (state) => ({
      pass: state.capability_tokens_enabled === true,
      detail: state.capability_tokens_enabled ? "Capability tokens enforced" : "Capability tokens not enforced"
    })
  }),
  Object.freeze({
    id: "federation_handshake",
    section: "15.7",
    reference: "LOOM-Protocol-Spec-v1.1.md §15.7",
    severity: "required",
    description: "Federation protocol negotiation support",
    evaluate: (state) => ({
      pass: state.federation_enabled === true,
      detail: state.federation_enabled ? "Federation handshake supported" : "Federation disabled"
    })
  }),
  Object.freeze({
    id: "thread_dag_validation",
    section: "10.2",
    reference: "LOOM-Protocol-Spec-v1.1.md §10.2",
    severity: "required",
    description: "Thread DAG validation is active",
    evaluate: (state) => ({
      pass: state.thread_dag_validation_enabled === true,
      detail: state.thread_dag_validation_enabled ? "DAG validation active" : "DAG validation disabled"
    })
  }),
  Object.freeze({
    id: "idempotency_support",
    section: "14.4",
    reference: "LOOM-Protocol-Spec-v1.1.md §14.4",
    severity: "required",
    description: "Idempotency key support is enabled",
    evaluate: (state) => ({
      pass: state.idempotency_enabled === true,
      detail: state.idempotency_enabled ? "Idempotency keys supported" : "Idempotency not supported"
    })
  }),
  Object.freeze({
    id: "rate_limiting",
    section: "14.3",
    reference: "LOOM-Protocol-Spec-v1.1.md §14.3",
    severity: "required",
    description: "Rate limiting is configured",
    evaluate: (state) => ({
      pass: state.rate_limiting_enabled === true,
      detail: state.rate_limiting_enabled ? "Rate limiting active" : "Rate limiting disabled"
    })
  }),
  Object.freeze({
    id: "replay_protection",
    section: "15.5",
    reference: "LOOM-Protocol-Spec-v1.1.md §15.5",
    severity: "required",
    description: "Replay protection is enabled",
    evaluate: (state) => ({
      pass: state.replay_protection_enabled === true,
      detail: state.replay_protection_enabled ? "Replay protection active" : "Replay protection disabled"
    })
  }),

  // ── Recommended (10) ─────────────────────────────────────────────────────
  Object.freeze({
    id: "e2ee_support",
    section: "7.4",
    reference: "LOOM-Protocol-Spec-v1.1.md §7.4",
    severity: "recommended",
    description: "End-to-end encryption profile support",
    evaluate: (state) => ({
      pass: state.e2ee_enabled === true,
      detail: state.e2ee_enabled
        ? `E2EE profiles: ${state.e2ee_profile_count || 0}`
        : "E2EE not enabled"
    })
  }),
  Object.freeze({
    id: "content_format_validation",
    section: "8.2",
    reference: "LOOM-Protocol-Spec-v1.1.md §8.2",
    severity: "recommended",
    description: "Content format validation for human-readable content",
    evaluate: (state) => ({
      pass: state.content_format_validation_enabled === true,
      detail: state.content_format_validation_enabled
        ? "Content format validation active"
        : "Content format not validated"
    })
  }),
  Object.freeze({
    id: "mime_registry",
    section: "16.7",
    reference: "LOOM-Protocol-Spec-v1.1.md §16.7",
    severity: "recommended",
    description: "MIME type registry and policy enforcement",
    evaluate: (state) => ({
      pass: state.mime_policy_mode !== "permissive" && state.mime_policy_mode != null,
      detail: `MIME policy mode: ${state.mime_policy_mode || "none"}`
    })
  }),
  Object.freeze({
    id: "content_filter",
    section: "23.2",
    reference: "LOOM-Protocol-Spec-v1.1.md §23.2",
    severity: "recommended",
    description: "Inbound content filtering is enabled",
    evaluate: (state) => ({
      pass: state.content_filter_enabled === true,
      detail: state.content_filter_enabled
        ? "Content filter active"
        : "Content filter disabled"
    })
  }),
  Object.freeze({
    id: "loop_protection",
    section: "18.5",
    reference: "LOOM-Protocol-Spec-v1.1.md §18.5",
    severity: "recommended",
    description: "Agent loop protection is configured",
    evaluate: (state) => ({
      pass: state.loop_protection_enabled === true,
      detail: state.loop_protection_enabled
        ? `Max hops: ${state.loop_max_hop_count || "?"}`
        : "Loop protection disabled"
    })
  }),
  Object.freeze({
    id: "agent_trust",
    section: "18.5",
    reference: "docs/CONFORMANCE.md (Agent trust extension profile)",
    severity: "recommended",
    description: "Agent behavioral trust scoring is enabled",
    evaluate: (state) => ({
      pass: state.agent_trust_enabled === true,
      detail: state.agent_trust_enabled
        ? "Agent trust scoring active"
        : "Agent trust scoring disabled"
    })
  }),
  Object.freeze({
    id: "retention_policies",
    section: "25.4",
    reference: "LOOM-Protocol-Spec-v1.1.md §25.4",
    severity: "recommended",
    description: "Message retention policies are configured",
    evaluate: (state) => ({
      pass: state.retention_policies_configured === true,
      detail: state.retention_policies_configured
        ? "Retention policies configured"
        : "No retention policies"
    })
  }),
  Object.freeze({
    id: "audit_logging",
    section: "25.1",
    reference: "LOOM-Protocol-Spec-v1.1.md §25.1",
    severity: "recommended",
    description: "Audit logging with HMAC integrity is enabled",
    evaluate: (state) => ({
      pass: state.audit_log_enabled === true,
      detail: state.audit_log_enabled
        ? `HMAC: ${state.audit_hmac_enabled ? "yes" : "no"}`
        : "Audit logging disabled"
    })
  }),
  Object.freeze({
    id: "mcp_sandbox",
    section: "22.3",
    reference: "docs/CONFORMANCE.md (MCP runtime extension profile)",
    severity: "recommended",
    description: "MCP tool sandbox policy is enforced",
    evaluate: (state) => ({
      pass: state.mcp_sandbox_enabled === true,
      detail: state.mcp_sandbox_enabled
        ? "MCP sandbox active"
        : "MCP sandbox not enforced"
    })
  }),
  Object.freeze({
    id: "prompt_injection_detection",
    section: "23.1",
    reference: "docs/CONFORMANCE.md (Prompt injection hardening profile)",
    severity: "recommended",
    description: "Prompt injection detection is active",
    evaluate: (state) => ({
      pass: state.prompt_injection_detection_enabled === true,
      detail: state.prompt_injection_detection_enabled
        ? "Injection detection active"
        : "Injection detection disabled"
    })
  }),

  // ── Optional (5) ─────────────────────────────────────────────────────────
  Object.freeze({
    id: "federation_trust_anchors",
    section: "15.7",
    reference: "LOOM-Protocol-Spec-v1.1.md §15.7",
    severity: "optional",
    description: "Federation trust anchors are configured",
    evaluate: (state) => ({
      pass: (state.federation_trust_anchor_count || 0) > 0,
      detail: `Trust anchors: ${state.federation_trust_anchor_count || 0}`
    })
  }),
  Object.freeze({
    id: "state_encryption_at_rest",
    section: "23.2",
    reference: "LOOM-Protocol-Spec-v1.1.md §23.2",
    severity: "optional",
    description: "State encryption at rest is enabled",
    evaluate: (state) => ({
      pass: state.state_encryption_at_rest === true,
      detail: state.state_encryption_at_rest
        ? "State encrypted at rest"
        : "State not encrypted at rest"
    })
  }),
  Object.freeze({
    id: "federation_signed_receipts",
    section: "24.3",
    reference: "LOOM-Protocol-Spec-v1.1.md §24.3",
    severity: "optional",
    description: "Federation requires signed delivery receipts",
    evaluate: (state) => ({
      pass: state.federation_signed_receipts === true,
      detail: state.federation_signed_receipts
        ? "Signed receipts required"
        : "Signed receipts not required"
    })
  }),
  Object.freeze({
    id: "blob_retention",
    section: "25.4",
    reference: "LOOM-Protocol-Spec-v1.1.md §25.4",
    severity: "optional",
    description: "Blob retention policy is configured",
    evaluate: (state) => ({
      pass: (state.blob_retention_days || 0) > 0,
      detail: (state.blob_retention_days || 0) > 0
        ? `Blob retention: ${state.blob_retention_days} days`
        : "No blob retention limit"
    })
  }),
  Object.freeze({
    id: "identity_proof_of_key",
    section: "14.2",
    reference: "LOOM-Protocol-Spec-v1.1.md §14.2",
    severity: "optional",
    description: "Identity registration requires proof of key",
    evaluate: (state) => ({
      pass: state.identity_proof_required === true,
      detail: state.identity_proof_required
        ? "Proof of key required"
        : "Proof of key not required"
    })
  })
]);

// ─── Check Listing ───────────────────────────────────────────────────────────

function resolveComplianceReference(check) {
  const reference = typeof check?.reference === "string" ? check.reference.trim() : "";
  if (reference) {
    return reference;
  }
  const legacySection = typeof check?.section === "string" ? check.section.trim() : "";
  return legacySection;
}

function resolveComplianceSection(check) {
  // `section` is retained as a stable compatibility field for existing tooling,
  // while `reference` carries the canonical pointer for current docs/spec text.
  const section = typeof check?.section === "string" ? check.section.trim() : "";
  if (section) {
    return section;
  }
  const reference = resolveComplianceReference(check);
  const match = /§\s*([0-9]+(?:\.[0-9]+)*)/.exec(reference);
  if (match) {
    return match[1];
  }
  return reference || "unspecified";
}

export function listComplianceChecks() {
  return COMPLIANCE_CHECKS.map((check) => ({
    id: check.id,
    reference: resolveComplianceReference(check),
    // Backward-compatible legacy field retained for existing clients.
    section: resolveComplianceSection(check),
    severity: check.severity,
    description: check.description
  }));
}

export function getComplianceCheckById(checkId) {
  const normalized = String(checkId || "").trim();
  if (!normalized) return null;
  const check = COMPLIANCE_CHECKS.find((c) => c.id === normalized);
  if (!check) return null;
  const reference = resolveComplianceReference(check);
  const section = resolveComplianceSection(check);
  return {
    id: check.id,
    reference,
    // Backward-compatible legacy field retained for existing clients.
    section,
    severity: check.severity,
    description: check.description
  };
}

// ─── Check Evaluation ────────────────────────────────────────────────────────

export function evaluateComplianceCheck(checkId, nodeState) {
  const normalized = String(checkId || "").trim();
  const check = COMPLIANCE_CHECKS.find((c) => c.id === normalized);
  if (!check) {
    return { id: normalized, pass: false, severity: "required", detail: "Unknown check" };
  }
  const result = check.evaluate(nodeState || {});
  const reference = resolveComplianceReference(check);
  const section = resolveComplianceSection(check);
  return {
    id: check.id,
    reference,
    // Backward-compatible legacy field retained for existing clients.
    section,
    severity: check.severity,
    pass: result.pass === true,
    detail: result.detail || ""
  };
}

// ─── Full Audit ──────────────────────────────────────────────────────────────

export function runComplianceAudit(nodeState) {
  const state = nodeState || {};
  const results = COMPLIANCE_CHECKS.map((check) => {
    const result = check.evaluate(state);
    const reference = resolveComplianceReference(check);
    const section = resolveComplianceSection(check);
    return {
      id: check.id,
      reference,
      // Backward-compatible legacy field retained for existing clients.
      section,
      severity: check.severity,
      pass: result.pass === true,
      detail: result.detail || ""
    };
  });

  const summary = {
    total: results.length,
    passed: results.filter((r) => r.pass).length,
    failed: results.filter((r) => !r.pass).length,
    required_passed: results.filter((r) => r.severity === "required" && r.pass).length,
    required_total: results.filter((r) => r.severity === "required").length,
    recommended_passed: results.filter((r) => r.severity === "recommended" && r.pass).length,
    recommended_total: results.filter((r) => r.severity === "recommended").length,
    optional_passed: results.filter((r) => r.severity === "optional" && r.pass).length,
    optional_total: results.filter((r) => r.severity === "optional").length
  };

  return {
    loom_version: state.loom_version || "1.1",
    audit_timestamp: new Date().toISOString(),
    results,
    summary
  };
}

// ─── Score Computation ───────────────────────────────────────────────────────

const SEVERITY_WEIGHTS = { required: 3, recommended: 2, optional: 1 };

export function computeComplianceScore(auditResult) {
  if (!auditResult?.results || auditResult.results.length === 0) return 0;

  let totalWeight = 0;
  let earnedWeight = 0;

  for (const check of auditResult.results) {
    const weight = SEVERITY_WEIGHTS[check.severity] || 1;
    totalWeight += weight;
    if (check.pass) {
      earnedWeight += weight;
    }
  }

  if (totalWeight === 0) return 0;
  return Math.round((earnedWeight / totalWeight) * 100);
}

// ─── Level Classification ────────────────────────────────────────────────────

export function classifyComplianceLevel(score) {
  if (typeof score !== "number" || score < 0) return COMPLIANCE_LEVELS.MINIMAL;
  if (score >= 90) return COMPLIANCE_LEVELS.FULL;
  if (score >= 70) return COMPLIANCE_LEVELS.SUBSTANTIAL;
  if (score >= 40) return COMPLIANCE_LEVELS.PARTIAL;
  return COMPLIANCE_LEVELS.MINIMAL;
}

// ─── Report Formatting ───────────────────────────────────────────────────────

export function formatComplianceReport(auditResult) {
  if (!auditResult || typeof auditResult !== "object") {
    return "No audit data available.";
  }

  const score = computeComplianceScore(auditResult);
  const level = classifyComplianceLevel(score);
  const summary = auditResult.summary || {};

  const lines = [
    "LOOM Protocol Compliance Report",
    `Version: ${auditResult.loom_version || "1.1"}`,
    `Score: ${score}/100 (${level})`,
    `Timestamp: ${auditResult.audit_timestamp || "N/A"}`,
    "",
    "Summary:",
    `  Total checks: ${summary.total || 0}`,
    `  Passed: ${summary.passed || 0}`,
    `  Failed: ${summary.failed || 0}`,
    `  Required: ${summary.required_passed || 0}/${summary.required_total || 0}`,
    `  Recommended: ${summary.recommended_passed || 0}/${summary.recommended_total || 0}`,
    `  Optional: ${summary.optional_passed || 0}/${summary.optional_total || 0}`,
    ""
  ];

  const failed = (auditResult.results || []).filter((r) => !r.pass);
  if (failed.length > 0) {
    lines.push("Failed checks:");
    for (const check of failed) {
      const reference = String(check.reference || check.section || "unspecified reference");
      lines.push(`  [${check.severity}] ${check.id} (${reference}): ${check.detail}`);
    }
  } else {
    lines.push("All checks passed.");
  }

  return lines.join("\n");
}
