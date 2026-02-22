import test from "node:test";
import assert from "node:assert/strict";

import {
  COMPLIANCE_SEVERITY,
  COMPLIANCE_LEVELS,
  COMPLIANCE_CHECKS,
  listComplianceChecks,
  getComplianceCheckById,
  evaluateComplianceCheck,
  runComplianceAudit,
  computeComplianceScore,
  classifyComplianceLevel,
  formatComplianceReport
} from "../src/protocol/atp_compliance.js";

// Full-compliance node state for testing
const FULL_STATE = {
  loom_version: "1.1",
  envelope_validation_enabled: true,
  signature_verification_enabled: true,
  capability_tokens_enabled: true,
  federation_enabled: true,
  thread_dag_validation_enabled: true,
  idempotency_enabled: true,
  rate_limiting_enabled: true,
  replay_protection_enabled: true,
  e2ee_enabled: true,
  e2ee_profile_count: 2,
  content_format_validation_enabled: true,
  mime_policy_mode: "denylist",
  content_filter_enabled: true,
  loop_protection_enabled: true,
  loop_max_hop_count: 20,
  agent_trust_enabled: true,
  retention_policies_configured: true,
  audit_log_enabled: true,
  audit_hmac_enabled: true,
  mcp_sandbox_enabled: true,
  prompt_injection_detection_enabled: true,
  federation_trust_anchor_count: 3,
  state_encryption_at_rest: true,
  federation_signed_receipts: true,
  blob_retention_days: 90,
  identity_proof_required: true
};

// Minimal node state — everything off
const MINIMAL_STATE = {
  loom_version: "1.1"
};

// ─── Constants ───────────────────────────────────────────────────────────────

test("COMPLIANCE_SEVERITY is frozen with all levels", () => {
  assert.ok(Object.isFrozen(COMPLIANCE_SEVERITY));
  assert.equal(COMPLIANCE_SEVERITY.REQUIRED, "required");
  assert.equal(COMPLIANCE_SEVERITY.RECOMMENDED, "recommended");
  assert.equal(COMPLIANCE_SEVERITY.OPTIONAL, "optional");
});

test("COMPLIANCE_LEVELS is frozen with all levels", () => {
  assert.ok(Object.isFrozen(COMPLIANCE_LEVELS));
  assert.equal(COMPLIANCE_LEVELS.FULL, "full");
  assert.equal(COMPLIANCE_LEVELS.SUBSTANTIAL, "substantial");
  assert.equal(COMPLIANCE_LEVELS.PARTIAL, "partial");
  assert.equal(COMPLIANCE_LEVELS.MINIMAL, "minimal");
});

test("COMPLIANCE_CHECKS is frozen", () => {
  assert.ok(Object.isFrozen(COMPLIANCE_CHECKS));
  assert.ok(COMPLIANCE_CHECKS.length >= 20);
});

test("each check has required fields", () => {
  for (const check of COMPLIANCE_CHECKS) {
    assert.ok(typeof check.id === "string" && check.id.length > 0, `check missing id`);
    assert.ok(typeof check.section === "string" && check.section.length > 0, `${check.id} missing section`);
    assert.ok(["required", "recommended", "optional"].includes(check.severity), `${check.id} invalid severity`);
    assert.ok(typeof check.description === "string" && check.description.length > 0, `${check.id} missing description`);
    assert.ok(typeof check.evaluate === "function", `${check.id} missing evaluate`);
  }
});

test("no duplicate check ids", () => {
  const ids = COMPLIANCE_CHECKS.map((c) => c.id);
  const unique = new Set(ids);
  assert.equal(ids.length, unique.size);
});

test("severity counts match expected distribution", () => {
  const required = COMPLIANCE_CHECKS.filter((c) => c.severity === "required");
  const recommended = COMPLIANCE_CHECKS.filter((c) => c.severity === "recommended");
  const optional = COMPLIANCE_CHECKS.filter((c) => c.severity === "optional");
  assert.equal(required.length, 8);
  assert.equal(recommended.length, 10);
  assert.equal(optional.length, 5);
});

// ─── listComplianceChecks ────────────────────────────────────────────────────

test("listComplianceChecks returns all checks", () => {
  const checks = listComplianceChecks();
  assert.equal(checks.length, COMPLIANCE_CHECKS.length);
});

test("listComplianceChecks does not include evaluate function", () => {
  const checks = listComplianceChecks();
  for (const check of checks) {
    assert.equal(check.evaluate, undefined);
  }
});

test("listComplianceChecks entries have id, section, severity, description", () => {
  const checks = listComplianceChecks();
  for (const check of checks) {
    assert.ok(typeof check.id === "string");
    assert.ok(typeof check.section === "string");
    assert.ok(typeof check.severity === "string");
    assert.ok(typeof check.description === "string");
  }
});

// ─── getComplianceCheckById ──────────────────────────────────────────────────

test("getComplianceCheckById finds existing check", () => {
  const check = getComplianceCheckById("envelope_validation");
  assert.ok(check);
  assert.equal(check.id, "envelope_validation");
  assert.equal(check.section, "3.1");
  assert.equal(check.severity, "required");
});

test("getComplianceCheckById returns null for unknown id", () => {
  assert.equal(getComplianceCheckById("nonexistent_check"), null);
});

test("getComplianceCheckById handles null input", () => {
  assert.equal(getComplianceCheckById(null), null);
});

test("getComplianceCheckById handles empty string", () => {
  assert.equal(getComplianceCheckById(""), null);
});

// ─── evaluateComplianceCheck ─────────────────────────────────────────────────

test("evaluateComplianceCheck returns pass=true for passing check", () => {
  const result = evaluateComplianceCheck("envelope_validation", FULL_STATE);
  assert.equal(result.pass, true);
  assert.equal(result.id, "envelope_validation");
  assert.equal(result.severity, "required");
});

test("evaluateComplianceCheck returns pass=false for failing check", () => {
  const result = evaluateComplianceCheck("envelope_validation", MINIMAL_STATE);
  assert.equal(result.pass, false);
});

test("evaluateComplianceCheck returns correct severity", () => {
  const result = evaluateComplianceCheck("e2ee_support", FULL_STATE);
  assert.equal(result.severity, "recommended");
});

test("evaluateComplianceCheck handles unknown check id", () => {
  const result = evaluateComplianceCheck("unknown_check", FULL_STATE);
  assert.equal(result.pass, false);
  assert.ok(result.detail.includes("Unknown"));
});

test("evaluateComplianceCheck handles null nodeState", () => {
  const result = evaluateComplianceCheck("envelope_validation", null);
  assert.equal(result.pass, false);
});

// ─── runComplianceAudit ──────────────────────────────────────────────────────

test("runComplianceAudit returns full audit for fully-compliant state", () => {
  const audit = runComplianceAudit(FULL_STATE);
  assert.equal(audit.loom_version, "1.1");
  assert.ok(audit.audit_timestamp);
  assert.equal(audit.results.length, COMPLIANCE_CHECKS.length);
  assert.equal(audit.summary.total, COMPLIANCE_CHECKS.length);
  assert.equal(audit.summary.passed, COMPLIANCE_CHECKS.length);
  assert.equal(audit.summary.failed, 0);
});

test("runComplianceAudit returns audit with failures for minimal state", () => {
  const audit = runComplianceAudit(MINIMAL_STATE);
  assert.ok(audit.summary.failed > 0);
  assert.ok(audit.summary.passed < audit.summary.total);
});

test("runComplianceAudit summary counts are correct", () => {
  const audit = runComplianceAudit(FULL_STATE);
  assert.equal(audit.summary.passed + audit.summary.failed, audit.summary.total);
});

test("runComplianceAudit required counts are correct", () => {
  const audit = runComplianceAudit(FULL_STATE);
  assert.equal(audit.summary.required_total, 8);
  assert.equal(audit.summary.required_passed, 8);
});

test("runComplianceAudit recommended counts are correct", () => {
  const audit = runComplianceAudit(FULL_STATE);
  assert.equal(audit.summary.recommended_total, 10);
  assert.equal(audit.summary.recommended_passed, 10);
});

test("runComplianceAudit optional counts are correct", () => {
  const audit = runComplianceAudit(FULL_STATE);
  assert.equal(audit.summary.optional_total, 5);
  assert.equal(audit.summary.optional_passed, 5);
});

test("runComplianceAudit has audit_timestamp", () => {
  const audit = runComplianceAudit(FULL_STATE);
  assert.ok(typeof audit.audit_timestamp === "string");
  assert.ok(audit.audit_timestamp.includes("T"));
});

test("runComplianceAudit has loom_version from state", () => {
  const audit = runComplianceAudit({ loom_version: "2.0" });
  assert.equal(audit.loom_version, "2.0");
});

test("runComplianceAudit with null state produces failures", () => {
  const audit = runComplianceAudit(null);
  assert.ok(audit.summary.failed > 0);
  assert.equal(audit.loom_version, "1.1");
});

// ─── computeComplianceScore ──────────────────────────────────────────────────

test("computeComplianceScore full compliance returns 100", () => {
  const audit = runComplianceAudit(FULL_STATE);
  assert.equal(computeComplianceScore(audit), 100);
});

test("computeComplianceScore empty audit returns 0", () => {
  assert.equal(computeComplianceScore(null), 0);
  assert.equal(computeComplianceScore({}), 0);
  assert.equal(computeComplianceScore({ results: [] }), 0);
});

test("computeComplianceScore partial compliance returns weighted score", () => {
  const audit = runComplianceAudit(MINIMAL_STATE);
  const score = computeComplianceScore(audit);
  assert.ok(score >= 0 && score <= 100);
  assert.ok(score < 100); // minimal state should not be 100
});

test("computeComplianceScore required checks weighted more than optional", () => {
  // 1 required pass only
  const audit1 = { results: [{ severity: "required", pass: true }] };
  // 1 optional pass only
  const audit2 = { results: [{ severity: "optional", pass: true }] };
  // Both should be 100 with one item, but the weighting shows when combined
  const combined = {
    results: [
      { severity: "required", pass: true },
      { severity: "optional", pass: false }
    ]
  };
  const score = computeComplianceScore(combined);
  // required weight=3, optional weight=1, total=4, earned=3, score=75
  assert.equal(score, 75);
});

test("computeComplianceScore handles null input gracefully", () => {
  assert.equal(computeComplianceScore(null), 0);
  assert.equal(computeComplianceScore(undefined), 0);
});

// ─── classifyComplianceLevel ─────────────────────────────────────────────────

test("classifyComplianceLevel score >= 90 returns full", () => {
  assert.equal(classifyComplianceLevel(90), "full");
  assert.equal(classifyComplianceLevel(95), "full");
  assert.equal(classifyComplianceLevel(100), "full");
});

test("classifyComplianceLevel score 70-89 returns substantial", () => {
  assert.equal(classifyComplianceLevel(70), "substantial");
  assert.equal(classifyComplianceLevel(80), "substantial");
  assert.equal(classifyComplianceLevel(89), "substantial");
});

test("classifyComplianceLevel score 40-69 returns partial", () => {
  assert.equal(classifyComplianceLevel(40), "partial");
  assert.equal(classifyComplianceLevel(55), "partial");
  assert.equal(classifyComplianceLevel(69), "partial");
});

test("classifyComplianceLevel score < 40 returns minimal", () => {
  assert.equal(classifyComplianceLevel(0), "minimal");
  assert.equal(classifyComplianceLevel(20), "minimal");
  assert.equal(classifyComplianceLevel(39), "minimal");
});

test("classifyComplianceLevel boundary at 90", () => {
  assert.equal(classifyComplianceLevel(90), "full");
  assert.equal(classifyComplianceLevel(89), "substantial");
});

test("classifyComplianceLevel boundary at 70", () => {
  assert.equal(classifyComplianceLevel(70), "substantial");
  assert.equal(classifyComplianceLevel(69), "partial");
});

test("classifyComplianceLevel boundary at 40", () => {
  assert.equal(classifyComplianceLevel(40), "partial");
  assert.equal(classifyComplianceLevel(39), "minimal");
});

test("classifyComplianceLevel handles negative score", () => {
  assert.equal(classifyComplianceLevel(-1), "minimal");
});

// ─── formatComplianceReport ──────────────────────────────────────────────────

test("formatComplianceReport includes score and level", () => {
  const audit = runComplianceAudit(FULL_STATE);
  const report = formatComplianceReport(audit);
  assert.ok(report.includes("Score: 100/100"));
  assert.ok(report.includes("full"));
});

test("formatComplianceReport includes summary counts", () => {
  const audit = runComplianceAudit(FULL_STATE);
  const report = formatComplianceReport(audit);
  assert.ok(report.includes("Total checks:"));
  assert.ok(report.includes("Passed:"));
  assert.ok(report.includes("Required:"));
});

test("formatComplianceReport lists failed checks", () => {
  const audit = runComplianceAudit(MINIMAL_STATE);
  const report = formatComplianceReport(audit);
  assert.ok(report.includes("Failed checks:"));
  assert.ok(report.includes("[required]"));
});

test("formatComplianceReport handles all-passing audit", () => {
  const audit = runComplianceAudit(FULL_STATE);
  const report = formatComplianceReport(audit);
  assert.ok(report.includes("All checks passed"));
});

test("formatComplianceReport handles null input", () => {
  const report = formatComplianceReport(null);
  assert.ok(report.includes("No audit data"));
});
