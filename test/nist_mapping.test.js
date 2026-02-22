import test from "node:test";
import assert from "node:assert/strict";

import {
  NIST_FRAMEWORK_REF,
  NIST_FAMILIES,
  NIST_CONTROL_MAPPINGS,
  NIST_ZERO_TRUST_MAPPINGS,
  listNistMappings,
  getNistMappingsByFamily,
  getNistMappingByControlId,
  computeNistCoverage,
  formatNistReport,
  listZeroTrustMappings
} from "../src/protocol/nist_mapping.js";

// ─── Constants ───────────────────────────────────────────────────────────────

test("NIST_FRAMEWORK_REF is frozen with correct standard", () => {
  assert.ok(Object.isFrozen(NIST_FRAMEWORK_REF));
  assert.equal(NIST_FRAMEWORK_REF.standard, "NIST SP 800-53 Rev 5");
  assert.ok(Object.isFrozen(NIST_FRAMEWORK_REF.supplementary));
  assert.equal(NIST_FRAMEWORK_REF.supplementary.length, 3);
});

test("NIST_FAMILIES is frozen with 7 families", () => {
  assert.ok(Object.isFrozen(NIST_FAMILIES));
  assert.equal(Object.keys(NIST_FAMILIES).length, 7);
  assert.equal(NIST_FAMILIES.AC, "Access Control");
  assert.equal(NIST_FAMILIES.AU, "Audit and Accountability");
  assert.equal(NIST_FAMILIES.IA, "Identification and Authentication");
  assert.equal(NIST_FAMILIES.SC, "System and Communications Protection");
  assert.equal(NIST_FAMILIES.SI, "System and Information Integrity");
  assert.equal(NIST_FAMILIES.CM, "Configuration Management");
  assert.equal(NIST_FAMILIES.IR, "Incident Response");
});

test("NIST_CONTROL_MAPPINGS is frozen with 29 controls", () => {
  assert.ok(Object.isFrozen(NIST_CONTROL_MAPPINGS));
  assert.equal(NIST_CONTROL_MAPPINGS.length, 29);
});

test("NIST_ZERO_TRUST_MAPPINGS is frozen with 5 principles", () => {
  assert.ok(Object.isFrozen(NIST_ZERO_TRUST_MAPPINGS));
  assert.equal(NIST_ZERO_TRUST_MAPPINGS.length, 5);
});

test("all control mappings have required fields", () => {
  for (const m of NIST_CONTROL_MAPPINGS) {
    assert.ok(Object.isFrozen(m));
    assert.ok(m.control_id, `missing control_id`);
    assert.ok(m.family, `missing family for ${m.control_id}`);
    assert.ok(m.title, `missing title for ${m.control_id}`);
    assert.ok(m.description, `missing description for ${m.control_id}`);
    assert.ok(m.loom_feature, `missing loom_feature for ${m.control_id}`);
    assert.ok(Object.keys(NIST_FAMILIES).includes(m.family), `invalid family ${m.family} for ${m.control_id}`);
  }
});

// ─── listNistMappings ───────────────────────────────────────────────────────

test("listNistMappings returns all 29 mappings", () => {
  const mappings = listNistMappings();
  assert.equal(mappings.length, 29);
});

test("listNistMappings returns a copy", () => {
  const a = listNistMappings();
  const b = listNistMappings();
  assert.notEqual(a, b);
  assert.deepEqual(a, b);
});

// ─── getNistMappingsByFamily ────────────────────────────────────────────────

test("getNistMappingsByFamily returns AC controls", () => {
  const ac = getNistMappingsByFamily("AC");
  assert.equal(ac.length, 7);
  assert.ok(ac.every((m) => m.family === "AC"));
});

test("getNistMappingsByFamily returns AU controls", () => {
  const au = getNistMappingsByFamily("AU");
  assert.equal(au.length, 6);
});

test("getNistMappingsByFamily is case insensitive", () => {
  const sc = getNistMappingsByFamily("sc");
  assert.equal(sc.length, 6);
});

test("getNistMappingsByFamily returns empty for unknown family", () => {
  assert.deepEqual(getNistMappingsByFamily("XX"), []);
  assert.deepEqual(getNistMappingsByFamily(null), []);
});

// ─── getNistMappingByControlId ──────────────────────────────────────────────

test("getNistMappingByControlId finds AC-1", () => {
  const m = getNistMappingByControlId("AC-1");
  assert.ok(m);
  assert.equal(m.control_id, "AC-1");
  assert.equal(m.family, "AC");
});

test("getNistMappingByControlId finds SC-8", () => {
  const m = getNistMappingByControlId("SC-8");
  assert.ok(m);
  assert.equal(m.title, "Transmission Confidentiality and Integrity");
});

test("getNistMappingByControlId is case insensitive", () => {
  const m = getNistMappingByControlId("au-2");
  assert.ok(m);
  assert.equal(m.control_id, "AU-2");
});

test("getNistMappingByControlId returns null for unknown", () => {
  assert.equal(getNistMappingByControlId("XX-99"), null);
  assert.equal(getNistMappingByControlId(null), null);
  assert.equal(getNistMappingByControlId(""), null);
});

// ─── computeNistCoverage ────────────────────────────────────────────────────

test("computeNistCoverage returns correct totals", () => {
  const coverage = computeNistCoverage();
  assert.equal(coverage.total, 29);
  assert.equal(coverage.mapped, 29);
  assert.equal(coverage.coverage_percent, 100);
});

test("computeNistCoverage reports per-family counts", () => {
  const coverage = computeNistCoverage();
  assert.equal(coverage.families.AC.total, 7);
  assert.equal(coverage.families.AU.total, 6);
  assert.equal(coverage.families.IA.total, 3);
  assert.equal(coverage.families.SC.total, 6);
  assert.equal(coverage.families.SI.total, 4);
  assert.equal(coverage.families.CM.total, 1);
  assert.equal(coverage.families.IR.total, 2);
});

test("computeNistCoverage family mapped counts match totals", () => {
  const coverage = computeNistCoverage();
  for (const code of Object.keys(NIST_FAMILIES)) {
    assert.equal(coverage.families[code].mapped, coverage.families[code].total,
      `family ${code} mapped should equal total`);
  }
});

test("computeNistCoverage all family codes present", () => {
  const coverage = computeNistCoverage();
  for (const code of Object.keys(NIST_FAMILIES)) {
    assert.ok(coverage.families[code], `missing family ${code}`);
  }
});

// ─── formatNistReport ───────────────────────────────────────────────────────

test("formatNistReport formats all mappings", () => {
  const report = formatNistReport(NIST_CONTROL_MAPPINGS);
  assert.ok(report.includes("NIST SP 800-53 Rev 5"));
  assert.ok(report.includes("AC-1"));
  assert.ok(report.includes("SC-8"));
  assert.ok(report.includes("Coverage: 29/29"));
});

test("formatNistReport handles empty array", () => {
  const report = formatNistReport([]);
  assert.ok(report.includes("No NIST control mappings"));
});

test("formatNistReport handles null", () => {
  const report = formatNistReport(null);
  assert.ok(report.includes("No NIST control mappings"));
});

// ─── listZeroTrustMappings ──────────────────────────────────────────────────

test("listZeroTrustMappings returns 5 principles", () => {
  const zt = listZeroTrustMappings();
  assert.equal(zt.length, 5);
  assert.equal(zt[0].principle, "ZT-1");
  assert.equal(zt[4].principle, "ZT-5");
});

test("listZeroTrustMappings returns a copy", () => {
  const a = listZeroTrustMappings();
  const b = listZeroTrustMappings();
  assert.notEqual(a, b);
});

// ─── Cross-reference compliance_check_ids ───────────────────────────────────

test("compliance_check_ids are valid strings or null", () => {
  for (const m of NIST_CONTROL_MAPPINGS) {
    if (m.compliance_check_id !== null) {
      assert.equal(typeof m.compliance_check_id, "string",
        `${m.control_id} compliance_check_id should be string or null`);
      assert.ok(m.compliance_check_id.length > 0,
        `${m.control_id} compliance_check_id should not be empty`);
    }
  }
});
