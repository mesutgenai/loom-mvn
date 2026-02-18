#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const DEFAULT_MATRIX_OUTPUT_DIR = "scripts/output/federation-interop-matrix";
const DEFAULT_REQUIRED_TARGETS = ["staging", "preprod"];
const DEFAULT_MAX_AGE_HOURS = 168;

const REQUIRED_ASSERTIONS = [
  "challenge_issue_passed",
  "delivery_passed",
  "receipt_signature_verified",
  "replay_guard_passed"
];

function parsePositiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function parseList(value, fallback) {
  if (value == null) {
    return [...fallback];
  }
  const normalized = String(value)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (normalized.length === 0) {
    return [...fallback];
  }
  return normalized;
}

function parseArgs(argv) {
  const args = {
    matrixReport: process.env.LOOM_INTEROP_MATRIX_REPORT || null,
    outputDir: process.env.LOOM_INTEROP_MATRIX_OUTPUT_DIR || DEFAULT_MATRIX_OUTPUT_DIR,
    requiredTargets: parseList(process.env.LOOM_INTEROP_REQUIRED_TARGETS, DEFAULT_REQUIRED_TARGETS),
    maxAgeHours: parsePositiveInt(process.env.LOOM_INTEROP_EVIDENCE_MAX_AGE_HOURS, DEFAULT_MAX_AGE_HOURS),
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }
    if (arg === "--matrix-report" && i + 1 < argv.length) {
      args.matrixReport = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--output-dir" && i + 1 < argv.length) {
      args.outputDir = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--required-targets" && i + 1 < argv.length) {
      args.requiredTargets = parseList(argv[i + 1], DEFAULT_REQUIRED_TARGETS);
      i += 1;
      continue;
    }
    if (arg === "--max-age-hours" && i + 1 < argv.length) {
      args.maxAgeHours = parsePositiveInt(argv[i + 1], DEFAULT_MAX_AGE_HOURS);
      i += 1;
      continue;
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage:
  node scripts/check_federation_interop_evidence.js [options]

Options:
  --matrix-report <path>      Use explicit matrix report JSON
  --output-dir <path>         Matrix output root (default: ${DEFAULT_MATRIX_OUTPUT_DIR})
  --required-targets <csv>    Required environment names (default: staging,preprod)
  --max-age-hours <int>       Maximum evidence age in hours (default: ${DEFAULT_MAX_AGE_HOURS})
  -h, --help                  Show help
`);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf-8"));
}

function findLatestReport(outputDir) {
  const root = resolve(outputDir);
  if (!existsSync(root)) {
    return null;
  }

  const candidates = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) {
      continue;
    }
    const reportPath = join(root, entry.name, "report.json");
    if (!existsSync(reportPath)) {
      continue;
    }
    let modifiedMs = 0;
    try {
      modifiedMs = statSync(reportPath).mtimeMs;
    } catch {
      modifiedMs = 0;
    }
    candidates.push({ reportPath, modifiedMs });
  }

  if (candidates.length === 0) {
    return null;
  }

  candidates.sort((left, right) => right.modifiedMs - left.modifiedMs);
  return candidates[0].reportPath;
}

function normalizeTargetName(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function validateAssertions(assertions, targetName, errors, checks) {
  if (!assertions || typeof assertions !== "object") {
    errors.push(`Target ${targetName} is missing assertions.`);
    return;
  }

  for (const assertion of REQUIRED_ASSERTIONS) {
    if (assertions[assertion] !== true) {
      errors.push(`Target ${targetName} assertion failed or missing: ${assertion}`);
    } else {
      checks.push(`Target ${targetName} assertion passed: ${assertion}`);
    }
  }
}

function validateEvidenceAge(timestamp, maxAgeHours, errors, checks) {
  const raw = String(timestamp || "").trim();
  if (!raw) {
    errors.push("Matrix report is missing finished_at.");
    return;
  }

  const finishedAtMs = Date.parse(raw);
  if (!Number.isFinite(finishedAtMs)) {
    errors.push(`Matrix report has invalid finished_at timestamp: ${raw}`);
    return;
  }

  const ageHours = (Date.now() - finishedAtMs) / (1000 * 60 * 60);
  if (ageHours > maxAgeHours) {
    errors.push(
      `Matrix report is stale (${ageHours.toFixed(2)}h old, max ${maxAgeHours}h).`
    );
    return;
  }
  checks.push(`Matrix report age (${ageHours.toFixed(2)}h) is within ${maxAgeHours}h`);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const checks = [];
  const warnings = [];
  const errors = [];

  const reportPath = args.matrixReport ? resolve(args.matrixReport) : findLatestReport(args.outputDir);
  if (!reportPath || !existsSync(reportPath)) {
    console.error("ERROR: matrix report not found. Run drill:federation-interop-matrix first.");
    process.exit(1);
  }
  checks.push(`Using matrix report: ${reportPath}`);

  let report;
  try {
    report = readJson(reportPath);
  } catch (error) {
    console.error(`ERROR: failed to parse matrix report: ${error.message}`);
    process.exit(1);
  }

  if (!Array.isArray(report.targets) || report.targets.length === 0) {
    errors.push("Matrix report has no target runs.");
  } else {
    checks.push(`Matrix report contains ${report.targets.length} target run(s)`);
  }

  if (report.success !== true) {
    errors.push("Matrix report indicates overall failure.");
  } else {
    checks.push("Matrix report indicates overall success");
  }

  validateEvidenceAge(report.finished_at, args.maxAgeHours, errors, checks);

  const indexByName = new Map();
  for (const target of Array.isArray(report.targets) ? report.targets : []) {
    const key = normalizeTargetName(target.name);
    if (!key) {
      warnings.push("Encountered target entry with empty name.");
      continue;
    }
    indexByName.set(key, target);
  }

  for (const required of args.requiredTargets) {
    const key = normalizeTargetName(required);
    if (!key) {
      continue;
    }
    const target = indexByName.get(key);
    if (!target) {
      errors.push(`Required target missing: ${required}`);
      continue;
    }
    if (target.success !== true) {
      errors.push(`Required target failed: ${required}`);
      continue;
    }
    checks.push(`Required target passed: ${required}`);
    validateAssertions(target.assertions, required, errors, checks);
  }

  console.log("\nFederation interop evidence summary:");
  for (const line of checks) {
    console.log(`  - PASS: ${line}`);
  }
  for (const line of warnings) {
    console.log(`  - WARN: ${line}`);
  }
  for (const line of errors) {
    console.log(`  - ERROR: ${line}`);
  }

  if (errors.length > 0) {
    console.error(`\nFAILED: ${errors.length} blocking issue(s) detected.`);
    process.exit(1);
  }
  console.log("\nPASSED: federation interop evidence checks succeeded.");
}

main();
