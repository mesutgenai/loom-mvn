#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const DEFAULT_MATRIX_OUTPUT_DIR = "scripts/output/federation-interop-matrix";
const DEFAULT_REQUIRED_TARGETS = ["staging", "preprod"];
const DEFAULT_MAX_AGE_HOURS = 168;
const DEFAULT_EXPECTED_TARGETS_FILE = "ops/federation/interop-targets.json";

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
    expectedTargetsFile: process.env.LOOM_INTEROP_TARGETS_FILE || DEFAULT_EXPECTED_TARGETS_FILE,
    allowLocalTargets: false,
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
    if (arg === "--expected-targets-file" && i + 1 < argv.length) {
      args.expectedTargetsFile = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--allow-local-targets") {
      args.allowLocalTargets = true;
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
  --expected-targets-file <path>
                              Optional targets config file; when set, required target origins must match this file
  --allow-local-targets       Allow localhost/loopback target URLs (disabled by default)
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

const LOOPBACK_ALIAS_SUFFIXES = ["nip.io", "sslip.io", "localtest.me", "lvh.me"];

function isLoopbackTargetHost(hostname) {
  const normalized = String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^\[(.*)\]$/, "$1");
  if (!normalized) {
    return true;
  }
  if (
    normalized === "localhost" ||
    normalized.startsWith("localhost.") ||
    normalized.endsWith(".localhost") ||
    normalized.includes(".localhost.")
  ) {
    return true;
  }
  if (normalized === "0.0.0.0" || normalized === "::1" || normalized === "0:0:0:0:0:0:0:1") {
    return true;
  }
  if (/^127\./.test(normalized)) {
    return true;
  }
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(normalized)) {
    return true;
  }
  if (/^::ffff:127\./.test(normalized)) {
    return true;
  }
  if (/^\d+$/.test(normalized)) {
    const asInt = Number(normalized);
    if (Number.isFinite(asInt) && asInt === 2130706433) {
      return true;
    }
  }
  if (/^0x[0-9a-f]+$/i.test(normalized)) {
    const asHexInt = Number.parseInt(normalized, 16);
    if (Number.isFinite(asHexInt) && asHexInt === 2130706433) {
      return true;
    }
  }
  if (/^0177\./.test(normalized)) {
    return true;
  }
  if (LOOPBACK_ALIAS_SUFFIXES.some((suffix) => normalized === suffix || normalized.endsWith(`.${suffix}`))) {
    return true;
  }
  return false;
}

function validateTargetBaseUrl(target, targetName, allowLocalTargets, errors, checks) {
  const raw = String(target?.base_url || "").trim();
  if (!raw) {
    errors.push(`Target ${targetName} is missing base_url in matrix evidence.`);
    return null;
  }

  let parsed;
  try {
    parsed = new URL(raw);
  } catch (error) {
    errors.push(`Target ${targetName} has invalid base_url (${raw}): ${error.message}`);
    return null;
  }

  if (!allowLocalTargets) {
    if (parsed.protocol !== "https:") {
      errors.push(`Target ${targetName} base_url must use https in production evidence: ${raw}`);
      return null;
    }
    if (isLoopbackTargetHost(parsed.hostname)) {
      errors.push(`Target ${targetName} base_url must not point to localhost/loopback: ${raw}`);
      return null;
    }
  }

  checks.push(`Target ${targetName} base_url validated (${parsed.origin})`);
  return parsed.origin.toLowerCase();
}

function loadExpectedTargetOrigins(filePath, allowLocalTargets, errors, checks) {
  const resolved = resolve(filePath);
  if (!existsSync(resolved)) {
    errors.push(`Expected targets file not found: ${resolved}`);
    return null;
  }

  let parsed;
  try {
    parsed = JSON.parse(readFileSync(resolved, "utf-8"));
  } catch (error) {
    errors.push(`Expected targets file is not valid JSON: ${resolved} (${error.message})`);
    return null;
  }

  const targets = Array.isArray(parsed) ? parsed : parsed?.targets;
  if (!Array.isArray(targets) || targets.length === 0) {
    errors.push(`Expected targets file must contain a non-empty targets array: ${resolved}`);
    return null;
  }

  const origins = new Map();
  for (const entry of targets) {
    const key = normalizeTargetName(entry?.name ?? entry?.environment);
    if (!key) {
      continue;
    }
    const raw = String(entry?.base_url ?? entry?.baseUrl ?? "").trim();
    if (!raw) {
      errors.push(`Expected target ${entry?.name ?? entry?.environment ?? "(unnamed)"} is missing base_url.`);
      continue;
    }
    try {
      const parsedUrl = new URL(raw);
      if (!allowLocalTargets) {
        if (parsedUrl.protocol !== "https:") {
          errors.push(`Expected target ${entry?.name ?? entry?.environment ?? "(unnamed)"} base_url must use https: ${raw}`);
          continue;
        }
        if (isLoopbackTargetHost(parsedUrl.hostname)) {
          errors.push(
            `Expected target ${entry?.name ?? entry?.environment ?? "(unnamed)"} base_url must not point to localhost/loopback: ${raw}`
          );
          continue;
        }
      }
      origins.set(key, parsedUrl.origin.toLowerCase());
    } catch (error) {
      errors.push(
        `Expected target ${entry?.name ?? entry?.environment ?? "(unnamed)"} has invalid base_url (${raw}): ${error.message}`
      );
    }
  }

  checks.push(`Loaded expected target origins from ${resolved}`);
  return origins;
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

  const expectedTargetOrigins = args.expectedTargetsFile
    ? loadExpectedTargetOrigins(args.expectedTargetsFile, args.allowLocalTargets, errors, checks)
    : null;

  const requiredTargetOrigins = new Map();
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
    const origin = validateTargetBaseUrl(target, required, args.allowLocalTargets, errors, checks);
    if (origin) {
      const existing = requiredTargetOrigins.get(origin);
      if (existing) {
        errors.push(
          `Required targets ${existing} and ${required} share the same base_url origin (${origin}); distinct environments are required.`
        );
      } else {
        requiredTargetOrigins.set(origin, required);
      }
    }
    if (expectedTargetOrigins) {
      const expectedOrigin = expectedTargetOrigins.get(key);
      if (!expectedOrigin) {
        errors.push(`Expected targets file does not include required target: ${required}`);
      } else if (origin && expectedOrigin !== origin) {
        errors.push(
          `Required target ${required} base_url origin (${origin}) does not match expected targets file (${expectedOrigin}).`
        );
      } else if (origin) {
        checks.push(`Required target ${required} origin matches expected targets file`);
      }
    }
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
