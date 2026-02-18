#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const DEFAULT_DOC_PATH = "docs/COMPLIANCE-CONTROLS.md";
const DEFAULT_CHECKLIST_DIR = "ops/compliance/checklists";

const REQUIRED_DOC_HEADINGS = [
  "# LOOM Compliance Controls",
  "## Compliance Scope",
  "## Audit Export Controls",
  "## Retention Policy",
  "## Policy Control Mapping",
  "## Evidence And Review Cadence",
  "## Validation Command"
];

const REQUIRED_DOC_TERMS = [
  "/v1/admin/persistence/backup",
  "/v1/audit",
  "LOOM_AUDIT_HMAC_KEY",
  "LOOM_AUDIT_REQUIRE_MAC_VALIDATION",
  "LOOM_AUDIT_VALIDATE_CHAIN",
  "docs/ACCESS-GOVERNANCE.md",
  "docs/SECRETS-KEY-ROTATION.md",
  "docs/RELEASE-POLICY.md",
  "npm run check:compliance",
  "npm run drill:compliance",
  "npm run gate:compliance"
];

const REQUIRED_CHECKLIST_SECTIONS = [
  "## Scope",
  "## Audit Export Validation",
  "## Retention Validation",
  "## Policy Control Validation",
  "## Sign-off"
];

const REQUIRED_POLICY_DOCS = [
  "docs/ACCESS-GOVERNANCE.md",
  "docs/SECRETS-KEY-ROTATION.md",
  "docs/INBOUND-BRIDGE-HARDENING.md",
  "docs/RATE-LIMIT-POLICY.md",
  "docs/SECURITY-TESTING-PROGRAM.md",
  "docs/RELEASE-POLICY.md"
];

const CHECKLIST_PLACEHOLDER_PATTERNS = [
  /^#.*\btemplate\b/im,
  /\bpass\/fail\b/i,
  /_{3,}/,
  /\bproduct owner:\s*pending\b/i,
  /\bsecurity owner:\s*pending\b/i,
  /\breview window:\s*[_-]+\s*$/im
];

function parsePositiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function parseEnvFile(path) {
  const parsed = {};
  const source = readFileSync(path, "utf-8");
  const lines = source.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const idx = trimmed.indexOf("=");
    if (idx <= 0) {
      continue;
    }
    const key = trimmed.slice(0, idx).trim();
    let value = trimmed.slice(idx + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    parsed[key] = value;
  }
  return parsed;
}

function parseArgs(argv) {
  const args = {
    docPath: DEFAULT_DOC_PATH,
    checklistDir: DEFAULT_CHECKLIST_DIR,
    maxAgeDays: 180,
    envFile: null,
    baseUrl: null,
    adminToken: null,
    bearerToken: null,
    timeoutMs: 10000,
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }
    if (arg === "--doc" && i + 1 < argv.length) {
      args.docPath = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--checklist-dir" && i + 1 < argv.length) {
      args.checklistDir = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--max-age-days" && i + 1 < argv.length) {
      args.maxAgeDays = parsePositiveInt(argv[i + 1], 180);
      i += 1;
      continue;
    }
    if (arg === "--env-file" && i + 1 < argv.length) {
      args.envFile = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--base-url" && i + 1 < argv.length) {
      args.baseUrl = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--admin-token" && i + 1 < argv.length) {
      args.adminToken = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--bearer-token" && i + 1 < argv.length) {
      args.bearerToken = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--timeout-ms" && i + 1 < argv.length) {
      args.timeoutMs = parsePositiveInt(argv[i + 1], 10000);
      i += 1;
      continue;
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage:
  node scripts/check_compliance_controls.js [options]

Options:
  --doc <path>             Compliance doc path (default: ${DEFAULT_DOC_PATH})
  --checklist-dir <path>   Compliance checklist records directory (default: ${DEFAULT_CHECKLIST_DIR})
  --max-age-days <int>     Warn when latest checklist is older than this (default: 180)
  --env-file <path>        Optional env file for runtime probe tokens/base URL
  --base-url <url>         Optional runtime URL for audit/control probes
  --admin-token <token>    Optional admin token for admin compliance probes
  --bearer-token <token>   Optional bearer token for /v1/audit probe
  --timeout-ms <int>       Runtime probe timeout in ms (default: 10000)
  -h, --help               Show help
`);
}

function isTemplateRecordName(name) {
  return /template/i.test(name);
}

function hasResolvedSignoff(source, label) {
  const escapedLabel = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const matcher = new RegExp(`^-\\s*${escapedLabel}:\\s*(.+)\\s*$`, "im");
  const match = source.match(matcher);
  if (!match) {
    return false;
  }
  const value = match[1].trim();
  if (!value) {
    return false;
  }
  if (/^_{3,}$/.test(value)) {
    return false;
  }
  if (/^pending$/i.test(value)) {
    return false;
  }
  return true;
}

function hasResolvedSignoffDate(source) {
  const matcher = source.match(/^-?\s*Date:\s*(.+)\s*$/im);
  if (!matcher) {
    return false;
  }
  const value = matcher[1].trim();
  if (!value || /^_{3,}$/.test(value)) {
    return false;
  }
  return /^\d{4}-\d{2}-\d{2}$/.test(value);
}

async function fetchJson(url, options = {}) {
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs || 10000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: options.method || "GET",
      headers: options.headers || {},
      signal: controller.signal
    });
    const text = await response.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return { response, text, json };
  } finally {
    clearTimeout(timer);
  }
}

function checkDoc(args, checks, errors) {
  const docPath = resolve(args.docPath);
  if (!existsSync(docPath)) {
    errors.push(`Compliance controls doc not found: ${docPath}`);
    return;
  }

  checks.push(`Compliance controls doc present: ${docPath}`);
  const source = readFileSync(docPath, "utf-8");

  for (const heading of REQUIRED_DOC_HEADINGS) {
    if (!source.includes(heading)) {
      errors.push(`Compliance controls doc missing required section: ${heading}`);
    } else {
      checks.push(`Compliance controls section present: ${heading}`);
    }
  }

  for (const term of REQUIRED_DOC_TERMS) {
    if (!source.includes(term)) {
      errors.push(`Compliance controls doc missing required control reference: ${term}`);
    } else {
      checks.push(`Compliance controls reference present: ${term}`);
    }
  }

  const reviewedMatch = source.match(/^Last reviewed:\s*(\d{4}-\d{2}-\d{2})\s*$/m);
  if (!reviewedMatch) {
    errors.push("Compliance controls doc is missing `Last reviewed: YYYY-MM-DD`.");
  } else {
    checks.push(`Compliance controls includes Last reviewed date: ${reviewedMatch[1]}`);
  }
}

function checkChecklistDirectory(args, checks, warnings, errors) {
  const checklistDir = resolve(args.checklistDir);
  if (!existsSync(checklistDir)) {
    errors.push(`Compliance checklist directory not found: ${checklistDir}`);
    return;
  }

  const checklistRecords = readdirSync(checklistDir)
    .filter((name) => name.endsWith(".md"))
    .filter((name) => !isTemplateRecordName(name))
    .map((name) => {
      const path = join(checklistDir, name);
      return {
        name,
        path,
        mtimeMs: statSync(path).mtimeMs
      };
    })
    .sort((left, right) => right.mtimeMs - left.mtimeMs);

  if (checklistRecords.length === 0) {
    errors.push(`No non-template compliance checklist records found under ${checklistDir}`);
    return;
  }

  checks.push(`Found ${checklistRecords.length} compliance checklist record(s)`);
  const latest = checklistRecords[0];
  const latestSource = readFileSync(latest.path, "utf-8");
  for (const pattern of CHECKLIST_PLACEHOLDER_PATTERNS) {
    if (pattern.test(latestSource)) {
      errors.push(`Latest compliance checklist contains unresolved placeholder content: ${latest.name}`);
      break;
    }
  }
  for (const section of REQUIRED_CHECKLIST_SECTIONS) {
    if (!latestSource.includes(section)) {
      errors.push(`Latest compliance checklist is missing section ${section}: ${latest.name}`);
    } else {
      checks.push(`Latest compliance checklist section present: ${section}`);
    }
  }

  const ageDays = (Date.now() - latest.mtimeMs) / (1000 * 60 * 60 * 24);
  if (ageDays > args.maxAgeDays) {
    warnings.push(
      `Latest compliance checklist record is ${ageDays.toFixed(1)} days old (max ${args.maxAgeDays} before warning).`
    );
  } else {
    checks.push(`Latest compliance checklist age (${ageDays.toFixed(1)} days) is within ${args.maxAgeDays} days`);
  }

  if (!hasResolvedSignoff(latestSource, "Product owner")) {
    errors.push(`Latest compliance checklist has unresolved Product owner sign-off: ${latest.name}`);
  } else {
    checks.push(`Latest compliance checklist includes Product owner sign-off: ${latest.name}`);
  }
  if (!hasResolvedSignoff(latestSource, "Security owner")) {
    errors.push(`Latest compliance checklist has unresolved Security owner sign-off: ${latest.name}`);
  } else {
    checks.push(`Latest compliance checklist includes Security owner sign-off: ${latest.name}`);
  }
  if (!hasResolvedSignoffDate(latestSource)) {
    errors.push(`Latest compliance checklist has unresolved or invalid Date sign-off (YYYY-MM-DD): ${latest.name}`);
  } else {
    checks.push(`Latest compliance checklist includes Date sign-off: ${latest.name}`);
  }
}

function checkRepositoryWiring(checks, errors) {
  for (const relPath of REQUIRED_POLICY_DOCS) {
    const full = resolve(relPath);
    if (!existsSync(full)) {
      errors.push(`Required policy doc missing: ${relPath}`);
    } else {
      checks.push(`Policy doc present: ${relPath}`);
    }
  }

  const readinessPath = resolve("docs/PRODUCTION-READINESS.md");
  if (!existsSync(readinessPath)) {
    errors.push("Required readiness artifact missing: docs/PRODUCTION-READINESS.md");
  } else {
    const readiness = readFileSync(readinessPath, "utf-8");
    if (!/\|\s*P2-03\s*\|\s*Compliance controls package\s*\|\s*Product\s*\|\s*DONE\s*\|/m.test(readiness)) {
      errors.push("docs/PRODUCTION-READINESS.md does not mark P2-03 as DONE.");
    } else {
      checks.push("Production readiness marks P2-03 as DONE");
    }
  }

  const releaseChecklistPath = resolve("docs/RELEASE-CHECKLIST.md");
  if (!existsSync(releaseChecklistPath)) {
    errors.push("Required release checklist artifact missing: docs/RELEASE-CHECKLIST.md");
  } else {
    const source = readFileSync(releaseChecklistPath, "utf-8");
    if (!source.includes("npm run check:compliance")) {
      errors.push("docs/RELEASE-CHECKLIST.md is missing npm run check:compliance.");
    } else {
      checks.push("Release checklist includes npm run check:compliance");
    }
    if (!source.includes("npm run drill:compliance")) {
      errors.push("docs/RELEASE-CHECKLIST.md is missing npm run drill:compliance.");
    } else {
      checks.push("Release checklist includes npm run drill:compliance");
    }
    if (!source.includes("npm run gate:compliance")) {
      errors.push("docs/RELEASE-CHECKLIST.md is missing npm run gate:compliance.");
    } else {
      checks.push("Release checklist includes npm run gate:compliance");
    }
  }

  const packageJsonPath = resolve("package.json");
  if (!existsSync(packageJsonPath)) {
    errors.push("package.json not found.");
  } else {
    try {
      const pkg = JSON.parse(readFileSync(packageJsonPath, "utf-8"));
      if (!pkg?.scripts?.["check:compliance"]) {
        errors.push("package.json is missing scripts.check:compliance.");
      } else {
        checks.push("package.json includes scripts.check:compliance");
      }
      if (!pkg?.scripts?.["drill:compliance"]) {
        errors.push("package.json is missing scripts.drill:compliance.");
      } else {
        checks.push("package.json includes scripts.drill:compliance");
      }
      if (!pkg?.scripts?.["gate:compliance"]) {
        errors.push("package.json is missing scripts.gate:compliance.");
      } else {
        checks.push("package.json includes scripts.gate:compliance");
      }
    } catch {
      errors.push("Failed to parse package.json while checking compliance scripts.");
    }
  }
}

async function runRuntimeChecks(baseUrl, adminToken, bearerToken, timeoutMs, checks, warnings, errors) {
  if (!baseUrl) {
    warnings.push("Runtime compliance probes skipped (no --base-url provided).");
    return;
  }

  let normalizedBaseUrl;
  try {
    normalizedBaseUrl = new URL(baseUrl).toString();
  } catch (error) {
    errors.push(`Invalid --base-url value: ${baseUrl} (${error.message})`);
    return;
  }

  if (!adminToken) {
    warnings.push("Admin runtime probes skipped (no --admin-token provided).");
  } else {
    try {
      const backupUrl = new URL("/v1/admin/persistence/backup?include_audit=true&audit_limit=2", normalizedBaseUrl).toString();
      const backup = await fetchJson(backupUrl, {
        timeoutMs,
        headers: {
          "x-loom-admin-token": adminToken
        }
      });
      if (!backup.response.ok || !backup.json) {
        errors.push(`/v1/admin/persistence/backup runtime probe failed: HTTP ${backup.response.status}`);
      } else {
        checks.push("/v1/admin/persistence/backup runtime probe succeeded");
        if (!Array.isArray(backup.json.audit_entries)) {
          errors.push("Backup payload missing audit_entries array.");
        } else {
          checks.push(`Backup payload includes audit_entries (${backup.json.audit_entries.length})`);
        }
        if (typeof backup.json.exported_at !== "string") {
          errors.push("Backup payload missing exported_at timestamp.");
        } else {
          checks.push("Backup payload includes exported_at timestamp");
        }
        if (!Object.prototype.hasOwnProperty.call(backup.json, "schema_version")) {
          errors.push("Backup payload missing schema_version.");
        } else {
          checks.push("Backup payload includes schema_version");
        }
      }
    } catch (error) {
      errors.push(`Backup runtime probe failed: ${error.message}`);
    }

    try {
      const statusUrl = new URL("/v1/admin/status", normalizedBaseUrl).toString();
      const status = await fetchJson(statusUrl, {
        timeoutMs,
        headers: {
          "x-loom-admin-token": adminToken
        }
      });
      if (!status.response.ok || !status.json) {
        errors.push(`/v1/admin/status runtime probe failed: HTTP ${status.response.status}`);
      } else {
        checks.push("/v1/admin/status runtime probe succeeded");
        if (typeof status.json.api_rate_limit_policy !== "object" || status.json.api_rate_limit_policy == null) {
          errors.push("/v1/admin/status missing api_rate_limit_policy snapshot.");
        } else {
          checks.push("/v1/admin/status includes api_rate_limit_policy");
        }
        if (typeof status.json.identity_rate_limit_policy !== "object" || status.json.identity_rate_limit_policy == null) {
          errors.push("/v1/admin/status missing identity_rate_limit_policy snapshot.");
        } else {
          checks.push("/v1/admin/status includes identity_rate_limit_policy");
        }
        if (typeof status.json.federation_inbound_policy !== "object" || status.json.federation_inbound_policy == null) {
          errors.push("/v1/admin/status missing federation_inbound_policy snapshot.");
        } else {
          checks.push("/v1/admin/status includes federation_inbound_policy");
        }
      }
    } catch (error) {
      errors.push(`Admin status runtime probe failed: ${error.message}`);
    }
  }

  if (!bearerToken) {
    warnings.push("User audit runtime probe skipped (no --bearer-token provided).");
    return;
  }

  try {
    const auditUrl = new URL("/v1/audit?limit=5", normalizedBaseUrl).toString();
    const audit = await fetchJson(auditUrl, {
      timeoutMs,
      headers: {
        authorization: `Bearer ${bearerToken}`
      }
    });
    if (!audit.response.ok || !audit.json) {
      errors.push(`/v1/audit runtime probe failed: HTTP ${audit.response.status}`);
      return;
    }
    if (!Array.isArray(audit.json.entries)) {
      errors.push("/v1/audit runtime probe did not return entries array.");
      return;
    }
    checks.push(`/v1/audit runtime probe succeeded (${audit.json.entries.length} entries)`);
    if (audit.json.entries.length === 0) {
      warnings.push("/v1/audit returned zero entries in runtime probe.");
    } else {
      const first = audit.json.entries[0];
      if (!first?.event_id || !first?.action || !first?.timestamp) {
        errors.push("/v1/audit entries are missing one of event_id/action/timestamp.");
      } else {
        checks.push("/v1/audit entries include event_id/action/timestamp fields");
      }
    }
  } catch (error) {
    errors.push(`User audit runtime probe failed: ${error.message}`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const env = { ...process.env };
  if (args.envFile) {
    const envPath = resolve(args.envFile);
    if (!existsSync(envPath)) {
      console.error(`ERROR: env file not found: ${envPath}`);
      process.exit(1);
    }
    Object.assign(env, parseEnvFile(envPath));
    console.log(`Loaded env file: ${envPath}`);
  }

  const checks = [];
  const warnings = [];
  const errors = [];

  checkDoc(args, checks, errors);
  checkChecklistDirectory(args, checks, warnings, errors);
  checkRepositoryWiring(checks, errors);

  const baseUrl = args.baseUrl || env.LOOM_BASE_URL || null;
  const adminToken = args.adminToken || env.LOOM_ADMIN_TOKEN || null;
  const bearerToken =
    args.bearerToken || env.LOOM_COMPLIANCE_AUDIT_BEARER_TOKEN || env.LOOM_FEDERATION_AUDIT_BEARER_TOKEN || null;

  await runRuntimeChecks(baseUrl, adminToken, bearerToken, args.timeoutMs, checks, warnings, errors);

  console.log("\nCompliance controls summary:");
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

  console.log("\nPASSED: compliance controls checks succeeded.");
}

main();
