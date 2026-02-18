#!/usr/bin/env node

import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";

import { generateSigningKeyPair } from "../src/protocol/crypto.js";

const DEFAULT_BASE_URL = "http://127.0.0.1:8787";
const DEFAULT_OUTPUT_DIR = "scripts/output/persistence-drills";
const DEFAULT_TIMEOUT_MS = 15000;

function parseBoolean(value, defaultValue = false) {
  if (value == null) {
    return defaultValue;
  }
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  return defaultValue;
}

function parsePositiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function nowStamp() {
  const date = new Date();
  const pad = (value) => String(value).padStart(2, "0");
  return [
    date.getUTCFullYear(),
    pad(date.getUTCMonth() + 1),
    pad(date.getUTCDate()),
    "T",
    pad(date.getUTCHours()),
    pad(date.getUTCMinutes()),
    pad(date.getUTCSeconds()),
    "Z"
  ].join("");
}

function parseArgs(argv) {
  const opts = {
    baseUrl: process.env.LOOM_BASE_URL || DEFAULT_BASE_URL,
    adminToken: process.env.LOOM_ADMIN_TOKEN || "",
    includeAudit: true,
    executeRestore: false,
    replaceState: true,
    truncateAudit: false,
    timeoutMs: parsePositiveInt(process.env.LOOM_DRILL_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
    outputDir: process.env.LOOM_DRILL_OUTPUT_DIR || DEFAULT_OUTPUT_DIR,
    drillId: `drill-${nowStamp()}`,
    writeBackup: true,
    expectedSchema: parsePositiveInt(process.env.LOOM_DRILL_EXPECTED_SCHEMA, 3),
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      opts.help = true;
      continue;
    }
    if (arg === "--base-url" && i + 1 < argv.length) {
      opts.baseUrl = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--admin-token" && i + 1 < argv.length) {
      opts.adminToken = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--include-audit" && i + 1 < argv.length) {
      opts.includeAudit = parseBoolean(argv[i + 1], true);
      i += 1;
      continue;
    }
    if (arg === "--execute-restore") {
      opts.executeRestore = true;
      continue;
    }
    if (arg === "--replace-state" && i + 1 < argv.length) {
      opts.replaceState = parseBoolean(argv[i + 1], true);
      i += 1;
      continue;
    }
    if (arg === "--truncate-audit" && i + 1 < argv.length) {
      opts.truncateAudit = parseBoolean(argv[i + 1], false);
      i += 1;
      continue;
    }
    if (arg === "--timeout-ms" && i + 1 < argv.length) {
      opts.timeoutMs = parsePositiveInt(argv[i + 1], DEFAULT_TIMEOUT_MS);
      i += 1;
      continue;
    }
    if (arg === "--output-dir" && i + 1 < argv.length) {
      opts.outputDir = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--drill-id" && i + 1 < argv.length) {
      opts.drillId = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--write-backup" && i + 1 < argv.length) {
      opts.writeBackup = parseBoolean(argv[i + 1], true);
      i += 1;
      continue;
    }
    if (arg === "--expected-schema" && i + 1 < argv.length) {
      opts.expectedSchema = parsePositiveInt(argv[i + 1], 3);
      i += 1;
      continue;
    }
  }

  return opts;
}

function printHelp() {
  console.log(`Usage:
  node scripts/run_persistence_drill.js [options]

Options:
  --base-url <url>           API base URL (default: ${DEFAULT_BASE_URL})
  --admin-token <token>      Admin token (or LOOM_ADMIN_TOKEN env)
  --include-audit <bool>     Include audit entries in backup (default: true)
  --execute-restore          Execute restore step (default: false)
  --replace-state <bool>     replace_state for restore payload (default: true)
  --truncate-audit <bool>    truncate_audit for restore payload (default: false)
  --expected-schema <int>    Expected schema version (default: 3)
  --timeout-ms <int>         HTTP timeout in ms (default: ${DEFAULT_TIMEOUT_MS})
  --output-dir <path>        Output directory (default: ${DEFAULT_OUTPUT_DIR})
  --drill-id <id>            Override drill ID
  --write-backup <bool>      Persist backup payload to file (default: true)
  -h, --help                 Show help

Examples:
  npm run drill:persistence -- --base-url https://loom.example.com --execute-restore
  npm run drill:persistence -- --base-url http://127.0.0.1:8787 --include-audit false
`);
}

function ensureBaseUrl(raw) {
  try {
    const url = new URL(raw);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("base URL must use http or https");
    }
    if (!url.pathname.endsWith("/")) {
      url.pathname = `${url.pathname}/`;
    }
    return url.toString();
  } catch (error) {
    throw new Error(`Invalid --base-url: ${raw} (${error.message})`);
  }
}

async function requestJson(baseUrl, path, adminToken, timeoutMs, method = "GET", body = null) {
  const url = new URL(path, baseUrl).toString();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method,
      headers: {
        "content-type": "application/json",
        "x-loom-admin-token": adminToken
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal
    });
    const text = await response.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return {
      url,
      status: response.status,
      ok: response.ok,
      json,
      text
    };
  } finally {
    clearTimeout(timer);
  }
}

function validateBackupShape(backup, includeAudit) {
  const errors = [];
  const warnings = [];
  if (!backup || typeof backup !== "object") {
    errors.push("Backup response is not an object.");
    return { errors, warnings };
  }
  if (!backup.state || typeof backup.state !== "object") {
    errors.push("Backup is missing `state` object.");
  }
  if (!Array.isArray(backup.audit_entries)) {
    errors.push("Backup is missing `audit_entries` array.");
  } else if (includeAudit && backup.audit_entries.length === 0) {
    warnings.push("Backup audit_entries array is empty.");
  }

  if (backup.loom_backup_version !== 1) {
    warnings.push(`Unexpected loom_backup_version: ${backup.loom_backup_version ?? "missing"}`);
  }
  if (!backup.exported_at) {
    warnings.push("Backup missing exported_at timestamp.");
  }
  return { errors, warnings };
}

function uniqueIdentityDomains(values = []) {
  const seen = new Set();
  const output = [];
  for (const value of values) {
    const normalized = String(value || "")
      .trim()
      .toLowerCase()
      .replace(/\.+$/, "");
    if (!normalized || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    output.push(normalized);
  }
  return output;
}

async function bootstrapPersistenceSeed(baseUrl, adminToken, timeoutMs) {
  const nodeDoc = await requestJson(baseUrl, "/.well-known/loom.json", adminToken, timeoutMs);
  if (!nodeDoc.ok || !nodeDoc.json) {
    throw new Error(`Seed bootstrap failed: node document request returned HTTP ${nodeDoc.status}`);
  }

  const baseHost = new URL(baseUrl).hostname;
  const domains = uniqueIdentityDomains([nodeDoc.json.node_id, baseHost]);
  if (domains.length === 0) {
    throw new Error("Seed bootstrap failed: unable to derive local identity domain.");
  }

  const keyPair = generateSigningKeyPair();
  const keyId = `k_sign_seed_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
  const localPart = `seed-${randomUUID().replace(/-/g, "").slice(0, 10)}`;

  let lastStatus = null;
  for (const domain of domains) {
    const identity = `loom://${localPart}@${domain}`;
    const register = await requestJson(
      baseUrl,
      "/v1/identity",
      adminToken,
      timeoutMs,
      "POST",
      {
        id: identity,
        display_name: "Persistence Drill Seed",
        signing_keys: [{ key_id: keyId, public_key_pem: keyPair.publicKeyPem }]
      }
    );
    lastStatus = register.status;
    if (register.ok) {
      return {
        identity,
        status: register.status
      };
    }
  }

  throw new Error(`Seed bootstrap failed: identity registration returned HTTP ${lastStatus ?? "unknown"}.`);
}

function writeJson(path, value) {
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n");
}

function makeSummaryMarkdown(report, backupPath, reportPath) {
  const lines = [];
  lines.push(`# Persistence Drill Report`);
  lines.push("");
  lines.push(`- Drill ID: \`${report.drill_id}\``);
  lines.push(`- Started: \`${report.started_at}\``);
  lines.push(`- Finished: \`${report.finished_at}\``);
  lines.push(`- Base URL: \`${report.base_url}\``);
  lines.push(`- Result: **${report.success ? "PASS" : "FAIL"}**`);
  lines.push(`- Restore executed: \`${report.restore.executed}\``);
  lines.push(`- Include audit: \`${report.include_audit}\``);
  lines.push("");

  if (report.schema_before) {
    lines.push(`## Schema`);
    lines.push("");
    lines.push(`- Before status: \`${report.schema_before.status}\``);
    lines.push(`- Before schema version: \`${report.schema_before.schema_version ?? "unknown"}\``);
    lines.push(`- After status: \`${report.schema_after?.status ?? "n/a"}\``);
    lines.push(`- After schema version: \`${report.schema_after?.schema_version ?? "n/a"}\``);
    lines.push(`- Expected schema version: \`${report.expected_schema}\``);
    lines.push("");
  }

  lines.push(`## Backup`);
  lines.push("");
  lines.push(`- HTTP status: \`${report.backup.status}\``);
  lines.push(`- Backend: \`${report.backup.backend ?? "unknown"}\``);
  lines.push(`- State key: \`${report.backup.state_key ?? "unknown"}\``);
  lines.push(`- Audit entries: \`${report.backup.audit_entries_count ?? 0}\``);
  lines.push("");

  if (report.restore.executed) {
    lines.push(`## Restore`);
    lines.push("");
    lines.push(`- HTTP status: \`${report.restore.status}\``);
    lines.push(`- Replaced state: \`${report.restore.replaced_state}\``);
    lines.push(`- Imported audit count: \`${report.restore.imported_audit_count}\``);
    lines.push(`- Truncate audit: \`${report.restore.truncate_audit}\``);
    lines.push("");
  }

  if (report.warnings.length > 0) {
    lines.push(`## Warnings`);
    lines.push("");
    for (const warning of report.warnings) {
      lines.push(`- ${warning}`);
    }
    lines.push("");
  }

  if (report.errors.length > 0) {
    lines.push(`## Errors`);
    lines.push("");
    for (const error of report.errors) {
      lines.push(`- ${error}`);
    }
    lines.push("");
  }

  lines.push(`## Artifacts`);
  lines.push("");
  if (backupPath) {
    lines.push(`- Backup JSON: \`${backupPath}\``);
  }
  lines.push(`- Drill report JSON: \`${reportPath}\``);
  lines.push("");

  return lines.join("\n") + "\n";
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    printHelp();
    process.exit(0);
  }

  const baseUrl = ensureBaseUrl(opts.baseUrl);
  if (!String(opts.adminToken || "").trim()) {
    console.error("ERROR: --admin-token is required (or set LOOM_ADMIN_TOKEN).");
    process.exit(1);
  }

  const report = {
    drill_id: opts.drillId,
    started_at: new Date().toISOString(),
    finished_at: null,
    base_url: baseUrl,
    include_audit: opts.includeAudit,
    expected_schema: opts.expectedSchema,
    restore: {
      requested: opts.executeRestore,
      executed: false,
      status: null,
      replaced_state: null,
      imported_audit_count: null,
      truncate_audit: opts.truncateAudit
    },
    schema_before: null,
    schema_after: null,
    backup: {
      status: null,
      backend: null,
      state_key: null,
      schema_version: null,
      audit_entries_count: null
    },
    warnings: [],
    errors: [],
    success: false
  };

  let backupPayload = null;

  try {
    const schemaBefore = await requestJson(
      baseUrl,
      "/v1/admin/persistence/schema",
      opts.adminToken,
      opts.timeoutMs
    );
    report.schema_before = {
      status: schemaBefore.status,
      schema_version: schemaBefore.json?.schema_version ?? null,
      backend: schemaBefore.json?.backend ?? null
    };
    if (!schemaBefore.ok) {
      report.errors.push(`Schema check failed: HTTP ${schemaBefore.status}`);
      throw new Error("schema_check_failed");
    }

    const fetchBackup = async () =>
      requestJson(
        baseUrl,
        `/v1/admin/persistence/backup?include_audit=${opts.includeAudit ? "true" : "false"}`,
        opts.adminToken,
        opts.timeoutMs
      );

    let backup = await fetchBackup();
    report.backup.status = backup.status;
    if (!backup.ok || !backup.json) {
      report.errors.push(`Backup request failed: HTTP ${backup.status}`);
      throw new Error("backup_failed");
    }

    backupPayload = backup.json;
    report.backup.backend = backupPayload.backend ?? null;
    report.backup.state_key = backupPayload.state_key ?? null;
    report.backup.schema_version = backupPayload.schema_version ?? null;
    report.backup.audit_entries_count = Array.isArray(backupPayload.audit_entries)
      ? backupPayload.audit_entries.length
      : null;

    let backupValidation = validateBackupShape(backupPayload, opts.includeAudit);
    if (
      opts.executeRestore &&
      backupValidation.errors.includes("Backup is missing `state` object.")
    ) {
      const seeded = await bootstrapPersistenceSeed(baseUrl, opts.adminToken, opts.timeoutMs);
      report.warnings.push(
        `Backup state was empty on first attempt; seeded state using ${seeded.identity} and retried backup.`
      );
      backup = await fetchBackup();
      report.backup.status = backup.status;
      if (!backup.ok || !backup.json) {
        report.errors.push(`Backup retry after seed failed: HTTP ${backup.status}`);
        throw new Error("backup_failed");
      }
      backupPayload = backup.json;
      report.backup.backend = backupPayload.backend ?? null;
      report.backup.state_key = backupPayload.state_key ?? null;
      report.backup.schema_version = backupPayload.schema_version ?? null;
      report.backup.audit_entries_count = Array.isArray(backupPayload.audit_entries)
        ? backupPayload.audit_entries.length
        : null;
      backupValidation = validateBackupShape(backupPayload, opts.includeAudit);
    }

    report.warnings.push(...backupValidation.warnings);
    if (backupValidation.errors.length > 0) {
      report.errors.push(...backupValidation.errors);
      throw new Error("backup_validation_failed");
    }

    if (
      report.schema_before.schema_version != null &&
      report.schema_before.schema_version !== opts.expectedSchema
    ) {
      report.errors.push(
        `Schema mismatch before drill: expected ${opts.expectedSchema}, got ${report.schema_before.schema_version}`
      );
      throw new Error("schema_mismatch_before");
    }

    if (opts.executeRestore) {
      const restorePayload = {
        confirm: "restore",
        backup: backupPayload,
        replace_state: opts.replaceState,
        truncate_audit: opts.truncateAudit
      };
      const restore = await requestJson(
        baseUrl,
        "/v1/admin/persistence/restore",
        opts.adminToken,
        opts.timeoutMs,
        "POST",
        restorePayload
      );
      report.restore.executed = true;
      report.restore.status = restore.status;
      report.restore.replaced_state = restore.json?.replaced_state ?? null;
      report.restore.imported_audit_count = restore.json?.imported_audit_count ?? null;

      if (!restore.ok) {
        report.errors.push(`Restore request failed: HTTP ${restore.status}`);
        throw new Error("restore_failed");
      }
    }

    const schemaAfter = await requestJson(
      baseUrl,
      "/v1/admin/persistence/schema",
      opts.adminToken,
      opts.timeoutMs
    );
    report.schema_after = {
      status: schemaAfter.status,
      schema_version: schemaAfter.json?.schema_version ?? null,
      backend: schemaAfter.json?.backend ?? null
    };
    if (!schemaAfter.ok) {
      report.errors.push(`Post-restore schema check failed: HTTP ${schemaAfter.status}`);
      throw new Error("schema_check_after_failed");
    }

    if (
      report.schema_after.schema_version != null &&
      report.schema_after.schema_version !== opts.expectedSchema
    ) {
      report.errors.push(
        `Schema mismatch after drill: expected ${opts.expectedSchema}, got ${report.schema_after.schema_version}`
      );
      throw new Error("schema_mismatch_after");
    }

    report.success = report.errors.length === 0;
  } catch (error) {
    if (error?.message && !["schema_check_failed", "backup_failed", "restore_failed", "schema_check_after_failed", "backup_validation_failed", "schema_mismatch_before", "schema_mismatch_after"].includes(error.message)) {
      report.errors.push(error.message);
    }
    report.success = false;
  } finally {
    report.finished_at = new Date().toISOString();
  }

  const outputRoot = resolve(opts.outputDir);
  const drillDir = resolve(join(outputRoot, opts.drillId));
  mkdirSync(drillDir, { recursive: true });

  const backupPath = opts.writeBackup && backupPayload ? join(drillDir, "backup.json") : null;
  const reportPath = join(drillDir, "report.json");
  const summaryPath = join(drillDir, "summary.md");

  if (backupPath) {
    writeJson(backupPath, backupPayload);
  }
  writeJson(reportPath, report);
  writeFileSync(summaryPath, makeSummaryMarkdown(report, backupPath, reportPath), "utf-8");

  console.log(`Drill report: ${reportPath}`);
  console.log(`Drill summary: ${summaryPath}`);
  if (backupPath) {
    console.log(`Backup payload: ${backupPath}`);
  }

  if (!report.success) {
    console.error("Persistence drill failed.");
    for (const error of report.errors) {
      console.error(`- ${error}`);
    }
    process.exit(1);
  }

  console.log("Persistence drill passed.");
}

main();
