#!/usr/bin/env node

import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { generateSigningKeyPair, signUtf8Message } from "../src/protocol/crypto.js";

const DEFAULT_BASE_URL = "http://127.0.0.1:8787";
const DEFAULT_OUTPUT_DIR = "scripts/output/compliance-drills";
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
  const args = {
    baseUrl: process.env.LOOM_BASE_URL || DEFAULT_BASE_URL,
    adminToken: process.env.LOOM_ADMIN_TOKEN || "",
    bearerToken: process.env.LOOM_COMPLIANCE_AUDIT_BEARER_TOKEN || process.env.LOOM_FEDERATION_AUDIT_BEARER_TOKEN || "",
    bootstrapAuditToken: parseBoolean(process.env.LOOM_COMPLIANCE_BOOTSTRAP_AUDIT_TOKEN, false),
    timeoutMs: parsePositiveInt(process.env.LOOM_DRILL_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
    outputDir: process.env.LOOM_DRILL_OUTPUT_DIR || DEFAULT_OUTPUT_DIR,
    drillId: `compliance-${nowStamp()}`,
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
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
    if (arg === "--bootstrap-audit-token") {
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        args.bootstrapAuditToken = parseBoolean(next, true);
        i += 1;
      } else {
        args.bootstrapAuditToken = true;
      }
      continue;
    }
    if (arg === "--timeout-ms" && i + 1 < argv.length) {
      args.timeoutMs = parsePositiveInt(argv[i + 1], DEFAULT_TIMEOUT_MS);
      i += 1;
      continue;
    }
    if (arg === "--output-dir" && i + 1 < argv.length) {
      args.outputDir = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--drill-id" && i + 1 < argv.length) {
      args.drillId = argv[i + 1];
      i += 1;
      continue;
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage:
  node scripts/run_compliance_probe.js [options]

Options:
  --base-url <url>           API base URL (default: ${DEFAULT_BASE_URL})
  --admin-token <token>      Admin token (or LOOM_ADMIN_TOKEN env)
  --bearer-token <token>     Bearer token for /v1/audit probe (or LOOM_COMPLIANCE_AUDIT_BEARER_TOKEN env)
  --bootstrap-audit-token    Auto-create temporary local identity + bearer token when bearer token is omitted
  --timeout-ms <int>         HTTP timeout in ms (default: ${DEFAULT_TIMEOUT_MS})
  --output-dir <path>        Output directory (default: ${DEFAULT_OUTPUT_DIR})
  --drill-id <id>            Override drill ID
  -h, --help                 Show help

Example:
  npm run drill:compliance -- --base-url https://loom.example.com --admin-token <token> --bearer-token <token>
  npm run drill:compliance -- --base-url https://loom.example.com --admin-token <token> --bootstrap-audit-token
`);
}

function normalizeBaseUrl(raw) {
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

async function requestJson(baseUrl, path, options = {}) {
  const url = new URL(path, baseUrl).toString();
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: options.method || "GET",
      headers: options.headers || {},
      body: options.body ? JSON.stringify(options.body) : undefined,
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

function writeJson(path, value) {
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n");
}

function randomSuffix() {
  return Math.random().toString(36).slice(2, 10);
}

function sanitizeIdentityDomain(raw) {
  const trimmed = String(raw || "").trim().toLowerCase();
  if (!trimmed) {
    return null;
  }
  const withoutScheme = trimmed.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  const firstSegment = withoutScheme.split("/")[0];
  const userHost = firstSegment.includes("@") ? firstSegment.split("@").pop() : firstSegment;
  const hostOnly = String(userHost || "").split(":")[0].replace(/\.+$/, "");
  if (!hostOnly) {
    return null;
  }
  if (!/^[a-z0-9.-]+$/.test(hostOnly)) {
    return null;
  }
  if (hostOnly.startsWith(".") || hostOnly.endsWith(".") || hostOnly.includes("..")) {
    return null;
  }
  return hostOnly;
}

function uniqueIdentityDomains(candidates) {
  const seen = new Set();
  const output = [];
  for (const candidate of candidates) {
    const domain = sanitizeIdentityDomain(candidate);
    if (!domain || seen.has(domain)) {
      continue;
    }
    seen.add(domain);
    output.push(domain);
  }
  return output;
}

async function bootstrapAuditBearerToken(baseUrl, adminToken, timeoutMs) {
  const nodeDoc = await requestJson(baseUrl, "/.well-known/loom.json", {
    timeoutMs
  });
  if (nodeDoc.status !== 200 || !nodeDoc.json) {
    throw new Error(`Bootstrap failed: node document probe returned HTTP ${nodeDoc.status}.`);
  }

  const baseHost = new URL(baseUrl).hostname;
  const domains = uniqueIdentityDomains([nodeDoc.json.node_id, baseHost]);
  if (domains.length === 0) {
    throw new Error("Bootstrap failed: unable to derive a valid local identity domain.");
  }

  const keys = generateSigningKeyPair();
  const keyId = `k_sign_compliance_drill_${randomSuffix()}`;
  const localPart = `compliance-drill-${randomSuffix()}`;

  let registerResult = null;
  let identity = null;
  for (const domain of domains) {
    const candidateIdentity = `loom://${localPart}@${domain}`;
    const response = await requestJson(baseUrl, "/v1/identity", {
      method: "POST",
      timeoutMs,
      headers: {
        "content-type": "application/json",
        "x-loom-admin-token": adminToken
      },
      body: {
        id: candidateIdentity,
        display_name: "Compliance Drill Actor",
        signing_keys: [{ key_id: keyId, public_key_pem: keys.publicKeyPem }]
      }
    });
    registerResult = response;
    if (response.status === 201) {
      identity = candidateIdentity;
      break;
    }
  }

  if (!identity) {
    throw new Error(
      `Bootstrap failed: unable to register temporary identity (last status ${registerResult?.status ?? "unknown"}).`
    );
  }

  const challenge = await requestJson(baseUrl, "/v1/auth/challenge", {
    method: "POST",
    timeoutMs,
    headers: {
      "content-type": "application/json"
    },
    body: {
      identity,
      key_id: keyId
    }
  });
  if (challenge.status !== 200 || !challenge.json?.nonce || !challenge.json?.challenge_id) {
    throw new Error(`Bootstrap failed: auth challenge returned HTTP ${challenge.status}.`);
  }

  const token = await requestJson(baseUrl, "/v1/auth/token", {
    method: "POST",
    timeoutMs,
    headers: {
      "content-type": "application/json"
    },
    body: {
      identity,
      key_id: keyId,
      challenge_id: challenge.json.challenge_id,
      signature: signUtf8Message(keys.privateKeyPem, challenge.json.nonce)
    }
  });
  if (token.status !== 200 || typeof token.json?.access_token !== "string") {
    throw new Error(`Bootstrap failed: auth token exchange returned HTTP ${token.status}.`);
  }

  return {
    accessToken: token.json.access_token,
    identity,
    key_id: keyId,
    node_id: nodeDoc.json.node_id || null,
    bootstrap_steps: {
      node_document_status: nodeDoc.status,
      identity_register_status: registerResult?.status ?? null,
      auth_challenge_status: challenge.status,
      auth_token_status: token.status
    }
  };
}

function buildSummary(report, reportPath) {
  const lines = [];
  lines.push("# Compliance Runtime Drill Report");
  lines.push("");
  lines.push(`- Drill ID: \`${report.drill_id}\``);
  lines.push(`- Started: \`${report.started_at}\``);
  lines.push(`- Finished: \`${report.finished_at}\``);
  lines.push(`- Base URL: \`${report.base_url}\``);
  lines.push(`- Result: **${report.success ? "PASS" : "FAIL"}**`);
  lines.push(`- Bootstrap bearer token: \`${report.bootstrap?.used === true}\``);
  if (report.bootstrap?.used) {
    lines.push(`- Bootstrap identity: \`${report.bootstrap.identity}\``);
  }
  lines.push("");
  lines.push("## Probe Results");
  lines.push("");
  lines.push(`- Admin backup export: \`${report.assertions.admin_backup_export_ok}\``);
  lines.push(`- Admin status policy snapshot: \`${report.assertions.admin_status_policy_snapshot_ok}\``);
  lines.push(`- Actor audit feed: \`${report.assertions.actor_audit_feed_ok}\``);
  lines.push("");

  if (report.warnings.length > 0) {
    lines.push("## Warnings");
    lines.push("");
    for (const warning of report.warnings) {
      lines.push(`- ${warning}`);
    }
    lines.push("");
  }

  if (report.errors.length > 0) {
    lines.push("## Errors");
    lines.push("");
    for (const error of report.errors) {
      lines.push(`- ${error}`);
    }
    lines.push("");
  }

  lines.push("## Artifacts");
  lines.push("");
  lines.push(`- Drill report JSON: \`${reportPath}\``);
  lines.push("");
  return lines.join("\n") + "\n";
}

function summarizeBackupPayload(payload) {
  if (!payload || typeof payload !== "object") {
    return null;
  }
  return {
    backend: payload.backend ?? null,
    state_key: payload.state_key ?? null,
    schema_version: payload.schema_version ?? null,
    exported_at: payload.exported_at ?? null,
    audit_entries_count: Array.isArray(payload.audit_entries) ? payload.audit_entries.length : null
  };
}

function summarizeAdminStatus(payload) {
  if (!payload || typeof payload !== "object") {
    return null;
  }
  return {
    service: payload.service ?? null,
    timestamp: payload.timestamp ?? null,
    has_api_rate_limit_policy: payload.api_rate_limit_policy != null,
    has_identity_rate_limit_policy: payload.identity_rate_limit_policy != null,
    has_federation_inbound_policy: payload.federation_inbound_policy != null
  };
}

function summarizeAuditPayload(payload) {
  if (!payload || typeof payload !== "object") {
    return null;
  }
  const entries = Array.isArray(payload.entries) ? payload.entries : [];
  const first = entries[0] || null;
  return {
    entries_count: entries.length,
    first_entry: first
      ? {
          event_id: first.event_id ?? null,
          action: first.action ?? null,
          timestamp: first.timestamp ?? null
        }
      : null
  };
}

async function runDrill(args) {
  if (!String(args.adminToken || "").trim()) {
    throw new Error("Admin token is required (--admin-token or LOOM_ADMIN_TOKEN).");
  }

  const baseUrl = normalizeBaseUrl(args.baseUrl);
  const report = {
    drill_id: args.drillId,
    started_at: new Date().toISOString(),
    finished_at: null,
    base_url: baseUrl,
    success: false,
    assertions: {
      admin_backup_export_ok: false,
      admin_status_policy_snapshot_ok: false,
      actor_audit_feed_ok: false
    },
    bootstrap: {
      enabled: args.bootstrapAuditToken === true,
      used: false,
      identity: null,
      key_id: null,
      node_id: null,
      steps: null
    },
    warnings: [],
    errors: [],
    requests: {}
  };

  try {
    let bearerToken = String(args.bearerToken || "").trim();
    if (!bearerToken) {
      if (!args.bootstrapAuditToken) {
        throw new Error(
          "Bearer token is required (--bearer-token or LOOM_COMPLIANCE_AUDIT_BEARER_TOKEN / LOOM_FEDERATION_AUDIT_BEARER_TOKEN). " +
            "Alternatively set --bootstrap-audit-token."
        );
      }
      const bootstrap = await bootstrapAuditBearerToken(baseUrl, args.adminToken, args.timeoutMs);
      bearerToken = bootstrap.accessToken;
      report.bootstrap.used = true;
      report.bootstrap.identity = bootstrap.identity;
      report.bootstrap.key_id = bootstrap.key_id;
      report.bootstrap.node_id = bootstrap.node_id;
      report.bootstrap.steps = bootstrap.bootstrap_steps;
    }

    const backup = await requestJson(baseUrl, "/v1/admin/persistence/backup?include_audit=true&audit_limit=5", {
      timeoutMs: args.timeoutMs,
      headers: {
        "x-loom-admin-token": args.adminToken
      }
    });

    report.requests.admin_backup = {
      url: backup.url,
      status: backup.status,
      payload: summarizeBackupPayload(backup.json)
    };

    if (backup.status !== 200 || !backup.json) {
      report.errors.push(`Admin backup probe failed with HTTP ${backup.status}.`);
    } else {
      const hasAuditEntries = Array.isArray(backup.json.audit_entries);
      const hasExportedAt = typeof backup.json.exported_at === "string";
      const hasSchema = Object.prototype.hasOwnProperty.call(backup.json, "schema_version");
      if (!hasAuditEntries) {
        report.errors.push("Admin backup payload is missing audit_entries array.");
      }
      if (!hasExportedAt) {
        report.errors.push("Admin backup payload is missing exported_at.");
      }
      if (!hasSchema) {
        report.errors.push("Admin backup payload is missing schema_version.");
      }
      if (hasAuditEntries && hasExportedAt && hasSchema) {
        report.assertions.admin_backup_export_ok = true;
      }
      if (hasAuditEntries && backup.json.audit_entries.length === 0) {
        report.warnings.push("Admin backup returned empty audit_entries array.");
      }
    }

    const adminStatus = await requestJson(baseUrl, "/v1/admin/status", {
      timeoutMs: args.timeoutMs,
      headers: {
        "x-loom-admin-token": args.adminToken
      }
    });

    report.requests.admin_status = {
      url: adminStatus.url,
      status: adminStatus.status,
      payload: summarizeAdminStatus(adminStatus.json)
    };

    if (adminStatus.status !== 200 || !adminStatus.json) {
      report.errors.push(`Admin status probe failed with HTTP ${adminStatus.status}.`);
    } else {
      const hasApiRatePolicy = adminStatus.json.api_rate_limit_policy != null;
      const hasIdentityRatePolicy = adminStatus.json.identity_rate_limit_policy != null;
      const hasFederationPolicy = adminStatus.json.federation_inbound_policy != null;
      if (!hasApiRatePolicy) {
        report.errors.push("Admin status payload missing api_rate_limit_policy.");
      }
      if (!hasIdentityRatePolicy) {
        report.errors.push("Admin status payload missing identity_rate_limit_policy.");
      }
      if (!hasFederationPolicy) {
        report.errors.push("Admin status payload missing federation_inbound_policy.");
      }
      if (hasApiRatePolicy && hasIdentityRatePolicy && hasFederationPolicy) {
        report.assertions.admin_status_policy_snapshot_ok = true;
      }
    }

    const auditFeed = await requestJson(baseUrl, "/v1/audit?limit=10", {
      timeoutMs: args.timeoutMs,
      headers: {
        authorization: `Bearer ${bearerToken}`
      }
    });

    report.requests.actor_audit = {
      url: auditFeed.url,
      status: auditFeed.status,
      payload: summarizeAuditPayload(auditFeed.json)
    };

    if (auditFeed.status !== 200 || !auditFeed.json) {
      report.errors.push(`Actor audit probe failed with HTTP ${auditFeed.status}.`);
    } else if (!Array.isArray(auditFeed.json.entries)) {
      report.errors.push("Actor audit payload missing entries array.");
    } else {
      const entries = auditFeed.json.entries;
      let auditEntryShapeOk = true;
      if (entries.length === 0) {
        report.warnings.push("Actor audit feed returned zero entries.");
      } else {
        const first = entries[0];
        if (!first?.event_id || !first?.action || !first?.timestamp) {
          report.errors.push("Actor audit entries missing event_id/action/timestamp fields.");
          auditEntryShapeOk = false;
        }
      }
      if (auditEntryShapeOk) {
        report.assertions.actor_audit_feed_ok = true;
      }
    }

    report.success = report.errors.length === 0;
  } catch (error) {
    report.errors.push(error?.message || String(error));
    report.success = false;
  } finally {
    report.finished_at = new Date().toISOString();
  }

  return report;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const drillOutputDir = join(resolve(args.outputDir), args.drillId);
  mkdirSync(drillOutputDir, { recursive: true });

  const reportPath = join(drillOutputDir, "report.json");
  const summaryPath = join(drillOutputDir, "summary.md");

  const report = await runDrill(args);
  writeJson(reportPath, report);
  writeFileSync(summaryPath, buildSummary(report, reportPath), "utf-8");

  console.log(`Compliance runtime drill report: ${reportPath}`);
  console.log(`Compliance runtime drill summary: ${summaryPath}`);
  console.log(`Compliance runtime drill result: ${report.success ? "PASS" : "FAIL"}`);

  if (!report.success) {
    for (const error of report.errors) {
      console.error(`ERROR: ${error}`);
    }
    process.exit(1);
  }
}

main();
