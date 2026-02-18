#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const DEFAULT_ALERT_RULES_PATH = "ops/alerts/loom-alert-rules.yaml";

const REQUIRED_ALERTS = [
  "LoomReadyProbeFailing",
  "LoomAdminStatusProbeFailing",
  "LoomFederationOutboxLagHigh",
  "LoomEmailOutboxLagHigh",
  "LoomWebhookOutboxLagHigh",
  "LoomAuthErrorSpike",
  "LoomPersistenceFailures"
];

const REQUIRED_METRICS = [
  "loom_requests_total",
  "loom_errors_total",
  "loom_federation_outbox_lag_ms",
  "loom_email_outbox_lag_ms",
  "loom_webhook_outbox_lag_ms",
  "loom_persistence_writes_failed",
  "loom_persistence_last_error"
];

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

function parseEnvFile(filePath) {
  const parsed = {};
  const source = readFileSync(filePath, "utf-8");
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
    envFile: null,
    baseUrl: null,
    adminToken: null,
    timeoutMs: 10000,
    alertRulesPath: DEFAULT_ALERT_RULES_PATH
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
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
    if (arg === "--timeout-ms" && i + 1 < argv.length) {
      args.timeoutMs = parsePositiveInt(argv[i + 1], 10000);
      i += 1;
      continue;
    }
    if (arg === "--alert-rules" && i + 1 < argv.length) {
      args.alertRulesPath = argv[i + 1];
      i += 1;
      continue;
    }
  }
  return args;
}

async function fetchWithTimeout(url, options = {}) {
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

function checkAlertRulesFile(alertRulesPath, checks, warnings, errors) {
  if (!existsSync(alertRulesPath)) {
    errors.push(`Alert rule file not found: ${alertRulesPath}`);
    return;
  }
  checks.push(`Alert rule file present: ${alertRulesPath}`);
  const source = readFileSync(alertRulesPath, "utf-8");

  for (const alertName of REQUIRED_ALERTS) {
    const pattern = new RegExp(`alert:\\s*${alertName}\\b`);
    if (!pattern.test(source)) {
      errors.push(`Alert rule missing: ${alertName}`);
    } else {
      checks.push(`Alert rule present: ${alertName}`);
    }
  }

  if (!/probe_success\{job="loom-ready"\}/.test(source)) {
    warnings.push("Alert rules do not reference blackbox job `loom-ready`.");
  }
  if (!/probe_success\{job="loom-admin-status"\}/.test(source)) {
    warnings.push("Alert rules do not reference blackbox job `loom-admin-status`.");
  }
}

async function runRuntimeChecks(baseUrl, adminToken, timeoutMs, metricsPublic, checks, warnings, errors) {
  const readyUrl = new URL("/ready", baseUrl).toString();
  const metricsUrl = new URL("/metrics", baseUrl).toString();
  const adminStatusUrl = new URL("/v1/admin/status", baseUrl).toString();

  const ready = await fetchWithTimeout(readyUrl, { timeoutMs });
  if (ready.response.status !== 200 && ready.response.status !== 503) {
    errors.push(`/ready returned unexpected HTTP ${ready.response.status}`);
  } else {
    checks.push(`/ready reachable (HTTP ${ready.response.status})`);
  }
  if (!ready.json || ready.json?.checks?.http !== "ok") {
    errors.push("/ready did not return expected JSON checks payload.");
  } else {
    checks.push("/ready payload includes checks.http=ok");
  }

  const metricsHeaders = {};
  if (!metricsPublic) {
    if (!adminToken) {
      errors.push("Runtime metrics scrape requires admin token when LOOM_METRICS_PUBLIC=false.");
    } else {
      metricsHeaders["x-loom-admin-token"] = adminToken;
    }
  }
  const metrics = await fetchWithTimeout(metricsUrl, {
    timeoutMs,
    headers: metricsHeaders
  });
  if (!metrics.response.ok) {
    errors.push(`/metrics scrape failed with HTTP ${metrics.response.status}`);
  } else {
    checks.push("/metrics scrape succeeded");
    for (const metricName of REQUIRED_METRICS) {
      if (!metrics.text.includes(metricName)) {
        errors.push(`/metrics missing required series: ${metricName}`);
      } else {
        checks.push(`/metrics contains ${metricName}`);
      }
    }
  }

  if (!adminToken) {
    warnings.push("Runtime admin status check skipped (no admin token provided).");
    return;
  }
  const adminStatus = await fetchWithTimeout(adminStatusUrl, {
    timeoutMs,
    headers: {
      "x-loom-admin-token": adminToken
    }
  });
  if (!adminStatus.response.ok || !adminStatus.json) {
    errors.push(`/v1/admin/status check failed with HTTP ${adminStatus.response.status}`);
    return;
  }
  checks.push("/v1/admin/status scrape succeeded");
  if (typeof adminStatus.json?.metrics?.requests_total !== "number") {
    errors.push("/v1/admin/status is missing metrics.requests_total.");
  } else {
    checks.push("/v1/admin/status includes metrics snapshot");
  }
  if (typeof adminStatus.json?.outbox?.federation?.lag_ms !== "number") {
    errors.push("/v1/admin/status is missing outbox lag fields.");
  } else {
    checks.push("/v1/admin/status includes outbox lag fields");
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const env = { ...process.env };
  if (args.envFile) {
    const envFilePath = resolve(args.envFile);
    if (!existsSync(envFilePath)) {
      console.error(`ERROR: env file not found: ${envFilePath}`);
      process.exit(1);
    }
    Object.assign(env, parseEnvFile(envFilePath));
    console.log(`Loaded env file: ${envFilePath}`);
  }

  const checks = [];
  const warnings = [];
  const errors = [];

  const publicService = parseBoolean(env.LOOM_PUBLIC_SERVICE, false);
  const metricsPublic = parseBoolean(env.LOOM_METRICS_PUBLIC, false);
  const configuredAdminToken = String(env.LOOM_ADMIN_TOKEN || "").trim();

  if (!publicService) {
    warnings.push("LOOM_PUBLIC_SERVICE is false; observability alerting gate is primarily for public deployments.");
  } else {
    checks.push("LOOM_PUBLIC_SERVICE=true");
  }

  if (metricsPublic) {
    warnings.push("LOOM_METRICS_PUBLIC=true; prefer authenticated metrics scraping in production.");
  } else {
    checks.push("LOOM_METRICS_PUBLIC=false (authenticated scrape mode)");
    if (!configuredAdminToken && !args.adminToken) {
      errors.push("LOOM_ADMIN_TOKEN (or --admin-token) is required to scrape authenticated metrics.");
    } else {
      checks.push("Admin token available for authenticated scrape");
    }
  }

  const alertRulesPath = resolve(args.alertRulesPath);
  checkAlertRulesFile(alertRulesPath, checks, warnings, errors);

  const baseUrl = args.baseUrl || env.LOOM_BASE_URL || null;
  const runtimeAdminToken = args.adminToken || configuredAdminToken || null;
  if (!baseUrl) {
    warnings.push("Runtime endpoint checks skipped (no --base-url/LOOM_BASE_URL provided).");
  } else {
    try {
      await runRuntimeChecks(baseUrl, runtimeAdminToken, args.timeoutMs, metricsPublic, checks, warnings, errors);
    } catch (error) {
      errors.push(`Runtime endpoint checks failed: ${error?.message || String(error)}`);
    }
  }

  console.log("\nObservability and alerting summary:");
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
  console.log("\nPASSED: observability and alerting checks succeeded.");
}

main();
