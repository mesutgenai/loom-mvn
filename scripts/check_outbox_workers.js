#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const DEFAULT_MAX_LAG_MS = 60000;

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

function parsePositiveIntStrict(value) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
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
    maxLagMs: DEFAULT_MAX_LAG_MS
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
    if (arg === "--max-lag-ms" && i + 1 < argv.length) {
      args.maxLagMs = parsePositiveInt(argv[i + 1], DEFAULT_MAX_LAG_MS);
      i += 1;
      continue;
    }
  }
  return args;
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

function normalizeWorker(value) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : 0;
}

function readPositiveIntEnv(env, key, fallback, errors) {
  const raw = String(env[key] || "").trim();
  if (!raw) {
    return fallback;
  }
  const parsed = parsePositiveIntStrict(raw);
  if (parsed == null) {
    errors.push(`${key} must be a positive integer.`);
    return fallback;
  }
  return parsed;
}

function validateRuntimeWorker(name, runtimeWorker, expectedInterval, expectedBatch, errors, warnings, checks) {
  if (!runtimeWorker || typeof runtimeWorker !== "object") {
    errors.push(`Runtime status missing ${name} worker block.`);
    return;
  }

  if (!runtimeWorker.enabled) {
    errors.push(`${name} worker is not enabled at runtime.`);
  } else {
    checks.push(`${name} worker enabled at runtime`);
  }

  const interval = normalizeWorker(runtimeWorker.interval_ms);
  const batch = normalizeWorker(runtimeWorker.batch_size);
  if (interval !== expectedInterval) {
    warnings.push(`${name} worker interval runtime=${interval} differs from expected=${expectedInterval}.`);
  } else {
    checks.push(`${name} worker interval matches expected (${expectedInterval}ms)`);
  }
  if (batch !== expectedBatch) {
    warnings.push(`${name} worker batch runtime=${batch} differs from expected=${expectedBatch}.`);
  } else {
    checks.push(`${name} worker batch size matches expected (${expectedBatch})`);
  }

  if (runtimeWorker.last_error) {
    errors.push(`${name} worker last_error is set: ${runtimeWorker.last_error}`);
  }
}

function validateOutboxLag(name, outboxStats, maxLagMs, errors, checks) {
  const lagMs = Number(outboxStats?.lag_ms || 0);
  if (!Number.isFinite(lagMs) || lagMs < 0) {
    errors.push(`${name} outbox lag_ms is invalid.`);
    return;
  }
  if (lagMs > maxLagMs) {
    errors.push(`${name} outbox lag_ms=${lagMs} exceeds max-lag-ms=${maxLagMs}.`);
  } else {
    checks.push(`${name} outbox lag within threshold (${lagMs}ms <= ${maxLagMs}ms)`);
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
  const pgUrl = String(env.LOOM_PG_URL || "").trim();
  const outboxWorkerId = String(env.LOOM_OUTBOX_WORKER_ID || "").trim();
  const claimLeaseMs = readPositiveIntEnv(env, "LOOM_OUTBOX_CLAIM_LEASE_MS", 60000, errors);
  const workers = [
    {
      name: "federation",
      intervalMs: readPositiveIntEnv(env, "LOOM_OUTBOX_AUTO_PROCESS_INTERVAL_MS", 5000, errors),
      batchSize: readPositiveIntEnv(env, "LOOM_OUTBOX_AUTO_PROCESS_BATCH_SIZE", 20, errors),
      runtimePath: "federation_outbox_worker"
    },
    {
      name: "email",
      intervalMs: readPositiveIntEnv(env, "LOOM_EMAIL_OUTBOX_AUTO_PROCESS_INTERVAL_MS", 5000, errors),
      batchSize: readPositiveIntEnv(env, "LOOM_EMAIL_OUTBOX_AUTO_PROCESS_BATCH_SIZE", 20, errors),
      runtimePath: "email_outbox_worker"
    },
    {
      name: "webhook",
      intervalMs: readPositiveIntEnv(env, "LOOM_WEBHOOK_OUTBOX_AUTO_PROCESS_INTERVAL_MS", 5000, errors),
      batchSize: readPositiveIntEnv(env, "LOOM_WEBHOOK_OUTBOX_AUTO_PROCESS_BATCH_SIZE", 20, errors),
      runtimePath: "webhook_outbox_worker"
    }
  ];

  if (!publicService) {
    warnings.push("LOOM_PUBLIC_SERVICE is false; worker reliability gate is primarily for public deployments.");
  } else {
    checks.push("LOOM_PUBLIC_SERVICE=true");
  }

  for (const worker of workers) {
    if (worker.intervalMs <= 0) {
      errors.push(`${worker.name} worker interval must be > 0 to keep continuous processing.`);
    } else {
      checks.push(`${worker.name} worker interval configured (${worker.intervalMs}ms)`);
    }
    if (worker.batchSize <= 0) {
      errors.push(`${worker.name} worker batch size must be > 0.`);
    } else {
      checks.push(`${worker.name} worker batch size configured (${worker.batchSize})`);
    }
  }

  if (pgUrl) {
    if (!outboxWorkerId) {
      errors.push("LOOM_OUTBOX_WORKER_ID must be set when PostgreSQL persistence is enabled.");
    } else {
      checks.push("LOOM_OUTBOX_WORKER_ID is set for distributed worker coordination");
    }
  }

  const maxWorkerInterval = Math.max(...workers.map((worker) => worker.intervalMs));
  if (claimLeaseMs < maxWorkerInterval) {
    warnings.push(
      `LOOM_OUTBOX_CLAIM_LEASE_MS (${claimLeaseMs}) is below max worker interval (${maxWorkerInterval}); claims may expire too aggressively.`
    );
  } else {
    checks.push(`LOOM_OUTBOX_CLAIM_LEASE_MS is aligned with worker intervals (${claimLeaseMs}ms)`);
  }

  const baseUrl = args.baseUrl || env.LOOM_BASE_URL || null;
  const adminToken = args.adminToken || env.LOOM_ADMIN_TOKEN || null;
  if (baseUrl || adminToken) {
    if (!baseUrl || !adminToken) {
      warnings.push("Runtime worker check skipped (both --base-url and --admin-token are required).");
    } else {
      try {
        const url = new URL("/v1/admin/status", baseUrl).toString();
        const { response, json } = await fetchJson(url, {
          timeoutMs: args.timeoutMs,
          headers: {
            "x-loom-admin-token": adminToken
          }
        });
        if (!response.ok || !json) {
          errors.push(`Runtime worker check failed: HTTP ${response.status}`);
        } else {
          checks.push("Runtime worker snapshot fetched from /v1/admin/status");
          for (const worker of workers) {
            validateRuntimeWorker(
              worker.name,
              json?.runtime?.[worker.runtimePath],
              worker.intervalMs,
              worker.batchSize,
              errors,
              warnings,
              checks
            );
          }
          validateOutboxLag("federation", json?.outbox?.federation, args.maxLagMs, errors, checks);
          validateOutboxLag("email", json?.outbox?.email, args.maxLagMs, errors, checks);
          validateOutboxLag("webhook", json?.outbox?.webhook, args.maxLagMs, errors, checks);
        }
      } catch (error) {
        errors.push(`Runtime worker check error: ${error?.message || String(error)}`);
      }
    }
  } else {
    warnings.push("Runtime worker check skipped (no --base-url/--admin-token provided).");
  }

  console.log("\nOutbox worker reliability summary:");
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
  console.log("\nPASSED: outbox worker reliability checks succeeded.");
}

main();
