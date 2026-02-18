#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const REQUIRED_FILES = [
  "docs/REQUEST-TRACING.md",
  "src/node/server.js",
  "src/node/store.js",
  "src/index.js"
];

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
    timeoutMs: 10000,
    help: false
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
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
    if (arg === "--timeout-ms" && i + 1 < argv.length) {
      const parsed = Number(argv[i + 1]);
      if (Number.isInteger(parsed) && parsed > 0) {
        args.timeoutMs = parsed;
      }
      i += 1;
      continue;
    }
  }
  return args;
}

function printHelp() {
  console.log(`Usage:
  node scripts/check_request_tracing.js [options]

Options:
  --env-file <path>      Optional env file to validate request-log flags
  --base-url <url>       Optional runtime URL to probe x-loom-request-id behavior
  --timeout-ms <int>     Runtime probe timeout in ms (default: 10000)
  -h, --help             Show help
`);
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: options.method || "GET",
      headers: options.headers || {},
      signal: controller.signal
    });
    return response;
  } finally {
    clearTimeout(timer);
  }
}

async function runRuntimeProbe(baseUrl, timeoutMs, checks, errors) {
  let healthUrl;
  try {
    healthUrl = new URL("/health", baseUrl).toString();
  } catch (error) {
    errors.push(`Invalid --base-url value: ${baseUrl} (${error.message})`);
    return;
  }

  try {
    const providedId = "trace-check-client-id";
    const withProvided = await fetchWithTimeout(
      healthUrl,
      {
        headers: {
          "x-request-id": providedId
        }
      },
      timeoutMs
    );
    const echoed = withProvided.headers.get("x-loom-request-id");
    if (withProvided.status !== 200) {
      errors.push(`/health probe failed with HTTP ${withProvided.status}`);
    } else if (echoed !== providedId) {
      errors.push(`x-loom-request-id did not echo supplied x-request-id (got: ${echoed || "null"})`);
    } else {
      checks.push("Runtime probe echoes incoming x-request-id via x-loom-request-id");
    }

    const generated = await fetchWithTimeout(healthUrl, {}, timeoutMs);
    const generatedId = generated.headers.get("x-loom-request-id") || "";
    if (generated.status !== 200) {
      errors.push(`/health generated-id probe failed with HTTP ${generated.status}`);
    } else if (!/^req_[a-f0-9-]+$/i.test(generatedId)) {
      errors.push(`x-loom-request-id generated format unexpected: ${generatedId || "null"}`);
    } else {
      checks.push("Runtime probe confirms generated x-loom-request-id format");
    }
  } catch (error) {
    errors.push(`Runtime tracing probe failed: ${error.message}`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const checks = [];
  const warnings = [];
  const errors = [];

  for (const relPath of REQUIRED_FILES) {
    const full = resolve(relPath);
    if (!existsSync(full)) {
      errors.push(`Required tracing artifact missing: ${relPath}`);
    } else {
      checks.push(`Tracing artifact present: ${relPath}`);
    }
  }

  if (existsSync(resolve("src/node/server.js"))) {
    const source = readFileSync(resolve("src/node/server.js"), "utf-8");
    if (!source.includes("x-loom-request-id")) {
      errors.push("src/node/server.js is missing x-loom-request-id response header support.");
    } else {
      checks.push("Server sets x-loom-request-id header");
    }
    if (!source.includes("request_id: reqId")) {
      warnings.push("Server request logs do not include `request_id` field.");
    } else {
      checks.push("Server request logs include request_id field");
    }
  }

  if (existsSync(resolve("src/node/store.js"))) {
    const source = readFileSync(resolve("src/node/store.js"), "utf-8");
    if (!source.includes("runWithTraceContext")) {
      errors.push("src/node/store.js is missing runWithTraceContext support.");
    } else {
      checks.push("Store exposes runWithTraceContext");
    }
    if (!source.includes("source_request_id")) {
      errors.push("src/node/store.js is missing source_request_id propagation.");
    } else {
      checks.push("Store propagates source_request_id for outbox flows");
    }
  }

  if (existsSync(resolve("src/index.js"))) {
    const source = readFileSync(resolve("src/index.js"), "utf-8");
    if (!source.includes("worker.batch.processed")) {
      warnings.push("Worker batch structured log marker not found in src/index.js.");
    } else {
      checks.push("Worker batch logs include structured tracing marker");
    }
  }

  if (args.envFile) {
    const envPath = resolve(args.envFile);
    if (!existsSync(envPath)) {
      errors.push(`Env file not found: ${envPath}`);
    } else {
      const env = parseEnvFile(envPath);
      if (String(env.LOOM_REQUEST_LOG_ENABLED || "").trim().toLowerCase() !== "true") {
        warnings.push("LOOM_REQUEST_LOG_ENABLED is not true in provided env file.");
      } else {
        checks.push("LOOM_REQUEST_LOG_ENABLED=true in provided env file");
      }
      const format = String(env.LOOM_REQUEST_LOG_FORMAT || "").trim().toLowerCase();
      if (format && format !== "json" && format !== "text") {
        errors.push("LOOM_REQUEST_LOG_FORMAT must be json or text.");
      } else if (format === "json") {
        checks.push("LOOM_REQUEST_LOG_FORMAT=json in provided env file");
      } else if (!format) {
        warnings.push("LOOM_REQUEST_LOG_FORMAT not set (defaults to json).");
      } else {
        warnings.push("LOOM_REQUEST_LOG_FORMAT=text set; json is preferred for structured tracing.");
      }
    }
  }

  if (args.baseUrl) {
    await runRuntimeProbe(args.baseUrl, args.timeoutMs, checks, errors);
  }

  console.log("\nRequest tracing summary:");
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

  console.log("\nPASSED: request tracing checks succeeded.");
}

main();
