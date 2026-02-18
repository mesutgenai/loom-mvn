#!/usr/bin/env node

import { spawnSync } from "node:child_process";

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

function parseArgs(argv) {
  const args = {
    envFile: null,
    baseUrl: process.env.LOOM_BASE_URL || null,
    adminToken: process.env.LOOM_ADMIN_TOKEN || null,
    bearerToken: process.env.LOOM_COMPLIANCE_AUDIT_BEARER_TOKEN || process.env.LOOM_FEDERATION_AUDIT_BEARER_TOKEN || null,
    bootstrapAuditToken: parseBoolean(process.env.LOOM_COMPLIANCE_BOOTSTRAP_AUDIT_TOKEN, false),
    timeoutMs: parsePositiveInt(process.env.LOOM_DRILL_TIMEOUT_MS, 15000),
    outputDir: process.env.LOOM_DRILL_OUTPUT_DIR || null,
    drillId: null,
    maxAgeDays: null,
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
      args.timeoutMs = parsePositiveInt(argv[i + 1], 15000);
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
    if (arg === "--max-age-days" && i + 1 < argv.length) {
      args.maxAgeDays = parsePositiveInt(argv[i + 1], 180);
      i += 1;
      continue;
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage:
  node scripts/run_compliance_gate.js [options]

Runs:
  1) scripts/check_compliance_controls.js
  2) scripts/run_compliance_probe.js

Options:
  --env-file <path>           Optional env file for check step
  --base-url <url>            API base URL for runtime probes
  --admin-token <token>       Admin token for runtime probes
  --bearer-token <token>      Bearer token for /v1/audit runtime probe
  --bootstrap-audit-token     Auto-bootstrap temporary audit bearer token for drill when bearer token is omitted
  --timeout-ms <int>          HTTP timeout in ms for runtime probes (default: 15000)
  --output-dir <path>         Drill artifact output directory override
  --drill-id <id>             Drill ID override
  --max-age-days <int>        Compliance checklist age warning threshold for check step
  -h, --help                  Show help

Examples:
  npm run gate:compliance -- --base-url https://loom.example.com --admin-token <token> --bootstrap-audit-token
  npm run gate:compliance -- --env-file .env.production --base-url https://loom.example.com --admin-token <token> --bearer-token <token>
`);
}

function runStep(label, args) {
  console.log(`\n[compliance-gate] ${label}`);
  const child = spawnSync(process.execPath, args, {
    stdio: "inherit",
    env: process.env
  });
  if (child.error) {
    throw child.error;
  }
  if (child.status !== 0) {
    throw new Error(`${label} failed with exit code ${child.status}`);
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  if (!String(args.baseUrl || "").trim()) {
    console.error("ERROR: --base-url is required for compliance gate runtime drill.");
    process.exit(1);
  }

  if (!String(args.adminToken || "").trim()) {
    console.error("ERROR: --admin-token is required for compliance gate runtime drill.");
    process.exit(1);
  }

  const checkArgs = ["scripts/check_compliance_controls.js"];
  if (args.envFile) {
    checkArgs.push("--env-file", args.envFile);
  }
  if (args.baseUrl) {
    checkArgs.push("--base-url", args.baseUrl);
  }
  if (args.adminToken) {
    checkArgs.push("--admin-token", args.adminToken);
  }
  if (args.timeoutMs) {
    checkArgs.push("--timeout-ms", String(args.timeoutMs));
  }
  if (args.maxAgeDays) {
    checkArgs.push("--max-age-days", String(args.maxAgeDays));
  }
  if (args.bearerToken) {
    checkArgs.push("--bearer-token", args.bearerToken);
  }

  const drillArgs = ["scripts/run_compliance_probe.js"];
  drillArgs.push("--base-url", args.baseUrl);
  drillArgs.push("--admin-token", args.adminToken);
  drillArgs.push("--timeout-ms", String(args.timeoutMs));
  if (args.outputDir) {
    drillArgs.push("--output-dir", args.outputDir);
  }
  if (args.drillId) {
    drillArgs.push("--drill-id", args.drillId);
  }
  if (args.bearerToken) {
    drillArgs.push("--bearer-token", args.bearerToken);
  } else if (args.bootstrapAuditToken) {
    drillArgs.push("--bootstrap-audit-token");
  } else {
    console.error(
      "ERROR: Provide --bearer-token or enable --bootstrap-audit-token (or LOOM_COMPLIANCE_BOOTSTRAP_AUDIT_TOKEN=true)."
    );
    process.exit(1);
  }

  try {
    runStep("Compliance static/runtime checks", checkArgs);
    runStep("Compliance runtime drill", drillArgs);
    console.log("\n[compliance-gate] PASS");
  } catch (error) {
    console.error(`\n[compliance-gate] FAIL: ${error?.message || String(error)}`);
    process.exit(1);
  }
}

main();
