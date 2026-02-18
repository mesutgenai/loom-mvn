#!/usr/bin/env node

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";

const DEFAULT_TARGETS_FILE = "ops/federation/interop-targets.json";
const DEFAULT_MATRIX_OUTPUT_DIR = "scripts/output/federation-interop-matrix";
const DEFAULT_DRILL_OUTPUT_DIR = "scripts/output/federation-interop-drills";
const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_REQUIRED_TARGETS = ["staging", "preprod"];
const DEFAULT_REMOTE_NODE_ID = "interop-remote.test";
const DEFAULT_REMOTE_NODE_KEY_ID = "k_node_sign_interop_remote_1";

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

function normalizeName(value, fallback) {
  const trimmed = String(value || fallback).trim();
  if (!trimmed) {
    return fallback;
  }
  return trimmed;
}

function sanitizeName(value) {
  return normalizeName(value, "target")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

function parseArgs(argv) {
  const args = {
    targetsFile: process.env.LOOM_INTEROP_TARGETS_FILE || DEFAULT_TARGETS_FILE,
    outputDir: process.env.LOOM_INTEROP_MATRIX_OUTPUT_DIR || DEFAULT_MATRIX_OUTPUT_DIR,
    drillOutputDir: process.env.LOOM_INTEROP_OUTPUT_DIR || DEFAULT_DRILL_OUTPUT_DIR,
    remoteNodeId: process.env.LOOM_INTEROP_REMOTE_NODE_ID || DEFAULT_REMOTE_NODE_ID,
    remoteNodeKeyId: process.env.LOOM_INTEROP_REMOTE_NODE_KEY_ID || DEFAULT_REMOTE_NODE_KEY_ID,
    adminToken: process.env.LOOM_ADMIN_TOKEN || "",
    timeoutMs: parsePositiveInt(process.env.LOOM_INTEROP_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
    stopOnFail: false,
    requiredTargets: parseList(process.env.LOOM_INTEROP_REQUIRED_TARGETS, DEFAULT_REQUIRED_TARGETS),
    matrixId: `interop-matrix-${nowStamp()}`,
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }
    if (arg === "--targets-file" && i + 1 < argv.length) {
      args.targetsFile = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--output-dir" && i + 1 < argv.length) {
      args.outputDir = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--drill-output-dir" && i + 1 < argv.length) {
      args.drillOutputDir = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--remote-node-id" && i + 1 < argv.length) {
      args.remoteNodeId = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--remote-node-key-id" && i + 1 < argv.length) {
      args.remoteNodeKeyId = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--admin-token" && i + 1 < argv.length) {
      args.adminToken = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--timeout-ms" && i + 1 < argv.length) {
      args.timeoutMs = parsePositiveInt(argv[i + 1], DEFAULT_TIMEOUT_MS);
      i += 1;
      continue;
    }
    if (arg === "--required-targets" && i + 1 < argv.length) {
      args.requiredTargets = parseList(argv[i + 1], DEFAULT_REQUIRED_TARGETS);
      i += 1;
      continue;
    }
    if (arg === "--matrix-id" && i + 1 < argv.length) {
      args.matrixId = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--stop-on-fail") {
      args.stopOnFail = true;
      continue;
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage:
  node scripts/run_federation_interop_matrix.js [options]

Options:
  --targets-file <path>       Path to JSON config (default: ${DEFAULT_TARGETS_FILE})
  --output-dir <path>         Matrix report output dir (default: ${DEFAULT_MATRIX_OUTPUT_DIR})
  --drill-output-dir <path>   Per-target drill output dir (default: ${DEFAULT_DRILL_OUTPUT_DIR})
  --remote-node-id <id>       Default remote node ID when target does not override
  --remote-node-key-id <id>   Default remote node key ID when target does not override
  --admin-token <token>       Fallback admin token when target does not define token/env
  --timeout-ms <int>          Per-target drill timeout (default: ${DEFAULT_TIMEOUT_MS})
  --required-targets <csv>    Required environment names (default: staging,preprod)
  --matrix-id <id>            Override matrix run ID
  --stop-on-fail              Abort remaining targets on first failure
  -h, --help                  Show help

Config shape:
  {
    "targets": [
      {
        "name": "staging",
        "base_url": "https://loom-staging.example.com",
        "admin_token_env": "LOOM_ADMIN_TOKEN_STAGING",
        "remote_node_id": "interop-peer.example"
      }
    ]
  }
`);
}

function parseTargetsFile(filePath) {
  const resolved = resolve(filePath);
  if (!existsSync(resolved)) {
    throw new Error(`Targets file not found: ${resolved}`);
  }
  const raw = readFileSync(resolved, "utf-8");
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Targets file is not valid JSON: ${resolved} (${error.message})`);
  }
  const targets = Array.isArray(parsed) ? parsed : parsed?.targets;
  if (!Array.isArray(targets) || targets.length === 0) {
    throw new Error(`Targets file must contain a non-empty targets array: ${resolved}`);
  }
  return targets;
}

function normalizeTarget(entry, index, args) {
  if (!entry || typeof entry !== "object") {
    throw new Error(`Target entry ${index + 1} is not an object.`);
  }

  const name = normalizeName(entry.name || entry.environment || `target-${index + 1}`, `target-${index + 1}`);
  const baseUrl = String(entry.base_url ?? entry.baseUrl ?? "").trim();
  if (!baseUrl) {
    throw new Error(`Target ${name} is missing base_url.`);
  }

  const adminTokenEnv = String(entry.admin_token_env ?? entry.adminTokenEnv ?? "").trim();
  const adminTokenInline = String(entry.admin_token ?? entry.adminToken ?? "").trim();
  const resolvedAdminToken = adminTokenInline || (adminTokenEnv ? String(process.env[adminTokenEnv] || "").trim() : "") || args.adminToken;
  if (!resolvedAdminToken) {
    throw new Error(
      `Target ${name} does not resolve an admin token. Set admin_token_env/admin_token in target or pass --admin-token.`
    );
  }

  return {
    name,
    baseUrl,
    adminToken: resolvedAdminToken,
    adminTokenEnv: adminTokenEnv || null,
    remoteNodeId: String(entry.remote_node_id ?? entry.remoteNodeId ?? args.remoteNodeId).trim(),
    remoteNodeKeyId: String(entry.remote_node_key_id ?? entry.remoteNodeKeyId ?? args.remoteNodeKeyId).trim(),
    notes: String(entry.notes || "").trim() || null
  };
}

function buildSummary(report, reportPath) {
  const lines = [];
  lines.push("# Federation Interop Matrix Report");
  lines.push("");
  lines.push(`- Matrix ID: \`${report.matrix_id}\``);
  lines.push(`- Started: \`${report.started_at}\``);
  lines.push(`- Finished: \`${report.finished_at}\``);
  lines.push(`- Result: **${report.success ? "PASS" : "FAIL"}**`);
  lines.push("");
  lines.push("## Target Runs");
  lines.push("");
  for (const target of report.targets) {
    lines.push(
      `- ${target.name}: **${target.success ? "PASS" : "FAIL"}** (${target.base_url}) drill=\`${target.drill_id}\``
    );
    if (target.failure) {
      lines.push(`  - failure: \`${target.failure}\``);
    }
  }
  lines.push("");
  lines.push(`- Report JSON: \`${reportPath}\``);
  return lines.join("\n") + "\n";
}

function runTargetDrill(target, args) {
  const drillId = `${sanitizeName(target.name)}-${nowStamp()}`;
  const drillScriptPath = resolve("scripts/run_federation_interop_drill.js");
  const drillOutputDir = resolve(args.drillOutputDir);
  mkdirSync(drillOutputDir, { recursive: true });

  const runArgs = [
    drillScriptPath,
    "--base-url",
    target.baseUrl,
    "--admin-token",
    target.adminToken,
    "--remote-node-id",
    target.remoteNodeId,
    "--remote-node-key-id",
    target.remoteNodeKeyId,
    "--timeout-ms",
    String(args.timeoutMs),
    "--output-dir",
    drillOutputDir,
    "--drill-id",
    drillId
  ];

  const startedAt = new Date().toISOString();
  const child = spawnSync(process.execPath, runArgs, {
    encoding: "utf-8",
    env: process.env
  });
  const finishedAt = new Date().toISOString();
  const reportPath = join(drillOutputDir, drillId, "report.json");
  const summaryPath = join(drillOutputDir, drillId, "summary.md");

  let reportJson = null;
  if (existsSync(reportPath)) {
    try {
      reportJson = JSON.parse(readFileSync(reportPath, "utf-8"));
    } catch {
      reportJson = null;
    }
  }

  const success = child.status === 0 && reportJson?.success === true;
  return {
    name: target.name,
    base_url: target.baseUrl,
    remote_node_id: target.remoteNodeId,
    remote_node_key_id: target.remoteNodeKeyId,
    drill_id: drillId,
    report_path: reportPath,
    summary_path: summaryPath,
    success,
    started_at: startedAt,
    finished_at: finishedAt,
    failure: success ? null : reportJson?.failure || child.stderr?.trim() || child.stdout?.trim() || "unknown failure",
    assertions: reportJson?.assertions || null,
    step_count: Array.isArray(reportJson?.steps) ? reportJson.steps.length : 0
  };
}

function checkRequiredTargets(report, requiredTargets) {
  const errors = [];
  const indexByName = new Map();
  for (const target of report.targets) {
    indexByName.set(String(target.name || "").trim().toLowerCase(), target);
  }
  for (const required of requiredTargets) {
    const key = String(required || "").trim().toLowerCase();
    if (!key) {
      continue;
    }
    const target = indexByName.get(key);
    if (!target) {
      errors.push(`Required target missing from matrix: ${required}`);
      continue;
    }
    if (!target.success) {
      errors.push(`Required target failed: ${required}`);
    }
  }
  return errors;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const matrixOutputRoot = resolve(args.outputDir);
  const matrixRunDir = join(matrixOutputRoot, args.matrixId);
  mkdirSync(matrixRunDir, { recursive: true });

  const reportPath = join(matrixRunDir, "report.json");
  const summaryPath = join(matrixRunDir, "summary.md");
  const report = {
    matrix_id: args.matrixId,
    started_at: new Date().toISOString(),
    finished_at: null,
    required_targets: args.requiredTargets,
    targets: [],
    success: false
  };

  try {
    const parsedTargets = parseTargetsFile(args.targetsFile);
    const normalizedTargets = parsedTargets.map((entry, index) => normalizeTarget(entry, index, args));

    for (const target of normalizedTargets) {
      const result = runTargetDrill(target, args);
      report.targets.push(result);
      if (!result.success && args.stopOnFail) {
        break;
      }
    }

    const requiredErrors = checkRequiredTargets(report, args.requiredTargets);
    if (requiredErrors.length > 0) {
      report.required_target_errors = requiredErrors;
    }
    report.success = report.targets.length > 0 && report.targets.every((target) => target.success) && requiredErrors.length === 0;
    report.finished_at = new Date().toISOString();

    writeFileSync(reportPath, JSON.stringify(report, null, 2) + "\n");
    writeFileSync(summaryPath, buildSummary(report, reportPath));

    if (!report.success) {
      console.error("Federation interop matrix finished: FAIL");
      console.error(`Report: ${reportPath}`);
      console.error(`Summary: ${summaryPath}`);
      if (Array.isArray(report.required_target_errors) && report.required_target_errors.length > 0) {
        for (const line of report.required_target_errors) {
          console.error(`Required target error: ${line}`);
        }
      }
      process.exit(1);
    }

    console.log("Federation interop matrix finished: PASS");
    console.log(`Report: ${reportPath}`);
    console.log(`Summary: ${summaryPath}`);
  } catch (error) {
    report.success = false;
    report.finished_at = new Date().toISOString();
    report.failure = error?.message || String(error);
    writeFileSync(reportPath, JSON.stringify(report, null, 2) + "\n");
    writeFileSync(summaryPath, buildSummary(report, reportPath));
    console.error("Federation interop matrix finished: FAIL");
    console.error(`Report: ${reportPath}`);
    console.error(`Summary: ${summaryPath}`);
    console.error(`Reason: ${report.failure}`);
    process.exit(1);
  }
}

main();
