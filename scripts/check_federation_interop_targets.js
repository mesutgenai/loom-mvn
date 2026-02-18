#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const DEFAULT_TARGETS_FILE = "ops/federation/interop-targets.json";
const DEFAULT_REQUIRED_TARGETS = ["staging", "preprod"];

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
    targetsFile: process.env.LOOM_INTEROP_TARGETS_FILE || DEFAULT_TARGETS_FILE,
    requiredTargets: parseList(process.env.LOOM_INTEROP_REQUIRED_TARGETS, DEFAULT_REQUIRED_TARGETS),
    allowLocalTargets: false,
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
    if (arg === "--required-targets" && i + 1 < argv.length) {
      args.requiredTargets = parseList(argv[i + 1], DEFAULT_REQUIRED_TARGETS);
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
  node scripts/check_federation_interop_targets.js [options]

Options:
  --targets-file <path>       Targets JSON file path (default: ${DEFAULT_TARGETS_FILE})
  --required-targets <csv>    Required target names (default: staging,preprod)
  --allow-local-targets        Allow localhost/loopback target URLs (disabled by default)
  -h, --help                  Show help
`);
}

function normalizeName(value) {
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

function parseTargets(path) {
  const fullPath = resolve(path);
  if (!existsSync(fullPath)) {
    throw new Error(`Targets file not found: ${fullPath}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(fullPath, "utf-8"));
  } catch (error) {
    throw new Error(`Targets file is not valid JSON: ${fullPath} (${error.message})`);
  }
  const targets = Array.isArray(parsed) ? parsed : parsed?.targets;
  if (!Array.isArray(targets) || targets.length === 0) {
    throw new Error(`Targets file must contain a non-empty targets array: ${fullPath}`);
  }
  return { fullPath, targets };
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

  let loaded;
  try {
    loaded = parseTargets(args.targetsFile);
  } catch (error) {
    console.error(`ERROR: ${error.message}`);
    process.exit(1);
  }
  checks.push(`Loaded targets file: ${loaded.fullPath}`);

  const targetByName = new Map();
  for (const entry of loaded.targets) {
    const key = normalizeName(entry?.name ?? entry?.environment);
    if (!key) {
      warnings.push("Found target entry without name/environment.");
      continue;
    }
    targetByName.set(key, entry);
  }

  const requiredOrigins = new Map();
  for (const requiredNameRaw of args.requiredTargets) {
    const requiredName = normalizeName(requiredNameRaw);
    if (!requiredName) {
      continue;
    }
    const target = targetByName.get(requiredName);
    if (!target) {
      errors.push(`Required target missing: ${requiredNameRaw}`);
      continue;
    }

    const baseUrlRaw = String(target.base_url ?? target.baseUrl ?? "").trim();
    if (!baseUrlRaw) {
      errors.push(`Target ${requiredNameRaw} is missing base_url.`);
      continue;
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(baseUrlRaw);
    } catch (error) {
      errors.push(`Target ${requiredNameRaw} has invalid base_url (${baseUrlRaw}): ${error.message}`);
      continue;
    }

    if (!args.allowLocalTargets) {
      if (parsedUrl.protocol !== "https:") {
        errors.push(`Target ${requiredNameRaw} base_url must use https: ${baseUrlRaw}`);
      }
      if (isLoopbackTargetHost(parsedUrl.hostname)) {
        errors.push(`Target ${requiredNameRaw} base_url must not point to localhost/loopback: ${baseUrlRaw}`);
      }
    }

    const origin = parsedUrl.origin.toLowerCase();
    const existing = requiredOrigins.get(origin);
    if (existing) {
      errors.push(
        `Targets ${existing} and ${requiredNameRaw} share the same base_url origin (${origin}); distinct environments are required.`
      );
    } else {
      requiredOrigins.set(origin, requiredNameRaw);
      checks.push(`Target ${requiredNameRaw} base_url validated (${origin})`);
    }

    const tokenRef = String(target.admin_token_env ?? "").trim();
    const inlineToken = String(target.admin_token ?? target.adminToken ?? "").trim();
    if (!tokenRef && !inlineToken) {
      errors.push(`Target ${requiredNameRaw} is missing admin token reference (admin_token_env or admin_token).`);
    } else if (tokenRef) {
      checks.push(`Target ${requiredNameRaw} references admin token env: ${tokenRef}`);
    } else {
      warnings.push(`Target ${requiredNameRaw} uses inline admin token; env indirection is preferred.`);
    }
  }

  console.log("\nFederation interop targets summary:");
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

  console.log("\nPASSED: federation interop target checks succeeded.");
}

main();
