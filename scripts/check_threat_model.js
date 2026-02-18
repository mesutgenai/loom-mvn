#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const DEFAULT_MODEL_PATH = "docs/THREAT-MODEL.md";

const REQUIRED_HEADINGS = [
  "# LOOM Threat Model",
  "## Scope",
  "## Assets",
  "## Trust Boundaries",
  "## STRIDE Analysis",
  "## Mitigation Mapping",
  "## Review Cadence"
];

const REQUIRED_STRIDE_TERMS = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation Of Privilege"
];

function parseArgs(argv) {
  const args = {
    modelPath: DEFAULT_MODEL_PATH,
    maxAgeDays: 120,
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }
    if (arg === "--model" && i + 1 < argv.length) {
      args.modelPath = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--max-age-days" && i + 1 < argv.length) {
      const parsed = Number(argv[i + 1]);
      if (Number.isInteger(parsed) && parsed > 0) {
        args.maxAgeDays = parsed;
      }
      i += 1;
      continue;
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage:
  node scripts/check_threat_model.js [options]

Options:
  --model <path>          Threat model markdown path (default: ${DEFAULT_MODEL_PATH})
  --max-age-days <int>    Warn when Last reviewed is older than this (default: 120)
  -h, --help              Show help
`);
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

  const modelPath = resolve(args.modelPath);
  if (!existsSync(modelPath)) {
    console.error(`ERROR: threat model not found: ${modelPath}`);
    process.exit(1);
  }
  checks.push(`Threat model present: ${modelPath}`);

  const source = readFileSync(modelPath, "utf-8");

  for (const heading of REQUIRED_HEADINGS) {
    if (!source.includes(heading)) {
      errors.push(`Missing required section: ${heading}`);
    } else {
      checks.push(`Section present: ${heading}`);
    }
  }

  for (const term of REQUIRED_STRIDE_TERMS) {
    if (!source.includes(term)) {
      errors.push(`Missing STRIDE term coverage: ${term}`);
    } else {
      checks.push(`STRIDE term present: ${term}`);
    }
  }

  const reviewedMatch = source.match(/^Last reviewed:\s*(\d{4}-\d{2}-\d{2})\s*$/m);
  if (!reviewedMatch) {
    errors.push("Threat model is missing `Last reviewed: YYYY-MM-DD`.");
  } else {
    const reviewedDate = reviewedMatch[1];
    const reviewedMs = Date.parse(`${reviewedDate}T00:00:00Z`);
    if (!Number.isFinite(reviewedMs)) {
      errors.push(`Invalid Last reviewed date: ${reviewedDate}`);
    } else {
      const nowMs = Date.now();
      const ageDays = (nowMs - reviewedMs) / (1000 * 60 * 60 * 24);
      if (ageDays < 0) {
        errors.push(`Last reviewed date is in the future: ${reviewedDate}`);
      } else if (ageDays > args.maxAgeDays) {
        warnings.push(
          `Threat model review age is ${ageDays.toFixed(1)} days (max ${args.maxAgeDays} before warning).`
        );
      } else {
        checks.push(`Threat model review age (${ageDays.toFixed(1)} days) is within ${args.maxAgeDays} days`);
      }
    }
  }

  console.log("\nThreat model summary:");
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

  console.log("\nPASSED: threat model checks succeeded.");
}

main();
