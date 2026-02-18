#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const DEFAULT_DOC = "docs/CAPACITY-CHAOS-TESTS.md";
const DEFAULT_REPORT_DIR = "ops/chaos/reports";

const REQUIRED_DOC_SECTIONS = [
  "## Load Scenarios",
  "## Chaos Scenarios",
  "## Pass Criteria",
  "## Evidence"
];

function parseArgs(argv) {
  const args = {
    docPath: DEFAULT_DOC,
    reportDir: DEFAULT_REPORT_DIR,
    maxAgeDays: 180,
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
    if (arg === "--report-dir" && i + 1 < argv.length) {
      args.reportDir = argv[i + 1];
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
  node scripts/check_capacity_chaos_readiness.js [options]

Options:
  --doc <path>            Capacity/chaos runbook path (default: ${DEFAULT_DOC})
  --report-dir <path>     Chaos report directory (default: ${DEFAULT_REPORT_DIR})
  --max-age-days <int>    Warn when latest report age exceeds this (default: 180)
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

  const docPath = resolve(args.docPath);
  if (!existsSync(docPath)) {
    errors.push(`Capacity/chaos runbook not found: ${docPath}`);
  } else {
    checks.push(`Capacity/chaos runbook present: ${docPath}`);
    const doc = readFileSync(docPath, "utf-8");
    for (const section of REQUIRED_DOC_SECTIONS) {
      if (!doc.includes(section)) {
        errors.push(`Runbook missing required section: ${section}`);
      } else {
        checks.push(`Runbook section present: ${section}`);
      }
    }
  }

  const reportDir = resolve(args.reportDir);
  if (!existsSync(reportDir)) {
    errors.push(`Chaos report directory not found: ${reportDir}`);
  } else {
    const reports = readdirSync(reportDir)
      .filter((name) => name.endsWith(".md"))
      .map((name) => {
        const path = join(reportDir, name);
        const mtimeMs = statSync(path).mtimeMs;
        return { name, path, mtimeMs };
      })
      .sort((left, right) => right.mtimeMs - left.mtimeMs);

    if (reports.length === 0) {
      errors.push(`No chaos reports found under ${reportDir}`);
    } else {
      checks.push(`Found ${reports.length} chaos report(s)`);
      const latest = reports[0];
      const ageDays = (Date.now() - latest.mtimeMs) / (1000 * 60 * 60 * 24);
      if (ageDays > args.maxAgeDays) {
        warnings.push(
          `Latest chaos report is ${ageDays.toFixed(1)} days old (max ${args.maxAgeDays} before warning).`
        );
      } else {
        checks.push(`Latest chaos report age (${ageDays.toFixed(1)} days) is within ${args.maxAgeDays} days`);
      }

      const latestSource = readFileSync(latest.path, "utf-8");
      if (!latestSource.includes("## Key Results")) {
        errors.push(`Latest chaos report missing '## Key Results': ${latest.name}`);
      } else {
        checks.push(`Latest chaos report includes Key Results: ${latest.name}`);
      }
      if (!latestSource.includes("## Scenarios Executed")) {
        errors.push(`Latest chaos report missing '## Scenarios Executed': ${latest.name}`);
      } else {
        checks.push(`Latest chaos report includes Scenarios Executed: ${latest.name}`);
      }
    }
  }

  console.log("\nCapacity/chaos readiness summary:");
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

  console.log("\nPASSED: capacity/chaos readiness checks succeeded.");
}

main();
