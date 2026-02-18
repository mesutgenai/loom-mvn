#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const DEFAULT_PLAN_PATH = "docs/DISASTER-RECOVERY-PLAN.md";
const DEFAULT_REPORT_DIR = "ops/dr/reports";

const REQUIRED_PLAN_TERMS = [
  "RTO",
  "RPO",
  "## Failover Procedure",
  "## Data Consistency Checks",
  "## Drill Cadence"
];

function parseArgs(argv) {
  const args = {
    planPath: DEFAULT_PLAN_PATH,
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
    if (arg === "--plan" && i + 1 < argv.length) {
      args.planPath = argv[i + 1];
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
  node scripts/check_disaster_recovery_plan.js [options]

Options:
  --plan <path>           DR plan path (default: ${DEFAULT_PLAN_PATH})
  --report-dir <path>     DR drill reports directory (default: ${DEFAULT_REPORT_DIR})
  --max-age-days <int>    Warn when latest drill report is older than this (default: 180)
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

  const planPath = resolve(args.planPath);
  if (!existsSync(planPath)) {
    errors.push(`DR plan not found: ${planPath}`);
  } else {
    checks.push(`DR plan present: ${planPath}`);
    const plan = readFileSync(planPath, "utf-8");
    for (const term of REQUIRED_PLAN_TERMS) {
      if (!plan.includes(term)) {
        errors.push(`DR plan missing required section/term: ${term}`);
      } else {
        checks.push(`DR plan includes: ${term}`);
      }
    }
  }

  const reportDir = resolve(args.reportDir);
  if (!existsSync(reportDir)) {
    errors.push(`DR report directory not found: ${reportDir}`);
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
      errors.push(`No DR reports found under ${reportDir}`);
    } else {
      checks.push(`Found ${reports.length} DR report(s)`);
      const latest = reports[0];
      const ageDays = (Date.now() - latest.mtimeMs) / (1000 * 60 * 60 * 24);
      if (ageDays > args.maxAgeDays) {
        warnings.push(
          `Latest DR report is ${ageDays.toFixed(1)} days old (max ${args.maxAgeDays} before warning).`
        );
      } else {
        checks.push(`Latest DR report age (${ageDays.toFixed(1)} days) is within ${args.maxAgeDays} days`);
      }

      const source = readFileSync(latest.path, "utf-8");
      if (!source.includes("## Outcomes")) {
        errors.push(`Latest DR report missing '## Outcomes': ${latest.name}`);
      } else {
        checks.push(`Latest DR report includes Outcomes: ${latest.name}`);
      }
    }
  }

  console.log("\nDisaster recovery plan summary:");
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

  console.log("\nPASSED: disaster recovery plan checks succeeded.");
}

main();
