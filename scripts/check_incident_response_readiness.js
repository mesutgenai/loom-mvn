#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const DEFAULT_RUNBOOK_PATH = "docs/INCIDENT-RESPONSE-ONCALL.md";
const DEFAULT_DRILL_DIR = "ops/incidents/drills";

const REQUIRED_RUNBOOK_HEADINGS = [
  "## On-Call Rotation",
  "## Severity Matrix",
  "## Incident Lifecycle",
  "## Security Incident Playbook",
  "## Availability Incident Playbook",
  "## Communications",
  "## Drill Program"
];

function parseArgs(argv) {
  const args = {
    runbookPath: DEFAULT_RUNBOOK_PATH,
    drillDir: DEFAULT_DRILL_DIR,
    minDrills: 1
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--runbook" && i + 1 < argv.length) {
      args.runbookPath = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--drill-dir" && i + 1 < argv.length) {
      args.drillDir = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--min-drills" && i + 1 < argv.length) {
      const value = Number(argv[i + 1]);
      args.minDrills = Number.isInteger(value) && value >= 0 ? value : 1;
      i += 1;
      continue;
    }
  }

  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const checks = [];
  const warnings = [];
  const errors = [];

  const runbookPath = resolve(args.runbookPath);
  const drillDir = resolve(args.drillDir);

  if (!existsSync(runbookPath)) {
    errors.push(`Incident runbook not found: ${runbookPath}`);
  } else {
    checks.push(`Incident runbook present: ${runbookPath}`);
    const source = readFileSync(runbookPath, "utf-8");
    for (const heading of REQUIRED_RUNBOOK_HEADINGS) {
      if (!source.includes(heading)) {
        errors.push(`Incident runbook missing required section: ${heading}`);
      } else {
        checks.push(`Runbook section present: ${heading.replace(/^##\s*/, "")}`);
      }
    }
  }

  if (!existsSync(drillDir)) {
    errors.push(`Incident drill directory not found: ${drillDir}`);
  } else {
    const drillFiles = readdirSync(drillDir)
      .filter((entry) => entry.toLowerCase().endsWith(".md"))
      .map((entry) => resolve(drillDir, entry))
      .sort();
    if (drillFiles.length < args.minDrills) {
      errors.push(`Incident drill notes count ${drillFiles.length} is below required minimum ${args.minDrills}.`);
    } else {
      checks.push(`Incident drill notes present (${drillFiles.length})`);
      const latest = drillFiles[drillFiles.length - 1];
      checks.push(`Latest drill note: ${latest}`);
      const latestSource = readFileSync(latest, "utf-8");
      if (!/follow[- ]up/i.test(latestSource)) {
        warnings.push(`Latest drill note does not include explicit follow-up section: ${latest}`);
      }
    }
  }

  console.log("\nIncident response readiness summary:");
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
  console.log("\nPASSED: incident response readiness checks succeeded.");
}

main();
