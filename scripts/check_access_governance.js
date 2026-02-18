#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const DEFAULT_DOC_PATH = "docs/ACCESS-GOVERNANCE.md";
const DEFAULT_REVIEW_DIR = "ops/access/reviews";

const REQUIRED_TERMS = [
  "least-privilege",
  "Quarterly access review",
  "Joiner/mover/leaver",
  "Audit trail",
  "break-glass"
];

function parseArgs(argv) {
  const args = {
    docPath: DEFAULT_DOC_PATH,
    reviewDir: DEFAULT_REVIEW_DIR,
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
    if (arg === "--review-dir" && i + 1 < argv.length) {
      args.reviewDir = argv[i + 1];
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
  node scripts/check_access_governance.js [options]

Options:
  --doc <path>            Access governance doc path (default: ${DEFAULT_DOC_PATH})
  --review-dir <path>     Access review records directory (default: ${DEFAULT_REVIEW_DIR})
  --max-age-days <int>    Warn when latest review record age exceeds this (default: 180)
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
    errors.push(`Access governance doc not found: ${docPath}`);
  } else {
    checks.push(`Access governance doc present: ${docPath}`);
    const source = readFileSync(docPath, "utf-8");
    for (const term of REQUIRED_TERMS) {
      if (!source.toLowerCase().includes(term.toLowerCase())) {
        errors.push(`Access governance doc missing required term: ${term}`);
      } else {
        checks.push(`Access governance doc includes: ${term}`);
      }
    }
  }

  const reviewDir = resolve(args.reviewDir);
  if (!existsSync(reviewDir)) {
    errors.push(`Access review directory not found: ${reviewDir}`);
  } else {
    const reviews = readdirSync(reviewDir)
      .filter((name) => name.endsWith(".md"))
      .map((name) => {
        const path = join(reviewDir, name);
        const mtimeMs = statSync(path).mtimeMs;
        return { name, path, mtimeMs };
      })
      .sort((left, right) => right.mtimeMs - left.mtimeMs);

    if (reviews.length === 0) {
      errors.push(`No access review records found under ${reviewDir}`);
    } else {
      checks.push(`Found ${reviews.length} access review record(s)`);
      const latest = reviews[0];
      const ageDays = (Date.now() - latest.mtimeMs) / (1000 * 60 * 60 * 24);
      if (ageDays > args.maxAgeDays) {
        warnings.push(
          `Latest access review record is ${ageDays.toFixed(1)} days old (max ${args.maxAgeDays} before warning).`
        );
      } else {
        checks.push(`Latest access review age (${ageDays.toFixed(1)} days) is within ${args.maxAgeDays} days`);
      }

      const reviewSource = readFileSync(latest.path, "utf-8");
      if (!reviewSource.includes("## Access Inventory")) {
        errors.push(`Latest access review record missing '## Access Inventory': ${latest.name}`);
      } else {
        checks.push(`Latest access review includes Access Inventory: ${latest.name}`);
      }
    }
  }

  console.log("\nAccess governance summary:");
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

  console.log("\nPASSED: access governance checks succeeded.");
}

main();
