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

const ACCESS_REVIEW_PLACEHOLDERS = [
  /replace template row/i,
  /\bexample\.user\b/i,
  /_{3,}/,
  /\bsecurity reviewer:\s*pending\b/i,
  /\bplatform reviewer:\s*pending\b/i
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

function isTemplateRecordName(name) {
  return /template/i.test(name);
}

function hasResolvedReviewerValue(source, roleLabel) {
  const escapedLabel = roleLabel.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const matcher = new RegExp(`^-\\s*${escapedLabel}:\\s*(.+)\\s*$`, "im");
  const match = source.match(matcher);
  if (!match) {
    return false;
  }
  const value = match[1].trim();
  if (!value) {
    return false;
  }
  if (/^_{3,}$/.test(value)) {
    return false;
  }
  if (/^pending$/i.test(value)) {
    return false;
  }
  return true;
}

function hasConcreteInventoryRow(source) {
  const lines = source.split(/\r?\n/);
  const inventoryHeaderIndex = lines.findIndex((line) => line.trim() === "## Access Inventory");
  if (inventoryHeaderIndex < 0) {
    return false;
  }
  const tableLines = [];
  for (let i = inventoryHeaderIndex + 1; i < lines.length; i += 1) {
    const trimmed = lines[i].trim();
    if (!trimmed) {
      if (tableLines.length > 0) {
        break;
      }
      continue;
    }
    if (!trimmed.startsWith("|")) {
      if (tableLines.length > 0) {
        break;
      }
      continue;
    }
    tableLines.push(trimmed);
  }
  if (tableLines.length < 3) {
    return false;
  }
  for (const row of tableLines.slice(2)) {
    const normalized = row.replace(/\|/g, "").trim();
    if (!normalized) {
      continue;
    }
    if (/example\.user/i.test(normalized)) {
      continue;
    }
    return true;
  }
  return false;
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
      .filter((name) => !isTemplateRecordName(name))
      .map((name) => {
        const path = join(reviewDir, name);
        const mtimeMs = statSync(path).mtimeMs;
        return { name, path, mtimeMs };
      })
      .sort((left, right) => right.mtimeMs - left.mtimeMs);

    if (reviews.length === 0) {
      errors.push(`No non-template access review records found under ${reviewDir}`);
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
      if (/^\s*#.*\btemplate\b/i.test(reviewSource)) {
        errors.push(`Latest access review record appears to be a template: ${latest.name}`);
      }
      for (const placeholder of ACCESS_REVIEW_PLACEHOLDERS) {
        if (placeholder.test(reviewSource)) {
          errors.push(`Latest access review record contains unresolved placeholder content: ${latest.name}`);
          break;
        }
      }
      if (!reviewSource.includes("## Access Inventory")) {
        errors.push(`Latest access review record missing '## Access Inventory': ${latest.name}`);
      } else {
        checks.push(`Latest access review includes Access Inventory: ${latest.name}`);
      }
      if (!hasConcreteInventoryRow(reviewSource)) {
        errors.push(`Latest access review record does not include a concrete access inventory row: ${latest.name}`);
      } else {
        checks.push(`Latest access review includes concrete access inventory rows: ${latest.name}`);
      }
      if (!hasResolvedReviewerValue(reviewSource, "Security reviewer")) {
        errors.push(`Latest access review record has unresolved Security reviewer sign-off: ${latest.name}`);
      } else {
        checks.push(`Latest access review includes Security reviewer sign-off: ${latest.name}`);
      }
      if (!hasResolvedReviewerValue(reviewSource, "Platform reviewer")) {
        errors.push(`Latest access review record has unresolved Platform reviewer sign-off: ${latest.name}`);
      } else {
        checks.push(`Latest access review includes Platform reviewer sign-off: ${latest.name}`);
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
