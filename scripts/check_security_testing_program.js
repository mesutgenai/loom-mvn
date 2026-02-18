#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const REQUIRED_FILES = [
  "docs/SECURITY-TESTING-PROGRAM.md",
  ".github/workflows/security.yml",
  "ops/security/findings-tracker-template.md",
  "scripts/check_secrets_hygiene.js"
];

const REQUIRED_DOC_LINES = [
  "Dependency scanning",
  "Static analysis (SAST)",
  "Periodic penetration testing",
  "Triage SLAs"
];

function main() {
  const checks = [];
  const warnings = [];
  const errors = [];

  for (const relPath of REQUIRED_FILES) {
    const path = resolve(relPath);
    if (!existsSync(path)) {
      errors.push(`Required security program artifact missing: ${relPath}`);
    } else {
      checks.push(`Security program artifact present: ${relPath}`);
    }
  }

  if (existsSync(resolve("docs/SECURITY-TESTING-PROGRAM.md"))) {
    const source = readFileSync(resolve("docs/SECURITY-TESTING-PROGRAM.md"), "utf-8");
    for (const line of REQUIRED_DOC_LINES) {
      if (!source.includes(line)) {
        errors.push(`docs/SECURITY-TESTING-PROGRAM.md missing required section text: ${line}`);
      } else {
        checks.push(`Security program section present: ${line}`);
      }
    }
    if (!/\|\s*Critical\s*\|/m.test(source) || !/\|\s*High\s*\|/m.test(source)) {
      errors.push("Security program doc is missing severity SLA table rows (Critical/High).");
    } else {
      checks.push("Security program includes severity SLA table");
    }
  }

  if (existsSync(resolve(".github/workflows/security.yml"))) {
    const workflow = readFileSync(resolve(".github/workflows/security.yml"), "utf-8");
    if (!workflow.includes("npm audit --audit-level=high")) {
      errors.push("security workflow missing npm audit step.");
    } else {
      checks.push("security workflow includes npm audit step");
    }
    if (!workflow.includes("npm run check:secrets")) {
      errors.push("security workflow missing check:secrets step.");
    } else {
      checks.push("security workflow includes check:secrets step");
    }
    if (!workflow.includes("github/codeql-action/init@")) {
      errors.push("security workflow missing CodeQL init step.");
    } else {
      checks.push("security workflow includes CodeQL initialization");
    }
    if (!workflow.includes("schedule:")) {
      warnings.push("security workflow does not include a scheduled run.");
    } else {
      checks.push("security workflow includes scheduled execution");
    }
  }

  console.log("\nSecurity testing program summary:");
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

  console.log("\nPASSED: security testing program checks succeeded.");
}

main();
