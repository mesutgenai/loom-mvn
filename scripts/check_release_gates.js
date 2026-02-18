#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { resolve } from "node:path";

const REQUIRED_FILES = [
  "CHANGELOG.md",
  "docs/CONFORMANCE.md",
  "docs/RELEASE-CHECKLIST.md",
  "ops/federation/interop-targets.json"
];

const REQUIRED_CHECKLIST_LINES = [
  "CI and test suite green",
  "Conformance checks passed",
  "Changelog updated",
  "Rollback plan documented"
];

const REQUIRED_RELEASE_CHECKLIST_COMMANDS = [
  "npm run gate:release",
  "npm run check:release-gates",
  "npm run check:federation-targets",
  "npm run check:prod-env",
  "npm run check:secrets",
  "npm run check:access-governance",
  "npm run check:compliance",
  "npm run drill:compliance",
  "npm run gate:compliance"
];

const REQUIRED_PACKAGE_SCRIPTS = [
  "test",
  "check:release-gates",
  "check:federation-targets",
  "check:prod-env",
  "check:secrets",
  "check:access-governance",
  "check:compliance",
  "drill:compliance",
  "gate:compliance",
  "gate:release"
];

function parseArgs(argv) {
  const args = {
    enforceCleanTree: false
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--enforce-clean-tree") {
      args.enforceCleanTree = true;
    }
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const checks = [];
  const warnings = [];
  const errors = [];

  for (const relPath of REQUIRED_FILES) {
    const path = resolve(relPath);
    if (!existsSync(path)) {
      errors.push(`Required release artifact missing: ${relPath}`);
    } else {
      checks.push(`Release artifact present: ${relPath}`);
    }
  }

  if (existsSync(resolve("CHANGELOG.md"))) {
    const changelog = readFileSync(resolve("CHANGELOG.md"), "utf-8");
    if (!/^## Unreleased/m.test(changelog)) {
      errors.push("CHANGELOG.md is missing `## Unreleased` section.");
    } else {
      checks.push("CHANGELOG.md includes `## Unreleased` section");
    }
    if (!/^## v\d+\.\d+\.\d+ - \d{4}-\d{2}-\d{2}/m.test(changelog)) {
      warnings.push("CHANGELOG.md does not contain a versioned release heading in expected format.");
    } else {
      checks.push("CHANGELOG.md contains versioned release entries");
    }
  }

  if (existsSync(resolve("docs/RELEASE-CHECKLIST.md"))) {
    const checklist = readFileSync(resolve("docs/RELEASE-CHECKLIST.md"), "utf-8");
    for (const requiredLine of REQUIRED_CHECKLIST_LINES) {
      if (!checklist.includes(requiredLine)) {
        errors.push(`docs/RELEASE-CHECKLIST.md missing required gate item: ${requiredLine}`);
      } else {
        checks.push(`Release checklist gate present: ${requiredLine}`);
      }
    }
    for (const command of REQUIRED_RELEASE_CHECKLIST_COMMANDS) {
      if (!checklist.includes(command)) {
        errors.push(`docs/RELEASE-CHECKLIST.md missing required validation command: ${command}`);
      } else {
        checks.push(`Release checklist validation command present: ${command}`);
      }
    }
    if (!checklist.includes("--interop-targets-file")) {
      errors.push("docs/RELEASE-CHECKLIST.md is missing --interop-targets-file in release gate command.");
    } else {
      checks.push("Release checklist includes --interop-targets-file in release gate command");
    }
    if (!checklist.includes("--expected-targets-file")) {
      errors.push("docs/RELEASE-CHECKLIST.md is missing --expected-targets-file in interop evidence command.");
    } else {
      checks.push("Release checklist includes --expected-targets-file in interop evidence command");
    }
  }

  if (existsSync(resolve("package.json"))) {
    try {
      const pkg = JSON.parse(readFileSync(resolve("package.json"), "utf-8"));
      for (const scriptName of REQUIRED_PACKAGE_SCRIPTS) {
        if (!pkg?.scripts?.[scriptName]) {
          errors.push(`package.json is missing \`scripts.${scriptName}\`.`);
        } else {
          checks.push(`package.json includes script: ${scriptName}`);
        }
      }
    } catch {
      errors.push("Failed to parse package.json.");
    }
  }

  if (existsSync(resolve(".github/workflows/ci.yml"))) {
    const workflow = readFileSync(resolve(".github/workflows/ci.yml"), "utf-8");
    if (!workflow.includes("npm run check:federation-targets")) {
      warnings.push("CI workflow does not include `npm run check:federation-targets`.");
    } else {
      checks.push("CI workflow includes federation interop target validation step");
    }
    if (!workflow.includes("npm run check:release-gates")) {
      warnings.push("CI workflow does not include `npm run check:release-gates`.");
    } else {
      checks.push("CI workflow includes release-gate validation step");
    }
    if (!workflow.includes("npm run check:access-governance")) {
      warnings.push("CI workflow does not include access governance validation step.");
    } else {
      checks.push("CI workflow includes access governance validation step");
    }
    if (!workflow.includes("npm run gate:compliance -- --help")) {
      warnings.push("CI workflow does not include compliance gate CLI verification.");
    } else {
      checks.push("CI workflow includes compliance gate CLI verification");
    }
    if (!workflow.includes("npm run gate:release -- --help")) {
      warnings.push("CI workflow does not include release gate CLI verification.");
    } else {
      checks.push("CI workflow includes release gate CLI verification");
    }
  } else {
    warnings.push("CI workflow file not found (.github/workflows/ci.yml).");
  }

  if (existsSync(resolve("scripts/run_release_gate.js"))) {
    const releaseGateScript = readFileSync(resolve("scripts/run_release_gate.js"), "utf-8");
    const forbiddenSkipFlags = [
      "--skip-pg",
      "--skip-federation-interop",
      "--skip-compliance-gate",
      "--skip-tests"
    ];
    for (const flag of forbiddenSkipFlags) {
      if (releaseGateScript.includes(flag)) {
        errors.push(`scripts/run_release_gate.js still exposes forbidden skip flag: ${flag}`);
      } else {
        checks.push(`Release gate omits skip flag: ${flag}`);
      }
    }
    if (!releaseGateScript.includes("--interop-targets-file")) {
      errors.push("scripts/run_release_gate.js is missing --interop-targets-file support.");
    } else {
      checks.push("Release gate includes --interop-targets-file support");
    }
    if (!releaseGateScript.includes("must reference a concrete environment file")) {
      errors.push("scripts/run_release_gate.js is missing example/template interop targets guard.");
    } else {
      checks.push("Release gate blocks example/template interop targets files");
    }
  } else {
    warnings.push("Release gate script not found (scripts/run_release_gate.js).");
  }

  if (args.enforceCleanTree) {
    try {
      const dirty = execSync("git status --porcelain", { encoding: "utf-8" }).trim();
      if (dirty) {
        errors.push("Git working tree is not clean (required by --enforce-clean-tree).");
      } else {
        checks.push("Git working tree is clean");
      }
    } catch (error) {
      warnings.push(`Could not evaluate git working tree state: ${error?.message || String(error)}`);
    }
  }

  console.log("\nRelease gate summary:");
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
  console.log("\nPASSED: release gate checks succeeded.");
}

main();
