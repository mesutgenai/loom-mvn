import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));

function runNodeScript(scriptPath, args, options = {}) {
  return spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: options.cwd || REPO_ROOT,
    encoding: "utf-8"
  });
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf-8");
}

test("check_federation_interop_evidence passes when report origins match expected targets", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "loom-interop-evidence-pass-"));
  try {
    const reportPath = join(tempRoot, "report.json");
    const targetsPath = join(tempRoot, "targets.json");
    const nowIso = new Date().toISOString();

    writeJson(reportPath, {
      matrix_id: "interop-matrix-test-pass",
      finished_at: nowIso,
      success: true,
      targets: [
        {
          name: "staging",
          base_url: "https://loom-staging.example.net",
          success: true,
          assertions: {
            challenge_issue_passed: true,
            delivery_passed: true,
            receipt_signature_verified: true,
            replay_guard_passed: true
          }
        },
        {
          name: "preprod",
          base_url: "https://loom-preprod.example.net",
          success: true,
          assertions: {
            challenge_issue_passed: true,
            delivery_passed: true,
            receipt_signature_verified: true,
            replay_guard_passed: true
          }
        }
      ]
    });

    writeJson(targetsPath, {
      targets: [
        { name: "staging", base_url: "https://loom-staging.example.net" },
        { name: "preprod", base_url: "https://loom-preprod.example.net" }
      ]
    });

    const scriptPath = resolve(REPO_ROOT, "scripts/check_federation_interop_evidence.js");
    const result = runNodeScript(scriptPath, [
      "--matrix-report",
      reportPath,
      "--expected-targets-file",
      targetsPath
    ]);

    assert.equal(result.status, 0, `expected pass, got ${result.status}\n${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /Required target staging origin matches expected targets file/);
    assert.match(result.stdout, /Required target preprod origin matches expected targets file/);
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("check_federation_interop_evidence fails when report origins differ from expected targets", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "loom-interop-evidence-fail-"));
  try {
    const reportPath = join(tempRoot, "report.json");
    const targetsPath = join(tempRoot, "targets.json");
    const nowIso = new Date().toISOString();

    writeJson(reportPath, {
      matrix_id: "interop-matrix-test-fail",
      finished_at: nowIso,
      success: true,
      targets: [
        {
          name: "staging",
          base_url: "https://loom-staging.example.net",
          success: true,
          assertions: {
            challenge_issue_passed: true,
            delivery_passed: true,
            receipt_signature_verified: true,
            replay_guard_passed: true
          }
        },
        {
          name: "preprod",
          base_url: "https://loom-preprod.example.net",
          success: true,
          assertions: {
            challenge_issue_passed: true,
            delivery_passed: true,
            receipt_signature_verified: true,
            replay_guard_passed: true
          }
        }
      ]
    });

    writeJson(targetsPath, {
      targets: [
        { name: "staging", base_url: "https://loom-staging.example.net" },
        { name: "preprod", base_url: "https://loom-preprod.other.net" }
      ]
    });

    const scriptPath = resolve(REPO_ROOT, "scripts/check_federation_interop_evidence.js");
    const result = runNodeScript(scriptPath, [
      "--matrix-report",
      reportPath,
      "--expected-targets-file",
      targetsPath
    ]);

    assert.notEqual(result.status, 0, `expected failure, got ${result.status}\n${result.stdout}\n${result.stderr}`);
    assert.match(
      result.stdout,
      /does not match expected targets file/,
      `expected mismatch output, got:\n${result.stdout}\n${result.stderr}`
    );
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("check_federation_interop_evidence fails for disguised loopback hosts", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "loom-interop-evidence-loopback-"));
  try {
    const reportPath = join(tempRoot, "report.json");
    const targetsPath = join(tempRoot, "targets.json");
    const nowIso = new Date().toISOString();

    writeJson(reportPath, {
      matrix_id: "interop-matrix-test-loopback",
      finished_at: nowIso,
      success: true,
      targets: [
        {
          name: "staging",
          base_url: "https://203.0.113.10.sslip.io",
          success: true,
          assertions: {
            challenge_issue_passed: true,
            delivery_passed: true,
            receipt_signature_verified: true,
            replay_guard_passed: true
          }
        },
        {
          name: "preprod",
          base_url: "https://loom-preprod.example.net",
          success: true,
          assertions: {
            challenge_issue_passed: true,
            delivery_passed: true,
            receipt_signature_verified: true,
            replay_guard_passed: true
          }
        }
      ]
    });

    writeJson(targetsPath, {
      targets: [
        { name: "staging", base_url: "https://203.0.113.10.sslip.io" },
        { name: "preprod", base_url: "https://loom-preprod.example.net" }
      ]
    });

    const scriptPath = resolve(REPO_ROOT, "scripts/check_federation_interop_evidence.js");
    const result = runNodeScript(scriptPath, [
      "--matrix-report",
      reportPath,
      "--expected-targets-file",
      targetsPath
    ]);

    assert.notEqual(result.status, 0, `expected failure, got ${result.status}\n${result.stdout}\n${result.stderr}`);
    assert.match(
      `${result.stdout}\n${result.stderr}`,
      /must not point to localhost\/loopback/i,
      `expected loopback rejection output, got:\n${result.stdout}\n${result.stderr}`
    );
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("run_release_gate rejects example interop targets file before execution", () => {
  const scriptPath = resolve(REPO_ROOT, "scripts/run_release_gate.js");
  const envFilePath = resolve(REPO_ROOT, ".env.production.example");

  const result = runNodeScript(scriptPath, [
    "--env-file",
    envFilePath,
    "--base-url",
    "https://loom.example.com",
    "--admin-token",
    "dummy-admin",
    "--bearer-token",
    "dummy-bearer",
    "--interop-targets-file",
    "ops/federation/interop-targets.example.json"
  ]);

  assert.notEqual(result.status, 0, `expected failure, got ${result.status}\n${result.stdout}\n${result.stderr}`);
  assert.match(
    `${result.stdout}\n${result.stderr}`,
    /must reference a concrete environment file, not an example\/template file/i
  );
});

test("check_federation_interop_targets fails for disguised loopback hosts", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "loom-interop-targets-loopback-"));
  try {
    const targetsPath = join(tempRoot, "targets.json");
    writeJson(targetsPath, {
      targets: [
        {
          name: "staging",
          base_url: "https://203.0.113.10.sslip.io",
          admin_token_env: "LOOM_STAGING_ADMIN_TOKEN"
        },
        {
          name: "preprod",
          base_url: "https://loom-preprod.example.net",
          admin_token_env: "LOOM_PREPROD_ADMIN_TOKEN"
        }
      ]
    });

    const scriptPath = resolve(REPO_ROOT, "scripts/check_federation_interop_targets.js");
    const result = runNodeScript(scriptPath, ["--targets-file", targetsPath, "--required-targets", "staging,preprod"]);

    assert.notEqual(result.status, 0, `expected failure, got ${result.status}\n${result.stdout}\n${result.stderr}`);
    assert.match(
      `${result.stdout}\n${result.stderr}`,
      /must not point to localhost\/loopback/i,
      `expected loopback rejection output, got:\n${result.stdout}\n${result.stderr}`
    );
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});
