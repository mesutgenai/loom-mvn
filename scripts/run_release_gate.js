#!/usr/bin/env node

import { spawnSync } from "node:child_process";

function parseBoolean(value, defaultValue = false) {
  if (value == null) {
    return defaultValue;
  }
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  return defaultValue;
}

function parsePositiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

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
    envFile: process.env.LOOM_RELEASE_ENV_FILE || null,
    baseUrl: process.env.LOOM_BASE_URL || null,
    adminToken: process.env.LOOM_ADMIN_TOKEN || null,
    bearerToken: process.env.LOOM_COMPLIANCE_AUDIT_BEARER_TOKEN || process.env.LOOM_FEDERATION_AUDIT_BEARER_TOKEN || null,
    bootstrapAuditToken: parseBoolean(process.env.LOOM_COMPLIANCE_BOOTSTRAP_AUDIT_TOKEN, false),
    expectedSchema: parsePositiveInt(process.env.LOOM_DRILL_EXPECTED_SCHEMA, 3),
    requiredTargets: parseList(process.env.LOOM_INTEROP_REQUIRED_TARGETS, ["staging", "preprod"]),
    maxAgeHours: parsePositiveInt(process.env.LOOM_INTEROP_EVIDENCE_MAX_AGE_HOURS, 168),
    timeoutMs: parsePositiveInt(process.env.LOOM_DRILL_TIMEOUT_MS, 15000),
    skipPg: false,
    skipFederationInterop: false,
    skipComplianceGate: false,
    skipTests: false,
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }
    if (arg === "--env-file" && i + 1 < argv.length) {
      args.envFile = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--base-url" && i + 1 < argv.length) {
      args.baseUrl = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--admin-token" && i + 1 < argv.length) {
      args.adminToken = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--bearer-token" && i + 1 < argv.length) {
      args.bearerToken = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--bootstrap-audit-token") {
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        args.bootstrapAuditToken = parseBoolean(next, true);
        i += 1;
      } else {
        args.bootstrapAuditToken = true;
      }
      continue;
    }
    if (arg === "--expected-schema" && i + 1 < argv.length) {
      args.expectedSchema = parsePositiveInt(argv[i + 1], 3);
      i += 1;
      continue;
    }
    if (arg === "--required-targets" && i + 1 < argv.length) {
      args.requiredTargets = parseList(argv[i + 1], ["staging", "preprod"]);
      i += 1;
      continue;
    }
    if (arg === "--max-age-hours" && i + 1 < argv.length) {
      args.maxAgeHours = parsePositiveInt(argv[i + 1], 168);
      i += 1;
      continue;
    }
    if (arg === "--timeout-ms" && i + 1 < argv.length) {
      args.timeoutMs = parsePositiveInt(argv[i + 1], 15000);
      i += 1;
      continue;
    }
    if (arg === "--skip-pg") {
      args.skipPg = true;
      continue;
    }
    if (arg === "--skip-federation-interop") {
      args.skipFederationInterop = true;
      continue;
    }
    if (arg === "--skip-compliance-gate") {
      args.skipComplianceGate = true;
      continue;
    }
    if (arg === "--skip-tests") {
      args.skipTests = true;
      continue;
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage:
  node scripts/run_release_gate.js [options]

Runs production release validation checks in sequence (wrapping release checklist commands).

Options:
  --env-file <path>             Environment file for env-backed checks (required)
  --base-url <url>              Runtime base URL for compliance gate
  --admin-token <token>         Admin token for compliance gate
  --bearer-token <token>        Bearer token for /v1/audit compliance probe
  --bootstrap-audit-token       Bootstrap temporary audit token for compliance gate when bearer token is omitted
  --expected-schema <int>       Expected postgres schema version for check:pg (default: 3)
  --required-targets <csv>      Required targets for federation interop evidence (default: staging,preprod)
  --max-age-hours <int>         Max federation interop evidence age in hours (default: 168)
  --timeout-ms <int>            Timeout for compliance runtime probes (default: 15000)
  --skip-pg                     Skip check:pg
  --skip-federation-interop     Skip check:federation-interop
  --skip-compliance-gate        Skip gate:compliance
  --skip-tests                  Skip npm test
  -h, --help                    Show help

Examples:
  npm run gate:release -- --env-file .env.production --base-url https://loom.example.com --admin-token <token> --bootstrap-audit-token
  npm run gate:release -- --env-file .env.production --base-url http://127.0.0.1:8787 --admin-token <token> --bootstrap-audit-token --skip-pg --skip-federation-interop
`);
}

function runNodeStep(label, script, extraArgs = []) {
  console.log(`\n[release-gate] ${label}`);
  const child = spawnSync(process.execPath, [script, ...extraArgs], {
    stdio: "inherit",
    env: process.env
  });
  if (child.error) {
    throw child.error;
  }
  if (child.status !== 0) {
    throw new Error(`${label} failed with exit code ${child.status}`);
  }
}

function runShellStep(label, command, args = []) {
  console.log(`\n[release-gate] ${label}`);
  const child = spawnSync(command, args, {
    stdio: "inherit",
    env: process.env
  });
  if (child.error) {
    throw child.error;
  }
  if (child.status !== 0) {
    throw new Error(`${label} failed with exit code ${child.status}`);
  }
}

function resolveNpmCommand() {
  return process.platform === "win32" ? "npm.cmd" : "npm";
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  if (!String(args.envFile || "").trim()) {
    console.error("ERROR: --env-file is required.");
    process.exit(1);
  }

  try {
    runNodeStep("Release checklist wiring checks", "scripts/check_release_gates.js");
    runNodeStep("Production env baseline", "scripts/verify_production_env.js", ["--env-file", args.envFile]);
    runNodeStep("Secret hygiene", "scripts/check_secrets_hygiene.js");

    if (!args.skipPg) {
      runNodeStep("Postgres readiness", "scripts/check_postgres_readiness.js", [
        "--env-file",
        args.envFile,
        "--expected-schema",
        String(args.expectedSchema)
      ]);
    } else {
      console.log("\n[release-gate] Skipping Postgres readiness (--skip-pg)");
    }

    runNodeStep("Federation controls", "scripts/check_federation_controls.js", ["--env-file", args.envFile]);
    runNodeStep("Inbound bridge hardening", "scripts/check_inbound_bridge_hardening.js", ["--env-file", args.envFile]);
    runNodeStep("Rate-limit policy", "scripts/check_rate_limit_policy.js", ["--env-file", args.envFile]);
    runNodeStep("Outbox worker reliability", "scripts/check_outbox_workers.js", ["--env-file", args.envFile]);
    runNodeStep("Observability and alerting", "scripts/check_observability_alerting.js", ["--env-file", args.envFile]);
    runNodeStep("Incident response readiness", "scripts/check_incident_response_readiness.js");
    runNodeStep("Request tracing", "scripts/check_request_tracing.js", ["--env-file", args.envFile]);
    runNodeStep("Threat model", "scripts/check_threat_model.js");
    runNodeStep("Security testing program", "scripts/check_security_testing_program.js");
    runNodeStep("Capacity and chaos", "scripts/check_capacity_chaos_readiness.js");
    runNodeStep("Disaster recovery plan", "scripts/check_disaster_recovery_plan.js");
    runNodeStep("Access governance", "scripts/check_access_governance.js");
    runNodeStep("Compliance controls", "scripts/check_compliance_controls.js", ["--env-file", args.envFile]);

    if (!args.skipComplianceGate) {
      if (!String(args.baseUrl || "").trim()) {
        throw new Error("Compliance gate requires --base-url (or pass --skip-compliance-gate).");
      }
      if (!String(args.adminToken || "").trim()) {
        throw new Error("Compliance gate requires --admin-token (or pass --skip-compliance-gate).");
      }
      const complianceArgs = [
        "scripts/run_compliance_gate.js",
        "--env-file",
        args.envFile,
        "--base-url",
        args.baseUrl,
        "--admin-token",
        args.adminToken,
        "--timeout-ms",
        String(args.timeoutMs)
      ];
      if (String(args.bearerToken || "").trim()) {
        complianceArgs.push("--bearer-token", args.bearerToken);
      } else if (args.bootstrapAuditToken) {
        complianceArgs.push("--bootstrap-audit-token");
      } else {
        throw new Error(
          "Compliance gate requires --bearer-token or --bootstrap-audit-token (or pass --skip-compliance-gate)."
        );
      }
      runNodeStep("Compliance gate", complianceArgs[0], complianceArgs.slice(1));
    } else {
      console.log("\n[release-gate] Skipping compliance gate (--skip-compliance-gate)");
    }

    if (!args.skipFederationInterop) {
      runNodeStep("Federation interop evidence", "scripts/check_federation_interop_evidence.js", [
        "--required-targets",
        args.requiredTargets.join(","),
        "--max-age-hours",
        String(args.maxAgeHours)
      ]);
    } else {
      console.log("\n[release-gate] Skipping federation interop evidence (--skip-federation-interop)");
    }

    if (!args.skipTests) {
      runShellStep("Test suite", resolveNpmCommand(), ["test"]);
    } else {
      console.log("\n[release-gate] Skipping test suite (--skip-tests)");
    }

    console.log("\n[release-gate] PASS");
  } catch (error) {
    console.error(`\n[release-gate] FAIL: ${error?.message || String(error)}`);
    process.exit(1);
  }
}

main();
