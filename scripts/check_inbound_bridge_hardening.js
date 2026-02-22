#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { applyConfigProfileEnvDefaults } from "../src/node/config_profile.js";

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

function parseEnvFile(filePath) {
  const parsed = {};
  const source = readFileSync(filePath, "utf-8");
  const lines = source.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const idx = trimmed.indexOf("=");
    if (idx <= 0) {
      continue;
    }
    const key = trimmed.slice(0, idx).trim();
    let value = trimmed.slice(idx + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    parsed[key] = value;
  }
  return parsed;
}

function parseArgs(argv) {
  const args = {
    envFile: null,
    baseUrl: null,
    bearerToken: null,
    adminToken: null,
    timeoutMs: 10000
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
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
    if (arg === "--bearer-token" && i + 1 < argv.length) {
      args.bearerToken = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--admin-token" && i + 1 < argv.length) {
      args.adminToken = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--timeout-ms" && i + 1 < argv.length) {
      const parsed = Number(argv[i + 1]);
      args.timeoutMs = Number.isInteger(parsed) && parsed > 0 ? parsed : 10000;
      i += 1;
      continue;
    }
  }
  return args;
}

async function fetchJson(url, options = {}) {
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs || 10000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: options.method || "GET",
      headers: options.headers || {},
      body: options.body,
      signal: controller.signal
    });
    const text = await response.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return { response, text, json };
  } finally {
    clearTimeout(timer);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const env = { ...process.env };
  if (args.envFile) {
    const envFilePath = resolve(args.envFile);
    if (!existsSync(envFilePath)) {
      console.error(`ERROR: env file not found: ${envFilePath}`);
      process.exit(1);
    }
    Object.assign(env, parseEnvFile(envFilePath));
    console.log(`Loaded env file: ${envFilePath}`);
  }

  let activeConfigProfile = null;
  try {
    activeConfigProfile = applyConfigProfileEnvDefaults(env, env.LOOM_CONFIG_PROFILE);
  } catch (error) {
    console.error(`ERROR: ${error?.message || String(error)}`);
    process.exit(1);
  }
  if (activeConfigProfile) {
    console.log(`Applied LOOM config profile defaults: ${activeConfigProfile}`);
  }

  const checks = [];
  const warnings = [];
  const errors = [];

  const publicService = parseBoolean(env.LOOM_PUBLIC_SERVICE, false);
  const bridgeInboundEnabled = parseBoolean(env.LOOM_BRIDGE_EMAIL_INBOUND_ENABLED, true);
  const bridgeInboundPublicConfirmed = parseBoolean(env.LOOM_BRIDGE_EMAIL_INBOUND_PUBLIC_CONFIRMED, false);
  const bridgeInboundRequireAdminToken = parseBoolean(
    env.LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_ADMIN_TOKEN,
    publicService && bridgeInboundEnabled
  );
  const bridgeInboundRequireAuthResults = parseBoolean(
    env.LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_AUTH_RESULTS,
    publicService && bridgeInboundEnabled
  );
  const bridgeInboundRequireDmarcPass = parseBoolean(
    env.LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_DMARC_PASS,
    publicService && bridgeInboundEnabled
  );
  const bridgeInboundRejectOnAuthFailure = parseBoolean(
    env.LOOM_BRIDGE_EMAIL_INBOUND_REJECT_ON_AUTH_FAILURE,
    publicService && bridgeInboundEnabled
  );
  const bridgeInboundQuarantineOnAuthFailure = parseBoolean(
    env.LOOM_BRIDGE_EMAIL_INBOUND_QUARANTINE_ON_AUTH_FAILURE,
    true
  );
  const bridgeInboundWeakAuthPolicyConfirmed = parseBoolean(
    env.LOOM_BRIDGE_EMAIL_INBOUND_WEAK_AUTH_POLICY_CONFIRMED,
    false
  );
  const bridgeInboundAllowAutomaticActuation = parseBoolean(
    env.LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_AUTOMATIC_ACTUATION,
    false
  );
  const bridgeInboundAutomationConfirmed = parseBoolean(
    env.LOOM_BRIDGE_EMAIL_INBOUND_AUTOMATION_CONFIRMED,
    false
  );
  const adminToken = String(env.LOOM_ADMIN_TOKEN || "").trim();

  if (!publicService) {
    warnings.push("LOOM_PUBLIC_SERVICE is false; strict inbound bridge policy checks are primarily for public deployments.");
  } else {
    checks.push("LOOM_PUBLIC_SERVICE=true");
  }

  if (!bridgeInboundEnabled) {
    warnings.push("LOOM_BRIDGE_EMAIL_INBOUND_ENABLED=false; inbound bridge surface is disabled.");
  } else {
    checks.push("LOOM_BRIDGE_EMAIL_INBOUND_ENABLED=true");
  }

  if (publicService && bridgeInboundEnabled && !bridgeInboundPublicConfirmed) {
    errors.push("LOOM_BRIDGE_EMAIL_INBOUND_PUBLIC_CONFIRMED=true is required when inbound bridge is enabled on public service.");
  } else if (publicService && bridgeInboundEnabled) {
    checks.push("LOOM_BRIDGE_EMAIL_INBOUND_PUBLIC_CONFIRMED=true");
  }

  if (bridgeInboundEnabled && bridgeInboundRequireAdminToken && !adminToken) {
    errors.push("LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_ADMIN_TOKEN=true requires LOOM_ADMIN_TOKEN.");
  } else if (bridgeInboundEnabled && bridgeInboundRequireAdminToken) {
    checks.push("Inbound bridge admin token gate is enabled");
  }

  if (publicService && bridgeInboundEnabled) {
    const strictPublicInboundPolicyEnabled =
      bridgeInboundRequireAdminToken &&
      bridgeInboundRequireAuthResults &&
      bridgeInboundRequireDmarcPass &&
      bridgeInboundRejectOnAuthFailure;
    if (!strictPublicInboundPolicyEnabled && !bridgeInboundWeakAuthPolicyConfirmed) {
      errors.push(
        "Weak public inbound bridge auth policy detected; enforce strict policy or set LOOM_BRIDGE_EMAIL_INBOUND_WEAK_AUTH_POLICY_CONFIRMED=true."
      );
    } else if (strictPublicInboundPolicyEnabled) {
      checks.push("Strict public inbound bridge auth policy is enabled");
    } else {
      warnings.push("Weak public inbound bridge auth policy is explicitly confirmed.");
    }

    if (!bridgeInboundRejectOnAuthFailure && !bridgeInboundQuarantineOnAuthFailure) {
      errors.push("Inbound auth failures are neither rejected nor quarantined; enable at least one mitigation.");
    }

    if (bridgeInboundAllowAutomaticActuation && !bridgeInboundAutomationConfirmed) {
      errors.push(
        "LOOM_BRIDGE_EMAIL_INBOUND_ALLOW_AUTOMATIC_ACTUATION=true requires LOOM_BRIDGE_EMAIL_INBOUND_AUTOMATION_CONFIRMED=true on public service."
      );
    } else if (bridgeInboundAllowAutomaticActuation) {
      warnings.push("Inbound bridge automatic actuation is enabled with explicit confirmation.");
    } else {
      checks.push("Inbound bridge non-actuating default is enforced");
    }
  }

  if (!bridgeInboundQuarantineOnAuthFailure) {
    warnings.push("LOOM_BRIDGE_EMAIL_INBOUND_QUARANTINE_ON_AUTH_FAILURE=false; only immediate rejection path is available.");
  }

  const baseUrl = args.baseUrl || env.LOOM_BASE_URL || null;
  const bearerToken = args.bearerToken || env.LOOM_BRIDGE_INBOUND_AUDIT_BEARER_TOKEN || null;
  const runtimeAdminToken = args.adminToken || adminToken || null;
  if (baseUrl || bearerToken) {
    if (!baseUrl || !bearerToken) {
      warnings.push("Runtime inbound bridge probe skipped (both --base-url and --bearer-token are required).");
    } else {
      const probeUrl = new URL("/v1/bridge/email/inbound", baseUrl).toString();
      const probeBody = JSON.stringify({
        smtp_from: "Probe Sender <probe@example.test>",
        rcpt_to: ["probe@example.test"],
        text: "inbound bridge hardening probe"
      });
      try {
        if (bridgeInboundEnabled && bridgeInboundRequireAdminToken) {
          const withoutAdmin = await fetchJson(probeUrl, {
            method: "POST",
            timeoutMs: args.timeoutMs,
            headers: {
              authorization: `Bearer ${bearerToken}`,
              "content-type": "application/json"
            },
            body: probeBody
          });
          if (withoutAdmin.response.status !== 403) {
            errors.push(
              `Runtime probe expected HTTP 403 without x-loom-admin-token, got ${withoutAdmin.response.status}.`
            );
          } else {
            checks.push("Runtime probe confirmed inbound bridge admin-token enforcement (403 without admin token)");
          }

          if (!runtimeAdminToken) {
            warnings.push("Runtime positive probe skipped (no admin token available for --admin-token or LOOM_ADMIN_TOKEN).");
          } else {
            const withAdmin = await fetchJson(probeUrl, {
              method: "POST",
              timeoutMs: args.timeoutMs,
              headers: {
                authorization: `Bearer ${bearerToken}`,
                "x-loom-admin-token": runtimeAdminToken,
                "content-type": "application/json"
              },
              body: probeBody
            });
            if (withAdmin.response.status === 403) {
              errors.push("Runtime positive probe failed: admin token was rejected for inbound bridge route.");
            } else {
              checks.push(`Runtime probe accepted admin-gated request path (HTTP ${withAdmin.response.status})`);
            }
          }
        } else if (!bridgeInboundEnabled) {
          const disabledProbe = await fetchJson(probeUrl, {
            method: "POST",
            timeoutMs: args.timeoutMs,
            headers: {
              authorization: `Bearer ${bearerToken}`,
              "content-type": "application/json"
            },
            body: probeBody
          });
          if (disabledProbe.response.status !== 404) {
            warnings.push(`Runtime probe expected 404 for disabled inbound bridge, got ${disabledProbe.response.status}.`);
          } else {
            checks.push("Runtime probe confirmed inbound bridge route is disabled (404)");
          }
        } else {
          warnings.push("Runtime probe skipped admin-gate check because LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_ADMIN_TOKEN=false.");
        }
      } catch (error) {
        errors.push(`Runtime inbound bridge probe error: ${error?.message || String(error)}`);
      }
    }
  } else {
    warnings.push("Runtime inbound bridge probe skipped (no --base-url/--bearer-token provided).");
  }

  console.log("\nInbound bridge hardening summary:");
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
  console.log("\nPASSED: inbound bridge hardening checks succeeded.");
}

main();
