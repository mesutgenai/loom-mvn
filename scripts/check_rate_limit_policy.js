#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const DEFAULTS = {
  apiWindowMs: 60000,
  apiDefaultMax: 2000,
  apiSensitiveMax: 120,
  identityWindowMs: 60000,
  identityDefaultMax: 2000,
  identitySensitiveMax: 400,
  federationNodeWindowMs: 60000,
  federationNodeMax: 120,
  federationGlobalWindowMs: 60000,
  federationGlobalMax: 1000
};

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

function parsePositiveIntStrict(value) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
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
    adminToken: null,
    timeoutMs: 10000,
    allowDefaults: false
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
    if (arg === "--admin-token" && i + 1 < argv.length) {
      args.adminToken = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--timeout-ms" && i + 1 < argv.length) {
      args.timeoutMs = parsePositiveInt(argv[i + 1], 10000);
      i += 1;
      continue;
    }
    if (arg === "--allow-defaults") {
      args.allowDefaults = true;
      continue;
    }
  }
  return args;
}

function hasExplicitValue(env, key) {
  return String(env[key] || "").trim().length > 0;
}

async function fetchJson(url, options = {}) {
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs || 10000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: options.method || "GET",
      headers: options.headers || {},
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

function validateNumericEnv(env, key, fallback, errors) {
  if (!hasExplicitValue(env, key)) {
    return fallback;
  }
  const strict = parsePositiveIntStrict(env[key]);
  if (strict == null) {
    errors.push(`${key} must be a positive integer.`);
    return fallback;
  }
  return strict;
}

function compareRuntimeValue(path, expected, actual, errors, warnings, checks) {
  if (actual == null) {
    warnings.push(`Runtime policy did not include ${path}; skipping runtime match check.`);
    return;
  }
  if (Number(actual) !== Number(expected)) {
    errors.push(`Runtime ${path} mismatch: expected ${expected}, got ${actual}.`);
  } else {
    checks.push(`Runtime ${path}=${expected}`);
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

  const checks = [];
  const warnings = [];
  const errors = [];

  const publicService = parseBoolean(env.LOOM_PUBLIC_SERVICE, false);
  if (!publicService) {
    warnings.push("LOOM_PUBLIC_SERVICE is false; rate-limit policy hardening gate is primarily for public deployments.");
  } else {
    checks.push("LOOM_PUBLIC_SERVICE=true");
  }

  const values = {
    apiWindowMs: validateNumericEnv(env, "LOOM_RATE_LIMIT_WINDOW_MS", DEFAULTS.apiWindowMs, errors),
    apiDefaultMax: validateNumericEnv(env, "LOOM_RATE_LIMIT_DEFAULT_MAX", DEFAULTS.apiDefaultMax, errors),
    apiSensitiveMax: validateNumericEnv(env, "LOOM_RATE_LIMIT_SENSITIVE_MAX", DEFAULTS.apiSensitiveMax, errors),
    identityWindowMs: validateNumericEnv(
      env,
      "LOOM_IDENTITY_RATE_LIMIT_WINDOW_MS",
      DEFAULTS.identityWindowMs,
      errors
    ),
    identityDefaultMax: validateNumericEnv(
      env,
      "LOOM_IDENTITY_RATE_LIMIT_DEFAULT_MAX",
      DEFAULTS.identityDefaultMax,
      errors
    ),
    identitySensitiveMax: validateNumericEnv(
      env,
      "LOOM_IDENTITY_RATE_LIMIT_SENSITIVE_MAX",
      DEFAULTS.identitySensitiveMax,
      errors
    ),
    federationNodeWindowMs: validateNumericEnv(
      env,
      "LOOM_FEDERATION_NODE_RATE_WINDOW_MS",
      DEFAULTS.federationNodeWindowMs,
      errors
    ),
    federationNodeMax: validateNumericEnv(env, "LOOM_FEDERATION_NODE_RATE_MAX", DEFAULTS.federationNodeMax, errors),
    federationGlobalWindowMs: validateNumericEnv(
      env,
      "LOOM_FEDERATION_GLOBAL_RATE_WINDOW_MS",
      DEFAULTS.federationGlobalWindowMs,
      errors
    ),
    federationGlobalMax: validateNumericEnv(
      env,
      "LOOM_FEDERATION_GLOBAL_RATE_MAX",
      DEFAULTS.federationGlobalMax,
      errors
    )
  };

  if (values.apiSensitiveMax > values.apiDefaultMax) {
    errors.push("LOOM_RATE_LIMIT_SENSITIVE_MAX must be <= LOOM_RATE_LIMIT_DEFAULT_MAX.");
  } else {
    checks.push("API sensitive/default rate relationship is valid");
  }

  if (values.identitySensitiveMax > values.identityDefaultMax) {
    errors.push("LOOM_IDENTITY_RATE_LIMIT_SENSITIVE_MAX must be <= LOOM_IDENTITY_RATE_LIMIT_DEFAULT_MAX.");
  } else {
    checks.push("Identity sensitive/default rate relationship is valid");
  }

  if (values.federationNodeMax > values.federationGlobalMax) {
    errors.push("LOOM_FEDERATION_NODE_RATE_MAX must be <= LOOM_FEDERATION_GLOBAL_RATE_MAX.");
  } else {
    checks.push("Federation node/global rate relationship is valid");
  }

  if (publicService) {
    const requiredKeys = [
      "LOOM_RATE_LIMIT_WINDOW_MS",
      "LOOM_RATE_LIMIT_DEFAULT_MAX",
      "LOOM_RATE_LIMIT_SENSITIVE_MAX",
      "LOOM_IDENTITY_RATE_LIMIT_WINDOW_MS",
      "LOOM_IDENTITY_RATE_LIMIT_DEFAULT_MAX",
      "LOOM_IDENTITY_RATE_LIMIT_SENSITIVE_MAX",
      "LOOM_FEDERATION_NODE_RATE_WINDOW_MS",
      "LOOM_FEDERATION_NODE_RATE_MAX",
      "LOOM_FEDERATION_GLOBAL_RATE_WINDOW_MS",
      "LOOM_FEDERATION_GLOBAL_RATE_MAX"
    ];
    for (const key of requiredKeys) {
      if (!hasExplicitValue(env, key)) {
        errors.push(`${key} must be explicitly set for public-service rate-limit policy.`);
      }
    }

    if (!args.allowDefaults) {
      const defaultsToAvoid = [
        ["LOOM_RATE_LIMIT_DEFAULT_MAX", values.apiDefaultMax, DEFAULTS.apiDefaultMax],
        ["LOOM_RATE_LIMIT_SENSITIVE_MAX", values.apiSensitiveMax, DEFAULTS.apiSensitiveMax],
        ["LOOM_IDENTITY_RATE_LIMIT_DEFAULT_MAX", values.identityDefaultMax, DEFAULTS.identityDefaultMax],
        ["LOOM_IDENTITY_RATE_LIMIT_SENSITIVE_MAX", values.identitySensitiveMax, DEFAULTS.identitySensitiveMax],
        ["LOOM_FEDERATION_NODE_RATE_MAX", values.federationNodeMax, DEFAULTS.federationNodeMax],
        ["LOOM_FEDERATION_GLOBAL_RATE_MAX", values.federationGlobalMax, DEFAULTS.federationGlobalMax]
      ];
      for (const [key, actual, defaultValue] of defaultsToAvoid) {
        if (Number(actual) === Number(defaultValue)) {
          errors.push(`${key} is still at default (${defaultValue}); tune from measured traffic or pass --allow-defaults.`);
        }
      }
    }
  }

  const baseUrl = args.baseUrl || env.LOOM_BASE_URL || null;
  const adminToken = args.adminToken || env.LOOM_ADMIN_TOKEN || null;
  if (baseUrl || adminToken) {
    if (!baseUrl || !adminToken) {
      warnings.push("Runtime policy check skipped (both --base-url and --admin-token are required).");
    } else {
      try {
        const url = new URL("/v1/admin/status", baseUrl).toString();
        const { response, json } = await fetchJson(url, {
          timeoutMs: args.timeoutMs,
          headers: {
            "x-loom-admin-token": adminToken
          }
        });
        if (!response.ok || !json) {
          errors.push(`Runtime policy check failed: HTTP ${response.status}`);
        } else {
          checks.push("Runtime policy snapshot fetched from /v1/admin/status");
          compareRuntimeValue(
            "federation_inbound_policy.rate_limit_window_ms",
            values.federationNodeWindowMs,
            json?.federation_inbound_policy?.rate_limit_window_ms,
            errors,
            warnings,
            checks
          );
          compareRuntimeValue(
            "federation_inbound_policy.rate_limit_max",
            values.federationNodeMax,
            json?.federation_inbound_policy?.rate_limit_max,
            errors,
            warnings,
            checks
          );
          compareRuntimeValue(
            "federation_inbound_policy.global_rate_limit_window_ms",
            values.federationGlobalWindowMs,
            json?.federation_inbound_policy?.global_rate_limit_window_ms,
            errors,
            warnings,
            checks
          );
          compareRuntimeValue(
            "federation_inbound_policy.global_rate_limit_max",
            values.federationGlobalMax,
            json?.federation_inbound_policy?.global_rate_limit_max,
            errors,
            warnings,
            checks
          );
          compareRuntimeValue(
            "api_rate_limit_policy.window_ms",
            values.apiWindowMs,
            json?.api_rate_limit_policy?.window_ms,
            errors,
            warnings,
            checks
          );
          compareRuntimeValue(
            "api_rate_limit_policy.default_max",
            values.apiDefaultMax,
            json?.api_rate_limit_policy?.default_max,
            errors,
            warnings,
            checks
          );
          compareRuntimeValue(
            "api_rate_limit_policy.sensitive_max",
            values.apiSensitiveMax,
            json?.api_rate_limit_policy?.sensitive_max,
            errors,
            warnings,
            checks
          );
          compareRuntimeValue(
            "identity_rate_limit_policy.window_ms",
            values.identityWindowMs,
            json?.identity_rate_limit_policy?.window_ms,
            errors,
            warnings,
            checks
          );
          compareRuntimeValue(
            "identity_rate_limit_policy.default_max",
            values.identityDefaultMax,
            json?.identity_rate_limit_policy?.default_max,
            errors,
            warnings,
            checks
          );
          compareRuntimeValue(
            "identity_rate_limit_policy.sensitive_max",
            values.identitySensitiveMax,
            json?.identity_rate_limit_policy?.sensitive_max,
            errors,
            warnings,
            checks
          );
        }
      } catch (error) {
        errors.push(`Runtime policy check error: ${error?.message || String(error)}`);
      }
    }
  } else {
    warnings.push("Runtime policy check skipped (no --base-url/--admin-token provided).");
  }

  console.log("\nRate-limit policy summary:");
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
  console.log("\nPASSED: rate-limit policy checks succeeded.");
}

main();
