#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { isIP } from "node:net";

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

function parseCommaList(value) {
  if (value == null) {
    return [];
  }
  return String(value)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeHostname(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "");
}

function hostnameMatchesAllowlist(hostname, allowlist = []) {
  const normalizedHost = normalizeHostname(hostname);
  if (!normalizedHost) {
    return false;
  }

  for (const rawPattern of allowlist) {
    const pattern = normalizeHostname(rawPattern);
    if (!pattern) {
      continue;
    }
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(2);
      if (suffix && (normalizedHost === suffix || normalizedHost.endsWith(`.${suffix}`))) {
        return true;
      }
      continue;
    }
    if (pattern.startsWith(".")) {
      const suffix = pattern.slice(1);
      if (suffix && (normalizedHost === suffix || normalizedHost.endsWith(`.${suffix}`))) {
        return true;
      }
      continue;
    }
    if (normalizedHost === pattern) {
      return true;
    }
  }
  return false;
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
    if (arg === "--timeout-ms" && i + 1 < argv.length) {
      const parsed = Number(argv[i + 1]);
      args.timeoutMs = Number.isInteger(parsed) && parsed > 0 ? parsed : 10000;
      i += 1;
      continue;
    }
  }
  return args;
}

function validateAllowlistEntries(listName, entries, errors, warnings) {
  if (entries.length === 0) {
    errors.push(`${listName} must not be empty.`);
    return;
  }
  for (const entry of entries) {
    const normalized = normalizeHostname(entry);
    if (!normalized) {
      errors.push(`${listName} includes an empty entry.`);
      continue;
    }
    if (normalized.includes("://") || normalized.includes("/") || normalized.includes("?")) {
      errors.push(`${listName} entry must be hostname/suffix only (no URL): ${entry}`);
      continue;
    }
    if (normalized === "*" || normalized === "*.*") {
      errors.push(`${listName} entry is too broad: ${entry}`);
      continue;
    }

    const stripped = normalized.startsWith("*.") ? normalized.slice(2) : normalized.startsWith(".") ? normalized.slice(1) : normalized;
    const ipVersion = isIP(stripped);
    if (ipVersion === 0) {
      const labels = stripped.split(".").filter(Boolean);
      if (labels.length < 2) {
        errors.push(`${listName} entry is too broad / invalid: ${entry}`);
      }
      if (stripped === "localhost" || stripped.endsWith(".local")) {
        warnings.push(`${listName} entry targets local host namespace: ${entry}`);
      }
    } else if (stripped.startsWith("127.") || stripped === "::1") {
      warnings.push(`${listName} entry targets loopback IP: ${entry}`);
    }
  }
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

function validateNodeUrls(nodes, allowlists, errors, warnings) {
  for (const node of nodes) {
    const nodeId = String(node?.node_id || "unknown");
    if (node?.allow_insecure_http === true) {
      errors.push(`Node ${nodeId} has allow_insecure_http=true.`);
    }
    if (node?.allow_private_network === true) {
      errors.push(`Node ${nodeId} has allow_private_network=true.`);
    }

    const deliverUrlRaw = String(node?.deliver_url || "").trim();
    if (!deliverUrlRaw) {
      warnings.push(`Node ${nodeId} has no explicit deliver_url (using derived default).`);
    } else {
      let deliverUrl;
      try {
        deliverUrl = new URL(deliverUrlRaw);
      } catch {
        errors.push(`Node ${nodeId} has invalid deliver_url.`);
        continue;
      }
      if (deliverUrl.protocol !== "https:") {
        errors.push(`Node ${nodeId} deliver_url is not https.`);
      }
      if (!hostnameMatchesAllowlist(deliverUrl.hostname, allowlists.federation)) {
        errors.push(`Node ${nodeId} deliver_url host is not in LOOM_FEDERATION_HOST_ALLOWLIST: ${deliverUrl.hostname}`);
      }
    }

    const identityResolveUrlRaw = String(node?.identity_resolve_url || "").trim();
    if (identityResolveUrlRaw) {
      let identityUrl;
      try {
        const probe = identityResolveUrlRaw.includes("{identity}")
          ? identityResolveUrlRaw.replace("{identity}", encodeURIComponent("loom://probe@example.test"))
          : identityResolveUrlRaw;
        identityUrl = new URL(probe);
      } catch {
        errors.push(`Node ${nodeId} has invalid identity_resolve_url.`);
        continue;
      }
      if (identityUrl.protocol !== "https:") {
        errors.push(`Node ${nodeId} identity_resolve_url is not https.`);
      }
      if (!hostnameMatchesAllowlist(identityUrl.hostname, allowlists.remoteIdentity)) {
        errors.push(
          `Node ${nodeId} identity_resolve_url host is not in LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST (or federation fallback): ${identityUrl.hostname}`
        );
      }
    }
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

  const errors = [];
  const warnings = [];
  const checks = [];

  const publicService = parseBoolean(env.LOOM_PUBLIC_SERVICE, false);
  const allowOpenOutbound = parseBoolean(env.LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND, false);
  const allowlists = {
    federation: parseCommaList(env.LOOM_FEDERATION_HOST_ALLOWLIST),
    bootstrap: parseCommaList(env.LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST),
    remoteIdentity: parseCommaList(env.LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST),
    webhook: parseCommaList(env.LOOM_WEBHOOK_HOST_ALLOWLIST)
  };

  if (!publicService) {
    warnings.push("LOOM_PUBLIC_SERVICE is false; federation outbound controls are typically enforced for public deployments.");
  } else {
    checks.push("LOOM_PUBLIC_SERVICE=true");
  }

  if (allowOpenOutbound) {
    errors.push("LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=true is not allowed for hardened public deployment.");
  }

  validateAllowlistEntries("LOOM_FEDERATION_HOST_ALLOWLIST", allowlists.federation, errors, warnings);
  validateAllowlistEntries("LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST", allowlists.bootstrap, errors, warnings);
  validateAllowlistEntries("LOOM_WEBHOOK_HOST_ALLOWLIST", allowlists.webhook, errors, warnings);

  const remoteIdentityResolveEnabled = parseBoolean(env.LOOM_FEDERATION_REMOTE_IDENTITY_RESOLVE_ENABLED, true);
  if (remoteIdentityResolveEnabled) {
    const effectiveRemoteIdentityAllowlist =
      allowlists.remoteIdentity.length > 0 ? allowlists.remoteIdentity : allowlists.federation;
    validateAllowlistEntries(
      "LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST",
      effectiveRemoteIdentityAllowlist,
      errors,
      warnings
    );
  }

  if (errors.length === 0) {
    checks.push("Static allowlist policy checks passed");
  }

  const baseUrl = args.baseUrl || env.LOOM_BASE_URL || null;
  const bearerToken = args.bearerToken || env.LOOM_FEDERATION_AUDIT_BEARER_TOKEN || null;
  if (baseUrl || bearerToken) {
    if (!baseUrl || !bearerToken) {
      warnings.push("Runtime federation node audit skipped (both --base-url and --bearer-token are required).");
    } else {
      try {
        const url = new URL("/v1/federation/nodes", baseUrl).toString();
        const { response, json } = await fetchJson(url, {
          timeoutMs: args.timeoutMs,
          headers: {
            authorization: `Bearer ${bearerToken}`
          }
        });
        if (!response.ok || !json || !Array.isArray(json.nodes)) {
          errors.push(`Runtime federation node audit failed: HTTP ${response.status}`);
        } else {
          checks.push(`Runtime audit fetched ${json.nodes.length} federation node(s)`);
          const effectiveRemoteIdentityAllowlist =
            allowlists.remoteIdentity.length > 0 ? allowlists.remoteIdentity : allowlists.federation;
          validateNodeUrls(
            json.nodes,
            {
              federation: allowlists.federation,
              remoteIdentity: effectiveRemoteIdentityAllowlist
            },
            errors,
            warnings
          );
        }
      } catch (error) {
        errors.push(`Runtime federation node audit error: ${error?.message || String(error)}`);
      }
    }
  } else {
    warnings.push("Runtime federation node audit skipped (no --base-url/--bearer-token provided).");
  }

  console.log("\nFederation controls summary:");
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
  console.log("\nPASSED: federation outbound control checks succeeded.");
}

main();
