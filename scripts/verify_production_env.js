#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

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

function loadEnvFile(filePath) {
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
  const result = {
    envFile: null
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--env-file" && i + 1 < argv.length) {
      result.envFile = argv[i + 1];
      i += 1;
    }
  }
  return result;
}

const args = parseArgs(process.argv.slice(2));
const env = { ...process.env };

if (args.envFile) {
  const envFilePath = resolve(args.envFile);
  if (!existsSync(envFilePath)) {
    console.error(`ERROR: env file not found: ${envFilePath}`);
    process.exit(1);
  }
  const loaded = loadEnvFile(envFilePath);
  Object.assign(env, loaded);
  console.log(`Loaded env file: ${envFilePath}`);
}

const errors = [];
const warnings = [];
const checks = [];

function ok(message) {
  checks.push(`PASS: ${message}`);
}
function fail(message) {
  errors.push(message);
}
function warn(message) {
  warnings.push(message);
}

const publicService = parseBoolean(env.LOOM_PUBLIC_SERVICE, false);
const nativeTlsEnabled = parseBoolean(env.LOOM_NATIVE_TLS_ENABLED, false);
const requireTlsProxy = parseBoolean(env.LOOM_REQUIRE_TLS_PROXY, true);
const tlsProxyConfirmed = parseBoolean(env.LOOM_TLS_PROXY_CONFIRMED, false);
const requireHttpsFromProxy = parseBoolean(
  env.LOOM_REQUIRE_HTTPS_FROM_PROXY,
  publicService && !nativeTlsEnabled
);
const trustProxy = parseBoolean(env.LOOM_TRUST_PROXY, false);
const trustProxyAllowlist = parseCommaList(env.LOOM_TRUST_PROXY_ALLOWLIST);
const metricsPublic = parseBoolean(env.LOOM_METRICS_PUBLIC, false);
const allowPublicMetricsOnPublicBind = parseBoolean(
  env.LOOM_ALLOW_PUBLIC_METRICS_ON_PUBLIC_BIND,
  false
);
const allowOpenOutboundHostsOnPublicBind = parseBoolean(
  env.LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND,
  false
);
const remoteIdentityResolveEnabled = parseBoolean(
  env.LOOM_FEDERATION_REMOTE_IDENTITY_RESOLVE_ENABLED,
  true
);
const demoPublicReads = parseBoolean(env.LOOM_DEMO_PUBLIC_READS, false);
const demoPublicReadsConfirmed = parseBoolean(env.LOOM_DEMO_PUBLIC_READS_CONFIRMED, false);
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
const pgUrl = String(env.LOOM_PG_URL || "").trim();
const pgSslEnabled = parseBoolean(env.LOOM_PG_SSL, false);

if (!publicService) {
  fail("LOOM_PUBLIC_SERVICE must be true for internet-facing production.");
} else {
  ok("LOOM_PUBLIC_SERVICE=true");
}

if (publicService) {
  const tlsModeValid = nativeTlsEnabled || (requireTlsProxy && tlsProxyConfirmed);
  if (!tlsModeValid) {
    fail(
      "Public service must use native TLS (LOOM_NATIVE_TLS_ENABLED=true) or confirmed TLS proxy (LOOM_REQUIRE_TLS_PROXY=true and LOOM_TLS_PROXY_CONFIRMED=true)."
    );
  } else {
    ok("Public TLS mode is configured");
  }

  if (!nativeTlsEnabled && !requireHttpsFromProxy) {
    fail("LOOM_REQUIRE_HTTPS_FROM_PROXY must be true when using proxy TLS termination.");
  } else if (!nativeTlsEnabled) {
    ok("LOOM_REQUIRE_HTTPS_FROM_PROXY=true");
  }

  if (!nativeTlsEnabled) {
    if (!trustProxy && trustProxyAllowlist.length === 0) {
      fail("Configure LOOM_TRUST_PROXY=true or LOOM_TRUST_PROXY_ALLOWLIST when proxy-terminating TLS.");
    } else {
      ok("Trusted proxy headers are configured");
    }
  }

  if (!String(env.LOOM_ADMIN_TOKEN || "").trim()) {
    fail("LOOM_ADMIN_TOKEN is required for public service.");
  } else {
    ok("LOOM_ADMIN_TOKEN is set");
  }

  if (!pgUrl) {
    fail("LOOM_PG_URL is required for durable production persistence.");
  } else {
    ok("LOOM_PG_URL is set");
  }

  if (!pgSslEnabled) {
    warn("LOOM_PG_SSL is disabled; enable TLS for managed/remote PostgreSQL.");
  } else {
    ok("LOOM_PG_SSL=true");
  }

  if (metricsPublic && !allowPublicMetricsOnPublicBind) {
    fail(
      "LOOM_METRICS_PUBLIC=true requires LOOM_ALLOW_PUBLIC_METRICS_ON_PUBLIC_BIND=true on public service."
    );
  } else if (!metricsPublic) {
    ok("Metrics remain authenticated (LOOM_METRICS_PUBLIC=false)");
  } else {
    warn("Metrics are public; confirm this is intentional.");
  }

  if (demoPublicReads && !demoPublicReadsConfirmed) {
    fail("LOOM_DEMO_PUBLIC_READS=true requires LOOM_DEMO_PUBLIC_READS_CONFIRMED=true.");
  } else if (!demoPublicReads) {
    ok("Demo public reads disabled");
  } else {
    warn("Demo public reads enabled for public service.");
  }

  if (!bridgeInboundEnabled) {
    warn("Inbound bridge is disabled (LOOM_BRIDGE_EMAIL_INBOUND_ENABLED=false).");
  } else {
    ok("Inbound bridge route is enabled");
    if (!bridgeInboundPublicConfirmed) {
      fail("LOOM_BRIDGE_EMAIL_INBOUND_PUBLIC_CONFIRMED=true is required on public service.");
    } else {
      ok("LOOM_BRIDGE_EMAIL_INBOUND_PUBLIC_CONFIRMED=true");
    }

    if (!bridgeInboundRequireAdminToken) {
      if (!bridgeInboundWeakAuthPolicyConfirmed) {
        fail(
          "LOOM_BRIDGE_EMAIL_INBOUND_REQUIRE_ADMIN_TOKEN=false requires LOOM_BRIDGE_EMAIL_INBOUND_WEAK_AUTH_POLICY_CONFIRMED=true on public service."
        );
      } else {
        warn("Inbound bridge admin token requirement is disabled with explicit weak-policy confirmation.");
      }
    } else {
      ok("Inbound bridge admin-token gate enabled");
    }

    const strictInboundPolicy =
      bridgeInboundRequireAdminToken &&
      bridgeInboundRequireAuthResults &&
      bridgeInboundRequireDmarcPass &&
      bridgeInboundRejectOnAuthFailure;
    if (!strictInboundPolicy && !bridgeInboundWeakAuthPolicyConfirmed) {
      fail(
        "Weak public inbound bridge auth policy detected; set strict defaults or LOOM_BRIDGE_EMAIL_INBOUND_WEAK_AUTH_POLICY_CONFIRMED=true."
      );
    } else if (strictInboundPolicy) {
      ok("Strict inbound auth-results/DMARC/reject policy enabled");
    } else {
      warn("Weak inbound bridge auth policy explicitly confirmed.");
    }

    if (!bridgeInboundRejectOnAuthFailure && !bridgeInboundQuarantineOnAuthFailure) {
      fail("Inbound bridge auth failures are neither rejected nor quarantined.");
    }
  }

  if (!allowOpenOutboundHostsOnPublicBind) {
    const federationAllowlist = parseCommaList(env.LOOM_FEDERATION_HOST_ALLOWLIST);
    const bootstrapAllowlist = parseCommaList(env.LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST);
    const webhookAllowlist = parseCommaList(env.LOOM_WEBHOOK_HOST_ALLOWLIST);
    const remoteIdentityAllowlist = parseCommaList(env.LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST);

    if (federationAllowlist.length === 0) {
      fail("LOOM_FEDERATION_HOST_ALLOWLIST is required on public service.");
    } else {
      ok("LOOM_FEDERATION_HOST_ALLOWLIST configured");
    }
    if (bootstrapAllowlist.length === 0) {
      fail("LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST is required on public service.");
    } else {
      ok("LOOM_FEDERATION_BOOTSTRAP_HOST_ALLOWLIST configured");
    }
    if (webhookAllowlist.length === 0) {
      fail("LOOM_WEBHOOK_HOST_ALLOWLIST is required on public service.");
    } else {
      ok("LOOM_WEBHOOK_HOST_ALLOWLIST configured");
    }
    if (remoteIdentityResolveEnabled) {
      if (remoteIdentityAllowlist.length === 0) {
        fail(
          "LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST is required when LOOM_FEDERATION_REMOTE_IDENTITY_RESOLVE_ENABLED=true."
        );
      } else {
        ok("LOOM_REMOTE_IDENTITY_HOST_ALLOWLIST configured");
      }
    }
  } else {
    fail("LOOM_ALLOW_OPEN_OUTBOUND_HOSTS_ON_PUBLIC_BIND=true is not allowed for hardened public deployment.");
  }
}

if (nativeTlsEnabled) {
  const certPem = String(env.LOOM_NATIVE_TLS_CERT_PEM || "").trim();
  const certFile = String(env.LOOM_NATIVE_TLS_CERT_FILE || "").trim();
  const keyPem = String(env.LOOM_NATIVE_TLS_KEY_PEM || "").trim();
  const keyFile = String(env.LOOM_NATIVE_TLS_KEY_FILE || "").trim();

  if (!certPem && !certFile) {
    fail("Native TLS is enabled but no certificate configured (LOOM_NATIVE_TLS_CERT_PEM/FILE).");
  } else {
    ok("Native TLS certificate configured");
  }
  if (!keyPem && !keyFile) {
    fail("Native TLS is enabled but no private key configured (LOOM_NATIVE_TLS_KEY_PEM/FILE).");
  } else {
    ok("Native TLS key configured");
  }

  if (certFile && !existsSync(resolve(certFile))) {
    fail(`Native TLS certificate file not found: ${resolve(certFile)}`);
  }
  if (keyFile && !existsSync(resolve(keyFile))) {
    fail(`Native TLS key file not found: ${resolve(keyFile)}`);
  }
}

const statusLines = [
  ...checks.map((line) => `  - ${line}`),
  ...warnings.map((line) => `  - WARN: ${line}`),
  ...errors.map((line) => `  - ERROR: ${line}`)
];

console.log("\nProduction env validation summary:");
for (const line of statusLines) {
  console.log(line);
}

if (errors.length > 0) {
  console.error(`\nFAILED: ${errors.length} blocking issue(s) detected.`);
  process.exit(1);
}

console.log("\nPASSED: production env checks succeeded.");
