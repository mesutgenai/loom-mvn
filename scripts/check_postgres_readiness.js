#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Pool } from "pg";

const REQUIRED_TABLES = [
  "loom_meta",
  "loom_state",
  "loom_audit",
  "loom_federation_rate_events",
  "loom_federation_abuse_events",
  "loom_federation_reputation",
  "loom_federation_challenges",
  "loom_outbox_claims"
];

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

function parseEnvFile(path) {
  const parsed = {};
  const source = readFileSync(path, "utf-8");
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
    envFile: null,
    connectionString: null,
    expectedSchema: 3,
    timeoutMs: 10000
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--env-file" && i + 1 < argv.length) {
      result.envFile = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--connection-string" && i + 1 < argv.length) {
      result.connectionString = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--expected-schema" && i + 1 < argv.length) {
      result.expectedSchema = parsePositiveInt(argv[i + 1], 3);
      i += 1;
      continue;
    }
    if (arg === "--timeout-ms" && i + 1 < argv.length) {
      result.timeoutMs = parsePositiveInt(argv[i + 1], 10000);
      i += 1;
      continue;
    }
  }

  return result;
}

function redactConnectionString(connectionString) {
  if (!connectionString) {
    return "";
  }
  try {
    const url = new URL(connectionString);
    if (url.password) {
      url.password = "***";
    }
    return url.toString();
  } catch {
    return "***";
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const env = { ...process.env };
  if (args.envFile) {
    Object.assign(env, parseEnvFile(resolve(args.envFile)));
    console.log(`Loaded env file: ${resolve(args.envFile)}`);
  }

  const connectionString = args.connectionString || env.LOOM_PG_URL;
  if (!String(connectionString || "").trim()) {
    console.error("ERROR: LOOM_PG_URL (or --connection-string) is required.");
    process.exit(1);
  }

  const useSsl = parseBoolean(env.LOOM_PG_SSL, false);
  const rejectUnauthorized = parseBoolean(env.LOOM_PG_SSL_REJECT_UNAUTHORIZED, true);
  const stateKey = String(env.LOOM_PG_STATE_KEY || "default").trim() || "default";
  const timeoutMs = args.timeoutMs;

  const checks = [];
  const warnings = [];
  const errors = [];

  const pool = new Pool({
    connectionString,
    connectionTimeoutMillis: timeoutMs,
    ssl: useSsl ? { rejectUnauthorized } : undefined
  });

  try {
    const client = await pool.connect();
    try {
      checks.push(`Connected to PostgreSQL: ${redactConnectionString(connectionString)}`);

      const ping = await client.query("SELECT NOW() AS ts");
      checks.push(`DB ping ok: ${ping.rows[0]?.ts ? "timestamp returned" : "no timestamp"}`);

      const tableRows = await client.query(
        `
          SELECT table_name
          FROM information_schema.tables
          WHERE table_schema = 'public'
            AND table_name = ANY($1::text[])
        `,
        [REQUIRED_TABLES]
      );
      const present = new Set(tableRows.rows.map((row) => row.table_name));
      const missing = REQUIRED_TABLES.filter((name) => !present.has(name));
      if (missing.length > 0) {
        errors.push(`Missing required tables: ${missing.join(", ")}`);
      } else {
        checks.push(`All required tables present (${REQUIRED_TABLES.length})`);
      }

      const schemaResult = await client.query(
        `
          SELECT (value_json->>'version')::int AS version
          FROM loom_meta
          WHERE key = 'schema_version'
          LIMIT 1
        `
      );
      if (schemaResult.rowCount === 0) {
        errors.push("loom_meta.schema_version is missing.");
      } else {
        const actualSchema = Number(schemaResult.rows[0].version);
        checks.push(`schema_version=${actualSchema}`);
        if (actualSchema !== args.expectedSchema) {
          errors.push(`Schema version mismatch: expected ${args.expectedSchema}, got ${actualSchema}.`);
        }
      }

      const stateResult = await client.query(
        `
          SELECT id, updated_at
          FROM loom_state
          WHERE id = $1
          LIMIT 1
        `,
        [stateKey]
      );
      if (stateResult.rowCount === 0) {
        warnings.push(`No loom_state row found yet for state_key="${stateKey}" (may be normal on first boot).`);
      } else {
        checks.push(`State row present for state_key="${stateKey}"`);
      }

      if (!useSsl) {
        warnings.push("LOOM_PG_SSL is not enabled; enable TLS for non-local database connections.");
      } else {
        checks.push(`Postgres TLS enabled (rejectUnauthorized=${rejectUnauthorized})`);
      }
    } finally {
      client.release();
    }
  } catch (error) {
    errors.push(`Postgres readiness check failed: ${error?.message || String(error)}`);
  } finally {
    await pool.end().catch(() => {});
  }

  console.log("\nPostgres readiness summary:");
  for (const entry of checks) {
    console.log(`  - PASS: ${entry}`);
  }
  for (const entry of warnings) {
    console.log(`  - WARN: ${entry}`);
  }
  for (const entry of errors) {
    console.log(`  - ERROR: ${entry}`);
  }

  if (errors.length > 0) {
    console.error(`\nFAILED: ${errors.length} blocking issue(s) detected.`);
    process.exit(1);
  }

  console.log("\nPASSED: Postgres readiness checks succeeded.");
}

main();
