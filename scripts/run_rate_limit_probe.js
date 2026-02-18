#!/usr/bin/env node

import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const DEFAULT_BASE_URL = "http://127.0.0.1:8787";
const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_OUTPUT_DIR = "scripts/output/rate-limit-probes";

function parsePositiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function nowStamp() {
  const date = new Date();
  const pad = (value) => String(value).padStart(2, "0");
  return [
    date.getUTCFullYear(),
    pad(date.getUTCMonth() + 1),
    pad(date.getUTCDate()),
    "T",
    pad(date.getUTCHours()),
    pad(date.getUTCMinutes()),
    pad(date.getUTCSeconds()),
    "Z"
  ].join("");
}

function parseJsonOrNull(value) {
  if (value == null) {
    return null;
  }
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function parseArgs(argv) {
  const args = {
    baseUrl: process.env.LOOM_BASE_URL || DEFAULT_BASE_URL,
    timeoutMs: parsePositiveInt(process.env.LOOM_RATE_PROBE_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
    outputDir: process.env.LOOM_RATE_PROBE_OUTPUT_DIR || DEFAULT_OUTPUT_DIR,
    probeId: `probe-${nowStamp()}`,
    defaultPath: "/ready",
    defaultMethod: "GET",
    defaultBody: null,
    defaultRequests: parsePositiveInt(process.env.LOOM_RATE_PROBE_DEFAULT_REQUESTS, 1200),
    sensitivePath: "/v1/auth/challenge",
    sensitiveMethod: "POST",
    sensitiveBody: {
      identity: "loom://missing@node.test",
      key_id: "k_missing_probe"
    },
    sensitiveRequests: parsePositiveInt(process.env.LOOM_RATE_PROBE_SENSITIVE_REQUESTS, 250),
    delayMs: parsePositiveInt(process.env.LOOM_RATE_PROBE_DELAY_MS, 1),
    expectDefaultMax: null,
    expectSensitiveMax: null,
    help: false
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }
    if (arg === "--base-url" && i + 1 < argv.length) {
      args.baseUrl = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--timeout-ms" && i + 1 < argv.length) {
      args.timeoutMs = parsePositiveInt(argv[i + 1], DEFAULT_TIMEOUT_MS);
      i += 1;
      continue;
    }
    if (arg === "--output-dir" && i + 1 < argv.length) {
      args.outputDir = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--probe-id" && i + 1 < argv.length) {
      args.probeId = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--default-path" && i + 1 < argv.length) {
      args.defaultPath = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--default-method" && i + 1 < argv.length) {
      args.defaultMethod = String(argv[i + 1]).toUpperCase();
      i += 1;
      continue;
    }
    if (arg === "--default-body" && i + 1 < argv.length) {
      args.defaultBody = parseJsonOrNull(argv[i + 1]);
      i += 1;
      continue;
    }
    if (arg === "--default-requests" && i + 1 < argv.length) {
      args.defaultRequests = parsePositiveInt(argv[i + 1], args.defaultRequests);
      i += 1;
      continue;
    }
    if (arg === "--sensitive-path" && i + 1 < argv.length) {
      args.sensitivePath = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--sensitive-method" && i + 1 < argv.length) {
      args.sensitiveMethod = String(argv[i + 1]).toUpperCase();
      i += 1;
      continue;
    }
    if (arg === "--sensitive-body" && i + 1 < argv.length) {
      args.sensitiveBody = parseJsonOrNull(argv[i + 1]);
      i += 1;
      continue;
    }
    if (arg === "--sensitive-requests" && i + 1 < argv.length) {
      args.sensitiveRequests = parsePositiveInt(argv[i + 1], args.sensitiveRequests);
      i += 1;
      continue;
    }
    if (arg === "--delay-ms" && i + 1 < argv.length) {
      args.delayMs = parsePositiveInt(argv[i + 1], 1);
      i += 1;
      continue;
    }
    if (arg === "--expect-default-max" && i + 1 < argv.length) {
      args.expectDefaultMax = parsePositiveInt(argv[i + 1], 1);
      i += 1;
      continue;
    }
    if (arg === "--expect-sensitive-max" && i + 1 < argv.length) {
      args.expectSensitiveMax = parsePositiveInt(argv[i + 1], 1);
      i += 1;
      continue;
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage:
  node scripts/run_rate_limit_probe.js [options]

Options:
  --base-url <url>              Base URL (default: ${DEFAULT_BASE_URL})
  --timeout-ms <int>            Request timeout in ms (default: ${DEFAULT_TIMEOUT_MS})
  --output-dir <path>           Output directory (default: ${DEFAULT_OUTPUT_DIR})
  --probe-id <id>               Override probe ID
  --default-path <path>         Default-bucket probe route (default: /ready)
  --default-method <method>     Default probe method (default: GET)
  --default-body <json>         Optional JSON body for default probe
  --default-requests <int>      Number of default probe requests (default: 1200)
  --sensitive-path <path>       Sensitive-bucket probe route (default: /v1/auth/challenge)
  --sensitive-method <method>   Sensitive probe method (default: POST)
  --sensitive-body <json>       JSON body for sensitive probe
  --sensitive-requests <int>    Number of sensitive probe requests (default: 250)
  --delay-ms <int>              Delay between requests in ms (default: 1)
  --expect-default-max <int>    Expected default bucket max for threshold check
  --expect-sensitive-max <int>  Expected sensitive bucket max for threshold check
  -h, --help                    Show help

Examples:
  npm run probe:rate-limits -- --base-url https://loom.example.com --expect-default-max 1000 --expect-sensitive-max 160
  npm run probe:rate-limits -- --base-url http://127.0.0.1:8787 --default-requests 300 --sensitive-requests 80
`);
}

function normalizeBaseUrl(raw) {
  try {
    const url = new URL(raw);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("protocol must be http or https");
    }
    if (!url.pathname.endsWith("/")) {
      url.pathname = `${url.pathname}/`;
    }
    return url.toString();
  } catch (error) {
    throw new Error(`Invalid --base-url: ${raw} (${error.message})`);
  }
}

function statusKey(status) {
  return String(Number(status) || 0);
}

async function requestWithTimeout(url, { method, body, timeoutMs }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method,
      headers: {
        "content-type": "application/json"
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal
    });
    const text = await response.text();
    return {
      status: response.status,
      ok: response.ok,
      text
    };
  } finally {
    clearTimeout(timer);
  }
}

async function runSeries(baseUrl, config) {
  const startedAt = new Date().toISOString();
  const statusCounts = {};
  let first429AtRequest = null;
  const errors = [];
  const samples = [];
  const url = new URL(config.path, baseUrl).toString();
  const startedMs = Date.now();

  for (let i = 1; i <= config.requests; i += 1) {
    try {
      const result = await requestWithTimeout(url, {
        method: config.method,
        body: config.body,
        timeoutMs: config.timeoutMs
      });
      const key = statusKey(result.status);
      statusCounts[key] = (statusCounts[key] || 0) + 1;
      if (result.status === 429 && first429AtRequest == null) {
        first429AtRequest = i;
      }
      if (i <= 5 || i === config.requests || result.status === 429) {
        samples.push({
          index: i,
          status: result.status
        });
      }
    } catch (error) {
      errors.push({
        index: i,
        message: error?.message || String(error)
      });
      if (errors.length >= 5) {
        break;
      }
    }

    if (config.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, config.delayMs));
    }
  }

  return {
    path: config.path,
    method: config.method,
    requests: config.requests,
    started_at: startedAt,
    duration_ms: Date.now() - startedMs,
    first_429_at_request: first429AtRequest,
    status_counts: statusCounts,
    samples,
    errors
  };
}

function evaluateExpectedThreshold(series, expectedMax) {
  if (expectedMax == null) {
    return {
      ok: series.first_429_at_request != null,
      message:
        series.first_429_at_request != null
          ? `first 429 observed at request ${series.first_429_at_request}`
          : "no 429 observed"
    };
  }
  const expectedFirst429 = expectedMax + 1;
  return {
    ok: Number(series.first_429_at_request) === expectedFirst429,
    message:
      series.first_429_at_request == null
        ? `expected first 429 at ${expectedFirst429}, but none observed`
        : `expected first 429 at ${expectedFirst429}, observed at ${series.first_429_at_request}`
  };
}

function buildSummary(report, reportPath) {
  const lines = [];
  lines.push("# Rate Limit Probe Report");
  lines.push("");
  lines.push(`- Probe ID: \`${report.probe_id}\``);
  lines.push(`- Started: \`${report.started_at}\``);
  lines.push(`- Finished: \`${report.finished_at}\``);
  lines.push(`- Base URL: \`${report.base_url}\``);
  lines.push(`- Result: **${report.success ? "PASS" : "FAIL"}**`);
  lines.push("");
  lines.push("## Default Bucket Probe");
  lines.push("");
  lines.push(`- Path: \`${report.default_probe.path}\``);
  lines.push(`- Method: \`${report.default_probe.method}\``);
  lines.push(`- Requests: \`${report.default_probe.requests}\``);
  lines.push(`- First 429: \`${report.default_probe.first_429_at_request ?? "none"}\``);
  lines.push(`- Threshold check: \`${report.default_probe.threshold_check.message}\``);
  lines.push("");
  lines.push("## Sensitive Bucket Probe");
  lines.push("");
  lines.push(`- Path: \`${report.sensitive_probe.path}\``);
  lines.push(`- Method: \`${report.sensitive_probe.method}\``);
  lines.push(`- Requests: \`${report.sensitive_probe.requests}\``);
  lines.push(`- First 429: \`${report.sensitive_probe.first_429_at_request ?? "none"}\``);
  lines.push(`- Threshold check: \`${report.sensitive_probe.threshold_check.message}\``);
  lines.push("");
  lines.push(`- Report JSON: \`${reportPath}\``);
  return lines.join("\n") + "\n";
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const startedAt = new Date().toISOString();
  const baseUrl = normalizeBaseUrl(args.baseUrl);
  const outputRoot = resolve(args.outputDir);
  const runDir = join(outputRoot, args.probeId);
  mkdirSync(runDir, { recursive: true });

  const defaultProbe = await runSeries(baseUrl, {
    path: args.defaultPath,
    method: args.defaultMethod,
    body: args.defaultBody,
    requests: args.defaultRequests,
    timeoutMs: args.timeoutMs,
    delayMs: args.delayMs
  });
  const sensitiveProbe = await runSeries(baseUrl, {
    path: args.sensitivePath,
    method: args.sensitiveMethod,
    body: args.sensitiveBody,
    requests: args.sensitiveRequests,
    timeoutMs: args.timeoutMs,
    delayMs: args.delayMs
  });

  const defaultThreshold = evaluateExpectedThreshold(defaultProbe, args.expectDefaultMax);
  const sensitiveThreshold = evaluateExpectedThreshold(sensitiveProbe, args.expectSensitiveMax);
  defaultProbe.threshold_check = defaultThreshold;
  sensitiveProbe.threshold_check = sensitiveThreshold;

  const report = {
    probe_id: args.probeId,
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    base_url: baseUrl,
    timeout_ms: args.timeoutMs,
    config: {
      default_requests: args.defaultRequests,
      sensitive_requests: args.sensitiveRequests,
      delay_ms: args.delayMs,
      expect_default_max: args.expectDefaultMax,
      expect_sensitive_max: args.expectSensitiveMax
    },
    default_probe: defaultProbe,
    sensitive_probe: sensitiveProbe,
    success:
      defaultThreshold.ok &&
      sensitiveThreshold.ok &&
      defaultProbe.errors.length === 0 &&
      sensitiveProbe.errors.length === 0
  };

  const reportPath = join(runDir, "report.json");
  const summaryPath = join(runDir, "summary.md");
  writeFileSync(reportPath, JSON.stringify(report, null, 2) + "\n");
  writeFileSync(summaryPath, buildSummary(report, reportPath));

  console.log(`Rate-limit probe finished: ${report.success ? "PASS" : "FAIL"}`);
  console.log(`Report: ${reportPath}`);
  console.log(`Summary: ${summaryPath}`);
  if (!report.success) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(`Rate-limit probe failed: ${error?.message || String(error)}`);
  process.exit(1);
});
