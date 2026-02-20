#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { isIP } from "node:net";

import { LoomStore } from "../src/node/store.js";

const URL_RE = /\bhttps?:\/\/[^\s<>"'`]+/gi;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const LOOM_IDENTITY_RE = /\bloom:\/\/[A-Za-z0-9._%+\-~]+@[A-Za-z0-9.-]+\b/g;
const SHORTENER_HOSTS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "is.gd",
  "ow.ly",
  "shorturl.at",
  "rb.gy"
]);
const DECISIONS = Object.freeze(["allow", "quarantine", "reject"]);
const SOURCES = new Set(["federation", "bridge_email", "all"]);
const PROFILES = new Set(["strict", "balanced", "agent"]);

function printUsage() {
  console.error(
    [
      "Usage:",
      "  node scripts/build_content_filter_corpus.js (--data-dir <path> | --state-file <path> | --backup-file <path> | --decision-log-file <path>) [options]",
      "",
      "Options:",
      "  --state-file <path>                     Path to raw LOOM state JSON file",
      "  --backup-file <path>                    Path to LOOM backup export JSON (uses .state payload)",
      "  --decision-log-file <path>              Path to content-filter decision NDJSON telemetry",
      "  --source <federation|bridge_email|all>   Filter source class (default: federation)",
      "  --profile <strict|balanced|agent>        Evaluation profile (default: agent)",
      "  --limit <n>                              Max vectors to emit (default: 500)",
      "  --max-text-chars <n>                     Max text chars per vector (default: 1600)",
      "  --out-corpus <path>                      Output corpus JSON path",
      "  --out-report <path>                      Output calibration report JSON path",
      "  --salt <value>                           Salt for deterministic anonymization",
      "  --node-id <value>                        Temporary node id for loading store state",
      ""
    ].join("\n")
  );
}

function parsePositiveInteger(value, fallback) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function parseArgs(argv) {
  const parsed = {
    dataDir: null,
    stateFile: null,
    backupFile: null,
    decisionLogFile: null,
    source: "federation",
    profile: "agent",
    limit: 500,
    maxTextChars: 1600,
    outCorpus: resolve("test/fixtures/content_filter_corpus/agent-production-like-v1.json"),
    outReport: resolve("scripts/output/content_filter_threshold_tuning_report.json"),
    salt: "loom-content-filter-corpus",
    nodeId: "loom-corpus-builder.local"
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--data-dir" && index + 1 < argv.length) {
      parsed.dataDir = resolve(argv[index + 1]);
      index += 1;
      continue;
    }
    if (arg === "--state-file" && index + 1 < argv.length) {
      parsed.stateFile = resolve(argv[index + 1]);
      index += 1;
      continue;
    }
    if (arg === "--backup-file" && index + 1 < argv.length) {
      parsed.backupFile = resolve(argv[index + 1]);
      index += 1;
      continue;
    }
    if (arg === "--decision-log-file" && index + 1 < argv.length) {
      parsed.decisionLogFile = resolve(argv[index + 1]);
      index += 1;
      continue;
    }
    if (arg === "--source" && index + 1 < argv.length) {
      parsed.source = String(argv[index + 1] || "").trim().toLowerCase();
      index += 1;
      continue;
    }
    if (arg === "--profile" && index + 1 < argv.length) {
      parsed.profile = String(argv[index + 1] || "").trim().toLowerCase();
      index += 1;
      continue;
    }
    if (arg === "--limit" && index + 1 < argv.length) {
      parsed.limit = parsePositiveInteger(argv[index + 1], parsed.limit);
      index += 1;
      continue;
    }
    if (arg === "--max-text-chars" && index + 1 < argv.length) {
      parsed.maxTextChars = parsePositiveInteger(argv[index + 1], parsed.maxTextChars);
      index += 1;
      continue;
    }
    if (arg === "--out-corpus" && index + 1 < argv.length) {
      parsed.outCorpus = resolve(argv[index + 1]);
      index += 1;
      continue;
    }
    if (arg === "--out-report" && index + 1 < argv.length) {
      parsed.outReport = resolve(argv[index + 1]);
      index += 1;
      continue;
    }
    if (arg === "--salt" && index + 1 < argv.length) {
      parsed.salt = String(argv[index + 1] || parsed.salt);
      index += 1;
      continue;
    }
    if (arg === "--node-id" && index + 1 < argv.length) {
      parsed.nodeId = String(argv[index + 1] || parsed.nodeId);
      index += 1;
    }
  }

  return parsed;
}

function ensureValidArgs(args) {
  const sourcesProvided =
    Number(Boolean(args.dataDir)) +
    Number(Boolean(args.stateFile)) +
    Number(Boolean(args.backupFile)) +
    Number(Boolean(args.decisionLogFile));
  if (sourcesProvided !== 1) {
    throw new Error("Provide exactly one of: --data-dir, --state-file, --backup-file, --decision-log-file");
  }
  if (!SOURCES.has(args.source)) {
    throw new Error(`--source must be one of: ${Array.from(SOURCES).join(", ")}`);
  }
  if (!PROFILES.has(args.profile)) {
    throw new Error(`--profile must be one of: ${Array.from(PROFILES).join(", ")}`);
  }
}

function hashToken(salt, kind, value, length = 12) {
  return createHash("sha256")
    .update(`${salt}:${kind}:${String(value || "")}`, "utf-8")
    .digest("hex")
    .slice(0, Math.max(4, length));
}

function anonymizeUrl(rawUrl, salt) {
  const original = String(rawUrl || "").trim();
  if (!original) {
    return "";
  }

  let parsed = null;
  try {
    parsed = new URL(original);
  } catch {
    return "https://h-anon.agent.example/";
  }

  const protocol = parsed.protocol === "http:" ? "http:" : "https:";
  const hostname = parsed.hostname.toLowerCase();
  const ipVersion = isIP(hostname);
  let host = "";
  if (ipVersion > 0) {
    const octet = (Number.parseInt(hashToken(salt, "ip", hostname, 2), 16) % 200) + 1;
    host = `198.51.100.${octet}`;
  } else if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    host = `xn--anon-${hashToken(salt, "punycode", hostname, 6)}.example`;
  } else if (SHORTENER_HOSTS.has(hostname)) {
    host = hostname;
  } else {
    host = `h-${hashToken(salt, "host", hostname, 8)}.agent.example`;
  }

  const pathToken = hashToken(salt, "path", parsed.pathname || "/", 10);
  const normalizedPath = parsed.pathname && parsed.pathname !== "/" ? `/p-${pathToken}` : "/";
  return `${protocol}//${host}${normalizedPath}`;
}

function anonymizeFilename(filename, salt) {
  const raw = String(filename || "").trim();
  if (!raw) {
    return `file-${hashToken(salt, "filename-empty", "empty", 8)}.bin`;
  }
  const normalized = raw.replace(/\s+/g, " ");
  const parts = normalized.split(".").map((entry) => entry.trim()).filter(Boolean);
  if (parts.length <= 1) {
    return `file-${hashToken(salt, "filename", normalized, 8)}.bin`;
  }
  const extensions = parts
    .slice(1)
    .map((entry) => entry.toLowerCase().replace(/[^a-z0-9]/g, ""))
    .filter(Boolean);
  const suffix = extensions.length > 0 ? `.${extensions.join(".")}` : ".bin";
  return `file-${hashToken(salt, "filename", normalized, 8)}${suffix}`;
}

function truncateText(value, maxChars) {
  const raw = String(value || "");
  if (raw.length <= maxChars) {
    return raw;
  }
  return `${raw.slice(0, Math.max(0, maxChars - 3))}...`;
}

function anonymizeText(raw, salt, maxChars) {
  let output = String(raw || "");
  output = output.replace(URL_RE, (match) => anonymizeUrl(match, salt));
  output = output.replace(LOOM_IDENTITY_RE, (match) => `loom://agent_${hashToken(salt, "identity", match, 8)}@agent.invalid`);
  output = output.replace(EMAIL_RE, (match) => `email_${hashToken(salt, "email", match, 10)}@anon.invalid`);
  output = output.replace(/\b\d{6,}\b/g, (match) => `n_${hashToken(salt, "number", match, 8)}`);
  output = output.replace(/[ \t]{2,}/g, " ").trim();
  return truncateText(output, maxChars);
}

function resolveHeaderValue(headers, name) {
  if (!headers || typeof headers !== "object") {
    return null;
  }
  const target = String(name || "").toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (String(key || "").toLowerCase() !== target) {
      continue;
    }
    if (Array.isArray(value)) {
      return value.map((entry) => String(entry || "")).join(", ");
    }
    return String(value || "");
  }
  return null;
}

function detectEnvelopeSource(envelope) {
  if (envelope?.meta?.federation?.source_node) {
    return "federation";
  }
  if (String(envelope?.meta?.bridge?.source || "").trim().toLowerCase() === "email") {
    return "bridge_email";
  }
  return "unknown";
}

function deriveEnvelopeSubject(envelope) {
  const bridgeHeaders = envelope?.meta?.bridge?.original_headers;
  const bridgeSubject = resolveHeaderValue(bridgeHeaders, "subject");
  if (bridgeSubject && bridgeSubject.trim()) {
    return bridgeSubject.trim();
  }
  const structuredIntent = String(envelope?.content?.structured?.intent || "").trim();
  if (structuredIntent) {
    return structuredIntent;
  }
  const type = String(envelope?.type || "").trim();
  if (type) {
    return type;
  }
  return "(no subject)";
}

function deriveEnvelopeText(envelope) {
  if (envelope?.content?.encrypted === true) {
    return "";
  }
  return String(envelope?.content?.human?.text || "").trim();
}

function deriveEnvelopeAttachments(envelope, salt) {
  const rawAttachments = Array.isArray(envelope?.attachments) ? envelope.attachments : [];
  return rawAttachments.slice(0, 12).map((attachment) => {
    const originalName = String(attachment?.filename || attachment?.name || "").trim();
    const originalMime = String(
      attachment?.mime_type || attachment?.mimeType || attachment?.contentType || "application/octet-stream"
    )
      .trim()
      .toLowerCase();
    return {
      filename: anonymizeFilename(originalName, salt),
      mime_type: originalMime || "application/octet-stream"
    };
  });
}

function quantile(values, ratio) {
  const sorted = (Array.isArray(values) ? values : [])
    .map((entry) => Number(entry))
    .filter((entry) => Number.isFinite(entry))
    .sort((a, b) => a - b);
  if (sorted.length === 0) {
    return null;
  }
  if (sorted.length === 1) {
    return sorted[0];
  }
  const clamped = Math.max(0, Math.min(1, Number(ratio) || 0));
  const index = clamped * (sorted.length - 1);
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) {
    return sorted[lower];
  }
  const weight = index - lower;
  return sorted[lower] * (1 - weight) + sorted[upper] * weight;
}

function buildThresholdSuggestion(vectors, baselineThresholds) {
  const allowVectors = vectors.filter((entry) => entry.expected_action === "allow");
  const quarantineVectors = vectors.filter((entry) => entry.expected_action === "quarantine");
  const rejectVectors = vectors.filter((entry) => entry.expected_action === "reject");
  const minimumTuningSampleSize = 50;
  const minimumAllowSampleSize = 20;
  if (vectors.length < minimumTuningSampleSize || allowVectors.length < minimumAllowSampleSize) {
    return {
      baseline_thresholds: baselineThresholds,
      suggested_thresholds: {
        spam_threshold: baselineThresholds.spam,
        phish_threshold: baselineThresholds.phish,
        quarantine_threshold: baselineThresholds.quarantine,
        reject_threshold: baselineThresholds.reject
      },
      quantiles: {
        allow_score_p95: quantile(allowVectors.map((entry) => entry.scores.total_score), 0.95),
        allow_score_p99: quantile(allowVectors.map((entry) => entry.scores.total_score), 0.99),
        reject_score_p20: quantile(rejectVectors.map((entry) => entry.scores.total_score), 0.2),
        reject_score_p50: quantile(rejectVectors.map((entry) => entry.scores.total_score), 0.5),
        quarantine_score_p90: quantile(quarantineVectors.map((entry) => entry.scores.total_score), 0.9)
      },
      insufficient_sample_size: {
        vectors: vectors.length,
        allow_vectors: allowVectors.length,
        minimum_vectors_required: minimumTuningSampleSize,
        minimum_allow_vectors_required: minimumAllowSampleSize
      }
    };
  }

  const allowSpamScores = allowVectors.map((entry) => entry.scores.spam_score);
  const allowPhishScores = allowVectors.map((entry) => entry.scores.phish_score);
  const allowTotalScores = allowVectors.map((entry) => entry.scores.total_score);
  const rejectTotalScores = rejectVectors.map((entry) => entry.scores.total_score);
  const quarantineTotalScores = quarantineVectors.map((entry) => entry.scores.total_score);

  const suggestedSpam = Math.max(
    1,
    Math.ceil(Math.max(0, quantile(allowSpamScores, 0.95) || 0))
  );
  const suggestedPhish = Math.max(
    1,
    Math.ceil((quantile(allowPhishScores, 0.95) || 0) + 1)
  );
  const suggestedQuarantine = Math.max(
    suggestedPhish,
    Math.ceil((quantile(allowTotalScores, 0.99) || 0) + 1)
  );

  const rejectAnchor = (() => {
    if (rejectTotalScores.length > 0) {
      return Math.floor(quantile(rejectTotalScores, 0.2) || suggestedQuarantine + 2);
    }
    if (quarantineTotalScores.length > 0) {
      return Math.ceil((quantile(quarantineTotalScores, 0.9) || suggestedQuarantine) + 1);
    }
    return suggestedQuarantine + 2;
  })();

  const suggestedReject = Math.max(suggestedQuarantine + 1, rejectAnchor);

  return {
    baseline_thresholds: baselineThresholds,
    suggested_thresholds: {
      spam_threshold: suggestedSpam,
      phish_threshold: suggestedPhish,
      quarantine_threshold: suggestedQuarantine,
      reject_threshold: suggestedReject
    },
    quantiles: {
      allow_score_p95: quantile(allowTotalScores, 0.95),
      allow_score_p99: quantile(allowTotalScores, 0.99),
      reject_score_p20: quantile(rejectTotalScores, 0.2),
      reject_score_p50: quantile(rejectTotalScores, 0.5),
      quarantine_score_p90: quantile(quarantineTotalScores, 0.9)
    }
  };
}

function mapByAction(vectors) {
  const counts = {
    allow: 0,
    quarantine: 0,
    reject: 0
  };
  for (const vector of vectors) {
    if (DECISIONS.includes(vector.expected_action)) {
      counts[vector.expected_action] += 1;
    }
  }
  return counts;
}

function mapBySource(vectors) {
  const counts = {};
  for (const vector of vectors) {
    const source = String(vector.source || "unknown");
    counts[source] = Number(counts[source] || 0) + 1;
  }
  return counts;
}

function shouldIncludeEnvelopeBySource(envelope, sourceFilter) {
  if (sourceFilter === "all") {
    return true;
  }
  return detectEnvelopeSource(envelope) === sourceFilter;
}

function ensureParentDir(pathname) {
  mkdirSync(dirname(pathname), { recursive: true });
}

function loadStateFromInput(args) {
  if (args.dataDir) {
    const store = new LoomStore({
      nodeId: args.nodeId,
      dataDir: args.dataDir,
      inboundContentFilterEnabled: true,
      inboundContentFilterProfileDefault: args.profile,
      inboundContentFilterProfileBridge: args.profile,
      inboundContentFilterProfileFederation: args.profile
    });
    return {
      store,
      input_mode: "data_dir",
      input_path: args.dataDir
    };
  }

  const store = new LoomStore({
    nodeId: args.nodeId,
    inboundContentFilterEnabled: true,
    inboundContentFilterProfileDefault: args.profile,
    inboundContentFilterProfileBridge: args.profile,
    inboundContentFilterProfileFederation: args.profile
  });

  if (args.stateFile) {
    const state = JSON.parse(readFileSync(args.stateFile, "utf-8"));
    if (!state || typeof state !== "object") {
      throw new Error("--state-file must contain a JSON object");
    }
    store.loadStateFromObject(state);
    return {
      store,
      input_mode: "state_file",
      input_path: args.stateFile
    };
  }

  const backup = JSON.parse(readFileSync(args.backupFile, "utf-8"));
  const state = backup?.state;
  if (!state || typeof state !== "object") {
    throw new Error("--backup-file does not include a usable state object");
  }
  store.loadStateFromObject(state);
  return {
    store,
    input_mode: "backup_file",
    input_path: args.backupFile
  };
}

function shouldIncludeVectorBySource(source, sourceFilter) {
  if (sourceFilter === "all") {
    return true;
  }
  return String(source || "unknown").trim().toLowerCase() === sourceFilter;
}

function loadVectorsFromDecisionLog(args) {
  const raw = readFileSync(args.decisionLogFile, "utf-8");
  const lines = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const vectors = [];
  for (const line of lines) {
    if (vectors.length >= args.limit) {
      break;
    }
    let entry = null;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    if (!entry || typeof entry !== "object") {
      continue;
    }

    const action = String(entry.action || "")
      .trim()
      .toLowerCase();
    if (!DECISIONS.includes(action)) {
      continue;
    }

    const source = String(entry.source || "unknown")
      .trim()
      .toLowerCase() || "unknown";
    if (!shouldIncludeVectorBySource(source, args.source)) {
      continue;
    }

    const profile = String(entry.profile || "")
      .trim()
      .toLowerCase();
    if (profile && profile !== args.profile) {
      continue;
    }

    vectors.push({
      id: `log_${String(vectors.length + 1).padStart(6, "0")}`,
      source,
      expected_action: action,
      scores: {
        total_score: Number(entry.score || 0),
        spam_score: Number(entry.spam_score || 0),
        phish_score: Number(entry.phish_score || 0),
        malware_score: Number(entry.malware_score || 0)
      },
      signal_codes: Array.isArray(entry.signal_codes)
        ? entry.signal_codes.map((code) => String(code || "").trim()).filter(Boolean)
        : []
    });
  }

  return vectors;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  ensureValidArgs(args);

  let input = null;
  let store = null;
  let vectors = [];
  if (args.decisionLogFile) {
    store = new LoomStore({
      nodeId: args.nodeId,
      inboundContentFilterEnabled: true,
      inboundContentFilterProfileDefault: args.profile,
      inboundContentFilterProfileBridge: args.profile,
      inboundContentFilterProfileFederation: args.profile
    });
    input = {
      input_mode: "decision_log_file",
      input_path: args.decisionLogFile
    };
    vectors = loadVectorsFromDecisionLog(args);
  } else {
    input = loadStateFromInput(args);
    store = input.store;

    const envelopes = Array.from(store.envelopesById.values()).sort((left, right) => {
      const leftTime = Date.parse(String(left?.created_at || "")) || 0;
      const rightTime = Date.parse(String(right?.created_at || "")) || 0;
      return rightTime - leftTime;
    });

    vectors = [];
    for (const envelope of envelopes) {
      if (vectors.length >= args.limit) {
        break;
      }
      if (!shouldIncludeEnvelopeBySource(envelope, args.source)) {
        continue;
      }

      const source = detectEnvelopeSource(envelope);
      const subject = deriveEnvelopeSubject(envelope);
      const text = deriveEnvelopeText(envelope);
      const attachments = deriveEnvelopeAttachments(envelope, args.salt);
      if (!subject && !text && attachments.length === 0) {
        continue;
      }

      const anonymizedSubject = anonymizeText(subject, args.salt, Math.min(240, args.maxTextChars));
      const anonymizedText = anonymizeText(text, args.salt, args.maxTextChars);
      const payload = {
        subject: anonymizedSubject,
        text: anonymizedText,
        html: "",
        attachments
      };
      const evaluation = store.evaluateInboundContentPolicy(payload, {
        source,
        profile: args.profile
      });

      vectors.push({
        id: `prod_${String(vectors.length + 1).padStart(4, "0")}`,
        source,
        subject: anonymizedSubject,
        text: anonymizedText,
        ...(attachments.length > 0 ? { attachments } : {}),
        expected_action: evaluation.action,
        scores: {
          total_score: evaluation.score,
          spam_score: evaluation.spam_score,
          phish_score: evaluation.phish_score,
          malware_score: evaluation.malware_score
        },
        signal_codes: Array.isArray(evaluation.signals) ? evaluation.signals.map((signal) => signal.code) : [],
        original_envelope_id_hash: hashToken(args.salt, "envelope-id", envelope?.id || "", 16)
      });
    }
  }

  const baselineThresholds = store.resolveInboundContentFilterThresholds(
    store.resolveInboundContentFilterProfileConfig(args.profile)
  );
  const thresholdSuggestion = buildThresholdSuggestion(vectors, baselineThresholds);
  const actionDistribution = mapByAction(vectors);
  const sourceDistribution = mapBySource(vectors);

  const corpus = {
    version: `agent-production-like-${args.profile}-v1`,
    generated_at: new Date().toISOString(),
    source_filter: args.source,
    profile: args.profile,
    total_vectors: vectors.length,
    vectors
  };

  const report = {
    generated_at: corpus.generated_at,
    input_mode: input.input_mode,
    input_path: input.input_path,
    source_filter: args.source,
    profile: args.profile,
    total_vectors: vectors.length,
    distribution: {
      by_action: actionDistribution,
      by_source: sourceDistribution
    },
    threshold_calibration: thresholdSuggestion,
    note:
      "Inputs are anonymized and re-scored with the selected profile to support threshold tuning with production-like distributions."
  };

  ensureParentDir(args.outCorpus);
  writeFileSync(args.outCorpus, `${JSON.stringify(corpus, null, 2)}\n`, "utf-8");

  ensureParentDir(args.outReport);
  writeFileSync(args.outReport, `${JSON.stringify(report, null, 2)}\n`, "utf-8");

  console.log(`[content-filter-corpus] wrote corpus: ${args.outCorpus}`);
  console.log(`[content-filter-corpus] wrote report: ${args.outReport}`);
  console.log(
    `[content-filter-corpus] vectors=${vectors.length} allow=${actionDistribution.allow} quarantine=${actionDistribution.quarantine} reject=${actionDistribution.reject}`
  );
  console.log(
    `[content-filter-corpus] suggested thresholds spam=${thresholdSuggestion.suggested_thresholds.spam_threshold} phish=${thresholdSuggestion.suggested_thresholds.phish_threshold} quarantine=${thresholdSuggestion.suggested_thresholds.quarantine_threshold} reject=${thresholdSuggestion.suggested_thresholds.reject_threshold}`
  );
}

try {
  main();
} catch (error) {
  console.error(`[content-filter-corpus] ${error?.message || error}`);
  printUsage();
  process.exitCode = 1;
}
