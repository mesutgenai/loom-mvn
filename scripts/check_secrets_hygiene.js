#!/usr/bin/env node

import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { basename } from "node:path";

const ALLOWED_SECRET_FILES = new Set([
  "test/fixtures/wire_tls_key.pem",
  "test/fixtures/wire_tls_cert.pem"
]);

const SECRET_PATTERNS = [
  {
    name: "private_key_block",
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/
  },
  {
    name: "aws_access_key_id",
    regex: /\bAKIA[0-9A-Z]{16}\b/
  },
  {
    name: "github_token",
    regex: /\bgh[pousr]_[A-Za-z0-9]{30,255}\b/
  },
  {
    name: "openai_key",
    regex: /\bsk-[A-Za-z0-9]{20,}\b/
  }
];

function listTrackedFiles() {
  const output = execSync("git ls-files -z", { encoding: "utf-8" });
  return output.split("\0").filter(Boolean);
}

function isLikelyText(content) {
  return !content.includes("\u0000");
}

function isPlaceholder(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) {
    return true;
  }
  const placeholderHints = [
    "replace",
    "example",
    "placeholder",
    "changeme",
    "dummy",
    "test",
    "redacted",
    "your-",
    "<",
    "$",
    "${"
  ];
  return placeholderHints.some((hint) => normalized.includes(hint));
}

function normalizeAssignedValue(rawValue) {
  const value = String(rawValue || "").trim();
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1).trim();
  }
  return value;
}

function findExplicitSecretAssignments(path, source) {
  const findings = [];
  const lines = source.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    let match = line.match(/^\s*LOOM_ADMIN_TOKEN\s*=\s*(.+)\s*$/);
    if (match) {
      const assigned = normalizeAssignedValue(match[1]);
      if (!isPlaceholder(assigned)) {
        findings.push({
          path,
          line: i + 1,
          type: "loom_admin_token_assignment"
        });
      }
    }

    match = line.match(/^\s*LOOM_NODE_SIGNING_PRIVATE_KEY_PEM\s*=\s*(.+)\s*$/);
    if (match) {
      const assigned = normalizeAssignedValue(match[1]);
      if (!isPlaceholder(assigned)) {
        findings.push({
          path,
          line: i + 1,
          type: "loom_node_private_key_assignment"
        });
      }
    }

    match = line.match(/x-loom-admin-token:\s*([^\s]+)/i);
    if (match) {
      const token = normalizeAssignedValue(match[1]);
      if (!isPlaceholder(token) && token.length >= 16) {
        findings.push({
          path,
          line: i + 1,
          type: "inline_admin_header_token"
        });
      }
    }
  }
  return findings;
}

function main() {
  const findings = [];
  const trackedFiles = listTrackedFiles();

  for (const path of trackedFiles) {
    const name = basename(path);
    if (name.startsWith(".env") && !name.endsWith(".example")) {
      findings.push({
        path,
        line: 1,
        type: "tracked_env_file"
      });
    }

    let source;
    try {
      source = readFileSync(path, "utf-8");
    } catch {
      continue;
    }
    if (!isLikelyText(source)) {
      continue;
    }

    const allowRawSecrets = ALLOWED_SECRET_FILES.has(path);

    if (!allowRawSecrets) {
      for (const pattern of SECRET_PATTERNS) {
        const match = source.match(pattern.regex);
        if (match) {
          const before = source.slice(0, match.index);
          const line = before.split(/\r?\n/).length;
          findings.push({
            path,
            line,
            type: pattern.name
          });
        }
      }
    }

    findings.push(...findExplicitSecretAssignments(path, source));
  }

  if (findings.length > 0) {
    console.error("Secret hygiene check failed. Potential secrets detected:");
    for (const finding of findings) {
      console.error(`- ${finding.path}:${finding.line} (${finding.type})`);
    }
    process.exit(1);
  }

  console.log("Secret hygiene check passed. No obvious committed secrets detected.");
}

main();
